/* Opt-in hardware fixture, built against the exact UCX source/configuration
 * used by the selected libraries. Public UCT calls perform real DC sends;
 * private headers only inspect the posted WQE for independent comparison.
 * Output is a private pipe: QPN plus a redacted prefix, never payload or key. */
#define _GNU_SOURCE
#include <config.h>
#include <uct/api/uct.h>
#include <uct/ib/mlx5/dc/dc_mlx5_ep.h>
#include <ucs/async/async.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *operation)
{
    fprintf(stderr, "RPINGMESH_UCX_TEST_ERROR: %s\n", operation);
    exit(1);
}
#define CHECK(expr) do { if ((expr) != UCS_OK) fail(#expr); } while (0)

static void gate(const char *message, int command)
{
    puts(message);
    fflush(stdout);
    if (getchar() != command) fail("control gate");
}

struct receiver { unsigned count; unsigned mask; };
static int use_devx, use_streams;
static const char *operation = "short";
static unsigned completed;
static void completion(uct_completion_t *comp)
{
    if (comp->status != UCS_OK) fail("zcopy completion");
    ++completed;
}
static size_t pack_message(void *dest, void *arg)
{
    memcpy(dest, arg, 8);
    memcpy((char *)dest + 8, "test", 4);
    return 12;
}
static ucs_status_t receive(void *arg, void *data, size_t length, unsigned flags)
{
    struct receiver *r = arg;
    uint64_t header;
    (void)flags;
    if (length != 12) fail("received length");
    memcpy(&header, data, sizeof(header));
    if (header >= 3 || memcmp((char *)data + 8, "test", 4) || (r->mask & (1u << header)))
        fail("received content");
    r->mask |= 1u << header;
    ++r->count;
    return UCS_OK;
}

static uct_md_h open_md(const char *device)
{
    uct_component_h *components;
    unsigned n;
    CHECK(uct_query_components(&components, &n));
    for (unsigned i = 0; i < n; ++i) {
        uct_component_attr_t a = {.field_mask = UCT_COMPONENT_ATTR_FIELD_MD_RESOURCE_COUNT};
        CHECK(uct_component_query(components[i], &a));
        a.md_resources = calloc(a.md_resource_count, sizeof(*a.md_resources));
        if (!a.md_resources && a.md_resource_count) fail("resource allocation");
        a.field_mask = UCT_COMPONENT_ATTR_FIELD_MD_RESOURCES;
        CHECK(uct_component_query(components[i], &a));
        for (unsigned j = 0; j < a.md_resource_count; ++j) {
            uct_md_config_t *config;
            uct_md_h md;
            if (uct_md_config_read(components[i], NULL, NULL, &config) != UCS_OK) continue;
            ucs_status_t status = uct_md_open(components[i], a.md_resources[j].md_name, config, &md);
            uct_config_release(config);
            if (status != UCS_OK) continue;
            uct_tl_resource_desc_t *resources;
            unsigned count;
            CHECK(uct_md_query_tl_resources(md, &resources, &count));
            int found = 0;
            for (unsigned k = 0; k < count; ++k)
                if (!strcmp(resources[k].tl_name, "dc_mlx5") && !strcmp(resources[k].dev_name, device)) found = 1;
            uct_release_tl_resource_list(resources);
            if (found) {
                free(a.md_resources);
                uct_release_component_list(components);
                return md;
            }
            uct_md_close(md);
        }
        free(a.md_resources);
    }
    uct_release_component_list(components);
    fail("DC memory domain unavailable");
    return NULL;
}

static uct_iface_h open_iface(uct_md_h md, uct_worker_h worker, const char *device)
{
    uct_iface_config_t *config;
    CHECK(uct_md_iface_config_read(md, "dc_mlx5", NULL, NULL, &config));
    CHECK(uct_config_modify(config, "DC_TX_POLICY", use_streams ? "hw_dcs" : "rand"));
    CHECK(uct_config_modify(config, "DC_NUM_DCI", "1"));
    if (use_streams) CHECK(uct_config_modify(config, "DC_NUM_DCI_CHANNELS", "4"));
    uct_iface_params_t p = {0};
    p.field_mask = UCT_IFACE_PARAM_FIELD_OPEN_MODE | UCT_IFACE_PARAM_FIELD_DEVICE |
                   UCT_IFACE_PARAM_FIELD_RX_HEADROOM;
    p.open_mode = UCT_IFACE_OPEN_MODE_DEVICE;
    p.mode.device.tl_name = "dc_mlx5";
    p.mode.device.dev_name = device;
    uct_iface_h iface;
    CHECK(uct_iface_open(md, worker, &p, config, &iface));
    uct_config_release(config);
    uct_iface_progress_enable(iface, UCT_PROGRESS_SEND | UCT_PROGRESS_RECV);
    return iface;
}

static uct_ep_h connect_ep(uct_iface_h sender, uct_iface_h receiver)
{
    uct_iface_attr_t attr;
    CHECK(uct_iface_query(receiver, &attr));
    if (!(attr.cap.flags & UCT_IFACE_FLAG_CONNECT_TO_IFACE) || !(attr.cap.flags & UCT_IFACE_FLAG_AM_SHORT)) fail("DC capabilities");
    void *dev = calloc(1, attr.device_addr_len), *address = calloc(1, attr.iface_addr_len);
    if (!dev || !address) fail("address allocation");
    CHECK(uct_iface_get_device_address(receiver, dev));
    CHECK(uct_iface_get_address(receiver, address));
    uct_ep_params_t p = {0};
    p.field_mask = UCT_EP_PARAM_FIELD_IFACE | UCT_EP_PARAM_FIELD_DEV_ADDR | UCT_EP_PARAM_FIELD_IFACE_ADDR;
    p.iface = sender;
    p.dev_addr = dev;
    p.iface_addr = address;
    uct_ep_h ep;
    CHECK(uct_ep_create(&p, &ep));
    free(address);
    free(dev);
    return ep;
}

static void report_wqe(uct_ep_h endpoint)
{
    uct_dc_mlx5_ep_t *ep = ucs_derived_of(endpoint, uct_dc_mlx5_ep_t);
    uct_dc_mlx5_iface_t *iface = ucs_derived_of(endpoint->iface, uct_dc_mlx5_iface_t);
    uct_ib_mlx5_txwq_t *wq = &uct_dc_mlx5_iface_dci(iface, ep->dci)->txwq;
    if (wq->super.type != (use_devx ? UCT_IB_MLX5_OBJ_TYPE_DEVX : UCT_IB_MLX5_OBJ_TYPE_VERBS))
        fail("unexpected DCI backend");
    size_t bytes = (char *)wq->qend - (char *)wq->qstart;
    if (!bytes || (bytes & (bytes - 1))) fail("SQ extent");
    struct mlx5dv_qp dv_qp = {0};
    struct mlx5dv_obj obj = {0};
    obj.qp.in = wq->super.verbs.qp;
    obj.qp.out = &dv_qp;
    if (use_devx) {
        if (!wq->super.devx.obj || wq->qstart != wq->super.devx.wq_buf ||
            wq->dbrec != &wq->super.devx.dbrec->db[MLX5_SND_DBR] ||
            (uint16_t)ntohl(*wq->dbrec) != wq->sw_pi) fail("DevX SQ correspondence");
    } else if (mlx5dv_init_obj(&obj, MLX5DV_OBJ_QP) || dv_qp.sq.buf != wq->qstart ||
        dv_qp.sq.stride != 64 || bytes != (size_t)dv_qp.sq.wqe_cnt * 64 ||
        (uint16_t)ntohl(*wq->dbrec) != wq->sw_pi) fail("UCX/provider SQ correspondence");
    const unsigned char *prefix = (const unsigned char *)wq->qstart + ((wq->prev_sw_pi * 64u) & (bytes - 1));
    if (use_streams && (iface->tx.num_dci_channels != 4 ||
        (((unsigned)prefix[9] << 8) | prefix[10]) != ep->dci_channel_index ||
        ep->dci_channel_index >= 4)) fail("DCI stream correspondence");
    unsigned char record[68] = {0};
    uint32_t qpn = htonl(wq->super.qp_num);
    memcpy(record, &qpn, 4);
    memcpy(record + 4, prefix, 16);
    memcpy(record + 28, prefix + 24, 40);
    if (fwrite(record, sizeof(record), 1, stdout) != 1) fail("record output");
}

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 6 || (argc >= 5 && strcmp(argv[4], "--verbs") &&
        strcmp(argv[4], "--devx") && strcmp(argv[4], "--streams"))) fail("invalid helper arguments");
    use_devx = argc >= 5 && strcmp(argv[4], "--verbs");
    use_streams = argc >= 5 && !strcmp(argv[4], "--streams");
    if (argc == 6) operation = argv[5];
    if (strcmp(operation, "short") && strcmp(operation, "short-iov") &&
        strcmp(operation, "bcopy") && strcmp(operation, "zcopy")) fail("invalid AM operation");
    alarm(60);
    if (setenv("UCX_IB_MLX5_DEVX", use_devx ? "yes" : "no", 1) || setenv("UCX_IB_GID_INDEX", argv[3], 1) ||
        setenv("UCX_LOG_LEVEL", "error", 1)) fail("environment");
    /* The fixture does not need a shared hardware counter set. */
    if (use_devx && setenv("UCX_IB_COUNTER_SET_ID", "0", 1)) fail("counter setting");
    char device[128];
    if (snprintf(device, sizeof(device), "%s:%s", argv[1], argv[2]) >= (int)sizeof(device)) fail("device argument");
    ucs_async_context_t *async;
    uct_worker_h worker;
    CHECK(ucs_async_context_create(UCS_ASYNC_MODE_THREAD_SPINLOCK, &async));
    CHECK(uct_worker_create(async, UCS_THREAD_MODE_SINGLE, &worker));
    uct_md_h md = open_md(device);
    /* Provider libraries are mapped; DCIs are created only after attachment. */
    gate("ready", 'g');
    uct_iface_h sender = open_iface(md, worker, device);
    uct_iface_h receivers[2];
    uct_ep_h eps[3];
    unsigned ep_count = use_streams ? 3 : 2;
    struct receiver state[2] = {{0}};
    for (unsigned i = 0; i < 2; ++i) {
        receivers[i] = open_iface(md, worker, device);
        CHECK(uct_iface_set_am_handler(receivers[i], 1, receive, &state[i], 0));
    }
    for (unsigned i = 0; i < ep_count; ++i) {
        eps[i] = connect_ep(sender, receivers[use_streams ? i / 2 : i]);
    }
    char payload[4] = {'t', 'e', 's', 't'};
    uct_mem_h memh = UCT_MEM_HANDLE_NULL;
    int zcopy = !strcmp(operation, "zcopy");
    if (zcopy) CHECK(uct_md_mem_reg(md, payload, sizeof(payload), UCT_MD_MEM_ACCESS_LOCAL_READ, &memh));
    for (uint64_t i = 0; i < 3; ++i) {
        uct_ep_h ep = eps[i % ep_count];
        uct_iov_t iov[2] = {{.buffer = &i, .length = 8, .memh = UCT_MEM_HANDLE_NULL, .count = 1},
                            {.buffer = payload, .length = 4, .memh = memh, .count = 1}};
        uct_completion_t comp = {.func = completion, .count = 1, .status = UCS_OK};
        if (!strcmp(operation, "short-iov")) {
            CHECK(uct_ep_am_short_iov(ep, 1, iov, 2));
        } else if (!strcmp(operation, "bcopy")) {
            if (uct_ep_am_bcopy(ep, 1, pack_message, &i, 0) != 12) fail("bcopy submission");
        } else if (zcopy) {
            if (uct_ep_am_zcopy(ep, 1, &i, 8, &iov[1], 1, 0, &comp) != UCS_INPROGRESS) fail("zcopy submission");
        } else {
            CHECK(uct_ep_am_short(ep, 1, i, payload, 4));
        }
        report_wqe(eps[i % ep_count]);
        while (state[0].count + state[1].count != i + 1 || (zcopy && completed != i + 1))
            uct_worker_progress(worker);
    }
    for (unsigned i = 0; i < ep_count; ++i) {
        ucs_status_t status;
        do {
            status = uct_ep_flush(eps[i], 0, NULL);
            uct_worker_progress(worker);
        } while (status == UCS_INPROGRESS || status == UCS_ERR_NO_RESOURCE);
        if (status != UCS_OK) fail("send completion");
    }
    if (zcopy) CHECK(uct_md_mem_dereg(md, memh));
    if (state[0].mask != (use_streams ? 3u : 5u) || state[1].mask != (use_streams ? 4u : 2u)) fail("receive destinations");
    gate("delivered", 'd');
    for (unsigned i = 0; i < ep_count; ++i) uct_ep_destroy(eps[i]);
    uct_iface_close(sender);
    for (unsigned i = 0; i < 2; ++i) uct_iface_close(receivers[i]);
    gate("retired", 'x');
    uct_md_close(md);
    uct_worker_destroy(worker);
    ucs_async_context_destroy(async);
    return 0;
}
