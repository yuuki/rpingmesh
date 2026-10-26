/* Opt-in hardware exerciser: submit to two local DCTs from one non-stream DCI.
 * stdout is a private binary pipe to the Go test, never a fixture to commit.
 * Use only public rdma-core APIs. This is not a production capture adapter.
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <infiniband/mlx5dv.h>
#include <infiniband/verbs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const uint64_t test_key = 0x12345678;

static void fail(const char *step)
{
    fprintf(stderr, "RPINGMESH_DC_TEST_ERROR: %s failed (errno=%d)\n", step, errno);
    exit(1); /* Closing the process also releases any partially created QPs. */
}

static void check(int rc, const char *step)
{
    if (rc) {
        errno = rc > 0 ? rc : errno;
        fail(step);
    }
}

static void control_wait(const char *status, int command)
{
    if (status && printf("%s\n", status) < 0)
        fail("control status");
    if (fflush(stdout) || getchar() != command)
        fail("control command");
}

static unsigned parse_number(const char *s, unsigned max)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || !*s || *end || n > max)
        fail("numeric argument validation");
    return (unsigned)n;
}

static struct ibv_qp *create_qp(struct ibv_context *ctx, struct ibv_pd *pd,
                               struct ibv_cq *cq, struct ibv_srq *srq,
                               const struct ibv_ah_attr *av, enum ibv_mtu mtu)
{
    const int target = srq != NULL;
    struct ibv_qp_init_attr_ex init = {
        .qp_type = IBV_QPT_DRIVER, .pd = pd, .send_cq = cq, .recv_cq = cq,
        .srq = srq, .comp_mask = IBV_QP_INIT_ATTR_PD,
    };
    struct mlx5dv_qp_init_attr dv = {
        .comp_mask = MLX5DV_QP_INIT_ATTR_MASK_DC,
    };
    dv.dc_init_attr.dc_type = target ? MLX5DV_DCTYPE_DCT : MLX5DV_DCTYPE_DCI;
    if (target) {
        dv.dc_init_attr.dct_access_key = test_key;
    } else {
        init.cap.max_send_wr = 8;
        init.cap.max_send_sge = 1;
        init.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
        init.send_ops_flags = IBV_QP_EX_WITH_SEND;
        dv.comp_mask |= MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;
        dv.create_flags = MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE;
    }
    struct ibv_qp *qp = mlx5dv_create_qp(ctx, &init, &dv);
    if (!qp)
        fail("DC QP creation");
    struct ibv_qp_attr attr = {
        .qp_state = IBV_QPS_INIT, .port_num = av->port_num, .pkey_index = 0,
        .qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE,
    };
    int mask = IBV_QP_STATE | IBV_QP_PORT | IBV_QP_PKEY_INDEX;
    if (target)
        mask |= IBV_QP_ACCESS_FLAGS;
    check(ibv_modify_qp(qp, &attr, mask), "DC QP INIT");
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.ah_attr = *av;
    attr.path_mtu = mtu;
    attr.min_rnr_timer = 12;
    mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU;
    if (target)
        mask |= IBV_QP_MIN_RNR_TIMER;
    check(ibv_modify_qp(qp, &attr, mask), "DC QP RTR");
    if (!target) {
        memset(&attr, 0, sizeof(attr));
        attr.qp_state = IBV_QPS_RTS;
        attr.timeout = 14;
        attr.retry_cnt = 2;
        attr.rnr_retry = 2;
        attr.max_rd_atomic = 1;
        check(ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN |
              IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
              IBV_QP_MAX_QP_RD_ATOMIC), "DCI RTS");
    }
    return qp;
}

static void await_pair(struct ibv_cq *cq, uint64_t send_id, uint64_t recv_id,
                       uint32_t source_qpn, uint32_t target_qpn)
{
    int sent = 0, received = 0;
    struct timespec start, now, pause = {.tv_nsec = 1000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!sent || !received) {
        struct ibv_wc wc;
        int n = ibv_poll_cq(cq, 1, &wc);
        if (n < 0)
            fail("CQ poll");
        if (n) {
            if (wc.status != IBV_WC_SUCCESS)
                fail("DC completion status");
            if (wc.wr_id == send_id && wc.opcode == IBV_WC_SEND &&
                wc.qp_num == source_qpn && !sent)
                sent = 1;
            else if (wc.wr_id == recv_id && wc.opcode == IBV_WC_RECV &&
                     wc.qp_num == target_qpn && wc.byte_len == 1 && !received)
                received = 1;
            else
                fail("DC completion identity");
        } else {
            nanosleep(&pause, NULL);
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 5)
            fail("DC completion timeout");
    }
}

static void put32(uint8_t *out, uint32_t value)
{
    value = htonl(value);
    memcpy(out, &value, sizeof(value));
}

int main(int argc, char **argv)
{
    int controlled = argc == 5 && !strcmp(argv[4], "--controlled");
    alarm(controlled ? 90 : 30);
    if (argc != 4 && !controlled)
        fail("expected device, port and GID index arguments");
    unsigned port = parse_number(argv[2], 255);
    unsigned index = parse_number(argv[3], 255);
    if (!port)
        fail("port validation");
    int count;
    struct ibv_device **devices = ibv_get_device_list(&count);
    if (!devices)
        fail("device enumeration");
    struct ibv_context *ctx = NULL;
    for (int i = 0; i < count; ++i) {
        if (!strcmp(ibv_get_device_name(devices[i]), argv[1]) &&
            mlx5dv_is_supported(devices[i])) {
            ctx = ibv_open_device(devices[i]);
            break;
        }
    }
    if (!ctx)
        fail("mlx5 device open");
    struct ibv_port_attr pattr;
    check(ibv_query_port(ctx, port, &pattr), "port query");
    if (pattr.state != IBV_PORT_ACTIVE || pattr.link_layer != IBV_LINK_LAYER_ETHERNET)
        fail("active Ethernet port requirement");
    struct ibv_gid_entry gid;
    check(ibv_query_gid_ex(ctx, port, index, &gid, 0), "GID query");
    const uint8_t zero_gid[16] = {0};
    if (gid.gid_type != IBV_GID_TYPE_ROCE_V2 || !memcmp(gid.gid.raw, zero_gid, 16))
        fail("RoCEv2 GID requirement");
    struct ibv_ah_attr av = {
        .port_num = port, .is_global = 1, .sl = 0,
        .grh = {.dgid = gid.gid, .sgid_index = index, .hop_limit = 64,
                .traffic_class = 0, .flow_label = 0x12345},
    };
    struct ibv_pd *pd = ibv_alloc_pd(ctx);
    if (!pd)
        fail("PD allocation");
    struct ibv_cq *cq = ibv_create_cq(ctx, 16, NULL, NULL, 0);
    if (!cq)
        fail("CQ creation");
    struct ibv_srq_init_attr srq_init = {.attr = {.max_wr = 8, .max_sge = 1}};
    struct ibv_srq *srq = ibv_create_srq(pd, &srq_init);
    if (!srq)
        fail("SRQ creation");
    /* The provider is loaded, but no DCIs exist until the observer attaches. */
    if (controlled)
        control_wait("ready", 'g');
    struct ibv_qp *dct[2] = {
        create_qp(ctx, pd, cq, srq, &av, pattr.active_mtu),
        create_qp(ctx, pd, cq, srq, &av, pattr.active_mtu),
    };
    struct ibv_qp *dci = create_qp(ctx, pd, cq, NULL, &av, pattr.active_mtu);
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(dci);
    struct mlx5dv_qp_ex *dvx = qpx ? mlx5dv_qp_ex_from_ibv_qp_ex(qpx) : NULL;
    if (!dvx)
        fail("extended DCI conversion");
    struct mlx5dv_qp direct = {0};
    struct mlx5dv_obj obj = {.qp = {.in = dci, .out = &direct}};
    check(mlx5dv_init_obj(&obj, MLX5DV_OBJ_QP), "DCI queue query");
    if (!direct.sq.buf || !direct.dbrec || !direct.sq.wqe_cnt || direct.sq.stride != 64)
        fail("supported SQ layout requirement");
    uint8_t data[128] = {0};
    struct ibv_mr *mr = ibv_reg_mr(pd, data, sizeof(data), IBV_ACCESS_LOCAL_WRITE);
    if (!mr)
        fail("MR registration");

    /* A/B/A addresses: two DCTs plus a new AV for the first DCT. The middle
     * send leaves the application flow label zero; the provider chooses sport.
     */
    const uint32_t labels[] = {0x12345, 0, 0x54321};
    for (unsigned i = 0; i < 3; ++i) {
        struct ibv_qp *target = dct[i % 2];
        av.grh.flow_label = labels[i];
        struct ibv_ah *ah = ibv_create_ah(pd, &av);
        if (!ah)
            fail("AH creation");
        data[0] = (uint8_t)(i + 1);
        memset(data + 64, 0, 64);
        struct ibv_sge recv_sge = {.addr = (uintptr_t)(data + 64), .length = 64, .lkey = mr->lkey};
        struct ibv_recv_wr recv = {.wr_id = 100 + i, .sg_list = &recv_sge, .num_sge = 1};
        struct ibv_recv_wr *bad;
        check(ibv_post_srq_recv(srq, &recv, &bad), "SRQ receive posting");
        uint32_t producer = ntohl(direct.dbrec[1]);
        size_t offset = (producer % direct.sq.wqe_cnt) * direct.sq.stride;
        ibv_wr_start(qpx);
        qpx->wr_id = 200 + i;
        qpx->wr_flags = IBV_SEND_SIGNALED;
        ibv_wr_send(qpx);
        mlx5dv_wr_set_dc_addr(dvx, ah, target->qp_num, test_key);
        ibv_wr_set_sge(qpx, mr->lkey, (uintptr_t)data, 1);
        uint8_t record[104] = {0};
        memcpy(record + 40, (uint8_t *)direct.sq.buf + offset, 64);
        /* Never emit the DC access key, even though this test uses a dummy. */
        memset(record + 40 + 16, 0, 8);
        check(ibv_wr_complete(qpx), "DC send submission");
        await_pair(cq, 200 + i, 100 + i, dci->qp_num, target->qp_num);
        if (data[64] != data[0])
            fail("DC receive payload validation");
        put32(record, dci->qp_num);
        put32(record + 4, target->qp_num);
        put32(record + 8, labels[i]);
        record[12] = index;
        record[13] = port;
        record[14] = av.grh.traffic_class;
        record[15] = av.sl;
        record[16] = av.grh.hop_limit;
        memcpy(record + 24, gid.gid.raw, 16);
        if (fwrite(record, sizeof(record), 1, stdout) != 1)
            fail("private record pipe");
        check(ibv_destroy_ah(ah), "AH destruction");
    }
    /* Keep the DCI alive while the observer drains and validates the batch. */
    if (controlled)
        control_wait(NULL, 'd');
    check(ibv_destroy_qp(dci), "DCI destruction");
    if (controlled)
        control_wait("retired", 'x');
    for (unsigned i = 0; i < 2; ++i)
        check(ibv_destroy_qp(dct[i]), "DCT destruction");
    check(ibv_dereg_mr(mr), "MR deregistration");
    check(ibv_destroy_srq(srq), "SRQ destruction");
    check(ibv_destroy_cq(cq), "CQ destruction");
    check(ibv_dealloc_pd(pd), "PD deallocation");
    check(ibv_close_device(ctx), "device close");
    ibv_free_device_list(devices);
    return fflush(stdout) == 0 ? 0 : 1;
}
