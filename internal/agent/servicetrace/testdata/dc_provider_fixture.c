/* Synthetic provider ABI for layout and user-run uprobe integration tests.
 * No RDMA hardware, real identities, provider offsets or access keys. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct ibv_context { uint64_t padding; int cmd_fd; };
struct ibv_qp { struct ibv_context *context; uint32_t qp_num; int qp_type; };
struct ibv_qp_ex { struct ibv_qp qp_base; };
struct verbs_qp { union { struct ibv_qp qp; struct ibv_qp_ex qp_ex; }; uint64_t padding; };
struct mlx5_wq { uint64_t padding; unsigned wqe_cnt; int wqe_shift; unsigned cur_post; };
struct mlx5_qp {
    uint64_t padding[3]; struct verbs_qp verbs_qp; int dc_type;
    void *sq_start; struct mlx5_wq sq; unsigned cur_post_rb; int nreq;
};
struct mlx5dv_qp_init_attr { uint64_t comp_mask; struct { int dc_type; } dc_init_attr; };
struct ibv_qp_attr { int qp_state; uint8_t port_num; struct { uint64_t padding; uint8_t port_num; } ah_attr; };
static struct mlx5_qp storage;
static unsigned char queue[64][64];
static int failure;

/* Deliberately synthetic UCX layouts; no copied production offsets. */
struct uct_ib_mlx5_txwq {
    struct { int type; uint32_t qp_num; struct { struct ibv_qp *qp; } verbs; } super;
    uint16_t sw_pi, prev_sw_pi;
    void *qstart, *qend, *curr;
    uint32_t *dbrec;
};
struct uct_dc_dci { uint64_t padding; struct uct_ib_mlx5_txwq txwq; };
struct uct_dc_mlx5_iface {
    struct { struct { struct { struct { struct { uint64_t padding; } super; } super; } super; } super; } super;
    struct { struct { struct uct_dc_dci **buffer; uint16_t length; } dcis; } tx;
};
struct uct_dc_mlx5_ep {
    struct { struct { struct uct_dc_mlx5_iface *iface; } super; } super;
    uint64_t padding;
#ifdef TEST_UCX_BAD_DCI
    uint32_t dci;
#else
    uint16_t dci;
#endif
};
static struct uct_dc_dci ucx_dci;
static struct uct_dc_dci *ucx_array[] = {&ucx_dci};
static struct uct_dc_mlx5_iface ucx_iface;
static struct uct_dc_mlx5_ep ucx_ep;
static uint32_t ucx_db;
static int ucx_mode;

__attribute__((noinline)) struct ibv_qp *mlx5dv_create_qp(struct ibv_context *ctx, void *unused,
                                                       struct mlx5dv_qp_init_attr *attr)
{
    (void)unused;
    memset(&storage, 0, sizeof(storage));
    storage.verbs_qp.qp = (struct ibv_qp){.context = ctx, .qp_num = 0x12345, .qp_type = 255};
    storage.dc_type = attr->dc_init_attr.dc_type;
    storage.sq_start = queue; storage.sq.wqe_cnt = 64; storage.sq.wqe_shift = 6;
    return &storage.verbs_qp.qp;
}
__attribute__((noinline)) int mlx5_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int mask)
{ (void)qp; (void)attr; (void)mask; return 0; }
__attribute__((noinline)) int mlx5_destroy_qp(struct ibv_qp *qp)
{ (void)qp; return 0; }
__attribute__((noinline)) int mlx5dv_modify_qp_udp_sport(struct ibv_qp *qp, uint16_t sport)
{ (void)qp; (void)sport; return 0; }
__attribute__((noinline)) int mlx5dv_devx_qp_modify(struct ibv_qp *qp, void *in, size_t size)
{ (void)qp; (void)in; (void)size; return 0; }
__attribute__((noinline)) int mlx5_send_wr_complete(struct ibv_qp_ex *qp)
{
    (void)qp;
    if (failure) storage.sq.cur_post = storage.cur_post_rb;
    return failure;
}

static void put32(unsigned char *p, uint32_t v)
{ p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

__attribute__((noinline)) int uct_dc_mlx5_ep_am_short(struct uct_dc_mlx5_ep *ep)
{
    if (ucx_mode == 1) return -2;
    struct uct_ib_mlx5_txwq *wq = &ep->super.super.iface->tx.dcis.buffer[ep->dci]->txwq;
    unsigned pos = storage.sq.cur_post++;
    unsigned char *p = queue[pos % 64];
    memset(p, 0, 64);
    put32(p, ((pos & 0xffff) << 8) | 0x0a);
    put32(p + 4, (0x12345 << 8) | 4);
    memset(p + 16, 0xa5, 8);
    put32(p + 24, 0x80000010);
    p[30] = 0xc1; p[31] = 0x23; p[43] = 64;
    p[58] = 0xff; p[59] = 0xff; p[60] = 192; p[62] = 2; p[63] = 1;
    wq->super.type = ucx_mode == 2;
    wq->super.qp_num = 0x12345 + (ucx_mode == 5);
    wq->super.verbs.qp = &storage.verbs_qp.qp;
    wq->prev_sw_pi = pos; wq->sw_pi = pos + 1;
    wq->qstart = queue; wq->qend = queue + 64;
    wq->curr = queue[(pos + 1) % 64];
    wq->dbrec = &ucx_db;
    put32((unsigned char *)&ucx_db, (uint16_t)(pos + 1 + (ucx_mode == 3)));
    if (ucx_mode == 4) put32(p, (((pos + 1) & 0xffff) << 8) | 0x0a);
    return 0;
}

static void submit(unsigned n, int invalid)
{
    storage.cur_post_rb = storage.sq.cur_post;
    storage.nreq = n;
    for (unsigned i = 0; i < n; ++i) {
        unsigned pos = storage.sq.cur_post++;
        unsigned char *p = queue[pos % 64];
        memset(p, 0, 64);
        put32(p, ((pos & 0xffff) << 8) | 0x0a);
        put32(p + 4, (0x12345 << 8) | 4);
        memset(p + 16, 0xa5, 8); /* Must be redacted by BPF, never exported. */
        put32(p + 24, 0x80000010 + i);
        p[30] = 0xc1; p[31] = 0x23; p[43] = 64;
        p[58] = 0xff; p[59] = 0xff; p[60] = 192; p[62] = 2; p[63] = 1;
        if (invalid) p[10] = 1;
    }
    mlx5_send_wr_complete(&storage.verbs_qp.qp_ex);
}

static void *worker(void *arg)
{
    if (arg) mlx5_destroy_qp(&storage.verbs_qp.qp);
    else submit(2, 0);
    return NULL;
}

static void *exec_worker(void *path)
{
    execl(path, path, "worker-exec", NULL);
    _exit(1);
}

int main(int argc, char **argv)
{
    (void)argc;
    struct ibv_context ctx = {.cmd_fd = open("/dev/null", O_RDONLY | O_CLOEXEC)};
    if (ctx.cmd_fd < 0) return 1;
    alarm(60);
    puts("ready"); fflush(stdout);
    struct ibv_qp *qp = &storage.verbs_qp.qp;
    ucx_iface.tx.dcis.buffer = ucx_array; ucx_iface.tx.dcis.length = 1;
    ucx_ep.super.super.iface = &ucx_iface;
    int op;
    while ((op = getchar()) != EOF) {
        struct ibv_qp_attr attr = {.qp_state = 1, .port_num = 1, .ah_attr.port_num = 1};
        switch (op) {
        case 'c': case 't': {
            struct mlx5dv_qp_init_attr init = {.comp_mask = op == 't' ? 10 : 2, .dc_init_attr.dc_type = 2};
            qp = mlx5dv_create_qp(&ctx, NULL, &init);
            mlx5_modify_qp(qp, &attr, 1 | 32);
            attr.qp_state = 3;
            mlx5_modify_qp(qp, &attr, 1);
            break;
        }
        case 'w': case 'y': {
            pthread_t thread;
            if (pthread_create(&thread, NULL, worker, op == 'y' ? &storage : NULL) ||
                pthread_join(thread, NULL)) return 1;
            break;
        }
        case 's': failure = 0; submit(2, 0); break;
        case 'A': case 'F': case 'D': case 'B': case 'I': case 'Q': case 'W':
            ucx_mode = op == 'F' ? 1 : op == 'D' ? 2 : op == 'B' ? 3 : op == 'I' ? 4 : op == 'Q' ? 5 : 0;
            if (op == 'W') storage.sq.cur_post = 65535;
            uct_dc_mlx5_ep_am_short(&ucx_ep);
            break;
        case 'f': failure = EINVAL; submit(2, 0); failure = 0; break;
        case 'b': submit(17, 0); break;
        case 'v': submit(2, 1); break;
        case 'a': break; /* Aborted batch: no completion callback. */
        case 'r': attr.qp_state = 0; mlx5_modify_qp(qp, &attr, 1); break;
        case 'u': mlx5dv_modify_qp_udp_sport(qp, 0xc123); break;
        case 'z': mlx5dv_devx_qp_modify(qp, NULL, 0); break;
        case 'd': mlx5_destroy_qp(qp); break;
        case 'q': {
            pthread_t thread;
            if (pthread_create(&thread, NULL, exec_worker, argv[0]) ||
                pthread_join(thread, NULL)) return 1;
            break;
        }
        case 'e': execl(argv[0], argv[0], "after-exec", NULL); return 1;
        case 'x': close(ctx.cmd_fd); return 0;
        default: continue;
        }
        puts("done"); fflush(stdout);
    }
    close(ctx.cmd_fd);
    return 0;
}
