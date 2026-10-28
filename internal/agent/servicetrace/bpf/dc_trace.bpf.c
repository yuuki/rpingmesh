// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Experimental libmlx5 extended-WR collector. No kernel/RDMA CO-RE types. */
#include "vmlinux_min.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define MAX_BATCH 16

struct dc_layout {
    __u32 qp_base, qp_num, qp_type, context_fd;
    __u32 dc_type, sq_start, sq_count, sq_shift, sq_post, post_rollback, requests;
    __u32 create_mask, create_dc_type;
    __u32 attr_state, attr_port, attr_av_port;
};
struct dc_config { __u32 pid; struct dc_layout layout; };
struct dc_identity { __u64 token; __u32 qpn; __s32 fd; __u32 port, state; };
struct dc_batch {
    __u64 qp;
    struct dc_identity identity;
    __u32 count, stream_channels;
    __u8 prefix[MAX_BATCH][64];
};
struct dc_create_pending { __s32 fd; };
struct dc_modify_pending { __u64 qp; struct dc_identity identity; };
struct ucx_dc_layout {
    __u32 ep_interface, ep_dci, interface_buffer, interface_length;
    __u32 dci_wq, wq_type, wq_qp, wq_qpn;
    __u32 wq_start, wq_end, wq_current, wq_db;
    __u32 wq_previous, wq_producer;
    __u32 wq_devx_object, wq_devx_buffer, interface_port;
    __u32 devx_context, devx_qpn, devx_enabled;
    __u32 ep_channel, streams_enabled;
};
struct dc_devx_queue { __u64 token, start, end, db; __u32 channels, reserved; };
struct dc_devx_create_pending { __u64 result; __u32 channels, reserved; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
    __type(key, __u64); __type(value, struct dc_devx_queue); } dc_devx_queues SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, struct dc_devx_create_pending); } dc_devx_creating SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, struct dc_modify_pending); } dc_devx_connecting SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct ucx_dc_layout); } dc_ucx_layout SEC(".maps");
struct dc_ucx_call { __u64 ep; __u32 kind, depth, invalid, opcode; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, struct dc_ucx_call); } dc_ucx_pending SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct dc_config); } dc_settings SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 11);
    __type(key, __u32); __type(value, __u64); } dc_stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64); } dc_epoch SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64); } dc_sequence SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
    __type(key, __u64); __type(value, struct dc_identity); } dc_qps SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, struct dc_create_pending); } dc_creating SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, struct dc_modify_pending); } dc_modifying SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u64); __type(value, struct dc_batch); } dc_pending SEC(".maps");
/* A per-CPU scratch record keeps the bounded batch off the 512-byte stack. */
struct { __uint(type, 6 /* BPF_MAP_TYPE_PERCPU_ARRAY */); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct dc_batch); } dc_scratch SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } dc_events SEC(".maps");

static __always_inline void count(__u32 index)
{
    __u64 *v = bpf_map_lookup_elem(&dc_stats, &index);
    if (v) __sync_fetch_and_add(v, 1);
}
static __always_inline struct dc_layout *layout(void)
{
    __u32 zero = 0;
    struct dc_config *c = bpf_map_lookup_elem(&dc_settings, &zero);
    if (!c || c->pid != bpf_get_current_pid_tgid() >> 32)
        return 0;
    return &c->layout;
}
#define READ(dst, base, off) bpf_probe_read_user(&(dst), sizeof(dst), (void *)((__u64)(base) + (off)))

static __always_inline bool current(struct dc_identity *id)
{
    __u32 zero = 0;
    __u64 *epoch = bpf_map_lookup_elem(&dc_epoch, &zero);
    return id && epoch && id->token > *epoch;
}

static __always_inline __u64 next_token(void)
{
    __u32 zero = 0;
    __u64 *sequence = bpf_map_lookup_elem(&dc_sequence, &zero);
    return sequence ? __sync_fetch_and_add(sequence, 1) + 1 : 0;
}

static long clear_entry(void *map, const void *key, void *value, void *context)
{
    bpf_map_delete_elem(map, key);
    return 0;
}

static __always_inline void invalidate_process(void)
{
    __u32 zero = 0;
    __u64 epoch = next_token();
    bpf_map_update_elem(&dc_epoch, &zero, &epoch, BPF_ANY);
    bpf_for_each_map_elem(&dc_qps, clear_entry, 0, 0);
    bpf_for_each_map_elem(&dc_creating, clear_entry, 0, 0);
    bpf_for_each_map_elem(&dc_modifying, clear_entry, 0, 0);
    bpf_for_each_map_elem(&dc_pending, clear_entry, 0, 0);
    bpf_for_each_map_elem(&dc_ucx_pending, clear_entry, 0, 0);
    bpf_for_each_map_elem(&dc_devx_queues, clear_entry, 0, 0);
    bpf_for_each_map_elem(&dc_devx_creating, clear_entry, 0, 0);
    bpf_for_each_map_elem(&dc_devx_connecting, clear_entry, 0, 0);
}

SEC("raw_tracepoint/sched_process_exit")
int dc_exit(void *ctx)
{
    __u32 zero = 0;
    struct dc_config *c = bpf_map_lookup_elem(&dc_settings, &zero);
    __u64 task = bpf_get_current_pid_tgid();
    if (!c || !c->pid || c->pid != task >> 32) return 0;
    /* A worker can exit inside a callback without reaching any return probe.
     * Drop its pending calls before TID reuse, but keep shared QP lifetimes. */
    bpf_map_delete_elem(&dc_creating, &task);
    bpf_map_delete_elem(&dc_modifying, &task);
    bpf_map_delete_elem(&dc_pending, &task);
    bpf_map_delete_elem(&dc_ucx_pending, &task);
    bpf_map_delete_elem(&dc_devx_creating, &task);
    bpf_map_delete_elem(&dc_devx_connecting, &task);
    /* Disable before the leader's PID can be reused. Leader-only exit while
     * workers survive conservatively ends tracking as well. */
    if (c->pid == (__u32)task) {
        c->pid = 0;
        invalidate_process();
    }
    return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int dc_exec(void *ctx)
{
    if (!layout()) return 0;
    /* exec has removed sibling threads and has not entered the new image. */
    invalidate_process();
    return 0;
}

SEC("uprobe")
int dc_create_enter(struct pt_regs *ctx)
{
    struct dc_layout *l = layout();
    if (!l) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&dc_creating, &task);
    __u64 attrs = PT_REGS_PARM3(ctx), mask = 0;
    __u32 type = 0;
    struct dc_create_pending p = {};
    if (!attrs) return 0;
    if (READ(mask, attrs, l->create_mask) || READ(type, attrs, l->create_dc_type) ||
        READ(p.fd, PT_REGS_PARM1(ctx), l->context_fd)) { count(3); return 0; }
    /* DC type DCI=2, MASK_DC=2. Reject streams, including stream zero. */
    if (!(mask & 2) || mask & 8 || type != 2 || p.fd < 0) { count(2); return 0; }
    if (bpf_map_update_elem(&dc_creating, &task, &p, BPF_ANY)) count(4);
    return 0;
}

SEC("uretprobe")
int dc_create_exit(struct pt_regs *ctx)
{
    struct dc_layout *l = layout();
    if (!l) return 0;
    __u64 task = bpf_get_current_pid_tgid(), qp = PT_REGS_RC(ctx);
    struct dc_create_pending *p = bpf_map_lookup_elem(&dc_creating, &task);
    if (!p) return 0;
    struct dc_identity id = {.fd = p->fd};
    bpf_map_delete_elem(&dc_creating, &task);
    if (!qp || qp < l->qp_base) return 0;
    __u32 type = 0, dc_type = 0;
    if (READ(id.qpn, qp, l->qp_num) || READ(type, qp, l->qp_type) ||
        READ(dc_type, qp - l->qp_base, l->dc_type)) { count(3); return 0; }
    if (type != 255 || dc_type != 2 || !id.qpn || id.qpn > 0xffffff) { count(2); return 0; }
    /* One atomic sequence distinguishes all lifetimes across CPUs and exec. */
    id.token = next_token();
    count(7);
    if (!id.token || bpf_map_update_elem(&dc_qps, &qp, &id, BPF_ANY)) {
        bpf_map_delete_elem(&dc_qps, &qp); count(4);
    }
    return 0;
}

/* Retire before destruction/override attempts. A failed attempt may cause a
 * false negative, but must never leave an unverified AV-port mapping active. */
SEC("uprobe")
int dc_retire(struct pt_regs *ctx)
{
    if (!layout()) return 0;
    __u64 qp = PT_REGS_PARM1(ctx);
    if (!bpf_map_delete_elem(&dc_qps, &qp)) count(6);
    bpf_map_delete_elem(&dc_devx_queues, &qp);
    return 0;
}

SEC("uprobe")
int dc_modify_enter(struct pt_regs *ctx)
{
    struct dc_layout *l = layout();
    if (!l) return 0;
    __u64 task = bpf_get_current_pid_tgid(), qp = PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&dc_modifying, &task);
    struct dc_identity *id = bpf_map_lookup_elem(&dc_qps, &qp);
    if (!current(id)) return 0;
    /* Post-RTS mutations can race a submission and change its interpretation.
     * Conservatively require a newly created DCI after any such attempt. */
    if (id->state == 3) {
        bpf_map_delete_elem(&dc_qps, &qp); count(6); return 0;
    }
    struct dc_modify_pending p = {.qp = qp, .identity = *id};
    __u64 attrs = PT_REGS_PARM2(ctx);
    __u32 mask = PT_REGS_PARM3(ctx);
    __u8 port = 0;
    if (mask & 1) {
        if (READ(p.identity.state, attrs, l->attr_state)) goto failed;
        if (p.identity.state == 0 || p.identity.state == 6) {
            bpf_map_delete_elem(&dc_qps, &qp); count(6); return 0;
        }
    }
    if (mask & 32) {
        if (READ(port, attrs, l->attr_port)) goto failed;
        p.identity.port = port;
    }
    if (mask & 128) {
        if (READ(port, attrs, l->attr_av_port)) goto failed;
        p.identity.port = port;
    }
    if (bpf_map_update_elem(&dc_modifying, &task, &p, BPF_ANY)) {
        bpf_map_delete_elem(&dc_qps, &qp); count(4);
    }
    return 0;
failed:
    bpf_map_delete_elem(&dc_qps, &qp); count(3); return 0;
}

SEC("uretprobe")
int dc_modify_exit(struct pt_regs *ctx)
{
    if (!layout()) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    struct dc_modify_pending *p = bpf_map_lookup_elem(&dc_modifying, &task);
    if (!p) return 0;
    struct dc_identity *id = bpf_map_lookup_elem(&dc_qps, &p->qp);
    if (!PT_REGS_RC(ctx) && current(id) && id->token == p->identity.token)
        if (bpf_map_update_elem(&dc_qps, &p->qp, &p->identity, BPF_ANY)) {
            bpf_map_delete_elem(&dc_qps, &p->qp); count(4);
        }
    bpf_map_delete_elem(&dc_modifying, &task);
    return 0;
}

SEC("uprobe")
int dc_complete_enter(struct pt_regs *ctx)
{
    struct dc_layout *l = layout();
    if (!l) return 0;
    __u64 task = bpf_get_current_pid_tgid(), qp = PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&dc_pending, &task);
    struct dc_identity *id = bpf_map_lookup_elem(&dc_qps, &qp);
    if (!current(id) || !id->port || id->state != 3 || qp < l->qp_base) return 0;
    __u64 mqp = qp - l->qp_base, start = 0;
    __u32 nreq = 0, count_wq = 0, shift = 0, first = 0, last = 0;
    if (READ(nreq, mqp, l->requests) || READ(start, mqp, l->sq_start) ||
        READ(count_wq, mqp, l->sq_count) || READ(shift, mqp, l->sq_shift) ||
        READ(first, mqp, l->post_rollback) || READ(last, mqp, l->sq_post)) { count(3); return 0; }
    if (!nreq) return 0;
    __u32 remaining = last - first;
    if (nreq > MAX_BATCH || !start || !count_wq || count_wq > (1 << 20) ||
        (count_wq & (count_wq - 1)) || shift != 6 || !remaining || remaining > count_wq) {
        count(2); return 0;
    }
    __u32 zero = 0;
    struct dc_batch *b = bpf_map_lookup_elem(&dc_scratch, &zero);
    if (!b) { count(4); return 0; }
    /* Volatile stores prevent clang from lowering this into an unsupported
     * out-of-line memset. Clear unused slots as well as the redacted keys. */
    for (__u32 i = 0; i < sizeof(b->prefix) / 8; i++)
        ((volatile __u64 *)b->prefix)[i] = 0;
    b->stream_channels = 0;
    b->qp = qp; b->identity = *id; b->count = nreq;
    for (__u32 i = 0; i < MAX_BATCH; i++) {
        if (i >= nreq) break;
        __u64 wqe = start + ((__u64)(first & (count_wq - 1)) << 6);
        /* The extended AV fits in one WQEBB. Never read/export its DC key. */
        if (bpf_probe_read_user(b->prefix[i], 12, (void *)wqe) ||
            bpf_probe_read_user(b->prefix[i] + 24, 40, (void *)(wqe + 24))) { count(3); return 0; }
        __u32 ctrl, qpn_ds;
        __builtin_memcpy(&ctrl, b->prefix[i], 4);
        __builtin_memcpy(&qpn_ds, b->prefix[i] + 4, 4);
        ctrl = __builtin_bswap32(ctrl); qpn_ds = __builtin_bswap32(qpn_ds);
        __u32 blocks = ((qpn_ds & 63) + 3) >> 2;
        if ((qpn_ds >> 8) != id->qpn || ((ctrl >> 8) & 0xffff) != (first & 0xffff) ||
            (qpn_ds & 192) || (qpn_ds & 63) < 4 || !blocks || blocks > remaining) { count(2); return 0; }
        first += blocks; remaining -= blocks;
    }
    if (remaining) { count(2); return 0; }
    if (bpf_map_update_elem(&dc_pending, &task, b, BPF_ANY)) count(4);
    return 0;
}

SEC("uretprobe")
int dc_complete_exit(struct pt_regs *ctx)
{
    if (!layout()) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    struct dc_batch *b = bpf_map_lookup_elem(&dc_pending, &task);
    if (!b) return 0;
    struct dc_identity *id = bpf_map_lookup_elem(&dc_qps, &b->qp);
    if (PT_REGS_RC(ctx)) count(1);
    else if (current(id) && id->token == b->identity.token && id->port == b->identity.port && id->state == 3) {
        if (bpf_ringbuf_output(&dc_events, b, sizeof(*b), 0)) count(5);
        else count(0);
    }
    bpf_map_delete_elem(&dc_pending, &task);
    return 0;
}

/* The supported UCX entry points each submit one WQE before returning their
 * documented success value. A pack callback may reenter UCT: reject the whole
 * nested call group rather than attribute its last WQE to the wrong call. */
static __always_inline int ucx_enter(struct pt_regs *ctx, __u32 kind, __u32 opcode)
{
    if (!layout()) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    struct dc_ucx_call *pending = bpf_map_lookup_elem(&dc_ucx_pending, &task);
    if (pending) {
        pending->depth++;
        pending->invalid = 1;
        return 0;
    }
    struct dc_ucx_call call = {.ep = PT_REGS_PARM1(ctx), .kind = kind, .depth = 1, .opcode = opcode};
    if (bpf_map_update_elem(&dc_ucx_pending, &task, &call, BPF_ANY)) count(4);
    return 0;
}
SEC("uprobe")
int dc_ucx_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 0, 0x0a); }
SEC("uprobe")
int dc_ucx_bcopy_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 1, 0x0a); }
SEC("uprobe")
int dc_ucx_zcopy_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 2, 0x0a); }

SEC("uprobe")
int dc_ucx_put_short_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 0, 0x08); }
SEC("uprobe")
int dc_ucx_put_bcopy_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 1, 0x08); }
SEC("uprobe")
int dc_ucx_put_zcopy_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 2, 0x08); }
SEC("uprobe")
int dc_ucx_get_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 2, 0x10); }

/* Tag eager sends use SEND_IMM only for a nonzero immediate value.
 * Retain only that decision, never the immediate or tag itself. */
SEC("uprobe")
int dc_ucx_tag_bcopy_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 1, PT_REGS_PARM3(ctx) ? 0x0b : 0x0a); }
SEC("uprobe")
int dc_ucx_tag_zcopy_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 2, PT_REGS_PARM3(ctx) ? 0x0b : 0x0a); }
SEC("uprobe")
int dc_ucx_tag_request_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 0, 0x0b); }
SEC("uprobe")
int dc_ucx_tag_rndv_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 3, 0x0a); }

/* UCX atomic operation enum: ADD, AND, OR, XOR, SWAP. Compare-and-swap
 * has separate entry points. Only opcode/size metadata is retained. */
static __always_inline __u32 ucx_atomic_opcode(struct pt_regs *ctx, int wide, int fetch)
{
    __u32 op = PT_REGS_PARM2(ctx);
    if (op > (fetch ? 4 : 3)) return 0xffffffff;
    if (op == 0 && wide) return 0x12;
    __u32 mod = wide ? 9 : 8;
    return (mod << 24) | ((op == 0 || op == 3) ? 0x15 : 0x14);
}
SEC("uprobe")
int dc_ucx_atomic32_post_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 0, ucx_atomic_opcode(ctx, 0, 0)); }
SEC("uprobe")
int dc_ucx_atomic64_post_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 0, ucx_atomic_opcode(ctx, 1, 0)); }
SEC("uprobe")
int dc_ucx_atomic32_fetch_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 2, ucx_atomic_opcode(ctx, 0, 1)); }
SEC("uprobe")
int dc_ucx_atomic64_fetch_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 2, ucx_atomic_opcode(ctx, 1, 1)); }
SEC("uprobe")
int dc_ucx_atomic_cswap32_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 2, 0x08000014); }
SEC("uprobe")
int dc_ucx_atomic_cswap64_enter(struct pt_regs *ctx) { return ucx_enter(ctx, 2, 0x11); }

SEC("uretprobe")
int dc_ucx_exit(struct pt_regs *ctx)
{
    struct dc_layout *l = layout();
    if (!l) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    struct dc_ucx_call *pending = bpf_map_lookup_elem(&dc_ucx_pending, &task);
    if (!pending) return 0;
    if (pending->depth > 1) { pending->depth--; return 0; }
    __u64 ep = pending->ep;
    __u32 kind = pending->kind, invalid = pending->invalid, opcode = pending->opcode;
    bpf_map_delete_elem(&dc_ucx_pending, &task);
    if (invalid) { count(2); return 0; }
    /* Tag rendezvous returns a uint32 operation ID (zero is valid), or a
     * sign-extended error pointer. This is submission, not transfer completion.
     * Atomic post returns UCS_OK; atomic fetch/cswap returns UCS_INPROGRESS.
     * AM/put bcopy returns a signed ssize_t length (including zero);
     * zcopy and get-bcopy return
     * UCS_INPROGRESS after submission, not a completed operation. */
    __u64 result = PT_REGS_RC(ctx);
    if ((kind == 0 && (__s32)result != 0) ||
        (kind == 1 && (__s64)result < 0) ||
        (kind == 2 && (__s32)result != 1) ||
        (kind == 3 && result > 0xffffffffULL)) { count(1); return 0; }
    __u32 zero = 0;
    struct ucx_dc_layout *u = bpf_map_lookup_elem(&dc_ucx_layout, &zero);
    if (!u) { count(4); return 0; }
    __u64 iface = 0, array = 0, dci = 0, qp = 0;
    __u16 index = 0, length = 0;
    if (READ(iface, ep, u->ep_interface) || READ(index, ep, u->ep_dci) ||
        READ(array, iface, u->interface_buffer) || READ(length, iface, u->interface_length)) goto read_failed;
    if (!array || index >= length || index >= 4096) goto unsupported;
    if (READ(dci, array, (__u64)index * 8)) goto read_failed;
    if (!dci) goto unsupported;
    __u64 wq = dci + u->dci_wq;
    __u32 type = 0, qpn = 0;
    if (READ(type, wq, u->wq_type)) goto read_failed;
    if (type > 1 || (type == 1 && !u->devx_enabled)) goto unsupported;
    if (READ(qp, wq, type == 1 ? u->wq_devx_object : u->wq_qp) || READ(qpn, wq, u->wq_qpn)) goto read_failed;
    struct dc_identity *id = bpf_map_lookup_elem(&dc_qps, &qp);
    if (!current(id) || !id->port || id->state != 3 || id->qpn != qpn || (type == 0 && qp < l->qp_base)) goto unsupported;
    __u64 start = 0, end = 0, curr = 0, db = 0, provider_start = 0;
    __u32 db_value = 0, blocks = 0, shift = 0, channels = 0;
    __u16 previous = 0, producer = 0;
    if (READ(start, wq, u->wq_start) || READ(end, wq, u->wq_end) ||
        READ(curr, wq, u->wq_current) || READ(db, wq, u->wq_db) ||
        READ(previous, wq, u->wq_previous) || READ(producer, wq, u->wq_producer) ||
        READ(db_value, db, 0)) goto read_failed;
    if (type == 1) {
        struct dc_devx_queue *saved = bpf_map_lookup_elem(&dc_devx_queues, &qp);
        if (!saved || saved->token != id->token || saved->start != start || saved->end != end || saved->db != db) goto unsupported;
        if (READ(provider_start, wq, u->wq_devx_buffer)) goto read_failed;
        channels = saved->channels > 1 ? saved->channels : 0;
        if (channels && !u->streams_enabled) goto unsupported;
        blocks = (end - start) >> 6;
        shift = 6;
    } else if (READ(provider_start, qp - l->qp_base, l->sq_start) ||
               READ(blocks, qp - l->qp_base, l->sq_count) || READ(shift, qp - l->qp_base, l->sq_shift)) goto read_failed;
    __u16 posted = producer - previous;
    if (!start || start != provider_start || !blocks || blocks > (1 << 16) ||
        (blocks & (blocks - 1)) || shift != 6 || end - start != (__u64)blocks * 64 ||
        !posted || posted > 4 || (__u16)__builtin_bswap32(db_value) != producer ||
        curr != start + ((__u64)(producer & (blocks - 1)) << 6)) goto unsupported;
    struct dc_batch *b = bpf_map_lookup_elem(&dc_scratch, &zero);
    if (!b) { count(4); return 0; }
    for (__u32 i = 0; i < sizeof(b->prefix) / 8; i++)
        ((volatile __u64 *)b->prefix)[i] = 0;
    b->qp = qp; b->identity = *id; b->count = 1; b->stream_channels = channels;
    __u64 wqe = start + ((__u64)(previous & (blocks - 1)) << 6);
    /* Never read immediate data, the DC access key, remote address/rkey,
     * tag headers, atomic operands or payload. */
    if (bpf_probe_read_user(b->prefix[0], 12, (void *)wqe) ||
        bpf_probe_read_user(b->prefix[0] + 24, 40, (void *)(wqe + 24))) goto read_failed;
    __u32 ctrl, qpn_ds;
    __builtin_memcpy(&ctrl, b->prefix[0], 4);
    __builtin_memcpy(&qpn_ds, b->prefix[0] + 4, 4);
    ctrl = __builtin_bswap32(ctrl); qpn_ds = __builtin_bswap32(qpn_ds);
    __u32 op = opcode & 255;
    __u32 atomic_ds = opcode == 0x09000014 ? 8 : 7;
    if (op >= 0x11 && (qpn_ds & 63) != atomic_ds) goto unsupported;
    if ((ctrl & 0xff0000ff) != opcode || ((ctrl >> 8) & 0xffff) != previous ||
        (qpn_ds >> 8) != qpn || (qpn_ds & 192) || (qpn_ds & 63) < ((opcode == 0x0a || opcode == 0x0b) ? 4 : 5) ||
        ((qpn_ds & 63) + 3) / 4 != posted) goto unsupported;
    __u16 channel = ((__u16)b->prefix[0][9] << 8) | b->prefix[0][10];
    if (channels) {
        __u8 expected = 0;
        if (READ(expected, ep, u->ep_channel)) goto read_failed;
        if (channel >= channels || channel != expected) goto unsupported;
    } else if (channel) goto unsupported;
    if (bpf_ringbuf_output(&dc_events, b, sizeof(*b), 0)) count(5);
    else { count(0); count(8); if (type == 1) count(9); }
    return 0;
read_failed:
    count(3); return 0;
unsupported:
    count(2); return 0;
}

/* Register successful UCX DCI creations with validated channel counts.
 * The opaque DevX object's layout comes from matching libmlx5 DWARF. */
SEC("uprobe")
int dc_devx_create_enter(struct pt_regs *ctx)
{
    if (!layout()) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    __u32 zero = 0, channels = (__u8)PT_REGS_PARM3(ctx);
    struct ucx_dc_layout *u = bpf_map_lookup_elem(&dc_ucx_layout, &zero);
    bpf_map_delete_elem(&dc_devx_creating, &task);
    if (!u || !channels || (channels & (channels - 1)) ||
        (channels != 1 && !u->streams_enabled)) { count(2); return 0; }
    struct dc_devx_create_pending p = {.result = PT_REGS_PARM4(ctx), .channels = channels};
    if (bpf_map_update_elem(&dc_devx_creating, &task, &p, BPF_ANY)) count(4);
    return 0;
}

SEC("uretprobe")
int dc_devx_create_exit(struct pt_regs *ctx)
{
    struct dc_layout *l = layout();
    if (!l) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    struct dc_devx_create_pending *pending = bpf_map_lookup_elem(&dc_devx_creating, &task);
    if (!pending) return 0;
    __u64 result = pending->result;
    __u32 channels = pending->channels;
    bpf_map_delete_elem(&dc_devx_creating, &task);
    if (PT_REGS_RC(ctx)) return 0;
    __u32 zero = 0;
    struct ucx_dc_layout *u = bpf_map_lookup_elem(&dc_ucx_layout, &zero);
    if (!u || !u->devx_enabled) return 0;
    __u64 dci = 0, obj = 0, context = 0, buffer = 0;
    __u32 type = 0, qpn = 0;
    struct dc_identity id = {};
    struct dc_devx_queue queue = {.channels = channels};
    if (READ(dci, result, 0)) goto failed;
    __u64 wq = dci + u->dci_wq;
    if (READ(type, wq, u->wq_type)) goto failed;
    if (type != 1) return 0;
    if (READ(obj, wq, u->wq_devx_object) || READ(id.qpn, wq, u->wq_qpn) ||
        READ(context, obj, u->devx_context) || READ(qpn, obj, u->devx_qpn) ||
        READ(id.fd, context, l->context_fd) || READ(buffer, wq, u->wq_devx_buffer) ||
        READ(queue.start, wq, u->wq_start) || READ(queue.end, wq, u->wq_end) ||
        READ(queue.db, wq, u->wq_db)) goto failed;
    __u64 bytes = queue.end - queue.start;
    if (!obj || !id.qpn || id.qpn > 0xffffff || qpn != id.qpn || id.fd < 0 ||
        !buffer || buffer != queue.start || !queue.db || bytes < 64 || bytes > (1 << 22) ||
        (bytes & (bytes - 1))) { count(2); return 0; }
    id.token = next_token(); queue.token = id.token;
    if (!id.token || bpf_map_update_elem(&dc_devx_queues, &obj, &queue, BPF_ANY) ||
        bpf_map_update_elem(&dc_qps, &obj, &id, BPF_ANY)) {
        bpf_map_delete_elem(&dc_devx_queues, &obj);
        bpf_map_delete_elem(&dc_qps, &obj); count(4); return 0;
    }
    count(7); count(10);
    return 0;
failed:
    count(3); return 0;
}

SEC("uprobe")
int dc_devx_connect_enter(struct pt_regs *ctx)
{
    if (!layout()) return 0;
    __u32 zero = 0;
    struct ucx_dc_layout *u = bpf_map_lookup_elem(&dc_ucx_layout, &zero);
    if (!u || !u->devx_enabled) return 0;
    __u64 task = bpf_get_current_pid_tgid(), dci = PT_REGS_PARM2(ctx), obj = 0;
    bpf_map_delete_elem(&dc_devx_connecting, &task);
    __u32 type = 0;
    if (READ(type, dci + u->dci_wq, u->wq_type)) { count(3); return 0; }
    if (type != 1) return 0;
    if (READ(obj, dci + u->dci_wq, u->wq_devx_object)) { count(3); return 0; }
    struct dc_identity *id = bpf_map_lookup_elem(&dc_qps, &obj);
    if (!current(id)) return 0;
    if (id->state != 0) goto retire;
    struct dc_modify_pending p = {.qp = obj, .identity = *id};
    __u8 port = 0;
    if (READ(port, PT_REGS_PARM1(ctx), u->interface_port)) { count(3); goto retire; }
    if (!port) goto retire;
    p.identity.port = port; p.identity.state = 3;
    if (bpf_map_update_elem(&dc_devx_connecting, &task, &p, BPF_ANY)) { count(4); goto retire; }
    id->state = 1; /* Only this task's initial connect may modify the object. */
    return 0;
retire:
    bpf_map_delete_elem(&dc_devx_queues, &obj);
    bpf_map_delete_elem(&dc_qps, &obj); count(6); return 0;
}

SEC("uretprobe")
int dc_devx_connect_exit(struct pt_regs *ctx)
{
    if (!layout()) return 0;
    __u64 task = bpf_get_current_pid_tgid();
    struct dc_modify_pending *p = bpf_map_lookup_elem(&dc_devx_connecting, &task);
    if (!p) return 0;
    struct dc_identity *id = bpf_map_lookup_elem(&dc_qps, &p->qp);
    if (current(id) && id->token == p->identity.token) {
        if (PT_REGS_RC(ctx) || id->state != 1) {
            bpf_map_delete_elem(&dc_devx_queues, &p->qp);
            bpf_map_delete_elem(&dc_qps, &p->qp); count(6);
        } else if (bpf_map_update_elem(&dc_qps, &p->qp, &p->identity, BPF_ANY)) {
            bpf_map_delete_elem(&dc_devx_queues, &p->qp);
            bpf_map_delete_elem(&dc_qps, &p->qp); count(4);
        }
    }
    bpf_map_delete_elem(&dc_devx_connecting, &task);
    return 0;
}

SEC("uprobe")
int dc_devx_modify(struct pt_regs *ctx)
{
    if (!layout()) return 0;
    __u64 obj = PT_REGS_PARM1(ctx), task = bpf_get_current_pid_tgid();
    struct dc_identity *id = bpf_map_lookup_elem(&dc_qps, &obj);
    if (!current(id)) return 0;
    struct dc_modify_pending *p = bpf_map_lookup_elem(&dc_devx_connecting, &task);
    if (id->state == 1 && p && p->qp == obj && p->identity.token == id->token) return 0;
    /* All other modification attempts retire even if the command fails. */
    bpf_map_delete_elem(&dc_devx_queues, &obj);
    bpf_map_delete_elem(&dc_qps, &obj); count(6);
    return 0;
}
