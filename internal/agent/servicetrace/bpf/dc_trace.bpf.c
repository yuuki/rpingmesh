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
    __u32 count, reserved;
    __u8 prefix[MAX_BATCH][64];
};
struct dc_create_pending { __s32 fd; };
struct dc_modify_pending { __u64 qp; struct dc_identity identity; };

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct dc_config); } dc_settings SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 8);
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
}

SEC("raw_tracepoint/sched_process_exit")
int dc_exit(void *ctx)
{
    __u32 zero = 0;
    struct dc_config *c = bpf_map_lookup_elem(&dc_settings, &zero);
    __u64 task = bpf_get_current_pid_tgid();
    /* Disable before the leader's PID can be reused. Leader-only exit while
     * workers survive conservatively ends tracking as well. */
    if (c && c->pid && c->pid == task >> 32 && c->pid == (__u32)task) {
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
    b->reserved = 0;
    b->qp = qp; b->identity = *id; b->count = nreq;
    for (__u32 i = 0; i < MAX_BATCH; i++) {
        if (i >= nreq) break;
        __u64 wqe = start + ((__u64)(first & (count_wq - 1)) << 6);
        /* The extended AV fits in one WQEBB. Never read/export its DC key. */
        if (bpf_probe_read_user(b->prefix[i], 16, (void *)wqe) ||
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
