// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Optional ib_core CO-RE tracer. Never load this object without module BTF. */
#include "vmlinux_min.h"
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>
#include "trace_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Field offsets are relocated against ib_core, not assumed from this layout.
 * Keep individual reads: copying a whole local struct defeats CO-RE. */
union ib_gid { __u8 raw[16]; } __attribute__((preserve_access_index));
enum ib_qp_type { IB_QPT_RC = 2, IB_QPT_UC = 3, IB_QPT_XRC_INI = 9, IB_QPT_XRC_TGT = 10 };
enum ib_qp_state { IB_QPS_RESET = 0, IB_QPS_RTR = 2, IB_QPS_ERR = 6 };
enum rdma_ah_attr_type { RDMA_AH_ATTR_TYPE_ROCE = 2 };
struct ib_global_route {
	union ib_gid dgid;
	__u32 flow_label;
	__u8 sgid_index, hop_limit, traffic_class;
} __attribute__((preserve_access_index));
struct rdma_ah_attr {
	struct ib_global_route grh;
	__u8 sl;
	__u32 port_num;
	__u8 ah_flags;
	enum rdma_ah_attr_type type;
} __attribute__((preserve_access_index));
struct ib_qp_attr {
	enum ib_qp_state qp_state;
	__u32 dest_qp_num;
	struct rdma_ah_attr ah_attr;
} __attribute__((preserve_access_index));
struct ib_device { char name[64]; } __attribute__((preserve_access_index));
struct ib_qp {
	struct ib_device *device;
	void *uobject;
	__u32 qp_num;
	enum ib_qp_type qp_type;
} __attribute__((preserve_access_index));

struct kernel_event {
	struct qp_event ev;
	char device[64];
};

/* Replaced by the uverbs maps at load time. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct kernel_event);
} kernel_pending SEC(".maps");

static __always_inline void count(__u32 index)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &index);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline int identity(struct kernel_event *e, struct ib_qp *qp)
{
	void *uobject = 0;
	struct ib_device *dev = 0;
	if (BPF_CORE_READ_INTO(&uobject, qp, uobject) ||
	    BPF_CORE_READ_INTO(&dev, qp, device) ||
	    BPF_CORE_READ_INTO(&e->ev.qp_num, qp, qp_num) ||
	    BPF_CORE_READ_INTO(&e->ev.qp_type, qp, qp_type))
		return -1;
	if (uobject || (e->ev.qp_type != 2 && e->ev.qp_type != 3 &&
		       e->ev.qp_type != 9 && e->ev.qp_type != 10))
		return 1;
	if (bpf_core_read_str(e->device, sizeof(e->device), &dev->name) <= 0)
		return -1;
	e->ev.ctx = (__u64)qp;
	e->ev.src = 4; /* SourceKernel */
	/* PID/cgroup deliberately remain zero: a worker is not the ULP owner. */
	return 0;
}

SEC("kprobe/ib_modify_qp")
int kernel_modify_enter(struct pt_regs *ctx)
{
	__u64 task = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&kernel_pending, &task);
	struct ib_qp *qp = (void *)PT_REGS_PARM1(ctx);
	struct ib_qp_attr *attr = (void *)PT_REGS_PARM2(ctx);
	__u32 mask = PT_REGS_PARM3(ctx);
	if (!(mask & 1))
		return 0;
	struct kernel_event e = {};
	int state = 0;
	int result = identity(&e, qp);
	if (result > 0)
		return 0;
	if (result < 0 || BPF_CORE_READ_INTO(&state, attr, qp_state))
		goto failed;
	if (state != 0 && state != 6 && state != 2)
		return 0;
	e.ev.kind = 2;
	e.ev.attr_mask = mask;
	e.ev.qp_state = state;
	if (state == 2) {
		/* Require a complete connected RoCE AV, never uninitialized attrs. */
		if (!(mask & (1 << 7)) || !(mask & (1 << 20)))
			return 0;
		int type = 0;
		__u32 port = 0;
		if (BPF_CORE_READ_INTO(&type, attr, ah_attr.type) ||
		    BPF_CORE_READ_INTO(&port, attr, ah_attr.port_num) ||
		    BPF_CORE_READ_INTO(&e.ev.is_global, attr, ah_attr.ah_flags))
			goto failed;
		if (type != 2 || !(e.ev.is_global & 1) || !port || port > 255)
			return 0;
		e.ev.dest_port_num = port;
		if (BPF_CORE_READ_INTO(&e.ev.dest_qp_num, attr, dest_qp_num) ||
		    BPF_CORE_READ_INTO(&e.ev.flow_label, attr, ah_attr.grh.flow_label) ||
		    BPF_CORE_READ_INTO(&e.ev.sgid_index, attr, ah_attr.grh.sgid_index) ||
		    BPF_CORE_READ_INTO(&e.ev.hop_limit, attr, ah_attr.grh.hop_limit) ||
		    BPF_CORE_READ_INTO(&e.ev.traffic_class, attr, ah_attr.grh.traffic_class) ||
		    BPF_CORE_READ_INTO(&e.ev.sl, attr, ah_attr.sl) ||
		    BPF_CORE_READ_INTO(&e.ev.dgid, attr, ah_attr.grh.dgid.raw))
			goto failed;
	}
	if (bpf_map_update_elem(&kernel_pending, &task, &e, BPF_ANY))
		goto failed;
	return 0;
failed:
	count(1);
	return 0;
}

SEC("kprobe/ib_destroy_qp_user")
int kernel_destroy_enter(struct pt_regs *ctx)
{
	__u64 task = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&kernel_pending, &task);
	struct kernel_event e = {};
	int result = identity(&e, (void *)PT_REGS_PARM1(ctx));
	if (result > 0)
		return 0;
	if (result < 0) {
		count(1);
		return 0;
	}
	e.ev.kind = 3;
	if (bpf_map_update_elem(&kernel_pending, &task, &e, BPF_ANY))
		count(1);
	return 0;
}

static __always_inline int complete(struct pt_regs *ctx, __u32 kind)
{
	__u64 task = bpf_get_current_pid_tgid();
	struct kernel_event *e = bpf_map_lookup_elem(&kernel_pending, &task);
	if (!e)
		return 0;
	if (PT_REGS_RC(ctx) == 0 && e->ev.kind == kind) {
		e->ev.ts_ns = bpf_ktime_get_ns();
		if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
			count(0);
	}
	/* Destroy may have freed qp; never dereference it at return. */
	bpf_map_delete_elem(&kernel_pending, &task);
	return 0;
}

SEC("kretprobe/ib_modify_qp")
int kernel_modify_exit(struct pt_regs *ctx) { return complete(ctx, 2); }
SEC("kretprobe/ib_destroy_qp_user")
int kernel_destroy_exit(struct pt_regs *ctx) { return complete(ctx, 3); }
