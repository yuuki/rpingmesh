// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * uverbs_trace: traces the lifecycle of application RDMA queue pairs for
 * R-Pingmesh service tracing (paper section 4.2.2).
 *
 * The paper traces the kernel's modify_qp and destroy_qp. This program sits
 * one layer up, at the entry points of the uverbs character device
 * (ib_uverbs_ioctl, ib_uverbs_write, ib_uverbs_close), and parses the
 * command buffers libibverbs hands to the kernel. Those buffers follow the
 * uverbs user-space ABI (uverbs_uapi.h), which is stable across kernels and
 * RDMA stacks, so the tracer needs no BTF for ib_core/ib_uverbs: out-of-tree
 * RDMA stacks (OFED) ship their modules without it, and the kernel's
 * struct ib_qp / ib_qp_attr layouts differ between stacks.
 *
 * Per command the tracer emits one event (struct qp_event) into a ring
 * buffer once the kernel reports success:
 *   - QP create (write CREATE_QP / EX_CREATE_QP / OPEN_QP, or the ioctl
 *     QP_CREATE method): the new QP's uverbs handle, number and type;
 *   - QP modify (write MODIFY_QP / EX_MODIFY_QP, carried by write(2) or by
 *     the ioctl INVOKE_WRITE method): the target state, the destination
 *     GID / QPN and the flow label of the address vector, which is the
 *     5-tuple of a connected QP once it reaches RTR;
 *   - QP destroy (write DESTROY_QP or the ioctl QP_DESTROY method);
 *   - context close (the file is released): every QP of that context is
 *     gone, including on process exit without explicit destroys.
 *
 * Commands that may fail are staged in a per-task map at entry and emitted
 * from the return probe only when the kernel returned success; the create
 * response (handle and QPN) is read from user memory at that point, after
 * the kernel wrote it.
 *
 * The user-space handles are unique per context, so events carry the
 * context identity (the struct file pointer) and user space joins create,
 * modify and destroy events into connections. The device is identified by
 * the device number of the uverbs node the context was opened on, which
 * user space maps to the RDMA device name through sysfs.
 */
#include "vmlinux_min.h"
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <bpf_tracing.h>
#include "uverbs_uapi.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Event kinds. Keep in sync with the Go Kind constants. */
#define EV_QP_CREATE 1
#define EV_QP_MODIFY 2
#define EV_QP_DESTROY 3
#define EV_CTX_CLOSE 4

/* How the command reached the kernel. Diagnostics only. */
#define SRC_WRITE 1        /* write(2) on the uverbs fd */
#define SRC_IOCTL_WRITE 2  /* ioctl INVOKE_WRITE carrying a write command */
#define SRC_IOCTL_NATIVE 3 /* an ioctl-native method (QP_CREATE/QP_DESTROY) */

/* Event layout; mirrored by the Go side (bpf2go -type qp_event). */
struct qp_event {
	__u64 ts_ns;
	__u64 ctx;       /* uverbs context identity (struct file *) */
	__u64 cgroup_id;
	__u32 pid;       /* thread group id */
	__u32 tid;
	__u32 kind;      /* EV_* */
	__u32 src;       /* SRC_* */
	__u32 dev;       /* device number of the uverbs node (dev_t) */
	__u32 qp_handle; /* uverbs object handle, unique within ctx */
	__u32 qp_num;    /* EV_QP_CREATE */
	__u32 qp_type;   /* EV_QP_CREATE: enum ib_uverbs_qp_type */
	__u32 attr_mask; /* EV_QP_MODIFY: enum ib_qp_attr_mask */
	__u32 dest_qp_num;
	__u32 flow_label;
	__u32 reserved;
	__u8 dgid[16];
	__u8 qp_state;
	__u8 sgid_index;
	__u8 port_num;
	__u8 hop_limit;
	__u8 traffic_class;
	__u8 sl;
	__u8 is_global;
	__u8 dest_port_num;
	char comm[16];
};

/* A command staged at entry, completed and emitted at return. */
struct pending {
	struct qp_event ev;
	/* EV_QP_CREATE via a write command: user pointer to the response
	 * (struct ib_uverbs_create_qp_resp). */
	__u64 resp;
	/* EV_QP_CREATE via the ioctl QP_CREATE method: user pointer to the
	 * attribute array and its length. */
	__u64 attrs;
	__u32 num_attrs;
	__u32 from_open_qp; /* qp_num already known from the command */
};

/* Counters read by user space (stats map). */
enum {
	STAT_RINGBUF_DROPPED = 0,
	STAT_PARSE_ERRORS,
	STAT_MAX,
};

/* Upper bound on the attributes scanned per ioctl: INVOKE_WRITE sends at
 * most 5 and QP_CREATE at most 15. */
#define MAX_ATTRS 16

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct pending);
} pending_cmds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline __u32 file_dev(struct file *filp)
{
	return BPF_CORE_READ(filp, f_inode, i_rdev);
}

/* Fills the identity fields and emits ev. */
static __always_inline void emit(struct qp_event *ev)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct qp_event *out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
	if (!out) {
		stat_inc(STAT_RINGBUF_DROPPED);
		return;
	}
	__builtin_memcpy(out, ev, sizeof(*out));
	out->ts_ns = bpf_ktime_get_ns();
	out->pid = pid_tgid >> 32;
	out->tid = (__u32)pid_tgid;
	out->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(out->comm, sizeof(out->comm));
	bpf_ringbuf_submit(out, 0);
}

static __always_inline void stage(struct pending *p)
{
	__u64 key = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&pending_cmds, &key, p, BPF_ANY);
}

/* Parses a MODIFY_QP body (the EX variant has the same prefix). */
static __always_inline int parse_modify(struct qp_event *ev, const void *body)
{
	struct ib_uverbs_modify_qp cmd;
	if (bpf_probe_read_user(&cmd, sizeof(cmd), body))
		return -1;
	ev->qp_handle = cmd.qp_handle;
	ev->attr_mask = cmd.attr_mask;
	ev->dest_qp_num = cmd.dest_qp_num;
	ev->flow_label = cmd.dest.flow_label;
	__builtin_memcpy(ev->dgid, cmd.dest.dgid, sizeof(ev->dgid));
	ev->qp_state = cmd.qp_state;
	ev->sgid_index = cmd.dest.sgid_index;
	ev->port_num = cmd.port_num;
	ev->hop_limit = cmd.dest.hop_limit;
	ev->traffic_class = cmd.dest.traffic_class;
	ev->sl = cmd.dest.sl;
	ev->is_global = cmd.dest.is_global;
	ev->dest_port_num = cmd.dest.port_num;
	return 0;
}

/*
 * Stages a write-path command. body points to the command body in user
 * memory (after the command headers); resp is the user pointer to the
 * response buffer, or 0 when the caller does not know it yet (the legacy
 * create/open/destroy bodies carry it in their first word).
 */
static __always_inline void stage_write_cmd(struct file *filp, __u32 command,
					    const void *body, __u64 resp, __u32 src)
{
	struct pending p = {};
	__u32 cmd = command & ~IB_USER_VERBS_CMD_FLAG_EXTENDED;
	bool ext = command & IB_USER_VERBS_CMD_FLAG_EXTENDED;

	p.ev.ctx = (__u64)filp;
	p.ev.dev = file_dev(filp);
	p.ev.src = src;

	switch (cmd) {
	case IB_USER_VERBS_CMD_MODIFY_QP:
		if (parse_modify(&p.ev, body)) {
			stat_inc(STAT_PARSE_ERRORS);
			return;
		}
		p.ev.kind = EV_QP_MODIFY;
		break;

	case IB_USER_VERBS_CMD_CREATE_QP: {
		__u8 qp_type = 0;
		__u32 off = ext ? EX_CREATE_QP_QP_TYPE_OFF : CREATE_QP_QP_TYPE_OFF;
		if (bpf_probe_read_user(&qp_type, sizeof(qp_type), body + off)) {
			stat_inc(STAT_PARSE_ERRORS);
			return;
		}
		if (!resp && !ext &&
		    bpf_probe_read_user(&resp, sizeof(resp), body + CREATE_QP_RESPONSE_OFF)) {
			stat_inc(STAT_PARSE_ERRORS);
			return;
		}
		if (!resp)
			return;
		p.ev.kind = EV_QP_CREATE;
		p.ev.qp_type = qp_type;
		p.resp = resp;
		break;
	}

	case IB_USER_VERBS_CMD_OPEN_QP: {
		__u8 qp_type = 0;
		__u32 qpn = 0;
		if (bpf_probe_read_user(&qp_type, sizeof(qp_type), body + OPEN_QP_QP_TYPE_OFF) ||
		    bpf_probe_read_user(&qpn, sizeof(qpn), body + OPEN_QP_QPN_OFF)) {
			stat_inc(STAT_PARSE_ERRORS);
			return;
		}
		if (!resp &&
		    bpf_probe_read_user(&resp, sizeof(resp), body + OPEN_QP_RESPONSE_OFF)) {
			stat_inc(STAT_PARSE_ERRORS);
			return;
		}
		if (!resp)
			return;
		p.ev.kind = EV_QP_CREATE;
		p.ev.qp_type = qp_type;
		p.ev.qp_num = qpn;
		p.resp = resp;
		p.from_open_qp = 1;
		break;
	}

	case IB_USER_VERBS_CMD_DESTROY_QP: {
		__u32 handle = 0;
		if (bpf_probe_read_user(&handle, sizeof(handle), body + DESTROY_QP_HANDLE_OFF)) {
			stat_inc(STAT_PARSE_ERRORS);
			return;
		}
		p.ev.kind = EV_QP_DESTROY;
		p.ev.qp_handle = handle;
		break;
	}

	default:
		return;
	}
	stage(&p);
}

/* Reads attribute i of an ioctl attribute array in user memory. */
static __always_inline int read_attr(struct ib_uverbs_attr *a, __u64 attrs, __u32 i)
{
	return bpf_probe_read_user(a, sizeof(*a),
				   (const void *)(attrs + (__u64)i * sizeof(*a)));
}

/* Completes a staged command after the kernel reported success. */
static __always_inline void finalize(struct pending *p)
{
	struct qp_event ev = p->ev;

	if (ev.kind == EV_QP_CREATE) {
		if (p->attrs) {
			/* ioctl QP_CREATE: the kernel wrote the new handle into
			 * the HANDLE attribute and the QPN behind RESP_QP_NUM. */
			bool have_handle = false, have_qpn = false;
			__u32 n = p->num_attrs;
			for (__u32 i = 0; i < MAX_ATTRS; i++) {
				struct ib_uverbs_attr a;
				if (i >= n)
					break;
				if (read_attr(&a, p->attrs, i))
					break;
				if (a.attr_id == UVERBS_ATTR_CREATE_QP_HANDLE) {
					ev.qp_handle = (__u32)a.data;
					have_handle = true;
				} else if (a.attr_id == UVERBS_ATTR_CREATE_QP_RESP_QP_NUM) {
					if (!bpf_probe_read_user(&ev.qp_num, sizeof(ev.qp_num),
								 (const void *)a.data))
						have_qpn = true;
				}
			}
			if (!have_handle || !have_qpn) {
				stat_inc(STAT_PARSE_ERRORS);
				return;
			}
		} else {
			struct ib_uverbs_create_qp_resp_head r;
			if (bpf_probe_read_user(&r, sizeof(r), (const void *)p->resp)) {
				stat_inc(STAT_PARSE_ERRORS);
				return;
			}
			ev.qp_handle = r.qp_handle;
			if (!p->from_open_qp)
				ev.qp_num = r.qpn;
		}
	}
	emit(&ev);
}

static __always_inline void complete(bool ok)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct pending *p = bpf_map_lookup_elem(&pending_cmds, &key);
	if (!p)
		return;
	if (ok)
		finalize(p);
	bpf_map_delete_elem(&pending_cmds, &key);
}

SEC("kprobe/ib_uverbs_ioctl")
int BPF_KPROBE(uverbs_ioctl_enter, struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ib_uverbs_ioctl_hdr hdr;
	__u64 attrs = arg + sizeof(hdr);
	__u32 n;

	if (cmd != RDMA_VERBS_IOCTL)
		return 0;
	if (bpf_probe_read_user(&hdr, sizeof(hdr), (const void *)arg))
		return 0;
	n = hdr.num_attrs;
	if (n > MAX_ATTRS)
		n = MAX_ATTRS;

	if (hdr.object_id == UVERBS_OBJECT_DEVICE && hdr.method_id == UVERBS_METHOD_INVOKE_WRITE) {
		__u64 write_cmd = 0, core_in = 0, core_out = 0;
		bool have_cmd = false;
		for (__u32 i = 0; i < MAX_ATTRS; i++) {
			struct ib_uverbs_attr a;
			if (i >= n)
				break;
			if (read_attr(&a, attrs, i))
				return 0;
			switch (a.attr_id) {
			case UVERBS_ATTR_WRITE_CMD:
				write_cmd = a.data; /* inline constant */
				have_cmd = true;
				break;
			case UVERBS_ATTR_CORE_IN:
				core_in = a.data; /* user pointer: the body is never inline */
				break;
			case UVERBS_ATTR_CORE_OUT:
				core_out = a.data;
				break;
			}
		}
		if (!have_cmd || !core_in)
			return 0;
		stage_write_cmd(filp, (__u32)write_cmd, (const void *)core_in, core_out,
				SRC_IOCTL_WRITE);
		return 0;
	}

	if (hdr.object_id != UVERBS_OBJECT_QP)
		return 0;

	if (hdr.method_id == UVERBS_METHOD_QP_CREATE) {
		struct pending p = {};
		bool have_type = false;
		for (__u32 i = 0; i < MAX_ATTRS; i++) {
			struct ib_uverbs_attr a;
			if (i >= n)
				break;
			if (read_attr(&a, attrs, i))
				return 0;
			if (a.attr_id == UVERBS_ATTR_CREATE_QP_TYPE) {
				p.ev.qp_type = (__u32)a.data; /* inline constant */
				have_type = true;
			}
		}
		if (!have_type)
			return 0;
		p.ev.kind = EV_QP_CREATE;
		p.ev.src = SRC_IOCTL_NATIVE;
		p.ev.ctx = (__u64)filp;
		p.ev.dev = file_dev(filp);
		p.attrs = attrs;
		p.num_attrs = n;
		stage(&p);
		return 0;
	}

	if (hdr.method_id == UVERBS_METHOD_QP_DESTROY) {
		struct pending p = {};
		bool have_handle = false;
		for (__u32 i = 0; i < MAX_ATTRS; i++) {
			struct ib_uverbs_attr a;
			if (i >= n)
				break;
			if (read_attr(&a, attrs, i))
				return 0;
			if (a.attr_id == UVERBS_ATTR_DESTROY_QP_HANDLE) {
				p.ev.qp_handle = (__u32)a.data; /* inline object id */
				have_handle = true;
			}
		}
		if (!have_handle)
			return 0;
		p.ev.kind = EV_QP_DESTROY;
		p.ev.src = SRC_IOCTL_NATIVE;
		p.ev.ctx = (__u64)filp;
		p.ev.dev = file_dev(filp);
		stage(&p);
		return 0;
	}
	return 0;
}

SEC("kretprobe/ib_uverbs_ioctl")
int BPF_KRETPROBE(uverbs_ioctl_exit, long ret)
{
	complete(ret == 0);
	return 0;
}

SEC("kprobe/ib_uverbs_write")
int BPF_KPROBE(uverbs_write_enter, struct file *filp, const char *buf, unsigned long count)
{
	struct ib_uverbs_cmd_hdr hdr;
	const void *body = buf + sizeof(hdr);
	__u64 resp = 0;

	if (count < sizeof(hdr))
		return 0;
	if (bpf_probe_read_user(&hdr, sizeof(hdr), buf))
		return 0;
	if (hdr.command & IB_USER_VERBS_CMD_FLAG_EXTENDED) {
		struct ib_uverbs_ex_cmd_hdr ex;
		if (bpf_probe_read_user(&ex, sizeof(ex), body))
			return 0;
		resp = ex.response;
		body += sizeof(ex);
	}
	stage_write_cmd(filp, hdr.command, body, resp, SRC_WRITE);
	return 0;
}

SEC("kretprobe/ib_uverbs_write")
int BPF_KRETPROBE(uverbs_write_exit, long ret)
{
	complete(ret >= 0);
	return 0;
}

SEC("kprobe/ib_uverbs_close")
int BPF_KPROBE(uverbs_close_enter, struct inode *inode, struct file *filp)
{
	struct qp_event ev = {};
	ev.kind = EV_CTX_CLOSE;
	ev.ctx = (__u64)filp;
	ev.dev = BPF_CORE_READ(inode, i_rdev);
	emit(&ev);
	return 0;
}
