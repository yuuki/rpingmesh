/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#ifndef RPINGMESH_TRACE_EVENT_H
#define RPINGMESH_TRACE_EVENT_H

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

#endif
