/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * The subset of the uverbs user-space ABI the tracer reads, transcribed from
 * include/uapi/rdma/ib_user_verbs.h, rdma_user_ioctl_cmds.h and
 * ib_user_ioctl_cmds.h. These layouts and numbers are a stable kernel ABI:
 * every libibverbs ever shipped relies on them, so the tracer can parse the
 * command buffers of any kernel and any RDMA stack (in-tree or OFED)
 * without that stack's type information.
 */
#ifndef __RPINGMESH_UVERBS_UAPI_H__
#define __RPINGMESH_UVERBS_UAPI_H__

#include "vmlinux_min.h"

/* ioctl(2) request number of RDMA_VERBS_IOCTL:
 * _IOWR(RDMA_IOCTL_MAGIC 0x1b, 1, struct ib_uverbs_ioctl_hdr (24 bytes)). */
#define RDMA_VERBS_IOCTL 0xc0181b01u

/* Write-path command numbers (enum ib_uverbs_write_cmds). */
#define IB_USER_VERBS_CMD_CREATE_QP 24
#define IB_USER_VERBS_CMD_MODIFY_QP 26
#define IB_USER_VERBS_CMD_DESTROY_QP 27
#define IB_USER_VERBS_CMD_OPEN_QP 40
#define IB_USER_VERBS_CMD_FLAG_EXTENDED 0x80000000u

/* ioctl objects, methods and attributes (ib_user_ioctl_cmds.h). */
#define UVERBS_OBJECT_DEVICE 0
#define UVERBS_OBJECT_QP 4
#define UVERBS_METHOD_INVOKE_WRITE 0
#define UVERBS_METHOD_QP_CREATE 0
#define UVERBS_METHOD_QP_DESTROY 1
#define UVERBS_ATTR_CORE_IN 0
#define UVERBS_ATTR_CORE_OUT 1
#define UVERBS_ATTR_WRITE_CMD 2
#define UVERBS_ATTR_CREATE_QP_HANDLE 0
#define UVERBS_ATTR_CREATE_QP_TYPE 9
#define UVERBS_ATTR_CREATE_QP_RESP_QP_NUM 14
#define UVERBS_ATTR_DESTROY_QP_HANDLE 0

/* enum ib_uverbs_qp_type. */
#define IB_UVERBS_QPT_RC 2
#define IB_UVERBS_QPT_UC 3
#define IB_UVERBS_QPT_UD 4
#define IB_UVERBS_QPT_XRC_INI 9
#define IB_UVERBS_QPT_XRC_TGT 10

struct ib_uverbs_cmd_hdr {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
};

struct ib_uverbs_ex_cmd_hdr {
	__u64 response;
	__u16 provider_in_words;
	__u16 provider_out_words;
	__u32 cmd_hdr_reserved;
};

struct ib_uverbs_ioctl_hdr {
	__u16 length;
	__u16 object_id;
	__u16 method_id;
	__u16 num_attrs;
	__u64 reserved1;
	__u32 driver_id;
	__u32 reserved2;
};

struct ib_uverbs_attr {
	__u16 attr_id;
	__u16 len;
	__u16 flags;
	__u16 attr_data;
	__u64 data;
};

struct ib_uverbs_qp_dest {
	__u8 dgid[16];
	__u32 flow_label;
	__u16 dlid;
	__u16 reserved;
	__u8 sgid_index;
	__u8 hop_limit;
	__u8 traffic_class;
	__u8 sl;
	__u8 src_path_bits;
	__u8 static_rate;
	__u8 is_global;
	__u8 port_num;
};

/* The body of CMD_MODIFY_QP; EX_CMD_MODIFY_QP appends rate_limit. */
struct ib_uverbs_modify_qp {
	struct ib_uverbs_qp_dest dest;
	struct ib_uverbs_qp_dest alt_dest;
	__u32 qp_handle;
	__u32 attr_mask;
	__u32 qkey;
	__u32 rq_psn;
	__u32 sq_psn;
	__u32 dest_qp_num;
	__u32 qp_access_flags;
	__u16 pkey_index;
	__u16 alt_pkey_index;
	__u8 qp_state;
	__u8 cur_qp_state;
	__u8 path_mtu;
	__u8 path_mig_state;
	__u8 en_sqd_async_notify;
	__u8 max_rd_atomic;
	__u8 max_dest_rd_atomic;
	__u8 min_rnr_timer;
	__u8 port_num;
	__u8 timeout;
	__u8 retry_cnt;
	__u8 rnr_retry;
	__u8 alt_port_num;
	__u8 alt_timeout;
	__u8 reserved[2];
};

/* Field offsets of the create/open/destroy bodies the tracer reads. */
#define CREATE_QP_RESPONSE_OFF 0  /* struct ib_uverbs_create_qp.response */
#define CREATE_QP_QP_TYPE_OFF 53  /* struct ib_uverbs_create_qp.qp_type */
#define EX_CREATE_QP_QP_TYPE_OFF 45 /* struct ib_uverbs_ex_create_qp.qp_type */
#define OPEN_QP_RESPONSE_OFF 0    /* struct ib_uverbs_open_qp.response */
#define OPEN_QP_QPN_OFF 20        /* struct ib_uverbs_open_qp.qpn */
#define OPEN_QP_QP_TYPE_OFF 24    /* struct ib_uverbs_open_qp.qp_type */
#define DESTROY_QP_HANDLE_OFF 8   /* struct ib_uverbs_destroy_qp.qp_handle */

/* The first two words of struct ib_uverbs_create_qp_resp. */
struct ib_uverbs_create_qp_resp_head {
	__u32 qp_handle;
	__u32 qpn;
};

#endif /* __RPINGMESH_UVERBS_UAPI_H__ */
