// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * R-Pingmesh eBPF Program
 * Copyright (c) 2025 Yuuki Tsubouchi
 */
#pragma once

#include "minimal_vmlinux.h"

#ifndef __custom_be64_defined  // guard
#define __custom_be64_defined
typedef __u64 __be64;
#endif

#ifndef __custom_bool_defined  // guard
#define __custom_bool_defined
#if !defined(bool) && \
    !defined(__cplusplus)  // Ensure 'bool' is not already defined
#define bool _Bool
#endif
#endif

typedef __u16 __be16;
typedef __u32 __be32;

enum ib_qp_type {
    IB_QPT_SMI = 0,
    IB_QPT_GSI = 1,
    IB_QPT_RC = 2,
    IB_QPT_UC = 3,
    IB_QPT_UD = 4,
    IB_QPT_RAW_IPV6 = 5,
    IB_QPT_RAW_ETHERTYPE = 6,
    IB_QPT_RAW_PACKET = 8,
    IB_QPT_XRC_INI = 9,
    IB_QPT_XRC_TGT = 10,
    IB_QPT_MAX = 11,
    IB_QPT_DRIVER = 255,
};

enum ib_qp_attr_mask {
    IB_QP_STATE = 1,
    IB_QP_CUR_STATE = (1 << 1),
    IB_QP_EN_SQD_ASYNC_NOTIFY = (1 << 2),
    IB_QP_ACCESS_FLAGS = (1 << 3),
    IB_QP_PKEY_INDEX = (1 << 4),
    IB_QP_PORT = (1 << 5),
    IB_QP_QKEY = (1 << 6),
    IB_QP_AV = (1 << 7),
    IB_QP_PATH_MTU = (1 << 8),
    IB_QP_TIMEOUT = (1 << 9),
    IB_QP_RETRY_CNT = (1 << 10),
    IB_QP_RNR_RETRY = (1 << 11),
    IB_QP_RQ_PSN = (1 << 12),
    IB_QP_MAX_QP_RD_ATOMIC = (1 << 13),
    IB_QP_ALT_PATH = (1 << 14),
    IB_QP_MIN_RNR_TIMER = (1 << 15),
    IB_QP_SQ_PSN = (1 << 16),
    IB_QP_MAX_DEST_RD_ATOMIC = (1 << 17),
    IB_QP_PATH_MIG_STATE = (1 << 18),
    IB_QP_CAP = (1 << 19),
    IB_QP_DEST_QPN = (1 << 20),
    IB_QP_RATE_LIMIT = (1 << 25),
};

enum ib_qp_state {
    IB_QPS_RESET = 0,
    IB_QPS_INIT = 1,
    IB_QPS_RTR = 2,
    IB_QPS_RTS = 3,
    IB_QPS_SQD = 4,
    IB_QPS_SQE = 5,
    IB_QPS_ERR = 6,
};

struct ib_port {
    struct ib_device *ibdev;
    u32 port_num;
};

struct ib_device {
    /**
     * port_data is indexed by port number
     */
    struct ib_port_data *port_data;
    u32 phys_port_cnt;
    u32 index;
};

struct ib_qp {
    struct ib_device *device;
    struct ib_pd *pd;

    u32 qp_num;
    enum ib_qp_type qp_type;
    u32 port;
};

union ib_gid {
    u8 raw[16];
    struct {
        __be64 subnet_prefix;
        __be64 interface_id;
    } global;
};

enum ib_gid_type {
    IB_GID_TYPE_IB = 0,
    IB_GID_TYPE_ROCE = 1,
    IB_GID_TYPE_ROCE_UDP_ENCAP = 2,
    IB_GID_TYPE_SIZE = 3,
};

struct ib_gid_attr {
    struct net_device *ndev;
    struct ib_device *device;
    union ib_gid gid;
    enum ib_gid_type gid_type;
    u16 index;
    u32 port_num;
};

struct ib_cq_init_attr {
    unsigned int cqe;
    u32 comp_vector;
    u32 flags;
};

struct ib_dm_mr_attr {
    u64 length;
    u64 offset;
    u32 access_flags;
};

struct ib_dm_alloc_attr {
    u64 length;
    u32 alignment;
    u32 flags;
};

enum ib_port_state {
    IB_PORT_NOP = 0,
    IB_PORT_DOWN = 1,
    IB_PORT_INIT = 2,
    IB_PORT_ARMED = 3,
    IB_PORT_ACTIVE = 4,
    IB_PORT_ACTIVE_DEFER = 5,
};

struct rdma_stat_desc {
    const char *name;
    unsigned int flags;
    const void *priv;
};

struct ib_port_attr {
    u64 subnet_prefix;
    enum ib_port_state state;
    u32 phys_mtu;
    int gid_tbl_len;
    unsigned int ip_gids : 1;
    u32 port_cap_flags;
    u32 max_msg_sz;
    u32 bad_pkey_cntr;
    u32 qkey_viol_cntr;
    u16 pkey_tbl_len;
    u32 sm_lid;
    u32 lid;
    u8 lmc;
    u8 max_vl_num;
    u8 sm_sl;
    u8 subnet_timeout;
    u8 init_type_reply;
    u8 active_width;
    u16 active_speed;
    u8 phys_state;
    u16 port_cap_flags2;
};

struct ib_cq {
    struct ib_device *device;
};

struct ib_global_route {
    const struct ib_gid_attr *sgid_attr;
    union ib_gid dgid;
    u32 flow_label;
    u8 sgid_index;
    u8 hop_limit;
    u8 traffic_class;
};

struct ib_grh {
    __be32 version_tclass_flow;
    __be16 paylen;
    u8 next_hdr;
    u8 hop_limit;
    union ib_gid sgid;
    union ib_gid dgid;
};

struct rdma_ah_init_attr {
    struct rdma_ah_attr *ah_attr;
    u32 flags;
    struct net_device *xmit_slave;
};

enum rdma_ah_attr_type {
    RDMA_AH_ATTR_TYPE_UNDEFINED = 0,
    RDMA_AH_ATTR_TYPE_IB = 1,
    RDMA_AH_ATTR_TYPE_ROCE = 2,
    RDMA_AH_ATTR_TYPE_OPA = 3,
};

struct ib_ah_attr {
    u16 dlid;
    u8 src_path_bits;
};

struct roce_ah_attr {
    u8 dmac[6];
};

struct opa_ah_attr {
    u32 dlid;
    u8 src_path_bits;
    bool make_grd;
};

struct rdma_ah_attr {
    struct ib_global_route grh;
    u8 sl;
    u8 static_rate;
    u32 port_num;
    u8 ah_flags;
    enum rdma_ah_attr_type type;
    union {
        struct ib_ah_attr ib;
        struct roce_ah_attr roce;
        struct opa_ah_attr opa;
    };
};

struct ib_qp_init_attr {
    enum ib_qp_type qp_type;
    u32 port_num;
    u32 source_qpn;
};

struct ib_qp_attr {
    enum ib_qp_state qp_state;
    enum ib_qp_state cur_qp_state;
    u32 qkey;
    u32 rq_psn;
    u32 sq_psn;
    u32 dest_qp_num;
    int qp_access_flags;
    struct rdma_ah_attr ah_attr;
    struct rdma_ah_attr alt_ah_attr;
    u16 pkey_index;
    u16 alt_pkey_index;
    u8 en_sqd_async_notify;
    u8 sq_draining;
    u8 max_rd_atomic;
    u8 max_dest_rd_atomic;
    u8 min_rnr_timer;
    u32 port_num;
    u8 timeout;
    u8 retry_cnt;
    u8 rnr_retry;
    u32 alt_port_num;
    u8 alt_timeout;
    u32 rate_limit;
};

struct ib_ah {
    struct ib_device *device;
    struct ib_pd *pd;
    struct ib_uobject *uobject;
    const struct ib_gid_attr *sgid_attr;
    enum rdma_ah_attr_type type;
};

struct ib_pd {
    u32 local_dma_lkey;
    u32 flags;
    struct ib_device *device;
    struct ib_uobject *uobject;
    u32 unsafe_global_rkey;
};

enum port_pkey_state {
    IB_PORT_PKEY_NOT_VALID = 0,
    IB_PORT_PKEY_VALID = 1,
    IB_PORT_PKEY_LISTED = 2,
};

struct ib_port_pkey {
    enum port_pkey_state state;
    u16 pkey_index;
    u32 port_num;
};

struct ib_ports_pkeys;

struct ib_ports_pkeys {
    struct ib_port_pkey main;
    struct ib_port_pkey alt;
};

enum ib_flow_attr_type {
    IB_FLOW_ATTR_NORMAL = 0,
    IB_FLOW_ATTR_ALL_DEFAULT = 1,
    IB_FLOW_ATTR_MC_DEFAULT = 2,
    IB_FLOW_ATTR_SNIFFER = 3,
};

enum ib_flow_spec_type {
    IB_FLOW_SPEC_ETH = 32,
    IB_FLOW_SPEC_IB = 34,
    IB_FLOW_SPEC_IPV4 = 48,
    IB_FLOW_SPEC_IPV6 = 49,
    IB_FLOW_SPEC_ESP = 52,
    IB_FLOW_SPEC_TCP = 64,
    IB_FLOW_SPEC_UDP = 65,
    IB_FLOW_SPEC_VXLAN_TUNNEL = 80,
    IB_FLOW_SPEC_GRE = 81,
    IB_FLOW_SPEC_MPLS = 96,
    IB_FLOW_SPEC_INNER = 256,
    IB_FLOW_SPEC_ACTION_TAG = 4096,
    IB_FLOW_SPEC_ACTION_DROP = 4097,
    IB_FLOW_SPEC_ACTION_HANDLE = 4098,
    IB_FLOW_SPEC_ACTION_COUNT = 4099,
};

struct ib_gid_table_entry {
    union ib_gid gid;  // Ensure this uses the previously defined union ib_gid
    struct net_device
        *ndev;  // May not be available directly in all contexts or via CO-RE
    // Add other fields if necessary, e.g., refcount, policy
    // For simplicity, starting with GID.
    // If ndev is needed and causes issues, it might need to be conditionally
    // compiled or handled. Adding a placeholder for potential alignment or
    // other data: unsigned long entry_data; // Placeholder, adjust as needed
};

struct ib_gid_table {
    int sz;
    /* In RoCE, adding a GID to the table requires:
     * (a) Find if this GID is already exists.
     * (b) Find a free space.
     * (c) Write the new GID
     *
     * Delete requires different set of operations:
     * (a) Find the GID
     * (b) Delete it.
     *
     **/
    struct ib_gid_table_entry **data_vec;
    /* bit field, each bit indicates the index of default GID */
    u32 default_gid_indices;
};

struct ib_port_cache {
    u64 subnet_prefix;
    struct ib_pkey_cache *pkey;
    struct ib_gid_table *gid;  // This is a pointer to ib_gid_table
    u8 lmc;
    enum ib_port_state port_state;
    // Ensure other relevant fields from kernel's ib_port_cache are here if
    // needed by CO-RE
};

struct ib_port_immutable {
    int pkey_tbl_len;
    int gid_tbl_len;
    u32 core_cap_flags;
    u32 max_mad_size;
};

struct ib_port;

struct ib_port_data {
    struct ib_device *ib_dev;
    struct ib_port_immutable immutable;
    struct ib_port_cache cache;
    struct net_device *netdev;
    struct ib_port *sysfs;
};

struct ib_udata;
