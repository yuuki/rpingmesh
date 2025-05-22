// go:build ignore

// Support for CO-RE (Compile Once - Run Everywhere)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

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
    IB_QP_RESERVED1 = (1 << 21),
    IB_QP_RESERVED2 = (1 << 22),
    IB_QP_RESERVED3 = (1 << 23),
    IB_QP_RESERVED4 = (1 << 24),
    IB_QP_RATE_LIMIT = (1 << 25),
};

// RDMA AH flags may have changed in newer kernels
#define RDMA_AH_ATTR_GRH 1

#ifndef IB_QPS_RTR
#define IB_QPS_RTR 3  // Common value for IB_QPS_RTR, verify with your vmlinux.h
#endif

// Structure definition for RDMA 5-tuple information
struct rdma_conn_tuple {
    __u64 timestamp;   // Timestamp when the event occurred
    __u8 event_type;   // Event type (1: create, 2: modify, 3: destroy)
    __u32 src_qpn;     // Source Queue Pair Number
    __u32 dst_qpn;     // Destination Queue Pair Number
    __u8 src_gid[16];  // Source Global Identifier (GID)
    __u8 dst_gid[16];  // Destination Global Identifier (GID)
    int qp_state;      // QP state (valid only for modify_qp)
    __u32 pid;         // Process ID
    __u32 tid;         // Thread ID
    char comm[16];     // Process name
};

// Ring buffer definition (for user space communication)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB
} rdma_events SEC(".maps");

// Function to hook ibv_modify_qp
SEC("kprobe/ib_modify_qp")
int BPF_KPROBE(trace_modify_qp, struct ib_qp *qp, struct ib_qp_attr *attr,
               int attr_mask) {
    struct rdma_conn_tuple *event;
    struct ib_device *dev;
    // struct ib_gid_attr sgid_attr; // Not used in the simplified version
    u8 port_num;

    // Filter by QP state: only proceed if IB_QP_STATE is set in attr_mask
    // and qp_state is IB_QPS_RTR (Ready To Receive)
    if (!(attr_mask & IB_QP_STATE)) {
        return 0;  // QP_STATE not being modified
    }
    // Correctly read qp_state using BPF_CORE_READ
    s32 qp_state_val;
    bpf_core_read(&qp_state_val, sizeof(qp_state_val), &attr->qp_state);
    if (qp_state_val != IB_QPS_RTR) {
        return 0;  // Not the state we are interested in
    }

    // Reserve space in the ring buffer for the event
    event = bpf_ringbuf_reserve(&rdma_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Set basic information
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = 2;  // modify
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read QPN
    bpf_core_read(&event->src_qpn, sizeof(event->src_qpn), &qp->qp_num);
    // Store the QP state we filtered on
    event->qp_state = qp_state_val;

    // Read destination information based on attr_mask
    if (attr_mask & IB_QP_AV) {
        struct rdma_ah_attr ah_attr_val;
        bpf_core_read(&ah_attr_val, sizeof(ah_attr_val), &attr->ah_attr);

        // Check AH type (RDMA_AH_ATTR_TYPE_ROCE or RDMA_AH_ATTR_TYPE_IB)
        // Assuming 'type' field exists in rdma_ah_attr. If not, this needs
        // adjustment. u32 ah_type; bpf_core_read(&ah_type, sizeof(ah_type),
        // &ah_attr_val.type); // Example read

        // For RoCE, dgid is typically within a nested structure like
        // ah_attr.roce.dgid For IB with GRH, dgid is typically ah_attr.grh.dgid
        // This part is highly dependent on vmlinux.h and kernel version.
        // We'll use a simplified/generalized approach for dgid based on common
        // patterns.

        // Attempt to read DGID from GRH if present (common for both RoCE with
        // GRH and IB) Check if ah_flags has RDMA_AH_ATTR_GRH
        u8 ah_flags_val;
        bpf_core_read(&ah_flags_val, sizeof(ah_flags_val),
                      &ah_attr_val.ah_flags);

        if (ah_flags_val & RDMA_AH_ATTR_GRH) {
            // GRH is present, read dgid from grh.dgid
            // Using bpf_probe_read_kernel for safety if direct BPF_CORE_READ
            // path is complex/unknown
            bpf_probe_read_kernel(&event->dst_gid, sizeof(event->dst_gid),
                                  &ah_attr_val.grh.dgid.raw[0]);
        } else {
            // If no GRH, specific logic for RoCE without GRH might be needed if
            // applicable. Often, RoCE AH might directly contain dgid, e.g.
            // ah_attr_val.roce.dgid This is a fallback/simplification:
            __builtin_memset(event->dst_gid, 0, sizeof(event->dst_gid));
        }

        if (attr_mask & IB_QP_DEST_QPN) {
            bpf_core_read(&event->dst_qpn, sizeof(event->dst_qpn),
                          &attr->dest_qp_num);
        } else {
            event->dst_qpn = 0;
        }
    } else {
        __builtin_memset(event->dst_gid, 0, sizeof(event->dst_gid));
        event->dst_qpn = 0;
    }

    // Read source GID - Placeholder, as this is complex and kernel-dependent
    // Agent side will need to correlate using src_qpn and its known local
    // RNICs.
    dev = BPF_CORE_READ(qp, device);
    if (dev) {
        port_num = 0;
        if (attr_mask & IB_QP_PORT) {
            bpf_core_read(&port_num, sizeof(port_num), &attr->port_num);
        }
        // If port_num is available, one might attempt to read GID from device's
        // GID table. However, this is non-trivial. For now, src_gid remains
        // zeroed. The user-space agent can fill this based on the qp->device
        // and qp->port_num if needed, or by matching src_qpn to its managed
        // RNICs.
        __builtin_memset(event->src_gid, 0, sizeof(event->src_gid));
    } else {
        __builtin_memset(event->src_gid, 0, sizeof(event->src_gid));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Function to hook ibv_destroy_qp
SEC("kprobe/ib_destroy_qp")
int BPF_KPROBE(trace_destroy_qp, struct ib_qp *qp) {
    struct rdma_conn_tuple *event;

    // Reserve space in the ring buffer for the event
    event = bpf_ringbuf_reserve(&rdma_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Set basic information
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = 3;  // destroy
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read QPN
    event->src_qpn = BPF_CORE_READ(qp, qp_num);

    // Initialize other fields to 0 as they are not available
    event->dst_qpn = 0;
    event->qp_state = -1;
    __builtin_memset(event->src_gid, 0, sizeof(event->src_gid));
    __builtin_memset(event->dst_gid, 0, sizeof(event->dst_gid));

    // Submit event to user space
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// Bonus: Function to hook ibv_create_qp (if monitoring is needed)
SEC("kprobe/ib_create_qp")
int BPF_KPROBE(trace_create_qp, struct ib_pd *pd,
               struct ib_qp_init_attr *init_attr) {
    struct rdma_conn_tuple *event;

    // Reserve space in the ring buffer for the event
    event = bpf_ringbuf_reserve(&rdma_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Set basic information
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = 1;  // create
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Initialize most fields to 0 as QPN etc. are not assigned at create time
    event->src_qpn = 0;  // Not assigned at create time
    event->dst_qpn = 0;
    event->qp_state = -1;
    __builtin_memset(event->src_gid, 0, sizeof(event->src_gid));
    __builtin_memset(event->dst_gid, 0, sizeof(event->dst_gid));

    // Submit event to user space
    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
