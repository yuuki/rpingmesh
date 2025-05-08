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

// 新しいカーネルではRDMA AHフラグが変更されている可能性があります
#define RDMA_AH_ATTR_GRH 1

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
    event->src_qpn = BPF_CORE_READ(qp, qp_num);

    // Read QP state based on attr_mask
    if (attr_mask & IB_QP_STATE) {
        event->qp_state = BPF_CORE_READ(attr, qp_state);
    } else {
        event->qp_state = -1;  // Unknown or unchanged
    }

    // Read destination information based on attr_mask
    if (attr_mask & IB_QP_AV) {
        // カーネル構造体の変更に対応
        struct rdma_ah_attr *ah_attr = &attr->ah_attr;

        // GRHフィールドがある場合のみDGIDにアクセス
        if (BPF_CORE_READ(ah_attr, grh.sgid_attr)) {
            // GRHからDGIDを読み取り
            const void *dgid_ptr = BPF_CORE_READ(ah_attr, grh.dgid.raw);
            if (dgid_ptr) {
                bpf_probe_read_kernel(event->dst_gid, sizeof(event->dst_gid),
                                      dgid_ptr);
            }
        }

        // Read destination QPN if available
        if (attr_mask & IB_QP_DEST_QPN) {
            event->dst_qpn = BPF_CORE_READ(attr, dest_qp_num);
        }
    }

    // Read source GID if available
    // Note: In a real implementation, we need to check which port the QP is
    // associated with and get the GID from that port's GID table Simplified
    // here for brevity

    // Submit event to user space
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
