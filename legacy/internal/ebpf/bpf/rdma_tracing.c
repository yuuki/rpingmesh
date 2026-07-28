// go:build ignore
// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/*
 * R-Pingmesh eBPF Program
 * Copyright (c) 2025 Yuuki Tsubouchi
 */

// Support for CO-RE (Compile Once - Run Everywhere)
#include "minimal_vmlinux.h"
#include "minimal_ib_verbs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Constants for better maintainability
#define DEFAULT_GID_INDEX 0  // Use index 0 for more reliable GID access
#define MAX_GID_INDEX 255
#define RDMA_AH_ATTR_GRH 0x01  // Correct value for GRH flag
#define INVALID_QP_STATE -1
#define INVALID_PORT_NUM 0

// Event type definitions
#define RDMA_EVENT_CREATE 1
#define RDMA_EVENT_MODIFY 2
#define RDMA_EVENT_DESTROY 3

// Ring buffer configuration
#define RDMA_RINGBUF_SIZE (1 << 24)  // 16MB - configurable

// Structure definition for RDMA 5-tuple information
// CO-RE compatible structure with explicit alignment verification
struct rdma_conn_tuple {
    __u64 timestamp;       // Timestamp when the event occurred (offset 0, 8 bytes)
    union ib_gid src_gid;  // Source Global Identifier (GID) (offset 8, 16 bytes)
    union ib_gid dst_gid;  // Destination Global Identifier (GID) (offset 24, 16 bytes)
    __u32 src_qpn;         // Source Queue Pair Number (offset 40, 4 bytes)
    __u32 dst_qpn;         // Destination Queue Pair Number (offset 44, 4 bytes)
    __u32 pid;             // Process ID (offset 48, 4 bytes)
    __u32 tid;             // Thread ID (offset 52, 4 bytes)
    __s32 qp_state;        // QP state (valid only for modify_qp) (offset 56, 4 bytes)
    __u8 event_type;       // Event type (1: create, 2: modify, 3: destroy) (offset 60, 1 byte)
    __u8 port_num;         // Port number for debugging (offset 61, 1 byte)
    __u8 reserved[2];      // Explicit padding for alignment (offset 62, 2 bytes)
    char comm[16];         // Process name (offset 64, 16 bytes)
} __attribute__((packed));

// Compile-time size verification to ensure struct layout consistency
_Static_assert(sizeof(struct rdma_conn_tuple) == 80, "rdma_conn_tuple struct size mismatch");

// Ring buffer definition (for user space communication)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RDMA_RINGBUF_SIZE);
} rdma_events SEC(".maps");

// Statistics map for monitoring
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} rdma_stats SEC(".maps");

// Statistics keys
enum {
    STAT_CREATE_COUNT = 0,
    STAT_MODIFY_COUNT = 1,
    STAT_DESTROY_COUNT = 2,
    STAT_ERROR_COUNT = 3,
    STAT_GID_READ_SUCCESS = 4,
    STAT_GID_READ_FAILURE = 5,
    STAT_PORT_DATA_FAILURE = 6,
    STAT_GID_TABLE_FAILURE = 7,
    STAT_CORE_READ_ERROR = 8,
    STAT_FIELD_MISSING = 9,
};

// Helper function to increment statistics using CO-RE
static __always_inline void increment_stat(__u32 key) {
    __u64 *value = bpf_map_lookup_elem(&rdma_stats, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

// CO-RE compatible helper function to get source GID
static __always_inline int read_source_gid_core(struct ib_device *dev,
                                                __u8 port_num,
                                                union ib_gid *out_gid,
                                                __u8 gid_index) {
    // Initialize output to zero
    __builtin_memset(out_gid, 0, sizeof(*out_gid));

    // Validate input parameters
    if (!dev || !out_gid) {
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    if (port_num == INVALID_PORT_NUM || gid_index > MAX_GID_INDEX) {
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    // Use CO-RE to read device physical port count
    __u32 phys_port_cnt = BPF_CORE_READ(dev, phys_port_cnt);
    if (phys_port_cnt == 0) {
        bpf_printk("read_source_gid_core: phys_port_cnt is 0\n");
        increment_stat(STAT_CORE_READ_ERROR);
        return -1;
    }

    // Allow port_num 0 but convert to 1-based for array access
    __u8 port_for_access = (port_num == 0) ? 1 : port_num;

    if (port_for_access > phys_port_cnt) {
        // If port validation fails, try port 1 as fallback
        if (phys_port_cnt >= 1) {
            port_for_access = 1;
            bpf_printk("read_source_gid_core: port validation failed, using fallback port 1\n");
        } else {
            bpf_printk("read_source_gid_core: invalid port_num %d (converted %d, max: %d)\n",
                       port_num, port_for_access, phys_port_cnt);
            increment_stat(STAT_ERROR_COUNT);
            return -1;
        }
    }

        // Use CO-RE to read port data array directly
    struct ib_port_data *port_data_array = BPF_CORE_READ(dev, port_data);
    if (!port_data_array) {
        bpf_printk("read_source_gid_core: port_data is NULL\n");
        increment_stat(STAT_PORT_DATA_FAILURE);
        return -1;
    }

    bpf_printk("read_source_gid_core: successfully read port_data_array\n");

    // Use CO-RE to read port cache (convert to 0-indexed)
    struct ib_port_cache port_cache;
    int ret = bpf_core_read(&port_cache, sizeof(port_cache),
                           &port_data_array[port_for_access - 1].cache);
    if (ret != 0) {
        bpf_printk("read_source_gid_core: failed to read port cache\n");
        increment_stat(STAT_CORE_READ_ERROR);
        return -1;
    }

    bpf_printk("read_source_gid_core: successfully read port cache\n");

    // Use CO-RE to read GID table pointer
    struct ib_gid_table *gid_table_ptr;
    BPF_CORE_READ_INTO(&gid_table_ptr, &port_cache, gid);
    if (!gid_table_ptr) {
        bpf_printk("read_source_gid_core: gid_table_ptr is NULL\n");
        increment_stat(STAT_GID_TABLE_FAILURE);
        return -1;
    }

    bpf_printk("read_source_gid_core: gid_table_ptr = %p\n", gid_table_ptr);

    // Skip reading GID table length due to kernel structure incompatibility
    // Most RDMA devices have at least one GID entry at index 0
    bpf_printk("read_source_gid_core: accessing index %d directly with CO-RE\n", gid_index);

    // Use CO-RE to read data vector
    struct ib_gid_table_entry **data_vec_ptr;
    BPF_CORE_READ_INTO(&data_vec_ptr, gid_table_ptr, data_vec);
    if (!data_vec_ptr) {
        bpf_printk("read_source_gid_core: data_vec_ptr is NULL\n");
        increment_stat(STAT_CORE_READ_ERROR);
        return -1;
    }

    bpf_printk("read_source_gid_core: data_vec_ptr = %p\n", data_vec_ptr);

    // Limit GID index for safety
    if (gid_index > 1) {
        bpf_printk("read_source_gid_core: gid_index %d too high, using index 0\n", gid_index);
        gid_index = 0;
    }

    // Use CO-RE to read specific GID entry
    struct ib_gid_table_entry *gid_entry_ptr;
    ret = bpf_core_read(&gid_entry_ptr, sizeof(gid_entry_ptr), &data_vec_ptr[gid_index]);
    if (ret != 0) {
        bpf_printk("read_source_gid_core: failed to read gid_entry_ptr[%d]\n", gid_index);
        increment_stat(STAT_CORE_READ_ERROR);
        return -1;
    }

    if (!gid_entry_ptr) {
        bpf_printk("read_source_gid_core: gid_entry_ptr[%d] is NULL\n", gid_index);
        increment_stat(STAT_CORE_READ_ERROR);
        return -1;
    }

    bpf_printk("read_source_gid_core: gid_entry_ptr[%d] = %p\n", gid_index, gid_entry_ptr);

    // Use CO-RE to read the GID
    union ib_gid tmp_gid = BPF_CORE_READ(gid_entry_ptr, gid);

    // Verify GID is not all zeros (which would indicate a problem)
    int is_zero = 1;
    for (int i = 0; i < 16; i++) {
        if (tmp_gid.raw[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (is_zero) {
        bpf_printk("read_source_gid_core: GID is all zeros, might indicate inactive entry\n");
        increment_stat(STAT_GID_READ_FAILURE);
        return -1;
    }

    __builtin_memcpy(out_gid, &tmp_gid, sizeof(union ib_gid));
    bpf_printk("read_source_gid_core: GID read successful with CO-RE\n");
    bpf_printk("read_source_gid_core: GID bytes 0-1: %02x%02x\n", tmp_gid.raw[0], tmp_gid.raw[1]);
    increment_stat(STAT_GID_READ_SUCCESS);
    return 0;
}

// Common function to initialize event structure
static __always_inline void init_rdma_event(struct rdma_conn_tuple *event,
                                            __u8 event_type) {
    if (!event) return;

    // Set basic information
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = event_type;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = (__u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Initialize to safe defaults
    event->src_qpn = 0;
    event->dst_qpn = 0;
    event->qp_state = INVALID_QP_STATE;
    event->port_num = INVALID_PORT_NUM;
    event->reserved[0] = 0;
    event->reserved[1] = 0;
    __builtin_memset(&event->src_gid, 0, sizeof(event->src_gid));
    __builtin_memset(&event->dst_gid, 0, sizeof(event->dst_gid));
}

// CO-RE compatible helper function to read destination QP information
static __always_inline int read_dest_qp_info_core(struct ib_qp_attr *attr,
                                                  __s32 attr_mask,
                                                  struct rdma_conn_tuple *event) {
    if (!attr || !event) {
        bpf_printk("read_dest_qp_info_core: attr or event is NULL\n");
        return -1;
    }

    bpf_printk("read_dest_qp_info_core: attr_mask=0x%x\n", attr_mask);

        // Read destination information based on attr_mask using CO-RE
    if (attr_mask & IB_QP_AV) {
        bpf_printk("read_dest_qp_info_core: IB_QP_AV is set, reading ah_attr with CO-RE\n");

        struct rdma_ah_attr ah_attr_val = BPF_CORE_READ(attr, ah_attr);
        bpf_printk("read_dest_qp_info_core: ah_attr read successful with CO-RE, type=%d\n", ah_attr_val.type);

                // Always attempt to read GRH using CO-RE
        bpf_printk("read_dest_qp_info_core: attempting to read GRH with CO-RE\n");

        struct ib_global_route grh;
        BPF_CORE_READ_INTO(&grh, &ah_attr_val, grh);
        bpf_printk("read_dest_qp_info_core: GRH read successful with CO-RE\n");

        // Read other GRH fields using CO-RE for validation
        struct ib_gid_attr sgid_attr;
        BPF_CORE_READ_INTO(&sgid_attr, &grh, sgid_attr);
        bpf_printk("read_dest_qp_info_core: GRH sgid_attr read successful\n");

        union ib_gid sgid;
        BPF_CORE_READ_INTO(&sgid, &sgid_attr, gid);
        bpf_printk("read_dest_qp_info_core: GRH sgid read successful\n");

        // Check if sgid is non-zero
        int sgid_non_zero = 0;
        for (int i = 0; i < 16; i++) {
            if (sgid.raw[i] != 0) {
                sgid_non_zero = 1;
                break;
            }
        }
        bpf_printk("read_dest_qp_info_core: GRH sgid non-zero: %d\n", sgid_non_zero);

        __u32 flow_label;
        BPF_CORE_READ_INTO(&flow_label, &grh, flow_label);
        bpf_printk("read_dest_qp_info_core: GRH flow_label=0x%x\n", flow_label);

        __u8 sgid_index;
        BPF_CORE_READ_INTO(&sgid_index, &grh, sgid_index);
        bpf_printk("read_dest_qp_info_core: GRH sgid_index=%d\n", sgid_index);

        // Use CO-RE to get destination GID
        union ib_gid dgid;
        BPF_CORE_READ_INTO(&dgid, &grh, dgid);

        // Check if dst_gid is all zeros
        int dst_is_zero = 1;
        for (int i = 0; i < 16; i++) {
            if (dgid.raw[i] != 0) {
                dst_is_zero = 0;
                break;
            }
        }

        if (dst_is_zero) {
            bpf_printk("read_dest_qp_info_core: dst GID is all zeros from GRH\n");
            // Don't copy zero GID, leave event->dst_gid as initialized zeros
        } else {
            // Use a temporary variable to avoid packed struct alignment issues
            union ib_gid temp_dst_gid = dgid;
            __builtin_memcpy(&event->dst_gid, &temp_dst_gid, sizeof(union ib_gid));
            bpf_printk("read_dest_qp_info_core: dst GID read successful from GRH with CO-RE\n");
            bpf_printk("read_dest_qp_info_core: dst GID bytes 0-1: %02x%02x\n", dgid.raw[0], dgid.raw[1]);
        }
    } else {
        bpf_printk("read_dest_qp_info_core: IB_QP_AV not set in attr_mask\n");
    }

    // Read destination QPN if available using CO-RE
    if (attr_mask & IB_QP_DEST_QPN) {
        bpf_printk("read_dest_qp_info_core: IB_QP_DEST_QPN is set, reading dest_qp_num with CO-RE\n");

        __u32 dest_qp_num = BPF_CORE_READ(attr, dest_qp_num);
        event->dst_qpn = dest_qp_num;
        bpf_printk("read_dest_qp_info_core: dest_qp_num=%u\n", dest_qp_num);
    } else {
        bpf_printk("read_dest_qp_info_core: IB_QP_DEST_QPN not set in attr_mask\n");
    }

    return 0;
}

// CO-RE compatible function to hook ib_modify_qp
SEC("kprobe/ib_modify_qp_with_udata")
int trace_modify_qp(struct ib_qp *qp, struct ib_qp_attr *attr, int attr_mask) {
    struct rdma_conn_tuple *event;
    struct ib_device *dev;
    __u8 port_num_for_gid = INVALID_PORT_NUM;
    __s32 qp_state_val = INVALID_QP_STATE;

    if (!qp || !attr) {
        increment_stat(STAT_ERROR_COUNT);
        bpf_printk("trace_modify_qp: qp or attr is NULL\n");
        return 0;
    }

    // Early filtering: only proceed if IB_QP_STATE is set
    if (!(attr_mask & IB_QP_STATE)) {
        return 0;
    }

    // Read and validate QP state using CO-RE
    qp_state_val = BPF_CORE_READ(attr, qp_state);

    // Filter for RTR state transitions
    if (qp_state_val != IB_QPS_RTR) {
        return 0;
    }

    bpf_printk("trace_modify_qp: RTR transition detected with CO-RE\n");

    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&rdma_events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_ERROR_COUNT);
        bpf_printk("trace_modify_qp: failed to reserve ringbuf space\n");
        return 0;
    }

    // Initialize event structure
    init_rdma_event(event, RDMA_EVENT_MODIFY);
    event->qp_state = qp_state_val;

    // Read source QPN using CO-RE
    __u32 src_qpn = BPF_CORE_READ(qp, qp_num);
    event->src_qpn = src_qpn;
    bpf_printk("trace_modify_qp: src_qpn=%u (CO-RE)\n", src_qpn);

    // Read destination QP information using CO-RE (continue even if this fails)
    if (read_dest_qp_info_core(attr, attr_mask, event) != 0) {
        bpf_printk("trace_modify_qp: read_dest_qp_info_core failed, continuing with zero dst info\n");
    } else {
        bpf_printk("trace_modify_qp: dst_qpn=%u, dst_gid read attempt completed with CO-RE\n", event->dst_qpn);
    }

    // Determine port number for GID lookup using CO-RE
    if (attr_mask & IB_QP_PORT) {
        __u8 attr_port_num = BPF_CORE_READ(attr, port_num);
        port_num_for_gid = attr_port_num;
        bpf_printk("trace_modify_qp: using port from attr: %u (CO-RE)\n", port_num_for_gid);
    }

    // If port_num_for_gid is still invalid, try QP's port using CO-RE
    if (port_num_for_gid == INVALID_PORT_NUM) {
        __u8 qp_port = BPF_CORE_READ(qp, port);
        port_num_for_gid = qp_port;
        bpf_printk("trace_modify_qp: using port from qp: %u (CO-RE)\n", port_num_for_gid);
    }

    // If still invalid, use default port 1
    if (port_num_for_gid == INVALID_PORT_NUM || port_num_for_gid == 0) {
        port_num_for_gid = 1;  // Default to port 1
        bpf_printk("trace_modify_qp: using default port: %u\n", port_num_for_gid);
    }

    event->port_num = port_num_for_gid;

    // Read source GID using CO-RE
    dev = BPF_CORE_READ(qp, device);
    if (dev) {
        bpf_printk("trace_modify_qp: attempting to read src_gid with port %u (CO-RE)\n", port_num_for_gid);
        union ib_gid tmp_src_gid;
        if (read_source_gid_core(dev, port_num_for_gid, &tmp_src_gid, DEFAULT_GID_INDEX) == 0) {
            __builtin_memcpy(&event->src_gid, &tmp_src_gid, sizeof(union ib_gid));
            bpf_printk("trace_modify_qp: src_gid read successful with CO-RE\n");
        } else {
            bpf_printk("trace_modify_qp: src_gid read failed with CO-RE, will be zero\n");
        }
    } else {
        bpf_printk("trace_modify_qp: device pointer is NULL\n");
    }

    increment_stat(STAT_MODIFY_COUNT);

    // Debug: Log key fields before submitting to verify correctness
    bpf_printk("trace_modify_qp: final validation - src_qpn=%u, dst_qpn=%u (CO-RE)\n", event->src_qpn, event->dst_qpn);
    bpf_printk("trace_modify_qp: struct size check - expected=80, actual=%d\n", sizeof(*event));

    bpf_ringbuf_submit(event, 0);
    bpf_printk("trace_modify_qp: event submitted to ringbuf with CO-RE\n");
    return 0;
}

// CO-RE compatible function to hook ib_destroy_qp_user
SEC("kprobe/ib_destroy_qp_user")
int trace_destroy_qp_user(struct ib_qp *qp, struct ib_udata *udata) {
    struct rdma_conn_tuple *event;
    struct ib_device *dev;
    __u8 port_num_from_qp = INVALID_PORT_NUM;

    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&rdma_events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_ERROR_COUNT);
        return 0;
    }

    // Initialize event structure
    init_rdma_event(event, RDMA_EVENT_DESTROY);

    // Read source QPN using CO-RE
    __u32 src_qpn = BPF_CORE_READ(qp, qp_num);

    if (src_qpn == 0) {
        increment_stat(STAT_ERROR_COUNT);
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    event->src_qpn = src_qpn;

    // Read port number from QP using CO-RE
    __u8 qp_port = BPF_CORE_READ(qp, port);

    if (qp_port == INVALID_PORT_NUM) {
        increment_stat(STAT_ERROR_COUNT);
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    port_num_from_qp = qp_port;
    event->port_num = port_num_from_qp;

    // Read source GID using CO-RE
    dev = BPF_CORE_READ(qp, device);
    if (dev) {
        union ib_gid tmp_src_gid;
        if (read_source_gid_core(dev, port_num_from_qp, &tmp_src_gid, DEFAULT_GID_INDEX) == 0) {
            __builtin_memcpy(&event->src_gid, &tmp_src_gid, sizeof(union ib_gid));
            bpf_printk("trace_destroy_qp_user: src_gid read successful with CO-RE\n");
        }
    }

    increment_stat(STAT_DESTROY_COUNT);
    bpf_ringbuf_submit(event, 0);
    bpf_printk("trace_destroy_qp_user: event submitted with CO-RE\n");
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
