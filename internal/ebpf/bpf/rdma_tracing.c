// go:build ignore

// Support for CO-RE (Compile Once - Run Everywhere)
#include "minimal_vmlinux.h"
#include "minimal_ib_verbs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Constants for better maintainability
#define DEFAULT_GID_INDEX 1
#define MAX_GID_INDEX 255
#define RDMA_AH_ATTR_GRH 1
#define INVALID_QP_STATE -1
#define INVALID_PORT_NUM 0

// Event type definitions
#define RDMA_EVENT_CREATE 1
#define RDMA_EVENT_MODIFY 2
#define RDMA_EVENT_DESTROY 3

// Ring buffer configuration
#define RDMA_RINGBUF_SIZE (1 << 24)  // 16MB - configurable

// Structure definition for RDMA 5-tuple information
// Optimized layout to minimize padding
struct rdma_conn_tuple {
    __u64 timestamp;       // Timestamp when the event occurred
    union ib_gid src_gid;  // Source Global Identifier (GID) - 16 bytes
    union ib_gid dst_gid;  // Destination Global Identifier (GID) - 16 bytes
    __u32 src_qpn;         // Source Queue Pair Number
    __u32 dst_qpn;         // Destination Queue Pair Number
    __u32 pid;             // Process ID
    __u32 tid;             // Thread ID
    __s32 qp_state;        // QP state (valid only for modify_qp)
    __u8 event_type;       // Event type (1: create, 2: modify, 3: destroy)
    __u8 port_num;         // Port number for debugging
    __u8 reserved[2];      // Explicit padding for alignment
    char comm[16];         // Process name
} __attribute__((packed));

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
};

// Helper function to increment statistics
static __always_inline void increment_stat(__u32 key) {
    __u64 *value = bpf_map_lookup_elem(&rdma_stats, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

// Improved helper function to get source GID with better error handling
static __always_inline int read_source_gid_safe(struct ib_device *dev,
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

    // Read device physical port count
    __u32 phys_port_cnt = BPF_CORE_READ(dev, phys_port_cnt);
    if (port_num > phys_port_cnt || port_num == 0) {
        bpf_printk("read_source_gid_safe: invalid port_num %d (max: %d)\n",
                   port_num, phys_port_cnt);
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    // Get port data array
    struct ib_port_data *port_data_array = BPF_CORE_READ(dev, port_data);
    if (!port_data_array) {
        bpf_printk("read_source_gid_safe: dev->port_data is NULL\n");
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    // Access the specific port_data_entry (convert to 0-indexed)
    struct ib_port_data *port_data_entry = &port_data_array[port_num - 1];
    if (!port_data_entry) {
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    // Get port cache
    struct ib_port_cache *port_cache_ptr = &port_data_entry->cache;

    // Read GID table pointer
    struct ib_gid_table *gid_table_ptr = NULL;
    if (bpf_core_read(&gid_table_ptr, sizeof(gid_table_ptr),
                      &port_cache_ptr->gid) != 0) {
        bpf_printk("read_source_gid_safe: failed to read gid_table_ptr\n");
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    if (!gid_table_ptr) {
        bpf_printk("read_source_gid_safe: gid_table_ptr is NULL\n");
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    // Read GID table length
    __s32 gid_tbl_len = 0;
    if (bpf_core_read(&gid_tbl_len, sizeof(gid_tbl_len), &gid_table_ptr->sz) !=
        0) {
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    if (gid_index >= gid_tbl_len || gid_tbl_len <= 0) {
        bpf_printk(
            "read_source_gid_safe: gid_index %d out of bounds (len: %d)\n",
            gid_index, gid_tbl_len);
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    // Read data vector
    struct ib_gid_table_entry **data_vec_ptr = NULL;
    if (bpf_core_read(&data_vec_ptr, sizeof(data_vec_ptr),
                      &gid_table_ptr->data_vec) != 0) {
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    if (!data_vec_ptr) {
        bpf_printk("read_source_gid_safe: data_vec_ptr is NULL\n");
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    // Read specific GID entry
    struct ib_gid_table_entry *gid_entry_ptr = NULL;
    if (bpf_core_read(&gid_entry_ptr, sizeof(gid_entry_ptr),
                      &data_vec_ptr[gid_index]) != 0) {
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    if (!gid_entry_ptr) {
        bpf_printk("read_source_gid_safe: gid_entry_ptr[%d] is NULL\n",
                   gid_index);
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

    // Finally read the GID
    if (bpf_core_read(out_gid, sizeof(*out_gid), &gid_entry_ptr->gid) != 0) {
        increment_stat(STAT_ERROR_COUNT);
        return -1;
    }

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

// Helper function to read destination QP information
static __always_inline int read_dest_qp_info(struct ib_qp_attr *attr,
                                             __s32 attr_mask,
                                             struct rdma_conn_tuple *event) {
    if (!attr || !event) {
        return -1;
    }

    // Read destination information based on attr_mask
    if (attr_mask & IB_QP_AV) {
        struct rdma_ah_attr ah_attr_val;
        if (bpf_core_read(&ah_attr_val, sizeof(ah_attr_val), &attr->ah_attr) !=
            0) {
            return -1;
        }

        __u8 ah_flags_val = 0;
        if (bpf_core_read(&ah_flags_val, sizeof(ah_flags_val),
                          &ah_attr_val.ah_flags) != 0) {
            return -1;
        }

        if (ah_flags_val & RDMA_AH_ATTR_GRH) {
            // GRH is present, read destination GID
            if (bpf_core_read(&event->dst_gid, sizeof(event->dst_gid),
                              &ah_attr_val.grh.dgid) != 0) {
                return -1;
            }
        }
    }

    // Read destination QPN if available
    if (attr_mask & IB_QP_DEST_QPN) {
        if (bpf_core_read(&event->dst_qpn, sizeof(event->dst_qpn),
                          &attr->dest_qp_num) != 0) {
            return -1;
        }
    }

    return 0;
}

// Function to hook ib_modify_qp
SEC("kprobe/ib_modify_qp")
int BPF_KPROBE(trace_modify_qp, struct ib_qp *qp, struct ib_qp_attr *attr,
               int attr_mask) {
    struct rdma_conn_tuple *event;
    struct ib_device *dev;
    __u8 port_num_for_gid = INVALID_PORT_NUM;
    __s32 qp_state_val = INVALID_QP_STATE;

    // Early filtering: only proceed if IB_QP_STATE is set
    if (!(attr_mask & IB_QP_STATE)) {
        return 0;
    }

    // Read and validate QP state
    if (bpf_core_read(&qp_state_val, sizeof(qp_state_val), &attr->qp_state) !=
        0) {
        increment_stat(STAT_ERROR_COUNT);
        return 0;
    }

    // Filter for RTR state transitions
    if (qp_state_val != IB_QPS_RTR) {
        return 0;
    }

    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&rdma_events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_ERROR_COUNT);
        return 0;
    }

    // Initialize event structure
    init_rdma_event(event, RDMA_EVENT_MODIFY);
    event->qp_state = qp_state_val;

    // Read source QPN
    if (bpf_core_read(&event->src_qpn, sizeof(event->src_qpn), &qp->qp_num) !=
        0) {
        increment_stat(STAT_ERROR_COUNT);
        goto submit_event;
    }

    // Read destination QP information
    read_dest_qp_info(attr, attr_mask, event);

    // Determine port number for GID lookup
    if (attr_mask & IB_QP_PORT) {
        bpf_core_read(&port_num_for_gid, sizeof(port_num_for_gid),
                      &attr->port_num);
    } else {
        // Fallback to QP's port
        bpf_core_read(&port_num_for_gid, sizeof(port_num_for_gid), &qp->port);
    }
    event->port_num = port_num_for_gid;

    // Read source GID
    dev = BPF_CORE_READ(qp, device);
    if (dev) {
        read_source_gid_safe(dev, port_num_for_gid, &event->src_gid,
                             DEFAULT_GID_INDEX);
    }

submit_event:
    increment_stat(STAT_MODIFY_COUNT);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Function to hook ib_destroy_qp
SEC("kprobe/ib_destroy_qp")
int BPF_KPROBE(trace_destroy_qp, struct ib_qp *qp) {
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

    // Read source QPN
    if (bpf_core_read(&event->src_qpn, sizeof(event->src_qpn), &qp->qp_num) !=
        0) {
        increment_stat(STAT_ERROR_COUNT);
        goto submit_event;
    }

    // Read port number from QP
    bpf_core_read(&port_num_from_qp, sizeof(port_num_from_qp), &qp->port);
    event->port_num = port_num_from_qp;

    // Read source GID
    dev = BPF_CORE_READ(qp, device);
    if (dev) {
        read_source_gid_safe(dev, port_num_from_qp, &event->src_gid,
                             DEFAULT_GID_INDEX);
    }

submit_event:
    increment_stat(STAT_DESTROY_COUNT);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Function to hook ib_create_qp
SEC("kprobe/ib_create_qp")
int BPF_KPROBE(trace_create_qp, struct ib_pd *pd,
               struct ib_qp_init_attr *init_attr) {
    struct rdma_conn_tuple *event;

    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&rdma_events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_ERROR_COUNT);
        return 0;
    }

    // Initialize event structure
    init_rdma_event(event, RDMA_EVENT_CREATE);

    // For create events, most information is not available yet
    // QPN will be assigned after creation, so we can't read it here

    increment_stat(STAT_CREATE_COUNT);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
