/*
 * rdma_bridge.h - C-ABI interface between Go (Cgo) and Zig RDMA library
 *
 * This header is the single source of truth for the Zig-Go RDMA interface.
 * The Zig library implements these functions with @export.
 * The Go bridge (rdmabridge/bridge.go) calls them via Cgo.
 *
 * ABI safety rules:
 *   - No bool types: use uint8_t (0 = false, 1 = true)
 *   - GIDs are 16-byte binary internally (rdma_gid_t)
 *   - All structs use explicit fixed-width integer types
 *   - Return codes: 0 = success, negative = error
 */

#ifndef RDMA_BRIDGE_H
#define RDMA_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Constants
 * ========================================================================= */

/* Queue type identifiers */
#define RDMA_QUEUE_TYPE_SENDER    0
#define RDMA_QUEUE_TYPE_RESPONDER 1

/* Memory and buffer sizing */
#define RDMA_MR_SIZE              4096
#define RDMA_GRH_SIZE             40
#define RDMA_CQ_SIZE              256
#define RDMA_INITIAL_RECV_BUFFERS 32

/* Protocol constants */
#define RDMA_QKEY              0x11111111
#define RDMA_PROBE_PACKET_SIZE 40

/* =========================================================================
 * Opaque Handle Types
 *
 * These handles are created and managed by the Zig library. Go code must
 * treat them as opaque pointers and only pass them back to Zig functions.
 * ========================================================================= */

typedef void* rdma_context_t;
typedef void* rdma_device_t;
typedef void* rdma_queue_t;
typedef void* rdma_event_ring_t;

/* =========================================================================
 * Data Structures
 * ========================================================================= */

/*
 * rdma_gid_t - GID as 16-byte binary representation
 *
 * Internally used for addressing. This is the raw 128-bit GID value
 * (equivalent to an IPv6 address or IPv4-mapped IPv6 address).
 * String conversion is performed at higher layers.
 */
typedef struct {
    uint8_t raw[16];
} rdma_gid_t;

/*
 * rdma_device_info_t - Device information returned to Go after opening
 *
 * Contains human-readable device identification and addressing info.
 * Filled by rdma_open_device() / rdma_open_device_by_name().
 */
typedef struct {
    char    device_name[64];     /* RDMA device name (e.g., "mlx5_0", "rxe0") */
    char    gid[64];             /* GID string representation for display */
    char    ip_addr[64];         /* Associated IP address string */
    uint8_t active_port;         /* Active port number (1-based) */
    uint8_t active_gid_index;    /* GID table index in use */
} rdma_device_info_t;

/*
 * rdma_queue_info_t - Queue Pair information returned after creation
 *
 * No bool types - uses uint8_t for ABI safety across Go/Zig boundary.
 */
typedef struct {
    uint32_t qpn;                 /* Queue Pair Number assigned by the hardware */
    uint8_t  uses_sw_timestamps;  /* 0 = hardware timestamps, 1 = software timestamps */
} rdma_queue_info_t;

/*
 * rdma_completion_event_t - Completion event written into ring buffer
 *
 * The Zig CQ poller fills this struct and pushes it into the event ring.
 * Go polls the ring to receive these events without crossing the FFI
 * boundary per-event.
 *
 * Timestamp fields (t1, t3, t4) are extracted from the probe packet
 * payload using big-endian decoding. timestamp_ns is the hardware or
 * software completion timestamp of this particular work completion.
 */
typedef struct {
    uint64_t   sequence_num;     /* Probe sequence number */
    uint64_t   t1;               /* From probe payload (BigEndian decoded) */
    uint64_t   t3;               /* From probe payload */
    uint64_t   t4;               /* From probe payload */
    uint8_t    is_ack;           /* 0 = probe, 1 = ACK */
    uint8_t    ack_type;         /* 1 = first ACK, 2 = second ACK */
    uint8_t    flags;            /* Reserved for future use */
    uint8_t    _pad;             /* Explicit padding for alignment */
    uint64_t   timestamp_ns;     /* HW or SW timestamp of this completion (ns) */
    rdma_gid_t source_gid;      /* Source GID parsed from GRH (16 bytes binary) */
    uint32_t   source_qpn;      /* Source QPN from work completion */
    uint32_t   flow_label;      /* Flow label from GRH IPv6 header */
    int32_t    status;           /* 0 = success, nonzero = RDMA error code */
    uint8_t    is_send;          /* 0 = receive completion, 1 = send completion */
    uint8_t    _pad2[3];         /* Explicit padding to maintain alignment */
} rdma_completion_event_t;

/*
 * rdma_send_result_t - Result of a synchronous probe send operation
 *
 * Returned by rdma_send_probe(). Contains the T1 (post time) and T2
 * (send completion time) timestamps, plus an error indicator.
 *
 * Size: 24 bytes (8 + 8 + 4 + 4 explicit padding).
 * The Zig extern struct (t1_ns u64 + t2_ns u64 + err i32) is 20 bytes of
 * fields but Zig pads the extern struct to 24 bytes to satisfy the 8-byte
 * alignment of the u64 members. The C struct must match: without an explicit
 * _pad field the C compiler also pads to 24 bytes implicitly, but the
 * explicit field makes the intent clear and prevents accidental shrinkage.
 * On x86-64 Linux SysV ABI a struct > 16 bytes is returned via a hidden
 * pointer, so both sides must agree on sizeof. Verified by the Zig test:
 *   try std.testing.expectEqual(@as(usize, 24), @sizeOf(SendResult));
 */
typedef struct {
    uint64_t t1_ns;              /* T1: time just before posting the send (ns) */
    uint64_t t2_ns;              /* T2: send completion timestamp from CQ (ns) */
    int32_t  error;              /* 0 = success, nonzero = error code */
    uint32_t _pad;               /* Explicit trailing padding to reach 24 bytes,
                                  * matching Zig extern struct alignment. */
} rdma_send_result_t;

/* =========================================================================
 * Context Lifecycle
 *
 * A context encapsulates the global RDMA state: device list, protection
 * domains, and other shared resources. Exactly one context should be
 * created per process.
 * ========================================================================= */

/*
 * rdma_init - Initialize the RDMA subsystem and create a context
 *
 * Enumerates available RDMA devices. The context must be destroyed
 * with rdma_destroy() when no longer needed.
 *
 * @param out_ctx  Receives the newly created context handle
 * @return         0 on success, negative error code on failure
 */
int32_t rdma_init(rdma_context_t* out_ctx);

/*
 * rdma_destroy - Tear down the RDMA context and release all resources
 *
 * All devices and queues must be closed/destroyed before calling this.
 *
 * @param ctx  Context handle from rdma_init()
 */
void rdma_destroy(rdma_context_t ctx);

/* =========================================================================
 * Device Operations
 *
 * Functions to enumerate, open, and close RDMA devices. Each opened
 * device allocates a Protection Domain and queries the active port/GID.
 * ========================================================================= */

/*
 * rdma_get_device_count - Return the number of available RDMA devices
 *
 * @param ctx  Context handle
 * @return     Number of devices (>= 0), or negative error code
 */
int32_t rdma_get_device_count(rdma_context_t ctx);

/*
 * rdma_open_device - Open an RDMA device by index
 *
 * Opens the device at the given index in the device list, queries the
 * specified GID index on the first active port, allocates a PD, and
 * populates the device info struct.
 *
 * @param ctx        Context handle
 * @param index      Device index (0-based)
 * @param gid_index  GID table index to use on the active port
 * @param out_dev    Receives the device handle
 * @param out_info   Receives device information (name, GID, IP, port)
 * @return           0 on success, negative error code on failure
 */
int32_t rdma_open_device(rdma_context_t ctx, int32_t index, int32_t gid_index,
                         rdma_device_t* out_dev, rdma_device_info_t* out_info);

/*
 * rdma_open_device_by_name - Open an RDMA device by name
 *
 * Same as rdma_open_device but looks up the device by name (e.g., "mlx5_0").
 *
 * @param ctx        Context handle
 * @param name       Null-terminated device name string
 * @param gid_index  GID table index to use on the active port
 * @param out_dev    Receives the device handle
 * @param out_info   Receives device information
 * @return           0 on success, negative error code on failure
 */
int32_t rdma_open_device_by_name(rdma_context_t ctx, const char* name,
                                 int32_t gid_index, rdma_device_t* out_dev,
                                 rdma_device_info_t* out_info);

/*
 * rdma_close_device - Close an RDMA device and free its resources
 *
 * Deallocates the PD and closes the device context. All queues
 * associated with this device must be destroyed first.
 *
 * @param dev  Device handle from rdma_open_device()
 */
void rdma_close_device(rdma_device_t dev);

/* =========================================================================
 * Queue Operations
 *
 * Create and destroy UD (Unreliable Datagram) Queue Pairs. Each queue
 * includes a QP, CQ, memory regions, and completion polling state.
 * The event ring is used by the CQ poller to deliver completion events
 * to Go without per-event FFI calls.
 * ========================================================================= */

/*
 * rdma_create_queue - Create a UD Queue Pair
 *
 * Creates a QP, transitions it to RTS state, allocates send/recv buffers
 * and memory regions, and starts the CQ poller thread.
 *
 * @param dev         Device handle
 * @param queue_type  RDMA_QUEUE_TYPE_SENDER or RDMA_QUEUE_TYPE_RESPONDER
 * @param ring        Event ring for completion event delivery
 * @param out_queue   Receives the queue handle
 * @param out_info    Receives queue information (QPN, timestamp mode)
 * @return            0 on success, negative error code on failure
 */
int32_t rdma_create_queue(rdma_device_t dev, int32_t queue_type,
                          rdma_event_ring_t ring, rdma_queue_t* out_queue,
                          rdma_queue_info_t* out_info);

/*
 * rdma_destroy_queue - Destroy a UD Queue Pair and free all resources
 *
 * Stops the CQ poller, deregisters memory regions, destroys QP/CQ.
 *
 * @param queue  Queue handle from rdma_create_queue()
 */
void rdma_destroy_queue(rdma_queue_t queue);

/* =========================================================================
 * Data Path - Probe and ACK Operations
 *
 * These functions implement the R-Pingmesh probing protocol:
 *   1. Prober sends probe       -> rdma_send_probe()
 *   2. Responder sends 1st ACK  -> rdma_send_first_ack()
 *   3. Responder sends 2nd ACK  -> rdma_send_second_ack()
 *
 * Completions are delivered asynchronously via the event ring.
 * ========================================================================= */

/*
 * rdma_send_probe - Send a probe packet to a remote target
 *
 * Constructs a ProbePacket with the given sequence number, creates an
 * address handle for the target GID, posts the send WR, and waits for
 * send completion.
 *
 * @param queue         Sender queue handle
 * @param target_gid    Target GID (16-byte binary)
 * @param target_qpn    Target Queue Pair Number
 * @param sequence_num  Probe sequence number
 * @param flow_label    IPv6 flow label for ECMP path selection
 * @param timeout_ms    Send completion timeout in milliseconds
 * @return              rdma_send_result_t with t1_ns, t2_ns, and error
 */
rdma_send_result_t rdma_send_probe(rdma_queue_t queue,
                                   const rdma_gid_t* target_gid,
                                   uint32_t target_qpn,
                                   uint64_t sequence_num,
                                   uint32_t flow_label,
                                   uint32_t timeout_ms);

/*
 * rdma_send_first_ack - Send the first ACK in response to a probe
 *
 * Corresponds to step 2 in the R-Pingmesh protocol (Figure 4 in the paper).
 * Echoes T1 from the probe, records T3 (receive time), and sends the ACK.
 * Outputs T4 (the send completion timestamp of this first ACK).
 *
 * @param queue              Responder queue handle
 * @param target_gid         Prober's GID (16-byte binary, from GRH)
 * @param target_qpn         Prober's QPN
 * @param flow_label         Flow label to maintain same ECMP path
 * @param recv_packet        Raw received packet buffer (for payload extraction)
 * @param recv_timestamp_ns  T3: receive completion timestamp (ns)
 * @param out_t4_ns          Receives T4: first ACK send completion time (ns)
 * @param timeout_ms         Send completion timeout in milliseconds
 * @return                   0 on success, negative error code on failure
 */
int32_t rdma_send_first_ack(rdma_queue_t queue,
                            const rdma_gid_t* target_gid,
                            uint32_t target_qpn,
                            uint32_t flow_label,
                            const uint8_t* recv_packet,
                            uint64_t recv_timestamp_ns,
                            uint64_t* out_t4_ns,
                            uint32_t timeout_ms);

/*
 * rdma_send_second_ack - Send the second ACK with processing delay info
 *
 * Corresponds to step 3 in the R-Pingmesh protocol (Figure 4 in the paper).
 * Contains T3 and T4 so the prober can compute the responder processing
 * delay and subtract it from the round-trip time.
 *
 * @param queue         Responder queue handle
 * @param target_gid    Prober's GID (16-byte binary)
 * @param target_qpn    Prober's QPN
 * @param flow_label    Flow label to maintain same ECMP path
 * @param recv_packet   Raw received packet buffer (for sequence number extraction)
 * @param t3_ns         T3: probe receive completion timestamp (ns)
 * @param t4_ns         T4: first ACK send completion timestamp (ns)
 * @param timeout_ms    Send completion timeout in milliseconds
 * @return              0 on success, negative error code on failure
 */
int32_t rdma_send_second_ack(rdma_queue_t queue,
                             const rdma_gid_t* target_gid,
                             uint32_t target_qpn,
                             uint32_t flow_label,
                             const uint8_t* recv_packet,
                             uint64_t t3_ns,
                             uint64_t t4_ns,
                             uint32_t timeout_ms);

/* =========================================================================
 * Event Ring Buffer
 *
 * A lock-free SPSC (Single Producer, Single Consumer) ring buffer for
 * delivering completion events from the Zig CQ poller thread to Go.
 * The Zig side produces events; Go polls for them.
 * ========================================================================= */

/*
 * rdma_event_ring_create - Create an event ring buffer
 *
 * @param capacity  Number of rdma_completion_event_t slots (should be power of 2)
 * @return          Ring handle, or NULL on failure
 */
rdma_event_ring_t rdma_event_ring_create(uint32_t capacity);

/*
 * rdma_event_ring_poll - Poll the event ring for completion events
 *
 * Non-blocking: copies up to max_count events into the output array.
 * Returns immediately with 0 if no events are available.
 *
 * @param ring        Ring handle
 * @param out_events  Array to receive completion events
 * @param max_count   Maximum number of events to retrieve
 * @return            Number of events retrieved (>= 0), or negative on error
 */
int32_t rdma_event_ring_poll(rdma_event_ring_t ring,
                             rdma_completion_event_t* out_events,
                             int32_t max_count);

/*
 * rdma_event_ring_destroy - Destroy an event ring buffer
 *
 * @param ring  Ring handle from rdma_event_ring_create()
 */
void rdma_event_ring_destroy(rdma_event_ring_t ring);

/* =========================================================================
 * Error Reporting
 * ========================================================================= */

/*
 * rdma_get_last_error - Get the last error message as a string
 *
 * Returns a pointer to a thread-local error string. The pointer is valid
 * until the next call to any rdma_* function on the same thread.
 *
 * @return  Null-terminated error string, or empty string if no error
 */
const char* rdma_get_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* RDMA_BRIDGE_H */
