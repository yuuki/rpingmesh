// queue.zig - UD Queue Pair lifecycle management.
//
// This module handles the creation and destruction of Unreliable Datagram (UD)
// Queue Pairs, including:
//   - Extended CQ creation with hardware timestamp fallback
//   - QP creation and state transitions (INIT -> RTR -> RTS)
//   - Buffer allocation and initial receive buffer posting
//   - Address Handle (AH) creation for sending to remote targets
//   - CQ poller thread startup and teardown
//
// The design follows the existing Go implementation in internal/rdma/queue.go
// but uses Zig idioms and the SPSC ring buffer for event delivery.

const std = @import("std");
const types = @import("types.zig");
const ring = @import("ring.zig");
const memory = @import("memory.zig");
const cq = @import("cq.zig");
const c = types.c;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during queue operations.
pub const QueueError = error{
    /// Memory allocation failed for the UdQueue struct.
    OutOfMemory,
    /// ibv_create_comp_channel() returned null.
    CreateCompChannelFailed,
    /// ibv_create_cq_ex() returned null (both HW and SW timestamp attempts).
    CreateCqFailed,
    /// ibv_create_qp() returned null.
    CreateQpFailed,
    /// ibv_modify_qp() failed during INIT transition.
    ModifyQpInitFailed,
    /// ibv_modify_qp() failed during RTR transition.
    ModifyQpRtrFailed,
    /// ibv_modify_qp() failed during RTS transition.
    ModifyQpRtsFailed,
    /// Buffer allocation or MR registration failed.
    BufferAllocFailed,
    /// Failed to post initial receive buffers.
    PostRecvFailed,
    /// Failed to start the CQ poller thread.
    StartPollerFailed,
    /// ibv_create_ah() returned null.
    CreateAhFailed,
    /// ibv_cq_ex_to_cq() returned null.
    CqConversionFailed,
};

// ---------------------------------------------------------------------------
// Queue creation
// ---------------------------------------------------------------------------

/// Create a UD Queue Pair with all associated resources.
///
/// This function performs the full queue initialization sequence:
///   1. Allocate the UdQueue struct
///   2. Create a completion channel for event notification
///   3. Create extended CQs (with HW timestamp fallback)
///   4. Create a UD QP with the CQs
///   5. Transition the QP through INIT -> RTR -> RTS states
///   6. Allocate send and receive buffers
///   7. Post initial receive buffers
///   8. Start the CQ poller thread
///
/// On failure, all partially allocated resources are cleaned up before
/// returning the error.
pub fn createQueue(
    dev: *types.RdmaDevice,
    queue_type: types.QueueType,
    event_ring: *ring.EventRing,
) QueueError!*types.UdQueue {
    // Allocate the UdQueue struct
    const queue = std.heap.page_allocator.create(types.UdQueue) catch {
        types.setLastError("failed to allocate UdQueue struct");
        return QueueError.OutOfMemory;
    };
    errdefer std.heap.page_allocator.destroy(queue);

    // Step 1: Create completion channel for event-driven CQ notification
    const comp_channel = c.ibv_create_comp_channel(dev.ctx) orelse {
        types.setLastError("ibv_create_comp_channel() failed");
        return QueueError.CreateCompChannelFailed;
    };
    errdefer _ = c.ibv_destroy_comp_channel(comp_channel);

    // Step 2: Create extended CQs with conditional HW timestamp support.
    // First try with wallclock timestamp; if the device does not support it
    // (returns EOPNOTSUPP/ENOTSUP), retry without the timestamp flag.
    const cq_result = createExtendedCqs(dev, comp_channel) orelse {
        // Error message already set by createExtendedCqs
        return QueueError.CreateCqFailed;
    };
    errdefer {
        destroyCqEx(cq_result.recv_cq);
        if (cq_result.send_cq != cq_result.recv_cq) {
            destroyCqEx(cq_result.send_cq);
        }
    }

    // Step 3: Create the UD QP
    const qp = createUdQp(dev, cq_result.send_cq, cq_result.recv_cq) orelse {
        types.setLastError("ibv_create_qp() failed");
        return QueueError.CreateQpFailed;
    };
    errdefer _ = c.ibv_destroy_qp(qp);

    // Step 4: Transition QP through INIT -> RTR -> RTS
    try transitionQpToInit(dev, qp);
    try transitionQpToRtr(qp);
    try transitionQpToRts(qp);

    // Step 5: Allocate send and receive buffers
    const send_bufset = memory.allocateBuffers(dev, types.NUM_SEND_SLOTS) catch {
        types.setLastError("failed to allocate send buffers");
        return QueueError.BufferAllocFailed;
    };
    errdefer {
        var mutable_send = send_bufset;
        memory.freeBuffers(&mutable_send);
    }

    const recv_bufset = memory.allocateBuffers(dev, types.NUM_RECV_SLOTS) catch {
        types.setLastError("failed to allocate recv buffers");
        return QueueError.BufferAllocFailed;
    };
    errdefer {
        var mutable_recv = recv_bufset;
        memory.freeBuffers(&mutable_recv);
    }

    // Initialize the queue struct
    queue.* = types.UdQueue{
        .qp = qp,
        .send_cq = cq_result.send_cq,
        .recv_cq = cq_result.recv_cq,
        .send_mr = send_bufset.mr,
        .recv_mr = recv_bufset.mr,
        .send_buf = send_bufset.buf,
        .recv_buf = recv_bufset.buf,
        .qpn = qp.qp_num,
        .uses_sw_timestamps = cq_result.uses_sw_timestamps,
        .queue_type = queue_type,
        .event_ring = event_ring,
        .cq_thread = null,
        .device = dev,
        .send_slot_states = [_]types.SlotState{types.SlotState.Free} ** types.NUM_SEND_SLOTS,
        .recv_slot_states = [_]types.SlotState{types.SlotState.Free} ** types.NUM_RECV_SLOTS,
        .running = std.atomic.Value(bool).init(false),
        .comp_channel = comp_channel,
        .send_completion_ready = std.atomic.Value(bool).init(false),
        .send_completion_timestamp = std.atomic.Value(u64).init(0),
        .send_completion_status = std.atomic.Value(i32).init(0),
    };

    // Step 6: Post initial receive buffers
    memory.postInitialRecvBuffers(qp, recv_bufset.mr, recv_bufset.buf, types.INITIAL_RECV_BUFFERS) catch {
        types.setLastError("failed to post initial recv buffers");
        return QueueError.PostRecvFailed;
    };

    // Step 7: Start the CQ poller thread
    cq.startCqPollerThread(queue) catch {
        types.setLastError("failed to start CQ poller thread");
        return QueueError.StartPollerFailed;
    };

    return queue;
}

// ---------------------------------------------------------------------------
// Queue destruction
// ---------------------------------------------------------------------------

/// Destroy a UD Queue Pair and free all associated resources.
///
/// This function performs cleanup in the correct order:
///   1. Stop the CQ poller thread
///   2. Destroy the QP
///   3. Free send/recv buffers and deregister MRs
///   4. Destroy CQs
///   5. Destroy the completion channel
///   6. Free the queue struct
pub fn destroyQueue(queue: *types.UdQueue) void {
    // Stop the CQ poller thread (sets running=false and joins)
    cq.stopCqPollerThread(queue);

    // Destroy the QP first (before CQs, as QP references them)
    _ = c.ibv_destroy_qp(queue.qp);

    // Free send buffers and deregister send MR
    _ = c.ibv_dereg_mr(queue.send_mr);
    const send_total = @as(usize, types.NUM_SEND_SLOTS) * @as(usize, types.SLOT_SIZE);
    const send_slice = queue.send_buf[0..send_total];
    std.heap.page_allocator.free(@alignCast(send_slice));

    // Free recv buffers and deregister recv MR
    _ = c.ibv_dereg_mr(queue.recv_mr);
    const recv_total = @as(usize, types.NUM_RECV_SLOTS) * @as(usize, types.SLOT_SIZE);
    const recv_slice = queue.recv_buf[0..recv_total];
    std.heap.page_allocator.free(@alignCast(recv_slice));

    // Destroy CQs (convert from ibv_cq_ex back to ibv_cq for destruction)
    destroyCqEx(queue.recv_cq);
    if (queue.send_cq != queue.recv_cq) {
        destroyCqEx(queue.send_cq);
    }

    // Destroy the completion channel
    _ = c.ibv_destroy_comp_channel(queue.comp_channel);

    // Free the queue struct
    std.heap.page_allocator.destroy(queue);
}

// ---------------------------------------------------------------------------
// Address Handle creation
// ---------------------------------------------------------------------------

/// Create an Address Handle (AH) for sending to a remote target.
///
/// Sets up the ibv_ah_attr with global routing (GRH) parameters:
///   - Destination GID from target_gid
///   - Flow label for ECMP path pinning
///   - Source GID index from the device configuration
///   - Maximum hop limit (255)
///
/// Uses ibv_create_ah() (not rdma_create_ah()) to match the Go implementation.
pub fn createAddressHandle(
    dev: *types.RdmaDevice,
    target_gid: [16]u8,
    flow_label: u32,
) QueueError!*c.ibv_ah {
    var ah_attr = std.mem.zeroes(c.ibv_ah_attr);

    // Global routing is required for RoCE
    ah_attr.is_global = 1;
    ah_attr.port_num = dev.port_num;
    ah_attr.sl = 0; // Service Level

    // GRH settings
    ah_attr.grh.dgid = types.bytesToGid(target_gid);
    ah_attr.grh.flow_label = flow_label;
    ah_attr.grh.sgid_index = dev.gid_index;
    ah_attr.grh.hop_limit = 255;
    ah_attr.grh.traffic_class = 0;

    const ah = c.ibv_create_ah(dev.pd, &ah_attr) orelse {
        types.setLastError("ibv_create_ah() failed");
        return QueueError.CreateAhFailed;
    };

    return ah;
}

/// Destroy an Address Handle.
///
/// Releases the AH resources allocated by ibv_create_ah().
pub fn destroyAddressHandle(ah: *c.ibv_ah) void {
    _ = c.ibv_destroy_ah(ah);
}

// ---------------------------------------------------------------------------
// Internal helpers - Extended CQ creation
// ---------------------------------------------------------------------------

/// Result of creating extended CQs with timestamp fallback.
const ExtendedCqResult = struct {
    send_cq: *c.ibv_cq_ex,
    recv_cq: *c.ibv_cq_ex,
    uses_sw_timestamps: bool,
};

/// Create extended CQs with hardware timestamp fallback.
///
/// First attempts to create the CQ with IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK.
/// If that fails with EOPNOTSUPP or ENOTSUP, retries without the timestamp flag
/// and sets uses_sw_timestamps to true.
///
/// The Go implementation uses a single CQ for both send and recv. We follow the
/// same pattern here: both send_cq and recv_cq point to the same CQ.
fn createExtendedCqs(dev: *types.RdmaDevice, comp_channel: *c.ibv_comp_channel) ?ExtendedCqResult {
    var cq_attr = std.mem.zeroes(c.ibv_cq_init_attr_ex);
    cq_attr.cqe = types.CQ_SIZE;
    cq_attr.cq_context = null;
    cq_attr.channel = comp_channel;
    cq_attr.comp_vector = 0;

    // Base flags: byte length and source QP are always needed
    const base_flags: u64 = @as(u64, c.IBV_WC_EX_WITH_BYTE_LEN) |
        @as(u64, c.IBV_WC_EX_WITH_SRC_QP);

    // Try with hardware wallclock timestamp first
    cq_attr.wc_flags = base_flags |
        @as(u64, c.IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK);

    var cq_ex = c.ibv_create_cq_ex(dev.ctx, &cq_attr);
    if (cq_ex != null) {
        // Hardware timestamps supported
        return ExtendedCqResult{
            .send_cq = cq_ex.?,
            .recv_cq = cq_ex.?,
            .uses_sw_timestamps = false,
        };
    }

    // Hardware timestamp creation failed. Check if it is EOPNOTSUPP/ENOTSUP
    // and fall back to software timestamps.
    const errno_val = std.c._errno().*;
    const eopnotsupp = @as(c_int, if (@hasDecl(std.c.E, "OPNOTSUPP")) @intFromEnum(std.c.E.OPNOTSUPP) else 95);
    const enotsup = @as(c_int, if (@hasDecl(std.c.E, "NOTSUP")) @intFromEnum(std.c.E.NOTSUP) else eopnotsupp);

    if (errno_val == eopnotsupp or errno_val == enotsup) {
        // Retry without the timestamp flag
        cq_attr.wc_flags = base_flags;
        cq_ex = c.ibv_create_cq_ex(dev.ctx, &cq_attr);
        if (cq_ex != null) {
            return ExtendedCqResult{
                .send_cq = cq_ex.?,
                .recv_cq = cq_ex.?,
                .uses_sw_timestamps = true,
            };
        }
    }

    // Both attempts failed
    types.setLastError("ibv_create_cq_ex() failed (both HW and SW timestamp attempts)");
    return null;
}

/// Safely destroy an extended CQ by converting it to a base CQ first.
///
/// ibv_destroy_cq() requires an ibv_cq pointer, but we store ibv_cq_ex.
/// Use ibv_cq_ex_to_cq() for the conversion.
fn destroyCqEx(cq_ex: *c.ibv_cq_ex) void {
    const base_cq = c.ibv_cq_ex_to_cq(cq_ex);
    if (base_cq != null) {
        _ = c.ibv_destroy_cq(base_cq);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers - QP creation and state transitions
// ---------------------------------------------------------------------------

/// Create a UD Queue Pair with the specified send and receive CQs.
///
/// Configures the QP with:
///   - qp_type = IBV_QPT_UD
///   - max_send_wr = NUM_SEND_SLOTS
///   - max_recv_wr = NUM_RECV_SLOTS
///   - max_send_sge = 1
///   - max_recv_sge = 1
fn createUdQp(
    dev: *types.RdmaDevice,
    send_cq: *c.ibv_cq_ex,
    recv_cq: *c.ibv_cq_ex,
) ?*c.ibv_qp {
    // Convert extended CQs to base CQs for QP creation
    const base_send_cq = c.ibv_cq_ex_to_cq(send_cq) orelse return null;
    const base_recv_cq = c.ibv_cq_ex_to_cq(recv_cq) orelse return null;

    var qp_init_attr = std.mem.zeroes(c.ibv_qp_init_attr);
    qp_init_attr.qp_type = c.IBV_QPT_UD;
    qp_init_attr.sq_sig_all = 0; // Signal completions per-WR via flags
    qp_init_attr.send_cq = base_send_cq;
    qp_init_attr.recv_cq = base_recv_cq;
    qp_init_attr.cap.max_send_wr = types.NUM_SEND_SLOTS;
    qp_init_attr.cap.max_recv_wr = types.NUM_RECV_SLOTS;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;

    return c.ibv_create_qp(dev.pd, &qp_init_attr);
}

/// Transition the QP to INIT state.
///
/// Required attributes:
///   IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY
///
/// Sets:
///   - pkey_index = 0
///   - port_num = dev.port_num
///   - qkey = QKEY (0x11111111)
fn transitionQpToInit(dev: *types.RdmaDevice, qp: *c.ibv_qp) QueueError!void {
    var attr = std.mem.zeroes(c.ibv_qp_attr);
    attr.qp_state = c.IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = dev.port_num;
    attr.qkey = types.QKEY;

    const mask = c.IBV_QP_STATE | c.IBV_QP_PKEY_INDEX | c.IBV_QP_PORT | c.IBV_QP_QKEY;
    if (c.ibv_modify_qp(qp, &attr, mask) != 0) {
        types.setLastError("ibv_modify_qp() to INIT failed");
        return QueueError.ModifyQpInitFailed;
    }
}

/// Transition the QP to RTR (Ready to Receive) state.
///
/// For UD QPs, no extra attributes are needed beyond IBV_QP_STATE.
fn transitionQpToRtr(qp: *c.ibv_qp) QueueError!void {
    var attr = std.mem.zeroes(c.ibv_qp_attr);
    attr.qp_state = c.IBV_QPS_RTR;

    if (c.ibv_modify_qp(qp, &attr, c.IBV_QP_STATE) != 0) {
        types.setLastError("ibv_modify_qp() to RTR failed");
        return QueueError.ModifyQpRtrFailed;
    }
}

/// Transition the QP to RTS (Ready to Send) state.
///
/// Required attributes:
///   IBV_QP_STATE | IBV_QP_SQ_PSN
///
/// Sets sq_psn = 0 (Packet Sequence Number for the send queue).
fn transitionQpToRts(qp: *c.ibv_qp) QueueError!void {
    var attr = std.mem.zeroes(c.ibv_qp_attr);
    attr.qp_state = c.IBV_QPS_RTS;
    attr.sq_psn = 0;

    const mask = c.IBV_QP_STATE | c.IBV_QP_SQ_PSN;
    if (c.ibv_modify_qp(qp, &attr, mask) != 0) {
        types.setLastError("ibv_modify_qp() to RTS failed");
        return QueueError.ModifyQpRtsFailed;
    }
}

// ---------------------------------------------------------------------------
// C-ABI exported functions (called from Go via Cgo)
// ---------------------------------------------------------------------------

/// Create a UD Queue Pair.
///
/// Exported as `rdma_create_queue` for the C ABI.
/// @param dev_ptr      Device handle from rdma_open_device()
/// @param queue_type   RDMA_QUEUE_TYPE_SENDER (0) or RDMA_QUEUE_TYPE_RESPONDER (1)
/// @param ring_ptr     Event ring for completion event delivery
/// @param out_queue    Receives the queue handle
/// @param out_info     Receives queue information (QPN, timestamp mode)
/// @return             0 on success, -1 on failure
export fn rdma_create_queue(
    dev_ptr: ?*types.RdmaDevice,
    queue_type_raw: i32,
    ring_ptr: ?*ring.EventRing,
    out_queue: *?*types.UdQueue,
    out_info: *extern struct {
        qpn: u32,
        uses_sw_timestamps: u8,
    },
) i32 {
    const dev = dev_ptr orelse {
        types.setLastError("null device pointer");
        return -1;
    };
    const event_ring = ring_ptr orelse {
        types.setLastError("null event ring pointer");
        return -1;
    };

    // Convert raw queue type integer to enum
    const qt: types.QueueType = switch (queue_type_raw) {
        0 => .Sender,
        1 => .Responder,
        else => {
            types.setLastError("invalid queue type");
            return -1;
        },
    };

    const queue = createQueue(dev, qt, event_ring) catch return -1;

    out_queue.* = queue;
    out_info.qpn = queue.qpn;
    out_info.uses_sw_timestamps = if (queue.uses_sw_timestamps) 1 else 0;

    return 0;
}

/// Destroy a UD Queue Pair and free all resources.
///
/// Exported as `rdma_destroy_queue` for the C ABI.
export fn rdma_destroy_queue(queue_ptr: ?*types.UdQueue) void {
    const queue = queue_ptr orelse return;
    destroyQueue(queue);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "QueueError enum is defined" {
    // Verify the error set exists and has expected variants
    const err: QueueError = QueueError.OutOfMemory;
    try std.testing.expect(err == QueueError.OutOfMemory);
}

test "destroyAddressHandle does not crash with valid pattern" {
    // This is a compile-time check that the function signature is correct.
    // We cannot call it without a real AH, but we can verify it compiles.
    const ptr: ?*c.ibv_ah = null;
    if (ptr) |ah| {
        destroyAddressHandle(ah);
    }
}

test "ExtendedCqResult struct layout" {
    const result = ExtendedCqResult{
        .send_cq = undefined,
        .recv_cq = undefined,
        .uses_sw_timestamps = true,
    };
    try std.testing.expect(result.uses_sw_timestamps);
}
