// queue.zig - UD Queue Pair lifecycle management.
//
// This module handles the creation and destruction of Unreliable Datagram (UD)
// Queue Pairs, including:
//   - Extended CQ creation with hardware timestamp fallback
//   - QP creation and state transitions (INIT -> RTR -> RTS)
//   - Buffer allocation and initial receive buffer posting
//   - Address Handle (AH) creation for sending to remote targets
//   - Completion channel setup for the event-driven CQ poller
//   - CQ poller thread startup and teardown

const std = @import("std");
const types = @import("types.zig");
const ring = @import("ring.zig");
const memory = @import("memory.zig");
const cq = @import("cq.zig");
const c = types.c;

const log = std.log.scoped(.rdma_queue);

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during queue operations.
pub const QueueError = error{
    /// Memory allocation failed for the UdQueue struct.
    OutOfMemory,
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
};

// ---------------------------------------------------------------------------
// Queue creation
// ---------------------------------------------------------------------------

/// Create a UD Queue Pair with all associated resources and start its CQ
/// poller thread.
///
/// Buffers are allocated before the QP is created even though the QP has no
/// functional dependency on them yet. This ordering is deliberate: Zig's
/// errdefer unwinds in LIFO order, so registering the QP-destroy errdefer
/// *after* the buffer-free errdefers guarantees that if a later step fails
/// (e.g. posting the initial receive buffers), the QP is destroyed before
/// the buffers it may have posted work requests against are freed. Freeing
/// a buffer while the QP could still reference it via an outstanding work
/// request would risk the hardware DMA'ing into freed memory.
///
/// On failure, all partially allocated resources are cleaned up before
/// returning the error.
pub fn createQueue(
    dev: *types.RdmaDevice,
    cq_mode: types.CqPollMode,
    event_ring: *ring.EventRing,
) QueueError!*types.UdQueue {
    const queue = std.heap.page_allocator.create(types.UdQueue) catch {
        types.setLastError("failed to allocate UdQueue struct");
        return QueueError.OutOfMemory;
    };
    errdefer std.heap.page_allocator.destroy(queue);

    // The channel's errdefer is registered before the CQ's, so on unwind the
    // CQ (which references the channel) is destroyed first.
    const wait = createCompChannelAndWakeFd(dev, cq_mode);
    errdefer wait.deinit();

    const cq_result = createExtendedCq(dev, wait.comp_channel) orelse {
        // Error message already set by createExtendedCq
        return QueueError.CreateCqFailed;
    };
    errdefer destroyCqEx(cq_result.cq);

    // Allocated before the QP (see the ordering note in the doc comment).
    var send_bufs = memory.allocateBuffers(dev, types.NUM_SEND_SLOTS) catch {
        types.setLastError("failed to allocate send buffers");
        return QueueError.BufferAllocFailed;
    };
    errdefer memory.freeBuffers(&send_bufs);

    var recv_bufs = memory.allocateBuffers(dev, types.NUM_RECV_SLOTS) catch {
        types.setLastError("failed to allocate recv buffers");
        return QueueError.BufferAllocFailed;
    };
    errdefer memory.freeBuffers(&recv_bufs);

    // Registered after the buffer errdefers above, so on unwind this
    // errdefer runs *first*: the QP is destroyed before the buffers are freed.
    const qp = createUdQp(dev, cq_result.cq) orelse {
        types.setLastError("ibv_create_qp() failed");
        return QueueError.CreateQpFailed;
    };
    errdefer _ = c.ibv_destroy_qp(qp);

    try transitionQpToInit(dev, qp);
    try transitionQpToRtr(qp);
    try transitionQpToRts(qp);

    queue.* = types.UdQueue.init(.{
        .qp = qp,
        .cq = cq_result.cq,
        .send_bufs = send_bufs,
        .recv_bufs = recv_bufs,
        .uses_sw_timestamps = cq_result.uses_sw_timestamps,
        .event_ring = event_ring,
        .device = dev,
        .comp_channel = wait.comp_channel,
        .wake_fd = wait.wake_fd,
    });

    memory.postInitialRecvBuffers(qp, recv_bufs.mr, recv_bufs.buf, types.INITIAL_RECV_BUFFERS) catch {
        types.setLastError("failed to post initial recv buffers");
        return QueueError.PostRecvFailed;
    };

    decideCqEventMode(queue, cq_mode);

    cq.startCqPollerThread(queue) catch {
        types.setLastError("failed to start CQ poller thread");
        return QueueError.StartPollerFailed;
    };

    return queue;
}

/// The two descriptors the event-driven CQ poller sleeps on: the CQ's
/// completion channel and the eventfd that wakes it for shutdown. Neither is
/// required; without them the poller busy-polls.
const PollerWaitFds = struct {
    comp_channel: ?*c.ibv_comp_channel,
    /// -1 when eventfd creation failed.
    wake_fd: i32,

    fn deinit(self: PollerWaitFds) void {
        if (self.comp_channel) |ch| {
            _ = c.ibv_destroy_comp_channel(ch);
        }
        if (self.wake_fd >= 0) {
            _ = c.close(self.wake_fd);
        }
    }
};

/// Create the completion channel and the poller's shutdown eventfd. The
/// channel must exist before the CQ is created; in Auto mode it is created
/// up front and simply left unarmed if the CQ ends up with software
/// timestamps. Busy mode never creates one.
fn createCompChannelAndWakeFd(dev: *types.RdmaDevice, cq_mode: types.CqPollMode) PollerWaitFds {
    const comp_channel: ?*c.ibv_comp_channel = if (cq_mode == .Busy) null else createCompChannel(dev);
    const wake_efd = c.eventfd(0, c.EFD_NONBLOCK | c.EFD_CLOEXEC);
    return .{ .comp_channel = comp_channel, .wake_fd = if (wake_efd >= 0) wake_efd else -1 };
}

/// Decide whether the CQ poller sleeps on CQ events. Event mode must be
/// wanted (see CqPollMode), needs a channel, and needs a provider that
/// accepts ibv_req_notify_cq(). Arming here proves the provider supports it
/// before uses_cq_events is reported to Go; the poller arms again before
/// its first drain, which is harmless. Must run before the poller thread
/// starts: uses_cq_events is a plain bool the poller thread also writes.
fn decideCqEventMode(queue: *types.UdQueue, cq_mode: types.CqPollMode) void {
    const wants_events = cq_mode.wantsEvents(queue.uses_sw_timestamps);
    if (wants_events and queue.comp_channel != null) {
        if (c.ibv_cq_ex_to_cq(queue.cq)) |base_cq| {
            queue.uses_cq_events = c.ibv_req_notify_cq(base_cq, 0) == 0;
        }
    }
    if (wants_events and !queue.uses_cq_events) {
        log.warn("CQ events unavailable; CQ poller falls back to busy polling", .{});
    }
}

// ---------------------------------------------------------------------------
// Queue destruction
// ---------------------------------------------------------------------------

/// Destroy a UD Queue Pair and free all associated resources: stop the CQ
/// poller, destroy the QP, free the buffers, destroy the CQ, then the
/// completion channel and wake eventfd, and finally the queue struct.
pub fn destroyQueue(queue: *types.UdQueue) void {
    cq.stopCqPollerThread(queue);

    // The QP goes before the CQ (it references it). Log a failure instead of
    // discarding it -- a nonzero return here is useful operational signal
    // during teardown even though we cannot recover.
    const qp_ret = c.ibv_destroy_qp(queue.qp);
    if (qp_ret != 0) {
        log.err("ibv_destroy_qp() failed with errno={d}; leaking leftover send-slot AHs to avoid destroying them while the QP may still reference them", .{qp_ret});
    } else {
        // Outstanding UD sends (including timed-out WRs whose slots were
        // left allocated) referenced per-slot AHs. Destroy those AHs only
        // after the QP is gone so no WR can still point at them.
        queue.destroyAllSendSlotAhs();
    }

    // memory.freeBuffers() owns the dereg-failure handling (intentional leak
    // instead of a potential use-after-free; see memory.zig).
    memory.freeBuffers(&queue.send_bufs);
    memory.freeBuffers(&queue.recv_bufs);

    destroyCqEx(queue.cq);

    // The channel can only be destroyed once no CQ references it. Every CQ
    // event was acknowledged by the poller as it was consumed, so
    // ibv_destroy_cq() above did not block on unacked events.
    if (queue.comp_channel) |ch| {
        if (c.ibv_destroy_comp_channel(ch) != 0) {
            log.err("ibv_destroy_comp_channel() failed", .{});
        }
    }
    if (queue.wake_fd >= 0) _ = c.close(queue.wake_fd);

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
///   - Service Level (sl) and traffic class (DSCP) from the device
///     configuration (static per-agent values; see RdmaDevice.sl /
///     RdmaDevice.traffic_class)
///
/// Uses ibv_create_ah() (not rdma_create_ah()).
pub fn createAddressHandle(
    dev: *types.RdmaDevice,
    target_gid: [16]u8,
    flow_label: u32,
) QueueError!*c.ibv_ah {
    var ah_attr = std.mem.zeroes(c.ibv_ah_attr);

    // Global routing is required for RoCE
    ah_attr.is_global = 1;
    ah_attr.port_num = dev.port_num;
    // Service Level (PFC priority) and traffic class (DSCP) are static,
    // agent-configured values stored on the device at open time (see
    // device.zig openDevice()) rather than per-send arguments, since every
    // send on this device shares the same lossless-class intent and the AH
    // is already rebuilt per send for flow_label (ECMP) rotation.
    ah_attr.sl = dev.sl;

    // GRH settings
    ah_attr.grh.dgid = types.bytesToGid(target_gid);
    ah_attr.grh.flow_label = flow_label;
    ah_attr.grh.sgid_index = dev.gid_index;
    ah_attr.grh.hop_limit = 255;
    ah_attr.grh.traffic_class = dev.traffic_class;

    const ah = c.ibv_create_ah(dev.pd, &ah_attr) orelse {
        types.setLastError("ibv_create_ah() failed");
        return QueueError.CreateAhFailed;
    };

    return ah;
}

// ---------------------------------------------------------------------------
// Internal helpers - Extended CQ creation
// ---------------------------------------------------------------------------

/// Result of creating the extended CQ with timestamp fallback.
const ExtendedCqResult = struct {
    cq: *c.ibv_cq_ex,
    uses_sw_timestamps: bool,
};

/// Create the extended CQ with hardware timestamp fallback.
///
/// First attempts to create the CQ with IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK.
/// If that fails with EOPNOTSUPP or ENOTSUP, retries without the timestamp flag
/// and sets uses_sw_timestamps to true.
///
/// One CQ serves both the send and the receive side of the QP, so the poller
/// waits on a single CQ. When `channel` is non-null the CQ is attached to it
/// so the poller can sleep until a completion event (see cq.zig).
fn createExtendedCq(dev: *types.RdmaDevice, channel: ?*c.ibv_comp_channel) ?ExtendedCqResult {
    var cq_attr = std.mem.zeroes(c.ibv_cq_init_attr_ex);
    cq_attr.cqe = types.CQ_SIZE;
    cq_attr.cq_context = null;
    cq_attr.channel = channel;
    cq_attr.comp_vector = 0;

    // Base flags: byte length and source QP are always needed
    const base_flags: u64 = @as(u64, c.IBV_WC_EX_WITH_BYTE_LEN) |
        @as(u64, c.IBV_WC_EX_WITH_SRC_QP);

    // Try with hardware wallclock timestamp first
    cq_attr.wc_flags = base_flags |
        @as(u64, c.IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK);

    if (c.ibv_create_cq_ex(dev.ctx, &cq_attr)) |cq_ex| {
        return ExtendedCqResult{ .cq = cq_ex, .uses_sw_timestamps = false };
    }

    // Hardware timestamp creation failed. Check if it is EOPNOTSUPP/ENOTSUP
    // and fall back to software timestamps.
    const errno_val = std.c._errno().*;
    const eopnotsupp = @as(c_int, if (@hasDecl(std.c.E, "OPNOTSUPP")) @backingInt(std.c.E.OPNOTSUPP) else 95);
    const enotsup = @as(c_int, if (@hasDecl(std.c.E, "NOTSUP")) @backingInt(std.c.E.NOTSUP) else eopnotsupp);

    if (errno_val == eopnotsupp or errno_val == enotsup) {
        cq_attr.wc_flags = base_flags;
        if (c.ibv_create_cq_ex(dev.ctx, &cq_attr)) |cq_ex| {
            return ExtendedCqResult{ .cq = cq_ex, .uses_sw_timestamps = true };
        }
    }

    types.setLastError("ibv_create_cq_ex() failed (both HW and SW timestamp attempts)");
    return null;
}

/// Create a completion channel whose fd is non-blocking, or return null.
///
/// The poller only calls ibv_get_cq_event() after poll() reports the fd
/// readable, but a non-blocking fd guarantees a spurious readiness can never
/// park the poller inside read() where shutdown could not reach it.
fn createCompChannel(dev: *types.RdmaDevice) ?*c.ibv_comp_channel {
    const ch: *c.ibv_comp_channel = c.ibv_create_comp_channel(dev.ctx) orelse return null;
    const flags = c.fcntl(ch.fd, c.F_GETFL);
    if (flags < 0 or c.fcntl(ch.fd, c.F_SETFL, flags | c.O_NONBLOCK) < 0) {
        _ = c.ibv_destroy_comp_channel(ch);
        return null;
    }
    return ch;
}

/// Destroy an extended CQ. ibv_destroy_cq() takes an ibv_cq, so convert
/// with ibv_cq_ex_to_cq() first.
fn destroyCqEx(cq_ex: *c.ibv_cq_ex) void {
    const base_cq = c.ibv_cq_ex_to_cq(cq_ex);
    if (base_cq != null) {
        const ret = c.ibv_destroy_cq(base_cq);
        if (ret != 0) {
            log.err("ibv_destroy_cq() failed with errno={d}", .{ret});
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers - QP creation and state transitions
// ---------------------------------------------------------------------------

/// Create a UD Queue Pair whose send and receive completions both go to
/// `cq_ex`, with NUM_SEND_SLOTS / NUM_RECV_SLOTS work requests of one SGE.
fn createUdQp(dev: *types.RdmaDevice, cq_ex: *c.ibv_cq_ex) ?*c.ibv_qp {
    const base_cq = c.ibv_cq_ex_to_cq(cq_ex) orelse return null;

    var qp_init_attr = std.mem.zeroes(c.ibv_qp_init_attr);
    qp_init_attr.qp_type = c.IBV_QPT_UD;
    qp_init_attr.sq_sig_all = 0; // Signal completions per-WR via flags
    qp_init_attr.send_cq = base_cq;
    qp_init_attr.recv_cq = base_cq;
    qp_init_attr.cap.max_send_wr = types.NUM_SEND_SLOTS;
    qp_init_attr.cap.max_recv_wr = types.NUM_RECV_SLOTS;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;

    return c.ibv_create_qp(dev.pd, &qp_init_attr);
}

/// Transition the QP to INIT state (pkey_index 0, the device's port, QKEY).
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

/// Transition the QP to RTR (Ready to Receive) state. For UD QPs, no extra
/// attributes are needed beyond IBV_QP_STATE.
fn transitionQpToRtr(qp: *c.ibv_qp) QueueError!void {
    var attr = std.mem.zeroes(c.ibv_qp_attr);
    attr.qp_state = c.IBV_QPS_RTR;

    if (c.ibv_modify_qp(qp, &attr, c.IBV_QP_STATE) != 0) {
        types.setLastError("ibv_modify_qp() to RTR failed");
        return QueueError.ModifyQpRtrFailed;
    }
}

/// Transition the QP to RTS (Ready to Send) state with sq_psn 0.
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

/// Create a UD Queue Pair (C-ABI export matching rdma_create_queue in
/// rdma_bridge.h). Returns 0 on success, -1 on failure.
export fn rdma_create_queue(
    dev_ptr: ?*types.RdmaDevice,
    queue_type_raw: i32,
    cq_poll_mode_raw: i32,
    ring_ptr: ?*ring.EventRing,
    out_queue: *?*types.UdQueue,
    out_info: *types.QueueInfo,
) i32 {
    const dev = dev_ptr orelse {
        types.setLastError("null device pointer");
        return -1;
    };
    const event_ring = ring_ptr orelse {
        types.setLastError("null event ring pointer");
        return -1;
    };
    // Sender and responder queues are built identically; the type is only
    // validated so a bad value surfaces at creation.
    _ = std.enums.fromInt(types.QueueType, queue_type_raw) orelse {
        types.setLastError("invalid queue type");
        return -1;
    };
    const cq_mode = std.enums.fromInt(types.CqPollMode, cq_poll_mode_raw) orelse {
        types.setLastError("invalid CQ poll mode");
        return -1;
    };

    const queue = createQueue(dev, cq_mode, event_ring) catch return -1;

    out_queue.* = queue;
    out_info.* = .{
        .qpn = queue.qpn,
        .uses_sw_timestamps = @intFromBool(queue.uses_sw_timestamps),
        .uses_cq_events = @intFromBool(queue.uses_cq_events),
    };
    return 0;
}

/// Destroy a UD Queue Pair and free all resources (C-ABI export matching
/// rdma_destroy_queue in rdma_bridge.h).
export fn rdma_destroy_queue(queue_ptr: ?*types.UdQueue) void {
    const queue = queue_ptr orelse return;
    destroyQueue(queue);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CqPollMode.wantsEvents" {
    try std.testing.expect(types.CqPollMode.Auto.wantsEvents(false));
    try std.testing.expect(!types.CqPollMode.Auto.wantsEvents(true));
    try std.testing.expect(types.CqPollMode.Event.wantsEvents(true));
    try std.testing.expect(types.CqPollMode.Event.wantsEvents(false));
    try std.testing.expect(!types.CqPollMode.Busy.wantsEvents(false));
    try std.testing.expect(!types.CqPollMode.Busy.wantsEvents(true));
}

test "queue type and poll mode raw values are range-checked" {
    try std.testing.expectEqual(@as(?types.QueueType, null), std.enums.fromInt(types.QueueType, @as(i32, 2)));
    try std.testing.expectEqual(@as(?types.QueueType, null), std.enums.fromInt(types.QueueType, @as(i32, -1)));
    try std.testing.expectEqual(@as(?types.CqPollMode, null), std.enums.fromInt(types.CqPollMode, @as(i32, 3)));
    try std.testing.expectEqual(@as(?types.QueueType, .Responder), std.enums.fromInt(types.QueueType, @as(i32, c.RDMA_QUEUE_TYPE_RESPONDER)));
    try std.testing.expectEqual(@as(?types.CqPollMode, .Busy), std.enums.fromInt(types.CqPollMode, @as(i32, c.RDMA_CQ_POLL_BUSY)));
}
