// packet.zig - Send side of the R-Pingmesh probing protocol.
//
// Sends probes (synchronously, waiting for the send completion that yields
// T2) and ACK pairs (asynchronously; the CQ poller posts the second ACK)
// over a UD queue. The wire format itself lives in wire.zig; this module
// owns the send slots, the address handles and the synchronous completion
// mailbox (waitSendCompletion).

const std = @import("std");
const types = @import("types.zig");
const wire = @import("wire.zig");
const queue_module = @import("queue.zig");
const memory = @import("memory.zig");
const c = types.c;

const ProbePacket = wire.ProbePacket;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of a synchronous probe send operation.
///
/// Matches the rdma_send_result_t struct in the C header.
pub const SendResult = extern struct {
    /// T1: time just before posting the send (nanoseconds).
    t1_ns: u64,

    /// T2: send completion timestamp from CQ (nanoseconds).
    t2_ns: u64,

    /// 0 on success, negative error code on failure.
    err: i32,
};

// ---------------------------------------------------------------------------
// Packet errors
// ---------------------------------------------------------------------------

/// Errors that can occur during packet operations.
pub const PacketError = error{
    /// No free send slot is available.
    NoFreeSendSlot,
    /// Failed to create an address handle.
    CreateAhFailed,
    /// ibv_post_send() returned an error.
    PostSendFailed,
    /// Timed out waiting for send completion.
    SendTimeout,
    /// Send completion reported an error.
    SendCompletionFailed,
    /// Packet version mismatch.
    VersionMismatch,
    /// Slot index out of bounds.
    SlotIndexOutOfBounds,
};

/// Decode the probe a responder is answering. `recv_packet` points at the
/// payload after the GRH; the CQ poller already checked its version before
/// delivering it, so a mismatch here means the caller passed stale bytes.
fn decodeReceivedProbe(recv_packet: [*]const u8) ?ProbePacket {
    return wire.deserializeProbePacket(@ptrCast(recv_packet)) orelse {
        types.setLastError("received packet has an unsupported wire format version");
        return null;
    };
}

// ---------------------------------------------------------------------------
// Send slot management
// ---------------------------------------------------------------------------

/// Find a free send slot in the queue, atomically marking it InUse.
///
/// Thin wrapper over UdQueue.allocSendSlot(). Returns the slot index, or null
/// if no free slot is available.
pub fn findFreeSendSlot(queue: *types.UdQueue) ?u32 {
    return queue.allocSendSlot();
}

/// Free a send slot, marking it as available for reuse. Thin wrapper over
/// UdQueue.freeSendSlot().
pub fn freeSendSlot(queue: *types.UdQueue, slot_index: u32) void {
    queue.freeSendSlot(slot_index);
}

// ---------------------------------------------------------------------------
// Send completion waiting
// ---------------------------------------------------------------------------

/// Wait for the send completion whose wr_id equals expected_wr_id.
///
/// The CQ poller publishes each completed send by writing timestamp/status and
/// then storing the completed wr_id LAST (release). This function spins until
/// the mailbox shows ITS OWN wr_id (acquire) and only then reads the matching
/// timestamp/status. Completions for OTHER wr_ids (e.g. a late completion from
/// a previously timed-out send whose slot was intentionally left allocated)
/// are ignored, which is what prevents send-completion crosstalk: a stale
/// completion can no longer be misread as this send's T2/status.
///
/// Because there is a single sender per queue and a QP reports send completions
/// in post order, this send's completion is always the last to be published,
/// so once its wr_id appears it will not be overwritten. The waiter therefore
/// never needs to reset the mailbox (which could race the poller's next store
/// and lose a wakeup).
///
/// Returns the send completion timestamp on success, or an error on timeout
/// or completion failure.
pub fn waitSendCompletion(queue: *types.UdQueue, expected_wr_id: u64, timeout_ms: u32) PacketError!u64 {
    const timeout_ns: u64 = @as(u64, timeout_ms) * 1_000_000;
    const start_ns: u64 = getMonotonicNs();

    while (queue.send_completion_wr_id.load(.acquire) != expected_wr_id) {
        const elapsed = getMonotonicNs() - start_ns;
        if (elapsed >= timeout_ns) {
            types.setLastError("timed out waiting for send completion");
            return PacketError.SendTimeout;
        }

        // Yield to avoid burning CPU in a tight loop
        std.atomic.spinLoopHint();
    }

    // Our wr_id is published; the release/acquire handoff guarantees the
    // timestamp/status written before it are visible.
    const status = queue.send_completion_status.load(.monotonic);
    if (status != 0) {
        types.setLastError("send completion reported error status");
        return PacketError.SendCompletionFailed;
    }

    return queue.send_completion_timestamp.load(.monotonic);
}

// ---------------------------------------------------------------------------
// Clock helper
// ---------------------------------------------------------------------------

/// Get the current monotonic clock time in nanoseconds.
///
/// Delegates to the shared `types.monotonicNs()` helper, which uses true
/// CLOCK_MONOTONIC (not `std.time.nanoTimestamp()`, which was CLOCK_REALTIME
/// in Zig 0.15.x) so that T1 stays in the same clock domain as the Go
/// side's T6.
fn getMonotonicNs() u64 {
    return types.monotonicNs();
}

// ---------------------------------------------------------------------------
// Core send implementation
// ---------------------------------------------------------------------------

/// Internal helper that performs the common send workflow:
///   1. Find a free send slot
///   2. Serialize the packet into the slot buffer
///   3. Create an address handle
///   4. Post the send work request
///   5. Wait for send completion
///   6. Cleanup and return the completion timestamp
///
/// Returns the send completion timestamp on success or an error.
fn sendPacketInternal(
    queue: *types.UdQueue,
    target_gid: [16]u8,
    flow_label: u32,
    target_qpn: u32,
    pkt: *const ProbePacket,
    timeout_ms: u32,
) PacketError!u64 {
    // Step 1: Find a free send slot. Slots are freed by the CQ poller when the
    // send completes, so a slot is available only if its previous WR has fully
    // completed -- never one with an outstanding (e.g. timed-out) WR.
    const slot_index = findFreeSendSlot(queue) orelse {
        types.setLastError("no free send slot available");
        return PacketError.NoFreeSendSlot;
    };
    // With no slot reuse while a WR is outstanding, the slot's wr_id uniquely
    // identifies the in-flight send for mailbox matching.
    const wr_id = types.sendWrId(slot_index);

    // Slot-freeing ownership below is deliberate: until ibv_post_send succeeds
    // there is no outstanding WR, so this function must free the slot on every
    // early-error path. Once the WR is posted, the slot must NOT be freed here
    // -- the CQ poller frees it when the completion arrives, even if that is a
    // late completion after a SendTimeout. Freeing (and reusing) an
    // outstanding WR's slot is exactly what causes send-completion crosstalk.

    // Step 2: Get the slot buffer pointer and serialize the packet
    const slot_ptr = memory.getSlotPtr(queue.send_buf, slot_index, types.NUM_SEND_SLOTS) catch {
        types.setLastError("send slot index out of bounds");
        freeSendSlot(queue, slot_index);
        return PacketError.SlotIndexOutOfBounds;
    };
    const buf_ptr: *wire.Bytes = @ptrCast(slot_ptr);
    wire.serializeProbePacket(pkt, buf_ptr);

    // Step 3: Create an address handle for the target. Ownership transfers
    // to the send slot before post_send: the CQ poller destroys the AH when
    // the completion arrives. Destroying it here via defer would free the AH
    // on waitSendCompletion timeout while the WR is still outstanding.
    const ah = queue_module.createAddressHandle(queue.device, target_gid, flow_label) catch {
        // Error message already set by createAddressHandle
        freeSendSlot(queue, slot_index);
        return PacketError.CreateAhFailed;
    };
    queue.setSendSlotAh(slot_index, ah);

    // Step 4: Reset the completion mailbox before posting so that a reused
    // slot's previous completion value cannot false-match our wait. Safe under
    // the single-sender contract: our previous send on this slot already
    // completed (that is why the slot was free), so no completion carrying
    // this wr_id is still in flight to be lost by the reset.
    queue.send_completion_wr_id.store(types.SEND_WR_ID_NONE, .release);

    // Step 5: Post the send work request. The slot is synchronous: its
    // completion is published to the mailbox (see types.SendSlotMode).
    queue.setSendSlotMode(slot_index, .Sync);
    memory.postUdSend(queue.qp, queue.send_mr, slot_ptr, slot_index, ah, target_qpn) catch {
        // No WR was accepted by the QP, so no completion will ever arrive to
        // free this slot or its AH; destroy both here.
        queue.destroySendSlotAh(slot_index);
        freeSendSlot(queue, slot_index);
        return PacketError.PostSendFailed;
    };

    // Step 6: Wait for this send's completion (matched by wr_id). On timeout we
    // intentionally leave the slot allocated: the WR is still outstanding and
    // its (late) completion is the only safe point to reclaim the slot.
    return try waitSendCompletion(queue, wr_id, timeout_ms);
}

// ---------------------------------------------------------------------------
// Public send functions
// ---------------------------------------------------------------------------

/// Send a probe packet to a remote target.
///
/// Constructs a probe packet with the given sequence number, serializes it,
/// posts a send WR via the queue, and waits for the send completion.
///
/// Returns a SendResult containing T1 (pre-send timestamp), T2 (send
/// completion timestamp), and an error indicator.
pub fn sendProbe(
    queue: *types.UdQueue,
    target_gid: [16]u8,
    target_qpn: u32,
    sequence_num: u64,
    flow_label: u32,
    timeout_ms: u32,
) SendResult {
    // Construct the probe packet
    const pkt = ProbePacket{
        .version = wire.PACKET_VERSION,
        .msg_type = wire.MSG_TYPE_PROBE,
        .ack_type = wire.ACK_TYPE_NONE,
        .flags = 0,
        .sequence_num = sequence_num,
        .t1 = 0, // Will be captured separately
        .t3 = 0,
        .t4 = 0,
    };

    // Capture T1 just before posting the send
    const t1_ns = getMonotonicNs();

    // Perform the send
    const t2_ns = sendPacketInternal(queue, target_gid, flow_label, target_qpn, &pkt, timeout_ms) catch {
        return SendResult{
            .t1_ns = t1_ns,
            .t2_ns = 0,
            .err = -1,
        };
    };

    return SendResult{
        .t1_ns = t1_ns,
        .t2_ns = t2_ns,
        .err = 0,
    };
}

/// Return code of sendAckPair / rdma_send_ack_pair when every send slot is
/// held by an in-flight send. The caller may retry once a completion has
/// returned a slot.
pub const ACK_PAIR_NO_FREE_SLOT: i32 = -2;

/// Post the first ACK of a probe and return without waiting for it.
///
/// Both ACKs are serialized up front into one send slot: the first ACK at
/// offset 0, and the second ACK (with T3, and T4 still zero) at
/// types.SECOND_ACK_SLOT_OFFSET. When the first ACK's send completion
/// arrives, the CQ poller writes its timestamp into the staged second ACK as
/// T4 and posts it on the same slot and AH (see cq.zig
/// flushPendingSecondAcks). The responder therefore never blocks on a send
/// completion, so a slow completion delays only its own probe instead of
/// every probe queued behind it, and no thread spins while it waits.
///
/// T4 is the first ACK's send completion timestamp (NIC hardware, or
/// CLOCK_MONOTONIC read by the CQ poller in software-timestamp mode).
///
/// Failures of the asynchronous part (completion errors, a second ACK that
/// cannot be posted) are counted in queue.async_ack_failures.
///
/// Returns 0 once the first ACK is posted, ACK_PAIR_NO_FREE_SLOT when no
/// send slot is free, or -1 on any other error (see rdma_get_last_error).
pub fn sendAckPair(
    queue: *types.UdQueue,
    target_gid: [16]u8,
    target_qpn: u32,
    flow_label: u32,
    recv_packet: [*]const u8,
    recv_timestamp_ns: u64,
) i32 {
    const original = decodeReceivedProbe(recv_packet) orelse return -1;

    const slot_index = findFreeSendSlot(queue) orelse {
        types.setLastError("no free send slot available");
        return ACK_PAIR_NO_FREE_SLOT;
    };

    // Until ibv_post_send accepts the WR, this function owns the slot and
    // frees it on every error path (as in sendPacketInternal).
    const slot_ptr = memory.getSlotPtr(queue.send_buf, slot_index, types.NUM_SEND_SLOTS) catch {
        types.setLastError("send slot index out of bounds");
        freeSendSlot(queue, slot_index);
        return -1;
    };

    stageAckPair(slot_ptr, &original, recv_timestamp_ns);

    const ah = queue_module.createAddressHandle(queue.device, target_gid, flow_label) catch {
        freeSendSlot(queue, slot_index);
        return -1;
    };

    // Publish the pair's context before the post: the CQ poller reads the
    // mode (acquire) when the completion arrives, and through it sees the
    // remote QPN, the staged second ACK and the AH.
    queue.send_slot_remote_qpn[slot_index] = target_qpn;
    queue.setSendSlotAh(slot_index, ah);
    queue.setSendSlotMode(slot_index, .AsyncFirstAck);

    memory.postUdSend(queue.qp, queue.send_mr, slot_ptr, slot_index, ah, target_qpn) catch {
        queue.setSendSlotMode(slot_index, .Sync);
        queue.destroySendSlotAh(slot_index);
        freeSendSlot(queue, slot_index);
        return -1;
    };
    return 0;
}

/// Serialize both ACKs of a pair into a send slot: the first ACK at offset 0
/// and the second ACK at types.SECOND_ACK_SLOT_OFFSET. Both echo the probe's
/// sequence number and T1 and carry T3; T4 is zero and is filled into the
/// second ACK by the CQ poller (cq.zig stampStagedSecondAck) once the first
/// ACK's send completion supplies it.
pub fn stageAckPair(slot_ptr: [*]u8, original: *const ProbePacket, t3_ns: u64) void {
    const first_ack = ProbePacket{
        .version = wire.PACKET_VERSION,
        .msg_type = wire.MSG_TYPE_ACK,
        .ack_type = wire.ACK_TYPE_FIRST,
        .flags = 0,
        .sequence_num = original.sequence_num,
        .t1 = original.t1,
        .t3 = t3_ns,
        .t4 = 0,
    };
    var second_ack = first_ack;
    second_ack.ack_type = wire.ACK_TYPE_SECOND;
    wire.serializeProbePacket(&first_ack, @ptrCast(slot_ptr));
    wire.serializeProbePacket(&second_ack, @ptrCast(slot_ptr + types.SECOND_ACK_SLOT_OFFSET));
}

// ---------------------------------------------------------------------------
// C-ABI exported functions
// ---------------------------------------------------------------------------

/// Send a probe packet (C-ABI export matching rdma_send_probe in rdma_bridge.h).
///
/// @param queue_ptr     Sender queue handle
/// @param target_gid    Pointer to 16-byte target GID
/// @param target_qpn    Target Queue Pair Number
/// @param sequence_num  Probe sequence number
/// @param flow_label    IPv6 flow label for ECMP path selection
/// @param timeout_ms    Send completion timeout in milliseconds
/// @return              rdma_send_result_t with t1_ns, t2_ns, and error
export fn rdma_send_probe(
    queue_ptr: ?*types.UdQueue,
    target_gid: ?*const [16]u8,
    target_qpn: u32,
    sequence_num: u64,
    flow_label: u32,
    timeout_ms: u32,
) SendResult {
    const queue = queue_ptr orelse {
        types.setLastError("null queue pointer");
        return SendResult{ .t1_ns = 0, .t2_ns = 0, .err = -1 };
    };
    const gid = target_gid orelse {
        types.setLastError("null target_gid pointer");
        return SendResult{ .t1_ns = 0, .t2_ns = 0, .err = -1 };
    };

    return sendProbe(queue, gid.*, target_qpn, sequence_num, flow_label, timeout_ms);
}

/// Post an asynchronous ACK pair (C-ABI export matching rdma_send_ack_pair in
/// rdma_bridge.h). See sendAckPair.
///
/// @param queue_ptr          Responder queue handle
/// @param target_gid         Pointer to 16-byte prober GID
/// @param target_qpn         Prober's QPN
/// @param flow_label         Flow label for ECMP path consistency
/// @param recv_packet        Raw received packet buffer (payload after GRH)
/// @param recv_timestamp_ns  T3: receive completion timestamp (ns)
/// @return                   0 when the first ACK is posted,
///                           ACK_PAIR_NO_FREE_SLOT (-2) when no send slot
///                           is free, -1 on other errors
export fn rdma_send_ack_pair(
    queue_ptr: ?*types.UdQueue,
    target_gid: ?*const [16]u8,
    target_qpn: u32,
    flow_label: u32,
    recv_packet: ?[*]const u8,
    recv_timestamp_ns: u64,
) i32 {
    const queue = queue_ptr orelse {
        types.setLastError("null queue pointer");
        return -1;
    };
    const gid = target_gid orelse {
        types.setLastError("null target_gid pointer");
        return -1;
    };
    const pkt = recv_packet orelse {
        types.setLastError("null recv_packet pointer");
        return -1;
    };
    return sendAckPair(queue, gid.*, target_qpn, flow_label, pkt, recv_timestamp_ns);
}

/// Number of asynchronous ACK pairs that failed after rdma_send_ack_pair
/// returned (C-ABI export matching rdma_queue_async_ack_failures in
/// rdma_bridge.h). Monotonic; 0 for a null queue.
export fn rdma_queue_async_ack_failures(queue_ptr: ?*types.UdQueue) u64 {
    const queue = queue_ptr orelse return 0;
    return queue.async_ack_failures.load(.monotonic);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SendResult size matches C ABI" {
    // rdma_send_result_t: uint64_t t1_ns + uint64_t t2_ns + int32_t error + 4 bytes padding = 24 bytes
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(SendResult));
}

test "findFreeSendSlot and freeSendSlot basic behavior" {
    // Create a mock queue-like struct by testing the slot management functions
    // with a stack-allocated slot states array.
    // Note: We cannot create a full UdQueue without RDMA hardware, so we test
    // the logic conceptually via the state array.
    var states: [types.NUM_SEND_SLOTS]types.SlotState = @splat(.Free);

    // Simulate findFreeSendSlot: find the first Free slot
    var found_slot: ?u32 = null;
    for (0..types.NUM_SEND_SLOTS) |i| {
        const idx: u32 = @intCast(i);
        if (states[idx] == .Free) {
            states[idx] = .InUse;
            found_slot = idx;
            break;
        }
    }
    try std.testing.expectEqual(@as(?u32, 0), found_slot);
    try std.testing.expectEqual(types.SlotState.InUse, states[0]);

    // Simulate freeSendSlot
    if (found_slot) |slot| {
        states[slot] = .Free;
    }
    try std.testing.expectEqual(types.SlotState.Free, states[0]);
}

test "findFreeSendSlot returns null when all slots busy" {
    const states: [types.NUM_SEND_SLOTS]types.SlotState = @splat(.InUse);

    // All slots are InUse, should not find any
    var found: ?u32 = null;
    for (0..types.NUM_SEND_SLOTS) |i| {
        const idx: u32 = @intCast(i);
        if (states[idx] == .Free) {
            found = idx;
            break;
        }
    }
    try std.testing.expect(found == null);
}

test "PacketError enum is defined" {
    const err: PacketError = PacketError.NoFreeSendSlot;
    try std.testing.expect(err == PacketError.NoFreeSendSlot);
}

test "getMonotonicNs returns non-zero value" {
    const ns = getMonotonicNs();
    try std.testing.expect(ns > 0);
}

test "getMonotonicNs is monotonic" {
    const t1 = getMonotonicNs();
    // Small busy loop to ensure time advances
    var sum: u64 = 0;
    for (0..1000) |i| {
        sum += i;
    }
    if (sum == 0) unreachable; // prevent optimizer from eliminating the loop
    const t2 = getMonotonicNs();
    try std.testing.expect(t2 >= t1);
}

test "stageAckPair stages both ACKs and the CQ poller's T4 stamp completes the second" {
    const cq = @import("cq.zig");
    var slot: [types.SLOT_SIZE]u8 = @splat(0);
    const probe_pkt = ProbePacket{
        .version = wire.PACKET_VERSION,
        .msg_type = wire.MSG_TYPE_PROBE,
        .ack_type = wire.ACK_TYPE_NONE,
        .flags = 0,
        .sequence_num = 0xAABBCCDD00000007,
        .t1 = 111,
        .t3 = 0,
        .t4 = 0,
    };
    stageAckPair(&slot, &probe_pkt, 333);
    cq.stampStagedSecondAck(&slot, 444);

    const first = wire.deserializeProbePacket(slot[0..40]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(wire.MSG_TYPE_ACK, first.msg_type);
    try std.testing.expectEqual(wire.ACK_TYPE_FIRST, first.ack_type);
    try std.testing.expectEqual(probe_pkt.sequence_num, first.sequence_num);
    try std.testing.expectEqual(@as(u64, 111), first.t1);
    try std.testing.expectEqual(@as(u64, 333), first.t3);
    try std.testing.expectEqual(@as(u64, 0), first.t4);

    const off = types.SECOND_ACK_SLOT_OFFSET;
    const second = wire.deserializeProbePacket(slot[off..][0..40]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(wire.MSG_TYPE_ACK, second.msg_type);
    try std.testing.expectEqual(wire.ACK_TYPE_SECOND, second.ack_type);
    try std.testing.expectEqual(probe_pkt.sequence_num, second.sequence_num);
    try std.testing.expectEqual(@as(u64, 111), second.t1);
    try std.testing.expectEqual(@as(u64, 333), second.t3);
    try std.testing.expectEqual(@as(u64, 444), second.t4);
}

test "ACK_PAIR_NO_FREE_SLOT matches RDMA_ACK_PAIR_NO_FREE_SLOT" {
    try std.testing.expectEqual(@as(i32, -2), ACK_PAIR_NO_FREE_SLOT);
}
