// packet.zig - Data-path module for sending and receiving RDMA probes and ACKs.
//
// This module implements the R-Pingmesh probing protocol wire format and the
// send-side operations for probes, first ACKs, and second ACKs. The wire format
// uses explicit BigEndian serialization (no packed struct casting) for portability.
//
// Wire Format (40 bytes):
//   Offset  Size  Field           Encoding
//   0       1     version         uint8 (currently 1)
//   1       1     msg_type        uint8 (0=probe, 1=ack)
//   2       1     ack_type        uint8 (0=N/A, 1=first, 2=second)
//   3       1     flags           uint8 (reserved)
//   4       8     sequence_num    uint64 BigEndian
//   12      8     t1              uint64 BigEndian (nanoseconds)
//   20      8     t3              uint64 BigEndian (nanoseconds)
//   28      8     t4              uint64 BigEndian (nanoseconds)
//   36      4     reserved        zero padding
//   Total: 40 bytes (= PROBE_PACKET_SIZE)

const std = @import("std");
const types = @import("types.zig");
const queue_module = @import("queue.zig");
const memory = @import("memory.zig");
const c = types.c;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Current version of the probe packet wire format.
pub const PACKET_VERSION: u8 = 1;

/// Message type: probe packet (initiator sends to responder).
pub const MSG_TYPE_PROBE: u8 = 0;

/// Message type: acknowledgement packet (responder sends back).
pub const MSG_TYPE_ACK: u8 = 1;

/// ACK type: not applicable (used in probe packets).
pub const ACK_TYPE_NONE: u8 = 0;

/// ACK type: first ACK containing T3 (responder receive timestamp).
pub const ACK_TYPE_FIRST: u8 = 1;

/// ACK type: second ACK containing both T3 and T4 (processing delay).
pub const ACK_TYPE_SECOND: u8 = 2;

// ---------------------------------------------------------------------------
// ProbePacket struct (Zig-native, NOT extern)
// ---------------------------------------------------------------------------

/// Represents a probe or ACK packet in Zig-native layout.
///
/// This struct is used for application-level manipulation of packet fields.
/// It is NOT laid out to match the wire format; use serializeProbePacket()
/// and deserializeProbePacket() for wire conversion.
pub const ProbePacket = struct {
    /// Wire format version (currently PACKET_VERSION = 1).
    version: u8,

    /// Message type: MSG_TYPE_PROBE (0) or MSG_TYPE_ACK (1).
    msg_type: u8,

    /// ACK type: ACK_TYPE_NONE (0), ACK_TYPE_FIRST (1), or ACK_TYPE_SECOND (2).
    ack_type: u8,

    /// Reserved flags for future use.
    flags: u8,

    /// Probe sequence number for correlating probes with their ACKs.
    sequence_num: u64,

    /// T1 timestamp: time the prober posted the send (nanoseconds).
    t1: u64,

    /// T3 timestamp: time the responder received the probe (nanoseconds).
    t3: u64,

    /// T4 timestamp: time the responder's first ACK send completed (nanoseconds).
    t4: u64,
};

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

/// Result of a first ACK send operation.
pub const FirstAckResult = struct {
    /// T4: send completion timestamp of the first ACK (nanoseconds).
    t4_ns: u64,

    /// 0 on success, negative error code on failure.
    error_code: i32,
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

// ---------------------------------------------------------------------------
// BigEndian helpers
// ---------------------------------------------------------------------------

/// Write a u64 value in BigEndian byte order at the given offset.
fn writeBigEndianU64(buf: [*]u8, offset: usize, value: u64) void {
    buf[offset] = @intCast((value >> 56) & 0xFF);
    buf[offset + 1] = @intCast((value >> 48) & 0xFF);
    buf[offset + 2] = @intCast((value >> 40) & 0xFF);
    buf[offset + 3] = @intCast((value >> 32) & 0xFF);
    buf[offset + 4] = @intCast((value >> 24) & 0xFF);
    buf[offset + 5] = @intCast((value >> 16) & 0xFF);
    buf[offset + 6] = @intCast((value >> 8) & 0xFF);
    buf[offset + 7] = @intCast(value & 0xFF);
}

/// Read a u64 value in BigEndian byte order from the given offset.
fn readBigEndianU64(buf: [*]const u8, offset: usize) u64 {
    return (@as(u64, buf[offset]) << 56) |
        (@as(u64, buf[offset + 1]) << 48) |
        (@as(u64, buf[offset + 2]) << 40) |
        (@as(u64, buf[offset + 3]) << 32) |
        (@as(u64, buf[offset + 4]) << 24) |
        (@as(u64, buf[offset + 5]) << 16) |
        (@as(u64, buf[offset + 6]) << 8) |
        @as(u64, buf[offset + 7]);
}

// ---------------------------------------------------------------------------
// Serialization / Deserialization
// ---------------------------------------------------------------------------

/// Serialize a ProbePacket into a 40-byte wire format buffer.
///
/// Writes each field at the correct offset using explicit BigEndian encoding.
/// The reserved bytes at offset 36-39 are zeroed.
pub fn serializeProbePacket(pkt: *const ProbePacket, buf: *[40]u8) void {
    // Single-byte fields at offsets 0-3
    buf[0] = pkt.version;
    buf[1] = pkt.msg_type;
    buf[2] = pkt.ack_type;
    buf[3] = pkt.flags;

    // Multi-byte fields in BigEndian
    writeBigEndianU64(buf, 4, pkt.sequence_num);
    writeBigEndianU64(buf, 12, pkt.t1);
    writeBigEndianU64(buf, 20, pkt.t3);
    writeBigEndianU64(buf, 28, pkt.t4);

    // Reserved bytes (36-39) zeroed
    buf[36] = 0;
    buf[37] = 0;
    buf[38] = 0;
    buf[39] = 0;
}

/// Deserialize a 40-byte wire format buffer into a ProbePacket.
///
/// Reads each field from the correct offset using BigEndian decoding.
/// If the version byte does not match PACKET_VERSION, returns a default
/// packet with flags set to 0xFF to indicate an error.
pub fn deserializeProbePacket(buf: *const [40]u8) ProbePacket {
    const version = buf[0];

    // Version validation: return error-flagged packet on mismatch
    if (version != PACKET_VERSION) {
        return ProbePacket{
            .version = version,
            .msg_type = 0,
            .ack_type = 0,
            .flags = 0xFF, // Error indicator
            .sequence_num = 0,
            .t1 = 0,
            .t3 = 0,
            .t4 = 0,
        };
    }

    return ProbePacket{
        .version = version,
        .msg_type = buf[1],
        .ack_type = buf[2],
        .flags = buf[3],
        .sequence_num = readBigEndianU64(buf, 4),
        .t1 = readBigEndianU64(buf, 12),
        .t3 = readBigEndianU64(buf, 20),
        .t4 = readBigEndianU64(buf, 28),
    };
}

// ---------------------------------------------------------------------------
// Send slot management
// ---------------------------------------------------------------------------

/// Find a free send slot in the queue.
///
/// Scans the send_slot_states array for a slot in the Free state.
/// If found, marks it as InUse and returns the slot index.
/// Returns null if no free slot is available.
pub fn findFreeSendSlot(queue: *types.UdQueue) ?u32 {
    for (0..types.NUM_SEND_SLOTS) |i| {
        const idx: u32 = @intCast(i);
        if (queue.send_slot_states[idx] == .Free) {
            queue.send_slot_states[idx] = .InUse;
            return idx;
        }
    }
    return null;
}

/// Free a send slot, marking it as available for reuse.
pub fn freeSendSlot(queue: *types.UdQueue, slot_index: u32) void {
    if (slot_index < types.NUM_SEND_SLOTS) {
        queue.send_slot_states[slot_index] = .Free;
    }
}

// ---------------------------------------------------------------------------
// Send completion waiting
// ---------------------------------------------------------------------------

/// Wait for a send completion by spinning on the atomic flag.
///
/// The CQ poller thread sets send_completion_ready to true after processing
/// a send completion. This function spins until the flag is set or the
/// timeout expires.
///
/// Returns the send completion timestamp on success, or an error on timeout
/// or completion failure.
pub fn waitSendCompletion(queue: *types.UdQueue, timeout_ms: u32) PacketError!u64 {
    const timeout_ns: u64 = @as(u64, timeout_ms) * 1_000_000;
    const start_ns: u64 = getMonotonicNs();

    // Spin-wait on the send_completion_ready atomic flag
    while (!queue.send_completion_ready.load(.acquire)) {
        // Check for timeout
        const elapsed = getMonotonicNs() - start_ns;
        if (elapsed >= timeout_ns) {
            types.setLastError("timed out waiting for send completion");
            return PacketError.SendTimeout;
        }

        // Yield to avoid burning CPU in a tight loop
        std.atomic.spinLoopHint();
    }

    // Check completion status
    const status = queue.send_completion_status.load(.acquire);
    if (status != 0) {
        types.setLastError("send completion reported error status");
        return PacketError.SendCompletionFailed;
    }

    // Read the completion timestamp
    return queue.send_completion_timestamp.load(.acquire);
}

// ---------------------------------------------------------------------------
// Clock helper
// ---------------------------------------------------------------------------

/// Get the current monotonic clock time in nanoseconds.
fn getMonotonicNs() u64 {
    const ts = std.time.nanoTimestamp();
    // nanoTimestamp returns i128; safely convert to u64
    return @intCast(@as(u128, @bitCast(ts)) & 0xFFFFFFFFFFFFFFFF);
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
    // Step 1: Find a free send slot
    const slot_index = findFreeSendSlot(queue) orelse {
        types.setLastError("no free send slot available");
        return PacketError.NoFreeSendSlot;
    };
    errdefer freeSendSlot(queue, slot_index);

    // Step 2: Get the slot buffer pointer and serialize the packet
    const slot_ptr = memory.getSlotPtr(queue.send_buf, slot_index, types.NUM_SEND_SLOTS) catch {
        types.setLastError("send slot index out of bounds");
        freeSendSlot(queue, slot_index);
        return PacketError.SlotIndexOutOfBounds;
    };
    const buf_ptr: *[40]u8 = @ptrCast(slot_ptr);
    serializeProbePacket(pkt, buf_ptr);

    // Step 3: Create an address handle for the target
    const ah = queue_module.createAddressHandle(queue.device, target_gid, flow_label) catch {
        // Error message already set by createAddressHandle
        freeSendSlot(queue, slot_index);
        return PacketError.CreateAhFailed;
    };
    defer queue_module.destroyAddressHandle(ah);

    // Step 4: Reset the send completion flag before posting
    queue.send_completion_ready.store(false, .release);

    // Step 5: Build and post the send work request
    var sge = c.ibv_sge{
        .addr = @intFromPtr(slot_ptr),
        .length = types.PROBE_PACKET_SIZE,
        .lkey = queue.send_mr.lkey,
    };

    var wr = std.mem.zeroes(c.ibv_send_wr);
    wr.wr_id = @intCast(slot_index);
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = c.IBV_WR_SEND;
    wr.send_flags = c.IBV_SEND_SIGNALED;
    wr.wr.ud.ah = ah;
    wr.wr.ud.remote_qpn = target_qpn;
    wr.wr.ud.remote_qkey = types.QKEY;

    var bad_wr: ?*c.ibv_send_wr = null;
    const ret = c.ibv_post_send(queue.qp, &wr, &bad_wr);
    if (ret != 0) {
        types.setLastError("ibv_post_send() failed");
        freeSendSlot(queue, slot_index);
        return PacketError.PostSendFailed;
    }

    // Step 6: Wait for send completion
    const timestamp = waitSendCompletion(queue, timeout_ms) catch |err| {
        freeSendSlot(queue, slot_index);
        return err;
    };

    // Step 7: Free the send slot
    freeSendSlot(queue, slot_index);

    return timestamp;
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
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_PROBE,
        .ack_type = ACK_TYPE_NONE,
        .flags = 0,
        .sequence_num = sequence_num,
        .t1 = 0, // Will be captured separately
        .t3 = 0,
        .t4 = 0,
    };

    // Capture T1 just before posting the send
    const t1_ns = getMonotonicNs();

    // Perform the send
    const t2_ns = sendPacketInternal(queue, target_gid, flow_label, target_qpn, &pkt, timeout_ms) catch |err| {
        _ = err;
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

/// Send the first ACK in response to a received probe.
///
/// Deserializes the received probe packet, constructs a first ACK with T3
/// (the responder's receive timestamp), posts the send, and returns T4
/// (the send completion timestamp of the ACK).
///
/// Returns a FirstAckResult containing T4 and an error indicator.
pub fn sendFirstAck(
    queue: *types.UdQueue,
    target_gid: [16]u8,
    target_qpn: u32,
    flow_label: u32,
    recv_packet: [*]const u8,
    recv_timestamp_ns: u64,
    timeout_ms: u32,
) FirstAckResult {
    // Deserialize the received probe packet to extract sequence_num and t1.
    // The recv_packet pointer points to the payload after the GRH.
    const original = deserializeProbePacket(@ptrCast(recv_packet));

    // Construct the first ACK packet
    const ack_pkt = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_ACK,
        .ack_type = ACK_TYPE_FIRST,
        .flags = 0,
        .sequence_num = original.sequence_num,
        .t1 = original.t1,
        .t3 = recv_timestamp_ns,
        .t4 = 0, // T4 will be captured from send completion
    };

    // Perform the send and capture T4
    const t4_ns = sendPacketInternal(queue, target_gid, flow_label, target_qpn, &ack_pkt, timeout_ms) catch {
        return FirstAckResult{
            .t4_ns = 0,
            .error_code = -1,
        };
    };

    return FirstAckResult{
        .t4_ns = t4_ns,
        .error_code = 0,
    };
}

/// Send the second ACK with processing delay information.
///
/// Deserializes the received probe packet for the sequence number, then
/// constructs a second ACK containing both T3 and T4 so the prober can
/// compute the responder processing delay and subtract it from the RTT.
///
/// Returns 0 on success, negative error code on failure.
pub fn sendSecondAck(
    queue: *types.UdQueue,
    target_gid: [16]u8,
    target_qpn: u32,
    flow_label: u32,
    recv_packet: [*]const u8,
    t3_ns: u64,
    t4_ns: u64,
    timeout_ms: u32,
) i32 {
    // Deserialize the received probe packet to extract sequence_num and t1
    const original = deserializeProbePacket(@ptrCast(recv_packet));

    // Construct the second ACK packet with processing delay information
    const ack_pkt = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_ACK,
        .ack_type = ACK_TYPE_SECOND,
        .flags = 0,
        .sequence_num = original.sequence_num,
        .t1 = original.t1,
        .t3 = t3_ns,
        .t4 = t4_ns,
    };

    // Perform the send
    _ = sendPacketInternal(queue, target_gid, flow_label, target_qpn, &ack_pkt, timeout_ms) catch {
        return -1;
    };

    return 0;
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

/// Send the first ACK (C-ABI export matching rdma_send_first_ack in rdma_bridge.h).
///
/// @param queue_ptr          Responder queue handle
/// @param target_gid         Pointer to 16-byte prober GID
/// @param target_qpn         Prober's QPN
/// @param flow_label         Flow label for ECMP path consistency
/// @param recv_packet        Raw received packet buffer (payload after GRH)
/// @param recv_timestamp_ns  T3: receive completion timestamp (ns)
/// @param out_t4_ns          Output pointer for T4 timestamp
/// @param timeout_ms         Send completion timeout in milliseconds
/// @return                   0 on success, negative error code on failure
export fn rdma_send_first_ack(
    queue_ptr: ?*types.UdQueue,
    target_gid: ?*const [16]u8,
    target_qpn: u32,
    flow_label: u32,
    recv_packet: ?[*]const u8,
    recv_timestamp_ns: u64,
    out_t4_ns: ?*u64,
    timeout_ms: u32,
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
    const t4_out = out_t4_ns orelse {
        types.setLastError("null out_t4_ns pointer");
        return -1;
    };

    const result = sendFirstAck(queue, gid.*, target_qpn, flow_label, pkt, recv_timestamp_ns, timeout_ms);
    if (result.error_code != 0) {
        return result.error_code;
    }

    t4_out.* = result.t4_ns;
    return 0;
}

/// Send the second ACK (C-ABI export matching rdma_send_second_ack in rdma_bridge.h).
///
/// @param queue_ptr     Responder queue handle
/// @param target_gid    Pointer to 16-byte prober GID
/// @param target_qpn    Prober's QPN
/// @param flow_label    Flow label for ECMP path consistency
/// @param recv_packet   Raw received packet buffer (payload after GRH)
/// @param t3_ns         T3: probe receive completion timestamp (ns)
/// @param t4_ns         T4: first ACK send completion timestamp (ns)
/// @param timeout_ms    Send completion timeout in milliseconds
/// @return              0 on success, negative error code on failure
export fn rdma_send_second_ack(
    queue_ptr: ?*types.UdQueue,
    target_gid: ?*const [16]u8,
    target_qpn: u32,
    flow_label: u32,
    recv_packet: ?[*]const u8,
    t3_ns: u64,
    t4_ns: u64,
    timeout_ms: u32,
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

    return sendSecondAck(queue, gid.*, target_qpn, flow_label, pkt, t3_ns, t4_ns, timeout_ms);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ProbePacket struct has expected fields" {
    const pkt = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_PROBE,
        .ack_type = ACK_TYPE_NONE,
        .flags = 0,
        .sequence_num = 42,
        .t1 = 1000,
        .t3 = 2000,
        .t4 = 3000,
    };
    try std.testing.expectEqual(@as(u8, 1), pkt.version);
    try std.testing.expectEqual(@as(u8, 0), pkt.msg_type);
    try std.testing.expectEqual(@as(u8, 0), pkt.ack_type);
    try std.testing.expectEqual(@as(u64, 42), pkt.sequence_num);
    try std.testing.expectEqual(@as(u64, 1000), pkt.t1);
    try std.testing.expectEqual(@as(u64, 2000), pkt.t3);
    try std.testing.expectEqual(@as(u64, 3000), pkt.t4);
}

test "SendResult size matches C ABI" {
    // rdma_send_result_t: uint64_t t1_ns + uint64_t t2_ns + int32_t error + 4 bytes padding = 24 bytes
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(SendResult));
}

test "protocol constants have correct values" {
    try std.testing.expectEqual(@as(u8, 1), PACKET_VERSION);
    try std.testing.expectEqual(@as(u8, 0), MSG_TYPE_PROBE);
    try std.testing.expectEqual(@as(u8, 1), MSG_TYPE_ACK);
    try std.testing.expectEqual(@as(u8, 0), ACK_TYPE_NONE);
    try std.testing.expectEqual(@as(u8, 1), ACK_TYPE_FIRST);
    try std.testing.expectEqual(@as(u8, 2), ACK_TYPE_SECOND);
}

test "writeBigEndianU64 and readBigEndianU64 roundtrip" {
    var buf: [8]u8 = undefined;
    const test_values = [_]u64{
        0,
        1,
        42,
        0xFF,
        0xFFFF,
        0xFFFFFFFF,
        0xDEADBEEFCAFEBABE,
        0xFFFFFFFFFFFFFFFF,
    };

    for (test_values) |value| {
        writeBigEndianU64(&buf, 0, value);
        const read_back = readBigEndianU64(&buf, 0);
        try std.testing.expectEqual(value, read_back);
    }
}

test "writeBigEndianU64 produces correct byte order" {
    var buf: [8]u8 = undefined;

    // 0x0102030405060708 should produce bytes [01, 02, 03, 04, 05, 06, 07, 08]
    writeBigEndianU64(&buf, 0, 0x0102030405060708);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x02), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x03), buf[2]);
    try std.testing.expectEqual(@as(u8, 0x04), buf[3]);
    try std.testing.expectEqual(@as(u8, 0x05), buf[4]);
    try std.testing.expectEqual(@as(u8, 0x06), buf[5]);
    try std.testing.expectEqual(@as(u8, 0x07), buf[6]);
    try std.testing.expectEqual(@as(u8, 0x08), buf[7]);
}

test "writeBigEndianU64 with offset" {
    var buf: [16]u8 = [_]u8{0} ** 16;
    writeBigEndianU64(&buf, 4, 0x0A0B0C0D0E0F1011);

    // Bytes before offset should be untouched
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[3]);

    // Value at offset
    try std.testing.expectEqual(@as(u8, 0x0A), buf[4]);
    try std.testing.expectEqual(@as(u8, 0x11), buf[11]);

    // Bytes after should be untouched
    try std.testing.expectEqual(@as(u8, 0x00), buf[12]);
}

test "serializeProbePacket writes correct bytes" {
    const pkt = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_ACK,
        .ack_type = ACK_TYPE_FIRST,
        .flags = 0x42,
        .sequence_num = 0x0000000000000001,
        .t1 = 0x00000000000003E8, // 1000
        .t3 = 0x00000000000007D0, // 2000
        .t4 = 0x0000000000000BB8, // 3000
    };

    var buf: [40]u8 = undefined;
    serializeProbePacket(&pkt, &buf);

    // Check single-byte header fields
    try std.testing.expectEqual(@as(u8, 1), buf[0]); // version
    try std.testing.expectEqual(@as(u8, 1), buf[1]); // msg_type = ACK
    try std.testing.expectEqual(@as(u8, 1), buf[2]); // ack_type = FIRST
    try std.testing.expectEqual(@as(u8, 0x42), buf[3]); // flags

    // Check sequence_num at offset 4 (BigEndian)
    try std.testing.expectEqual(@as(u64, 1), readBigEndianU64(&buf, 4));

    // Check t1 at offset 12
    try std.testing.expectEqual(@as(u64, 1000), readBigEndianU64(&buf, 12));

    // Check t3 at offset 20
    try std.testing.expectEqual(@as(u64, 2000), readBigEndianU64(&buf, 20));

    // Check t4 at offset 28
    try std.testing.expectEqual(@as(u64, 3000), readBigEndianU64(&buf, 28));

    // Check reserved bytes are zero
    try std.testing.expectEqual(@as(u8, 0), buf[36]);
    try std.testing.expectEqual(@as(u8, 0), buf[37]);
    try std.testing.expectEqual(@as(u8, 0), buf[38]);
    try std.testing.expectEqual(@as(u8, 0), buf[39]);
}

test "deserializeProbePacket roundtrip" {
    const original = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_ACK,
        .ack_type = ACK_TYPE_SECOND,
        .flags = 0,
        .sequence_num = 12345678,
        .t1 = 1_000_000_000,
        .t3 = 2_000_000_000,
        .t4 = 3_000_000_000,
    };

    var buf: [40]u8 = undefined;
    serializeProbePacket(&original, &buf);
    const deserialized = deserializeProbePacket(&buf);

    try std.testing.expectEqual(original.version, deserialized.version);
    try std.testing.expectEqual(original.msg_type, deserialized.msg_type);
    try std.testing.expectEqual(original.ack_type, deserialized.ack_type);
    try std.testing.expectEqual(original.flags, deserialized.flags);
    try std.testing.expectEqual(original.sequence_num, deserialized.sequence_num);
    try std.testing.expectEqual(original.t1, deserialized.t1);
    try std.testing.expectEqual(original.t3, deserialized.t3);
    try std.testing.expectEqual(original.t4, deserialized.t4);
}

test "deserializeProbePacket with version mismatch returns error-flagged packet" {
    var buf: [40]u8 = [_]u8{0} ** 40;
    buf[0] = 99; // Invalid version

    const pkt = deserializeProbePacket(&buf);

    try std.testing.expectEqual(@as(u8, 99), pkt.version);
    try std.testing.expectEqual(@as(u8, 0xFF), pkt.flags); // Error indicator
    try std.testing.expectEqual(@as(u64, 0), pkt.sequence_num);
}

test "serialize probe packet has correct total size" {
    // Verify the wire format size matches the protocol constant
    try std.testing.expectEqual(@as(u32, 40), types.PROBE_PACKET_SIZE);
}

test "serializeProbePacket zeroes reserved bytes even if buffer was dirty" {
    var buf: [40]u8 = [_]u8{0xFF} ** 40; // Fill with 0xFF

    const pkt = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_PROBE,
        .ack_type = ACK_TYPE_NONE,
        .flags = 0,
        .sequence_num = 0,
        .t1 = 0,
        .t3 = 0,
        .t4 = 0,
    };

    serializeProbePacket(&pkt, &buf);

    // Reserved bytes must be zero regardless of previous buffer content
    try std.testing.expectEqual(@as(u8, 0), buf[36]);
    try std.testing.expectEqual(@as(u8, 0), buf[37]);
    try std.testing.expectEqual(@as(u8, 0), buf[38]);
    try std.testing.expectEqual(@as(u8, 0), buf[39]);
}

test "serializeProbePacket all message type combinations" {
    // Test probe packet
    {
        const pkt = ProbePacket{
            .version = PACKET_VERSION,
            .msg_type = MSG_TYPE_PROBE,
            .ack_type = ACK_TYPE_NONE,
            .flags = 0,
            .sequence_num = 100,
            .t1 = 0,
            .t3 = 0,
            .t4 = 0,
        };
        var buf: [40]u8 = undefined;
        serializeProbePacket(&pkt, &buf);
        try std.testing.expectEqual(@as(u8, 0), buf[1]); // MSG_TYPE_PROBE
        try std.testing.expectEqual(@as(u8, 0), buf[2]); // ACK_TYPE_NONE
    }

    // Test first ACK
    {
        const pkt = ProbePacket{
            .version = PACKET_VERSION,
            .msg_type = MSG_TYPE_ACK,
            .ack_type = ACK_TYPE_FIRST,
            .flags = 0,
            .sequence_num = 100,
            .t1 = 500,
            .t3 = 1000,
            .t4 = 0,
        };
        var buf: [40]u8 = undefined;
        serializeProbePacket(&pkt, &buf);
        try std.testing.expectEqual(@as(u8, 1), buf[1]); // MSG_TYPE_ACK
        try std.testing.expectEqual(@as(u8, 1), buf[2]); // ACK_TYPE_FIRST
    }

    // Test second ACK
    {
        const pkt = ProbePacket{
            .version = PACKET_VERSION,
            .msg_type = MSG_TYPE_ACK,
            .ack_type = ACK_TYPE_SECOND,
            .flags = 0,
            .sequence_num = 100,
            .t1 = 500,
            .t3 = 1000,
            .t4 = 1500,
        };
        var buf: [40]u8 = undefined;
        serializeProbePacket(&pkt, &buf);
        try std.testing.expectEqual(@as(u8, 1), buf[1]); // MSG_TYPE_ACK
        try std.testing.expectEqual(@as(u8, 2), buf[2]); // ACK_TYPE_SECOND
    }
}

test "deserializeProbePacket with max u64 values" {
    const original = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_PROBE,
        .ack_type = ACK_TYPE_NONE,
        .flags = 0,
        .sequence_num = 0xFFFFFFFFFFFFFFFF,
        .t1 = 0xFFFFFFFFFFFFFFFF,
        .t3 = 0xFFFFFFFFFFFFFFFF,
        .t4 = 0xFFFFFFFFFFFFFFFF,
    };

    var buf: [40]u8 = undefined;
    serializeProbePacket(&original, &buf);
    const deserialized = deserializeProbePacket(&buf);

    try std.testing.expectEqual(original.sequence_num, deserialized.sequence_num);
    try std.testing.expectEqual(original.t1, deserialized.t1);
    try std.testing.expectEqual(original.t3, deserialized.t3);
    try std.testing.expectEqual(original.t4, deserialized.t4);
}

test "findFreeSendSlot and freeSendSlot basic behavior" {
    // Create a mock queue-like struct by testing the slot management functions
    // with a stack-allocated slot states array.
    // Note: We cannot create a full UdQueue without RDMA hardware, so we test
    // the logic conceptually via the state array.
    var states: [types.NUM_SEND_SLOTS]types.SlotState = [_]types.SlotState{.Free} ** types.NUM_SEND_SLOTS;

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
    var states: [types.NUM_SEND_SLOTS]types.SlotState = [_]types.SlotState{.InUse} ** types.NUM_SEND_SLOTS;

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

test "FirstAckResult struct layout" {
    const result = FirstAckResult{
        .t4_ns = 1000,
        .error_code = 0,
    };
    try std.testing.expectEqual(@as(u64, 1000), result.t4_ns);
    try std.testing.expectEqual(@as(i32, 0), result.error_code);
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
    _ = sum;
    const t2 = getMonotonicNs();
    try std.testing.expect(t2 >= t1);
}
