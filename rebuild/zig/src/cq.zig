// cq.zig - CQ polling thread and completion processing.
//
// This module implements the dedicated CQ poller thread that runs per queue.
// It uses event-driven notification (ibv_get_cq_event / ibv_req_notify_cq)
// to block until completions arrive, then polls them with the extended CQ API
// (ibv_start_poll / ibv_next_poll / ibv_end_poll).
//
// For receive completions, the poller parses the GRH and probe payload, builds
// a CompletionEvent, and pushes it into the SPSC ring buffer for consumption
// by the Go side.
//
// For send completions, the poller extracts the timestamp and signals the
// waiting sender thread via atomic variables on the UdQueue struct.

const std = @import("std");
const types = @import("types.zig");
const ring = @import("ring.zig");
const memory = @import("memory.zig");
const c = types.c;

// ---------------------------------------------------------------------------
// GRH parsing
// ---------------------------------------------------------------------------

/// Information extracted from a Global Routing Header (GRH).
///
/// The GRH is 40 bytes prepended by the hardware to every UD receive buffer.
/// It follows the IPv6 header format and contains the source/destination GIDs
/// and the flow label used for ECMP path selection.
pub const GRHInfo = struct {
    /// Source GID (16 bytes) identifying the sender.
    source_gid: [16]u8,

    /// Destination GID (16 bytes) identifying the receiver.
    dest_gid: [16]u8,

    /// Flow label from the IPv6 header (lower 20 bits of the first 4-byte word).
    /// Used for ECMP path pinning in the R-Pingmesh protocol.
    flow_label: u32,
};

/// Parse the 40-byte GRH at the start of a UD receive buffer.
///
/// GRH layout (IPv6 header format):
///   Bytes 0-3:   Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits)
///   Bytes 4-5:   Payload Length
///   Byte  6:     Next Header
///   Byte  7:     Hop Limit
///   Bytes 8-23:  Source GID (128 bits)
///   Bytes 24-39: Destination GID (128 bits)
pub fn parseGRH(buf: [*]const u8) GRHInfo {
    // Extract the flow label from the first 4 bytes (big-endian).
    // Flow label occupies bits 12-31 (the lower 20 bits of the 32-bit word).
    const word0: u32 = (@as(u32, buf[0]) << 24) |
        (@as(u32, buf[1]) << 16) |
        (@as(u32, buf[2]) << 8) |
        @as(u32, buf[3]);
    const flow_label = word0 & 0x000FFFFF;

    // Source GID: bytes 8-23
    var source_gid: [16]u8 = undefined;
    for (0..16) |i| {
        source_gid[i] = buf[8 + i];
    }

    // Destination GID: bytes 24-39
    var dest_gid: [16]u8 = undefined;
    for (0..16) |i| {
        dest_gid[i] = buf[24 + i];
    }

    return GRHInfo{
        .source_gid = source_gid,
        .dest_gid = dest_gid,
        .flow_label = flow_label,
    };
}

// ---------------------------------------------------------------------------
// Probe packet payload parsing
// ---------------------------------------------------------------------------

/// Parse probe packet fields from the payload buffer (after GRH).
///
/// The probe packet is 40 bytes with big-endian encoded fields:
///   Bytes 0-7:   sequence_num (u64)
///   Bytes 8-15:  t1 (u64)
///   Bytes 16-23: t3 (u64)
///   Bytes 24-31: t4 (u64)
///   Byte  32:    is_ack (u8)
///   Byte  33:    ack_type (u8)
///   Bytes 34-39: reserved/padding
const ProbePayload = struct {
    sequence_num: u64,
    t1: u64,
    t3: u64,
    t4: u64,
    is_ack: u8,
    ack_type: u8,
};

/// Read a big-endian u64 from a byte pointer at the given offset.
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

/// Parse a probe packet payload from raw bytes.
fn parseProbePayload(buf: [*]const u8) ProbePayload {
    return ProbePayload{
        .sequence_num = readBigEndianU64(buf, 0),
        .t1 = readBigEndianU64(buf, 8),
        .t3 = readBigEndianU64(buf, 16),
        .t4 = readBigEndianU64(buf, 24),
        .is_ack = buf[32],
        .ack_type = buf[33],
    };
}

// ---------------------------------------------------------------------------
// CQ poller thread management
// ---------------------------------------------------------------------------

/// Start the CQ poller thread for the given queue.
///
/// Sets queue.running to true and spawns a std.Thread that runs cqPollerLoop.
/// The thread handle is stored in queue.cq_thread for later joining.
pub fn startCqPollerThread(queue: *types.UdQueue) !void {
    queue.running.store(true, .release);
    queue.cq_thread = try std.Thread.spawn(.{}, cqPollerLoop, .{queue});
}

/// Stop the CQ poller thread and wait for it to exit.
///
/// Sets queue.running to false, then requests a CQ notification to wake
/// the thread if it is blocked in ibv_get_cq_event(). Finally joins the
/// thread to ensure it has fully exited before returning.
pub fn stopCqPollerThread(queue: *types.UdQueue) void {
    // Signal the poller to stop
    queue.running.store(false, .release);

    // Wake the blocked thread by requesting a CQ notification.
    // This causes ibv_get_cq_event() to return, allowing the thread
    // to observe the running=false flag and exit.
    const base_cq = c.ibv_cq_ex_to_cq(queue.recv_cq);
    if (base_cq != null) {
        _ = c.ibv_req_notify_cq(base_cq, 0);
    }

    // Join the thread
    if (queue.cq_thread) |thread| {
        thread.join();
        queue.cq_thread = null;
    }
}

// ---------------------------------------------------------------------------
// CQ poller loop (thread entry point)
// ---------------------------------------------------------------------------

/// Main loop for the CQ poller thread.
///
/// This function is the entry point for the dedicated poller thread. It:
///   1. Requests CQ notification via ibv_req_notify_cq()
///   2. Blocks on ibv_get_cq_event() until a completion arrives
///   3. Acknowledges the event via ibv_ack_cq_events()
///   4. Polls completions using the extended CQ API
///   5. Dispatches recv completions to the event ring, send completions
///      to the atomic signaling mechanism
///
/// The loop continues until queue.running is set to false.
fn cqPollerLoop(queue: *types.UdQueue) void {
    const recv_base_cq = c.ibv_cq_ex_to_cq(queue.recv_cq);
    if (recv_base_cq == null) {
        types.setLastError("cqPollerLoop: failed to get base CQ from recv_cq");
        return;
    }

    // Main polling loop
    while (queue.running.load(.acquire)) {
        // Request notification for the next completion event
        if (c.ibv_req_notify_cq(recv_base_cq, 0) != 0) {
            if (!queue.running.load(.acquire)) break;
            types.setLastError("cqPollerLoop: ibv_req_notify_cq() failed");
            continue;
        }

        // Block until a CQ event arrives
        var ev_cq: ?*c.ibv_cq = null;
        var ev_ctx: ?*anyopaque = null;
        const ret = c.ibv_get_cq_event(queue.comp_channel, &ev_cq, &ev_ctx);
        if (ret != 0) {
            // ibv_get_cq_event failed - check if we are shutting down
            if (!queue.running.load(.acquire)) break;
            types.setLastError("cqPollerLoop: ibv_get_cq_event() failed");
            continue;
        }

        // Acknowledge the event (must be done before requesting the next one)
        if (ev_cq) |cq_ptr| {
            c.ibv_ack_cq_events(cq_ptr, 1);
        }

        // Poll the recv CQ for completions using extended polling API
        pollCqCompletions(queue, queue.recv_cq, false);

        // Also poll the send CQ if it is separate from recv CQ
        if (queue.send_cq != queue.recv_cq) {
            pollCqCompletions(queue, queue.send_cq, true);
        }
    }
}

/// Poll a single CQ for all available completions.
///
/// Uses the extended polling API: ibv_start_poll -> process -> ibv_next_poll -> ibv_end_poll.
/// The is_send_cq parameter determines whether completions are treated as send or recv.
fn pollCqCompletions(queue: *types.UdQueue, cq: *c.ibv_cq_ex, is_send_cq: bool) {
    var poll_attr = std.mem.zeroes(c.ibv_poll_cq_attr);

    const ret_start = c.ibv_start_poll(cq, &poll_attr);
    if (ret_start != 0) {
        // ENOENT means no completions available - this is normal
        return;
    }

    // Process the first completion
    dispatchCompletion(queue, cq, is_send_cq);

    // Process remaining completions
    while (c.ibv_next_poll(cq) == 0) {
        dispatchCompletion(queue, cq, is_send_cq);
    }

    c.ibv_end_poll(cq);
}

/// Dispatch a single work completion to the appropriate handler.
///
/// Reads the opcode from the extended CQ to determine whether this is a
/// send or receive completion, then delegates to the appropriate processor.
fn dispatchCompletion(queue: *types.UdQueue, cq: *c.ibv_cq_ex, is_send_cq: bool) {
    const status: i32 = @intCast(cq.status);

    if (status != c.IBV_WC_SUCCESS) {
        // For error completions, check if it might be a send based on context
        if (is_send_cq) {
            processSendCompletion(queue, cq);
        }
        // For recv errors, we could repost the buffer but skip for now
        return;
    }

    const opcode = c.ibv_wc_read_opcode(cq);
    if (opcode == c.IBV_WC_RECV) {
        processRecvCompletion(queue, cq);
    } else if (opcode == c.IBV_WC_SEND) {
        processSendCompletion(queue, cq);
    }
    // Unknown opcodes are silently ignored
}

// ---------------------------------------------------------------------------
// Receive completion processing
// ---------------------------------------------------------------------------

/// Process a single receive completion.
///
/// Extracts the slot index from wr_id, reads the timestamp (HW or SW),
/// parses the GRH for source GID and flow label, parses the probe payload,
/// builds a CompletionEvent, pushes it into the event ring, and reposts
/// the receive buffer for reuse.
pub fn processRecvCompletion(queue: *types.UdQueue, cq: *c.ibv_cq_ex) void {
    // Get the slot index from wr_id
    const wr_id: u64 = cq.wr_id;
    const slot_index: u32 = @intCast(wr_id & 0xFFFFFFFF);

    // Get timestamp
    const timestamp_ns: u64 = getCompletionTimestamp(queue, cq);

    // Get source QPN from the extended completion
    const src_qp: u32 = c.ibv_wc_read_src_qp(cq);

    // Get the receive buffer slot pointer
    const slot_ptr = memory.getSlotPtr(queue.recv_buf, slot_index, types.NUM_RECV_SLOTS) catch {
        // Slot index out of bounds - cannot process
        return;
    };

    // Parse GRH from the first 40 bytes of the receive buffer
    const grh_info = parseGRH(slot_ptr);

    // Parse probe payload from bytes after the GRH
    const payload_ptr = slot_ptr + types.GRH_SIZE;
    const payload = parseProbePayload(payload_ptr);

    // Build the completion event
    const event = ring.CompletionEvent{
        .sequence_num = payload.sequence_num,
        .t1 = payload.t1,
        .t3 = payload.t3,
        .t4 = payload.t4,
        .is_ack = payload.is_ack,
        .ack_type = payload.ack_type,
        .flags = 0,
        ._pad = 0,
        .timestamp_ns = timestamp_ns,
        .source_gid = grh_info.source_gid,
        .source_qpn = src_qp,
        .flow_label = grh_info.flow_label,
        .status = @intCast(cq.status),
        .is_send = 0,
        ._pad2 = [_]u8{ 0, 0, 0 },
    };

    // Push the event into the ring buffer
    if (queue.event_ring) |event_ring| {
        _ = event_ring.push(&event);
    }

    // Repost the receive buffer slot so the hardware can use it again
    memory.postRecvBuffer(queue.qp, queue.recv_mr, queue.recv_buf, slot_index) catch {
        // Failed to repost - the slot will be lost until queue recreation.
        // This is logged via setLastError in the postRecvBuffer function.
    };
}

// ---------------------------------------------------------------------------
// Send completion processing
// ---------------------------------------------------------------------------

/// Process a single send completion.
///
/// Extracts the timestamp from the completion and signals the waiting sender
/// thread via the atomic variables on the UdQueue struct. The sender thread
/// spins on send_completion_ready after posting a send WR and reads the
/// timestamp and status once the flag becomes true.
pub fn processSendCompletion(queue: *types.UdQueue, cq: *c.ibv_cq_ex) void {
    // Get timestamp
    const timestamp_ns: u64 = getCompletionTimestamp(queue, cq);

    // Get completion status
    const status: i32 = @intCast(cq.status);

    // Signal the waiting sender with the result
    queue.send_completion_timestamp.store(timestamp_ns, .release);
    queue.send_completion_status.store(status, .release);
    queue.send_completion_ready.store(true, .release);
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

/// Get the completion timestamp, using HW or SW source depending on queue config.
///
/// If the queue uses hardware timestamps, reads the wallclock nanosecond
/// timestamp from the extended CQ. Otherwise falls back to the system
/// monotonic clock.
fn getCompletionTimestamp(queue: *types.UdQueue, cq: *c.ibv_cq_ex) u64 {
    if (queue.uses_sw_timestamps) {
        // Software timestamp: use system clock as approximation
        const ts = std.time.nanoTimestamp();
        // nanoTimestamp returns i128; truncate to u64
        return @intCast(@as(u128, @bitCast(ts)) & 0xFFFFFFFFFFFFFFFF);
    } else {
        // Hardware timestamp: read from extended CQ
        return c.ibv_wc_read_completion_wallclock_ns(cq);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseGRH extracts source and dest GID" {
    // Construct a minimal 40-byte GRH
    var grh: [40]u8 = [_]u8{0} ** 40;

    // Version=6, TC=0, Flow Label=0x12345
    // First 4 bytes: 0110 0000 | 0000 0001 | 0010 0011 | 0100 0101
    grh[0] = 0x60; // version=6, tc high=0
    grh[1] = 0x01; // tc low=0, flow label high=1
    grh[2] = 0x23; // flow label mid
    grh[3] = 0x45; // flow label low

    // Source GID: fe80::1 (bytes 8-23)
    grh[8] = 0xfe;
    grh[9] = 0x80;
    grh[23] = 0x01;

    // Dest GID: fe80::2 (bytes 24-39)
    grh[24] = 0xfe;
    grh[25] = 0x80;
    grh[39] = 0x02;

    const info = parseGRH(&grh);

    // Check flow label (lower 20 bits of 0x60012345 = 0x12345)
    try std.testing.expectEqual(@as(u32, 0x12345), info.flow_label);

    // Check source GID
    try std.testing.expectEqual(@as(u8, 0xfe), info.source_gid[0]);
    try std.testing.expectEqual(@as(u8, 0x80), info.source_gid[1]);
    try std.testing.expectEqual(@as(u8, 0x01), info.source_gid[15]);

    // Check dest GID
    try std.testing.expectEqual(@as(u8, 0xfe), info.dest_gid[0]);
    try std.testing.expectEqual(@as(u8, 0x80), info.dest_gid[1]);
    try std.testing.expectEqual(@as(u8, 0x02), info.dest_gid[15]);
}

test "parseGRH flow label zero" {
    var grh: [40]u8 = [_]u8{0} ** 40;
    grh[0] = 0x60; // version=6

    const info = parseGRH(&grh);
    try std.testing.expectEqual(@as(u32, 0), info.flow_label);
}

test "parseGRH flow label max (20 bits)" {
    var grh: [40]u8 = [_]u8{0} ** 40;
    // Flow label = 0xFFFFF (20 bits all set)
    // First 4 bytes: 0110 0000 | 0000 1111 | 1111 1111 | 1111 1111
    grh[0] = 0x60;
    grh[1] = 0x0F;
    grh[2] = 0xFF;
    grh[3] = 0xFF;

    const info = parseGRH(&grh);
    try std.testing.expectEqual(@as(u32, 0xFFFFF), info.flow_label);
}

test "readBigEndianU64 correctness" {
    const buf = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A };
    try std.testing.expectEqual(@as(u64, 42), readBigEndianU64(&buf, 0));

    const buf2 = [_]u8{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(@as(u64, 1 << 56), readBigEndianU64(&buf2, 0));

    const buf3 = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFF), readBigEndianU64(&buf3, 0));
}

test "parseProbePayload extracts fields" {
    var payload: [40]u8 = [_]u8{0} ** 40;

    // sequence_num = 1 (bytes 0-7, big-endian)
    payload[7] = 0x01;

    // t1 = 1000 (bytes 8-15)
    payload[14] = 0x03;
    payload[15] = 0xE8;

    // is_ack = 1 (byte 32)
    payload[32] = 1;

    // ack_type = 2 (byte 33)
    payload[33] = 2;

    const parsed = parseProbePayload(&payload);
    try std.testing.expectEqual(@as(u64, 1), parsed.sequence_num);
    try std.testing.expectEqual(@as(u64, 1000), parsed.t1);
    try std.testing.expectEqual(@as(u64, 0), parsed.t3);
    try std.testing.expectEqual(@as(u64, 0), parsed.t4);
    try std.testing.expectEqual(@as(u8, 1), parsed.is_ack);
    try std.testing.expectEqual(@as(u8, 2), parsed.ack_type);
}

test "GRHInfo struct has expected fields" {
    const info = GRHInfo{
        .source_gid = [_]u8{0} ** 16,
        .dest_gid = [_]u8{0} ** 16,
        .flow_label = 0,
    };
    try std.testing.expectEqual(@as(u32, 0), info.flow_label);
    try std.testing.expectEqual(@as(usize, 16), info.source_gid.len);
    try std.testing.expectEqual(@as(usize, 16), info.dest_gid.len);
}
