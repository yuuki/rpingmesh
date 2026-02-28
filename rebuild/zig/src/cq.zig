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
/// Standard GRH layout (IPv6 header format, used for native InfiniBand):
///   Bytes 0-3:   Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits)
///   Bytes 4-5:   Payload Length
///   Byte  6:     Next Header
///   Byte  7:     Hop Limit
///   Bytes 8-23:  Source GID (128 bits)
///   Bytes 24-39: Destination GID (128 bits)
///
/// rdma_rxe IPv4 GRH format (Linux soft-RoCE for RoCEv2 over IPv4):
///   Bytes 0-19:  All zeros (the synthesized GRH header fields are zeroed)
///   Bytes 20-39: IPv4 header (20 bytes)
///     - Bytes 20-23: IP version/IHL/DSCP/ECN/total_length (first nibble = 0x4)
///     - Bytes 32-35: Source IPv4 address
///     - Bytes 36-39: Destination IPv4 address
///
/// This function detects the rdma_rxe IPv4 format by checking whether bytes 0-7
/// are all zero AND byte 20 has an IPv4 version nibble (0x4x). In that case it
/// constructs IPv4-mapped IPv6 GIDs (::ffff:a.b.c.d) from the embedded IP header.
pub fn parseGRH(buf: [*]const u8) GRHInfo {
    // Detect rdma_rxe IPv4 "GRH": bytes 0-7 all zero AND byte 20 is IPv4 (0x4x).
    const is_rxe_ipv4 = (buf[0] == 0 and buf[1] == 0 and buf[2] == 0 and buf[3] == 0 and
        buf[4] == 0 and buf[5] == 0 and buf[6] == 0 and buf[7] == 0 and
        (buf[20] & 0xF0) == 0x40);

    if (is_rxe_ipv4) {
        // IPv4 header is at buf[20..39].
        // Source IP at buf[32..35] (IPv4 header offset 12).
        // Dest   IP at buf[36..39] (IPv4 header offset 16).
        // Construct IPv4-mapped IPv6 GIDs: ::ffff:a.b.c.d
        var source_gid = [_]u8{0} ** 16;
        source_gid[10] = 0xff;
        source_gid[11] = 0xff;
        source_gid[12] = buf[32];
        source_gid[13] = buf[33];
        source_gid[14] = buf[34];
        source_gid[15] = buf[35];

        var dest_gid = [_]u8{0} ** 16;
        dest_gid[10] = 0xff;
        dest_gid[11] = 0xff;
        dest_gid[12] = buf[36];
        dest_gid[13] = buf[37];
        dest_gid[14] = buf[38];
        dest_gid[15] = buf[39];

        return GRHInfo{
            .source_gid = source_gid,
            .dest_gid = dest_gid,
            .flow_label = 0, // IPv4 has no flow label
        };
    }

    // Standard IPv6-format GRH.
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
/// Wire format (40 bytes, matching packet.zig serializeProbePacket):
///   Byte  0:     version (u8)
///   Byte  1:     msg_type (u8) — 0=probe, 1=ack
///   Byte  2:     ack_type (u8) — 0=N/A, 1=first, 2=second
///   Byte  3:     flags (u8)
///   Bytes 4-11:  sequence_num (u64, big-endian)
///   Bytes 12-19: t1 (u64, big-endian)
///   Bytes 20-27: t3 (u64, big-endian)
///   Bytes 28-35: t4 (u64, big-endian)
///   Bytes 36-39: reserved (zero)
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
/// Reads fields at the correct wire format offsets (see ProbePayload comment above).
fn parseProbePayload(buf: [*]const u8) ProbePayload {
    return ProbePayload{
        .sequence_num = readBigEndianU64(buf, 4),  // offset 4: after 4-byte header
        .t1 = readBigEndianU64(buf, 12),            // offset 12
        .t3 = readBigEndianU64(buf, 20),            // offset 20
        .t4 = readBigEndianU64(buf, 28),            // offset 28
        .is_ack = buf[1],                            // msg_type: 0=probe, 1=ack
        .ack_type = buf[2],                          // ack_type: 0=none, 1=first, 2=second
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
/// Sets queue.running to false and joins the thread. The thread exits
/// naturally after its next sleep cycle (at most ~50 microseconds).
pub fn stopCqPollerThread(queue: *types.UdQueue) void {
    queue.running.store(false, .release);

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
/// Uses busy polling (no ibv_get_cq_event) for reliability across different
/// RDMA implementations and environments (including soft-RoCE in containers).
/// Polls the CQ every ~50 microseconds and sleeps briefly between polls to
/// avoid burning the CPU.
///
/// The loop continues until queue.running is set to false.
fn cqPollerLoop(queue: *types.UdQueue) void {
    std.debug.print("[CQ_POLLER] thread started for queue @{x}\n", .{@intFromPtr(queue)});
    var iter: u64 = 0;
    while (queue.running.load(.acquire)) {
        // Poll recv CQ (handles both IBV_WC_RECV and IBV_WC_SEND opcodes
        // since we use a single shared CQ for both directions)
        pollCqCompletions(queue, queue.recv_cq);

        // Also poll the send CQ if it is separate from recv CQ
        if (queue.send_cq != queue.recv_cq) {
            pollCqCompletions(queue, queue.send_cq);
        }

        iter += 1;
        // Print alive message every 10000 iterations (~0.5s) for debugging
        if (iter % 10000 == 0) {
            std.debug.print("[CQ_POLLER] @{x} alive iter={d}\n", .{ @intFromPtr(queue), iter });
        }

        // Sleep briefly between polls to reduce CPU usage.
        // 50 microseconds gives good responsiveness while staying efficient.
        std.Thread.sleep(50_000);
    }
    std.debug.print("[CQ_POLLER] @{x} exiting after {d} iters\n", .{ @intFromPtr(queue), iter });
}

/// Poll a single CQ for all available completions.
///
/// Dispatches to one of two implementations based on whether the queue uses
/// software timestamps (rdma_rxe / no HW wallclock) or hardware timestamps.
///
/// For software timestamp mode (uses_sw_timestamps == true), the classic
/// ibv_poll_cq() API is used.  Some rdma_rxe versions do not properly
/// consume completions through ibv_end_poll(), causing the extended poll API
/// to re-deliver the same completion on every subsequent ibv_start_poll()
/// call.  ibv_poll_cq() does not have this issue.
///
/// For hardware timestamp mode, the extended API (ibv_start_poll /
/// ibv_next_poll / ibv_end_poll) is used so that wallclock timestamps can be
/// read via ibv_wc_read_completion_wallclock_ns().
fn pollCqCompletions(queue: *types.UdQueue, cq: *c.ibv_cq_ex) void {
    if (queue.uses_sw_timestamps) {
        pollCqClassic(queue, cq);
        return;
    }
    pollCqExtended(queue, cq);
}

/// Classic CQ polling using ibv_poll_cq().
///
/// Converts the extended CQ handle to a base CQ, calls ibv_poll_cq() to
/// drain up to 32 completions at once, and dispatches each to
/// dispatchClassicWc().
fn pollCqClassic(queue: *types.UdQueue, cq: *c.ibv_cq_ex) void {
    const base_cq = c.ibv_cq_ex_to_cq(cq) orelse return;
    var wc_buf: [32]c.ibv_wc = undefined;
    const n = c.ibv_poll_cq(base_cq, 32, &wc_buf[0]);
    if (n <= 0) return;
    var i: usize = 0;
    while (i < @as(usize, @intCast(n))) : (i += 1) {
        dispatchClassicWc(queue, &wc_buf[i]);
    }
}

/// Dispatch a classic ibv_wc completion to the appropriate handler.
fn dispatchClassicWc(queue: *types.UdQueue, wc: *const c.ibv_wc) void {
    const status_int: i32 = @intCast(wc.status);
    if (wc.opcode == c.IBV_WC_SEND) {
        std.debug.print("[CQ_DISPATCH] @{x} SEND (classic) status={d}\n", .{ @intFromPtr(queue), status_int });
        // Signal the waiting sender thread with a SW timestamp.
        const ts = swTimestampNs();
        queue.send_completion_timestamp.store(ts, .release);
        queue.send_completion_status.store(status_int, .release);
        queue.send_completion_ready.store(true, .release);
    } else if (wc.opcode == c.IBV_WC_RECV) {
        std.debug.print("[CQ_DISPATCH] @{x} RECV (classic) status={d}\n", .{ @intFromPtr(queue), status_int });
        if (wc.status == c.IBV_WC_SUCCESS) {
            processRecvClassic(queue, wc);
        }
    } else {
        std.debug.print("[CQ_DISPATCH] @{x} unknown opcode (classic) status={d}\n", .{ @intFromPtr(queue), status_int });
    }
}

/// Process a receive completion from the classic ibv_wc path.
///
/// Mirrors processRecvCompletion() but reads fields directly from ibv_wc
/// instead of the extended CQ handle.
fn processRecvClassic(queue: *types.UdQueue, wc: *const c.ibv_wc) void {
    const slot_index: u32 = @intCast(wc.wr_id & 0xFFFFFFFF);
    const ts = swTimestampNs();
    const src_qp: u32 = wc.src_qp;

    const slot_ptr = memory.getSlotPtr(queue.recv_buf, slot_index, types.NUM_RECV_SLOTS) catch return;
    const grh_info = parseGRH(slot_ptr);
    const payload_ptr = slot_ptr + types.GRH_SIZE;
    const payload = parseProbePayload(payload_ptr);

    const event = ring.CompletionEvent{
        .sequence_num = payload.sequence_num,
        .t1 = payload.t1,
        .t3 = payload.t3,
        .t4 = payload.t4,
        .is_ack = payload.is_ack,
        .ack_type = payload.ack_type,
        .flags = 0,
        ._pad = 0,
        .timestamp_ns = ts,
        .source_gid = grh_info.source_gid,
        .source_qpn = src_qp,
        .flow_label = grh_info.flow_label,
        .status = @intCast(wc.status),
        .is_send = 0,
        ._pad2 = [_]u8{ 0, 0, 0 },
    };

    if (queue.event_ring) |event_ring| {
        _ = event_ring.push(&event);
    }

    memory.postRecvBuffer(queue.qp, queue.recv_mr, queue.recv_buf, slot_index) catch {};
}

/// Extended CQ polling using ibv_start_poll / ibv_next_poll / ibv_end_poll.
///
/// Used only when the device supports hardware wallclock timestamps
/// (uses_sw_timestamps == false).
fn pollCqExtended(queue: *types.UdQueue, cq: *c.ibv_cq_ex) void {
    var poll_attr = std.mem.zeroes(c.ibv_poll_cq_attr);

    const ret_start = c.ibv_start_poll(cq, &poll_attr);
    if (ret_start != 0) {
        // ENOENT means no completions available - this is normal
        return;
    }

    // Process the first completion
    dispatchCompletion(queue, cq);

    // Process remaining completions
    while (c.ibv_next_poll(cq) == 0) {
        dispatchCompletion(queue, cq);
    }

    c.ibv_end_poll(cq);
}

/// Return the current monotonic clock time in nanoseconds (software fallback).
fn swTimestampNs() u64 {
    const ts = std.time.nanoTimestamp();
    return @intCast(@as(u128, @bitCast(ts)) & 0xFFFFFFFFFFFFFFFF);
}

/// Dispatch a single work completion to the appropriate handler.
///
/// Routes by opcode (IBV_WC_SEND or IBV_WC_RECV). For send completions,
/// always signals the waiting sender thread (even on error) so it does
/// not spin-wait indefinitely. For recv completions, only pushes to the
/// ring on success.
fn dispatchCompletion(queue: *types.UdQueue, cq: *c.ibv_cq_ex) void {
    const opcode = c.ibv_wc_read_opcode(cq);
    const status: i32 = @intCast(cq.status);

    if (opcode == c.IBV_WC_SEND) {
        std.debug.print("[CQ_DISPATCH] @{x} SEND completion status={d}\n", .{ @intFromPtr(queue), status });
        // Always signal the sender, regardless of status, so waitSendCompletion
        // can report the error rather than timing out.
        processSendCompletion(queue, cq);
    } else if (opcode == c.IBV_WC_RECV) {
        std.debug.print("[CQ_DISPATCH] @{x} RECV completion status={d}\n", .{ @intFromPtr(queue), status });
        if (status == c.IBV_WC_SUCCESS) {
            processRecvCompletion(queue, cq);
        }
        // Recv errors: buffer slot is effectively lost until queue recreation.
        // For the test scenario this is acceptable.
    } else {
        std.debug.print("[CQ_DISPATCH] @{x} unknown opcode, status={d}\n", .{ @intFromPtr(queue), status });
    }
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
