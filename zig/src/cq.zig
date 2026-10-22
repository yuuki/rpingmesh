// cq.zig - CQ polling thread and completion processing.
//
// This module implements the dedicated CQ poller thread that runs per queue.
// The poller is event-driven: it arms the CQ (ibv_req_notify_cq), drains it,
// and then sleeps in poll() on the queue's completion channel until the
// hardware raises the next completion event. An idle agent therefore costs
// no CPU here, and a completion is handled one interrupt/wakeup after it
// lands instead of up to one sleep interval later.
//
// If the provider cannot create a completion channel or arm the CQ, the
// poller falls back to busy polling with a ~50 microsecond sleep between
// polls (the pre-event-driven behavior), which costs ~1% of a CPU per queue.
//
// For receive completions, the poller parses the GRH and probe payload, builds
// a CompletionEvent, and pushes it into the SPSC ring buffer for consumption
// by the Go side. After each drained batch that produced events it signals
// the ring's eventfd so the Go consumer can sleep instead of polling.
//
// For send completions, the poller extracts the timestamp and either signals
// the waiting sender thread via atomic variables on the UdQueue struct
// (synchronous sends), or, for the first ACK of an asynchronous ACK pair,
// writes the timestamp as T4 into the second ACK staged in the same send slot
// and posts it (see types.SendSlotMode and packet.zig sendAckPair).

const std = @import("std");
const types = @import("types.zig");
const wire = @import("wire.zig");
const ring = @import("ring.zig");
const memory = @import("memory.zig");
const c = types.c;

/// Scoped logger for CQ poller diagnostics. These are std.log.debug calls
/// (not std.debug.print), so by default (ReleaseSafe/ReleaseFast/ReleaseSmall,
/// which use log level .info) they compile out entirely -- logEnabled() is
/// evaluated at comptime, so there is zero per-completion runtime cost in
/// production builds. Only Debug builds (log level .debug) emit them.
const log = std.log.scoped(.cq_poller);

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
        var source_gid: [16]u8 = @splat(0);
        source_gid[10] = 0xff;
        source_gid[11] = 0xff;
        source_gid[12] = buf[32];
        source_gid[13] = buf[33];
        source_gid[14] = buf[34];
        source_gid[15] = buf[35];

        var dest_gid: [16]u8 = @splat(0);
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
// Receive sanity checks
// ---------------------------------------------------------------------------

/// True when the UD completion is long enough to hold a GRH plus a full
/// 40-byte probe payload. Short completions can still succeed with the
/// configured QKEY; reading past byte_len would interpret stale slot bytes.
fn recvByteLenOK(byte_len: u32) bool {
    return byte_len >= types.GRH_SIZE + types.PROBE_PACKET_SIZE;
}

/// Return a recv slot to the hardware. Every recv completion, delivered or
/// dropped, ends here; a slot that cannot be reposted is lost until the
/// queue is recreated.
fn repostRecv(queue: *types.UdQueue, slot_index: u32) void {
    memory.postRecvBuffer(queue.qp, queue.recv_bufs.mr, queue.recv_bufs.buf, slot_index) catch {
        log.warn("@{x} failed to repost recv slot={d}", .{ @intFromPtr(queue), slot_index });
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
/// Sets queue.running to false, wakes the poller out of poll() through
/// wake_fd, and joins the thread. Without a wake_fd the event-mode poller
/// still exits within CQ_EVENT_WAIT_TIMEOUT_MS; the busy-poll fallback exits
/// after its next ~50 microsecond sleep.
pub fn stopCqPollerThread(queue: *types.UdQueue) void {
    queue.running.store(false, .release);
    if (queue.wake_fd >= 0) {
        const one: u64 = 1;
        _ = c.write(queue.wake_fd, &one, @sizeOf(u64));
    }

    if (queue.cq_thread) |thread| {
        thread.join();
        queue.cq_thread = null;
    }
}

// ---------------------------------------------------------------------------
// CQ poller loop (thread entry point)
// ---------------------------------------------------------------------------

/// Upper bound on one poll() sleep in event mode. Completions never wait for
/// this timeout -- they wake the poller through the completion channel. It
/// is a safety net: if a provider ever failed to raise an event for an armed
/// CQ, the poller still re-arms and drains the CQ this often. 100 ms keeps
/// that cost at 10 wakeups/s per queue while bounding the damage well under
/// the 1 s send/ACK timeouts used by the Go side.
const CQ_EVENT_WAIT_TIMEOUT_MS: c_int = 100;

/// Sleep between polls in the busy-poll fallback.
const BUSY_POLL_SLEEP_NS: c_long = 50_000;

/// Main loop for the CQ poller thread.
///
/// Runs the event-driven loop when the queue has a usable completion
/// channel, otherwise the busy-poll fallback. Either loop continues until
/// queue.running is set to false.
fn cqPollerLoop(queue: *types.UdQueue) void {
    log.debug("thread started for queue @{x} (cq_events={})", .{ @intFromPtr(queue), queue.uses_cq_events });
    if (queue.uses_cq_events) {
        eventPollerLoop(queue);
    }
    // Event mode returns early only when re-arming failed; finish the
    // queue's lifetime in busy-poll mode so completions keep flowing.
    if (queue.running.load(.acquire)) {
        busyPollerLoop(queue);
    }
    log.debug("@{x} exiting", .{@intFromPtr(queue)});
}

/// Event-driven poller loop.
///
/// Each iteration arms the CQ BEFORE draining it. Any completion that lands
/// after the arm -- including one racing with the final empty poll --
/// raises a channel event, so the poll() below cannot sleep through it (no
/// lost wakeup). Completions that arrived before the arm are drained here
/// and may also produce one spurious event, which costs a single extra
/// wakeup that finds the CQ empty.
///
/// Returns when queue.running becomes false, or (after clearing
/// queue.uses_cq_events) when the provider refuses to re-arm the CQ.
fn eventPollerLoop(queue: *types.UdQueue) void {
    const base_cq = c.ibv_cq_ex_to_cq(queue.cq) orelse {
        queue.uses_cq_events = false;
        return;
    };
    const channel = queue.comp_channel orelse {
        queue.uses_cq_events = false;
        return;
    };

    while (queue.running.load(.acquire)) {
        if (c.ibv_req_notify_cq(base_cq, 0) != 0) {
            log.warn("@{x} ibv_req_notify_cq failed; falling back to busy polling", .{@intFromPtr(queue)});
            queue.uses_cq_events = false;
            return;
        }

        drainCq(queue);

        waitForCqEvent(queue, channel);
    }
}

/// Sleep until the CQ raises a completion event, the shutdown eventfd is
/// written, or CQ_EVENT_WAIT_TIMEOUT_MS elapses. A consumed CQ event is
/// acknowledged immediately so ibv_destroy_cq() never blocks on unacked
/// events at teardown.
fn waitForCqEvent(queue: *types.UdQueue, channel: *c.ibv_comp_channel) void {
    var fds = [2]c.struct_pollfd{
        .{ .fd = channel.fd, .events = c.POLLIN, .revents = 0 },
        // A negative fd is ignored by poll(), so a missing wake_fd only
        // delays shutdown until the timeout.
        .{ .fd = queue.wake_fd, .events = c.POLLIN, .revents = 0 },
    };
    const ready = c.poll(&fds, fds.len, CQ_EVENT_WAIT_TIMEOUT_MS);
    if (ready <= 0) {
        // Timeout or EINTR: the caller re-arms and drains, which is always
        // safe.
        return;
    }
    if ((fds[0].revents & c.POLLIN) != 0) {
        var ev_cq: ?*c.ibv_cq = null;
        var ev_ctx: ?*anyopaque = null;
        // The channel fd is non-blocking (queue.zig createCompChannel), so a
        // spurious readiness returns -1/EAGAIN instead of blocking.
        if (c.ibv_get_cq_event(channel, &ev_cq, &ev_ctx) == 0) {
            if (ev_cq) |cq_ptr| c.ibv_ack_cq_events(cq_ptr, 1);
        }
    }
}

/// Drain every available completion from the queue's CQ, then wake the
/// Go consumer once if any event was pushed into the ring.
///
/// The notification is sent in busy mode too: a queue that started in event
/// mode and fell back at runtime still has a Go consumer blocked on the
/// eventfd, and the write costs one syscall per batch, not per poll.
fn drainCq(queue: *types.UdQueue) void {
    const produced_before: u64 = if (queue.event_ring) |r| r.producedCount() else 0;
    while (pollCqCompletions(queue, queue.cq) != 0) {}
    if (queue.event_ring) |r| {
        if (r.producedCount() != produced_before) r.notify();
    }
}

/// Busy-poll fallback loop, used when CQ events are unavailable.
///
/// Polls the CQ, then sleeps ~50 microseconds. Costs roughly 1% of a CPU
/// per queue even when idle, which is why event mode is preferred.
fn busyPollerLoop(queue: *types.UdQueue) void {
    while (queue.running.load(.acquire)) {
        drainCq(queue);

        // libc nanosleep: std.Thread.sleep was removed in Zig 0.16 (sleeping
        // now goes through std.Io, which this C-ABI library does not carry).
        const req: types.c.struct_timespec = .{ .tv_sec = 0, .tv_nsec = BUSY_POLL_SLEEP_NS };
        _ = types.c.nanosleep(&req, null);
    }
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
///
/// Returns the number of work completions consumed (0 when the CQ is empty).
fn pollCqCompletions(queue: *types.UdQueue, cq: *c.ibv_cq_ex) usize {
    var pending = PendingSecondAcks{};
    const n = if (queue.uses_sw_timestamps)
        pollCqClassic(queue, cq, &pending)
    else
        pollCqExtended(queue, cq, &pending);
    // Post the second ACKs only after the poll session has ended
    // (ibv_end_poll in the extended path), so no send is posted while the
    // provider is in the middle of iterating the CQ.
    flushPendingSecondAcks(queue, &pending);
    return n;
}

// ---------------------------------------------------------------------------
// Asynchronous ACK pairs
// ---------------------------------------------------------------------------

/// Second ACKs whose first ACK completed during one CQ poll, waiting to be
/// posted once the poll ends. A slot has at most one WR in flight and its
/// second ACK is posted only by the flush, so a slot appears at most once
/// and NUM_SEND_SLOTS entries always suffice.
pub const PendingSecondAcks = struct {
    slots: [types.NUM_SEND_SLOTS]u32 = undefined,
    t4_ns: [types.NUM_SEND_SLOTS]u64 = undefined,
    len: usize = 0,

    /// Queue slot's second ACK with T4 = t4_ns. Returns false when full,
    /// which the invariant above rules out; the caller then fails the pair.
    pub fn add(self: *PendingSecondAcks, slot: u32, t4_ns: u64) bool {
        if (self.len >= self.slots.len) return false;
        self.slots[self.len] = slot;
        self.t4_ns[self.len] = t4_ns;
        self.len += 1;
        return true;
    }
};

/// Write t4_ns into the T4 field of the second ACK staged in a send slot.
pub fn stampStagedSecondAck(slot_ptr: [*]u8, t4_ns: u64) void {
    wire.writeT4(@ptrCast(slot_ptr + types.SECOND_ACK_SLOT_OFFSET), t4_ns);
}

/// Post every queued second ACK: stamp T4, switch the slot to
/// AsyncSecondAck and post the staged packet on the slot's AH. A pair whose
/// second ACK cannot be posted is counted as failed and its slot reclaimed.
fn flushPendingSecondAcks(queue: *types.UdQueue, pending: *const PendingSecondAcks) void {
    for (pending.slots[0..pending.len], pending.t4_ns[0..pending.len]) |slot, t4_ns| {
        const slot_ptr = memory.getSlotPtr(queue.send_bufs.buf, slot, types.NUM_SEND_SLOTS) catch {
            failAsyncAck(queue, slot);
            continue;
        };
        const ah = queue.sendSlotAh(slot) orelse {
            failAsyncAck(queue, slot);
            continue;
        };
        stampStagedSecondAck(slot_ptr, t4_ns);
        queue.setSendSlotMode(slot, .AsyncSecondAck);
        memory.postUdSend(
            queue.qp,
            queue.send_bufs.mr,
            slot_ptr + types.SECOND_ACK_SLOT_OFFSET,
            slot,
            ah,
            queue.send_slot_remote_qpn[slot],
        ) catch {
            log.debug("@{x} failed to post second ACK on slot={d}", .{ @intFromPtr(queue), slot });
            failAsyncAck(queue, slot);
        };
    }
}

/// Count a failed asynchronous ACK pair and release its slot and AH.
fn failAsyncAck(queue: *types.UdQueue, slot: u32) void {
    _ = queue.async_ack_failures.fetchAdd(1, .monotonic);
    queue.releaseSendSlot(slot);
}

/// Maximum completions consumed by one poll session (classic ibv_poll_cq call
/// or extended start/next/end sequence). Bounding it lets pollCqCompletions
/// post the second ACKs queued during the session promptly under sustained
/// load, instead of only once the CQ runs empty.
const MAX_POLL_BATCH = 32;

/// Classic CQ polling using ibv_poll_cq().
///
/// Converts the extended CQ handle to a base CQ, calls ibv_poll_cq() to
/// drain up to 32 completions at once, and dispatches each to
/// dispatchClassicWc().
fn pollCqClassic(queue: *types.UdQueue, cq: *c.ibv_cq_ex, pending: *PendingSecondAcks) usize {
    const base_cq = c.ibv_cq_ex_to_cq(cq) orelse return 0;
    var wc_buf: [MAX_POLL_BATCH]c.ibv_wc = undefined;
    const n = c.ibv_poll_cq(base_cq, MAX_POLL_BATCH, &wc_buf[0]);
    if (n <= 0) return 0;
    const count: usize = @intCast(n);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        dispatchClassicWc(queue, &wc_buf[i], pending);
    }
    return count;
}

/// Dispatch a classic ibv_wc completion to the appropriate handler.
///
/// Completions are classified by wr_id (types.isSendWrId), never by opcode:
/// libibverbs leaves wc.opcode undefined unless status == IBV_WC_SUCCESS, so
/// a flushed or errored CQE must still reach signalSendCompletion (which
/// fails a synchronous sender fast and reclaims an asynchronous ACK pair's
/// slot) or the recv repost path.
fn dispatchClassicWc(queue: *types.UdQueue, wc: *const c.ibv_wc, pending: *PendingSecondAcks) void {
    const status: i32 = @intCast(wc.status);
    if (types.isSendWrId(wc.wr_id)) {
        log.debug("@{x} SEND (classic) status={d}", .{ @intFromPtr(queue), status });
        signalSendCompletion(queue, wc.wr_id, swTimestampNs(), status, pending);
    } else if (wc.status == c.IBV_WC_SUCCESS) {
        log.debug("@{x} RECV (classic) status={d}", .{ @intFromPtr(queue), status });
        processRecvClassic(queue, wc);
    } else {
        repostFailedRecv(queue, wc.wr_id, status);
    }
}

/// Repost the slot of a failed recv completion (e.g. IBV_WC_WR_FLUSH_ERR on
/// teardown, or a transient link error). The completion still owns one of
/// NUM_RECV_SLOTS; without the repost that slot is lost until the queue is
/// recreated, and repeated errors would starve the recv queue.
fn repostFailedRecv(queue: *types.UdQueue, wr_id: u64, status: i32) void {
    const slot_index = types.wrIdSlot(wr_id);
    log.warn("@{x} RECV completion error status={d}, reposting slot={d}", .{ @intFromPtr(queue), status, slot_index });
    repostRecv(queue, slot_index);
}

/// Process a successful receive completion from the classic ibv_wc path.
fn processRecvClassic(queue: *types.UdQueue, wc: *const c.ibv_wc) void {
    deliverRecv(queue, .{
        .slot_index = types.wrIdSlot(wc.wr_id),
        .timestamp_ns = swTimestampNs(),
        .src_qp = wc.src_qp,
        .has_grh = (wc.wc_flags & c.IBV_WC_GRH) != 0,
        .byte_len = wc.byte_len,
    });
}

/// Extended CQ polling using ibv_start_poll / ibv_next_poll / ibv_end_poll.
///
/// Used only when the device supports hardware wallclock timestamps
/// (uses_sw_timestamps == false).
fn pollCqExtended(queue: *types.UdQueue, cq: *c.ibv_cq_ex, pending: *PendingSecondAcks) usize {
    var poll_attr = std.mem.zeroes(c.ibv_poll_cq_attr);

    const ret_start = c.ibv_start_poll(cq, &poll_attr);
    if (ret_start != 0) {
        // ENOENT means no completions available - this is normal
        return 0;
    }

    // Process the first completion
    dispatchCompletion(queue, cq, pending);
    var count: usize = 1;

    // Process remaining completions, at most MAX_POLL_BATCH per poll
    // session: the session must end (and the queued second ACKs be posted)
    // even if completions keep arriving faster than they are drained.
    // drainCq() polls again until the CQ is empty.
    while (count < MAX_POLL_BATCH and c.ibv_next_poll(cq) == 0) {
        dispatchCompletion(queue, cq, pending);
        count += 1;
    }

    c.ibv_end_poll(cq);
    return count;
}

/// Return the current monotonic clock time in nanoseconds (software fallback).
///
/// Delegates to the shared `types.monotonicNs()` helper, which uses true
/// CLOCK_MONOTONIC (not `std.time.nanoTimestamp()`, which was CLOCK_REALTIME
/// in Zig 0.15.x) so that SW-fallback T2/T3/T4/T5 stay in the same clock
/// domain as T1 (`packet.zig`) and the Go side's T6.
fn swTimestampNs() u64 {
    return types.monotonicNs();
}

/// Dispatch a single extended-CQ work completion to the appropriate handler.
/// Classified by wr_id for the same reason as dispatchClassicWc.
fn dispatchCompletion(queue: *types.UdQueue, cq: *c.ibv_cq_ex, pending: *PendingSecondAcks) void {
    const status: i32 = @intCast(cq.status);
    if (types.isSendWrId(cq.wr_id)) {
        log.debug("@{x} SEND completion status={d}", .{ @intFromPtr(queue), status });
        processSendCompletion(queue, cq, pending);
    } else if (status == c.IBV_WC_SUCCESS) {
        log.debug("@{x} RECV completion status={d}", .{ @intFromPtr(queue), status });
        processRecvCompletion(queue, cq);
    } else {
        repostFailedRecv(queue, cq.wr_id, status);
    }
}

// ---------------------------------------------------------------------------
// Receive completion processing
// ---------------------------------------------------------------------------

/// Process a successful receive completion from the extended CQ path.
///
/// src_qp and byte_len are CQE fields requested at CQ creation
/// (IBV_WC_EX_WITH_SRC_QP / _BYTE_LEN); wc_flags is a core field that
/// ibv_wc_read_wc_flags() reads unconditionally.
fn processRecvCompletion(queue: *types.UdQueue, cq: *c.ibv_cq_ex) void {
    deliverRecv(queue, .{
        .slot_index = types.wrIdSlot(cq.wr_id),
        .timestamp_ns = getCompletionTimestamp(queue, cq),
        .src_qp = c.ibv_wc_read_src_qp(cq),
        .has_grh = (c.ibv_wc_read_wc_flags(cq) & c.IBV_WC_GRH) != 0,
        .byte_len = c.ibv_wc_read_byte_len(cq),
    });
}

/// The inputs of a successful recv completion that the classic and extended
/// CQ APIs expose differently. Everything after reading them is shared.
const RecvCompletion = struct {
    slot_index: u32,
    /// HW wallclock or SW CLOCK_MONOTONIC timestamp of the completion.
    timestamp_ns: u64,
    src_qp: u32,
    /// IBV_WC_GRH: the driver wrote a GRH into the slot. Without it the
    /// sender's GID is unknown.
    has_grh: bool,
    byte_len: u32,
};

/// Deliver a successful recv completion to Go: parse the GRH and the probe
/// payload, push a CompletionEvent into the event ring, and repost the slot.
/// A completion without a GRH, shorter than GRH + packet (the rest of the
/// slot would be stale bytes from an earlier recv) or with an unknown wire
/// version is dropped; its slot is reposted all the same.
fn deliverRecv(queue: *types.UdQueue, rc: RecvCompletion) void {
    const slot_ptr = memory.getSlotPtr(queue.recv_bufs.buf, rc.slot_index, types.NUM_RECV_SLOTS) catch return;
    defer repostRecv(queue, rc.slot_index);

    if (!rc.has_grh or !recvByteLenOK(rc.byte_len)) return;
    const grh_info = parseGRH(slot_ptr);
    const pkt = wire.deserializeProbePacket(@ptrCast(slot_ptr + types.GRH_SIZE)) orelse return;

    const event = recvEvent(&pkt, &grh_info, &rc);
    if (queue.event_ring) |event_ring| {
        _ = event_ring.push(&event);
    }
}

/// Build the event Go receives for a probe or ACK.
fn recvEvent(pkt: *const wire.ProbePacket, grh_info: *const GRHInfo, rc: *const RecvCompletion) ring.CompletionEvent {
    return ring.CompletionEvent{
        .sequence_num = pkt.sequence_num,
        .t1 = pkt.t1,
        .t3 = pkt.t3,
        .t4 = pkt.t4,
        .is_ack = pkt.msg_type,
        .ack_type = pkt.ack_type,
        .flags = 0,
        ._pad = 0,
        .timestamp_ns = rc.timestamp_ns,
        .source_gid = grh_info.source_gid,
        .source_qpn = rc.src_qp,
        .flow_label = grh_info.flow_label,
        .status = c.IBV_WC_SUCCESS,
        .is_send = 0,
        ._pad2 = [_]u8{ 0, 0, 0 },
    };
}

// ---------------------------------------------------------------------------
// Send completion processing
// ---------------------------------------------------------------------------

/// Process a single send completion (extended CQ path).
///
/// Extracts the timestamp, status, and wr_id from the completion and hands
/// them to signalSendCompletion().
pub fn processSendCompletion(queue: *types.UdQueue, cq: *c.ibv_cq_ex, pending: *PendingSecondAcks) void {
    const timestamp_ns: u64 = getCompletionTimestamp(queue, cq);
    const status: i32 = @intCast(cq.status);
    signalSendCompletion(queue, cq.wr_id, timestamp_ns, status, pending);
}

/// Handle a send completion according to its slot's SendSlotMode.
///
/// AsyncFirstAck: on success, queue the slot's staged second ACK with
/// T4 = timestamp_ns; the slot and AH stay allocated for it. On error, count
/// the pair as failed and reclaim the slot.
/// AsyncSecondAck: reclaim the slot (counting an error status as a failure).
/// Neither touches the mailbox, so asynchronous pairs never disturb a
/// synchronous waiter on the same queue.
/// Sync: free the completed send's slot and publish its result to the
/// waiting sender, as follows.
///
/// The slot is freed here (not by the sender) so that a late completion for a
/// timed-out send still returns its slot for reuse. The completed wr_id is
/// stored LAST with release ordering: the waiter in waitSendCompletion() spins
/// on send_completion_wr_id with acquire ordering, so it only observes the
/// timestamp/status once its own wr_id is published. See the mailbox invariant
/// comment in types.zig.
fn signalSendCompletion(queue: *types.UdQueue, wr_id: u64, timestamp_ns: u64, status: i32, pending: *PendingSecondAcks) void {
    const slot_index = types.wrIdSlot(wr_id);
    switch (queue.sendSlotMode(slot_index)) {
        .AsyncFirstAck => {
            if (status == 0 and pending.add(slot_index, timestamp_ns)) return;
            log.debug("@{x} first ACK completion status={d} on slot={d}", .{ @intFromPtr(queue), status, slot_index });
            failAsyncAck(queue, slot_index);
            return;
        },
        .AsyncSecondAck => {
            if (status != 0) {
                log.debug("@{x} second ACK completion status={d} on slot={d}", .{ @intFromPtr(queue), status, slot_index });
                _ = queue.async_ack_failures.fetchAdd(1, .monotonic);
            }
            queue.releaseSendSlot(slot_index);
            return;
        },
        .Sync => {},
    }
    // This is the matching completion for the posted WR, so the AH is no
    // longer referenced and the slot can be released.
    queue.releaseSendSlot(slot_index);

    queue.send_completion_timestamp.store(timestamp_ns, .monotonic);
    queue.send_completion_status.store(status, .monotonic);
    // Publish last: this release pairs with the sender's acquire load and makes
    // the timestamp/status above visible once the wr_id matches.
    queue.send_completion_wr_id.store(wr_id, .release);
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

/// Get the completion timestamp, using HW or SW source depending on queue config.
///
/// If the queue uses hardware timestamps, reads the wallclock nanosecond
/// timestamp from the extended CQ. Otherwise falls back to the shared
/// CLOCK_MONOTONIC helper (see `swTimestampNs`).
fn getCompletionTimestamp(queue: *types.UdQueue, cq: *c.ibv_cq_ex) u64 {
    if (queue.uses_sw_timestamps) {
        // Software timestamp: use CLOCK_MONOTONIC, same domain as T1 and
        // the Go side's T6.
        return swTimestampNs();
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
    var grh: [40]u8 = @splat(0);

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
    var grh: [40]u8 = @splat(0);
    grh[0] = 0x60; // version=6

    const info = parseGRH(&grh);
    try std.testing.expectEqual(@as(u32, 0), info.flow_label);
}

test "parseGRH flow label max (20 bits)" {
    var grh: [40]u8 = @splat(0);
    // Flow label = 0xFFFFF (20 bits all set)
    // First 4 bytes: 0110 0000 | 0000 1111 | 1111 1111 | 1111 1111
    grh[0] = 0x60;
    grh[1] = 0x0F;
    grh[2] = 0xFF;
    grh[3] = 0xFF;

    const info = parseGRH(&grh);
    try std.testing.expectEqual(@as(u32, 0xFFFFF), info.flow_label);
}

test "recvByteLenOK requires GRH plus probe payload" {
    const need: u32 = types.GRH_SIZE + types.PROBE_PACKET_SIZE;
    try std.testing.expect(!recvByteLenOK(need - 1));
    try std.testing.expect(recvByteLenOK(need));
    try std.testing.expect(recvByteLenOK(need + 16));
}

test "GRHInfo struct has expected fields" {
    const info = GRHInfo{
        .source_gid = @splat(0),
        .dest_gid = @splat(0),
        .flow_label = 0,
    };
    try std.testing.expectEqual(@as(u32, 0), info.flow_label);
    try std.testing.expectEqual(@as(usize, 16), info.source_gid.len);
    try std.testing.expectEqual(@as(usize, 16), info.dest_gid.len);
}

test "PendingSecondAcks holds one entry per send slot" {
    var pending = PendingSecondAcks{};
    var i: u32 = 0;
    while (i < types.NUM_SEND_SLOTS) : (i += 1) {
        try std.testing.expect(pending.add(i, 1000 + i));
    }
    try std.testing.expect(!pending.add(0, 1));
    try std.testing.expectEqual(@as(usize, types.NUM_SEND_SLOTS), pending.len);
    try std.testing.expectEqual(@as(u32, 3), pending.slots[3]);
    try std.testing.expectEqual(@as(u64, 1003), pending.t4_ns[3]);
}

test "stampStagedSecondAck writes T4 big-endian into the staged packet only" {
    var slot: [types.SLOT_SIZE]u8 = @splat(0xAA);
    stampStagedSecondAck(&slot, 0x0102030405060708);
    const at = types.SECOND_ACK_SLOT_OFFSET + wire.OFFSET_T4;
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), std.mem.readInt(u64, slot[at..][0..8], .big));
    // The first ACK and the rest of the staged packet are untouched.
    for (slot[0..at]) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
    for (slot[at + 8 ..]) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
}

/// A UdQueue for dispatch tests: every send slot free, no verbs objects.
/// Only paths that never touch qp/MRs may run on it (send-side bookkeeping;
/// destroySendSlotAh is a no-op while no AH is stored).
fn testQueue() types.UdQueue {
    var queue: types.UdQueue = undefined;
    queue.send_slot_ah = @splat(std.atomic.Value(usize).init(0));
    queue.send_slot_states = @splat(std.atomic.Value(u8).init(@backingInt(types.SlotState.Free)));
    queue.send_slot_modes = @splat(std.atomic.Value(u8).init(@backingInt(types.SendSlotMode.Sync)));
    queue.send_slot_remote_qpn = @splat(0);
    queue.async_ack_failures = std.atomic.Value(u64).init(0);
    queue.send_completion_wr_id = std.atomic.Value(u64).init(types.SEND_WR_ID_NONE);
    queue.send_completion_timestamp = std.atomic.Value(u64).init(0);
    queue.send_completion_status = std.atomic.Value(i32).init(0);
    return queue;
}

fn slotState(queue: *types.UdQueue, slot: u32) types.SlotState {
    return @fromBackingInt(queue.send_slot_states[slot].load(.acquire));
}

test "an errored send completion with an unset opcode still reaches the mailbox" {
    var queue = testQueue();
    const slot = queue.allocSendSlot() orelse return error.TestUnexpectedResult;
    queue.setSendSlotMode(slot, .Sync);

    var wc = std.mem.zeroes(c.ibv_wc);
    wc.wr_id = types.sendWrId(slot);
    wc.status = c.IBV_WC_WR_FLUSH_ERR;
    // The provider leaves opcode undefined on error; make it the value that
    // would misroute the completion if the dispatcher looked at it.
    wc.opcode = c.IBV_WC_RECV;
    var pending = PendingSecondAcks{};
    dispatchClassicWc(&queue, &wc, &pending);

    try std.testing.expectEqual(types.SlotState.Free, slotState(&queue, slot));
    try std.testing.expectEqual(wc.wr_id, queue.send_completion_wr_id.load(.acquire));
    try std.testing.expectEqual(@as(i32, @intCast(c.IBV_WC_WR_FLUSH_ERR)), queue.send_completion_status.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), pending.len);
}

test "an errored first-ACK completion fails the pair and reclaims its slot" {
    var queue = testQueue();
    const slot = queue.allocSendSlot() orelse return error.TestUnexpectedResult;
    queue.setSendSlotMode(slot, .AsyncFirstAck);

    var wc = std.mem.zeroes(c.ibv_wc);
    wc.wr_id = types.sendWrId(slot);
    wc.status = c.IBV_WC_WR_FLUSH_ERR;
    wc.opcode = c.IBV_WC_RECV;
    var pending = PendingSecondAcks{};
    dispatchClassicWc(&queue, &wc, &pending);

    try std.testing.expectEqual(types.SlotState.Free, slotState(&queue, slot));
    try std.testing.expectEqual(types.SendSlotMode.Sync, queue.sendSlotMode(slot));
    try std.testing.expectEqual(@as(u64, 1), queue.async_ack_failures.load(.monotonic));
    // Asynchronous pairs never touch the mailbox.
    try std.testing.expectEqual(types.SEND_WR_ID_NONE, queue.send_completion_wr_id.load(.acquire));
}

test "a successful first-ACK completion queues the second ACK and keeps the slot" {
    var queue = testQueue();
    const slot = queue.allocSendSlot() orelse return error.TestUnexpectedResult;
    queue.setSendSlotMode(slot, .AsyncFirstAck);

    var wc = std.mem.zeroes(c.ibv_wc);
    wc.wr_id = types.sendWrId(slot);
    wc.status = c.IBV_WC_SUCCESS;
    wc.opcode = c.IBV_WC_SEND;
    var pending = PendingSecondAcks{};
    dispatchClassicWc(&queue, &wc, &pending);

    try std.testing.expectEqual(types.SlotState.InUse, slotState(&queue, slot));
    try std.testing.expectEqual(@as(usize, 1), pending.len);
    try std.testing.expectEqual(slot, pending.slots[0]);
    try std.testing.expectEqual(@as(u64, 0), queue.async_ack_failures.load(.monotonic));
}

test "recvEvent maps the packet, GRH and completion onto the Go-facing event" {
    const pkt = wire.ProbePacket{
        .version = wire.PACKET_VERSION,
        .msg_type = wire.MSG_TYPE_ACK,
        .ack_type = wire.ACK_TYPE_SECOND,
        .flags = 0x55,
        .sequence_num = 0x1122334455667788,
        .t1 = 1,
        .t3 = 3,
        .t4 = 4,
    };
    var grh_info = GRHInfo{ .source_gid = @splat(0), .dest_gid = @splat(0), .flow_label = 0xABCDE };
    grh_info.source_gid[15] = 9;
    const rc = RecvCompletion{ .slot_index = 7, .timestamp_ns = 555, .src_qp = 0x2A, .has_grh = true, .byte_len = 80 };

    const ev = recvEvent(&pkt, &grh_info, &rc);
    try std.testing.expectEqual(pkt.sequence_num, ev.sequence_num);
    try std.testing.expectEqual(@as(u64, 1), ev.t1);
    try std.testing.expectEqual(@as(u64, 3), ev.t3);
    try std.testing.expectEqual(@as(u64, 4), ev.t4);
    try std.testing.expectEqual(wire.MSG_TYPE_ACK, ev.is_ack);
    try std.testing.expectEqual(wire.ACK_TYPE_SECOND, ev.ack_type);
    try std.testing.expectEqual(@as(u64, 555), ev.timestamp_ns);
    try std.testing.expectEqual(@as(u32, 0x2A), ev.source_qpn);
    try std.testing.expectEqual(@as(u32, 0xABCDE), ev.flow_label);
    try std.testing.expectEqual(@as(u8, 9), ev.source_gid[15]);
    try std.testing.expectEqual(@as(i32, 0), ev.status);
    try std.testing.expectEqual(@as(u8, 0), ev.is_send);
}
