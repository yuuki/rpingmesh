// ring.zig - Lock-free SPSC (Single-Producer Single-Consumer) ring buffer.
//
// This ring buffer delivers completion events from the Zig CQ poller thread
// (producer) to the Go poller goroutine (consumer) without per-event FFI calls.
//
// Design:
//   - Power-of-2 capacity for branchless modular indexing via bitmask
//   - Cache-line padded head/tail to eliminate false sharing between cores
//   - Producer writes head with .release ordering; consumer reads with .acquire
//   - Consumer writes tail with .release ordering; producer reads with .acquire
//   - When the ring is full, events are dropped and drop_count is incremented

const std = @import("std");

// ---------------------------------------------------------------------------
// CompletionEvent - matches rdma_completion_event_t in rdma_bridge.h
// ---------------------------------------------------------------------------

/// A completion event delivered from the CQ poller to Go via the ring buffer.
///
/// This struct must be layout-compatible with rdma_completion_event_t in the
/// C header. Fields use fixed-width integer types and explicit padding to
/// ensure identical memory layout across Zig, C, and Go.
pub const CompletionEvent = extern struct {
    /// Probe sequence number used to correlate probes with ACKs.
    sequence_num: u64,

    /// T1 timestamp from probe payload (big-endian decoded).
    t1: u64,

    /// T3 timestamp from probe payload.
    t3: u64,

    /// T4 timestamp from probe payload.
    t4: u64,

    /// 0 = probe, 1 = ACK.
    is_ack: u8,

    /// ACK type: 1 = first ACK, 2 = second ACK.
    ack_type: u8,

    /// Reserved flags for future use.
    flags: u8,

    /// Explicit padding for 8-byte alignment of timestamp_ns.
    _pad: u8 = 0,

    /// Hardware or software timestamp of this completion in nanoseconds.
    timestamp_ns: u64,

    /// Source GID parsed from the GRH (16 bytes, binary).
    source_gid: [16]u8,

    /// Source Queue Pair Number from the work completion.
    source_qpn: u32,

    /// Flow label from the GRH IPv6 header.
    flow_label: u32,

    /// Completion status: 0 = success, nonzero = RDMA error code.
    status: i32,

    /// 0 = receive completion, 1 = send completion.
    is_send: u8,

    /// Explicit padding to maintain struct alignment.
    _pad2: [3]u8 = [_]u8{ 0, 0, 0 },
};

// Compile-time verification that CompletionEvent matches the C struct size.
//
// Layout with C ABI alignment rules:
//   offset  0: sequence_num (u64, 8 bytes)
//   offset  8: t1 (u64, 8 bytes)
//   offset 16: t3 (u64, 8 bytes)
//   offset 24: t4 (u64, 8 bytes)
//   offset 32: is_ack, ack_type, flags, _pad (4 x u8, 4 bytes)
//   offset 36: [4 bytes implicit padding for u64 alignment]
//   offset 40: timestamp_ns (u64, 8 bytes)
//   offset 48: source_gid ([16]u8, 16 bytes)
//   offset 64: source_qpn (u32, 4 bytes)
//   offset 68: flow_label (u32, 4 bytes)
//   offset 72: status (i32, 4 bytes)
//   offset 76: is_send (u8, 1 byte)
//   offset 77: _pad2 ([3]u8, 3 bytes)
//   Total: 80 bytes (already 8-byte aligned, no trailing padding)
comptime {
    if (@sizeOf(CompletionEvent) != 80) {
        @compileError("CompletionEvent size mismatch: expected 80 bytes for C ABI compatibility");
    }
}

// ---------------------------------------------------------------------------
// Cache line alignment
// ---------------------------------------------------------------------------

/// Cache line size for the target architecture. Used to pad atomic counters
/// to prevent false sharing between the producer and consumer cores.
const CACHE_LINE_SIZE = 64;

/// Atomic counter padded to a full cache line. Ensures the head and tail
/// counters each occupy their own cache line so that producer writes to
/// head do not cause cache invalidation on the consumer's tail cache line
/// and vice versa.
const CacheLinePaddedAtomic = struct {
    value: std.atomic.Value(u64) align(CACHE_LINE_SIZE) = std.atomic.Value(u64).init(0),
    // Explicit padding to fill the rest of the cache line.
    // std.atomic.Value(u64) is 8 bytes; we need 56 bytes of padding.
    _padding: [CACHE_LINE_SIZE - @sizeOf(std.atomic.Value(u64))]u8 = undefined,

    comptime {
        if (@sizeOf(CacheLinePaddedAtomic) != CACHE_LINE_SIZE) {
            @compileError("CacheLinePaddedAtomic must be exactly one cache line");
        }
    }
};

// ---------------------------------------------------------------------------
// EventRing
// ---------------------------------------------------------------------------

/// Lock-free SPSC ring buffer for CompletionEvent delivery.
///
/// The CQ poller thread is the sole producer: it calls push() to enqueue
/// completion events. The Go goroutine is the sole consumer: it calls
/// poll() to dequeue events in batches.
///
/// Capacity is always a power of 2 so that index wrapping can use a
/// bitmask (capacity - 1) instead of a modulo operation.
pub const EventRing = struct {
    /// Backing storage for the ring buffer entries.
    buffer: []CompletionEvent,

    /// Write index. Only modified by the producer (CQ poller thread).
    /// Cache-line padded to avoid false sharing with tail.
    head: CacheLinePaddedAtomic,

    /// Read index. Only modified by the consumer (Go goroutine).
    /// Cache-line padded to avoid false sharing with head.
    tail: CacheLinePaddedAtomic,

    /// Number of entries in the ring (always a power of 2).
    capacity: u64,

    /// Bitmask for fast modular indexing: capacity - 1.
    mask: u64,

    /// Counter for events dropped because the ring was full.
    /// Read by Go for metrics/diagnostics.
    drop_count: std.atomic.Value(u64),

    /// Allocate and initialize an EventRing.
    ///
    /// The requested capacity is rounded up to the next power of 2 (minimum 2).
    /// Returns null if memory allocation fails.
    pub fn create(requested_capacity: u32) ?*EventRing {
        // Round up to next power of 2 (minimum 2)
        const min_cap: u64 = 2;
        var cap: u64 = min_cap;
        const target: u64 = @intCast(requested_capacity);
        while (cap < target) {
            cap <<= 1;
        }

        // Allocate the ring struct itself
        const self = std.heap.page_allocator.create(EventRing) catch return null;

        // Allocate the backing buffer
        const buffer = std.heap.page_allocator.alloc(CompletionEvent, @intCast(cap)) catch {
            std.heap.page_allocator.destroy(self);
            return null;
        };

        // Zero-initialize all buffer entries
        @memset(buffer, std.mem.zeroes(CompletionEvent));

        self.* = EventRing{
            .buffer = buffer,
            .head = .{},
            .tail = .{},
            .capacity = cap,
            .mask = cap - 1,
            .drop_count = std.atomic.Value(u64).init(0),
        };

        return self;
    }

    /// Free all memory associated with the ring.
    pub fn destroy(self: *EventRing) void {
        std.heap.page_allocator.free(self.buffer);
        std.heap.page_allocator.destroy(self);
    }

    /// Push a completion event into the ring (producer side).
    ///
    /// Returns true on success, false if the ring is full. When full,
    /// the event is dropped and drop_count is atomically incremented.
    ///
    /// Memory ordering: head is stored with .release so the consumer
    /// sees the written event data when it loads head with .acquire.
    pub fn push(self: *EventRing, event: *const CompletionEvent) bool {
        const current_head = self.head.value.load(.monotonic);
        const current_tail = self.tail.value.load(.acquire);

        // Ring is full when head is one full lap ahead of tail
        if (current_head - current_tail >= self.capacity) {
            _ = self.drop_count.fetchAdd(1, .monotonic);
            return false;
        }

        // Write the event into the buffer slot
        const index: usize = @intCast(current_head & self.mask);
        self.buffer[index] = event.*;

        // Publish the new head with release ordering so the consumer
        // sees the event data before seeing the updated head.
        self.head.value.store(current_head + 1, .release);

        return true;
    }

    /// Poll the ring for completion events (consumer side).
    ///
    /// Copies up to max_count events into out_events and returns the
    /// number of events retrieved. Returns 0 immediately if the ring
    /// is empty (non-blocking).
    ///
    /// Memory ordering: head is loaded with .acquire to ensure the
    /// consumer sees event data written before the head update. Tail
    /// is stored with .release so the producer can safely reclaim slots.
    pub fn poll(self: *EventRing, out_events: [*]CompletionEvent, max_count: i32) i32 {
        if (max_count <= 0) return 0;

        const current_tail = self.tail.value.load(.monotonic);
        const current_head = self.head.value.load(.acquire);

        // Number of available events
        const available = current_head - current_tail;
        if (available == 0) return 0;

        const count: u64 = @min(available, @as(u64, @intCast(max_count)));

        // Copy events out of the ring
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            const index: usize = @intCast((current_tail + i) & self.mask);
            out_events[@intCast(i)] = self.buffer[index];
        }

        // Advance tail with release ordering so the producer knows
        // these slots are now free for reuse.
        self.tail.value.store(current_tail + count, .release);

        return @intCast(count);
    }

    /// Get the total number of events dropped due to ring-full conditions.
    ///
    /// This is a monotonically increasing counter useful for monitoring
    /// and diagnostics. If this value is growing, the consumer is not
    /// draining events fast enough.
    pub fn getDropCount(self: *EventRing) u64 {
        return self.drop_count.load(.monotonic);
    }
};

// ---------------------------------------------------------------------------
// C-ABI exported functions (called from Go via Cgo)
// ---------------------------------------------------------------------------

/// Create an event ring buffer.
///
/// Exported as `rdma_event_ring_create` for the C ABI.
/// Returns an opaque pointer (rdma_event_ring_t) or null on failure.
export fn rdma_event_ring_create(capacity: u32) ?*EventRing {
    return EventRing.create(capacity);
}

/// Poll the event ring for completion events.
///
/// Exported as `rdma_event_ring_poll` for the C ABI.
/// Returns the number of events copied, or -1 on invalid arguments.
export fn rdma_event_ring_poll(ring_ptr: ?*EventRing, out_events: ?[*]CompletionEvent, max_count: i32) i32 {
    const r = ring_ptr orelse return -1;
    const events = out_events orelse return -1;
    return r.poll(events, max_count);
}

/// Destroy an event ring buffer and free all associated memory.
///
/// Exported as `rdma_event_ring_destroy` for the C ABI.
export fn rdma_event_ring_destroy(ring_ptr: ?*EventRing) void {
    const r = ring_ptr orelse return;
    r.destroy();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CompletionEvent size matches C ABI" {
    // 80 bytes: includes 4 bytes implicit padding between _pad and timestamp_ns
    // due to u64 alignment requirement in C ABI (extern struct).
    try std.testing.expectEqual(@as(usize, 80), @sizeOf(CompletionEvent));
}

test "CacheLinePaddedAtomic is exactly one cache line" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(CacheLinePaddedAtomic));
}

test "EventRing create and destroy" {
    const r = EventRing.create(16) orelse return error.SkipZigTest;
    defer r.destroy();
    try std.testing.expectEqual(@as(u64, 16), r.capacity);
    try std.testing.expectEqual(@as(u64, 15), r.mask);
    try std.testing.expectEqual(@as(u64, 0), r.getDropCount());
}

test "EventRing rounds up to power of 2" {
    const r = EventRing.create(10) orelse return error.SkipZigTest;
    defer r.destroy();
    try std.testing.expectEqual(@as(u64, 16), r.capacity);
}

test "EventRing minimum capacity is 2" {
    const r = EventRing.create(1) orelse return error.SkipZigTest;
    defer r.destroy();
    try std.testing.expectEqual(@as(u64, 2), r.capacity);
}

test "EventRing push and poll single event" {
    const r = EventRing.create(4) orelse return error.SkipZigTest;
    defer r.destroy();

    var event = std.mem.zeroes(CompletionEvent);
    event.sequence_num = 42;
    event.t1 = 1000;
    event.is_ack = 1;
    event.ack_type = 2;
    event.status = 0;

    // Push one event
    try std.testing.expect(r.push(&event));

    // Poll it back
    var out: [1]CompletionEvent = undefined;
    const count = r.poll(&out, 1);
    try std.testing.expectEqual(@as(i32, 1), count);
    try std.testing.expectEqual(@as(u64, 42), out[0].sequence_num);
    try std.testing.expectEqual(@as(u64, 1000), out[0].t1);
    try std.testing.expectEqual(@as(u8, 1), out[0].is_ack);
    try std.testing.expectEqual(@as(u8, 2), out[0].ack_type);
}

test "EventRing poll returns 0 when empty" {
    const r = EventRing.create(4) orelse return error.SkipZigTest;
    defer r.destroy();

    var out: [4]CompletionEvent = undefined;
    const count = r.poll(&out, 4);
    try std.testing.expectEqual(@as(i32, 0), count);
}

test "EventRing poll with zero max_count" {
    const r = EventRing.create(4) orelse return error.SkipZigTest;
    defer r.destroy();

    var event = std.mem.zeroes(CompletionEvent);
    try std.testing.expect(r.push(&event));

    var out: [1]CompletionEvent = undefined;
    const count = r.poll(&out, 0);
    try std.testing.expectEqual(@as(i32, 0), count);
}

test "EventRing full ring drops events" {
    const r = EventRing.create(2) orelse return error.SkipZigTest;
    defer r.destroy();

    var event = std.mem.zeroes(CompletionEvent);

    // Fill the ring (capacity = 2)
    event.sequence_num = 1;
    try std.testing.expect(r.push(&event));
    event.sequence_num = 2;
    try std.testing.expect(r.push(&event));

    // Third push should fail (ring full)
    event.sequence_num = 3;
    try std.testing.expect(!r.push(&event));

    // Drop count should be 1
    try std.testing.expectEqual(@as(u64, 1), r.getDropCount());
}

test "EventRing wraps around correctly" {
    const r = EventRing.create(4) orelse return error.SkipZigTest;
    defer r.destroy();

    var event = std.mem.zeroes(CompletionEvent);
    var out: [4]CompletionEvent = undefined;

    // Fill and drain several times to exercise wrap-around
    var round: u64 = 0;
    while (round < 3) : (round += 1) {
        // Push 4 events
        var i: u64 = 0;
        while (i < 4) : (i += 1) {
            event.sequence_num = round * 4 + i;
            try std.testing.expect(r.push(&event));
        }

        // Poll all 4
        const count = r.poll(&out, 4);
        try std.testing.expectEqual(@as(i32, 4), count);

        // Verify sequence numbers
        i = 0;
        while (i < 4) : (i += 1) {
            try std.testing.expectEqual(round * 4 + i, out[@intCast(i)].sequence_num);
        }
    }
}

test "EventRing batch poll returns partial" {
    const r = EventRing.create(8) orelse return error.SkipZigTest;
    defer r.destroy();

    var event = std.mem.zeroes(CompletionEvent);

    // Push 3 events
    var i: u64 = 0;
    while (i < 3) : (i += 1) {
        event.sequence_num = i + 10;
        try std.testing.expect(r.push(&event));
    }

    // Poll asking for 8, should only get 3
    var out: [8]CompletionEvent = undefined;
    const count = r.poll(&out, 8);
    try std.testing.expectEqual(@as(i32, 3), count);
    try std.testing.expectEqual(@as(u64, 10), out[0].sequence_num);
    try std.testing.expectEqual(@as(u64, 11), out[1].sequence_num);
    try std.testing.expectEqual(@as(u64, 12), out[2].sequence_num);
}

test "EventRing C-ABI exported functions" {
    // Test create
    const r = rdma_event_ring_create(16) orelse return error.SkipZigTest;

    // Test poll with no events
    var out: [4]CompletionEvent = undefined;
    const count = rdma_event_ring_poll(r, &out, 4);
    try std.testing.expectEqual(@as(i32, 0), count);

    // Test poll with null ring
    const null_count = rdma_event_ring_poll(null, &out, 4);
    try std.testing.expectEqual(@as(i32, -1), null_count);

    // Test poll with null events pointer
    const null_events_count = rdma_event_ring_poll(r, null, 4);
    try std.testing.expectEqual(@as(i32, -1), null_events_count);

    // Test destroy (should not crash)
    rdma_event_ring_destroy(r);

    // Test destroy with null (should be a no-op)
    rdma_event_ring_destroy(null);
}

test "EventRing source_gid preserved through push/poll" {
    const r = EventRing.create(4) orelse return error.SkipZigTest;
    defer r.destroy();

    var event = std.mem.zeroes(CompletionEvent);
    event.source_gid = [16]u8{
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    event.source_qpn = 12345;
    event.flow_label = 0xABCDE;

    try std.testing.expect(r.push(&event));

    var out: [1]CompletionEvent = undefined;
    const count = r.poll(&out, 1);
    try std.testing.expectEqual(@as(i32, 1), count);
    try std.testing.expectEqualSlices(u8, &event.source_gid, &out[0].source_gid);
    try std.testing.expectEqual(@as(u32, 12345), out[0].source_qpn);
    try std.testing.expectEqual(@as(u32, 0xABCDE), out[0].flow_label);
}
