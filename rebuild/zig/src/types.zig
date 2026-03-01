// types.zig - Core types shared across all Zig modules for the RDMA bridge library.
//
// This module defines the fundamental data structures, constants, and helper
// functions used throughout the Zig RDMA implementation. All types are designed
// to be ABI-compatible with the C header (rdma_bridge.h) and the Go Cgo bridge.

const std = @import("std");

// ---------------------------------------------------------------------------
// libibverbs / librdmacm C bindings
// ---------------------------------------------------------------------------

/// Re-exported C types from libibverbs and librdmacm.
/// Usage: `types.c.ibv_context`, `types.c.ibv_qp`, etc.
pub const c = @cImport({
    @cInclude("infiniband/verbs.h");
    @cInclude("rdma/rdma_cma.h");
});

// ---------------------------------------------------------------------------
// Constants (matching rdma_bridge.h)
// ---------------------------------------------------------------------------

/// Size of each memory region buffer in bytes.
pub const MR_SIZE: u32 = 4096;

/// Size of the Global Routing Header prepended by the hardware on UD receives.
pub const GRH_SIZE: u32 = 40;

/// Number of entries in each Completion Queue.
pub const CQ_SIZE: u32 = 256;

/// Number of receive buffers posted at queue creation time.
pub const INITIAL_RECV_BUFFERS: u32 = 32;

/// Queue key used for all UD Queue Pairs in this system.
pub const QKEY: u32 = 0x11111111;

/// Size of a probe packet payload in bytes.
pub const PROBE_PACKET_SIZE: u32 = 40;

/// Number of send slots in the send memory region.
pub const NUM_SEND_SLOTS: u32 = 32;

/// Number of receive slots in the receive memory region.
pub const NUM_RECV_SLOTS: u32 = 32;

/// Size of each buffer slot: MR_SIZE (payload) + GRH_SIZE (header).
/// For receive buffers the hardware writes GRH_SIZE bytes of GRH followed
/// by up to MR_SIZE bytes of payload into each slot.
pub const SLOT_SIZE: u32 = MR_SIZE + GRH_SIZE;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Describes whether a send/receive slot is available, waiting for a
/// completion, or actively being used by the application.
pub const SlotState = enum(u8) {
    /// Slot is available for new work requests.
    Free = 0,
    /// Slot has been posted to the hardware and is awaiting completion.
    Posted = 1,
    /// Slot is being consumed by application code (e.g. packet parsing).
    InUse = 2,
};

/// Identifies the role of a UD Queue Pair, matching the C defines
/// RDMA_QUEUE_TYPE_SENDER (0) and RDMA_QUEUE_TYPE_RESPONDER (1).
pub const QueueType = enum(u8) {
    /// Sends probes and receives ACKs.
    Sender = 0,
    /// Receives probes and sends ACKs.
    Responder = 1,
};

// ---------------------------------------------------------------------------
// Forward declarations (ring buffer is defined in ring.zig)
// ---------------------------------------------------------------------------

const ring = @import("ring.zig");

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Global RDMA context. Encapsulates the device list obtained from
/// ibv_get_device_list(). Exactly one context should exist per process.
pub const RdmaContext = struct {
    /// Pointer to the array of device pointers returned by ibv_get_device_list().
    /// The double pointer matches the C signature: `struct ibv_device **`.
    device_list: ?*?*c.ibv_device,

    /// Number of devices in the device list, as returned by ibv_get_device_list().
    device_count: i32,

    /// Whether this context has been successfully initialized.
    initialized: bool,
};

/// Represents an opened RDMA device with its Protection Domain and
/// active port/GID configuration.
pub const RdmaDevice = struct {
    /// Device context handle from ibv_open_device().
    ctx: *c.ibv_context,

    /// Protection Domain allocated for this device.
    pd: *c.ibv_pd,

    /// Active port number (1-based, as used by the verbs API).
    port_num: u8,

    /// GID table index on the active port.
    gid_index: u8,

    /// GID value queried from the device (union ibv_gid).
    gid: c.ibv_gid,

    /// Human-readable device information matching rdma_device_info_t in the
    /// C header. This is filled during device open and returned to Go.
    device_info: DeviceInfo,

    /// Whether this device supports hardware completion timestamps.
    has_hw_timestamps: bool,
};

/// Device information struct, matching rdma_device_info_t in rdma_bridge.h.
/// Uses fixed-size byte arrays for ABI stability across the Go boundary.
pub const DeviceInfo = extern struct {
    /// RDMA device name (e.g. "mlx5_0", "rxe0").
    device_name: [64]u8,

    /// GID string representation for display purposes.
    gid: [64]u8,

    /// Associated IP address string.
    ip_addr: [64]u8,

    /// Active port number (1-based).
    active_port: u8,

    /// GID table index in use.
    active_gid_index: u8,
};

/// UD (Unreliable Datagram) Queue Pair with all associated resources:
/// CQs, memory regions, buffers, and the CQ poller thread.
pub const UdQueue = struct {
    /// The Queue Pair handle.
    qp: *c.ibv_qp,

    /// Extended Completion Queue for send completions (supports timestamps).
    send_cq: *c.ibv_cq_ex,

    /// Extended Completion Queue for receive completions.
    recv_cq: *c.ibv_cq_ex,

    /// Memory Region for the send buffer.
    send_mr: *c.ibv_mr,

    /// Memory Region for the receive buffer.
    recv_mr: *c.ibv_mr,

    /// Send buffer: page-aligned contiguous memory for send slots.
    /// Total size = NUM_SEND_SLOTS * SLOT_SIZE bytes.
    send_buf: [*]align(4096) u8,

    /// Receive buffer: page-aligned contiguous memory for receive slots.
    /// Total size = NUM_RECV_SLOTS * SLOT_SIZE bytes.
    recv_buf: [*]align(4096) u8,

    /// Queue Pair Number assigned by the hardware.
    qpn: u32,

    /// Whether this queue uses software timestamps (true) or hardware
    /// timestamps (false). Determined at creation based on device capabilities.
    uses_sw_timestamps: bool,

    /// Role of this queue: Sender or Responder.
    queue_type: QueueType,

    /// Pointer to the event ring buffer where CQ completions are written.
    /// The ring is owned by the Go side and passed in during queue creation.
    event_ring: ?*ring.EventRing,

    /// Handle for the CQ poller thread that reads completions and pushes
    /// events into the event ring.
    cq_thread: ?std.Thread,

    /// Back-pointer to the parent device.
    device: *RdmaDevice,

    /// Per-slot state tracking for send buffers.
    send_slot_states: [NUM_SEND_SLOTS]SlotState,

    /// Per-slot state tracking for receive buffers.
    recv_slot_states: [NUM_RECV_SLOTS]SlotState,

    /// Whether the CQ poller thread should keep running. Set to false
    /// during queue destruction to signal the poller to exit.
    running: std.atomic.Value(bool),

    // ----- Send completion signaling (synchronous send path) -----

    /// Atomic flag set by the CQ poller when a send completion is ready.
    /// The sender thread spins on this after posting a send WR.
    send_completion_ready: std.atomic.Value(bool),

    /// Send completion timestamp (nanoseconds). Written by the CQ poller,
    /// read by the sender after send_completion_ready becomes true.
    send_completion_timestamp: std.atomic.Value(u64),

    /// Send completion status. 0 = success, nonzero = RDMA error code.
    /// Written by the CQ poller alongside the timestamp.
    send_completion_status: std.atomic.Value(i32),
};

// ---------------------------------------------------------------------------
// GID helpers
// ---------------------------------------------------------------------------

/// Convert an ibv_gid union to a 16-byte array.
///
/// The ibv_gid union contains the raw 128-bit GID value. This function
/// extracts it as a plain byte array for portable handling and serialization.
pub fn gidToBytes(gid: c.ibv_gid) [16]u8 {
    return gid.raw;
}

/// Convert a 16-byte array to an ibv_gid union.
///
/// Inverse of gidToBytes(). Used when constructing address handles from
/// GID bytes received over the wire or from Go.
pub fn bytesToGid(bytes: [16]u8) c.ibv_gid {
    return c.ibv_gid{ .raw = bytes };
}

/// Format a 16-byte GID as an IPv6-style colon-separated hex string.
///
/// Produces 8 groups of 4 hex digits separated by colons, compatible with
/// both standard IPv6 notation and InfiniBand GID notation used by
/// probe.ParseGID in the Go layer.
/// Example: "fe80:0000:0000:0000:0000:0000:0000:0001"
///
/// The returned buffer is 64 bytes: 39 chars used, null-terminated,
/// remaining bytes zeroed.
pub fn gidToString(gid_bytes: [16]u8) [64]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [64]u8 = [_]u8{0} ** 64;
    var pos: usize = 0;

    for (0..8) |group| {
        if (group > 0) {
            result[pos] = ':';
            pos += 1;
        }
        const hi = gid_bytes[group * 2];
        const lo = gid_bytes[group * 2 + 1];
        result[pos] = hex_chars[hi >> 4];
        pos += 1;
        result[pos] = hex_chars[hi & 0x0f];
        pos += 1;
        result[pos] = hex_chars[lo >> 4];
        pos += 1;
        result[pos] = hex_chars[lo & 0x0f];
        pos += 1;
    }
    // Remaining bytes are already zero from initialization.
    return result;
}

// ---------------------------------------------------------------------------
// Thread-local error message
// ---------------------------------------------------------------------------

/// Thread-local buffer for the last error message. Each thread gets its
/// own copy so concurrent RDMA operations do not clobber each other's
/// error strings. Initialized to all zeros (empty string).
threadlocal var last_error: [256]u8 = [_]u8{0} ** 256;

/// Store an error message in the thread-local error buffer.
///
/// The message is copied and null-terminated. If the input exceeds 255
/// bytes it is silently truncated to fit the buffer.
pub fn setLastError(msg: []const u8) void {
    const copy_len = @min(msg.len, last_error.len - 1);
    @memcpy(last_error[0..copy_len], msg[0..copy_len]);
    last_error[copy_len] = 0;
    // Zero out any leftover bytes from a previous longer message.
    if (copy_len + 1 < last_error.len) {
        @memset(last_error[copy_len + 1 ..], 0);
    }
}

/// Get a pointer to the thread-local error string.
///
/// Returns a null-terminated C string suitable for returning across the
/// FFI boundary. The pointer is valid until the next call to setLastError()
/// on the same thread.
pub fn getLastError() [*:0]const u8 {
    // The buffer is always null-terminated by setLastError() and by the
    // zero-initialization, so we can safely cast.
    return @ptrCast(&last_error);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "gidToBytes and bytesToGid roundtrip" {
    const original = [16]u8{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const gid = bytesToGid(original);
    const back = gidToBytes(gid);
    try std.testing.expectEqualSlices(u8, &original, &back);
}

test "gidToString produces IPv6-style 8-group hex" {
    const gid_bytes = [16]u8{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const result = gidToString(gid_bytes);
    const expected = "fe80:0000:0000:0000:0000:0000:0000:0001";
    try std.testing.expectEqualStrings(expected, result[0..expected.len]);
    // Verify null termination
    try std.testing.expectEqual(@as(u8, 0), result[expected.len]);
}

test "gidToString IPv4-mapped GID" {
    // ::ffff:10.200.0.1 in raw bytes
    const gid_bytes = [16]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0xc8, 0x00, 0x01 };
    const result = gidToString(gid_bytes);
    const expected = "0000:0000:0000:0000:0000:ffff:0ac8:0001";
    try std.testing.expectEqualStrings(expected, result[0..expected.len]);
}

test "setLastError and getLastError" {
    setLastError("test error message");
    const err = getLastError();
    const err_slice = std.mem.sliceTo(err, 0);
    try std.testing.expectEqualStrings("test error message", err_slice);
}

test "setLastError truncates long messages" {
    // Create a message longer than 255 bytes
    const long_msg = "A" ** 300;
    setLastError(long_msg);
    const err = getLastError();
    const err_slice = std.mem.sliceTo(err, 0);
    try std.testing.expectEqual(@as(usize, 255), err_slice.len);
}

test "setLastError overwrites previous message" {
    setLastError("first error");
    setLastError("second");
    const err = getLastError();
    const err_slice = std.mem.sliceTo(err, 0);
    try std.testing.expectEqualStrings("second", err_slice);
}

test "SlotState enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(SlotState.Free));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(SlotState.Posted));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(SlotState.InUse));
}

test "QueueType enum values match C defines" {
    // RDMA_QUEUE_TYPE_SENDER = 0, RDMA_QUEUE_TYPE_RESPONDER = 1
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(QueueType.Sender));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(QueueType.Responder));
}

test "constants match C header" {
    try std.testing.expectEqual(@as(u32, 4096), MR_SIZE);
    try std.testing.expectEqual(@as(u32, 40), GRH_SIZE);
    try std.testing.expectEqual(@as(u32, 256), CQ_SIZE);
    try std.testing.expectEqual(@as(u32, 32), INITIAL_RECV_BUFFERS);
    try std.testing.expectEqual(@as(u32, 0x11111111), QKEY);
    try std.testing.expectEqual(@as(u32, 40), PROBE_PACKET_SIZE);
    try std.testing.expectEqual(@as(u32, 4136), SLOT_SIZE);
}

test "DeviceInfo is extern struct with correct field sizes" {
    // Verify it is a packed/extern struct that can cross the FFI boundary
    const info = std.mem.zeroes(DeviceInfo);
    try std.testing.expectEqual(@as(u8, 0), info.active_port);
    try std.testing.expectEqual(@as(u8, 0), info.active_gid_index);
    // device_name, gid, ip_addr are each 64 bytes
    try std.testing.expectEqual(@as(usize, 64), info.device_name.len);
    try std.testing.expectEqual(@as(usize, 64), info.gid.len);
    try std.testing.expectEqual(@as(usize, 64), info.ip_addr.len);
}
