// memory.zig - Buffer allocation and Memory Region (MR) registration.
//
// This module manages page-aligned buffer allocation, ibv_reg_mr/ibv_dereg_mr
// calls, and receive buffer posting. Buffers are divided into fixed-size slots
// (SLOT_SIZE bytes each) to allow independent use by send/receive work requests.
//
// Each slot is large enough to hold GRH_SIZE (40 bytes) + MR_SIZE (4096 bytes)
// of payload, which is the maximum data the hardware writes on a UD receive.

const std = @import("std");
const types = @import("types.zig");
const c = types.c;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of each buffer slot in bytes: GRH (40) + payload (4096) = 4136.
pub const SLOT_SIZE = types.SLOT_SIZE;

/// Page size used for buffer alignment. Most architectures use 4096.
const PAGE_SIZE = 4096;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during memory operations.
pub const MemoryError = error{
    /// Page-aligned memory allocation failed.
    AllocFailed,
    /// ibv_reg_mr() returned null.
    RegMrFailed,
    /// ibv_dereg_mr() returned a non-zero error code.
    DeregMrFailed,
    /// The slot index is out of bounds for the buffer.
    SlotIndexOutOfBounds,
    /// ibv_post_recv() failed.
    PostRecvFailed,
    /// A required pointer argument was null.
    NullPointer,
};

// ---------------------------------------------------------------------------
// BufferSet
// ---------------------------------------------------------------------------

/// A set of page-aligned buffers registered as an RDMA Memory Region.
///
/// The buffer is divided into num_slots contiguous slots of SLOT_SIZE bytes.
/// Each slot can be independently used as a scatter/gather element in a
/// work request.
pub const BufferSet = struct {
    /// Pointer to the page-aligned buffer memory.
    buf: [*]align(PAGE_SIZE) u8,

    /// Memory Region handle from ibv_reg_mr().
    mr: *c.ibv_mr,

    /// Number of slots in this buffer set.
    num_slots: u32,

    /// Total size of the buffer in bytes (num_slots * SLOT_SIZE).
    size: usize,
};

// ---------------------------------------------------------------------------
// Buffer allocation and registration
// ---------------------------------------------------------------------------

/// Allocate a page-aligned buffer and register it as an RDMA Memory Region.
///
/// The buffer is divided into num_slots slots of SLOT_SIZE bytes each.
/// The MR is registered with IBV_ACCESS_LOCAL_WRITE permission, which
/// allows the HCA to write received data directly into the buffer.
///
/// On failure, all partially allocated resources are cleaned up before
/// returning the error.
pub fn allocateBuffers(dev: *types.RdmaDevice, num_slots: u32) MemoryError!BufferSet {
    if (num_slots == 0) {
        types.setLastError("num_slots must be > 0");
        return MemoryError.AllocFailed;
    }

    const total_size: usize = @as(usize, num_slots) * @as(usize, SLOT_SIZE);

    // Allocate page-aligned memory. The page_allocator produces page-aligned
    // allocations by default, but we explicitly request the alignment.
    const buf = std.heap.page_allocator.alignedAlloc(u8, PAGE_SIZE, total_size) catch {
        types.setLastError("failed to allocate page-aligned buffer");
        return MemoryError.AllocFailed;
    };
    errdefer std.heap.page_allocator.free(buf);

    // Zero-initialize the buffer
    @memset(buf, 0);

    // Register the buffer as a Memory Region with the device's PD.
    // IBV_ACCESS_LOCAL_WRITE allows the HCA to write into this buffer
    // (required for receive operations).
    const mr = c.ibv_reg_mr(
        dev.pd,
        @ptrCast(buf.ptr),
        total_size,
        c.IBV_ACCESS_LOCAL_WRITE,
    ) orelse {
        types.setLastError("ibv_reg_mr() failed");
        return MemoryError.RegMrFailed;
    };

    return BufferSet{
        .buf = buf.ptr,
        .mr = mr,
        .num_slots = num_slots,
        .size = total_size,
    };
}

/// Deregister the Memory Region and free the buffer memory.
///
/// After calling this function, the BufferSet must not be used again.
/// Any work requests referencing this buffer's lkey will be invalid.
pub fn freeBuffers(buf_set: *BufferSet) void {
    // Deregister the Memory Region first (before freeing the underlying memory)
    _ = c.ibv_dereg_mr(buf_set.mr);

    // Free the page-aligned buffer
    const slice = buf_set.buf[0..buf_set.size];
    std.heap.page_allocator.free(@alignCast(slice));

    // Zero out the struct to prevent dangling pointer use
    buf_set.buf = undefined;
    buf_set.mr = undefined;
    buf_set.num_slots = 0;
    buf_set.size = 0;
}

// ---------------------------------------------------------------------------
// Slot access
// ---------------------------------------------------------------------------

/// Get a pointer to a specific slot within a buffer.
///
/// Each slot starts at offset (slot_index * SLOT_SIZE) from the beginning
/// of the buffer. Returns a pointer to the first byte of the slot.
///
/// Bounds checking: returns an error if slot_index >= num_slots.
pub fn getSlotPtr(buf: [*]u8, slot_index: u32, num_slots: u32) MemoryError![*]u8 {
    if (slot_index >= num_slots) {
        types.setLastError("slot index out of bounds");
        return MemoryError.SlotIndexOutOfBounds;
    }

    const offset: usize = @as(usize, slot_index) * @as(usize, SLOT_SIZE);
    return buf + offset;
}

// ---------------------------------------------------------------------------
// Receive buffer posting
// ---------------------------------------------------------------------------

/// Post a single receive buffer to a Queue Pair.
///
/// Creates an ibv_recv_wr (receive work request) that tells the HCA where
/// to write incoming data for this slot. The wr_id is set to the slot_index
/// so that when a completion arrives, we can identify which buffer was used.
///
/// The scatter/gather entry points to the slot's buffer with a length of
/// SLOT_SIZE and the lkey from the registered Memory Region.
pub fn postRecvBuffer(
    qp: *c.ibv_qp,
    mr: *c.ibv_mr,
    buf: [*]u8,
    slot_index: u32,
) MemoryError!void {
    const offset: usize = @as(usize, slot_index) * @as(usize, SLOT_SIZE);

    // Scatter/gather list entry: describes the buffer for this receive
    var sge = c.ibv_sge{
        .addr = @intFromPtr(buf + offset),
        .length = SLOT_SIZE,
        .lkey = mr.lkey,
    };

    // Receive work request
    var wr = c.ibv_recv_wr{
        .wr_id = @intCast(slot_index),
        .next = null,
        .sg_list = &sge,
        .num_sge = 1,
    };

    var bad_wr: ?*c.ibv_recv_wr = null;
    const ret = c.ibv_post_recv(qp, &wr, &bad_wr);
    if (ret != 0) {
        types.setLastError("ibv_post_recv() failed");
        return MemoryError.PostRecvFailed;
    }
}

/// Post receive buffers for slots 0 through num_buffers-1.
///
/// This is called during queue initialization to pre-post a batch of
/// receive buffers so the HCA has buffers ready to receive incoming
/// packets immediately after the QP transitions to the RTS state.
///
/// If any individual post fails, the function returns immediately with
/// an error. Buffers posted before the failure remain posted.
pub fn postInitialRecvBuffers(
    qp: *c.ibv_qp,
    mr: *c.ibv_mr,
    buf: [*]u8,
    num_buffers: u32,
) MemoryError!void {
    var i: u32 = 0;
    while (i < num_buffers) : (i += 1) {
        try postRecvBuffer(qp, mr, buf, i);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SLOT_SIZE matches types constant" {
    try std.testing.expectEqual(types.SLOT_SIZE, SLOT_SIZE);
    try std.testing.expectEqual(@as(u32, 4136), SLOT_SIZE);
}

test "getSlotPtr returns correct offset" {
    // Create a small test buffer (not registered with RDMA, just for pointer math)
    var test_buf: [4136 * 4]u8 = undefined;
    const base: [*]u8 = &test_buf;

    // Slot 0 should be at the base
    const slot0 = try getSlotPtr(base, 0, 4);
    try std.testing.expectEqual(base, slot0);

    // Slot 1 should be at base + SLOT_SIZE
    const slot1 = try getSlotPtr(base, 1, 4);
    const expected_offset: usize = SLOT_SIZE;
    try std.testing.expectEqual(base + expected_offset, slot1);

    // Slot 2 should be at base + 2 * SLOT_SIZE
    const slot2 = try getSlotPtr(base, 2, 4);
    try std.testing.expectEqual(base + 2 * expected_offset, slot2);
}

test "getSlotPtr rejects out of bounds index" {
    var test_buf: [4136 * 2]u8 = undefined;
    const base: [*]u8 = &test_buf;

    // Slot index 2 is out of bounds for a 2-slot buffer
    const result = getSlotPtr(base, 2, 2);
    try std.testing.expectError(MemoryError.SlotIndexOutOfBounds, result);

    // Slot index 0 and 1 should succeed
    _ = try getSlotPtr(base, 0, 2);
    _ = try getSlotPtr(base, 1, 2);
}

test "getSlotPtr rejects when num_slots is zero" {
    var test_buf: [4136]u8 = undefined;
    const base: [*]u8 = &test_buf;

    const result = getSlotPtr(base, 0, 0);
    try std.testing.expectError(MemoryError.SlotIndexOutOfBounds, result);
}

test "BufferSet struct has expected fields" {
    // Verify the struct layout is correct at compile time
    const info = @typeInfo(BufferSet);
    try std.testing.expect(info == .@"struct");

    const fields = info.@"struct".fields;
    try std.testing.expectEqual(@as(usize, 4), fields.len);
    try std.testing.expectEqualStrings("buf", fields[0].name);
    try std.testing.expectEqualStrings("mr", fields[1].name);
    try std.testing.expectEqualStrings("num_slots", fields[2].name);
    try std.testing.expectEqualStrings("size", fields[3].name);
}
