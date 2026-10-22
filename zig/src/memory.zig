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

const SLOT_SIZE = types.SLOT_SIZE;
const PAGE_SIZE = types.PAGE_SIZE;

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
    /// ibv_post_send() failed.
    PostSendFailed,
    /// A required pointer argument was null.
    NullPointer,
};

/// See types.BufferSet; allocateBuffers() creates one.
pub const BufferSet = types.BufferSet;

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
    const buf = std.heap.page_allocator.alignedAlloc(u8, @as(std.mem.Alignment, @fromBackingInt(@intCast(@ctz(@as(usize, PAGE_SIZE))))), total_size) catch {
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
/// After calling this function, the BufferSet must not be used again on
/// success. Any work requests referencing this buffer's lkey will be
/// invalid.
///
/// If ibv_dereg_mr() fails (nonzero return), the underlying pages are
/// deliberately NOT freed and the function returns early. The kernel/HCA
/// may still hold a reference to this memory (e.g. an outstanding
/// completion the driver has not fully drained, or a firmware/driver bug on
/// real hardware -- ibv_dereg_mr() is documented to fail with EBUSY in
/// exactly this situation). Freeing pages that hardware can still DMA into
/// would turn into a use-after-free once those pages are reused by the
/// allocator, which is a far worse outcome than an intentional, bounded
/// leak on an already-exceptional error path.
pub fn freeBuffers(buf_set: *BufferSet) void {
    const dereg_ret = c.ibv_dereg_mr(buf_set.mr);
    if (dereg_ret != 0) {
        std.log.scoped(.rdma_memory).err(
            "ibv_dereg_mr() failed with errno={d}; leaking {d} bytes to avoid a potential use-after-free",
            .{ dereg_ret, buf_set.size },
        );
        types.setLastError("ibv_dereg_mr() failed; buffer intentionally leaked to avoid use-after-free");
        return;
    }

    // Free the page-aligned buffer
    const slice = buf_set.buf[0..buf_set.size];
    std.heap.page_allocator.free(slice);

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

/// Post one signaled UD send of a PROBE_PACKET_SIZE-byte packet.
///
/// `packet` must point into the send MR `mr` (a send slot, or the second ACK
/// staged inside one). The WR's wr_id is types.sendWrId(slot_index), which is
/// how the CQ poller maps the completion back to the slot and tells it from a
/// recv completion. Used by packet.zig for every send it posts and by cq.zig
/// for the second ACK of an asynchronous pair.
/// ibv_post_send is thread-safe for a QP created without a thread domain (as
/// queue.zig creates it), so the CQ poller may post while the application
/// thread posts on the same QP. A provider single-thread mode (for example
/// MLX5_SINGLE_THREADED=1) or a thread domain would break that.
pub fn postUdSend(
    qp: *c.ibv_qp,
    mr: *c.ibv_mr,
    packet: [*]u8,
    slot_index: u32,
    ah: *c.ibv_ah,
    remote_qpn: u32,
) MemoryError!void {
    var sge = c.ibv_sge{
        .addr = @intFromPtr(packet),
        .length = types.PROBE_PACKET_SIZE,
        .lkey = mr.lkey,
    };

    var wr = std.mem.zeroes(c.ibv_send_wr);
    wr.wr_id = types.sendWrId(slot_index);
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = c.IBV_WR_SEND;
    wr.send_flags = c.IBV_SEND_SIGNALED;
    wr.wr.ud.ah = ah;
    wr.wr.ud.remote_qpn = remote_qpn;
    wr.wr.ud.remote_qkey = types.QKEY;

    var bad_wr: ?*c.ibv_send_wr = null;
    if (c.ibv_post_send(qp, &wr, &bad_wr) != 0) {
        types.setLastError("ibv_post_send() failed");
        return MemoryError.PostSendFailed;
    }
}

/// Post a single receive buffer to a Queue Pair.
///
/// Creates an ibv_recv_wr (receive work request) that tells the HCA where
/// to write incoming data for this slot. The wr_id is the bare slot_index
/// (no SEND_WR_ID_FLAG), which identifies both the buffer and, to the CQ
/// poller, the completion as a receive.
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
