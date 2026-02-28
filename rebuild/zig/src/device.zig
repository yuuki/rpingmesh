// device.zig - RDMA device lifecycle management.
//
// This module handles device enumeration, opening, and closing. It wraps
// libibverbs device operations and provides a clean Zig interface that is
// exported via C-ABI functions for the Go bridge layer.
//
// Lifecycle:
//   1. initContext()    - Enumerate RDMA devices
//   2. openDevice()     - Open a specific device, allocate PD, query GID
//   3. closeDevice()    - Release PD and close device context
//   4. destroyContext() - Free device list

const std = @import("std");
const types = @import("types.zig");
const c = types.c;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during RDMA device operations.
pub const DeviceError = error{
    /// ibv_get_device_list() returned null.
    GetDeviceListFailed,
    /// No RDMA devices were found on the system.
    NoDevicesFound,
    /// The requested device index is out of range.
    InvalidDeviceIndex,
    /// ibv_open_device() returned null.
    OpenDeviceFailed,
    /// ibv_alloc_pd() returned null.
    AllocPdFailed,
    /// No active port found on the device.
    NoActivePort,
    /// ibv_query_port() failed.
    QueryPortFailed,
    /// ibv_query_gid() failed or returned a zero GID.
    QueryGidFailed,
    /// Device name not found in the device list.
    DeviceNotFound,
    /// ibv_query_device_ex() failed.
    QueryDeviceExFailed,
    /// Memory allocation failed.
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// Context lifecycle
// ---------------------------------------------------------------------------

/// Initialize the RDMA subsystem by enumerating available devices.
///
/// Calls ibv_get_device_list() to discover all RDMA devices on the system.
/// The returned context must be destroyed with destroyContext() when no
/// longer needed.
pub fn initContext() DeviceError!*types.RdmaContext {
    const ctx = std.heap.page_allocator.create(types.RdmaContext) catch {
        types.setLastError("failed to allocate RdmaContext");
        return DeviceError.OutOfMemory;
    };

    var num_devices: c_int = 0;
    const device_list = c.ibv_get_device_list(&num_devices);
    if (device_list == null) {
        std.heap.page_allocator.destroy(ctx);
        types.setLastError("ibv_get_device_list() failed");
        return DeviceError.GetDeviceListFailed;
    }

    ctx.* = types.RdmaContext{
        .device_list = device_list,
        .device_count = @intCast(num_devices),
        .initialized = true,
    };

    return ctx;
}

/// Tear down the RDMA context and release all resources.
///
/// Frees the device list obtained from ibv_get_device_list() and
/// deallocates the context struct. All devices opened from this context
/// must be closed before calling this function.
pub fn destroyContext(ctx: *types.RdmaContext) void {
    if (ctx.device_list) |list| {
        c.ibv_free_device_list(list);
    }
    ctx.initialized = false;
    std.heap.page_allocator.destroy(ctx);
}

/// Return the number of RDMA devices discovered during context initialization.
pub fn getDeviceCount(ctx: *types.RdmaContext) i32 {
    return ctx.device_count;
}

// ---------------------------------------------------------------------------
// Device open / close
// ---------------------------------------------------------------------------

/// Open an RDMA device by its index in the device list.
///
/// This function performs the full device initialization sequence:
///   1. Validate the index and open the device context
///   2. Allocate a Protection Domain (PD)
///   3. Find the first active port and query the specified GID
///   4. Check for hardware timestamp support
///   5. Populate the DeviceInfo struct with name, GID, and IP
///
/// On failure, all partially allocated resources are cleaned up before
/// returning the error.
pub fn openDevice(ctx: *types.RdmaContext, index: i32, gid_index: i32) DeviceError!*types.RdmaDevice {
    // Validate index bounds
    if (index < 0 or index >= ctx.device_count) {
        types.setLastError("device index out of range");
        return DeviceError.InvalidDeviceIndex;
    }

    // Access the device pointer from the device list array.
    // The device list is a C array of ibv_device pointers.
    const device_list = ctx.device_list orelse {
        types.setLastError("device list is null");
        return DeviceError.GetDeviceListFailed;
    };

    const dev_ptr_array: [*]?*c.ibv_device = @ptrCast(device_list);
    const device = dev_ptr_array[@intCast(index)] orelse {
        types.setLastError("device pointer at index is null");
        return DeviceError.InvalidDeviceIndex;
    };

    // Open the device context
    const ibv_ctx = c.ibv_open_device(device) orelse {
        types.setLastError("ibv_open_device() failed");
        return DeviceError.OpenDeviceFailed;
    };
    errdefer _ = c.ibv_close_device(ibv_ctx);

    // Allocate a Protection Domain
    const pd = c.ibv_alloc_pd(ibv_ctx) orelse {
        types.setLastError("ibv_alloc_pd() failed");
        return DeviceError.AllocPdFailed;
    };
    errdefer _ = c.ibv_dealloc_pd(pd);

    // Find the first active port and query GID
    const port_result = findActivePortAndGid(ibv_ctx, gid_index) orelse {
        // Error message already set by findActivePortAndGid
        return DeviceError.NoActivePort;
    };

    // Check hardware timestamp capability
    const has_hw_timestamps = queryHwTimestampSupport(ibv_ctx);

    // Get device name
    const dev_name_ptr = c.ibv_get_device_name(device);
    var device_name: [64]u8 = [_]u8{0} ** 64;
    if (dev_name_ptr != null) {
        const name_slice = std.mem.sliceTo(dev_name_ptr, 0);
        const copy_len = @min(name_slice.len, device_name.len - 1);
        @memcpy(device_name[0..copy_len], name_slice[0..copy_len]);
    }

    // Format GID and extract IP
    const gid_bytes = types.gidToBytes(port_result.gid);
    const gid_str = types.gidToString(gid_bytes);
    const ip_str = extractIPFromGID(gid_bytes);

    // Allocate and populate the device struct
    const dev = std.heap.page_allocator.create(types.RdmaDevice) catch {
        types.setLastError("failed to allocate RdmaDevice");
        return DeviceError.OutOfMemory;
    };

    dev.* = types.RdmaDevice{
        .ctx = ibv_ctx,
        .pd = pd,
        .port_num = port_result.port_num,
        .gid_index = @intCast(gid_index),
        .gid = port_result.gid,
        .device_info = types.DeviceInfo{
            .device_name = device_name,
            .gid = gid_str,
            .ip_addr = ip_str,
            .active_port = port_result.port_num,
            .active_gid_index = @intCast(gid_index),
        },
        .has_hw_timestamps = has_hw_timestamps,
    };

    return dev;
}

/// Open an RDMA device by name (e.g., "mlx5_0", "rxe0").
///
/// Iterates through the device list and finds the device with the matching
/// name, then delegates to the openDevice logic.
pub fn openDeviceByName(ctx: *types.RdmaContext, name: [*:0]const u8, gid_index: i32) DeviceError!*types.RdmaDevice {
    const device_list = ctx.device_list orelse {
        types.setLastError("device list is null");
        return DeviceError.GetDeviceListFailed;
    };

    const dev_ptr_array: [*]?*c.ibv_device = @ptrCast(device_list);
    const target_name = std.mem.sliceTo(name, 0);

    var i: i32 = 0;
    while (i < ctx.device_count) : (i += 1) {
        const device = dev_ptr_array[@intCast(i)] orelse continue;
        const dev_name_ptr = c.ibv_get_device_name(device);
        if (dev_name_ptr == null) continue;

        const dev_name = std.mem.sliceTo(dev_name_ptr, 0);
        if (std.mem.eql(u8, dev_name, target_name)) {
            return openDevice(ctx, i, gid_index);
        }
    }

    types.setLastError("device not found by name");
    return DeviceError.DeviceNotFound;
}

/// Close an RDMA device and free all associated resources.
///
/// Deallocates the Protection Domain, closes the device context, and
/// frees the RdmaDevice struct memory. All queues associated with this
/// device must be destroyed before calling this function.
pub fn closeDevice(dev: *types.RdmaDevice) void {
    _ = c.ibv_dealloc_pd(dev.pd);
    _ = c.ibv_close_device(dev.ctx);
    std.heap.page_allocator.destroy(dev);
}

// ---------------------------------------------------------------------------
// IP extraction from GID
// ---------------------------------------------------------------------------

/// Extract an IP address string from a 16-byte GID.
///
/// If the GID is an IPv4-mapped IPv6 address (bytes 0-9 are zero, bytes
/// 10-11 are 0xFF), the last 4 bytes are formatted as dotted-decimal IPv4.
/// Otherwise the full GID is formatted as colon-separated IPv6 hex groups.
pub fn extractIPFromGID(gid: [16]u8) [64]u8 {
    var result: [64]u8 = [_]u8{0} ** 64;

    // Check for IPv4-mapped IPv6: first 10 bytes zero, bytes 10-11 are 0xFF
    const is_ipv4_mapped = blk: {
        for (gid[0..10]) |b| {
            if (b != 0) break :blk false;
        }
        break :blk (gid[10] == 0xff and gid[11] == 0xff);
    };

    if (is_ipv4_mapped) {
        // Format as dotted-decimal IPv4: A.B.C.D
        var pos: usize = 0;
        for (0..4) |i| {
            if (i > 0) {
                result[pos] = '.';
                pos += 1;
            }
            pos += formatU8Decimal(result[pos..], gid[12 + i]);
        }
    } else {
        // Format as colon-separated hex groups (full IPv6 representation).
        // Each group is 2 bytes (4 hex digits), separated by colons.
        // Example: fe80:0000:0000:0000:0000:0000:0000:0001
        const hex_chars = "0123456789abcdef";
        var pos: usize = 0;
        for (0..8) |group| {
            if (group > 0) {
                result[pos] = ':';
                pos += 1;
            }
            const hi = gid[group * 2];
            const lo = gid[group * 2 + 1];
            result[pos] = hex_chars[hi >> 4];
            pos += 1;
            result[pos] = hex_chars[hi & 0x0f];
            pos += 1;
            result[pos] = hex_chars[lo >> 4];
            pos += 1;
            result[pos] = hex_chars[lo & 0x0f];
            pos += 1;
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Result of searching for an active port with a valid GID.
const PortGidResult = struct {
    port_num: u8,
    gid: c.ibv_gid,
};

/// Iterate over all physical ports to find the first active port with a
/// non-zero GID at the specified GID index.
///
/// Mirrors the Go OpenDevice() logic that iterates ports 1..phys_port_cnt,
/// queries each port's state, and checks the GID at the given index.
fn findActivePortAndGid(ibv_ctx: *c.ibv_context, gid_index: i32) ?PortGidResult {
    // Query device attributes to get the number of physical ports
    var device_attr: c.ibv_device_attr = std.mem.zeroes(c.ibv_device_attr);
    if (c.ibv_query_device(ibv_ctx, &device_attr) != 0) {
        types.setLastError("ibv_query_device() failed");
        return null;
    }

    const phys_port_cnt = device_attr.phys_port_cnt;
    if (phys_port_cnt == 0) {
        types.setLastError("device has 0 physical ports");
        return null;
    }

    // Iterate ports 1..phys_port_cnt (verbs API uses 1-based port numbers)
    var port_num: u8 = 1;
    while (port_num <= phys_port_cnt) : (port_num += 1) {
        var port_attr: c.ibv_port_attr = std.mem.zeroes(c.ibv_port_attr);
        if (c.ibv_query_port(ibv_ctx, port_num, &port_attr) != 0) {
            continue;
        }

        // Skip non-active ports
        if (port_attr.state != c.IBV_PORT_ACTIVE) {
            continue;
        }

        // Query the GID at the specified index on this active port
        var gid: c.ibv_gid = std.mem.zeroes(c.ibv_gid);
        if (c.ibv_query_gid(ibv_ctx, port_num, gid_index, &gid) != 0) {
            continue;
        }

        // Validate the GID is not all zeros
        const gid_bytes = types.gidToBytes(gid);
        var is_zero = true;
        for (gid_bytes) |b| {
            if (b != 0) {
                is_zero = false;
                break;
            }
        }
        if (is_zero) {
            continue;
        }

        return PortGidResult{
            .port_num = port_num,
            .gid = gid,
        };
    }

    types.setLastError("no usable GID found on any active port");
    return null;
}

/// Query whether the device supports hardware completion timestamps.
///
/// Uses ibv_query_device_ex() to get extended device attributes and checks
/// if hca_core_clock is non-zero, which indicates the device can provide
/// hardware timestamps on work completions.
fn queryHwTimestampSupport(ibv_ctx: *c.ibv_context) bool {
    var attr_ex: c.ibv_device_attr_ex = std.mem.zeroes(c.ibv_device_attr_ex);
    var input: c.ibv_query_device_ex_input = std.mem.zeroes(c.ibv_query_device_ex_input);

    if (c.ibv_query_device_ex(ibv_ctx, &input, &attr_ex) != 0) {
        // If the query fails, conservatively assume no HW timestamp support
        return false;
    }

    // A non-zero hca_core_clock indicates the device has a hardware clock
    // capable of generating completion timestamps.
    return (attr_ex.hca_core_clock != 0);
}

/// Format a u8 value as a decimal string into the output buffer.
/// Returns the number of characters written.
fn formatU8Decimal(buf: []u8, value: u8) usize {
    if (value >= 100) {
        buf[0] = '0' + (value / 100);
        buf[1] = '0' + ((value / 10) % 10);
        buf[2] = '0' + (value % 10);
        return 3;
    } else if (value >= 10) {
        buf[0] = '0' + (value / 10);
        buf[1] = '0' + (value % 10);
        return 2;
    } else {
        buf[0] = '0' + value;
        return 1;
    }
}

// ---------------------------------------------------------------------------
// C-ABI exported functions (called from Go via Cgo)
// ---------------------------------------------------------------------------

/// Initialize the RDMA subsystem and create a context.
///
/// Exported as `rdma_init` for the C ABI.
/// @param out_ctx  Receives the newly created context handle.
/// @return         0 on success, -1 on failure.
export fn rdma_init(out_ctx: *?*types.RdmaContext) i32 {
    const ctx = initContext() catch return -1;
    out_ctx.* = ctx;
    return 0;
}

/// Tear down the RDMA context and release all resources.
///
/// Exported as `rdma_destroy` for the C ABI.
export fn rdma_destroy(ctx_ptr: ?*types.RdmaContext) void {
    const ctx = ctx_ptr orelse return;
    destroyContext(ctx);
}

/// Return the number of available RDMA devices.
///
/// Exported as `rdma_get_device_count` for the C ABI.
/// @return  Number of devices (>= 0), or -1 if context is null.
export fn rdma_get_device_count(ctx_ptr: ?*types.RdmaContext) i32 {
    const ctx = ctx_ptr orelse return -1;
    return getDeviceCount(ctx);
}

/// Open an RDMA device by index.
///
/// Exported as `rdma_open_device` for the C ABI.
/// @return  0 on success, -1 on failure.
export fn rdma_open_device(
    ctx_ptr: ?*types.RdmaContext,
    index: i32,
    gid_index: i32,
    out_dev: *?*types.RdmaDevice,
    out_info: *types.DeviceInfo,
) i32 {
    const ctx = ctx_ptr orelse {
        types.setLastError("null context");
        return -1;
    };

    const dev = openDevice(ctx, index, gid_index) catch return -1;
    out_dev.* = dev;
    out_info.* = dev.device_info;
    return 0;
}

/// Open an RDMA device by name.
///
/// Exported as `rdma_open_device_by_name` for the C ABI.
/// @return  0 on success, -1 on failure.
export fn rdma_open_device_by_name(
    ctx_ptr: ?*types.RdmaContext,
    name: ?[*:0]const u8,
    gid_index: i32,
    out_dev: *?*types.RdmaDevice,
    out_info: *types.DeviceInfo,
) i32 {
    const ctx = ctx_ptr orelse {
        types.setLastError("null context");
        return -1;
    };
    const name_ptr = name orelse {
        types.setLastError("null device name");
        return -1;
    };

    const dev = openDeviceByName(ctx, name_ptr, gid_index) catch return -1;
    out_dev.* = dev;
    out_info.* = dev.device_info;
    return 0;
}

/// Close an RDMA device and free its resources.
///
/// Exported as `rdma_close_device` for the C ABI.
export fn rdma_close_device(dev_ptr: ?*types.RdmaDevice) void {
    const dev = dev_ptr orelse return;
    closeDevice(dev);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "extractIPFromGID with IPv4-mapped IPv6" {
    // ::ffff:192.168.1.100
    const gid = [16]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x64,
    };
    const result = extractIPFromGID(gid);
    const expected = "192.168.1.100";
    try std.testing.expectEqualStrings(expected, result[0..expected.len]);
    try std.testing.expectEqual(@as(u8, 0), result[expected.len]);
}

test "extractIPFromGID with IPv4-mapped 10.0.0.1" {
    // ::ffff:10.0.0.1
    const gid = [16]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
    };
    const result = extractIPFromGID(gid);
    const expected = "10.0.0.1";
    try std.testing.expectEqualStrings(expected, result[0..expected.len]);
    try std.testing.expectEqual(@as(u8, 0), result[expected.len]);
}

test "extractIPFromGID with full IPv6" {
    // fe80::1
    const gid = [16]u8{
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const result = extractIPFromGID(gid);
    const expected = "fe80:0000:0000:0000:0000:0000:0000:0001";
    try std.testing.expectEqualStrings(expected, result[0..expected.len]);
    try std.testing.expectEqual(@as(u8, 0), result[expected.len]);
}

test "extractIPFromGID with IPv4-mapped 255.255.255.255" {
    const gid = [16]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const result = extractIPFromGID(gid);
    const expected = "255.255.255.255";
    try std.testing.expectEqualStrings(expected, result[0..expected.len]);
}

test "extractIPFromGID with non-zero prefix is IPv6" {
    // Non-zero byte in first 10 bytes means it is not IPv4-mapped
    const gid = [16]u8{
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01,
    };
    const result = extractIPFromGID(gid);
    // Should format as IPv6, not IPv4
    const expected = "0000:0001:0000:0000:0000:ffff:c0a8:0101";
    try std.testing.expectEqualStrings(expected, result[0..expected.len]);
}

test "formatU8Decimal formats single digit" {
    var buf: [4]u8 = undefined;
    const len = formatU8Decimal(&buf, 5);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, '5'), buf[0]);
}

test "formatU8Decimal formats two digits" {
    var buf: [4]u8 = undefined;
    const len = formatU8Decimal(&buf, 42);
    try std.testing.expectEqual(@as(usize, 2), len);
    try std.testing.expectEqualStrings("42", buf[0..2]);
}

test "formatU8Decimal formats three digits" {
    var buf: [4]u8 = undefined;
    const len = formatU8Decimal(&buf, 255);
    try std.testing.expectEqual(@as(usize, 3), len);
    try std.testing.expectEqualStrings("255", buf[0..3]);
}

test "formatU8Decimal formats zero" {
    var buf: [4]u8 = undefined;
    const len = formatU8Decimal(&buf, 0);
    try std.testing.expectEqual(@as(usize, 1), len);
    try std.testing.expectEqual(@as(u8, '0'), buf[0]);
}
