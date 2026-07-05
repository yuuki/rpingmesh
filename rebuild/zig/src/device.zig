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
///   3. Find the first active port and query the specified GID (also
///      validates the GID's RoCE type via sysfs; see logGidTypeInfo())
///   4. Populate the DeviceInfo struct with name, GID, and IP
///
/// `sl` and `traffic_class` are static, agent-configured values stored on
/// the returned device and later applied to every Address Handle created
/// for it (see createAddressHandle() in queue.zig); they do not affect
/// device discovery or GID selection.
///
/// On failure, all partially allocated resources are cleaned up before
/// returning the error.
pub fn openDevice(ctx: *types.RdmaContext, index: i32, gid_index: i32, sl: u8, traffic_class: u8) DeviceError!*types.RdmaDevice {
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

    // Get device name. This is needed both for the DeviceInfo struct below
    // and for the sysfs GID-type validation performed inside
    // findActivePortAndGid(), so it is extracted before that call.
    const dev_name_ptr = c.ibv_get_device_name(device);
    var device_name: [64]u8 = [_]u8{0} ** 64;
    var device_name_len: usize = 0;
    if (dev_name_ptr != null) {
        const name_slice = std.mem.sliceTo(dev_name_ptr, 0);
        device_name_len = @min(name_slice.len, device_name.len - 1);
        @memcpy(device_name[0..device_name_len], name_slice[0..device_name_len]);
    }

    // Find the first active port and query GID
    const port_result = findActivePortAndGid(ibv_ctx, gid_index, device_name[0..device_name_len]) orelse {
        // Error message already set by findActivePortAndGid
        return DeviceError.NoActivePort;
    };

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
        .sl = sl,
        .traffic_class = traffic_class,
        .device_info = types.DeviceInfo{
            .device_name = device_name,
            .gid = gid_str,
            .ip_addr = ip_str,
            .active_port = port_result.port_num,
            .active_gid_index = @intCast(gid_index),
        },
    };

    return dev;
}

/// Open an RDMA device by name (e.g., "mlx5_0", "rxe0").
///
/// Iterates through the device list and finds the device with the matching
/// name, then delegates to the openDevice logic. `sl` and `traffic_class`
/// are forwarded unchanged; see openDevice() for their meaning.
pub fn openDeviceByName(ctx: *types.RdmaContext, name: [*:0]const u8, gid_index: i32, sl: u8, traffic_class: u8) DeviceError!*types.RdmaDevice {
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
            return openDevice(ctx, i, gid_index, sl, traffic_class);
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
    const log = std.log.scoped(.rdma_device);

    // Log (rather than silently discard) failures from these teardown
    // calls. A non-zero return here typically means resources are still
    // referenced (e.g. a queue/QP was not destroyed first) and is useful
    // operational signal even though we cannot recover from it at this
    // point in the shutdown path.
    const dealloc_ret = c.ibv_dealloc_pd(dev.pd);
    if (dealloc_ret != 0) {
        log.err("ibv_dealloc_pd() failed with errno={d}", .{dealloc_ret});
    }

    const close_ret = c.ibv_close_device(dev.ctx);
    if (close_ret != 0) {
        log.err("ibv_close_device() failed with errno={d}", .{close_ret});
    }

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

/// Formats the diagnostic emitted when at least one active port was found
/// but the configured `gid_index` did not resolve to a usable GID on it
/// (either `ibv_query_gid()` failed -- e.g. the index is past the end of
/// the port's GID table -- or the entry it returned was all zeros).
///
/// This is deliberately distinct from the "no active port" case (see
/// findActivePortAndGid()): a caller reading "no usable GID found on any
/// active port" when a port *is* up but `gid_index` is simply wrong would
/// reasonably conclude the link itself is down, sending them down the wrong
/// debugging path. Naming the device, port, and GID table size lets an
/// operator immediately see that gid_index is out of range or unpopulated,
/// without needing to reproduce the failure with ibv_devinfo.
///
/// `gid_tbl_len` is the value ibv_query_port() reported for the port
/// (0 if the port attributes could not be queried at all, which should not
/// normally happen for a port already found to be active).
///
/// Returns the formatted message as a slice into `buf`. If `buf` is too
/// small to hold the formatted message, returns an empty slice as a safe
/// fallback (setLastError() also gracefully handles a slice longer than its
/// internal capacity, but bufPrint itself errors on overflow rather than
/// truncating).
fn formatInvalidGidIndexError(buf: []u8, dev_name: []const u8, port_num: u8, gid_index: i32, gid_tbl_len: i32) []const u8 {
    return std.fmt.bufPrint(
        buf,
        "gid_index={d} is invalid or not present on device {s} port {d} (GID table size {d}): " ++
            "active port found, but ibv_query_gid() failed or the entry is empty -- check " ++
            "gid_index is within [0, {d})",
        .{ gid_index, dev_name, port_num, gid_tbl_len, gid_tbl_len },
    ) catch buf[0..0];
}

/// Iterate over all physical ports to find the first active port with a
/// non-zero GID at the specified GID index.
///
/// Mirrors the Go OpenDevice() logic that iterates ports 1..phys_port_cnt,
/// queries each port's state, and checks the GID at the given index.
///
/// Once a usable GID is found, this also validates its RoCE GID type via
/// sysfs (see logGidTypeInfo()) and logs a warning if it is not RoCE v2 --
/// on real Mellanox hardware, gid_index 0 is commonly RoCE v1, which does
/// not interoperate with a RoCE v2 peer even though the GID itself is
/// non-zero and otherwise looks valid. This validation is purely
/// informational: the configured gid_index is still used as-is.
///
/// On failure, the error set via setLastError() distinguishes two distinct
/// root causes so operators are not misled into debugging the wrong layer:
///   1. No port on the device is active at all (link/cabling/switch issue).
///   2. An active port exists, but gid_index does not resolve to a usable
///      GID on it (misconfiguration -- see formatInvalidGidIndexError()).
fn findActivePortAndGid(ibv_ctx: *c.ibv_context, gid_index: i32, dev_name: []const u8) ?PortGidResult {
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

    // Remember the first active port encountered (and its GID table size)
    // so that, if no port yields a usable GID at gid_index, the failure
    // message can name a specific port instead of implying no port was
    // ever active.
    var first_active_port: ?u8 = null;
    var first_active_gid_tbl_len: i32 = 0;

    // Iterate ports 1..phys_port_cnt (verbs API uses 1-based port numbers)
    var port_num: u8 = 1;
    while (port_num <= phys_port_cnt) : (port_num += 1) {
        var port_attr: c.ibv_port_attr = std.mem.zeroes(c.ibv_port_attr);
        if (c.ibv_query_port(ibv_ctx, port_num, @ptrCast(&port_attr)) != 0) {
            continue;
        }

        // Skip non-active ports
        if (port_attr.state != c.IBV_PORT_ACTIVE) {
            continue;
        }

        if (first_active_port == null) {
            first_active_port = port_num;
            first_active_gid_tbl_len = @intCast(port_attr.gid_tbl_len);
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

        logGidTypeInfo(dev_name, port_num, gid_index);

        return PortGidResult{
            .port_num = port_num,
            .gid = gid,
        };
    }

    if (first_active_port) |p| {
        // Sized to comfortably fit the formatted message even in the
        // (unrealistic) worst case of a 63-byte device name and i32-max
        // gid_index/gid_tbl_len values -- see formatInvalidGidIndexError().
        var err_buf: [384]u8 = undefined;
        const msg = formatInvalidGidIndexError(&err_buf, dev_name, p, gid_index, first_active_gid_tbl_len);
        types.setLastError(msg);
    } else {
        types.setLastError("no active port found on any physical port (link down, cabling, or switch issue)");
    }
    return null;
}

// ---------------------------------------------------------------------------
// GID type validation (RoCE v1 vs RoCE v2) via sysfs
// ---------------------------------------------------------------------------
//
// libibverbs has no verbs-level API to query whether a given gid_index is
// RoCE v1, RoCE v1.5, or RoCE v2 -- the kernel exposes this only via sysfs:
//   /sys/class/infiniband/<dev>/ports/<port>/gid_attrs/types/<index>
// This matters in practice because production Mellanox NICs frequently
// populate gid_index 0 with a RoCE v1 entry (for legacy compatibility) and
// place the RoCE v2 (UDP/IP-routable) entry at a higher index. rdma_rxe
// (soft-RoCE, used in CI/dev) typically only ever creates RoCE v2 entries,
// which is why this class of misconfiguration would not be caught by
// soft-RoCE testing and only surfaces against real hardware.

/// Highest GID table index probed when searching for a RoCE v2 alternative.
/// 32 comfortably covers the GID table sizes exposed by mlx5 and rdma_rxe.
const MAX_GID_SEARCH_INDEX: i32 = 32;

/// Coarse classification of a GID table entry's RoCE type, as reported by
/// the kernel via sysfs gid_attrs/types/<index>.
const GidType = enum {
    roce_v1,
    roce_v1_5,
    roce_v2,
    infiniband,
    unknown,
};

/// Read and classify the GID type for (dev_name, port_num, gid_index) from
/// sysfs. Returns null if the sysfs file cannot be opened or read -- this is
/// expected on older kernels that predate the gid_attrs sysfs interface, or
/// in restricted containers without /sys mounted, and is not itself an
/// error.
fn readGidTypeFromSysfs(dev_name: []const u8, port_num: u8, gid_index: i32) ?GidType {
    if (dev_name.len == 0) return null;

    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(
        &path_buf,
        "/sys/class/infiniband/{s}/ports/{d}/gid_attrs/types/{d}",
        .{ dev_name, port_num, gid_index },
    ) catch return null;

    var file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    var content_buf: [64]u8 = undefined;
    const n = file.readAll(&content_buf) catch return null;
    const content = std.mem.trim(u8, content_buf[0..n], " \t\r\n");

    // Order matters: check the more specific "RoCE v2" before the "RoCE v1"
    // substring match. Known kernel strings: "IB/RoCE v1", "RoCE v2".
    if (std.mem.indexOf(u8, content, "RoCE v2") != null) return .roce_v2;
    if (std.mem.indexOf(u8, content, "RoCE v1.5") != null) return .roce_v1_5;
    if (std.mem.indexOf(u8, content, "RoCE v1") != null) return .roce_v1;
    if (std.mem.indexOf(u8, content, "IB") != null) return .infiniband;
    return .unknown;
}

/// Search gid_index 0..MAX_GID_SEARCH_INDEX on the given port for the first
/// entry classified as RoCE v2. Returns null if none is found (or if sysfs
/// is unavailable).
fn findFirstRoceV2GidIndex(dev_name: []const u8, port_num: u8) ?i32 {
    var idx: i32 = 0;
    while (idx < MAX_GID_SEARCH_INDEX) : (idx += 1) {
        if (readGidTypeFromSysfs(dev_name, port_num, idx)) |gt| {
            if (gt == .roce_v2) return idx;
        }
    }
    return null;
}

/// Log the GID type of the configured gid_index and warn if it is not
/// RoCE v2. This is purely diagnostic: it never changes which gid_index is
/// actually used, so behavior stays conservative and predictable. If a
/// RoCE v2 entry is found elsewhere on the same port, its index is logged
/// as a suggestion for the operator to update their configuration with.
fn logGidTypeInfo(dev_name: []const u8, port_num: u8, gid_index: i32) void {
    const log = std.log.scoped(.rdma_device);

    const gid_type = readGidTypeFromSysfs(dev_name, port_num, gid_index) orelse {
        log.warn(
            "could not determine RoCE GID type via sysfs for gid_index={d} on {s} port {d} " ++
                "(older kernel or /sys unavailable); proceeding without RoCE v1/v2 validation",
            .{ gid_index, dev_name, port_num },
        );
        return;
    };

    log.info("gid_index={d} on {s} port {d} has GID type {s}", .{ gid_index, dev_name, port_num, @tagName(gid_type) });

    if (gid_type != .roce_v2) {
        log.warn(
            "configured gid_index={d} on {s} port {d} is {s}, not RoCE v2; this is a common " ++
                "cause of unreachable peers on production Mellanox NICs, which often place a " ++
                "RoCE v1 entry at gid_index 0",
            .{ gid_index, dev_name, port_num, @tagName(gid_type) },
        );
        if (findFirstRoceV2GidIndex(dev_name, port_num)) |suggested| {
            log.warn(
                "found a RoCE v2 GID at gid_index={d} on {s} port {d}; consider updating the " ++
                    "gid_index configuration (not switched automatically to preserve explicit " ++
                    "configuration behavior)",
                .{ suggested, dev_name, port_num },
            );
        } else {
            log.warn("no RoCE v2 GID found on {s} port {d}", .{ dev_name, port_num });
        }
    }
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
    service_level: u8,
    traffic_class: u8,
    out_dev: *?*types.RdmaDevice,
    out_info: *types.DeviceInfo,
) i32 {
    const ctx = ctx_ptr orelse {
        types.setLastError("null context");
        return -1;
    };

    const dev = openDevice(ctx, index, gid_index, service_level, traffic_class) catch return -1;
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
    service_level: u8,
    traffic_class: u8,
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

    const dev = openDeviceByName(ctx, name_ptr, gid_index, service_level, traffic_class) catch return -1;
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

test "formatInvalidGidIndexError names the device, port, and gid_index" {
    var buf: [256]u8 = undefined;
    const msg = formatInvalidGidIndexError(&buf, "mlx5_0", 1, 100, 3);
    try std.testing.expect(std.mem.indexOf(u8, msg, "gid_index=100") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "mlx5_0") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "port 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "table size 3") != null);
}

test "formatInvalidGidIndexError does not claim no port is active" {
    var buf: [256]u8 = undefined;
    const msg = formatInvalidGidIndexError(&buf, "rxe0", 1, 5, 2);
    // The whole point of this message is to distinguish "gid_index is
    // wrong" from "no active port" -- it must never resemble the latter.
    try std.testing.expect(std.mem.indexOf(u8, msg, "no usable GID found on any active port") == null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "no active port") == null);
}

test "formatInvalidGidIndexError with a small buffer returns empty slice" {
    var buf: [8]u8 = undefined;
    const msg = formatInvalidGidIndexError(&buf, "mlx5_0", 1, 100, 3);
    try std.testing.expectEqual(@as(usize, 0), msg.len);
}
