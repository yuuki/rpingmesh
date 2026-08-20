// last_error.zig - Thread-local last-error string for the C ABI.
//
// Kept in its own module so ring.zig can record allocation failures without
// importing types.zig (types.zig already imports ring.zig for EventRing).

const std = @import("std");

/// Thread-local buffer for the last error message. Each thread gets its
/// own copy so concurrent RDMA operations do not clobber each other's
/// error strings. Initialized to all zeros (empty string).
threadlocal var last_error: [256]u8 = [_]u8{0} ** 256;

/// Store an error message in the thread-local error buffer.
///
/// The message is copied and null-terminated. If the input exceeds 255
/// bytes it is silently truncated to fit the buffer.
pub fn setLastError(msg: []const u8) void {
    // Explicit `usize` annotation matters here: @min's peer-type resolution
    // narrows its result to the smallest integer type that can hold the
    // known upper bound (last_error.len - 1 == 255 fits in a u8), so without
    // this annotation copy_len is inferred as u8. copy_len + 1 below then
    // overflows a u8 when copy_len == 255 (the max-length-message case),
    // triggering a safety-checked integer-overflow panic. Keeping copy_len
    // as usize keeps all arithmetic in the same domain as last_error.len.
    const copy_len: usize = @min(msg.len, last_error.len - 1);
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

test "setLastError and getLastError" {
    setLastError("test error message");
    const err = getLastError();
    const err_slice = std.mem.sliceTo(err, 0);
    try std.testing.expectEqualStrings("test error message", err_slice);
}

test "setLastError truncates long messages" {
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
