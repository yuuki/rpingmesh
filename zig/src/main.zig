// main.zig - Root module for the Zig RDMA bridge library.
//
// This file serves as the single entry point for the library. It re-exports
// all sub-modules so they can be imported as a unit, forces the linker to
// include all C-ABI exported functions (critical for static library builds),
// and provides the top-level test runner.

const std = @import("std");

// ---------------------------------------------------------------------------
// Public module re-exports
//
// Consumers can import any sub-module via:
//   const rdma = @import("main.zig");
//   const ring = rdma.ring;
//   const dev  = rdma.device;
// ---------------------------------------------------------------------------

pub const types = @import("types.zig");
pub const wire = @import("wire.zig");
pub const last_error = @import("last_error.zig");
pub const ring = @import("ring.zig");
pub const device = @import("device.zig");
pub const memory = @import("memory.zig");
pub const queue = @import("queue.zig");
pub const cq = @import("cq.zig");
pub const packet = @import("packet.zig");

// ---------------------------------------------------------------------------
// C-ABI error reporting export
//
// Matches: const char* rdma_get_last_error(void) in rdma_bridge.h.
// ---------------------------------------------------------------------------

/// Return the last error message as a null-terminated C string.
///
/// The pointer is valid until the next call to any rdma_* function on the
/// same thread. Returns an empty string if no error has been recorded.
export fn rdma_get_last_error() [*:0]const u8 {
    return types.getLastError();
}

// ---------------------------------------------------------------------------
// Linker retention for C-ABI exports
//
// In a static library build, the linker may strip unreferenced symbols.
// Referencing each module that defines `export fn` symbols in a comptime
// block forces the compiler to emit them into the .a archive. The exports
// themselves are listed in include/rdma_bridge.h.
// ---------------------------------------------------------------------------

comptime {
    _ = ring;
    _ = device;
    _ = queue;
    _ = packet;
}

// ---------------------------------------------------------------------------
// Test entry point
//
// Running `zig build test` will execute all tests in every sub-module via
// this transitive reference.
// ---------------------------------------------------------------------------

test {
    _ = types;
    _ = wire;
    _ = last_error;
    _ = ring;
    _ = device;
    _ = memory;
    _ = queue;
    _ = cq;
    _ = packet;
}
