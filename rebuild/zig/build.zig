// build.zig - Zig build configuration for the RDMA bridge static library.
//
// Produces: zig-out/lib/librdmabridge.a
//           zig-out/include/rdma_bridge.h
//
// The static library is linked by Go/Cgo to call the RDMA functions
// defined in rdma_bridge.h. Cross-compilation targets x86_64-linux-gnu
// by default since RDMA (libibverbs/librdmacm) is Linux-only.

const std = @import("std");

pub fn build(b: *std.Build) void {
    // -----------------------------------------------------------------------
    // Target and optimization
    //
    // Default target: x86_64-linux-gnu (RDMA is only available on Linux).
    // Override at build time with -Dtarget=... if needed.
    // Default optimization: ReleaseSafe (optimized with runtime safety checks).
    // -----------------------------------------------------------------------
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .linux,
            .abi = .gnu,
        },
    });

    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });

    // -----------------------------------------------------------------------
    // Static library: librdmabridge.a
    // -----------------------------------------------------------------------
    const lib = b.addStaticLibrary(.{
        .name = "rdmabridge",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link the RDMA system libraries that the Zig code calls via @cImport.
    //   - rdmacm   : librdmacm  (RDMA connection management)
    //   - ibverbs   : libibverbs (InfiniBand verbs API)
    //   - c         : libc       (standard C library)
    lib.linkSystemLibrary("rdmacm");
    lib.linkSystemLibrary("ibverbs");
    lib.linkLibC();

    // Add the project include directory so @cInclude("rdma_bridge.h") resolves.
    lib.addIncludePath(b.path("include"));

    // Install the static library to zig-out/lib/librdmabridge.a
    b.installArtifact(lib);

    // Install the C header to zig-out/include/rdma_bridge.h so that
    // Go/Cgo and other C consumers can reference it.
    lib.installHeader(b.path("include/rdma_bridge.h"), "rdma_bridge.h");

    // -----------------------------------------------------------------------
    // Test step: zig build test
    //
    // Runs all unit tests defined in src/main.zig and transitively in every
    // sub-module. Tests also need the system libraries since the type
    // definitions reference libibverbs/librdmacm C structs.
    // -----------------------------------------------------------------------
    const lib_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_tests.linkSystemLibrary("rdmacm");
    lib_tests.linkSystemLibrary("ibverbs");
    lib_tests.linkLibC();

    lib_tests.addIncludePath(b.path("include"));

    const run_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
