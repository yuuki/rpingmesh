// build.zig - Zig build configuration for the RDMA bridge static library.
//
// Produces: zig-out/lib/librdmabridge.a
//           zig-out/include/rdma_bridge.h
//
// The static library is linked by Go/Cgo to call the RDMA functions
// defined in rdma_bridge.h. Compiles for the native target architecture.
// Requires: libibverbs-dev, librdmacm-dev (Linux only).
//
// Compatible with Zig 0.15.x build API (uses createModule + addLibrary).

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Use native target and ReleaseSafe optimization.
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });

    // -----------------------------------------------------------------------
    // Root module for librdmabridge.a
    // -----------------------------------------------------------------------
    const lib_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lib_module.linkSystemLibrary("rdmacm", .{});
    lib_module.linkSystemLibrary("ibverbs", .{});
    lib_module.addIncludePath(b.path("include"));

    // -----------------------------------------------------------------------
    // Static library: librdmabridge.a
    // -----------------------------------------------------------------------
    const lib = b.addLibrary(.{
        .name = "rdmabridge",
        .root_module = lib_module,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // -----------------------------------------------------------------------
    // Test step: zig build test
    //
    // Runs all unit tests defined in src/main.zig and transitively in every
    // sub-module. Tests also need the system libraries since the type
    // definitions reference libibverbs/librdmacm C structs.
    // -----------------------------------------------------------------------
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_module.linkSystemLibrary("rdmacm", .{});
    test_module.linkSystemLibrary("ibverbs", .{});
    test_module.addIncludePath(b.path("include"));

    const lib_tests = b.addTest(.{
        .root_module = test_module,
    });
    const run_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
