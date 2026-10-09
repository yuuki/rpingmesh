// build.zig - Zig build configuration for the RDMA bridge static library.
//
// Produces: zig-out/lib/librdmabridge.a
//           zig-out/include/rdma_bridge.h
//
// The static library is linked by Go/Cgo to call the RDMA functions
// defined in rdma_bridge.h. Compiles for the native target architecture.
// Requires: libibverbs-dev, librdmacm-dev (Linux only).
//
// Requires Zig 0.17.x. C bindings come from a TranslateC step (src/c.h)
// because Zig 0.16 removed the @cImport builtin.

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Default to the host OS/arch but the *baseline* CPU model, not the
    // build machine's CPU: the library ships inside release binaries built on
    // CI runners, and native CPU features leak vendor-specific instructions
    // (e.g. AMD SSE4a `insertq` from an EPYC runner traps with SIGILL on Intel
    // Xeon hosts). Pass -Dcpu=native for a host-tuned local build.
    const target = b.standardTargetOptions(.{
        .default_target = .{ .cpu_model = .baseline },
    });
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });

    // -----------------------------------------------------------------------
    // C bindings (libibverbs, librdmacm, libc) imported as module "c"
    // -----------------------------------------------------------------------
    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate_c.addIncludePath(b.path("include"));
    const c_module = translate_c.createModule();

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
    lib_module.addImport("c", c_module);

    // -----------------------------------------------------------------------
    // Static library: librdmabridge.a
    // -----------------------------------------------------------------------
    const lib = b.addLibrary(.{
        .name = "rdmabridge",
        .root_module = lib_module,
        .linkage = .static,
        // Always emit objects through LLVM. Zig 0.15's self-hosted x86_64
        // backend (the Debug default) emits local-dynamic TLS relocations
        // (R_X86_64_DTPOFF32) and DWARF 5 forms that older system linkers,
        // e.g. GNU ld 2.35 on RHEL/Rocky 9, fail to link into the cgo binary.
        .use_llvm = true,
    });
    // The archive is linked by the system C toolchain (via cgo), not by Zig,
    // so compiler-rt symbols the LLVM backend references (for example
    // __zig_probe_stack in ReleaseSafe) must travel inside the archive.
    lib.bundle_compiler_rt = true;
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
    test_module.addImport("c", c_module);

    const lib_tests = b.addTest(.{
        .root_module = test_module,
    });
    const run_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
