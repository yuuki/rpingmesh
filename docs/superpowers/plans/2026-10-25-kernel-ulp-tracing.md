# Kernel ULP Tracing Implementation Plan

**Goal:** Extend service tracing to kernel-owned connected QPs and investigate mlx5 DC visibility for issue #111.

**Architecture:** Keep the uverbs object independent of RDMA module BTF. Load a second, optional CO-RE object for kernel QP modify/destroy calls, sharing the event ring and counters. Keep kernel connections in a separate identity namespace and reconcile their lifetime against successful netlink inventories.

**Tech Stack:** Go 1.27.3, cilium/ebpf, clang/bpf2go, Linux RDMA CO-RE.

**Spec:** `docs/design/ebpf-service-tracing.md` and GitHub issue #111.

## Constraints

- Default behavior remains unchanged; module BTF and attachment failures disable only the extension.
- Kernel workers are not service owners; do not attribute their PID/cgroup to a service.
- Only successful transitions publish events. User QPs must not be counted twice.
- DC address handles and QP dumps alone are not evidence of a sent flow. Document unsupported paths rather than inventing destinations.
- Keep comments and documentation in English; do not modify legacy code.

## Tasks

- [x] Add portable kernel event decoding and separate table lifecycle tests, including reset/error/destroy, user/kernel identity collisions, and inventory/event races.
- [x] Add `bpf/kernel_trace.bpf.c` with minimal CO-RE types, success-only staging, and shared ring/counters. Generate amd64 and arm64 objects and extend `make check-bpf`.
- [x] Add optional loader and `service_tracing_kernel_ulp_enabled` configuration. Resolve kernel device names through the existing sysfs inventory before applying events.
- [x] Add loader integration checks and configuration/monitor tests. Run portable tests, Linux tests and verifier attachment checks where host capabilities permit.
- [x] Record kernel ULP constraints and source-backed DC investigation in the design documentation and README. Review the final diff and report any unverified hardware paths explicitly.

## Validation commands

```sh
go test ./internal/agent/servicetrace ./internal/config
BPF2GO_CC=/opt/homebrew/opt/llvm/bin/clang BPF2GO_STRIP=/opt/homebrew/opt/llvm/bin/llvm-strip make generate-bpf check-bpf
GOOS=linux GOARCH=amd64 go test -c -o /tmp/rpingmesh-servicetrace-amd64.test ./internal/agent/servicetrace
GOOS=linux GOARCH=arm64 go test -c -o /tmp/rpingmesh-servicetrace-arm64.test ./internal/agent/servicetrace
git diff --check
```

Linux tests use the existing RDMA Docker image with this checkout mounted at `/workspace`. Kernel verification requires root, vmlinux/module BTF, and loaded `ib_core`/`ib_uverbs` modules; hardware DC validation requires mlx5 and UCX workloads.

## Verification results

- Portable servicetrace/config tests and `go test -race` passed on macOS.
- Both BPF objects compiled for amd64/arm64; `make check-bpf` passed.
- Linux test binaries cross-compiled for amd64 and arm64.
- Linux arm64, Go 1.27.3, privileged Docker: `go test ./internal/agent/... ./internal/config/...`, `go vet ./internal/agent/... ./internal/config/...`, `make build-zig`, and `make build-agent` passed from a clean source directory.
- `TestKernelTracerOpenClose` passed against the running kernel with ib_core BTF, including CO-RE relocation and all four probe attachments. The first run caught enum/int CO-RE incompatibility; matching the kernel enum types fixed it.
- Independent read-only review found no actionable correctness defects.
- Actual kernel ULP workload event emission and mlx5 hardware port equivalence remain unverified. DC tracing is deliberately not implemented; the investigation and requirements are recorded in the design document, and #111 must not be closed as fully implemented.
