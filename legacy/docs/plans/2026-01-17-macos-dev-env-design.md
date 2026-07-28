# macOS Development and Unit Testing (Hardware-Independent) Investigation Notes

**Created:** 2026-01-17

## Background

RpingMesh depends on RDMA (`libibverbs`) and eBPF (Linux kernel), making it difficult to build, verify, and run unit tests in environments without specialized hardware like RDMA NICs.
Meanwhile, for local development (especially on macOS), fast feedback is important for "unit testing of logic", "config/CLI/serialization", and "control plane (gRPC/DB)".

This memo identifies blockers for setting up **a development environment where we can verify functionality and run unit tests on macOS**, and compares realistic approaches.

## Current Status (Measured)

When running the following on macOS (darwin), build failed at compilation stage (unable to compile before test execution).

Command:

```bash
go test ./... -run TestDoesNotExist -count=0
```

Main failure reasons (excerpts):

- `internal/rdma`: Build fails because `#include <infiniband/verbs.h>` is not found
  - Example: `internal/rdma/packet.go:5:11: fatal error: 'infiniband/verbs.h' file not found`
- `internal/ebpf`: Build fails because generated artifacts/dependencies don't exist on darwin
  - For M1/M2 (with `GOARCH=arm64`), `rdmatracing_x86_bpfel.go` assumes `amd64`, causing undefined types/functions
  - `github.com/cilium/ebpf/ringbuf` is Linux-specific API; types don't exist/aren't provided on darwin

As a consequence, `internal/agent` / `internal/monitor` / `internal/probe` / `internal/state` fail to build on darwin via `internal/rdma`.

## Blockers for macOS Support (Summary)

### 1) RDMA (cgo + libibverbs) Dependency Exposed at Package Boundary

- `internal/rdma` requires cgo and cannot compile on darwin.
- Furthermore, `internal/state` / `internal/probe` / `internal/monitor` / `internal/agent` strongly depend on concrete types from `internal/rdma` (e.g., `*rdma.RDMAManager`, `*rdma.RNIC`, `*rdma.UDQueue`).

→ **Cannot run `go test` on macOS unless OS/hardware dependencies are isolated using build tags and stubs/abstractions.**

### 2) eBPF is Linux (and Specific Architecture) Dependent

- `internal/ebpf/rdma_tracing.go` uses Linux-specific syscalls/rlimit/BTF/kprobe/ringbuf.
- Generated `rdmatracing_x86_bpfel.go` assumes `amd64`; on Apple Silicon (arm64) macOS, necessary types/functions don't exist for compilation.

→ **Practically, eBPF should be limited to Linux, with no-op/stub on non-Linux** (at least for unit test execution).

### 3) Docker/DevContainer's "Run on Linux" is Effective, but Apple Silicon Has Pitfalls

- `Dockerfile.agent` is fixed to `GOOS=linux GOARCH=amd64`.
- On Apple Silicon, Docker defaults to `linux/arm64`, risking **amd64 binary execution in arm64 container failure** (requires `--platform linux/amd64` or multiarch support).
- `.devcontainer/devcontainer.json` could be valid JSONC, but missing commas in the `mounts` array (at least in current appearance) may cause loading failures in real environments.

→ **"Developing on macOS" requires both "directly running `go test` on macOS host" and "running Linux containers/VMs on macOS"** - both options need clarification.

## Success Criteria (Goals)

**Minimum (Tier 1):**
- `go test ./...` on macOS **completes without compilation errors**; hardware-dependent tests are skipped
- Additional dependencies (rqlite, etc.) can be provided via Docker (can run `make test-local` on macOS)

**Desirable (Tier 2):**
- `cmd/agent` **starts in "RDMA/eBPF disabled" mode** on macOS, allowing verification of control plane communication (config loading, gRPC connection, DB access, etc.)

**Tier 3 (Selected for this plan):**
- **Integration tests including soft-RoCE + eBPF** can be reproduced on macOS Linux VM (lima/colima, etc.)

## Approach Options (Comparison)

### Option A (Recommended): build tags + stubs to "compile everything on macOS", run unit tests

Goal:
- Run unit tests of logic (config/registry/pinglist/prober/monitor pure logic) fast on macOS
- Parts touching RDMA/eBPF are Linux-only; on macOS they're no-op/stub and only compile

Specifics:
- Split `internal/rdma` into `linux && cgo` implementation and stub implementation for others (maintain types/method signatures)
- Split `internal/ebpf` into `linux` implementation and stub implementation for others
- For `internal/ebpf/*_test.go` tests that depend on real kernel, add `//go:build linux` to exclude from macOS build targets (or skip matching stub implementation)

Advantages:
- `go test ./...` runs on macOS (fast feedback)
- CI continues to ensure correctness on Linux/Docker

Disadvantages:
- Stub/abstraction design needed (code changes in short term)

### Option B: Support macOS Only via devcontainer/Docker (Give Up Host go test)

Goal:
- Maintain RDMA/eBPF environment via "running Linux on macOS"

Advantages:
- High compatibility with existing Docker-based workflow (`make test`)

Disadvantages:
- Due to Apple Silicon `linux/amd64` fixed builds and eBPF/privilege/kernel constraints, "won't work" risk remains
- Local lightweight unit test iteration becomes slow

### Option C: Prepare Linux VM (lima/colima) on macOS, Run `make test` There

Goal:
- Avoid Docker Desktop constraints, handle eBPF/soft-RoCE on Linux kernel

Advantages:
- Integration tests including eBPF/soft-RoCE easier to reproduce

Disadvantages:
- High onboarding cost (VM/network/privileges/soft-RoCE)
- Overkill if goal is "fast unit test iteration"

## Tier 3 Technical Considerations (Important)

### 1) Apple Silicon (arm64) and eBPF Artifact Architecture Alignment

Currently, `go:generate` in `internal/ebpf/rdma_tracing.go` is fixed to `-target amd64`, and generated Go bindings (`internal/ebpf/rdmatracing_x86_bpfel.go`) are `//go:build 386 || amd64`.
**On a linux/arm64 VM (e.g., Ubuntu VM running natively on Apple Silicon), the eBPF package won't build.**

To run Tier 3 natively on Apple Silicon, one of these is necessary:

- (Recommended) Multi-arch eBPF generation; provide `arm64` artifacts (e.g., `rdmatracing_arm64_bpfel.go` / `*.o`)
- Alternatively, run x86_64 (amd64) Linux VM (QEMU emulation on Apple Silicon is slow)

### 2) soft-RoCE (RXE) Setup

soft-RoCE uses `rdma_rxe` on Linux to treat existing NICs as RDMA devices (`rdma link add rxe0 type rxe netdev <iface>`).
VM network interface names vary by environment, so procedures assume `ip link` / `rdma link show`.

### 3) eBPF Execution Requirements

- debugfs mount (`/sys/kernel/debug`)
- `ulimit -l unlimited` (MEMLOCK)
- root privileges (or CAP_BPF/CAP_SYS_ADMIN)
- kprobe target functions (e.g., `ib_modify_qp_with_udata`) must exist in kernel

## Recommended Approach (Tier 3)

First, **achieve Tier 1 reliably with Option A (build tags + stubs)**, then **add Tier 3 with Option C (Linux VM)**.

Rationale:
- Current biggest pain point is "macOS `go test` won't even compile"
- RDMA/eBPF integration tests better suited to Linux (VM) for reproducibility and stability

## One Clarification Question

What Mac do you use?

1. Intel Mac (amd64)
2. Apple Silicon (arm64)

(For case 2, Tier 3 determination: "arm64 native VM + eBPF multi-arch" or "amd64 VM (emulation)" - which is preferable?)
