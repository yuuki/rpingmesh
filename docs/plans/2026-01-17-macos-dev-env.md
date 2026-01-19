# macOS Development Environment (Hardware-Independent) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable `go test ./...` to run on macOS (darwin) by isolating RDMA/eBPF dependencies to Linux only (unit tests run without specialized hardware).

**Architecture:** Split RDMA/eBPF into `linux` implementation and `!linux` stub implementation using build tags. Upper layers (agent/monitor/probe/state) maintain a stub-compatible API (types/method signatures). Integration tests are directed to Linux (Docker/CI).

**Tech Stack:** Go build tags (`//go:build`), Go unit tests, Docker (rqlite provisioning), (optional) DevContainer

---

### Task 1: Reproduce Current Failure and Lock Down Goals

**Files:**
- Modify: `docs/plans/2026-01-17-macos-dev-env-design.md`

**Step 1: Reproduce Failure (macOS)**

Run: `go test ./... -run TestDoesNotExist -count=0`
Expected: `internal/rdma` missing `infiniband/verbs.h`, and `internal/ebpf` undefined errors occur

**Step 2: Define Goals**

- `go test ./...` runs to completion on macOS (required tests skip, zero compilation errors)
- `make test` continues to work on Linux as before (at minimum, don't break it)

**Step 3: Commit**

If only updating `docs`:
```bash
git add docs/plans/2026-01-17-macos-dev-env-design.md
git commit -m "docs: add macOS dev env investigation notes"
```

---

### Task 2: Split `internal/ebpf` into Linux Implementation and Stub

**Files:**
- Modify: `internal/ebpf/rdma_tracing.go`
- Create: `internal/ebpf/rdma_tracing_linux.go`
- Create: `internal/ebpf/rdma_tracing_stub.go`
- Modify: `internal/ebpf/bpf_integration_test.go`
- Modify: `internal/ebpf/bpf_e2e_test.go`

**Step 1: Separate Types/Constants to OS-Independent Code**

- Move `RdmaConnTuple` / constants / helpers (like `EventTypeString()`) to **files with no import dependencies**
- Perform struct size validation in `init()` for Linux only (don't panic in stub environments)

**Step 2: Create Linux Implementation File**

`internal/ebpf/rdma_tracing_linux.go` (example):

```go
//go:build linux

package ebpf

// Move existing ServiceTracer implementation here (depends on ringbuf/kprobe/BTF/rlimit)
```

**Step 3: Create Non-Linux Stub**

`internal/ebpf/rdma_tracing_stub.go` (example):

```go
//go:build !linux

package ebpf

import "fmt"

type ServiceTracer struct{}

func NewServiceTracer() (*ServiceTracer, error) { return nil, fmt.Errorf("ebpf: unsupported on this OS") }
func (t *ServiceTracer) Start() error           { return fmt.Errorf("ebpf: unsupported on this OS") }
func (t *ServiceTracer) Stop() error            { return nil }
func (t *ServiceTracer) Events() <-chan RdmaConnTuple {
	ch := make(chan RdmaConnTuple)
	close(ch)
	return ch
}
func (t *ServiceTracer) GetStatistics() (map[string]uint64, error) { return map[string]uint64{}, nil }
```

**Step 4: Limit Tests to Linux**

- Add `//go:build linux` to `internal/ebpf/bpf_integration_test.go` and `internal/ebpf/bpf_e2e_test.go`
- On macOS, `internal/ebpf` tests will be excluded from compilation targets, and upper layers build successfully with stubs

**Step 5: Local Verification (macOS)**

Run: `go test ./internal/ebpf -run TestDoesNotExist -count=0`
Expected: PASS (tests don't execute but compilation succeeds)

**Step 6: Commit**

```bash
git add internal/ebpf
git commit -m "fix: make ebpf package buildable on non-linux"
```

---

### Task 3: Split `internal/rdma` into Linux+Cgo Implementation and Stub

**Files:**
- Modify: `internal/rdma/device.go`
- Modify: `internal/rdma/queue.go`
- Modify: `internal/rdma/cq.go`
- Modify: `internal/rdma/packet.go`
- Create: `internal/rdma/rdma_stub.go`
- (If needed) Create: `internal/rdma/types.go`

**Step 1: Add Build Tags to Linux+Cgo Files**

Add to the beginning of each file (example):

```go
//go:build linux && cgo
```

**Step 2: Add Non-Linux Stub**

Define types/functions/methods referenced by upper layers in `internal/rdma/rdma_stub.go` (example):

- `type RNIC struct { DeviceName, GID, IPAddr string; ProberQueue, ResponderQueue *UDQueue; ... }`
- `type RDMAManager struct { Devices []*RNIC }`
- `func NewRDMAManager() (*RDMAManager, error)` (returns `unsupported`)
- `func (m *RDMAManager) CreateSenderAndResponderQueues(...) error` (`unsupported`)
- `type UDQueue struct { RNIC *RNIC; QPN uint32; QueueType UDQueueType }`
- `func (u *UDQueue) SendProbePacket(...) (time.Time, error)` (`unsupported`)
- `func (u *UDQueue) ReceivePacket(...) (*ProbePacket, time.Time, *ProcessedWorkCompletion, error)` (`unsupported`)
- `func (u *UDQueue) Destroy()` (no-op)

**Step 3: Organize Test Handling**

- For `TestRDMAEnvironmentDetection` in `internal/rdma/device_test.go`, ensure it naturally skips when the stub's `NewRDMAManager()` returns an error (current implementation is close to this)
- For "pure Go" tests (packet structures, serialization, etc.) that should run on macOS, move necessary types to `types.go` (avoid cgo dependencies)

**Step 4: Local Verification (macOS)**

Run: `go test ./internal/rdma -count=1`
Expected: PASS (hardware-dependent tests skip, rest succeed)

**Step 5: Commit**

```bash
git add internal/rdma
git commit -m "fix: make rdma package buildable on non-linux via stubs"
```

---

### Task 4: Verify Upper-Layer Packages (agent/state/monitor/probe) Build on macOS

**Files:**
- Modify (if needed): `internal/ebpf/*`, `internal/rdma/*` (if missing APIs appear)

**Step 1: Compilation Verification**

Run: `go test ./... -run TestDoesNotExist -count=0`
Expected: PASS (zero compilation errors)

**Step 2: Execute Unit Tests**

Run: `go test ./... -count=1`
Expected: PASS (tests requiring rqlite handled separately)

**Step 3: Commit**

```bash
git add -A
git commit -m "test: enable running unit tests on macOS"
```

---

### Task 5: Make rqlite Dependency Easy to Launch on macOS

**Files:**
- Create: `scripts/rqlite-local-up.sh`
- Create: `scripts/rqlite-local-down.sh`
- Modify: `Makefile`
- (Optional) Create: `docs/dev/macos.md`

**Step 1: rqlite Startup Scripts**

`scripts/rqlite-local-up.sh` (example):

```bash
#!/usr/bin/env bash
set -euo pipefail
docker run --rm -d --name rpingmesh-rqlite -p 4001:4001 rqlite/rqlite:8.37.0 -http-addr "0.0.0.0:4001"
```

`scripts/rqlite-local-down.sh` (example):

```bash
#!/usr/bin/env bash
set -euo pipefail
docker rm -f rpingmesh-rqlite 2>/dev/null || true
```

**Step 2: Add Makefile Targets**

- `make rqlite-up` / `make rqlite-down`
- Document prerequisites for `make test-local` in README/Docs

**Step 3: Local Verification**

Run: `make rqlite-up`
Run: `make test-local`
Run: `make rqlite-down`

**Step 4: Commit**

```bash
git add scripts Makefile docs/dev/macos.md
git commit -m "chore: add rqlite helpers for local testing"
```

---

### Task 6: (Optional) Explicitly Pin Platform for Docker Workflow on Apple Silicon

**Files:**
- Modify: `docker-compose.test.yml`
- Modify: `docker-compose.build.yml`
- Modify: `docker-compose.yml`

**Step 1: Add `platform: linux/amd64`**

Add to services that execute `GOARCH=amd64` binaries only (e.g., `agent_test` / `agent` / `agent-builder`).

**Step 2: Local Verification**

Run: `docker compose -f docker-compose.test.yml up --build agent_test --abort-on-container-exit`

**Step 3: Commit**

```bash
git add docker-compose*.yml
git commit -m "chore: pin linux/amd64 platform for agent containers"
```

---

### Task 7: Create Tier 3 (Linux VM) Integration Test Environment with soft-RoCE + eBPF

**Files:**
- Modify: `docs/plans/2026-01-17-macos-dev-env-design.md:1`
- Create: `docs/dev/macos-colima-vm.md`

**Step 1: Decide Which VM to Use (Decision Point)**

- Intel Mac: Can assume `linux/amd64` VM
- Apple Silicon (current choice):
  - `colima` with `linux/arm64` native VM (recommended)
  - Prerequisite: multi-arch eBPF generation (Task 8)

**Step 2: Launch Linux VM and Mount Repository to VM**

VM options:
- lima
- colima
- multipass

Fix to current choice (colima) with detailed steps in `docs/dev/macos-colima-vm.md`.

**Step 3: Install Build/Runtime Dependencies in VM (Example: Debian/Ubuntu)**

Examples (package names vary by distribution):
- Go (verify with `go env`)
- `clang`, `llvm`, `libbpf-dev`, `bpftool`, `libelf-dev`, `pkg-config`
- `libibverbs-dev`, `librdmacm-dev`, `rdma-core`
- `linux-headers-$(uname -r)` (if available)
- `protobuf-compiler` (if `make generate-proto` is needed)
- `iproute2`, `iputils-ping`

**Step 4: Enable soft-RoCE (RXE)**

Example:
```bash
sudo modprobe rdma_rxe
ip link
rdma link show
sudo rdma link add rxe0 type rxe netdev <VM_NIC_NAME>
rdma link show
```

**Step 5: Satisfy eBPF Execution Prerequisites**

Example:
```bash
sudo mount -t debugfs none /sys/kernel/debug || true
ulimit -l unlimited || true
```

**Step 6: Run Integration Tests**

Minimum:
- `make generate` (if VM can generate)
- `go test ./...`

To include RDMA/eBPF:
- Run targeted tests with `-run` flag, keeping logs of Skip/Fail reasons

**Step 7: Document Results**

Record in `docs/dev/macos-colima-vm.md`:
- VM type/OS/kernel/architecture (`uname -a`)
- RXE setup procedure (interface name used)
- `go test` execution results (success/skip/fail logs)

---

### Task 8: (Recommended for Apple Silicon) Generate Multi-Arch eBPF Bindings for linux/arm64 VM

**Files:**
- Modify: `internal/ebpf/rdma_tracing.go`
- Run: `make generate-bpf` (in VM)
- Create (generated): `internal/ebpf/rdmatracing_arm64_bpfel.go`, etc.

**Step 1: Add `-target` to bpf2go to Enable arm64 Generation**

Approach example:
- Split `go:generate` into two invocations for `amd64` and `arm64`
- Commit generated files following bpf2go conventions (don't hand-edit)

**Step 2: Run `make generate-bpf` in linux/arm64 VM**

Run: `make generate-bpf`
Expected: arm64 `*_bpfel.go` and `*.o` files are generated

**Step 3: Run `go test ./internal/ebpf -count=1` in linux/arm64 VM**

Expected:
- Skip if permissions/features insufficient (but compilation succeeds)
- Load eBPF successfully if all conditions are met

**Step 4: Commit**

```bash
git add internal/ebpf
git commit -m "feat: generate ebpf bindings for arm64"
```
