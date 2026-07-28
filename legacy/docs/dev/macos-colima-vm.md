# macOS (Apple Silicon) + Colima: Running Tier 3 (soft-RoCE + eBPF) Integration Tests

Target: Use `colima` on macOS (arm64) to run RpingMesh's RDMA/eBPF verification and testing on a Linux VM.

## Alternative: Using Devcontainer (Recommended)

As a simpler setup option, you can use a pre-configured devcontainer:

- **See [Devcontainer RDMA Setup Guide](./devcontainer-rdma-setup.md)**
- **Benefits:**
  - Automatic environment setup
  - Pre-installed tools and dependencies
  - Validation checks on startup
  - Helper scripts for troubleshooting
  - Automatic configuration of privileged mode and required capabilities
  - Full eBPF and RDMA support
- **Scope:** Both RDMA development environment (soft-RoCE) and eBPF development

**Combining Colima + Devcontainer is the most recommended development environment.**

Use this guide if you want to run directly on Colima VM instead of devcontainer.

### Notes When Using Devcontainer in Colima Environment

If using devcontainer in a Colima environment:

1. **devcontainer.json configuration required**
   - `--privileged` mode
   - `CAP_BPF` capability
   - `/sys/kernel/debug` debugfs mount

2. **Use diagnostic tools**
   ```bash
   # Run inside container
   .devcontainer/check-rdma-readiness.sh
   ```

3. **Known limitations**
   - eBPF CO-RE Relocation: Compatibility issues with Colima kernel may occur
   - `/sys/kernel/btf` is readable but may be restricted by module configuration
   - Workaround: Skip eBPF tests or use alternative verification methods

## Goals (Success Criteria)

- Repository is accessible (mounted) inside Linux VM
- `rdma_rxe` (soft-RoCE) can be enabled in VM (`rdma link show` displays RXE)
- eBPF execution prerequisites are met in VM (debugfs / memlock / privileges)
- `go test ./...` can run in VM (if failures occur, reasons are documented reproducibly)

## 0. Prerequisites

- Homebrew is available
- `docker` CLI is installed
- (Recommended) Install `clang/llvm/libbpf-dev/bpftool` etc. in VM so `make generate-bpf` can run
- eBPF artifacts **must support arm64** (see "multi-arch" in `docs/plans/2026-01-17-macos-dev-env-design.md`)

## 1. Starting Colima (Example)

On host macOS:

```bash
colima start --arch aarch64 --cpu 6 --memory 10 --disk 80
colima status
```

Reference (measured):
- colima: 0.9.1
- VM OS: Ubuntu 24.04.1 LTS
- kernel: 6.8.0-50-generic
- arch: aarch64

Enter VM:

```bash
colima ssh
```

Basic verification in VM:

```bash
uname -a
cat /etc/os-release
ip link
df -h
```

## 2. Verify Repository is Accessible from VM

Whether macOS home directory is visible from VM varies by environment. First, check with one of:

```bash
ls /Users || true
ls $HOME || true
```

If repository is visible (example):

```bash
cd /Users/y-tsubouchi/src/github.com/yuuki/rpingmesh
```

If not visible, adjust colima mount settings first to **make source accessible from VM**.

## 3. Install Dependencies in VM

Check OS, then install for Debian/Ubuntu (package names may vary):

```bash
sudo apt-get update
sudo apt-get install -y \
  git curl ca-certificates \
  clang llvm bpftool libbpf-dev libelf-dev pkg-config \
  rdma-core libibverbs-dev librdmacm-dev \
  iproute2 iputils-ping \
  linux-headers-$(uname -r) || true
```

Notes (measured on Ubuntu 24.04 / arm64):
- `bpftool` is in `linux-tools-common` / `linux-tools-$(uname -r)`, add if needed
- `ibv_devinfo` requires `ibverbs-utils`
- RDMA cgo build requires `build-essential`

Additional commands actually used:

```bash
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r) || true
sudo apt-get install -y ibverbs-utils
sudo apt-get install -y build-essential
```

To install Go 1.24.3 (arm64) on VM:

```bash
GO_VERSION=1.25
curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz -o /tmp/go${GO_VERSION}.linux-arm64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go${GO_VERSION}.linux-arm64.tar.gz
echo "export PATH=/usr/local/go/bin:\$PATH" | sudo tee /etc/profile.d/go.sh >/dev/null
export PATH=/usr/local/go/bin:$PATH
go version
```

Verify RDMA/eBPF:

```bash
bpftool version || true
rdma version || true
ibv_devinfo || true
```

## 4. Enable soft-RoCE (RXE)

Load modules:

```bash
sudo modprobe rdma_rxe
sudo modprobe ib_core || true
sudo modprobe ib_uverbs || true
```

Check VM's NIC name (example: `eth0`):

```bash
ip link
ip route
```

Create RXE device:

```bash
sudo rdma link add rxe0 type rxe netdev <VM_NIC_NAME>
rdma link show
```

Verification (if `/sys/class/infiniband` exists, environment is close to expected):

```bash
ls -la /sys/class/infiniband || true
ibv_devinfo | head -n 40 || true
```

Example measured logs:
- `rdma link show` displays `rxe0/1 state ACTIVE ... netdev eth0`
- `ibv_devinfo` confirms `hca_id: rxe0`

Key points when failures occur:
- `modprobe rdma_rxe` fails (module missing/kernel config issue)
- `rdma link add` fails (rdma-core not installed/interface name error/permission issue)

## 5. Meet eBPF Execution Prerequisites

debugfs:

```bash
sudo mount -t debugfs none /sys/kernel/debug || true
```

memlock:

```bash
ulimit -l unlimited || true
```

(Optional) Check if kprobe target functions exist:

```bash
sudo grep -w "ib_modify_qp_with_udata" /proc/kallsyms | head -n 5 || true
```

Notes (measured):
- `/sys/kernel/btf/ib_core` and `/sys/kernel/btf/ib_uverbs` exist

## 6. Running Tests/Verification (in VM)

### 6.1 First: Compilation/Unit Tests (Excluding Hardware Dependencies)

```bash
go version
go test ./... -count=1
```

### 6.2 Tests Including RDMA/eBPF (Only if Environment is Ready)

eBPF loading (requires privileges):

```bash
sudo -E go test ./internal/ebpf -run TestBPFProgramLoading -count=1 -v
```

RDMA device detection (assuming soft-RoCE is installed):

```bash
sudo -E go test ./internal/rdma -run TestRDMAEnvironmentDetection -count=1 -v
```

Measured results:
- `TestRDMAEnvironmentDetection` passes with soft-RoCE (rxe0)
- eBPF **may SKIP with CO-RE relocation error** in some cases
  - Example: `bad CO-RE relocation: invalid func unknown#...`
  - This likely indicates `/sys/kernel/btf` is readable but kernel/module configuration or CO-RE compatibility is the issue

## 7. Troubleshooting When Things Don't Work

- `internal/ebpf` won't build: eBPF artifacts likely fixed to `amd64` (multi-arch needed)
- `modprobe rdma_rxe` fails: Colima VM kernel lacks RXE (VM/kernel selection needs review)
- eBPF loading fails: Check debugfs/memlock/privileges/kernel function availability (`ib_*`) in order

## 8. Measured Environment Notes (Verification Results for This Repository)

- colima: 0.9.1
- VM: Ubuntu 24.04.1 LTS / kernel 6.8.0-50-generic / aarch64
- mount: `/Users/y-tsubouchi` visible via virtiofs
- RDMA: `rxe0` created via `rdma_rxe`, verified with `ibv_devinfo`
- eBPF: `TestBPFProgramLoading` skipped due to CO-RE relocation error (requires further investigation)
