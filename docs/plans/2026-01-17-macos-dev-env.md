# macOS開発環境（ハードウェア非依存） Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** macOS（darwin）上で `go test ./...` を実行できるようにし、RDMA/eBPF 依存部分は Linux 専用として隔離する（ハードウェアがなくても単体テストが回る）。

**Architecture:** RDMA/eBPF を build tag で `linux` 実装と `!linux` スタブ実装に分離し、上位層（agent/monitor/probe/state）はスタブでもコンパイル可能な API（型/メソッドシグネチャ）を維持する。統合テストは Linux（Docker/CI）に寄せる。

**Tech Stack:** Go build tags（`//go:build`）、Go 単体テスト、Docker（rqlite 供給）、（任意）DevContainer

---

### Task 1: 現状の失敗を再現し、ゴールを固定する

**Files:**
- Modify: `docs/plans/2026-01-17-macos-dev-env-design.md`

**Step 1: 失敗再現（macOS）**

Run: `go test ./... -run TestDoesNotExist -count=0`
Expected: `internal/rdma` の `infiniband/verbs.h` 不在、および `internal/ebpf` の未定義エラーが発生

**Step 2: ゴール定義**

- macOS で `go test ./...` が完走（必要なテストは Skip、コンパイルエラーはゼロ）
- Linux では従来通り `make test` が動く（少なくとも壊さない）

**Step 3: Commit**

`docs` の更新のみでコミットする場合:
```bash
git add docs/plans/2026-01-17-macos-dev-env-design.md
git commit -m "docs: add macOS dev env investigation notes"
```

---

### Task 2: `internal/ebpf` を linux 実装とスタブに分割する

**Files:**
- Modify: `internal/ebpf/rdma_tracing.go`
- Create: `internal/ebpf/rdma_tracing_linux.go`
- Create: `internal/ebpf/rdma_tracing_stub.go`
- Modify: `internal/ebpf/bpf_integration_test.go`
- Modify: `internal/ebpf/bpf_e2e_test.go`

**Step 1: 型/定数を OS 非依存に分離**

- `RdmaConnTuple` / 定数群 / ヘルパー（`EventTypeString()` 等）を **import 依存のないファイル**へ移す
- `init()` の struct サイズ検証は linux のみで実施（スタブ環境では panic しない）

**Step 2: Linux 実装ファイルを作る**

`internal/ebpf/rdma_tracing_linux.go`（例）:

```go
//go:build linux

package ebpf

// 既存の ServiceTracer 実装（ringbuf/kprobe/BTF/rlimit 依存）をここへ移動
```

**Step 3: 非 Linux スタブを作る**

`internal/ebpf/rdma_tracing_stub.go`（例）:

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

**Step 4: テストを linux 限定にする**

- `internal/ebpf/bpf_integration_test.go` と `internal/ebpf/bpf_e2e_test.go` に `//go:build linux` を追加
- macOS では `internal/ebpf` のテストがコンパイル対象外になり、スタブで上位層はビルド可能になる

**Step 5: ローカル検証（macOS）**

Run: `go test ./internal/ebpf -run TestDoesNotExist -count=0`
Expected: PASS（テスト実行はしないがコンパイルが通る）

**Step 6: Commit**

```bash
git add internal/ebpf
git commit -m "fix: make ebpf package buildable on non-linux"
```

---

### Task 3: `internal/rdma` を linux+cgo 実装とスタブに分割する

**Files:**
- Modify: `internal/rdma/device.go`
- Modify: `internal/rdma/queue.go`
- Modify: `internal/rdma/cq.go`
- Modify: `internal/rdma/packet.go`
- Create: `internal/rdma/rdma_stub.go`
- (必要なら) Create: `internal/rdma/types.go`

**Step 1: linux+cgo ファイルに build tag を付与**

各ファイル先頭に付与（例）:

```go
//go:build linux && cgo
```

**Step 2: 非 Linux 用スタブを追加**

`internal/rdma/rdma_stub.go` に、上位層が参照する型/関数/メソッドを定義する（例）:

- `type RNIC struct { DeviceName, GID, IPAddr string; ProberQueue, ResponderQueue *UDQueue; ... }`
- `type RDMAManager struct { Devices []*RNIC }`
- `func NewRDMAManager() (*RDMAManager, error)`（`unsupported` を返す）
- `func (m *RDMAManager) CreateSenderAndResponderQueues(...) error`（`unsupported`）
- `type UDQueue struct { RNIC *RNIC; QPN uint32; QueueType UDQueueType }`
- `func (u *UDQueue) SendProbePacket(...) (time.Time, error)`（`unsupported`）
- `func (u *UDQueue) ReceivePacket(...) (*ProbePacket, time.Time, *ProcessedWorkCompletion, error)`（`unsupported`）
- `func (u *UDQueue) Destroy()`（no-op）

**Step 3: テストの扱いを整理**

- `internal/rdma/device_test.go` の `TestRDMAEnvironmentDetection` は、スタブの `NewRDMAManager()` がエラーを返すことで自然に Skip されるようにする（現在の実装はその形に近い）
- “純 Go” のテスト（パケット構造・シリアライズ等）は macOS でも走らせたい場合、必要な型を `types.go` に寄せる（cgo 依存を避ける）

**Step 4: ローカル検証（macOS）**

Run: `go test ./internal/rdma -count=1`
Expected: PASS（ハード依存は Skip、残りは成功）

**Step 5: Commit**

```bash
git add internal/rdma
git commit -m "fix: make rdma package buildable on non-linux via stubs"
```

---

### Task 4: 上位パッケージ（agent/state/monitor/probe）が macOS でビルドできることを確認する

**Files:**
- Modify (必要なら): `internal/ebpf/*`, `internal/rdma/*`（不足 API が出た場合）

**Step 1: コンパイル検証**

Run: `go test ./... -run TestDoesNotExist -count=0`
Expected: PASS（コンパイルエラー 0）

**Step 2: 単体テスト実行**

Run: `go test ./... -count=1`
Expected: PASS（rqlite が必要なテストは別途）

**Step 3: Commit**

```bash
git add -A
git commit -m "test: enable running unit tests on macOS"
```

---

### Task 5: rqlite 依存を macOS で簡単に起動できるようにする

**Files:**
- Create: `scripts/rqlite-local-up.sh`
- Create: `scripts/rqlite-local-down.sh`
- Modify: `Makefile`
- (任意) Create: `docs/dev/macos.md`

**Step 1: rqlite 起動スクリプト**

`scripts/rqlite-local-up.sh`（例）:

```bash
#!/usr/bin/env bash
set -euo pipefail
docker run --rm -d --name rpingmesh-rqlite -p 4001:4001 rqlite/rqlite:8.37.0 -http-addr "0.0.0.0:4001"
```

`scripts/rqlite-local-down.sh`（例）:

```bash
#!/usr/bin/env bash
set -euo pipefail
docker rm -f rpingmesh-rqlite 2>/dev/null || true
```

**Step 2: Makefile ターゲット追加**

- `make rqlite-up` / `make rqlite-down`
- `make test-local` の前提を README/Docs に明記

**Step 3: ローカル検証**

Run: `make rqlite-up`
Run: `make test-local`
Run: `make rqlite-down`

**Step 4: Commit**

```bash
git add scripts Makefile docs/dev/macos.md
git commit -m "chore: add rqlite helpers for local testing"
```

---

### Task 6: （任意）Apple Silicon で Docker ワークフローが動くように platform を明示する

**Files:**
- Modify: `docker-compose.test.yml`
- Modify: `docker-compose.build.yml`
- Modify: `docker-compose.yml`

**Step 1: `platform: linux/amd64` を追加**

`agent_test` / `agent` / `agent-builder` など、`GOARCH=amd64` バイナリを実行するサービスに限定して追加する。

**Step 2: ローカル検証**

Run: `docker compose -f docker-compose.test.yml up --build agent_test --abort-on-container-exit`

**Step 3: Commit**

```bash
git add docker-compose*.yml
git commit -m "chore: pin linux/amd64 platform for agent containers"
```

---

### Task 7: Tier 3（Linux VM）で soft-RoCE + eBPF 統合テスト環境を作る

**Files:**
- Modify: `docs/plans/2026-01-17-macos-dev-env-design.md:1`
- Create: `docs/dev/macos-colima-vm.md`

**Step 1: どの VM で進めるか決める（分岐点）**

- Intel Mac: `linux/amd64` VM を前提にしてよい
- Apple Silicon（今回の選択）:
  - `colima` で `linux/arm64` ネイティブ VM（推奨）
  - eBPF 生成物の multi-arch 化（Task 8）を前提にする

**Step 2: Linux VM を起動し、リポジトリを VM にマウントする**

VM の選択肢:
- lima
- colima
- multipass

今回の選択（colima）に固定し、具体手順は `docs/dev/macos-colima-vm.md` に記載する。

**Step 3: VM 内にビルド/実行依存を入れる（例: Debian/Ubuntu 系）**

例（パッケージ名はディストリにより差あり）:
- Go（`go env` で確認）
- `clang`, `llvm`, `libbpf-dev`, `bpftool`, `libelf-dev`, `pkg-config`
- `libibverbs-dev`, `librdmacm-dev`, `rdma-core`
- `linux-headers-$(uname -r)`（可能なら）
- `protobuf-compiler`（`make generate-proto` が必要な場合）
- `iproute2`, `iputils-ping`

**Step 4: soft-RoCE（RXE）を有効化する**

例:
```bash
sudo modprobe rdma_rxe
ip link
rdma link show
sudo rdma link add rxe0 type rxe netdev <VMのNIC名>
rdma link show
```

**Step 5: eBPF 実行前提を満たす**

例:
```bash
sudo mount -t debugfs none /sys/kernel/debug || true
ulimit -l unlimited || true
```

**Step 6: 統合テストを回す**

最低限:
- `make generate`（VM で生成できる場合）
- `go test ./...`

RDMA/eBPF を含めたい場合:
- 対象テストを `-run` で絞って実行し、Skip/Fail の理由をログに残す

**Step 7: 記録を残す**

`docs/dev/macos-colima-vm.md` に以下を記載:
- VM 種別/OS/カーネル/アーキ（`uname -a`）
- RXE セットアップ手順（使用 IF 名）
- `go test` 実行結果（成功/Skip/失敗のログ）

---

### Task 8: （Apple Silicon 推奨）eBPF 生成物を multi-arch 化して linux/arm64 VM で動かす

**Files:**
- Modify: `internal/ebpf/rdma_tracing.go`
- Run: `make generate-bpf`（VM 内）
- Create (generated): `internal/ebpf/rdmatracing_arm64_bpfel.go` 等

**Step 1: bpf2go の `-target` を追加して arm64 生成を可能にする**

方針例:
- `go:generate` を 2 回に分けて `amd64` と `arm64` を生成する
- 生成ファイルは bpf2go の規約に従いコミットする（手編集しない）

**Step 2: linux/arm64 VM で `make generate-bpf` を実行**

Run: `make generate-bpf`
Expected: arm64 向けの `*_bpfel.go` と `*.o` が生成される

**Step 3: linux/arm64 VM で `go test ./internal/ebpf -count=1` を実行**

Expected:
- 権限/機能不足なら Skip（ただしコンパイルは成功）
- 条件が揃う環境なら eBPF のロードに成功する

**Step 4: Commit**

```bash
git add internal/ebpf
git commit -m "feat: generate ebpf bindings for arm64"
```
