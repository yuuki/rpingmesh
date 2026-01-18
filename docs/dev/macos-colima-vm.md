# macOS（Apple Silicon）+ colima で Tier 3（soft-RoCE + eBPF）統合テストを回す手順

対象: macOS（arm64）で `colima` を使い、Linux VM 上で RpingMesh の RDMA/eBPF を含む動作確認・テストを実施する。

## 目標（成功条件）

- Linux VM 内で本リポジトリを参照できる（マウント）
- VM 内で `rdma_rxe`（soft-RoCE）が有効化できる（`rdma link show` に RXE が出る）
- VM 内で eBPF 実行前提（debugfs / memlock / 権限）を満たせる
- VM 内で `go test ./...` が実行できる（失敗する場合は、失敗理由が再現可能な形で記録される）

## 0. 前提

- Homebrew が使える
- `docker` CLI がインストール済み
- （推奨）`make generate-bpf` を VM 内で回せるように、VM 内に `clang/llvm/libbpf-dev/bpftool` 等を入れる
- eBPF 生成物は **arm64 対応が必要**（`docs/plans/2026-01-17-macos-dev-env-design.md` の「multi-arch 化」参照）

## 1. colima の起動（例）

ホスト macOS 側:

```bash
colima start --arch aarch64 --cpu 6 --memory 10 --disk 80
colima status
```

参考（実測）:
- colima: 0.9.1
- VM OS: Ubuntu 24.04.1 LTS
- kernel: 6.8.0-50-generic
- arch: aarch64

VM に入る:

```bash
colima ssh
```

VM 側で最低限の確認:

```bash
uname -a
cat /etc/os-release
ip link
df -h
```

## 2. リポジトリが VM から見えることを確認

VM から macOS のホームディレクトリが見えるかは環境差があります。まずは以下のどちらかで確認します。

```bash
ls /Users || true
ls $HOME || true
```

リポジトリが見えたら（例）:

```bash
cd /Users/y-tsubouchi/src/github.com/yuuki/rpingmesh
```

見えない場合は、colima のマウント設定を調整し、**VM 内からソースが参照できる状態**を先に作ります。

## 3. VM 内に依存パッケージを導入

OS を確認し、Debian/Ubuntu 系なら以下を目安に導入します（パッケージ名は多少ズレることがあります）。

```bash
sudo apt-get update
sudo apt-get install -y \
  git curl ca-certificates \
  clang llvm bpftool libbpf-dev libelf-dev pkg-config \
  rdma-core libibverbs-dev librdmacm-dev \
  iproute2 iputils-ping \
  linux-headers-$(uname -r) || true
```

補足（Ubuntu 24.04 / arm64 の実測）:
- `bpftool` は `linux-tools-common` / `linux-tools-$(uname -r)` に含まれるため、必要に応じて追加
- `ibv_devinfo` は `ibverbs-utils` を入れる
- RDMA の cgo ビルドには `build-essential` が必要

実際に使用した追加コマンド:

```bash
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r) || true
sudo apt-get install -y ibverbs-utils
sudo apt-get install -y build-essential
```

Go 1.24.3（arm64）を VM に導入する場合:

```bash
GO_VERSION=1.24.3
curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz -o /tmp/go${GO_VERSION}.linux-arm64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go${GO_VERSION}.linux-arm64.tar.gz
echo "export PATH=/usr/local/go/bin:\$PATH" | sudo tee /etc/profile.d/go.sh >/dev/null
export PATH=/usr/local/go/bin:$PATH
go version
```

RDMA/eBPF の確認:

```bash
bpftool version || true
rdma version || true
ibv_devinfo || true
```

## 4. soft-RoCE（RXE）を有効化

モジュールをロード:

```bash
sudo modprobe rdma_rxe
sudo modprobe ib_core || true
sudo modprobe ib_uverbs || true
```

VM の NIC 名を確認（例: `eth0`）:

```bash
ip link
ip route
```

RXE デバイス作成:

```bash
sudo rdma link add rxe0 type rxe netdev <VMのNIC名>
rdma link show
```

確認（`/sys/class/infiniband` が存在すれば期待に近い状態）:

```bash
ls -la /sys/class/infiniband || true
ibv_devinfo | head -n 40 || true
```

実測ログ（例）:
- `rdma link show` で `rxe0/1 state ACTIVE ... netdev eth0` が表示
- `ibv_devinfo` で `hca_id: rxe0` が確認できる

失敗した場合の記録ポイント:
- `modprobe rdma_rxe` が失敗する（モジュールが無い/カーネル構成）
- `rdma link add` が失敗する（`rdma-core` 未導入/IF 名ミス/権限不足）

## 5. eBPF 実行前提を満たす

debugfs:

```bash
sudo mount -t debugfs none /sys/kernel/debug || true
```

memlock:

```bash
ulimit -l unlimited || true
```

（任意）kprobe 対象関数が存在するかの当たりを付ける:

```bash
sudo grep -w "ib_modify_qp_with_udata" /proc/kallsyms | head -n 5 || true
```

補足（実測）:
- `/sys/kernel/btf/ib_core` と `/sys/kernel/btf/ib_uverbs` が存在

## 6. テスト/動作確認の回し方（VM 内）

### 6.1 まずはコンパイル/単体テスト（ハード依存を除く）

```bash
go version
go test ./... -count=1
```

### 6.2 RDMA/eBPF を含むテスト（環境が揃った場合のみ）

eBPF ロード系（権限が必要）:

```bash
sudo -E go test ./internal/ebpf -run TestBPFProgramLoading -count=1 -v
```

RDMA デバイス検出（soft-RoCE を入れている前提）:

```bash
sudo -E go test ./internal/rdma -run TestRDMAEnvironmentDetection -count=1 -v
```

実測結果:
- `TestRDMAEnvironmentDetection` は soft-RoCE（rxe0）で PASS
- eBPF は **CO-RE relocation エラーで SKIP** になるケースがある
  - 例: `bad CO-RE relocation: invalid func unknown#...`
  - この場合、`/sys/kernel/btf` は読めているが、カーネル/モジュール構成や CO-RE 互換性が原因の可能性が高い

## 7. 期待通りに動かない場合の切り分け

- `internal/ebpf` がビルドできない: eBPF 生成物が `amd64` 固定の可能性が高い（multi-arch 化が必要）
- `modprobe rdma_rxe` が失敗: colima VM のカーネルに RXE が入っていない（VM/カーネル選定の見直しが必要）
- eBPF のロードが失敗: `debugfs`/memlock/権限/カーネル関数の有無（`ib_*`）を順に確認

## 8. 実測環境メモ（このリポジトリでの検証結果）

- colima: 0.9.1
- VM: Ubuntu 24.04.1 LTS / kernel 6.8.0-50-generic / aarch64
- mount: `/Users/y-tsubouchi` が virtiofs で見える
- RDMA: `rdma_rxe` により `rxe0` を作成、`ibv_devinfo` で確認済み
- eBPF: `TestBPFProgramLoading` は CO-RE relocation エラーにより SKIP（要追加調査）
