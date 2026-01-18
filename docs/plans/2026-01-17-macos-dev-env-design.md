# macOS上での開発/単体テスト対応（ハードウェア非依存） 調査メモ

作成日: 2026-01-17

## 背景

RpingMesh は RDMA（`libibverbs`）および eBPF（Linux kernel）に依存し、TMA デバイス等の特殊ハードウェアがない環境では、そのままではビルド・動作確認・単体テストが困難です。  
一方で、ローカル開発（特に macOS）では「ロジック部分の単体テスト」「コンフィグ/CLI/シリアライゼーション」「コントロールプレーン（gRPC/DB 周り）」の高速フィードバックが重要です。

本メモは、**macOS 上で動作確認と単体テストを回せる開発環境**を整備するための阻害要因を洗い出し、現実的な対応方針を比較します。

## 現状の確認（実測）

macOS（darwin）上で以下を実行すると、ビルド段階で失敗しました（テスト実行以前にコンパイル不能）。

実行コマンド:

```bash
go test ./... -run TestDoesNotExist -count=0
```

主な失敗要因（抜粋）:

- `internal/rdma`: `#include <infiniband/verbs.h>` が見つからずビルド失敗
  - 例: `internal/rdma/packet.go:5:11: fatal error: 'infiniband/verbs.h' file not found`
- `internal/ebpf`: 生成物/依存が darwin に存在せずビルド失敗
  - M1/M2 等（`GOARCH=arm64`）の場合、`rdmatracing_x86_bpfel.go` が `amd64` 前提のため型/関数が未定義になる
  - `github.com/cilium/ebpf/ringbuf` は Linux 前提の API で、darwin では型が存在しない/提供されない

副次的に、`internal/agent` / `internal/monitor` / `internal/probe` / `internal/state` は `internal/rdma` を経由して darwin ビルドが破綻します。

## macOS対応における阻害要因（整理）

### 1) RDMA（cgo + libibverbs）前提がパッケージ境界に露出している

- `internal/rdma` は cgo を前提としており、darwin でコンパイルできません。
- さらに、`internal/state` / `internal/probe` / `internal/monitor` / `internal/agent` が `internal/rdma` の具体型（`*rdma.RDMAManager`, `*rdma.RNIC`, `*rdma.UDQueue` 等）に強く依存しています。

→ **OS/ハード依存を build tag とスタブ/抽象化で隔離**しない限り、macOS で `go test` を回せません。

### 2) eBPF は Linux（かつ特定アーキテクチャ）前提

- `internal/ebpf/rdma_tracing.go` は Linux 特有の syscall/rlimit/BTF/kprobe/ringbuf を利用しています。
- 生成された `rdmatracing_x86_bpfel.go` が `amd64` 前提で、Apple Silicon（arm64）の macOS ではビルドに必要な型/関数が存在しません。

→ **eBPF 実装を linux 限定にし、非 Linux では no-op/stub にする**のが現実的です（少なくとも単体テスト実行のため）。

### 3) Docker/DevContainer での「Linux上で実行」は有効だが、Apple Silicon での罠がある

- `Dockerfile.agent` は `GOOS=linux GOARCH=amd64` 固定でビルドしています。
- Apple Silicon 環境だと、Docker が `linux/arm64` をデフォルトにするため、**amd64 バイナリを arm64 コンテナで実行して失敗**する可能性があります（`--platform linux/amd64` か multiarch 対応が必要）。
- `.devcontainer/devcontainer.json` は JSONC としては成立し得ますが、`mounts` の配列にカンマ欠落があり（少なくとも現状の見た目では）実環境で読み込み失敗する恐れがあります。

→ 「macOS上で開発する」=「macOSホスト上で直接 go test」だけでなく、**macOS上で Linux コンテナ/VM を回す**選択肢も整理が必要です。

## 目標（成功条件）

最低ライン（Tier 1）:
- macOS 上で `go test ./...` が **コンパイルエラーなく完走**し、ハードウェア依存テストはスキップされる
- 追加依存（rqlite 等）は Docker で供給できる（`make test-local` を macOS で実行できる）

望ましい（Tier 2）:
- macOS 上で `cmd/agent` が **「RDMA/eBPF 無効」モードで起動**し、コントロールプレーンの疎通（設定読み込み・gRPC 接続・DB 参照等）まで確認できる

Tier 3（今回選択）:
- macOS 上の Linux VM（lima/colima 等）で **soft-RoCE + eBPF を含む統合テスト**を再現できる

## アプローチ案（比較）

### 案A（推奨）: build tag + スタブで「macOSでも全部コンパイル」させ、単体テストを回す

狙い:
- ロジックの単体テスト（config/registry/pinglist/prober/monitor の純粋ロジック）を macOS で高速に回す
- RDMA/eBPF に触れる部分は linux 限定とし、macOS では no-op/stub でコンパイルだけ通す

具体:
- `internal/rdma` を `linux && cgo` 実装と、それ以外のスタブ実装に分割（型・メソッドシグネチャを維持）
- `internal/ebpf` を `linux` 実装と、それ以外のスタブ実装に分割
- `internal/ebpf/*_test.go` のうち実カーネル依存のものは `//go:build linux` を付けて macOS ではビルド対象外にする（あるいはスタブ実装に合わせて Skip）

メリット:
- macOS 上で `go test ./...` が回る（高速フィードバック）
- CI は従来通り Linux/Docker で担保できる

デメリット:
- スタブ/抽象化の設計が必要（短期的にはコード変更量が増える）

### 案B: macOS では devcontainer/Docker のみを正式サポート（ホストでの go test は諦める）

狙い:
- 「macOS 上で Linux を動かす」ことで RDMA/eBPF に近い環境を維持する

メリット:
- 既存の Docker ベースのワークフロー（`make test`）と親和性が高い

デメリット:
- Apple Silicon の `linux/amd64` 固定ビルドや eBPF/特権/カーネルの制約により、結局 “動かない” 可能性が残る
- ローカルの軽量単体テストの回転が遅くなる

### 案C: macOS で Linux VM（lima/colima）を整備し、そこで `make test` を回す

狙い:
- Docker Desktop の制約を避け、Linux カーネル上で eBPF 等を扱えるようにする

メリット:
- eBPF/soft-RoCE を含む統合テストを再現しやすい

デメリット:
- 導入コストが高い（VM/ネットワーク/権限/soft-RoCE）
- 目的が「単体テストの高速化」なら過剰

## Tier 3 実現のための技術論点（重要）

### 1) Apple Silicon（arm64）と eBPF 生成物のアーキテクチャ整合

現状、`internal/ebpf/rdma_tracing.go` の `go:generate` は `-target amd64` 固定であり、生成された Go バインディング（`internal/ebpf/rdmatracing_x86_bpfel.go`）も `//go:build 386 || amd64` です。  
そのため、**linux/arm64 の VM（例: Apple Silicon でネイティブに動く Ubuntu VM）では eBPF パッケージがビルドできません**。

Tier 3 を Apple Silicon でネイティブに回すには、どちらかが必要です:

- (推奨) eBPF 生成を multi-arch 化し、`arm64` 用の生成物（例: `rdmatracing_arm64_bpfel.go` / `*.o`）を用意する
- もしくは、x86_64（amd64）Linux VM を用意してそこで実行する（Apple Silicon では QEMU エミュレーションになり遅い）

### 2) soft-RoCE（RXE）セットアップ

soft-RoCE は Linux 上で `rdma_rxe` を使い、既存 NIC を RDMA デバイスとして扱えるようにします（`rdma link add rxe0 type rxe netdev <iface>`）。  
VM のネットワーク IF 名は環境により異なるため、`ip link` / `rdma link show` を前提に手順を組みます。

### 3) eBPF 実行要件

- `debugfs` のマウント（`/sys/kernel/debug`）
- `ulimit -l unlimited`（MEMLOCK）
- root 権限（または CAP_BPF/CAP_SYS_ADMIN）
- kprobe 対象関数（`ib_modify_qp_with_udata` 等）がカーネルに存在すること

## 推奨方針（Tier 3）

まず **案A（build tag + スタブ）で Tier 1 を確実に達成**したうえで、**案C（Linux VM）で Tier 3 を追加**します。

理由:
- 現状の最大の痛点は「macOS で `go test` がコンパイルすら通らない」こと
- RDMA/eBPF の統合テストは Linux（VM）に寄せた方が、再現性と安定性が高い

## 要確認（1つだけ質問）

お使いの Mac はどちらですか？

1. Intel Mac（amd64）
2. Apple Silicon（arm64）

（2 の場合、Tier 3 は「arm64 ネイティブ VM + eBPF multi-arch 化」か「amd64 VM（エミュレーション）」のどちらで進めるのが良いか判断します。）
