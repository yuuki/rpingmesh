# Devcontainer RDMA セットアップガイド

## 概要

R-Pingmesh の devcontainer は RDMA（soft-RoCE）開発環境を提供します。このガイドでは、セットアップ、検証、トラブルシューティング方法を説明します。

## 前提条件

- Docker または互換コンテナランタイム
- VS Code + Remote-Containers 拡張機能（または GitHub Codespaces）
- **RDMA 完全動作のため:**
  - Linux ホスト（カーネル 5.4+ 推奨）
  - ホストカーネルモジュール: `rdma_rxe`, `ib_core`, `ib_uverbs`

## 自動セットアップ

devcontainer 起動時に `post-create.sh` が自動的に以下を実行します:

1. RDMA カーネルモジュールのロード
2. 最初の ethernet インターフェースに soft-RoCE を作成
3. RDMA 環境の検証
4. ヘルパースクリプト（`setup-soft-roce.sh`）の作成

初期化出力を確認し、警告やエラーがないかチェックしてください。

## 検証

### 自動検証

コンテナ起動後、検証スクリプトを実行:

```bash
.devcontainer/validate-rdma-environment.sh
```

### 手動検証

#### RDMA ツール確認

```bash
# rdma コマンド
rdma version

# ibv_devinfo コマンド
ibv_devinfo -l
```

#### RDMA デバイス確認

```bash
# RDMA リンクの確認
rdma link show
# 期待される出力:
# link rxe0/1 state ACTIVE physical_state LINK_UP netdev eth0

# InfiniBand デバイス確認
ls -la /sys/class/infiniband
# 期待される出力: rxe0 ディレクトリ

# デバイス詳細情報
ibv_devinfo | head -n 20
# 期待される出力: hca_id: rxe0 とその詳細
```

#### RDMA テスト実行

```bash
# RDMA デバイス初期化テスト（soft-RoCE 必要）
go test ./internal/rdma -run TestDeviceInit -v

# RDMA パッケージ全体のテスト
go test ./internal/rdma -v
```

#### ビルド確認

```bash
# RDMA パッケージのビルド（cgo）
go build ./internal/rdma

# Agent のビルド
go build ./cmd/agent
```

## 手動 soft-RoCE セットアップ

自動セットアップが失敗した場合、ヘルパースクリプトを使用:

```bash
# 利用可能なネットワークインターフェース確認
ip link show

# デフォルトインターフェースで soft-RoCE 作成
setup-soft-roce.sh

# 特定のインターフェースを指定
setup-soft-roce.sh eth0
```

## トラブルシューティング

### soft-RoCE 作成が失敗する

**症状:** `rdma link add` が失敗、または警告メッセージ

**原因と対処:**

1. **カーネルモジュールが利用不可**
   ```bash
   # コンテナ内で確認
   lsmod | grep rdma_rxe

   # ホストマシンで確認・ロード
   sudo modprobe rdma_rxe
   sudo modprobe ib_core
   sudo modprobe ib_uverbs

   # 確認
   lsmod | grep rdma
   ```

2. **権限不足**
   - devcontainer は既に必要な capabilities（NET_ADMIN, SYS_ADMIN）を持っています
   - それでも失敗する場合、ホスト側の設定が必要な可能性があります

3. **ネットワークインターフェースが見つからない**
   ```bash
   # コンテナ内のインターフェース確認
   ip link show

   # 手動で特定のインターフェースを指定
   setup-soft-roce.sh <interface-name>
   ```

### RDMA テストが SKIP される

**症状:** `go test ./internal/rdma` で一部テストが SKIP

**期待される動作:**
- soft-RoCE がない環境では一部テストが SKIP されるのは正常です
- ハードウェア RDMA NIC が必要なテストも SKIP されます

**確認すべきこと:**
- `TestDeviceInit` は soft-RoCE があれば PASS すべき
- SKIP の理由がログに出力されるので確認

### cgo ビルドが失敗する

**症状:** `go build` で「C compiler not found」や「library not found」エラー

**対処:**

1. **build-essential 確認**
   ```bash
   dpkg -l | grep build-essential
   gcc --version
   ```

2. **RDMA ライブラリ確認**
   ```bash
   ldconfig -p | grep libibverbs
   ldconfig -p | grep librdmacm
   ```

3. **ライブラリが見つからない場合**
   ```bash
   # コンテナを再ビルド（Dockerfile の変更が反映されていない可能性）
   # VS Code: Command Palette > "Rebuild Container"
   ```

### デバイスが表示されない

**症状:** `rdma link show` で何も表示されない、または `ibv_devinfo` がデバイスを検出しない

**対処:**

1. **soft-RoCE を手動作成**
   ```bash
   setup-soft-roce.sh
   ```

2. **ホストカーネルサポート確認**
   ```bash
   # ホストマシンで
   modinfo rdma_rxe
   # 出力があれば、カーネルが RXE をサポートしています
   ```

3. **コンテナの制限**
   - devcontainer は `--privileged` を使用していません
   - 一部の操作にはホスト側での準備が必要です

## コンテナの制限事項

devcontainer 環境では以下の制限があります:

### できること
- ✅ soft-RoCE の使用（ホストモジュールロード済みの場合）
- ✅ RDMA アプリケーションの開発とテスト
- ✅ cgo を使った RDMA コードのビルド
- ✅ UD (Unreliable Datagram) の送受信テスト

### 制約事項
- ❌ カーネルモジュールの直接ロード（ホスト権限必要）
- ❌ 実 RDMA NIC へのアクセス（デバイスパススルー必要）
- ❌ Privileged モード操作（devcontainer 制限）

## ホスト環境の準備

完全な RDMA 機能を使うため、ホスト側で以下を準備:

### Ubuntu/Debian ホスト

```bash
# RDMA パッケージのインストール
sudo apt-get update
sudo apt-get install -y \
    rdma-core \
    libibverbs-dev \
    librdmacm-dev \
    linux-headers-$(uname -r)

# カーネルモジュールのロード
sudo modprobe rdma_rxe
sudo modprobe ib_core
sudo modprobe ib_uverbs

# 確認
lsmod | grep rdma
```

### macOS ホスト

macOS では Docker Desktop を使用しますが、Linux VM 上で動作するため:

1. **代替: Colima VM を使用**
   - [macOS Colima VM セットアップガイド](./macos-colima-vm.md)参照
   - Colima は Linux VM として動作し、RDMA カーネルモジュールをサポート可能

2. **Docker Desktop の制限**
   - Docker Desktop の Linux VM はカスタマイズが困難
   - RDMA カーネルモジュールが利用できない可能性が高い
   - 開発とビルドは可能ですが、RDMA デバイステストは制限される

## 開発ワークフロー

### 1. コンテナ起動
- VS Code で「Reopen in Container」
- 初期化出力を確認（RDMA セットアップのステータス）

### 2. 環境検証
```bash
.devcontainer/validate-rdma-environment.sh
```

### 3. 開発とテスト
```bash
# コード変更

# ビルド確認
go build ./cmd/agent

# RDMA テスト実行
go test ./internal/rdma -v

# 全体テスト
go test ./... -v
```

### 4. トラブルシュー ト
- 検証スクリプトで問題特定
- 必要に応じて `setup-soft-roce.sh` 実行
- ホスト環境の確認

## 既知の問題

### Issue: コンテナ再起動後に soft-RoCE が消える

**原因:** RDMA デバイスはコンテナのネットワーク名前空間に作成されるため

**対処:** コンテナ起動時に自動セットアップが実行されます。失敗した場合は手動で `setup-soft-roce.sh` を実行

### Issue: ibv_devinfo で「No IB devices found」

**原因:** soft-RoCE デバイスが作成されていない

**対処:**
```bash
# 手動セットアップ
setup-soft-roce.sh

# 確認
rdma link show
ibv_devinfo
```

### Issue: ホストで rdma_rxe が見つからない

**原因:** ホストカーネルが RXE モジュールを含んでいない

**対処:**
1. カーネルアップデート、または
2. RXE サポート付きカーネルの使用、または
3. Colima などの代替ソリューションを使用

## 参考情報

- [macOS Colima VM セットアップ](./macos-colima-vm.md) - macOS 開発者向け
- [RDMA Development Guide](../README.md) - RDMA コンセプトと API
- [Soft-RoCE Documentation](https://github.com/SoftRoCE/rxe-dev/wiki) - soft-RoCE 詳細

## 環境変数

devcontainer で設定される環境変数:

- `RDMA_ENABLED=1` - RDMA 機能が有効であることを示す
- `GOPATH=/go` - Go ワークスペース
- `GO111MODULE=on` - Go モジュールモード

## 追加リソース

### RDMA コマンドリファレンス

```bash
# デバイス一覧
rdma dev show

# リンク状態
rdma link show

# リソース確認
rdma resource show

# InfiniBand デバイス情報
ibv_devices
ibv_devinfo

# デバイス詳細
ibv_devinfo -d rxe0
```

### デバッグコマンド

```bash
# カーネルモジュール確認
lsmod | grep -E "rdma|ib_"

# システムログ確認
dmesg | grep -i rdma
dmesg | grep -i rxe

# ネットワークインターフェース
ip link show

# ライブラリ確認
ldconfig -p | grep -E "ibverbs|rdmacm"
```

## まとめ

devcontainer は RDMA 開発環境を自動的にセットアップします:

1. ✅ **自動セットアップ:** 起動時に RDMA 環境を初期化
2. ✅ **検証ツール:** `validate-rdma-environment.sh` で環境確認
3. ✅ **リカバリー:** `setup-soft-roce.sh` で手動セットアップ可能
4. ⚠️ **制約理解:** コンテナとホストの制限を認識

問題が発生した場合は、検証スクリプトを実行し、エラーメッセージに従って対処してください。
