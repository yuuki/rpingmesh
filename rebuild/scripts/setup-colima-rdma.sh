#!/usr/bin/env bash
# setup-colima-rdma.sh - One-time setup of RDMA modules on the Colima VM.
#
# Run this script once from the macOS host before running e2e tests:
#   make setup-colima
#
# This script installs linux-modules-extra (which contains rdma_rxe) and
# loads the required kernel modules inside the Colima Linux VM.

set -euo pipefail

KVER=$(colima ssh -- uname -r 2>/dev/null | tr -d '\r')
echo "==> Colima VM kernel: ${KVER}"

# Check if rdma_rxe is already available
if colima ssh -- "find /lib/modules/${KVER} -name 'rdma_rxe*' 2>/dev/null | grep -q ." 2>/dev/null; then
    echo "==> rdma_rxe module is already installed."
else
    echo "==> Updating apt package lists on Colima VM..."
    colima ssh -- sudo apt-get update -qq
    echo "==> Installing linux-modules-extra-${KVER} on Colima VM..."
    echo "    (requires sudo password if prompted)"
    colima ssh -- sudo apt-get install -y --fix-missing "linux-modules-extra-${KVER}"
    echo "==> Installation complete."
fi

# Load modules
echo "==> Loading rdma_rxe and related modules..."
colima ssh -- sudo modprobe rdma_rxe
colima ssh -- sudo modprobe ib_uverbs 2>/dev/null || true

echo "==> Verifying RDMA module state:"
colima ssh -- lsmod | grep -E "rdma_rxe|ib_core|ib_uverbs" || echo "    (no rdma modules listed)"

echo ""
echo "==> Colima RDMA setup complete. You can now run: make test-e2e"
