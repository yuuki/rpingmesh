#!/bin/bash
set -e

# Add any post-creation steps here
echo "Setting up RpingMesh development environment..."

# Verify Go installation
go version

# Set up environment variables
cat <<EOF >> ~/.bashrc

# RpingMesh Environment
export PATH=\$PATH:/go/bin
export GOPATH=/go
export GO111MODULE=on
EOF

# Set up fish shell environment (if needed)
if command -v fish &> /dev/null; then
    mkdir -p ~/.config/fish
    cat <<EOF >> ~/.config/fish/config.fish

# RpingMesh Environment
set -gx PATH \$PATH /go/bin
set -gx GOPATH /go
set -gx GO111MODULE on
EOF
fi

echo ""
echo "=============================================="
echo "Initializing RDMA Environment"
echo "=============================================="
echo ""

# Load RDMA kernel modules
echo "Loading RDMA kernel modules..."
modprobe rdma_rxe 2>/dev/null && echo "  ✓ rdma_rxe loaded" || echo "  ⚠ rdma_rxe module not available (may need host kernel support)"
modprobe ib_core 2>/dev/null && echo "  ✓ ib_core loaded" || echo "  ⚠ ib_core module load attempted"
modprobe ib_uverbs 2>/dev/null && echo "  ✓ ib_uverbs loaded" || echo "  ⚠ ib_uverbs module load attempted"
echo ""

# Detect network interfaces
echo "Detecting network interfaces..."
FIRST_NIC=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|en)' | head -n 1)
if [ -n "$FIRST_NIC" ]; then
    echo "  Found interface: $FIRST_NIC"

    # Attempt soft-RoCE setup
    echo "  Setting up soft-RoCE on $FIRST_NIC..."
    if rdma link add rxe0 type rxe netdev "$FIRST_NIC" 2>/dev/null; then
        echo "  ✓ soft-RoCE device rxe0 created successfully"
    else
        echo "  ⚠ soft-RoCE creation failed (may need host permissions or kernel module)"
    fi
else
    echo "  ⚠ No suitable network interface found for soft-RoCE"
fi
echo ""

# Create helper script for manual soft-RoCE setup
echo "Creating soft-RoCE helper script..."
cat > /usr/local/bin/setup-soft-roce.sh <<'EOFSOFTROC'
#!/bin/bash
# Helper script for manual soft-RoCE setup

echo "Soft-RoCE Setup Helper"
echo "======================"
echo ""

# Show available interfaces
echo "Available network interfaces:"
ip -o link show | awk -F': ' '{print "  " $2}'
echo ""

# Ask for interface or use default
if [ -z "$1" ]; then
    FIRST_NIC=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|en)' | head -n 1)
    if [ -n "$FIRST_NIC" ]; then
        NIC="$FIRST_NIC"
        echo "Using default interface: $NIC"
    else
        echo "Usage: setup-soft-roce.sh <interface-name>"
        echo "Example: setup-soft-roce.sh eth0"
        exit 1
    fi
else
    NIC="$1"
fi

echo "Setting up soft-RoCE on interface: $NIC"
echo ""

# Load modules
echo "Loading kernel modules..."
modprobe rdma_rxe || { echo "Failed to load rdma_rxe module"; exit 1; }
modprobe ib_core 2>/dev/null
modprobe ib_uverbs 2>/dev/null
echo ""

# Create RXE device
echo "Creating RXE device..."
rdma link add rxe0 type rxe netdev "$NIC" || { echo "Failed to create rxe0"; exit 1; }
echo ""

echo "Soft-RoCE setup complete!"
echo ""
echo "Verification:"
rdma link show
echo ""
ibv_devinfo | head -n 20
EOFSOFTROC

chmod +x /usr/local/bin/setup-soft-roce.sh
echo "  ✓ Helper script created at /usr/local/bin/setup-soft-roce.sh"
echo ""

# RDMA verification
echo "=============================================="
echo "RDMA Environment Verification"
echo "=============================================="
echo ""

echo "1. RDMA tools:"
rdma version 2>/dev/null && echo "  ✓ rdma command available" || echo "  ✗ rdma command not found"
ibv_devinfo -l 2>/dev/null && echo "  ✓ ibv_devinfo available" || echo "  ✗ ibv_devinfo not found"
echo ""

echo "2. RDMA devices:"
if rdma link show 2>/dev/null | grep -q "rxe"; then
    echo "  ✓ RDMA devices found:"
    rdma link show | sed 's/^/    /'
else
    echo "  ⚠ No RDMA devices found"
    echo "    Run 'setup-soft-roce.sh' to create soft-RoCE device manually"
fi
echo ""

echo "3. InfiniBand devices:"
if [ -d /sys/class/infiniband ] && [ -n "$(ls -A /sys/class/infiniband 2>/dev/null)" ]; then
    echo "  ✓ InfiniBand devices:"
    ls -1 /sys/class/infiniband | sed 's/^/    /'
else
    echo "  ⚠ No InfiniBand devices found"
fi
echo ""

echo "4. ibverbs device info:"
if ibv_devinfo 2>/dev/null | head -n 20 | grep -q "hca_id"; then
    echo "  ✓ ibverbs devices detected"
    ibv_devinfo | head -n 20 | sed 's/^/    /'
else
    echo "  ⚠ No ibverbs devices found"
fi
echo ""

echo "=============================================="
echo "RDMA initialization complete!"
echo ""
echo "If soft-RoCE setup failed, retry manually:"
echo "  setup-soft-roce.sh [interface-name]"
echo "=============================================="
echo ""

echo "Installing Claude Code..."
curl -fsSL https://claude.ai/install.sh | bash

# Find the workspace directory
WORKSPACE_DIR=${WORKSPACE_DIR:-$(pwd)}
echo "Workspace directory: $WORKSPACE_DIR"

if [ -f "$WORKSPACE_DIR/go.mod" ]; then
    cd "$WORKSPACE_DIR"
    echo "Found go.mod in $WORKSPACE_DIR"

    # Check for eBPF directory
    if [ -d "$WORKSPACE_DIR/internal/ebpf" ]; then
        echo "Found eBPF directory, running go generate"
        cd "$WORKSPACE_DIR/internal/ebpf"
        go generate ./... || echo "Warning: Failed to generate eBPF bindings. You may need to set the correct KERNEL_VERSION environment variable."
    else
        echo "eBPF directory not found at $WORKSPACE_DIR/internal/ebpf, skipping go generate"
    fi

    # Go back to project root and run go mod tidy
    cd "$WORKSPACE_DIR"
    go mod tidy
else
    echo "go.mod not found in $WORKSPACE_DIR - this may not be the project root"
    echo "Skipping go mod tidy and eBPF generation"
    echo "Current directory contents:"
    ls -la
fi

echo "Development environment setup complete!"
