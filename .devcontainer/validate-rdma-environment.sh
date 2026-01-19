#!/bin/bash
# Comprehensive RDMA environment validation for devcontainer

set -e

echo "=================================================="
echo "R-Pingmesh RDMA Development Environment Validation"
echo "=================================================="
echo ""

ERRORS=0
WARNINGS=0

# Helper functions
error() {
    echo "❌ ERROR: $1"
    ((ERRORS++))
}

warning() {
    echo "⚠️  WARNING: $1"
    ((WARNINGS++))
}

success() {
    echo "✅ $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        success "$1 is installed"
        return 0
    else
        error "$1 is not installed"
        return 1
    fi
}

# 1. Check Go installation
echo "1. Checking Go installation..."
if check_command go; then
    go version
else
    error "Go is required for RDMA development"
fi
echo ""

# 2. Check RDMA tools
echo "2. Checking RDMA tools..."
check_command rdma
check_command ibv_devinfo
if command -v ibv_devices &> /dev/null; then
    success "ibv_devices is available"
fi
echo ""

# 3. Check build tools (for cgo)
echo "3. Checking build tools (cgo support)..."
check_command gcc
check_command make
if dpkg -l | grep -q build-essential; then
    success "build-essential is installed"
else
    warning "build-essential package status unknown"
fi
echo ""

# 4. Check RDMA libraries
echo "4. Checking RDMA libraries..."
if ldconfig -p | grep -q libibverbs; then
    success "libibverbs found"
else
    error "libibverbs not found (required for RDMA development)"
fi
if ldconfig -p | grep -q librdmacm; then
    success "librdmacm found"
else
    error "librdmacm not found (required for RDMA development)"
fi
echo ""

# 5. Check RDMA devices
echo "5. Checking RDMA devices..."
if rdma link show &> /dev/null; then
    RDMA_DEVICES=$(rdma link show 2>/dev/null | wc -l)
    if [ "$RDMA_DEVICES" -gt 0 ]; then
        success "Found $RDMA_DEVICES RDMA device(s)"
        echo ""
        rdma link show | sed 's/^/    /'
        echo ""
    else
        warning "No RDMA devices found"
        echo "    Run 'setup-soft-roce.sh' to create soft-RoCE device"
    fi
else
    warning "Cannot query RDMA devices (rdma command failed)"
fi
echo ""

# 6. Check InfiniBand devices
echo "6. Checking InfiniBand devices..."
if [ -d /sys/class/infiniband ]; then
    IB_DEVICES=$(ls /sys/class/infiniband 2>/dev/null | wc -l)
    if [ "$IB_DEVICES" -gt 0 ]; then
        success "Found $IB_DEVICES InfiniBand device(s)"
        ls -1 /sys/class/infiniband | sed 's/^/    /'
    else
        warning "No InfiniBand devices found in /sys/class/infiniband"
    fi
else
    warning "/sys/class/infiniband does not exist"
fi
echo ""

# 7. Check ibverbs device info
echo "7. Checking ibverbs device info..."
if ibv_devinfo -l &> /dev/null; then
    IB_DEV_COUNT=$(ibv_devinfo -l 2>/dev/null | wc -l)
    if [ "$IB_DEV_COUNT" -gt 0 ]; then
        success "ibverbs devices detected"
        echo ""
        echo "Device details:"
        ibv_devinfo | head -n 30 | sed 's/^/    /'
        echo ""
    else
        warning "No ibverbs devices found"
    fi
else
    warning "ibv_devinfo command failed (no devices or permission issue)"
fi
echo ""

# 8. Test basic Go build with cgo
echo "8. Testing Go build capability (cgo)..."
cd /workspace
if [ -f "go.mod" ]; then
    # Try to build a package that uses cgo (RDMA package)
    if go build -o /tmp/test-rdma-build ./internal/rdma &> /tmp/build-output.txt; then
        success "RDMA package builds successfully with cgo"
        rm -f /tmp/test-rdma-build
    else
        error "RDMA package build failed"
        echo ""
        echo "Build output:"
        cat /tmp/build-output.txt | head -n 20 | sed 's/^/    /'
        echo ""
    fi
    rm -f /tmp/build-output.txt
else
    warning "Not in R-Pingmesh workspace, skipping build test"
fi
echo ""

# 9. Check RDMA_ENABLED environment variable
echo "9. Checking RDMA environment configuration..."
if [ "$RDMA_ENABLED" = "1" ]; then
    success "RDMA_ENABLED is set to 1"
else
    warning "RDMA_ENABLED environment variable is not set"
fi
echo ""

# 10. Test RDMA functionality (if device available)
echo "10. Testing RDMA functionality..."
if rdma link show 2>/dev/null | grep -q "rxe"; then
    success "soft-RoCE device (rxe) is active"

    # Try to run a simple RDMA test if available
    cd /workspace
    if [ -f "go.mod" ]; then
        echo ""
        echo "  Running basic RDMA device test..."
        if timeout 10 go test -v ./internal/rdma -run TestDeviceInit 2>&1 | tee /tmp/rdma-test-output.txt | grep -q "PASS\|SKIP"; then
            if grep -q "PASS" /tmp/rdma-test-output.txt; then
                success "RDMA device initialization test PASSED"
            elif grep -q "SKIP" /tmp/rdma-test-output.txt; then
                warning "RDMA test SKIPPED (may need additional setup)"
            fi
        else
            warning "RDMA test failed or timed out"
            echo ""
            echo "Test output:"
            cat /tmp/rdma-test-output.txt | tail -n 20 | sed 's/^/    /'
            echo ""
        fi
        rm -f /tmp/rdma-test-output.txt
    fi
else
    warning "No soft-RoCE device found - RDMA functionality test skipped"
    echo "    Create soft-RoCE device with: setup-soft-roce.sh"
fi
echo ""

# Platform detection
echo "=================================================="
echo "Platform Information"
echo "=================================================="
PLATFORM=$(uname -s)
echo "Platform: $PLATFORM"

if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    if [ -d /colima ]; then
        echo "Host: macOS with Colima VM (recommended)"
    else
        echo "Host: Docker container"
    fi
fi
echo ""

# Summary
echo "=================================================="
echo "Validation Summary"
echo "=================================================="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo "✅ RDMA environment is ready for development!"
    if [ $WARNINGS -gt 0 ]; then
        echo "⚠️  Some warnings detected. Review output above."
        echo ""
        echo "Common fixes:"
        echo "  - No RDMA devices: Run 'setup-soft-roce.sh'"
        echo "  - Module load failures: Check host kernel support"
        echo ""
        echo "For detailed diagnosis, run:"
        echo "  .devcontainer/check-rdma-readiness.sh"
    fi
    exit 0
else
    echo "❌ RDMA environment has critical errors. Please fix issues above."
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Run detailed diagnostics: .devcontainer/check-rdma-readiness.sh"
    echo "  2. Ensure RDMA packages are installed"
    echo "  3. Check build-essential for cgo support"
    echo "  4. Run 'setup-soft-roce.sh' to create soft-RoCE device"
    echo ""
    echo "Platform-specific guidance:"
    echo ""
    echo "Linux host:"
    echo "  - Load kernel modules: sudo modprobe rdma_rxe"
    echo "  - Full RDMA/eBPF support available"
    echo ""
    echo "macOS + Colima:"
    echo "  - Ensure Colima VM is running: colima status"
    echo "  - Full RDMA/eBPF support available"
    echo "  - See: docs/dev/macos-colima-vm.md"
    echo ""
    echo "macOS + Docker Desktop:"
    echo "  - Limited RDMA support"
    echo "  - Consider switching to Colima for better compatibility"
    echo "  - See: docs/dev/macos-colima-vm.md"
    echo ""
    echo "Documentation:"
    echo "  - Devcontainer setup: docs/dev/devcontainer-rdma-setup.md"
    echo "  - Colima setup: docs/dev/macos-colima-vm.md"
    exit 1
fi
