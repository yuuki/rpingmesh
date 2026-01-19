#!/bin/bash
# Host environment pre-validation script
# Runs before post-create.sh to detect host environment and provide warnings

set -e

echo ""
echo "=============================================="
echo "Host Environment Pre-validation"
echo "=============================================="
echo ""

# Platform detection
PLATFORM=$(uname -s)
echo "Detected platform: $PLATFORM"

# Check container environment
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo "Running inside container: Yes"

    # Estimate host environment
    if [ -d /colima ]; then
        echo "Container runtime: Colima"
        echo "✅ Colima supports RDMA kernel modules and eBPF"
    else
        echo "Container runtime: Docker (or compatible)"
        echo "⚠️  Host type could not be determined"
    fi
else
    echo "Running inside container: No (unexpected)"
fi
echo ""

# Check kernel version
KERNEL_VERSION=$(uname -r)
echo "Kernel version: $KERNEL_VERSION"

# Check kernel minimum requirement (5.4+)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 4 ]); then
    echo "✅ Kernel version is sufficient for eBPF (≥5.4 required)"
else
    echo "⚠️  Kernel version may be too old for eBPF (5.4+ recommended)"
fi
echo ""

# Check for required kernel modules
echo "Checking for RDMA kernel modules..."
MODULES_AVAILABLE=true

check_module_file() {
    MODULE_NAME=$1
    # Check if module is available in /lib/modules or /sys/module
    if [ -d "/lib/modules/$(uname -r)/kernel/drivers/infiniband" ] || \
       modprobe -n "$MODULE_NAME" &>/dev/null; then
        echo "  ✅ $MODULE_NAME: available"
        return 0
    else
        echo "  ❌ $MODULE_NAME: not found"
        return 1
    fi
}

check_module_file "rdma_rxe" || MODULES_AVAILABLE=false
check_module_file "ib_core" || MODULES_AVAILABLE=false

if [ "$MODULES_AVAILABLE" = false ]; then
    echo ""
    echo "⚠️  Warning: Some RDMA kernel modules are not available"
    echo "    This may affect RDMA device functionality"
    echo ""
    echo "    For Colima users:"
    echo "      - Ensure Colima VM is running with kernel module support"
    echo "      - Check: colima status"
    echo ""
    echo "    For Docker Desktop users:"
    echo "      - Docker Desktop has limited kernel module support"
    echo "      - Consider using Colima for RDMA development"
    echo "      - See: docs/dev/macos-colima-vm.md"
fi
echo ""

# Check debugfs
echo "Checking debugfs..."
if [ -d /sys/kernel/debug ]; then
    echo "  ✅ /sys/kernel/debug exists"
    if mount | grep -q "debugfs on /sys/kernel/debug"; then
        echo "  ✅ debugfs is already mounted"
    else
        echo "  ⚠️  debugfs exists but not mounted (will attempt in post-create)"
    fi
else
    echo "  ⚠️  /sys/kernel/debug does not exist (may need host support)"
fi
echo ""

# Platform-specific guidance
echo "=============================================="
echo "Platform-Specific Guidance"
echo "=============================================="
echo ""

if [ "$PLATFORM" = "Linux" ]; then
    echo "Platform: Linux"
    echo ""
    echo "Expected capabilities:"
    echo "  ✅ RDMA kernel modules (if host supports)"
    echo "  ✅ soft-RoCE device creation"
    echo "  ✅ eBPF program loading"
    echo "  ✅ Full development and testing"
    echo ""
    echo "If RDMA setup fails, check:"
    echo "  - Kernel module availability (modprobe rdma_rxe)"
    echo "  - Container privileges (--privileged or CAP_BPF)"
    echo "  - debugfs mount (should be automatic)"
    echo ""
else
    echo "Platform: $PLATFORM"
    echo ""
    echo "Note: Non-Linux platforms have limitations"
    echo "  ⚠️  Direct RDMA support may be limited"
    echo "  ⚠️  Depends on VM/container runtime capabilities"
    echo ""
    echo "Recommended setup:"
    echo "  - Use Colima for full RDMA support"
    echo "  - See: docs/dev/macos-colima-vm.md"
fi

echo "=============================================="
echo ""
echo "Pre-validation complete. Continuing with environment setup..."
echo ""
