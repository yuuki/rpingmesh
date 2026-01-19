#!/bin/bash
# RDMA environment diagnostic tool
# Displays detailed current environment status and provides platform-specific guidance

set -e

echo ""
echo "===================================="
echo "RDMA Readiness Check"
echo "===================================="
echo ""

# Platform detection
PLATFORM=$(uname -s)
echo "Platform: $PLATFORM (Docker container)"

# Estimate host environment
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    if [ -d /colima ]; then
        HOST_TYPE="macOS with Colima VM"
    elif [ -f /run/.containerenv ]; then
        HOST_TYPE="Podman container"
    else
        HOST_TYPE="Docker container (unknown host)"
    fi
else
    HOST_TYPE="Unknown (not in container)"
fi
echo "Host: $HOST_TYPE"
echo ""

# Check container capabilities
echo "Container Capabilities:"
if command -v capsh &> /dev/null; then
    CAPS=$(capsh --print 2>/dev/null | grep "Current:" | cut -d: -f2 || echo "")

    check_cap() {
        if echo "$CAPS" | grep -q "$1"; then
            echo "  ✅ $1"
            return 0
        else
            echo "  ❌ $1 (missing)"
            return 1
        fi
    }

    check_cap "cap_sys_admin"
    check_cap "cap_net_admin"
    check_cap "cap_bpf" || echo "     (Required for eBPF programs)"
    check_cap "cap_ipc_lock"

    # Check privileged mode
    if [ -r /proc/1/status ] && grep -q "CapEff:.*0000003fffffffff" /proc/1/status 2>/dev/null; then
        echo "  ✅ Privileged mode: enabled"
    else
        echo "  ⚠️  Privileged mode: may not be fully enabled"
    fi
else
    echo "  ⚠️  capsh command not available"
fi
echo ""

# Check kernel modules
echo "Kernel Modules:"
check_module() {
    if lsmod | grep -q "^$1 "; then
        echo "  ✅ $1: loaded"
        return 0
    else
        echo "  ❌ $1: not loaded"
        return 1
    fi
}

RDMA_MODULES_OK=true
check_module "rdma_rxe" || RDMA_MODULES_OK=false
check_module "ib_core" || RDMA_MODULES_OK=false
check_module "ib_uverbs" || RDMA_MODULES_OK=false
echo ""

# Check RDMA devices
echo "RDMA Devices:"
if command -v rdma &> /dev/null; then
    RDMA_DEVICES=$(rdma link show 2>/dev/null || echo "")
    if [ -n "$RDMA_DEVICES" ]; then
        echo "  ✅ RDMA devices found:"
        echo "$RDMA_DEVICES" | sed 's/^/    /'
        RDMA_DEVICES_OK=true
    else
        echo "  ❌ No RDMA devices found"
        RDMA_DEVICES_OK=false
    fi
else
    echo "  ❌ rdma command not available"
    RDMA_DEVICES_OK=false
fi
echo ""

# Check ibverbs devices
echo "ibverbs Devices:"
if command -v ibv_devinfo &> /dev/null; then
    IBV_DEVICES=$(ibv_devinfo -l 2>/dev/null || echo "")
    if [ -n "$IBV_DEVICES" ]; then
        echo "  ✅ ibverbs devices detected:"
        echo "$IBV_DEVICES" | sed 's/^/    /'
    else
        echo "  ❌ No ibverbs devices found"
    fi
else
    echo "  ❌ ibv_devinfo command not available"
fi
echo ""

# Check InfiniBand sysfs
echo "InfiniBand sysfs:"
if [ -d /sys/class/infiniband ]; then
    IB_DEVICES=$(ls -1 /sys/class/infiniband 2>/dev/null || echo "")
    if [ -n "$IB_DEVICES" ]; then
        echo "  ✅ InfiniBand devices in sysfs:"
        echo "$IB_DEVICES" | sed 's/^/    /'
    else
        echo "  ⚠️  /sys/class/infiniband exists but is empty"
    fi
else
    echo "  ❌ /sys/class/infiniband not found"
fi
echo ""

# Check eBPF support
echo "eBPF Support:"
EBPF_OK=true

# Check debugfs mount
if mount | grep -q "debugfs on /sys/kernel/debug"; then
    echo "  ✅ debugfs mounted at /sys/kernel/debug"
else
    echo "  ❌ debugfs not mounted"
    EBPF_OK=false
fi

# Check BTF availability
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "  ✅ BTF available (vmlinux)"
else
    echo "  ⚠️  BTF vmlinux not found"
fi

# Check BTF module (ib_core)
if [ -f /sys/kernel/btf/ib_core ]; then
    echo "  ✅ BTF available (ib_core)"
elif [ -d /sys/kernel/btf ]; then
    echo "  ⚠️  BTF ib_core not found (may affect RDMA tracing)"
fi
echo ""

# Overall assessment
echo "===================================="
echo "Overall Status"
echo "===================================="
echo ""

if [ "$RDMA_MODULES_OK" = true ] && [ "$RDMA_DEVICES_OK" = true ] && [ "$EBPF_OK" = true ]; then
    echo "🎉 Environment is ready for RDMA development!"
    echo ""
    echo "Next steps:"
    echo "  - Run tests: go test ./internal/rdma -v"
    echo "  - Start agent: ./bin/rpingmesh-agent"
elif [ "$RDMA_DEVICES_OK" = true ]; then
    echo "✅ RDMA devices are available"
    echo "⚠️  Some eBPF features may be limited"
    echo ""
    echo "Next steps:"
    echo "  - Run RDMA tests: go test ./internal/rdma -v"
    echo "  - For eBPF issues, check debugfs mount"
else
    echo "❌ RDMA environment is not ready"
    echo ""
    echo "Troubleshooting:"

    if [ "$RDMA_MODULES_OK" = false ]; then
        echo ""
        echo "1. Load RDMA kernel modules:"
        echo "   sudo modprobe rdma_rxe"
        echo "   sudo modprobe ib_core"
        echo "   sudo modprobe ib_uverbs"
        echo ""
    fi

    if [ "$RDMA_DEVICES_OK" = false ]; then
        echo "2. Create soft-RoCE device:"
        echo "   Run: setup-soft-roce.sh [interface-name]"
        echo "   Or manually:"
        echo "     sudo rdma link add rxe0 type rxe netdev eth0"
        echo ""
    fi

    if [ "$EBPF_OK" = false ]; then
        echo "3. Mount debugfs (if missing):"
        echo "   sudo mount -t debugfs none /sys/kernel/debug"
        echo ""
    fi

    echo "For more help, see:"
    echo "  - docs/dev/devcontainer-rdma-setup.md"
    echo "  - docs/dev/macos-colima-vm.md"
    echo "  - .devcontainer/validate-rdma-environment.sh"
fi

echo ""
echo "===================================="
echo ""
