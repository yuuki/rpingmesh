#!/bin/bash
set -e

# Script to generate eBPF code and Go bindings on the host system
# This is useful for development on systems with all the required dependencies installed

# Ensure we're in the project root
cd "$(dirname "$0")/.."

echo "Generating eBPF code and Go bindings..."

# Create include directory if it doesn't exist
mkdir -p pkg/ebpf/bpf/include

# Check if vmlinux.h exists, use minimal version if not generated
if [ ! -f pkg/ebpf/bpf/include/vmlinux.h ]; then
    echo "Using minimal vmlinux.h header..."
    cp scripts/minimal_vmlinux.h pkg/ebpf/bpf/include/vmlinux.h

    # Try to generate a full vmlinux.h if bpftool is available
    if command -v bpftool &> /dev/null; then
        echo "Attempting to generate complete vmlinux.h using bpftool..."
        if [ -f /sys/kernel/btf/vmlinux ]; then
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/ebpf/bpf/include/vmlinux.h.new
            if [ $? -eq 0 ]; then
                # Only replace if successful
                mv pkg/ebpf/bpf/include/vmlinux.h.new pkg/ebpf/bpf/include/vmlinux.h
                echo "Successfully generated vmlinux.h from kernel BTF"
            else
                echo "Failed to generate vmlinux.h from kernel BTF, using minimal version"
                rm -f pkg/ebpf/bpf/include/vmlinux.h.new
            fi
        else
            echo "Kernel BTF not available at /sys/kernel/btf/vmlinux"
        fi
    else
        echo "bpftool not found. Using minimal vmlinux.h."
    fi
fi

# Determine architecture for include paths
ARCH_SUFFIX=""
if [ -d "/usr/include/$(uname -m)-linux-gnu" ]; then
  ARCH_SUFFIX="$(uname -m)-linux-gnu"
fi

# Add all potentially relevant include paths
INCLUDE_PATHS="-I pkg/ebpf/bpf/include -I /usr/include"
[ -n "$ARCH_SUFFIX" ] && INCLUDE_PATHS="$INCLUDE_PATHS -I /usr/include/$ARCH_SUFFIX"
[ -d /usr/include/asm ] && INCLUDE_PATHS="$INCLUDE_PATHS -I /usr/include/asm"
[ -d /usr/include/asm-generic ] && INCLUDE_PATHS="$INCLUDE_PATHS -I /usr/include/asm-generic"
[ -n "$ARCH_SUFFIX" ] && [ -d /usr/include/$ARCH_SUFFIX/asm ] && INCLUDE_PATHS="$INCLUDE_PATHS -I /usr/include/$ARCH_SUFFIX/asm"

# Compile BPF C code
echo "Compiling eBPF code..."
if command -v clang &> /dev/null; then
    echo "Using include paths: $INCLUDE_PATHS"

    clang -g -O2 -Wall -target bpf \
        $INCLUDE_PATHS \
        -c pkg/ebpf/bpf/rdma_tracing.c -o /tmp/rdma_tracing.o

    if [ $? -eq 0 ]; then
        echo "BPF binary compiled: /tmp/rdma_tracing.o"
    else
        echo "Warning: BPF compilation had errors but we'll continue anyway"
        touch /tmp/rdma_tracing.o  # Create empty file to continue
    fi
else
    echo "WARNING: clang not found. Cannot compile eBPF code."
    echo "Please install clang to compile eBPF code."
    exit 1
fi

# Generate Go bindings using bpf2go
echo "Generating Go bindings..."
if ! command -v bpf2go &> /dev/null; then
    echo "Installing bpf2go..."
    go install github.com/cilium/ebpf/cmd/bpf2go@latest
fi

# Package name is required for bpf2go
cd pkg/ebpf
GOPACKAGE=ebpf bpf2go -cc clang \
    -go-package github.com/yuuki/rpingmesh/pkg/ebpf \
    rdmaTracing ../ebpf/bpf/rdma_tracing.c -- \
    $INCLUDE_PATHS

echo "eBPF code generation completed!"
