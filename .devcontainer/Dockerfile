FROM golang:1.24-bullseye

ARG KERNEL_VERSION
ENV KERNEL_VERSION=${KERNEL_VERSION}

# Install common development dependencies
RUN apt-get update && apt-get install -y \
    apt-utils \
    git \
    curl \
    wget \
    vim \
    tmux \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    bpftool \
    pkg-config \
    libibverbs-dev \
    librdmacm-dev \
    dpkg-dev \
    linux-libc-dev \
    iproute2 \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Try to install kernel headers, but continue if it fails
RUN if [ -n "${KERNEL_VERSION}" ]; then \
    apt-get update && \
    apt-get install -y linux-headers-${KERNEL_VERSION} || \
    echo "Warning: Failed to install linux-headers-${KERNEL_VERSION}. eBPF features may not work correctly."; \
    fi

# Install Go tools
RUN go install golang.org/x/tools/gopls@latest \
    && go install github.com/go-delve/delve/cmd/dlv@latest \
    && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest \
    && go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Install protoc
RUN apt-get update && apt-get install -y protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /workspace

# Make sure scripts are executable
RUN mkdir -p /workspace/.devcontainer && \
    echo '#!/bin/bash\necho "Dev container initialized"' > /workspace/.devcontainer/init.sh && \
    chmod +x /workspace/.devcontainer/init.sh
