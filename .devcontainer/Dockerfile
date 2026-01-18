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
    pkg-config \
    libibverbs-dev \
    librdmacm-dev \
    rdma-core \
    ibverbs-utils \
    build-essential \
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

# Install protoc
RUN apt-get update && apt-get install -y protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install rqlite
RUN curl -L https://github.com/rqlite/rqlite/releases/download/v8.37.0/rqlite-v8.37.0-linux-amd64.tar.gz | tar -xz && \
    mv rqlite-v8.37.0-linux-amd64/rqlited /usr/local/bin/rqlited && \
    mv rqlite-v8.37.0-linux-amd64/rqlite /usr/local/bin/rqlite && \
    rm -rf rqlite-v8.37.0-linux-amd64

# Set up working directory
WORKDIR /workspace

# Make sure scripts are executable
RUN mkdir -p /workspace/.devcontainer && \
    echo '#!/bin/bash\necho "Dev container initialized"' > /workspace/.devcontainer/init.sh && \
    chmod +x /workspace/.devcontainer/init.sh
