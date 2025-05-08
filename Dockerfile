FROM golang:1.24-bullseye AS builder

ARG KERNEL_VERSION
RUN if [ -z "$KERNEL_VERSION" ]; then \
      echo >&2 "ERROR: KERNEL_VERSION is empty.  \
      Please pass --build-arg KERNEL_VERSION=$(uname -r)"; \
      exit 1; \
    fi

# Install necessary dependencies for eBPF and RDMA development
RUN apt-get update && apt-get install -y \
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
    linux-headers-${KERNEL_VERSION} \
    linux-headers-${KERNEL_VERSION}-common \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Compile eBPF C code using standard include paths
RUN clang -g -O2 -Wall -target bpf \
      -I pkg/ebpf/bpf/include \
      -I /usr/src/linux-headers-${KERNEL_VERSION}-common/include \
      -I /usr/src/linux-headers-${KERNEL_VERSION}/include \
      -I /usr/include \
      -c pkg/ebpf/bpf/rdma_tracing.c -o /tmp/rdma_tracing.o || touch /tmp/rdma_tracing.o

# Install bpf2go and run go generate to create eBPF bindings
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest
RUN cd pkg/ebpf && KERNEL_VERSION=${KERNEL_VERSION} go generate ./...

# Build the Go application
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /app/bin/agent cmd/agent/main.go

# Create default configuration
RUN mkdir -p /app && \
    /app/bin/agent --create-config --config-output /app/agent.yaml || true

# Runtime image
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libibverbs1 \
    librdmacm1 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary and config
COPY --from=builder /app/bin/agent ./agent
COPY --from=builder /app/agent.yaml ./agent.yaml

ENTRYPOINT ["./agent"]
