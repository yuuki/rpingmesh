# R-Pingmesh Rebuild - Build System
# Requires: Go 1.24+, Zig 0.13+, protoc, clang, libibverbs-dev, librdmacm-dev

.PHONY: all build build-zig build-go build-controller build-agent \
        generate generate-proto clean test test-go help

# Directories
ZIG_DIR := zig
ZIG_OUT := $(ZIG_DIR)/zig-out
BIN_DIR := bin
PROTO_DIR := proto/controller_agent

# Output binaries
CONTROLLER_BIN := $(BIN_DIR)/rpingmesh-controller
AGENT_BIN := $(BIN_DIR)/rpingmesh-agent

# Default target
all: build

# Build everything
build: build-zig generate build-go

# Build Zig static library
build-zig:
	@echo "==> Building Zig RDMA bridge library..."
	cd $(ZIG_DIR) && zig build -Doptimize=ReleaseSafe
	@echo "==> Zig library built: $(ZIG_OUT)/lib/librdmabridge.a"

# Generate protobuf code
generate: generate-proto

generate-proto:
	@echo "==> Generating protobuf code..."
	cd $(PROTO_DIR) && go generate
	@echo "==> Proto generation complete"

# Build Go binaries
build-go: build-controller build-agent

build-controller:
	@echo "==> Building controller..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -o $(CONTROLLER_BIN) ./cmd/controller/
	@echo "==> Controller built: $(CONTROLLER_BIN)"

build-agent:
	@echo "==> Building agent..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -o $(AGENT_BIN) ./cmd/agent/
	@echo "==> Agent built: $(AGENT_BIN)"

# Run Go tests (probe package is pure Go, no RDMA needed)
test: test-go

test-go:
	@echo "==> Running Go tests..."
	go test -v ./internal/probe/...
	@echo "==> Tests complete"

# Clean build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	cd $(ZIG_DIR) && rm -rf zig-out .zig-cache
	@echo "==> Clean complete"

# Help
help:
	@echo "R-Pingmesh Rebuild Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all             Build everything (default)"
	@echo "  build           Build Zig library, generate proto, build Go"
	@echo "  build-zig       Build Zig RDMA bridge static library"
	@echo "  build-go        Build Go controller and agent binaries"
	@echo "  build-controller Build controller binary only"
	@echo "  build-agent     Build agent binary only"
	@echo "  generate        Generate all code (proto)"
	@echo "  generate-proto  Generate protobuf Go code"
	@echo "  test            Run tests"
	@echo "  test-go         Run Go tests"
	@echo "  clean           Remove all build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  Go 1.24+, Zig 0.13+, protoc, libibverbs-dev, librdmacm-dev"
