# R-Pingmesh Rebuild - Build System
# Requires: Go 1.26+, Zig 0.16+, protoc, clang, libibverbs-dev, librdmacm-dev

.PHONY: all build build-zig build-go build-controller build-agent \
        generate generate-proto clean test test-go \
        test-e2e setup-colima test-e2e-controller clean-e2e-controller help

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
	cd $(ZIG_DIR) && zig build
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

# Install rdma_rxe kernel module on the Colima VM (run once before first test-e2e).
# Requires colima to be running: colima start
setup-colima:
	@chmod +x scripts/setup-colima-rdma.sh
	@bash scripts/setup-colima-rdma.sh

# Run RDMA e2e tests via Docker (requires Colima or Docker with privileged containers).
# Sets up two soft-RoCE devices (rxe0, rxe1) and runs TestRDMAE2E.
# First-time setup: run 'make setup-colima' to install rdma_rxe on the Colima VM.
test-e2e:
	@echo "==> Running RDMA e2e tests (soft-RoCE, rxe0+rxe1)..."
	docker compose -f docker-compose.e2e.yml run --rm --build rdma-e2e
	@echo "==> e2e tests complete"

# Run Agent-to-Controller E2E tests (requires Docker, no RDMA needed)
test-e2e-controller:
	@echo "==> Running Agent-to-Controller E2E tests..."
	COMPOSE_FILE=docker-compose.e2e-controller.yml docker compose up --build --abort-on-container-exit e2e_test
	@echo "==> E2E tests complete"

# Clean up Agent-to-Controller E2E Docker resources
clean-e2e-controller:
	COMPOSE_FILE=docker-compose.e2e-controller.yml docker compose down -v

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
	@echo "  all                  Build everything (default)"
	@echo "  build                Build Zig library, generate proto, build Go"
	@echo "  build-zig            Build Zig RDMA bridge static library"
	@echo "  build-go             Build Go controller and agent binaries"
	@echo "  build-controller     Build controller binary only"
	@echo "  build-agent          Build agent binary only"
	@echo "  generate             Generate all code (proto)"
	@echo "  generate-proto       Generate protobuf Go code"
	@echo "  test                 Run tests"
	@echo "  test-go              Run Go tests"
	@echo "  setup-colima         Install rdma_rxe kernel module on Colima VM (run once)"
	@echo "  test-e2e             Run RDMA e2e tests via Docker (requires Colima)"
	@echo "  test-e2e-controller  Run Agent-to-Controller E2E tests (Docker)"
	@echo "  clean-e2e-controller Clean up Agent-to-Controller E2E Docker resources"
	@echo "  clean                Remove all build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  Go 1.26+, Zig 0.16+, protoc, libibverbs-dev, librdmacm-dev"
	@echo "  For test-e2e: colima running, run 'make setup-colima' first"
