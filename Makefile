.PHONY: build agent-up debugfs-volume generate-config generate-bpf test-controller test-agent test clean-compose clean build-local

# Default configuration
IMAGE_NAME := rpingmesh-agent
VERSION := 0.1.0
TAG := $(IMAGE_NAME):$(VERSION)
KERNEL_VERSION := 5.10.0-34

build: build-controller build-agent

build-controller:
	@echo "Building controller with Docker Compose"
	@KERNEL_VERSION=$(KERNEL_VERSION) VERSION=$(VERSION) docker compose -f docker-compose.build.yml build controller-builder
	@echo "Copying controller binary from container..."
	@chmod +x scripts/copy-from-image.sh
	@./scripts/copy-from-image.sh rpingmesh-cursor-controller-builder controller-temp /app/controller ./bin/controller
	@./scripts/copy-from-image.sh rpingmesh-cursor-controller-builder controller-temp /app/controller.yaml ./bin/controller.yaml

build-agent:
	@echo "Building agent with Docker Compose"
	@KERNEL_VERSION=$(KERNEL_VERSION) VERSION=$(VERSION) docker compose -f docker-compose.build.yml build agent-builder
	@echo "Copying agent binary from container..."
	@chmod +x scripts/copy-from-image.sh
	@./scripts/copy-from-image.sh rpingmesh-cursor-agent-builder agent-temp /app/agent ./bin/agent
	@./scripts/copy-from-image.sh rpingmesh-cursor-agent-builder agent-temp /app/agent.yaml ./bin/agent.yaml

# Run with Docker Compose
agent-up:
	@echo "Starting service with Docker Compose"
	@KERNEL_VERSION=$(KERNEL_VERSION) VERSION=$(VERSION) docker compose up agent

# Create a debugfs volume for Docker Desktop
debugfs-volume:
	@echo "Creating debugfs volume for Docker Desktop..."
	@docker volume create --driver local --opt type=debugfs --opt device=debugfs debugfs || echo "Volume may already exist"
	@echo "debugfs volume created."

generate-config:
	@echo "Generating default configuration file with Docker Compose"
	@KERNEL_VERSION=$(KERNEL_VERSION) VERSION=$(VERSION) docker compose run --rm generate-config > agent.yaml
	@echo "Configuration file generated: ./agent.yaml"

# Clean up Docker Compose resources
clean-compose:
	@echo "Cleaning up Docker Compose resources"
	@docker compose down -v
	@docker compose rm -f

# Clean up Docker images
clean:
	@echo "Removing Docker image: $(TAG)"
	@docker rmi $(TAG) || true

build-local:
	@echo "Building controller and agent locally"
	@go build -buildvcs=false -o ./bin/controller ./cmd/controller
	@go build -buildvcs=false -o ./bin/agent ./cmd/agent

# Generate bpf2go code locally (requires local dependencies)
ARCH_SUFFIX := $(shell if [ -d /usr/include/$$(uname -m)-linux-gnu ]; then echo "$$(uname -m)-linux-gnu"; fi)
INCLUDE_PATHS := -Ipkg/ebpf/bpf/include -I/usr/include
ifneq ($(ARCH_SUFFIX),)
	INCLUDE_PATHS += -I/usr/include/$(ARCH_SUFFIX)
	INCLUDE_PATHS += -I/usr/include/$(ARCH_SUFFIX)/asm
endif
ifeq ($(wildcard /usr/include/asm),/usr/include/asm)
	INCLUDE_PATHS += -I/usr/include/asm
endif
ifeq ($(wildcard /usr/include/asm-generic),/usr/include/asm-generic)
	INCLUDE_PATHS += -I/usr/include/asm-generic
endif

generate-bpf:
	@echo "Generating eBPF Go bindings"
	@mkdir -p pkg/ebpf/bpf/include
	@if [ ! -f pkg/ebpf/bpf/include/vmlinux.h ]; then \
		cp scripts/minimal_vmlinux.h pkg/ebpf/bpf/include/vmlinux.h; \
	fi
	@echo "Using include paths for bpf2go: $(INCLUDE_PATHS)"
	@cd pkg/ebpf && GOPACKAGE=ebpf bpf2go -cc clang \
		-go-package github.com/yuuki/rpingmesh/pkg/ebpf \
		rdmaTracing ../ebpf/bpf/rdma_tracing.c -- $(INCLUDE_PATHS)

# Test controller
test-controller:
	@echo "Running controller tests with Docker..."
	@docker compose -f docker-compose.test.yml up --build controller_test --abort-on-container-exit --remove-orphans

# Test agent
test-agent:
	@echo "Running agent tests with Docker..."
	@KERNEL_VERSION=$(KERNEL_VERSION) docker compose -f docker-compose.test.yml up --build agent_test --abort-on-container-exit --remove-orphans

# Run all tests
test:
	@echo "Running all tests with Docker..."
	@KERNEL_VERSION=$(KERNEL_VERSION) docker compose -f docker-compose.test.yml up --build controller_test agent_test --abort-on-container-exit

test-local:
	@echo "Running all Go tests locally"
	@go test ./...

# Help target
help:
	@echo "Available targets:"
	@echo "  build            - Build the Docker image with Docker Compose"
	@echo "  build-local      - Build the controller and agent binaries locally"
	@echo "  agent-up         - Run the agent container with Docker Compose"
	@echo "  debugfs-volume   - Create debugfs volume for Docker Desktop"
	@echo "  generate-config  - Generate default configuration file with Docker Compose"
	@echo "  generate-bpf     - Generate eBPF Go bindings locally"
	@echo "  test-controller  - Run controller tests with Docker Compose"
	@echo "  test-agent       - Run agent tests with Docker Compose"
	@echo "  test             - Run all tests with Docker Compose"
	@echo "  test-local       - Run all Go tests locally"
	@echo "  clean            - Remove the Docker image"
	@echo "  clean-compose    - Clean up Docker Compose resources"
	@echo "  help             - Show this help message"
