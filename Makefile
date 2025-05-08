.PHONY: build run clean generate debugfs-volume run-desktop test-registry

# Default configuration
IMAGE_NAME := rpingmesh-agent
VERSION := 0.1.0
TAG := $(IMAGE_NAME):$(VERSION)
KERNEL_VERSION := 5.10.0-34

# Build the Docker image
build:
	@echo "Building Docker image: $(TAG)"
	@docker build --build-arg KERNEL_VERSION=$(KERNEL_VERSION) -t $(TAG) .

# Build the Docker image with debug output
build-debug:
	@echo "Building Docker image with debug output: $(TAG)"
	@docker build --build-arg KERNEL_VERSION=$(KERNEL_VERSION) --progress=plain -t $(TAG) .

# Run the Docker container with privileged mode
run: build
	@echo "Running Docker container: $(TAG)"
	@docker run -it --rm \
		--privileged \
		--cap-add SYS_ADMIN \
		--cap-add NET_ADMIN \
		--cap-add IPC_LOCK \
		--network host \
		$(TAG)

# Run the Docker container with a specific config file
run-with-config: build
	@echo "Running Docker container with config: $(TAG)"
	@docker run -it --rm \
		--privileged \
		--cap-add SYS_ADMIN \
		--cap-add NET_ADMIN \
		--cap-add IPC_LOCK \
		--network host \
		-v $(PWD)/agent.yaml:/app/config.yaml \
		$(TAG) --config /app/config.yaml

# Create a debugfs volume for Docker Desktop
debugfs-volume:
	@echo "Creating debugfs volume for Docker Desktop..."
	@docker volume create --driver local --opt type=debugfs --opt device=debugfs debugfs || echo "Volume may already exist"
	@echo "debugfs volume created."

# Run with Docker Desktop support
run-desktop: build debugfs-volume
	@echo "Running Docker container with Docker Desktop support: $(TAG)"
	@docker run -it --rm \
		--privileged \
		--cap-add SYS_ADMIN \
		--cap-add NET_ADMIN \
		--cap-add IPC_LOCK \
		--network host \
		-v debugfs:/sys/kernel/debug \
		$(TAG)

# Generate a default configuration file
generate-config:
	@echo "Generating default configuration file"
	@docker run --rm \
		$(TAG) --create-config --config-output /app/agent.yaml
	@docker cp $$(docker ps -lq):/app/agent.yaml ./agent.yaml
	@echo "Configuration file generated: ./agent.yaml"

# Clean up Docker images
clean:
	@echo "Removing Docker image: $(TAG)"
	@docker rmi $(TAG) || true

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
	@scripts/test-controller.sh

# Help target
help:
	@echo "Available targets:"
	@echo "  build            - Build the Docker image"
	@echo "  build-debug      - Build with debug output"
	@echo "  run              - Run the Docker container with privileged mode"
	@echo "  run-with-config  - Run with a specific config file"
	@echo "  run-desktop      - Run with Docker Desktop support (with debugfs)"
	@echo "  debugfs-volume   - Create debugfs volume for Docker Desktop"
	@echo "  generate-config  - Generate a default configuration file"
	@echo "  clean            - Remove the Docker image"
	@echo "  generate-bpf     - Generate eBPF Go bindings locally"
	@echo "  test-registry    - Run registry tests with Docker"
	@echo "  help             - Show this help message"
