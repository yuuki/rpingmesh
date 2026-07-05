# R-Pingmesh Rebuild - Build System
# Requires: Go 1.26+, Zig 0.15.2 (the version verified in e2e/CI), protoc,
# clang, libibverbs-dev, librdmacm-dev

.PHONY: all build build-zig build-go build-controller build-agent \
        generate generate-proto clean test test-go test-zig test-all vet \
        test-e2e setup-colima test-e2e-controller clean-e2e-controller \
        check-nfpm package package-agent package-controller \
        package-build-agent package-build-controller help

# Directories
ZIG_DIR := zig
ZIG_OUT := $(ZIG_DIR)/zig-out
BIN_DIR := bin
PROTO_DIR := proto/controller_agent
DIST_DIR := dist

# Output binaries
CONTROLLER_BIN := $(BIN_DIR)/rpingmesh-controller
AGENT_BIN := $(BIN_DIR)/rpingmesh-agent

# Package version/arch, consumed by packaging/nfpm/*.yaml via ${NFPM_VERSION}
# / ${NFPM_ARCH}. Override on the command line for a release build, e.g.:
#   make package VERSION=1.2.3
# deb/rpm both require the version to start with a digit, so the untagged
# fallback below is "0.0.0+git.<short sha>" rather than raw `git describe`
# output (which starts with the commit hash, not a digit, when there is no
# tag on HEAD -- true for this repo today).
NFPM_VERSION ?= $(shell v=$$(git describe --tags --exact-match 2>/dev/null); if [ -n "$$v" ]; then printf '%s' "$$v" | sed 's/^v//'; else printf '0.0.0+git.%s' "$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"; fi)
NFPM_ARCH ?= $(shell go env GOARCH 2>/dev/null || echo amd64)
ifdef VERSION
NFPM_VERSION := $(VERSION)
endif
export NFPM_VERSION NFPM_ARCH

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

# Run Go tests. NOTE: this only covers internal/probe/... (pure Go, no RDMA
# hardware needed). Use `make test-all` to run every package's tests (Linux,
# full CGO/RDMA build env) or `make test-e2e` / `make test-e2e-controller`
# for the Docker-based end-to-end suites.
test: test-go

test-go:
	@echo "==> Running Go tests..."
	go test -v ./internal/probe/...
	@echo "==> Tests complete"

# Run Zig unit tests (types.zig, ring.zig, cq.zig, etc.). Pure Zig, no Go/CGO
# involved, but still needs libibverbs/librdmacm headers on the build host
# (some modules @cImport them), so like build-zig this is Linux-only in
# practice (see Dockerfile.e2e).
test-zig:
	@echo "==> Running Zig unit tests..."
	cd $(ZIG_DIR) && zig build test
	@echo "==> Zig tests complete"

# Run `go vet` across the whole module.
vet:
	@echo "==> Running go vet..."
	go vet ./...
	@echo "==> Vet complete"

# Run all Go tests in the module (excluding ./e2e/..., which requires live
# infrastructure or RDMA hardware/soft-RoCE and is exercised by
# test-e2e / test-e2e-controller instead), plus the Zig unit tests. Requires
# the full CGO/RDMA build environment (libibverbs-dev, librdmacm-dev,
# librdmabridge.a already built), so this is intended for Linux, not local
# macOS development.
test-all: test-zig
	@echo "==> Running all Go tests (excluding ./e2e/...)..."
	go test $$(go list ./... | grep -v '/e2e')
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

# Fail fast with an actionable message if nfpm isn't installed, rather than
# letting `nfpm package` below fail with "command not found".
check-nfpm:
	@command -v nfpm >/dev/null 2>&1 || { \
		echo "ERROR: nfpm not found on PATH."; \
		echo "Install it (e.g. 'go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest'"; \
		echo "or see https://nfpm.goreleaser.com/install/), then re-run 'make package'."; \
		exit 1; \
	}

# Build .deb/.rpm packages for both the agent and the controller. See
# packaging/nfpm/*.yaml and packaging/systemd/*.service, and the "Deployment
# (systemd)" section of README.md for the full install/enable workflow.
package: package-agent package-controller

# Packaging-only build steps: unlike build-agent/build-controller (which
# target the host running `make`), these force GOOS=linux and
# GOARCH=$(NFPM_ARCH) so the resulting binary always matches what the nfpm
# packages below declare (platform: linux, arch: ${NFPM_ARCH}) -- regardless
# of what host `make package` is invoked from. Without this, `go build` on a
# macOS host would silently produce a Darwin binary and nfpm would happily
# wrap it in a package labelled "linux".
#
# The controller is CGO_ENABLED=0 (pure Go), so this cross-compiles cleanly
# from any host, including macOS. The agent is CGO_ENABLED=1 and links
# libibverbs/librdmacm via Cgo, which cannot cross-compile against a foreign
# C toolchain/sysroot -- GOOS=linux GOARCH=$(NFPM_ARCH) here only produces a
# working binary when `make` is actually run on a matching Linux host (see
# README.md "Building"); on any other host this step fails, same as
# build-agent does today.
# Depends on generate (proto codegen): both binaries import the generated
# proto/controller_agent/*.pb.go package, which is gitignored (regenerated by
# `make generate-proto`, not checked in). build-controller/build-agent have
# this same requirement, but today only the top-level `build` target
# sequences `generate` before them (build: build-zig generate build-go).
# package-build-controller is meant to be runnable standalone (e.g. straight
# after a fresh checkout or `make clean`, as `package-controller`'s
# prerequisite), so it declares the dependency explicitly rather than
# relying on the caller to remember the ordering.
package-build-controller: generate
	@echo "==> Building controller for packaging (GOOS=linux GOARCH=$(NFPM_ARCH))..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(NFPM_ARCH) go build -o $(CONTROLLER_BIN) ./cmd/controller/
	@echo "==> Controller built for packaging: $(CONTROLLER_BIN)"

# Depends on build-zig: the agent's Cgo build links zig/zig-out/lib/librdmabridge.a
# (see internal/rdmabridge/bridge.go's cgo LDFLAGS), which plain `go build`
# does not produce. Also depends on generate (proto codegen), for the same
# reason as package-build-controller above -- see that target's comment.
# build-agent has both of these same requirements, but today only the
# top-level `build` target sequences build-zig and generate before it (see
# CLAUDE.md, "After modifying Zig source ... run `make build-zig` before
# `make build-agent`"). package-build-agent is meant to be runnable
# standalone (e.g. straight after a fresh checkout or `make clean`, as
# `package-agent`'s prerequisite), so it declares both dependencies
# explicitly rather than relying on the caller to remember the ordering.
package-build-agent: build-zig generate
	@echo "==> Building agent for packaging (GOOS=linux GOARCH=$(NFPM_ARCH))..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=$(NFPM_ARCH) go build -o $(AGENT_BIN) ./cmd/agent/
	@echo "==> Agent built for packaging: $(AGENT_BIN)"

# Requires a Linux/CGO_ENABLED=1 build host with libibverbs-dev/librdmacm-dev
# whose GOARCH matches $(NFPM_ARCH) (same requirement as build-agent; see
# README.md "Building").
package-agent: package-build-agent check-nfpm
	@echo "==> Packaging rpingmesh-agent $(NFPM_VERSION) ($(NFPM_ARCH))..."
	@mkdir -p $(DIST_DIR)
	nfpm package --config packaging/nfpm/nfpm-agent.yaml --packager deb --target $(DIST_DIR)/
	nfpm package --config packaging/nfpm/nfpm-agent.yaml --packager rpm --target $(DIST_DIR)/
	@echo "==> Agent packages written to $(DIST_DIR)/"

package-controller: package-build-controller check-nfpm
	@echo "==> Packaging rpingmesh-controller $(NFPM_VERSION) ($(NFPM_ARCH))..."
	@mkdir -p $(DIST_DIR)
	nfpm package --config packaging/nfpm/nfpm-controller.yaml --packager deb --target $(DIST_DIR)/
	nfpm package --config packaging/nfpm/nfpm-controller.yaml --packager rpm --target $(DIST_DIR)/
	@echo "==> Controller packages written to $(DIST_DIR)/"

# Clean build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR) $(DIST_DIR)
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
	@echo "  test-go              Run Go tests (internal/probe only, pure Go)"
	@echo "  test-zig             Run Zig unit tests (zig build test)"
	@echo "  vet                  Run go vet ./..."
	@echo "  test-all             Run go test on all packages except ./e2e/..., plus test-zig (Linux, full build env)"
	@echo "  setup-colima         Install rdma_rxe kernel module on Colima VM (run once)"
	@echo "  test-e2e             Run RDMA e2e tests via Docker (requires Colima)"
	@echo "  test-e2e-controller  Run Agent-to-Controller E2E tests (Docker)"
	@echo "  clean-e2e-controller Clean up Agent-to-Controller E2E Docker resources"
	@echo "  package              Build .deb/.rpm packages for agent and controller (requires nfpm)"
	@echo "  package-agent        Build .deb/.rpm packages for the agent only"
	@echo "  package-controller   Build .deb/.rpm packages for the controller only"
	@echo "  clean                Remove all build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  Go 1.26+, Zig 0.15.2, protoc, libibverbs-dev, librdmacm-dev"
	@echo "  For test-e2e: colima running, run 'make setup-colima' first"
	@echo "  For package: nfpm (https://nfpm.goreleaser.com/install/)"
