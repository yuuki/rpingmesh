# R-Pingmesh - Build System
# Requires: Go 1.27.4+, Zig 0.17.0 (the version verified in e2e/CI), protoc,
# clang, libibverbs-dev, librdmacm-dev

.PHONY: all build build-zig build-go build-controller build-agent build-dc-trace \
        generate generate-proto generate-bpf check-bpf install-protoc-plugins \
        clean test test-go test-zig test-scripts test-all vet complexity \
        check lint fmt lint-actions lock-actions test-race test-fuzz test-integration bench vuln \
        test-e2e setup-colima test-e2e-controller clean-e2e-controller \
        check-nfpm package package-agent package-controller \
        package-build-agent package-build-agent-el9 package-build-controller \
        archive archive-agent archive-controller \
        obs-up obs-down obs-seed obs-verify obs-logs help

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

# VERSION is intentionally optional for local development. Release builds pass
# it explicitly so the binaries, packages, and GitHub Release share a version.
GO_LDFLAGS :=
ifdef VERSION
GO_LDFLAGS := -X github.com/yuuki/rpingmesh/internal/buildinfo.Version=$(VERSION)
endif

# How package-agent/archive-agent produce bin/rpingmesh-agent:
#   native - build on this host (package-build-agent); the binary inherits this
#            host's glibc floor.
#   el9    - build inside an Enterprise Linux 9 container
#            (package-build-agent-el9) so the binary runs on glibc >= 2.34.
#            Release builds use this.
AGENT_BUILDER ?= native
ifeq ($(AGENT_BUILDER),el9)
AGENT_PACKAGE_BUILD := package-build-agent-el9
else ifeq ($(AGENT_BUILDER),native)
AGENT_PACKAGE_BUILD := package-build-agent
else
$(error AGENT_BUILDER must be "native" or "el9", got "$(AGENT_BUILDER)")
endif

# Oldest glibc the released agent must run on (RHEL 9 family).
AGENT_GLIBC_FLOOR := 2.34

# Tool versions. CI pins the same versions (.github/workflows/test.yml and
# security.yml); bump them together.
GOLANGCI_LINT_VERSION      ?= v2.15.0
GOVULNCHECK_VERSION        ?= v1.9.0
ACTIONLINT_VERSION         ?= v1.7.12
ZIZMOR_VERSION             ?= 1.32.0
GH_ACTIONS_LOCK_VERSION    ?= v0.4.1
# protoc-gen-go follows google.golang.org/protobuf in go.mod; the gRPC plugin
# is a separate module and is pinned here.
PROTOC_GEN_GO_GRPC_VERSION ?= v1.6.2
FUZZTIME                   ?= 30s
# Extra flags for each fuzz run, e.g. FUZZFLAGS=-parallel=2 on a shared host.
FUZZFLAGS                  ?=
BENCH_COUNT                ?= 6

# `go run pkg@version` would otherwise build a tool with the Go version of the
# tool's own go.mod, and a golangci-lint built with an older Go refuses this
# module. Evaluated here, inside the module, `go env GOVERSION` is the
# toolchain go.mod selects (GOTOOLCHAIN=auto).
GO_TOOLCHAIN := $(shell go env GOVERSION 2>/dev/null)

# Each tool can be overridden with an installed binary, e.g.
# `make lint GOLANGCI_LINT=golangci-lint`.
GOLANGCI_LINT ?= GOTOOLCHAIN=$(GO_TOOLCHAIN) go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK   ?= GOTOOLCHAIN=$(GO_TOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
ACTIONLINT    ?= GOTOOLCHAIN=$(GO_TOOLCHAIN) go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
# uvx or pipx (preinstalled on GitHub-hosted runners) runs the pinned zizmor.
ZIZMOR        ?= $(if $(shell command -v uvx 2>/dev/null),uvx zizmor@$(ZIZMOR_VERSION),pipx run zizmor==$(ZIZMOR_VERSION))
# gh-actions-lock (the `gh actions-lock` extension) runs through `go run` too.
GH_ACTIONS_LOCK ?= GOTOOLCHAIN=$(GO_TOOLCHAIN) go run github.com/github/gh-actions-lock/cmd/gh-actions-lock@$(GH_ACTIONS_LOCK_VERSION)

# Default target
all: build

# Build everything
build: build-zig generate build-go

# Build Zig static library
build-zig:
	@echo "==> Building Zig RDMA bridge library..."
	cd $(ZIG_DIR) && zig build --release=safe
	@echo "==> Zig library built: $(ZIG_OUT)/lib/librdmabridge.a"

# Generate protobuf code
generate: generate-proto

generate-proto:
	@echo "==> Generating protobuf code..."
	cd $(PROTO_DIR) && go generate
	@echo "==> Proto generation complete"

# Install the protoc plugins generate-proto needs into $(go env GOPATH)/bin:
# protoc-gen-go at the google.golang.org/protobuf version in go.mod and
# protoc-gen-go-grpc at PROTOC_GEN_GO_GRPC_VERSION. protoc itself comes from
# the system (e.g. `apt-get install protobuf-compiler`).
install-protoc-plugins:
	go install google.golang.org/protobuf/cmd/protoc-gen-go
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

# Compile the service-tracing eBPF program with bpf2go (go.mod tool). The
# generated objects under internal/agent/servicetrace/ are committed, so
# build-agent never needs clang; run this after editing anything under
# internal/agent/servicetrace/bpf/. Needs a clang with the BPF backend
# (clang >= 14); point BPF2GO_CC/BPF2GO_STRIP at it when it is not the
# default clang (e.g. Homebrew LLVM on macOS, since Apple clang lacks the
# BPF target).
BPF_DIR := internal/agent/servicetrace
generate-bpf:
	@echo "==> Generating eBPF objects (bpf2go)..."
	go generate ./$(BPF_DIR)/
	@echo "==> eBPF generation complete"

# Verify the eBPF program still compiles and that the committed Go bindings
# are up to date, without touching the committed objects (the .o files differ
# between clang versions, so only the .go files are compared). The bpf2go
# command line mirrors the go:generate directive in
# internal/agent/servicetrace/generate.go; keep the two in sync.
check-bpf:
	@echo "==> Checking eBPF program and bindings..."
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
		cd $(BPF_DIR) && GOPACKAGE=servicetrace go tool bpf2go -output-dir "$$tmp" \
			-tags linux -target amd64,arm64 -type qp_event -no-global-types \
			uverbs bpf/uverbs_trace.bpf.c -- -I bpf -I bpf/include -O2 -g -Wall -Werror && \
		for f in uverbs_x86_bpfel.go uverbs_arm64_bpfel.go; do \
			diff -u "$$f" "$$tmp/$$f" || { echo "ERROR: $$f is stale; run 'make generate-bpf'"; exit 1; }; \
		done
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
		cd $(BPF_DIR) && GOPACKAGE=servicetrace go tool bpf2go -output-dir "$$tmp" \
			-tags linux -target amd64,arm64 -type kernel_event -no-global-types \
			kernel bpf/kernel_trace.bpf.c -- -I bpf -I bpf/include -O2 -g -Wall -Werror && \
		for f in kernel_x86_bpfel.go kernel_arm64_bpfel.go; do \
			diff -u "$$f" "$$tmp/$$f" || { echo "ERROR: $$f is stale; run 'make generate-bpf'"; exit 1; }; \
		done
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
		cd $(BPF_DIR) && GOPACKAGE=servicetrace go tool bpf2go -output-dir "$$tmp" \
			-tags linux -target amd64,arm64 -type dc_batch -type dc_devx_queue -type dc_identity -type dc_config -no-global-types \
			dc bpf/dc_trace.bpf.c -- -mcpu=v3 -I bpf -I bpf/include -O2 -g -Wall -Werror && \
		for f in dc_x86_bpfel.go dc_arm64_bpfel.go; do \
			diff -u "$$f" "$$tmp/$$f" || { echo "ERROR: $$f is stale; run 'make generate-bpf'"; exit 1; }; \
		done
	@echo "==> eBPF check complete"

# Build Go binaries
build-go: build-controller build-agent

build-controller:
	@echo "==> Building controller..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags "$(GO_LDFLAGS)" -o $(CONTROLLER_BIN) ./cmd/controller/
	@echo "==> Controller built: $(CONTROLLER_BIN)"

build-agent:
	@echo "==> Building agent..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -ldflags "$(GO_LDFLAGS)" -o $(AGENT_BIN) ./cmd/agent/
	@echo "==> Agent built: $(AGENT_BIN)"

# Experimental Linux-only, pure-Go diagnostic collector; not packaged/enabled
# as part of the agent until privileged and wire-path validation is complete.
build-dc-trace:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -o $(BIN_DIR)/rpingmesh-dc-trace ./cmd/dc-trace/

# Pure-Go packages: no Cgo, no RDMA hardware, runnable on any OS. The
# controller packages need the generated protobuf bindings (`make
# generate-proto` on a fresh checkout). internal/agent, internal/rdmabridge and
# cmd/agent need the Cgo/RDMA build environment: use `make test-all` (Linux)
# or `make test-e2e` / `make test-e2e-controller` for the Docker-based suites.
PURE_GO_TEST_PKGS := ./internal/probe/... ./internal/config/... ./internal/telemetry/... \
	./internal/lldp/... ./internal/logging/... ./internal/buildinfo/... \
	./internal/controller/... ./internal/agent/controller_client/... \
	./internal/agent/servicetrace/... ./cmd/controller/...

test: test-go

test-go:
	@echo "==> Running Go tests (pure-Go packages)..."
	go test $(PURE_GO_TEST_PKGS)
	@echo "==> Tests complete"

# Run the Python tests of the scripts/topology tooling (stdlib only).
test-scripts:
	@echo "==> Running scripts/topology tests..."
	python3 -m unittest discover -s scripts/topology -p 'test_*.py'
	@echo "==> Script tests complete"

# Run Zig unit tests (types.zig, ring.zig, cq.zig, etc.). Pure Zig, no Go/CGO
# involved, but still needs libibverbs/librdmacm headers on the build host
# (the `c` module is translated from them), so like build-zig this is
# Linux-only in practice (see Dockerfile.e2e).
test-zig:
	@echo "==> Running Zig unit tests..."
	cd $(ZIG_DIR) && zig build test
	@echo "==> Zig tests complete"

# Run `go vet` across the whole module.
vet:
	@echo "==> Running go vet..."
	go vet ./...
	@echo "==> Vet complete"

# Rank the most complex functions with cccc (https://github.com/moznion/cccc);
# what is analyzed is configured in cccc.toml.
complexity:
	cccc --table --top-cognitive 20 .

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

# ---------------------------------------------------------------------------
# Quality gates. `make check` is the local pre-PR gate: what the required PR
# CI jobs check that needs neither root, RDMA hardware nor network services.
# It needs protoc (for generate-proto), Zig, libibverbs-dev and librdmacm-dev
# on Linux; see AGENTS.md for the conditional extras (check-bpf, e2e).
# ---------------------------------------------------------------------------

check: lint lint-actions test-race test-zig test-scripts

# golangci-lint (linters and gofmt, configured in .golangci.yml) and go.mod
# tidiness. The controller packages import the generated protobuf code, so it
# is generated first.
lint: generate
	$(GOLANGCI_LINT) run ./...
	go mod tidy -diff

# Apply the formatters configured in .golangci.yml.
fmt:
	$(GOLANGCI_LINT) fmt ./...

# Lint (actionlint) and audit (zizmor) the GitHub Actions workflows. zizmor's
# online audits need a GitHub token (GH_TOKEN); without one it runs offline.
# gh-actions-lock checks that .github/workflows/actions.lock pins every
# action the workflows use; with GH_TOKEN it also verifies each pin upstream.
lint-actions:
	$(ACTIONLINT)
	$(ZIZMOR) $(if $(GH_TOKEN),,--offline) .
	$(GH_ACTIONS_LOCK) $(if $(GH_TOKEN),--verify,--verify-local)

# Pin the actions in .github/workflows/actions.lock after a `uses:` changed,
# then review the diff. Needs a GitHub token (GH_TOKEN or `gh auth login`).
lock-actions:
	$(GH_ACTIONS_LOCK)

# Unit tests with the race detector. On Linux this is every package except
# ./e2e/... (the same set as test-all), after building librdmabridge.a and the
# protobuf code. Elsewhere the Cgo packages cannot build, so only the pure-Go
# packages run. Tests that need root (the eBPF tracer load/attach tests) skip
# when run unprivileged.
ifeq ($(shell uname -s),Linux)
test-race: build-zig generate
	go test -race $$(go list ./... | grep -v '/e2e')
else
test-race: generate
	go test -race $(PURE_GO_TEST_PKGS)
endif

# Directories that define Go fuzz targets; only their test binaries are built.
FUZZ_DIRS = $(sort $(dir $(shell grep -rl --include='*_test.go' '^func Fuzz' internal cmd)))

# Run every Go fuzz target for FUZZTIME (Linux: internal/rdmabridge needs
# librdmabridge.a). New crashers are written to the package's
# testdata/fuzz/<FuzzName>/; commit them as regression seeds with the fix.
test-fuzz: build-zig generate
	@set -e; for dir in $(FUZZ_DIRS); do \
		pkg=./$${dir%/}; \
		targets=$$(go test -list '^Fuzz' $$pkg); \
		for f in $$(printf '%s\n' "$$targets" | grep '^Fuzz'); do \
			echo "==> $$pkg $$f ($(FUZZTIME))"; \
			go test -run='^$$' -fuzz="^$$f\$$" -fuzztime=$(FUZZTIME) $(FUZZFLAGS) $$pkg; \
		done; \
	done

# Tests that need network services in containers (Docker): the
# agent-to-controller suite against rqlite and against PostgreSQL. The
# registry's own PostgreSQL tests run in test-race when
# RPINGMESH_TEST_POSTGRES_URI names a database they may create schemas in.
# The soft-RoCE suite (test-e2e) additionally needs a privileged container
# and the rdma_rxe module.
test-integration: test-e2e-controller

# Benchmarks of every non-e2e package, written to bench.txt (gitignored);
# compare two runs with benchstat. Linux only, like test-race.
bench: build-zig generate
	@go test -run='^$$' -bench=. -benchmem -count=$(BENCH_COUNT) $$(go list ./... | grep -v '/e2e') > bench.txt 2>&1; \
		rc=$$?; cat bench.txt; exit $$rc

# Known vulnerabilities reachable from the code.
vuln: generate
	$(GOVULNCHECK) ./...

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
# packaging/nfpm/*.yaml and packaging/systemd/*.service, and the "Deployment"
# section of README.md for the full install/enable workflow.
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
# README.md "Deployment"); on any other host this step fails, same as
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
	CGO_ENABLED=0 GOOS=linux GOARCH=$(NFPM_ARCH) go build -ldflags "$(GO_LDFLAGS)" -o $(CONTROLLER_BIN) ./cmd/controller/
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
	CGO_ENABLED=1 GOOS=linux GOARCH=$(NFPM_ARCH) go build -ldflags "$(GO_LDFLAGS)" -o $(AGENT_BIN) ./cmd/agent/
	@echo "==> Agent built for packaging: $(AGENT_BIN)"

# Portable agent build: runs package-build-agent inside an Enterprise Linux 9
# container (Dockerfile.agent-el9) so the binary only depends on glibc
# <= $(AGENT_GLIBC_FLOOR) and EL9's libibverbs symbol versions, then re-checks
# the glibc floor on the extracted binary. Needs Docker with buildx; for a
# foreign NFPM_ARCH the Docker host must be able to emulate that platform.
package-build-agent-el9:
	@echo "==> Building agent in an EL9 container (linux/$(NFPM_ARCH), glibc floor $(AGENT_GLIBC_FLOOR))..."
	@mkdir -p $(BIN_DIR)
	docker buildx build --platform linux/$(NFPM_ARCH) -f Dockerfile.agent-el9 \
		--build-arg VERSION=$(VERSION) \
		--output type=local,dest=$(BIN_DIR) .
	./scripts/check-glibc-compat.sh $(AGENT_BIN) $(AGENT_GLIBC_FLOOR)
	@echo "==> Agent built for packaging: $(AGENT_BIN)"

# With the default AGENT_BUILDER=native this requires a Linux/CGO_ENABLED=1
# build host with libibverbs-dev/librdmacm-dev whose GOARCH matches
# $(NFPM_ARCH) (same requirement as build-agent; see README.md "Deployment").
# AGENT_BUILDER=el9 builds in a container instead (see above).
package-agent: $(AGENT_PACKAGE_BUILD) check-nfpm
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

# Build compressed binary archives (with LICENSE and NOTICE) for GitHub
# Releases. Each archive has one top-level directory so extraction never writes
# the binary directly into the caller's current directory. The agent archive
# has the same Linux/Cgo build-host requirement as package-agent.
archive: archive-agent archive-controller

archive-agent: $(AGENT_PACKAGE_BUILD)
	@echo "==> Archiving rpingmesh-agent $(NFPM_VERSION) ($(NFPM_ARCH))..."
	@mkdir -p $(DIST_DIR)
	@stage=$$(mktemp -d); trap 'rm -rf "$$stage"' EXIT; \
		archive=rpingmesh-agent_$(NFPM_VERSION)_linux_$(NFPM_ARCH); \
		mkdir -p "$$stage/$$archive"; \
		cp $(AGENT_BIN) "$$stage/$$archive/rpingmesh-agent"; \
		cp LICENSE NOTICE "$$stage/$$archive/"; \
		tar -C "$$stage" -czf "$(DIST_DIR)/$$archive.tar.gz" "$$archive"
	@echo "==> Agent archive written to $(DIST_DIR)/"

archive-controller: package-build-controller
	@echo "==> Archiving rpingmesh-controller $(NFPM_VERSION) ($(NFPM_ARCH))..."
	@mkdir -p $(DIST_DIR)
	@stage=$$(mktemp -d); trap 'rm -rf "$$stage"' EXIT; \
		archive=rpingmesh-controller_$(NFPM_VERSION)_linux_$(NFPM_ARCH); \
		mkdir -p "$$stage/$$archive"; \
		cp $(CONTROLLER_BIN) "$$stage/$$archive/rpingmesh-controller"; \
		cp LICENSE NOTICE "$$stage/$$archive/"; \
		tar -C "$$stage" -czf "$(DIST_DIR)/$$archive.tar.gz" "$$archive"
	@echo "==> Controller archive written to $(DIST_DIR)/"

# Clean build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR) $(DIST_DIR)
	cd $(ZIG_DIR) && rm -rf zig-out .zig-cache
	@echo "==> Clean complete"

# Observability stack (Grafana dashboards demo; see docs/design/grafana-dashboards.md)
OBS_DIR := deploy/observability
OBS_COMPOSE := $(OBS_DIR)/docker-compose.observability.yml

obs-up: ## Start the observability stack (VictoriaMetrics + otel-collector + Grafana)
	cd $(OBS_DIR) && { [ -f .env ] || cp .env.example .env; }
	docker compose -f $(OBS_COMPOSE) --env-file $(OBS_DIR)/.env up -d

obs-down: ## Stop the observability stack and remove volumes
	docker compose -f $(OBS_COMPOSE) down -v

obs-seed: ## Seed synthetic mesh metrics into VictoriaMetrics
	VM_URL=http://localhost:8428 ./scripts/seed-demo-metrics.sh

obs-logs: ## Tail observability stack logs
	docker compose -f $(OBS_COMPOSE) logs -f

obs-verify: ## Verify Grafana health, provisioning, and every panel query
	./scripts/verify-observability.sh

# Help
help:
	@echo "R-Pingmesh Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all                  Build everything (default)"
	@echo "  build                Build Zig library, generate proto, build Go"
	@echo "  build-zig            Build Zig RDMA bridge static library"
	@echo "  build-go             Build Go controller and agent binaries"
	@echo "  build-controller     Build controller binary only"
	@echo "  build-agent          Build agent binary only"
	@echo "  build-dc-trace       Build experimental DC collector (Linux only)"
	@echo "  generate             Generate all code (proto)"
	@echo "  generate-proto       Generate protobuf Go code"
	@echo "  generate-bpf         Compile the service-tracing eBPF program (needs clang with the BPF backend)"
	@echo "  check-bpf            Verify the eBPF program compiles and its committed Go bindings are current"
	@echo "  install-protoc-plugins  Install the pinned protoc-gen-go and protoc-gen-go-grpc"
	@echo "  check                Local pre-PR gate: lint, lint-actions, test-race, test-zig, test-scripts"
	@echo "  lint                 golangci-lint (.golangci.yml) and go mod tidy -diff"
	@echo "  fmt                  Apply the formatters of .golangci.yml"
	@echo "  lint-actions         actionlint and zizmor on .github/, and check .github/workflows/actions.lock"
	@echo "  lock-actions         Update .github/workflows/actions.lock after changing a uses: line"
	@echo "  test                 Run tests (alias of test-go)"
	@echo "  test-go              Run Go tests of every pure-Go package (no Cgo, no RDMA hardware)"
	@echo "  test-race            Go unit tests with -race (Linux: all non-e2e packages)"
	@echo "  test-fuzz            Run every Go fuzz target for FUZZTIME (default 30s)"
	@echo "  test-integration     Container-based integration tests (alias of test-e2e-controller)"
	@echo "  bench                Run Go benchmarks into bench.txt (compare with benchstat)"
	@echo "  vuln                 govulncheck ./..."
	@echo "  test-zig             Run Zig unit tests (zig build test)"
	@echo "  test-scripts         Run the Python tests of scripts/topology/"
	@echo "  vet                  Run go vet ./..."
	@echo "  complexity           Rank the most complex functions with cccc (settings in cccc.toml)"
	@echo "  test-all             Run go test on all packages except ./e2e/..., plus test-zig (Linux, full build env)"
	@echo "  setup-colima         Install rdma_rxe kernel module on Colima VM (run once)"
	@echo "  test-e2e             Run RDMA e2e tests via Docker (requires Colima)"
	@echo "  test-e2e-controller  Run Agent-to-Controller E2E tests (Docker)"
	@echo "  clean-e2e-controller Clean up Agent-to-Controller E2E Docker resources"
	@echo "  package              Build .deb/.rpm packages for agent and controller (requires nfpm)"
	@echo "  package-agent        Build .deb/.rpm packages for the agent only"
	@echo "  package-controller   Build .deb/.rpm packages for the controller only"
	@echo "  archive              Build .tar.gz binary archives for GitHub Releases"
	@echo "  package-build-agent-el9  Build a portable agent (glibc >= $(AGENT_GLIBC_FLOOR)) in an EL9 container"
	@echo "                       (use AGENT_BUILDER=el9 with package/archive to package it)"
	@echo "  clean                Remove all build artifacts"
	@echo "  obs-up               Start the observability stack (VictoriaMetrics + otel-collector + Grafana)"
	@echo "  obs-down             Stop the observability stack and remove volumes"
	@echo "  obs-seed             Seed synthetic mesh metrics into VictoriaMetrics"
	@echo "  obs-verify           Verify Grafana health, provisioning, and every panel query"
	@echo "  obs-logs             Tail observability stack logs"
	@echo ""
	@echo "Requirements:"
	@echo "  Go 1.27.4+, Zig 0.17.0, protoc, libibverbs-dev, librdmacm-dev"
	@echo "  For generate-bpf/check-bpf: clang >= 14 with the BPF backend"
	@echo "  For test-e2e: colima running, run 'make setup-colima' first"
	@echo "  For package: nfpm (https://nfpm.goreleaser.com/install/)"
