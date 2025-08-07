# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Building
- `make build-local` - Build binaries locally (requires Go 1.24.3+, clang, libbpf-dev)
- `make build-debug` - Build debug versions with debug symbols
- `make build-controller` - Build controller with Docker
- `make build-agent` - Build agent with Docker

### Testing
- `make test-local` - Run Go tests locally (sets RQLITE_LOCAL_TEST_URI)
- `make test` - Run all tests in Docker containers
- `make test-controller` - Run controller tests only
- `make test-agent` - Run agent tests only
- `go test ./...` - Run tests directly with Go
- `go test -v ./internal/rdma -run TestDeviceInit` - Run specific test

### Code Generation
- `make generate` - Generate all code (protobuf + eBPF)
- `make generate-proto` - Generate protobuf bindings only
- `make generate-bpf` - Generate eBPF bindings only
- `go generate ./...` - Alternative generation command

### Docker Development
- `make agent-up` - Start agent container
- `make debugfs-volume` - Create debugfs volume for Docker Desktop
- `make generate-config` - Generate default configuration files
- `make clean-compose` - Clean Docker Compose resources

## Architecture

R-Pingmesh is a service-aware RoCE network monitoring and diagnostic system based on end-to-end probing with three core components:

**Agent**: Deployed on RDMA hosts, performs probing and eBPF tracing. Manages RDMA devices, executes network probes, and monitors kernel RDMA events via eBPF ServiceTracer.

**Controller**: Central coordination service that manages agent registry and distributes pinglists (target assignments). Stores agent/RNIC information in rqlite.

**Analyzer**: Data aggregation service that receives probe results and path information from agents for network performance analysis.

### Communication Flow
- Controller ↔ Agent: gRPC for registration, pinglist distribution (`controller_agent.proto`)
- Agent → Analyzer: gRPC for probe data upload (`agent_analyzer.proto`)
- eBPF programs trace RDMA QP lifecycle events in kernel space

### Key Packages
- `internal/ebpf/` - eBPF ServiceTracer for RDMA event monitoring
  - `rdma_tracing.go` - Main eBPF tracer implementation
  - `bpf/rdma_tracing.c` - eBPF C code for kernel tracing
- `internal/agent/` - Agent implementation
  - `serviceflowmonitor/` - Service flow monitoring with eBPF integration
  - `controller_client/` - gRPC client for controller communication
  - `telemetry/` - OpenTelemetry metrics collection
- `internal/controller/` - Controller service
  - `registry/` - Agent and RNIC registry management with rqlite
  - `pinglist/` - Target assignment and distribution
- `internal/analyzer/` - Analyzer service
  - `analysis/` - Network performance analysis engine
  - `storage/` - Data persistence layer
- `internal/probe/` - RDMA probing infrastructure
- `internal/rdma/` - RDMA device and queue management
  - `device.go` - RNIC device discovery and management
  - `queue.go` - UD Queue Pair operations
  - `cq.go` - Completion Queue polling
  - `packet.go` - Packet send/receive operations
- `internal/config/` - Configuration structures for all components
- `internal/monitor/` - Cluster monitoring implementation

## eBPF Development

Uses `github.com/cilium/ebpf` package for eBPF programs. eBPF C code in `internal/ebpf/bpf/rdma_tracing.c` traces RDMA verbs operations. Build process generates Go bindings via `bpf2go`.

Key requirements:
- Linux kernel 5.4+ with eBPF support
- CAP_BPF capability or root privileges
- Kernel headers installed for compilation

## Configuration

All components use Viper for configuration with support for YAML files, environment variables, and command-line flags. Config structures in `internal/config/`.

Environment variables:
- `RQLITE_DB_URI` - rqlite database connection for controller
- `RQLITE_LOCAL_TEST_URI` - rqlite connection for local testing (default: http://localhost:4001)

## Development Environment

### DevContainer Support
Project includes `.devcontainer/devcontainer.json` with pre-configured environment including Go, eBPF tools, RDMA libraries, and required extensions. Use with VS Code or GitHub Codespaces.

### Local Development Requirements
- Go 1.24.3+ with module support
- eBPF: clang, libbpf-dev, kernel headers
- RDMA: libibverbs-dev, librdmacm-dev
- Protocol Buffers: protoc, protoc-gen-go, protoc-gen-go-grpc
- Testing: testify framework
- Rate limiting: uber-go/ratelimit

## Docker Requirements

For eBPF functionality, containers need `--privileged` mode with capabilities: `SYS_ADMIN`, `NET_ADMIN`, `IPC_LOCK`, `CAP_BPF`. Debugfs mount required at `/sys/kernel/debug`.

## Binary Locations

Built binaries are placed in `./bin/`:
- `rpingmesh-controller` - Controller service binary
- `rpingmesh-agent` - Agent service binary
- `rpingmesh-analyzer` - Analyzer service binary (when built)
