# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language Standards

**All code comments and documentation must be in English.**

- All code comments in `.go`, `.c`, and other source files must be written in English
- All documentation files (`.md`) must be written in English
- Commit messages must be in English
- PR descriptions and issue comments should be in English for accessibility to all contributors
- This ensures consistency across the project and improves collaboration with international developers

## Commands

### Building
- `make build-local` - Build binaries locally (requires Go 1.25+, clang, libbpf-dev)
- `make build` - Build both controller and agent with Docker
- `make build-controller` - Build controller with Docker
- `make build-agent` - Build agent with Docker
- `make build-debug` - Build debug versions locally with debug symbols (disables optimizations, preserves symbols)
- `make build-debug-controller` - Build controller debug version only
- `make build-debug-agent` - Build agent debug version only

**Note**: `build-local` runs `make generate` automatically. Always run code generation after modifying `.proto` or eBPF `.c` files.

### Testing
- `make test-local` - Run Go tests locally (requires rqlite running on localhost:4001)
- `make test` - Run all tests in Docker containers (controller + agent)
- `make test-controller` - Run controller tests only in Docker
- `make test-agent` - Run agent tests only in Docker
- `go test ./...` - Run tests directly with Go (respects RQLITE_LOCAL_TEST_URI env var)
- `go test -v ./internal/rdma -run TestDeviceInit` - Run specific test with verbose output
- `go test -race ./...` - Run tests with race detector

**Testing Tips**:
- Use `go test -v ./pkg/path -run TestName` pattern for focused testing
- eBPF tests require privileged mode and kernel headers
- RDMA tests require RDMA-capable hardware or soft-RoCE

### Code Generation
- `make generate` - Generate all code (protobuf + eBPF via bpf2go)
- `make generate-proto` - Generate protobuf bindings only
- `make generate-bpf` - Generate eBPF bindings only (requires clang, kernel headers)
- `go generate ./...` - Alternative generation command

**Code Generation Rules**:
- Always regenerate after modifying `.proto` files in `proto/`
- Always regenerate after modifying eBPF C code in `internal/ebpf/bpf/`
- Generated files: `*_grpc.pb.go`, `*.pb.go`, `rdmatracing_x86_bpfel.go`
- bpf2go generates architecture-specific Go bindings from C code

### Docker Development
- `make agent-up` - Start agent container with Docker Compose
- `make debugfs-volume` - Create debugfs volume for Docker Desktop (required for eBPF)
- `make generate-config` - Generate default agent.yaml configuration
- `make clean-compose` - Clean Docker Compose resources (volumes, containers)

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

### Key Concepts
- **Service Tracing**: eBPF programs hook `modify_qp` and `destroy_qp` syscalls to capture RDMA connection lifecycle
- **Ring Buffer**: Events are sent from kernel to userspace via eBPF ring buffer for minimal overhead
- **5-tuple Extraction**: Each connection event captures Src/Dst GID, Src/Dst QPN, PID, TID, and process name
- **struct alignment**: `RdmaConnTuple` in Go must exactly match C struct layout (80 bytes, verified at init)

### Requirements
- Linux kernel 5.4+ with eBPF support (5.8+ recommended for ring buffer)
- CAP_BPF capability or root privileges for loading eBPF programs
- Kernel headers installed for compilation (`linux-headers-$(uname -r)`)
- BTF (BPF Type Format) support for CO-RE (Compile Once - Run Everywhere)

### Development Workflow
1. Modify `internal/ebpf/bpf/rdma_tracing.c` (C code)
2. Run `make generate-bpf` to regenerate Go bindings
3. Update `internal/ebpf/rdma_tracing.go` if struct layout changes
4. Verify struct size compatibility at compile time
5. Test with `go test ./internal/ebpf/...` (requires privileged mode)

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
- `rpingmesh-controller.debug` - Controller debug binary (from `make build-debug-controller`)
- `rpingmesh-agent.debug` - Agent debug binary (from `make build-debug-agent`)

Configuration files are also copied to `./bin/` during Docker builds.

## RDMA Development

### Cgo Integration
RDMA operations use Cgo to call into `libibverbs` C library. Key files:
- `internal/rdma/device.go` - RDMA device discovery and context management
- `internal/rdma/queue.go` - Queue Pair (QP) creation and management for UD (Unreliable Datagram)
- `internal/rdma/cq.go` - Completion Queue (CQ) polling for send/receive completions
- `internal/rdma/packet.go` - Packet send/receive operations with hardware timestamps

### Development Notes
- Cgo requires `libibverbs-dev` and `librdmacm-dev` packages
- RDMA tests require actual RDMA hardware or soft-RoCE setup
- Use `rdma_cm` kernel module for connection management
- Hardware timestamp accuracy depends on NIC capabilities (typically sub-microsecond)

### Testing Without Hardware
If RDMA hardware is unavailable:
- Use soft-RoCE (`rdma link add rxe0 type rxe netdev eth0`)
- Run tests in Docker with privileged mode
- Mock RDMA device for unit tests (see `internal/agent/agent_mock_test.go`)

## Monitoring and Observability

### OpenTelemetry Integration
Agent exports OTLP metrics via `internal/agent/telemetry/otel_metrics.go`:
- RTT measurements (network_rtt, prober_delay, responder_delay)
- Probe success/failure rates
- RDMA device statistics
- eBPF event counts

### Metrics Configuration
Configure OTLP exporters via environment variables:
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OTLP collector endpoint
- `OTEL_EXPORTER_OTLP_PROTOCOL` - Protocol (grpc or http/protobuf)
- `OTEL_SERVICE_NAME` - Service name for metrics

## Debugging Tips

### eBPF Debugging
- Check eBPF program loading: `bpftool prog list`
- View eBPF maps: `bpftool map dump name <map_name>`
- Enable eBPF verifier logs: Set `EBPF_LOGGING=1` environment variable
- Check kernel ring buffer for eBPF errors: `dmesg | grep bpf`

### RDMA Debugging
- List RDMA devices: `rdma link show`
- Check device status: `ibstat` or `ibv_devinfo`
- Monitor RDMA traffic: `rdma stat show` or `perfquery`
- Check QP state: Use `rdma res show qp` to see active Queue Pairs

### gRPC Debugging
- Enable gRPC logging: `GRPC_GO_LOG_VERBOSITY_LEVEL=99 GRPC_GO_LOG_SEVERITY_LEVEL=info`
- Use grpcurl for testing: `grpcurl -plaintext localhost:8080 list`
- Check protobuf definitions in `proto/` directories

## Important Development Patterns

### Code Comments and Documentation
- Write all code comments in English for clarity and consistency
- Use clear, descriptive comments explaining the "why" rather than the "what"
- Documentation files (`.md`) must be in English
- All commit messages and PR descriptions should be in English
- This enables better collaboration and accessibility for all contributors

### Error Handling
- Use `github.com/rs/zerolog` for structured logging (not standard `log` package)
- Wrap errors with context: `fmt.Errorf("operation failed: %w", err)`
- Check error return values from Cgo functions explicitly

### Testing Patterns
- Use `github.com/stretchr/testify` for assertions
- Mock external dependencies (see `agent_mock_test.go` examples)
- Use table-driven tests for multiple test cases
- Tag integration tests: `// +build integration` for CI separation

### Concurrency
- Use `uber-go/ratelimit` for rate limiting probe operations
- Protect shared state with `sync.Mutex` or channels
- Context propagation for cancellation: Always accept `context.Context` in long-running operations

## Common Issues

### Build Failures
- **Missing headers**: Install `libibverbs-dev`, `librdmacm-dev`, `linux-headers-$(uname -r)`
- **Cgo errors**: Ensure `CGO_ENABLED=1` and proper include paths
- **eBPF generation fails**: Install `clang`, `llvm`, and kernel headers

### Test Failures
- **RDMA tests fail**: Requires RDMA hardware or soft-RoCE configuration
- **eBPF tests fail**: Requires privileged mode (`sudo`) and kernel ≥5.4
- **rqlite connection errors**: Start rqlite server on localhost:4001 for local tests

### Runtime Issues
- **eBPF program won't load**: Check `CAP_BPF` capability or run as root
- **RDMA device not found**: Verify RDMA drivers loaded (`lsmod | grep rdma`)
- **Permission denied errors**: Container needs `--privileged` or specific capabilities
