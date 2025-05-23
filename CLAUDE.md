# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Building
- `make build-local` - Build binaries locally (requires Go 1.24.3+, clang, libbpf-dev)
- `make build-debug` - Build debug versions with debug symbols

### Testing
- `make test-local` - Run Go tests locally

### Development
- `go generate ./...` - Generate eBPF bindings and protobuf code

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
- `internal/ebpf/rdma_tracing.go` - eBPF ServiceTracer for RDMA event monitoring
- `internal/agent/serviceflowmonitor/` - Service flow monitoring with eBPF integration
- `internal/controller/registry/` - Agent and RNIC registry management
- `internal/probe/` - RDMA probing infrastructure
- `internal/rdma/` - RDMA device and queue management

## eBPF Development

Uses `github.com/cilium/ebpf` package for eBPF programs. eBPF C code in `internal/ebpf/bpf/rdma_tracing.c` traces RDMA verbs operations. Build process generates Go bindings via `bpf2go`.

## Configuration

All components use Viper for configuration with support for YAML files, environment variables, and command-line flags. Config structures in `internal/config/`.

## Dependencies

- Go 1.24.3+ with module support
- eBPF: clang, libbpf-dev, kernel headers
- RDMA: libibverbs-dev, librdmacm-dev
- Protocol Buffers: protoc, protoc-gen-go, protoc-gen-go-grpc
- Testing: testify framework

## Docker Requirements

For eBPF functionality, containers need `--privileged` mode with capabilities: `SYS_ADMIN`, `NET_ADMIN`, `IPC_LOCK`, `CAP_BPF`. Debugfs mount required at `/sys/kernel/debug`.
