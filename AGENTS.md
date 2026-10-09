# Repository Guidelines

## Project Structure

- `cmd/agent` and `cmd/controller` contain the active binary entry points.
- `internal/` contains the active Go implementation:
  - `agent/` runs probing, responding, controller synchronization, and analysis reporting.
  - `config/` loads YAML, environment, and CLI configuration.
  - `controller/` implements the gRPC service, registry, pinglist generation, and Phase 1 analyzer.
  - `probe/` defines probe results and timing calculations.
  - `rdmabridge/` is the Go/Cgo boundary to the Zig RDMA library.
  - `telemetry/` exports OpenTelemetry metrics.
  - `testutil/` contains shared test helpers.
- `zig/` contains the RDMA data-path library and its public C ABI in
  `zig/include/rdma_bridge.h`.
- `proto/` contains gRPC sources; generated `*.pb.go` files live beside them.
- `configs/` contains example agent and controller configuration.
- `e2e/` contains controller and RDMA end-to-end tests.
- `packaging/` contains nfpm definitions and systemd units.
- `dashboards/` and `deploy/` contain the observability assets and local stack.
- `docs/design/` contains design documentation.
- `legacy/` archives the previous implementation as a separate Go module.

## Build, Test, and Development Commands

Run active-development commands from the repository root.

- `make build`: Build the Zig library, generate protobuf bindings, and build both binaries.
- `make build-zig`: Build `zig/zig-out/lib/librdmabridge.a`.
- `make generate-proto`: Regenerate Go protobuf and gRPC bindings.
- `make build-controller`: Build the pure-Go controller.
- `make build-agent`: Build the Linux/Cgo agent linked to the Zig RDMA library.
- `make test`: Run the portable Go probe tests.
- `make vet`: Run `go vet` for all Go packages.
- `make test-all`: Run Zig tests and all non-e2e Go tests in a Linux RDMA build environment.
- `make test-e2e-controller`: Run the controller integration path in Docker.
- `make test-e2e`: Run the privileged soft-RoCE/RDMA end-to-end suite.
- `make package`: Build agent and controller `.deb` and `.rpm` packages.
- `make obs-up`, `make obs-down`, `make obs-seed`, `make obs-logs`, and
  `make obs-verify`: Operate and verify the local observability stack.

## Toolchain and Platform Constraints

- Use Go 1.27.2 or newer, Zig 0.17.0, protoc, protoc-gen-go, and
  protoc-gen-go-grpc.
- Agent builds require Linux, Cgo, libibverbs, and librdmacm. Agent runtime and
  RDMA e2e tests additionally require RDMA hardware or privileged soft-RoCE.
- The controller is pure Go (`CGO_ENABLED=0`) and has no RDMA dependency.

## Coding and Documentation

- Follow standard Go conventions and run `gofmt` on edited Go files.
- Keep code comments and repository documentation in English.
- Do not edit generated `proto/controller_agent/*.pb.go` files by hand.
- After changing a `.proto` file, run `make generate-proto`.
- Keep the Zig C ABI, `zig/include/rdma_bridge.h`, and
  `internal/rdmabridge/bridge.go` synchronized.
- Prefer simple, systematic solutions and update documentation with behavior or
  workflow changes.

## Testing and Change Management

- Keep Go tests in `*_test.go` files with `TestXxx` names.
- Use Conventional Commits (for example, `feat:`, `fix(agent):`, `docs:`, or
  `ci:`).
- PRs must state their purpose, impact, and commands run.
- Explicitly document breaking changes, required privileges, kernel
  constraints, and RDMA dependencies in PRs.
- Do not modify `legacy/` unless the task explicitly requests legacy maintenance.
