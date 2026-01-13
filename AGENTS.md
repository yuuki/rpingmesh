# Repository Guidelines

## Project Structure
- `cmd/` contains entry points (`cmd/agent`, `cmd/controller`).
- `internal/` holds core implementations (agent/controller/analyzer/probe/rdma/ebpf/config/monitor).
- `proto/` contains gRPC `.proto` files; generated code lives alongside as `*.pb.go`.
- eBPF C sources are in `internal/ebpf/bpf/`; generated Go bindings are in `internal/ebpf/`.
- `docs/` holds design docs, `scripts/` helper scripts, and `bin/` build outputs.

## Build, Test, and Development Commands
- `make build-local`: Build locally with Go (outputs to `./bin/`).
- `make build` / `make build-controller` / `make build-agent`: Build with Docker Compose.
- `make build-debug`: Build debug binaries (`-N -l`).
- `make generate`: Generate protobuf + eBPF code.
- `make test`: Run all tests in Docker; `make test-controller` / `make test-agent` for subsets.
- `make test-local`: Run `go test ./...` (sets `RQLITE_LOCAL_TEST_URI`).

## Coding Style & Naming Conventions
- Follow Go standards; `gofmt` is required (`gofmt -w`).
- Package names are lowercase; exported identifiers use CamelCase; acronyms follow Go conventions.
- Do not edit generated code (`proto/`, `internal/ebpf/`) by hand.

## Testing Guidelines
- Tests live in `*_test.go` and use `TestXxx` naming.
- Primary frameworks are Go `testing` plus `testify`.
- Run `make generate` before tests if eBPF/Proto changes are involved.

## Commit & Pull Request Guidelines
- Use Conventional Commits (e.g., `feat: ...`, `fix(agent): ...`, `docs: ...`, `ci: ...`).
- PRs should include purpose/summary, impact scope, and tests run (with commands).
- Call out breaking changes or requirements (privileges, kernel constraints, RDMA dependencies).

## Environment & Configuration Notes
- eBPF/RDMA requires privileges and kernel dependencies; Docker runs need debugfs and elevated caps (`make debugfs-volume`).
- Configuration uses YAML + environment variables (e.g., `RQLITE_DB_URI`, `RQLITE_LOCAL_TEST_URI`).
