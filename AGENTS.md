# AGENTS.md

This file holds only what the code does not show: rules, contracts and
conventions. Design decisions are recorded in [docs/design/](docs/design/).

## Rules the code does not show

- English only: code comments, documentation, commit messages, PR descriptions.
- No real environment identifiers (host names, IPs, cluster or partition names,
  user names, local paths, allocation IDs, access routes) in code, docs, issues
  or PRs; use synthetic examples.
- Zig hands completions to Go only through the SPSC event ring, polled by its
  single Go consumer; never through Cgo callbacks.
- Keep the CQ arm-then-drain order (`zig/src/cq.zig`) and the eventfd write in
  busy mode: a queue can fall back to busy while Go still waits on the fd.
- Never make the responder wait on a send completion (it would stall its event
  ring); async ACK completions never touch the probes' single-sender mailbox.
- Metric attributes stay at ToR level plus the local RNIC, never GIDs or IPs;
  destination-RNIC identity only on the opt-in `rpingmesh.target_rnic.*`
  instruments, service-tracing results only on `rpingmesh.service.*`.
- Per-probe path: no blocking calls, no logging above Debug, no unbounded maps;
  a full event ring drops events (size `event_ring_capacity`, never block).
- Kernel names (host, RDMA device, netdev) may be invalid UTF-8: apply
  `strings.ToValidUTF8` where they enter gRPC or OTLP; keep raw names for sysfs.
- Bound every new unauthenticated controller input in
  `internal/controller/validate.go`.
- Hardware and soft-RoCE tests skip without their hardware and tolerate failed
  probes; never make them required.
- User-visible changes get a `CHANGELOG.md` entry under `[Unreleased]`.

## Compatibility contracts

Never change these silently: they break deployed agents, controllers,
dashboards or the kernel interface.

- Probe wire format (40 bytes, BigEndian, version byte at offset 0):
  `zig/src/wire.zig` ↔ `SerializeProbePacket` (`internal/rdmabridge/bridge.go`);
  the golden bytes of both layout tests stay identical.
- C ABI, no `bool` (use `uint8_t`): `zig/include/rdma_bridge.h` ↔
  `zig/src/main.zig` ↔ `internal/rdmabridge/bridge.go`.
- eBPF events: `struct qp_event` (112 bytes, little-endian) ↔ `DecodeEvent`
  (`internal/agent/servicetrace/event.go`); `bpf/uverbs_uapi.h` ↔ kernel UAPI.
- gRPC API (`proto/controller_agent/controller_agent.proto`): add fields, never
  renumber; adjacent agent and controller versions interoperate.
- Metric names and attributes: `internal/telemetry/otel_metrics.go`,
  `internal/controller/analyzer/metrics.go`; `dashboards/` query them.
- Configuration keys and defaults: `internal/config/`, `configs/`.
- Registry schema (`internal/controller/registry/registry.go`): add columns by
  migration only; older controllers share the database.
- Packaging: binary names, `packaging/systemd/` units, drop-ins and their
  capabilities, the nfpm file layout.

## Before opening a pull request

Run `make check`. Also, when you touch:

- `internal/agent/servicetrace/bpf/`: `make generate-bpf check-bpf`; commit the
  regenerated `*_bpfel.{go,o}`.
- `zig/`: `make build-zig test-zig build-agent`.
- `.proto` files: `make generate-proto`, then `make check`.
- parsers or decoders: `make test-fuzz FUZZTIME=1m`; commit any crasher under
  `testdata/fuzz/` with the fix.
- the controller/agent gRPC path or the registry: `make test-integration`.
- the RDMA data path: `make test-e2e` where soft-RoCE is available.
- dependencies: `make vuln`.

## Git conventions

Branches: `<type>/<issue>-<summary>`, or `<type>/<summary>` without an issue
(`fix/166-connect-errors`, `feat/qp-counters`). `<type>` is a commit type
below; `<summary>` is 2–5 lowercase ASCII words joined by `-`. Branches named
by tools keep their names (`agent/*`, `claude/*`, `copilot/*`,
`dependabot/*`). Never push to the default branch.

Commits follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

    <type>(<scope>)!: <subject>

    <body>

    <footer>

- `type`: `feat` (new user-visible behaviour), `fix` (bug fix), `perf`,
  `refactor` (no behaviour change), `test`, `docs`, `build` (build system,
  dependencies, packaging), `ci` (workflows), `chore` (anything else, e.g.
  `chore(release): prepare v1.2.3`), `revert`.
- `scope`: optional; the package or area changed: `agent`, `controller`,
  `servicetrace`, `rdmabridge`, `zig`, `telemetry`, `lldp`, `packaging`.
- `!` and a `BREAKING CHANGE: <what changed and how to migrate>` footer for
  any change to a compatibility contract above.
- `subject`: imperative, lower case (except identifiers), no final period,
  at most 72 characters including the prefix.
- `body`: why the change is needed and what it affects, wrapped at 72
  columns; required unless the subject says everything.
- `footer`: `Fixes #N` / `Refs #N`, `BREAKING CHANGE:`, trailers such as
  `Co-Authored-By:`.
- One logical change per commit; regenerated files go in the commit that
  changes their source. Pull request titles use the same format (they become
  the squash commit).

## Forbidden

- Disabling, skipping, deleting or weakening tests, fuzz targets, lint rules or
  CI checks to get green (`|| true`, `continue-on-error`, blanket excludes,
  loosened assertions).
- Editing generated files by hand (`*.pb.go`, `*_bpfel.{go,o}`).
- Modifying `legacy/` (frozen) unless the task asks for legacy maintenance.
- Adding dependencies without a stated justification.
- Changing a compatibility contract without calling it out.
- Loosening workflow permissions, unpinning actions, or adding
  `pull_request_target`/`workflow_run` triggers.
- Committing secrets, real environment identifiers or machine-specific details.
- Rewriting published history, force-pushing, tagging or publishing releases.

## Needs human review

Even with green CI: `.github/`, permissions, secrets and systemd capabilities;
eBPF programs, kernel dump and netlink decoders, the controller's input
validation and TLS configuration; the compatibility contracts; dependency
additions or major upgrades; large refactors.

## Environment notes

- With `GH_TOKEN` set but the GitHub API unreachable:
  `env -u GH_TOKEN make check`.
- As root without tracefs mounted, `TestTracerOpenClose` fails instead of
  skipping: mount tracefs (e.g. in a private mount namespace) or run
  unprivileged.
