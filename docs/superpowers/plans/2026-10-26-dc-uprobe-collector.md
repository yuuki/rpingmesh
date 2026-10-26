# Experimental DC Uprobe Collector Plan

**Goal:** Implement a runnable, opt-in libmlx5 DC submission collector whose privileged validation is performed by the user.

**Architecture:** Resolve private layout fields and function entry points from ELF/DWARF matching the selected library. Observe DCI creation, state changes, destruction and the extended WR completion boundary; copy bounded batches before submission and publish only after successful return. Keep this experimental collector separate from automatic probe generation until wire-port and ECMP behavior are validated.

**Constraints:**

- The agent does not run sudo. Provide explicit user-run commands for loading and attaching BPF.
- Never record deployment identifiers, binary fingerprints from an actual machine, or live address data in the repository or public reports.
- Require matching library/debug build IDs, supported ELF architecture, exact DWARF field sizes, and executable function addresses. Do not accept guessed offsets.
- Exclude stream-enabled DCIs and invalidate tracking on QP UDP-port override attempts, reset/error and destruction.
- Accept only complete, bounded batches after a successful completion-function return. Dropped events and lifetime reuse must not revive dead DCIs.
- This targets libmlx5 extended WR calls, not UCX direct WQE construction, pre-existing QPs or packet-level ECMP validation.

## Tasks

- [x] Add ELF/DWARF layout resolution and portable validation tests.
- [x] Add bounded BPF lifecycle/submission capture, generated objects and generation checks.
- [x] Add Linux loader, live-identity checks, collector CLI and non-privileged tests.
- [x] Add a user-run integration test using a synthetic provider ABI, covering success, failure, streams, overrides and teardown without RDMA hardware.
- [x] Document exact privileged test commands and limitations, run non-privileged checks, obtain adversarial review and fix findings.

The privileged integration test and actual application attachment must be reported as unexecuted until the user supplies their results.

## Development validation

- Portable service-tracing tests with the Go race detector: passed.
- Linux non-privileged synthetic ELF/DWARF, BPF object ABI and decoder tests: passed.
- Linux amd64 CLI build and vet; Linux arm64 test cross compilation: passed.
- BPF generation and binding checks for amd64 and arm64: passed.
- Adversarial review findings addressed: globally unique lifetime sequence,
  exec registry reclamation, all-candidate extended-QP base validation,
  PID reuse exclusion, and worker-exec invalidation.
- Worker threads use the same process filter; user-run integration coverage
  includes worker submission/destruction and full-registry exec reclamation.
- Privileged integration, verifier acceptance and actual attachment: unexecuted.

User-run commands and limitations are in
[`dc-uprobe-collector.md`](../../design/dc-uprobe-collector.md).
