# DC Send Tracking Core Implementation Plan

**Goal:** Start #111's DC work with a testable mlx5 WQE decoder and bounded, expiring per-send flow tracking.

**Architecture:** Keep the core separate from connected-QP tracing. A future, build-validated adapter supplies committed WQE prefixes and unique DCI lifetime identities; neither an AH setter nor a QP snapshot can publish a DC flow. Do not expose a runtime switch until submission hooks and hardware behavior have been verified.

**Tech Stack:** Go 1.27.3; mlx5 control/address-vector layout; existing portable service tracing tests.

**Spec:** `docs/design/ebpf-service-tracing.md`, DC transport investigation (#111).

## Constraints

- Use authorized, allocated mlx5 hardware for validation.
- Verify allocation ownership and installed UCX/libmlx5 builds before running workloads.
- Decode only verified RoCEv2, non-stream DCI sends without QP UDP-port overrides. The WQE alone cannot prove these preconditions.
- Preserve the AV's UDP-port candidate separately from its flow label; never use connected-QP QPN arithmetic for DC.
- Store multiple remotes and address variants per DCI with a total flow limit and inactivity expiry. Do not retain access keys or payloads.
- Keep the existing runtime unchanged until a provider-specific adapter is validated.

## Tasks

- [x] Add `mlx5_dc.go` and `mlx5_dc_test.go`: decode a 64-byte control/extended-AV prefix, validate QPN, opcode, segment count, reserved/stream fields, DCT and RoCE port, and reject truncated/unsupported inputs.
- [x] Add `dc_flows.go` and `dc_flows_test.go`: accept only adapter-confirmed submissions, require unique DCI lifetime tokens, retain distinct AVs, expire inactive entries, cap total entries, and clear one destroyed DCI or all entries after capture loss.
- [x] Test endian offsets, malformed prefixes, zero application flow labels, multiple remotes, repeated sends, timestamp ordering, capacity, expiry, and lifetime teardown. Run race tests and vet.
- [x] Document the implemented core and unimplemented attachment/ECMP validation. Obtain an independent adversarial review and address findings.
- [ ] Inspect the target allocation and binaries, implement an adapter for that exact build, and compare observed fields with actual packets on mlx5 hardware. This step depends on SSH access and must not be replaced with guessed ABI offsets.

## Validation

```sh
GOCACHE=/tmp/rpingmesh-go-cache go test -race ./internal/agent/servicetrace ./internal/config
GOCACHE=/tmp/rpingmesh-go-cache go vet ./internal/agent/servicetrace ./internal/config
git diff --check
```

Portable fixtures verify parsing and lifetime logic, not hardware packet equivalence. The runtime adapter and enabling option remain absent until hardware validation.

## Results

- Portable package/config race tests and vet passed.
- DC decoder/flow tests passed in the existing Linux arm64 RDMA image as an unprivileged user.
- Decoder fuzzing passed for 10 seconds (4,193,240 executions).
- The control/AV definitions match the pinned upstream header. The fixtures are synthetic, not packet captures.
- Independent adversarial review reported no actionable P1–P3 findings in this increment.
- Target access is still required for the final adapter task; no supported UCX/libmlx5 build is claimed.
