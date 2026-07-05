# RNIC Runtime Re-initialization

Status: Design only (P3-I). No implementation is proposed here. This document
specifies how the agent should detect an RDMA device/port fault at runtime and
recover the affected Prober/Responder/Queue without a process restart.

## Goals

- Subscribe to RDMA **asynchronous events** (`ibv_get_async_event`) so the agent
  learns about device-fatal and port up/down transitions instead of silently
  going deaf after a fault.
- **Recover per-RNIC**: on a fatal/removal event for device *i*, tear down and
  rebuild only that device's Prober, Responder, Queues, and event rings, then
  re-register with the controller so the new QPNs propagate. Other RNICs keep
  probing untouched.
- Respect the existing lifecycle contracts: the `destroyOnce`/`sync.Once`
  idempotent teardown in Prober/Responder, the SPSC event-ring ordering rule
  (ring created before queue), and the deterministic results fan-in shutdown in
  `agent.go`.
- Fail safe: bounded retries with backoff; if a device cannot be recovered,
  leave it down, surface it as a metric, and keep the rest of the agent healthy.

## Non-Goals

- No recovery from a **host-fatal** condition (RDMA subsystem gone entirely) —
  that remains a process-restart case handled by systemd `Restart=on-failure`.
- No attempt to preserve **in-flight probes** across a reinit. Probes pending on
  a destroyed queue are treated as lost (they already time out via
  `stalePendingTimeout`); correctness of the *measurement* is not compromised —
  those windows simply record loss, which is the truthful outcome of a NIC fault.
- No live QP migration / connection re-establishment tricks. UD QPs are
  connectionless; recovery is destroy-and-recreate, not repair.
- No change to the 6-timestamp protocol, the wire format, or the controller
  registry schema.

## Current State (verified against code)

- **No async-event subscription exists.** The Zig C-ABI
  (`zig/include/rdma_bridge.h`) exposes context/device/queue lifecycle, the
  data-path sends, and the **completion** event ring
  (`rdma_event_ring_create/poll/destroy/drop_count`) — but nothing calls
  `ibv_get_async_event`. After a device fault the CQ poller thread simply stops
  producing completions and the affected Prober/Responder goes silent with no
  signal.
- **Per-device isolation already exists in the agent.** `agent.go` keeps
  parallel slices: `devices`, `probers`, `responders`, `monitors`,
  `proberRings`, `respRings`, one entry per opened RNIC. Everything is already
  indexed by device *i*, which is exactly the granularity reinit needs.
- **The device holds its `ibv_context`.** Zig `types.zig RdmaDevice` has
  `ctx: *c.ibv_context` (line ~111); `ibv_get_async_event(context, &event)`
  operates on that context. The Go `rdmabridge.Device` wraps `handle`
  (context) + `devHandle`, with `Info` (GID/IP/name/port). Async subscription
  therefore lives naturally at the device level, one watcher per open device.
- **Teardown is already idempotent and per-component.**
  - `Prober.Destroy()` uses `destroyOnce sync.Once` and `queueMu` to guard the
    `queue` pointer; it closes the prober's `Results()` channel and tears down
    the queue exactly once.
  - `Responder.Destroy()` mirrors this.
  - `rdmabridge.Queue.Destroy()`, `Device.Close()`, `EventRing.Destroy()` are the
    lower-level frees; the header documents the ordering constraint (queues
    destroyed before device; ring outlives... see below).
- **The results fan-in is the hard integration point.**
  `Agent.createResultsFanIn` starts **one goroutine per prober**, each capturing
  a specific `*Prober p` and `range p.Results()`. It shares process-global
  `resultsWg`, `resultsDone`, `results`, and `analysisResults`.
  `Agent.stopResultsFanIn` closes `resultsDone`, waits `resultsWg`, then closes
  `results` (and `analysisResults`) **exactly once**. This whole machine is
  built for one-shot shutdown, not for replacing a single prober mid-flight —
  reinit must extend it carefully (see "Fan-in re-wiring").
- **Re-registration already works.** `buildRegistrationRequest` builds the full
  RNIC set (GID, current QPN from `responder.GetQueueInfo()`, IP, device name)
  and `registerWithController` / the heartbeat both send the **complete** set.
  The registry (`RegisterRNICs`) does set-replacement per agent, so a changed
  QPN after reinit propagates on the next registration with no special-casing.
  This means reinit's "re-register" step is just: trigger a registration with
  the rebuilt state.
- **Event-ring creation ordering.** Per `agent.go` and CLAUDE.md, the
  `EventRing` must be created **before** the `Queue` and passed into
  `rdma_create_queue`. Reinit must recreate the ring first, then the queue.

## Design

### Component 1 — Zig async-event watcher (new C-ABI surface)

`ibv_get_async_event` is **blocking** by default (it reads the device's async
fd). Mirror the existing completion-ring pattern: a dedicated Zig watcher thread
per device blocks on the event, classifies it, `ibv_ack_async_event`s it, and
pushes a typed record into a **new, separate SPSC ring** that Go polls. Keeping
this ring distinct from the completion ring is deliberate — different struct,
different semantics, different consumer cadence, and it must not contend with the
hot completion path.

New C-ABI (added to `rdma_bridge.h`, implemented in a new `zig/src/async.zig`,
exported from `main.zig`):

```c
/* Async event kinds delivered to Go (stable ABI values). */
#define RDMA_ASYNC_DEVICE_FATAL   1   /* IBV_EVENT_DEVICE_FATAL: full reinit */
#define RDMA_ASYNC_PORT_ERR       2   /* IBV_EVENT_PORT_ERR: link down */
#define RDMA_ASYNC_PORT_ACTIVE    3   /* IBV_EVENT_PORT_ACTIVE: link back */
#define RDMA_ASYNC_QP_FATAL       4   /* IBV_EVENT_QP_FATAL: queue-scoped reinit */
#define RDMA_ASYNC_GID_CHANGE     5   /* IBV_EVENT_GID_CHANGE: re-query GID */
#define RDMA_ASYNC_OTHER          6   /* logged, no action */

typedef struct {
    uint32_t event_type;   /* one of RDMA_ASYNC_* */
    uint8_t  port_num;     /* affected port (0 if N/A) */
    uint8_t  _pad[3];
} rdma_async_event_t;

/* New opaque handle, alongside the existing rdma_context_t/rdma_device_t/
 * rdma_queue_t/rdma_event_ring_t in rdma_bridge.h. Kept distinct from
 * rdma_event_ring_t so the async control ring cannot be mistakenly passed to a
 * completion-ring API (they carry different event structs). */
typedef void* rdma_async_ring_t;

/* One watcher per device. The watcher owns a small SPSC ring Go polls. */
int32_t  rdma_async_watch_start(rdma_device_t dev, rdma_async_ring_t* out_ring);
int32_t  rdma_async_ring_poll(rdma_async_ring_t ring, rdma_async_event_t* out, int32_t max);
void     rdma_async_watch_stop(rdma_async_ring_t ring);   /* unblocks + joins watcher */
```

**Teardown of a blocking watcher** is the subtle part. `ibv_get_async_event`
blocks in the watcher thread; `rdma_async_watch_stop` must unblock it
deterministically. Two workable mechanisms, to be chosen during implementation:

1. **Non-blocking async fd + `poll()`**: dup the device's `async_fd`
   (`ibv_context.async_fd`), set `O_NONBLOCK`, and have the watcher `poll()` on
   `{async_fd, shutdown_eventfd}`. `rdma_async_watch_stop` writes the eventfd →
   `poll` returns → thread drains any pending event and exits. This is the clean
   approach and is the recommended one.
2. **Close-to-unblock**: rely on device close to error the blocking call. This
   races the very reinit we are performing and is harder to reason about;
   avoid.

Events map to actions:

| Event | Meaning | Action |
|-------|---------|--------|
| `DEVICE_FATAL` | HCA/verbs context dead | **Full device reinit** (below) |
| `PORT_ERR` | link down (cable/peer) | Mark device degraded; pause its prober; wait for `PORT_ACTIVE` (do **not** destroy — the context is still valid) |
| `PORT_ACTIVE` | link restored | Resume prober; re-query GID if a `GID_CHANGE` was seen |
| `QP_FATAL` | one QP errored | Queue-scoped rebuild (recreate that Prober/Responder queue) without closing the device |
| `GID_CHANGE` | GID table changed | Re-query GID/IP; if changed, re-register (new addressing) |

`PORT_ERR` vs `DEVICE_FATAL` distinction matters: a flapping cable should *pause*,
not *rebuild* (rebuilding on a transient port bounce would churn QPNs and spam
re-registration). Only a fatal/removal event triggers the destructive path.

### Component 2 — Go async supervisor

A new `internal/agent/rnic_supervisor.go` runs one goroutine per device that
polls that device's async ring (same poll-in-a-goroutine model as the completion
ring — never a Cgo callback) and drives a per-device state machine:

```
        HEALTHY ──PORT_ERR──► DEGRADED ──PORT_ACTIVE──► HEALTHY
           │                     │
      DEVICE_FATAL          DEVICE_FATAL
           ▼                     ▼
        REINITIALIZING ──ok──► HEALTHY
           │  fail (backoff exhausted)
           ▼
         DOWN  (metric raised; left for operator / process restart)
```

The supervisor serializes reinit of a given device (a device is reinitialized by
at most one goroutine at a time) and never touches other devices' state.

### Component 3 — Per-device reinit sequence

For `DEVICE_FATAL` on device *i*, the supervisor performs, under a per-device
reinit lock:

1. **Quiesce.** Stop `monitors[i]` from pushing new targets and pause
   `probers[i]` (a new `Prober.Pause()` / `Resume()` or a cheap "suspend sends"
   flag — sends short-circuit while paused). This prevents new sends against a
   dead queue.
2. **Detach fan-in for prober *i*.** Signal the single fan-in goroutine bound to
   `probers[i]` to exit and wait for just that one (see "Fan-in re-wiring").
3. **Destroy the affected components** using the existing idempotent teardown:
   `probers[i].Destroy()`, `responders[i].Destroy()`, then their queues are
   freed inside those; then `proberRings[i].Destroy()`, `respRings[i].Destroy()`,
   `rdma_async_watch_stop(asyncRing[i])`, and finally `devices[i].Close()`.
   Order matches the header rule (queues before device; rings after queues).
4. **Re-open the device** with the *same* parameters the agent used originally —
   by name if `AllowedDeviceNames` is set, else by index — passing the same
   `gidIndex`, `sl`, `tc` (already threaded through `openDevices` →
   `OpenDevice(index, gidIndex, sl, tc)`). A removed-then-readded rxe device may
   reappear at a different index; **prefer re-open by name** during reinit even
   when the initial open was by index, keyed on `devices[i].Info.DeviceName`, to
   survive index reshuffling.
5. **Rebuild in creation order**: new `EventRing`s → new async watcher → new
   `Prober` (new QPN) → new `Responder` (new QPN) → new `ClusterMonitor` bound to
   the new prober. Re-apply per-target rate limit and flow-label rotation period
   from config, exactly as `Initialize` does.
6. **Re-attach fan-in** for the new prober *i* (start one new fan-in goroutine
   bound to it).
7. **Re-register** with the controller by triggering `buildRegistrationRequest`
   + `RegisterAgent` (reusing `registerWithController`'s retry/backoff). The new
   QPNs are in `responders[i].GetQueueInfo()`, so the full-set re-registration
   propagates them; the registry's set-replacement does the rest.
8. **Resume** prober *i* and its monitor. Transition state → HEALTHY.

**In-flight & pending state.** The destroyed prober's `pending` map is discarded
with it; any probe awaiting an ACK becomes a timeout on the *old* queue and is
never matched (the sequence-number epoch — `agentEpoch` high bits — was randomized
per prober and the QPN changed, so a stray late ACK cannot misroute into the new
queue). Those probes land as loss in whatever window was open, which is correct.
No special reconciliation is needed.

### Fan-in re-wiring (the critical integration risk)

Today `createResultsFanIn` and `stopResultsFanIn` are a **one-shot** design:
N goroutines, a single shared `resultsWg`, a single `resultsDone` closed once,
and `results`/`analysisResults` closed exactly once at shutdown. Reinit needs to
replace **one** prober's fan-in goroutine while the others keep running and the
shared channels stay open. Reconciling this with the existing contract:

- **Per-prober cancellation, not global.** Replace the single `resultsDone` with
  a mechanism that can stop one goroutine: give each fan-in goroutine its own
  `stop chan struct{}` (kept in a per-device slice), while `stopResultsFanIn`
  still closes all of them for shutdown. A goroutine selects on its own `stop`
  in addition to `resultsDone`.
- **Never close the shared channels on a single reinit.** `results` and
  `analysisResults` are closed only at final shutdown, exactly as now. A reinit
  goroutine exit must NOT close them (other probers still send). It only exits
  its own `range`/select loop; the new goroutine for the rebuilt prober begins
  sending on the same shared channels.
- **WaitGroup discipline.** The reinit waits for *only* the one old goroutine to
  finish (a per-goroutine `done`/`sync.WaitGroup` of size 1), not the global
  `resultsWg`. The global `resultsWg` still gates final shutdown; the new
  goroutine is added to it when started.
- **Ordering vs prober Destroy.** The old prober's `Results()` closes on
  `Destroy()`, ending its goroutine's `range`. So the safe sequence is: signal
  the goroutine's `stop` (so it unblocks even if mid-send on a full channel) →
  `probers[i].Destroy()` (closes Results, ends range) → wait that one goroutine →
  proceed. This is the same reasoning `stopResultsFanIn` documents, narrowed to a
  single prober.

This re-wiring (making the fan-in support single-prober replace) is itself the
largest and riskiest code change and should be its own PR, landed and tested
**before** any device is actually reinitialized.

### Failure handling, backoff, partial failure

- **Backoff.** Reinit attempts use exponential backoff reusing the existing
  constants' spirit (`registerRetryInitialBackoff` 1s → `registerRetryMaxBackoff`
  30s) with a bounded attempt count (e.g. 5). Between attempts the device stays
  paused/degraded, not spinning.
- **Give-up → DOWN.** On exhausting attempts, the device is left in `DOWN`: its
  slot stays nil-ish (prober/responder absent), a metric is raised, and the agent
  continues with its remaining RNICs. Recovery from `DOWN` is a process restart
  (systemd), matching the Non-Goal boundary.
- **Partial failure (multi-RNIC, one bad card).** This is the common case and is
  handled by construction: everything is per-device, the supervisor touches only
  device *i*, and the re-registration sends the full current set (healthy RNICs
  unchanged, rebuilt RNIC with its new QPN, `DOWN` RNIC omitted so the controller
  stops distributing it in pinglists via set-replacement).
- **Event storms / flapping.** Debounce: a `PORT_ERR`/`PORT_ACTIVE` flap only
  pauses/resumes (cheap). Repeated `DEVICE_FATAL` within a short window escalates
  straight to `DOWN` rather than churning QPNs.

### Metrics (OTLP, low cardinality)

Registered on the agent's existing meter, aggregated across devices under a small
label set (matching the `ring="prober"/"responder"` aggregation convention in
`agent.go`):

| metric | type | attributes | meaning |
|--------|------|-----------|---------|
| `rpingmesh.agent.rnic_async_events_total` | Counter | `event` (fatal/port_err/port_active/...) | async events observed |
| `rpingmesh.agent.rnic_reinit_total` | Counter | `result` (ok/failed) | reinit attempts |
| `rpingmesh.agent.rnic_state` | Gauge | `state` (healthy/degraded/reinit/down) | count of devices in each state |

No per-device / per-GID attributes on metrics; device identity goes to logs.

## soft-RoCE testability (investigation + strategy)

**Can `rdma link delete` reproduce a device-fatal?** This needs empirical
confirmation on the CI rxe setup, but the expected behavior: deleting an rxe link
(`rdma link delete rxe0`) removes the device; libibverbs surfaces this to a
process holding the context as a fatal/removal condition and the async fd becomes
readable/hung-up. `rdma link add` recreates it (as the e2e harness already does
for provisioning — see `docker-compose.e2e.yml` cap list and
`scripts/setup-colima-rdma.sh`). A `PORT_ERR`/`PORT_ACTIVE` pair is harder to
force on rxe (no real cable); it may be inducible by bringing the underlying
netdev down/up (`ip link set <veth> down/up`) given the soft-RoCE policy-routing
setup already in the repo.

**Strategy** (staged, because full device-fatal e2e is the least certain part):

1. **Zig unit test** (`zig build test`): the async ring push/poll/drop and the
   watcher-stop unblock path, with a fake/mock event source — no real fault
   needed. Deterministic.
2. **Go unit test** (RDMA-free): the supervisor state machine and the reinit
   *orchestration* driven by an injected fake that emits async events and a fake
   device/bridge — assert the destroy→reopen→rebuild→re-register call sequence
   and the fan-in single-prober replace, using the same fake-bridge seam the
   existing agent tests use. This covers the hard integration logic without a
   NIC.
3. **e2e (soft-RoCE, Docker)**: a new test that starts the agent against rxe0,
   confirms probing, then `rdma link delete rxe0` mid-test and (after a delay)
   `rdma link add`, and asserts the agent emits a reinit event and resumes
   probing on the rebuilt device (assert *shape*, not success rate, matching the
   existing e2e philosophy). If device-fatal proves not to fire on rxe delete,
   fall back to the netdev down/up path for `PORT_ERR`/`PORT_ACTIVE` and gate the
   destructive-reinit e2e as a known hardware-only test.

The investigation task (does rxe delete raise `IBV_EVENT_DEVICE_FATAL`, and does
the async fd behave as assumed) is the first concrete implementation step and its
outcome may adjust the event→action table above.

## Alternatives Considered

- **Poll device health instead of subscribing to async events.** Rejected:
  polling `ibv_query_port` on a timer is racy and slow to detect fatal removal,
  and it cannot distinguish a transient port bounce from a fatal. Async events
  are the purpose-built mechanism.
- **Cgo callback from the watcher thread into Go.** Rejected for the same reason
  the completion path avoids it (CLAUDE.md): callbacks across the Cgo boundary
  from a foreign thread are fragile; the SPSC-ring + Go-poll model is the
  established pattern and reused here.
- **Restart the whole agent on any device fault.** Rejected for multi-RNIC
  hosts: one bad card would blind every other healthy RNIC for the restart
  window. Per-device reinit preserves monitoring on the survivors. (Whole-process
  restart remains the fallback only for host-fatal / give-up.)
- **Reuse the completion event ring for async events.** Rejected: different
  struct and semantics, and it would couple a cold control path to the hot
  data path. A separate ring keeps the fast path untouched.
- **Rebuild on `PORT_ERR`.** Rejected: a flapping link would churn QPNs and spam
  re-registration. `PORT_ERR` pauses; only fatal rebuilds.
- **Generalize the fan-in to a fully dynamic registry up front.** Considered;
  the narrower "support single-prober replace" change is lower-risk and
  sufficient. A full dynamic redesign is more than reinit needs.

## Implementation Plan (PR breakdown)

1. **P3-I.1 — Zig async watcher + C-ABI.** `zig/src/async.zig`, the
   `rdma_async_*` exports, the `rdma_async_event_t` struct, and the
   non-blocking-fd + eventfd stop mechanism. `internal/rdmabridge` wrappers
   (`AsyncRing`, `Device.WatchAsync`, `AsyncRing.Poll/Stop`). Zig unit tests for
   ring + stop-unblock. No agent behavior change yet (watcher can be started and
   its events logged only). **Includes the investigation** of rxe delete
   behavior.
2. **P3-I.2 — Fan-in single-prober replace.** Refactor `createResultsFanIn` /
   `stopResultsFanIn` to per-goroutine stop channels and a helper to
   detach/attach one prober's fan-in without closing the shared channels. Pure
   Go, unit-tested with fake probers. Lands and is proven **before** reinit uses
   it.
3. **P3-I.3 — Supervisor + per-device reinit orchestration.**
   `internal/agent/rnic_supervisor.go`: the state machine, quiesce/pause,
   destroy→reopen(by name)→rebuild→re-register→resume, backoff, DOWN handling.
   `Prober.Pause/Resume`. Go unit tests with injected fake async events and fake
   bridge; assert the exact call sequence and fan-in re-wire. Metrics.
4. **P3-I.4 — soft-RoCE e2e.** New Docker e2e that deletes/re-adds rxe0 mid-run
   (or netdev down/up fallback) and asserts reinit + resumed probing shape.
5. **P3-I.5 (optional) — QP_FATAL / GID_CHANGE fine-grained handling.**
   Queue-scoped rebuild without device close, and GID re-query + re-register.
   Smaller, layered on the machinery from I.3.

## Open Questions

- **Does `rdma link delete` raise `IBV_EVENT_DEVICE_FATAL` on rxe, and how does
  the async fd behave on removal?** This is an empirical unknown that shapes the
  event→action table and the e2e strategy. It is the first task in P3-I.1.
  *(Investigation, not user input — but if it turns out device-fatal is not
  reproducible in CI, the destructive-reinit e2e becomes hardware-only, which is
  a coverage decision worth surfacing.)*
- **Re-open by name vs by index after removal.** The design recommends by-name
  during reinit even when the initial open was by index, to survive rxe index
  reshuffling. Is by-name always resolvable for the target fleet's NICs
  (mlx5_N)? *(User input helpful.)*
- **DOWN policy.** Should a device that exhausts reinit attempts trigger a
  process exit (let systemd restart the whole agent, re-probing everything) or
  stay DOWN and keep the survivors probing? The design chooses stay-DOWN; the
  opposite (fail the process) is defensible if operators prefer "all or
  nothing". *(User input needed.)*
- **Pause vs keep-registered during `PORT_ERR`.** While a port is down, should
  the RNIC remain in the registry (so peers keep trying and record loss, which is
  itself signal) or be withdrawn (so peers stop wasting probes)? The design keeps
  it registered and lets loss be recorded; withdrawing is an alternative.
  *(User input helpful.)*
