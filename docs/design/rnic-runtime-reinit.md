# RNIC Runtime Re-initialization

Status: design only, not implemented (tracking ID P3-I). As an interim
measure, the agent detects that an opened device was unregistered,
re-registered, or renamed (its `/sys/class/infiniband_verbs/uverbsN` node
disappears, gets a new inode, or names another device) and exits non-zero so systemd restarts it (`internal/agent/device_watch.go`). This
design would replace that restart with per-RNIC recovery. This document
specifies how the agent detects an RDMA device or port fault at runtime and
rebuilds the affected device's Prober, Responder, and queues without a process
restart.

## Goals

- Subscribe to RDMA **asynchronous events** (`ibv_get_async_event`) so the
  agent learns about fatal device errors and port up/down transitions instead
  of going silent after a fault.
- **Recover per RNIC.** On a fatal event for device *i*, tear down and rebuild
  only that device's Prober, Responder, queues, and event rings, then
  re-register so the new QPNs reach the controller. Other RNICs keep probing.
- Respect the existing lifecycle contracts: idempotent Prober/Responder
  teardown, event ring created before its queue, and the deterministic
  results fan-in shutdown in `agent.go`.
- Fail safe: bounded retries with backoff. A device that cannot be recovered
  stays down, is surfaced as a metric, and does not affect the rest of the
  agent.

## Non-Goals

- No recovery when the RDMA subsystem is gone entirely. That remains a process
  restart, handled by systemd `Restart=on-failure`.
- No preservation of in-flight probes across a rebuild (see
  [In-flight probes](#in-flight-probes)).
- No QP repair. UD QPs are connectionless; recovery is destroy and recreate.
- No change to the 6-timestamp protocol, the wire format, or the registry
  schema.

## Current State (verified against code)

- **No async-event handling exists.** The C ABI (`zig/include/rdma_bridge.h`)
  covers context, device, and queue lifecycle, the data-path sends, and the
  **completion** event ring (`rdma_event_ring_create`/`poll`/`destroy`/
  `drop_count`/`notify_fd`). Nothing calls `ibv_get_async_event`. After a
  device fault the CQ poller stops producing completions and the affected
  Prober and Responder go quiet without any signal.
- **Agent state is already per device.** `Agent` in `internal/agent/agent.go`
  keeps parallel slices indexed by device: `devices`, `probers`,
  `responders`, `monitors`, `proberRings`, `respRings`, plus the resolved
  per-device `deviceNetdevs`, `deviceTorIDs`, and `devicePlaneIDs`.
- **Several goroutines read those slices without a lock.** The heartbeat
  (`heartbeatLoop` → `buildRegistrationRequest`) walks `responders` and
  `devices`; the ring-drop metric callbacks walk `proberRings` and
  `respRings`; the self-protection `Watchdog` holds its own copy of the prober
  list as `throttlers`. Today these slices never change after `Initialize`, so
  this is safe. Reinit breaks that assumption.
- **The device owns its `ibv_context`.** `RdmaDevice` in `zig/src/types.zig`
  holds `ctx: *c.ibv_context`, which is what `ibv_get_async_event` operates
  on. The Go `rdmabridge.Device` wraps the context handle, `devHandle`, and
  `Info` (name, GID, IP, port, GID index). An async watcher therefore belongs
  at the device level, one per open device.
- **Teardown is idempotent per component.**
  - `Prober.Destroy()` calls `Stop()`, then, under `destroyOnce`, closes
    `Results()` and destroys the queue (guarded by `queueMu`).
  - `Responder.Destroy()` calls `Stop()` and destroys the queue under
    `queueMu`; repeat calls are no-ops because the queue pointer is nil.
  - `Prober.Stop()`/`Start()` already support a restart: `Start` recreates
    `stopCh`.
  - Lower-level frees are `Queue.Destroy()`, `Device.Close()`, and
    `EventRing.Destroy()`. The header requires queues to be destroyed before
    their device and all devices before `rdma_destroy`. `Agent.Stop` destroys
    the rings last, after the devices and the context.
- **The results fan-in is one-shot.** `createResultsFanIn` starts one
  goroutine per prober, each ranging over that prober's `Results()` and
  sharing `resultsWg`, `resultsDone`, `results`, and `analysisResults`.
  `stopResultsFanIn` closes `resultsDone`, waits on `resultsWg`, and closes
  `results` and `analysisResults` exactly once. It cannot replace a single
  prober (see [Fan-in re-wiring](#fan-in-re-wiring)).
- **Re-registration already propagates new QPNs.** `buildRegistrationRequest`
  sends the complete RNIC set (QPN from `responder.GetQueueInfo()`), and
  `RegisterRNICs` replaces all rows for the agent in one transaction. Both the
  initial `registerWithController` and the heartbeat use it, so a rebuilt
  device's new QPN reaches the registry on the next registration.
- **The device list is cached.** `RdmaContext` (`zig/src/types.zig`) stores
  `device_list` and `device_count`, filled once by `ibv_get_device_list()` in
  `rdma_init`. `rdma_get_device_count`, `rdma_get_device_name`,
  `rdma_open_device`, and `rdma_open_device_by_name` all read that cached
  array. A device that is removed and re-added is not in it.

## Design

### Component 1: Zig async-event watcher (new C ABI)

A dedicated Zig thread per device waits for async events, classifies each
one, acknowledges it with `ibv_ack_async_event`, and pushes a typed record
into a **separate SPSC ring** that Go polls. The ring is separate from the
completion ring because it carries a different struct, has a different
consumer cadence, and must not contend with the hot completion path.

New C ABI in `rdma_bridge.h`, implemented and exported from a new
`zig/src/async.zig` (exports live in their module files, as in `device.zig`
and `ring.zig`; `main.zig` references the module in its `comptime` block so the
symbols are retained in the static library):

```c
/* Async event kinds delivered to Go (stable ABI values). */
#define RDMA_ASYNC_DEVICE_FATAL   1   /* IBV_EVENT_DEVICE_FATAL: full reinit */
#define RDMA_ASYNC_PORT_ERR       2   /* IBV_EVENT_PORT_ERR: link down */
#define RDMA_ASYNC_PORT_ACTIVE    3   /* IBV_EVENT_PORT_ACTIVE: link back */
#define RDMA_ASYNC_QP_FATAL       4   /* IBV_EVENT_QP_FATAL: queue-scoped rebuild */
#define RDMA_ASYNC_GID_CHANGE     5   /* IBV_EVENT_GID_CHANGE: re-query GID */
#define RDMA_ASYNC_OTHER          6   /* logged, no action */

typedef struct {
    uint32_t event_type;   /* one of RDMA_ASYNC_* */
    uint8_t  port_num;     /* affected port (0 if N/A) */
    uint8_t  _pad[3];
} rdma_async_event_t;

/* Distinct from rdma_event_ring_t so the async ring cannot be passed to a
 * completion-ring API by mistake. */
typedef void* rdma_async_ring_t;

/* One watcher per device; the watcher owns a small SPSC ring that Go polls. */
int32_t rdma_async_watch_start(rdma_device_t dev, rdma_async_ring_t* out_ring);
int32_t rdma_async_ring_poll(rdma_async_ring_t ring, rdma_async_event_t* out, int32_t max);
void    rdma_async_watch_stop(rdma_async_ring_t ring);   /* unblocks and joins the watcher */
```

**Stopping a blocked watcher.** `ibv_get_async_event` blocks on the device's
`async_fd`. The watcher instead blocks in `poll(2)` on two descriptors:
`ibv_context.async_fd` and a shutdown `eventfd`. It calls
`ibv_get_async_event` only after `poll` reports `async_fd` readable, so the
call returns at once. `rdma_async_watch_stop` writes the eventfd, `poll`
returns, and the thread exits.

The watcher never changes the file status flags of `async_fd`. `O_NONBLOCK`
lives on the open file description, which `dup(2)` shares, so setting it even
on a duplicate would make the context's own `async_fd` non-blocking for every
other user. Readiness comes from `poll`, not from non-blocking reads.

Unblocking by closing the device instead was rejected: it races the very
reinit being performed.

Events map to actions:

| Event | Meaning | Action |
|-------|---------|--------|
| `DEVICE_FATAL` | verbs context is dead | Full device reinit |
| `PORT_ERR` | link down | Mark the device degraded and pause its prober. The context is still valid; do not destroy anything. |
| `PORT_ACTIVE` | link restored | Resume the prober; re-query the GID if a `GID_CHANGE` was seen |
| `QP_FATAL` | one QP errored | Rebuild that Prober's or Responder's queue without closing the device |
| `GID_CHANGE` | GID table changed | Re-query GID and IP; re-register if they changed |

A flapping cable must only pause and resume. Rebuilding on a port bounce would
churn QPNs and flood the controller with re-registrations. Only a fatal event
takes the destructive path.

### Component 2: Go supervisor

A new `internal/agent/rnic_supervisor.go` runs one goroutine per device. It
polls that device's async ring (polled from Go, never a Cgo callback, like the
completion ring) and drives a per-device state machine:

```
        HEALTHY ──PORT_ERR──► DEGRADED ──PORT_ACTIVE──► HEALTHY
           │                     │
      DEVICE_FATAL          DEVICE_FATAL
           ▼                     ▼
        REINITIALIZING ──ok──► HEALTHY
           │  fail (attempts exhausted)
           ▼
         DOWN  (metric raised; left for the operator or a process restart)
```

At most one reinit runs per device at a time, and the supervisor touches only
that device's state. Pause and resume can reuse `Prober.Stop()`/`Start()` or a
lighter "suspend sends" flag; either way sends must stop before the queue is
destroyed.

### Component 3: Per-device reinit sequence

For `DEVICE_FATAL` on device *i*, under that device's reinit lock:

1. **Quiesce.** Stop `monitors[i]` and pause `probers[i]` so no new sends hit
   the dead queue.
2. **Signal fan-in goroutine *i* to stop, without waiting.** Close its
   per-goroutine `stop` channel. This unblocks a goroutine that is mid-send on
   a full channel. A goroutine parked in `range p.Results()` cannot see `stop`,
   so waiting here would deadlock.
3. **Destroy, then wait.** `probers[i].Destroy()` closes `Results()`, which
   ends the goroutine's `range`; now wait for that one goroutine. Then
   `responders[i].Destroy()`, `rdma_async_watch_stop` for the device's async
   ring, and `devices[i].Close()`. Destroy `proberRings[i]` and `respRings[i]`
   only after their queues are gone, matching `Agent.Stop`.
4. **Refresh the device list, then reopen.** The cached device list does not
   contain a re-added device, so reopening without a refresh fails or opens a
   stale entry.
   - Recreating the whole context (`rdma_destroy` + `rdma_init`) is rejected:
     the header requires every device and queue to be destroyed first, which
     would stop every healthy RNIC.
   - Instead add `int32_t rdma_refresh_devices(rdma_context_t ctx)`, which
     calls `ibv_free_device_list()` and re-runs `ibv_get_device_list()`,
     updating `device_list` and `device_count` in place.
     `ibv_free_device_list()` frees only the list array, not the contexts of
     opened devices, so healthy RNICs are unaffected. Go exposes it as
     `Context.RefreshDevices()`.
   - **Context mutex.** The refresh frees an array that every
     count/name/open call reads. Two devices can fail together, and their
     reinits run concurrently under separate per-device locks, so the shared
     list needs its own lock. A context-level mutex (on the Go `Context` or in
     the Zig `RdmaContext`) makes `RefreshDevices`, `GetDeviceCount`,
     `GetDeviceName`, `OpenDevice`, and `OpenDeviceByName` mutually exclusive.
     Lock order: per-device reinit lock first, then the context mutex around
     the refresh-and-reopen span only. Release it before re-registration so a
     slow RPC never blocks another device's enumeration.
   - **Reopen by name**, using `devices[i].Info.DeviceName`, even if the
     initial open was by index: a re-added device often appears at a new
     index. Pass the same `gid_index`, `service_level`, and `traffic_class` as
     `openDevices`, and set the same `CQPollMode`.
5. **Rebuild in creation order.** Re-resolve the device's netdev and ToR (and
   its plane) as `Initialize` does, because a re-added device may bind a
   different netdev. Then create new event rings, the async watcher, the
   `Prober` (new QPN), and the `Responder` (new QPN). Re-apply
   `SetSourceTorID`, `SetSourceNetdev`, `SetPerTypeRateLimit`, and
   `SetFlowLabelRotationPeriod` as `Initialize` does, replace the prober in
   the watchdog's throttler list, and create a new `ClusterMonitor` with the
   device's GID and plane.
6. **Re-attach the fan-in** with one new goroutine bound to the new prober.
7. **Re-register** through `registerWithController` (same retry and backoff).
   The full-set registration carries the new QPNs.
8. **Resume** the prober and start the monitor. State becomes HEALTHY.

#### Shared per-device state

Steps 3–5 replace entries in slices that the heartbeat, the ring-drop metric
callbacks, and the watchdog read concurrently. Guard the per-device slots with
an agent-level `sync.RWMutex` (readers take the read lock), or replace each
slot atomically. While a slot is empty, `buildRegistrationRequest` and the
drop-count callbacks must skip it instead of dereferencing nil.

Replacing a ring also resets its drop count, which makes the
`rpingmesh.event_ring_dropped_total` observable counter go backwards. Keep a
per-slot running total across replacements so the counter stays monotonic.

#### In-flight probes

`Prober.Destroy()` discards the pending map without emitting results.
`cleanupStalePending`, which turns expired entries into failed results, runs
only in the probe loop, so probes still awaiting an ACK at destroy time vanish
instead of counting as loss. Reinit should emit those entries as failed
results before destroying the prober, so the window records the fault. A late
ACK cannot be misrouted into the new queue: the new prober has a new random
`agentEpoch` and a new QPN.

### Fan-in re-wiring

Reinit must replace one prober's fan-in goroutine while the others keep
running and the shared channels stay open:

- **Per-goroutine stop.** Give each fan-in goroutine its own
  `stop chan struct{}` in a per-device slice. The goroutine selects on both
  its own `stop` and `resultsDone`. `stopResultsFanIn` still stops all of
  them at shutdown.
- **Never close the shared channels on reinit.** `results` and
  `analysisResults` are closed only at final shutdown. The replacement
  goroutine sends on the same channels.
- **Per-goroutine wait.** Reinit waits only for the one old goroutine (its own
  done channel or a WaitGroup of one), not `resultsWg`. The new goroutine is
  added to `resultsWg` so final shutdown still waits for it.
- **Order.** Signal `stop` → `probers[i].Destroy()` → wait for the goroutine.
  This is the reasoning documented on `stopResultsFanIn`, narrowed to one
  prober.

This refactor is the largest and riskiest change. It lands and is tested in
its own PR before any device is reinitialized.

### Failure handling

- **Backoff.** Reinit attempts back off exponentially from 1 s to 30 s (the
  values of `registerRetryInitialBackoff` and `registerRetryMaxBackoff`) with
  a bounded attempt count (for example 5). The device stays paused between
  attempts.
- **DOWN.** After the last attempt the device stays DOWN: its slots are empty,
  a metric reports it, and the other RNICs keep probing. Re-registration omits
  it, so the controller stops handing it out in pinglists. Leaving DOWN
  requires a process restart.
- **Partial failure.** One bad card among several is the common case. State is
  per device, so only the shared device list (context mutex) and the shared
  per-device slices (see [Shared per-device state](#shared-per-device-state))
  need cross-device locking.
- **Event storms.** Port flaps only pause and resume. Repeated `DEVICE_FATAL`
  within a short window goes straight to DOWN instead of churning QPNs.

### Metrics (OTLP)

Registered on the agent's existing `rpingmesh.agent` meter:

| Metric | Type | Attributes | Meaning |
|--------|------|------------|---------|
| `rpingmesh.agent.rnic_async_events_total` | Counter | `event` (`device_fatal`/`port_err`/`port_active`/`qp_fatal`/`gid_change`/`other`) | async events observed |
| `rpingmesh.agent.rnic_reinit_total` | Counter | `result` (`ok`/`failed`) | reinit attempts |
| `rpingmesh.agent.rnic_state` | Gauge | `state` (`healthy`/`degraded`/`reinit`/`down`) | number of devices in each state |

These follow the aggregate style of `rpingmesh.event_ring_dropped_total`
(one `ring` attribute, not one series per device). The local RNIC is a
bounded attribute in this project (probe metrics carry `source_rdma_device`),
so adding it here is acceptable if per-device state is needed on dashboards.
GIDs never appear on metrics; device identity goes to logs.

## soft-RoCE Testability

**Can `rdma link delete` reproduce a fatal event?** This needs confirmation
on the CI rxe setup. Expected behavior: deleting the rxe link removes the
device, and a process holding its context sees a fatal or removal condition on
`async_fd`. `rdma link add` recreates it, as `scripts/run-e2e.sh` does when it
provisions `rxe0` on `veth0`. A `PORT_ERR`/`PORT_ACTIVE` pair may be inducible
by taking the underlying veth down and up.

**Strategy** (staged, because device-fatal e2e is the least certain part):

1. **Zig unit tests** (`make test-zig`): async ring push/poll/drop and the
   stop-unblock path with a fake event source.
2. **Go unit tests** (RDMA-free): the supervisor state machine and reinit
   orchestration, driven by injected fake events. The agent tests today use
   metadata-only `fakeDevice` and `fakeProber` helpers and have no bridge
   interface, so this needs a new seam over the reopen/create/destroy calls.
   Assert the destroy → refresh → reopen → rebuild → re-register sequence and
   the single-prober fan-in replacement.
3. **e2e (soft-RoCE, Docker)**: start the agent on rxe0, confirm probing,
   delete and re-add the rxe link, and assert a reinit and resumed probing
   (shape only, as in the existing e2e tests). If deletion raises no fatal
   event, test `PORT_ERR`/`PORT_ACTIVE` through veth down/up and mark the
   destructive-reinit e2e as hardware-only.

The rxe investigation is the first implementation step; its result may change
the event→action table.

## Alternatives Considered

- **Poll device health** (`ibv_query_port` on a timer). Rejected: slow to
  detect removal and unable to tell a port bounce from a fatal error.
- **Cgo callback from the watcher thread.** Rejected for the same reason the
  completion path avoids it: callbacks into Go from a foreign thread are
  fragile. The SPSC ring polled from Go is the established pattern.
- **Restart the agent on any device fault.** Rejected for multi-RNIC hosts:
  one bad card would blind every healthy RNIC during the restart. Restart
  remains the fallback for host-wide failure and DOWN.
- **Reuse the completion ring for async events.** Rejected: different struct
  and semantics, and it would couple a cold control path to the hot data
  path.
- **Rebuild on `PORT_ERR`.** Rejected: a flapping link would churn QPNs.
- **Fully dynamic fan-in up front.** Not needed; single-prober replacement is
  smaller and sufficient.

## Implementation Plan (PR breakdown)

1. **P3-I.1: Zig async watcher and C ABI.** `zig/src/async.zig`, the
   `rdma_async_*` exports, `rdma_async_event_t`, and the `poll`-based stop.
   Go wrappers in `internal/rdmabridge` (`AsyncRing`, `Device.WatchAsync`,
   `AsyncRing.Poll`/`Stop`). Zig unit tests. Events are only logged. Includes
   the rxe deletion investigation.
2. **P3-I.2: device-list refresh and context mutex.**
   `rdma_refresh_devices` in `zig/src/device.zig` plus the header entry;
   `Context.RefreshDevices()`; the context mutex over refresh, count, name, and
   open. Tests: a refresh re-reads the count without disturbing an open
   device; a race-detector test interleaves refresh with open and count.
3. **P3-I.3: fan-in single-prober replacement and slot locking.**
   Per-goroutine stop channels, a detach/attach helper that leaves the shared
   channels open, and the lock over the per-device slices. Pure Go, tested
   with fake probers.
4. **P3-I.4: supervisor and reinit orchestration.** `rnic_supervisor.go`:
   state machine, pause, destroy → refresh → reopen by name → rebuild →
   re-register → resume, backoff, DOWN, pending-probe flush, and metrics.
   Unit tests assert the exact call sequence.
5. **P3-I.5: soft-RoCE e2e.** Delete and re-add rxe0 mid-run (or veth
   down/up) and assert reinit and resumed probing. This also exercises the
   device-list refresh.
6. **P3-I.6 (optional): `QP_FATAL` and `GID_CHANGE`.** Queue-scoped rebuild
   without closing the device, and GID re-query with re-registration.

## Open Questions

- **Does `rdma link delete` raise `IBV_EVENT_DEVICE_FATAL` on rxe, and how
  does `async_fd` behave on removal?** First task of P3-I.1. If the event
  cannot be reproduced in CI, destructive-reinit e2e becomes hardware-only,
  which is a coverage decision worth surfacing.
- **Reopen by name.** Is the device name stable across removal and re-add for
  the fleet's NICs? *(User input helpful.)*
- **DOWN policy.** Should a device that exhausts its attempts make the process
  exit (systemd restarts everything) or stay DOWN while the others keep
  probing? The design stays DOWN. *(User input needed.)*
- **Registration during `PORT_ERR`.** Keep the RNIC registered so peers record
  loss (itself a signal), or withdraw it so peers stop probing it? The design
  keeps it registered. *(User input helpful.)*
