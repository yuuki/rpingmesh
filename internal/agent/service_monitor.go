package agent

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/agent/servicetrace"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/telemetry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	// serviceRebuildDebounce coalesces a burst of connection events (a job
	// start opens thousands of QPs within a second) into one target rebuild
	// and one controller round trip.
	serviceRebuildDebounce = 1 * time.Second

	// serviceResolveBatch bounds the GIDs sent per GetTargetRnicInfo call;
	// it stays below the controller's MaxTargetRnicInfoGIDs.
	serviceResolveBatch = 1024

	// serviceUnresolvedRetry is how soon a GID the controller did not know
	// is asked for again, so a peer whose agent registers after the flow
	// opened is picked up well before the next full refresh.
	serviceUnresolvedRetry = 60 * time.Second
)

// serviceTargetResolver is the subset of the controller client the service
// monitor uses, declared here so tests can inject a fake.
type serviceTargetResolver interface {
	GetTargetRnicInfo(ctx context.Context, agentID, requesterGID string, targetGIDs []string) ([]*controller_agent.PingTarget, error)
}

// serviceEventSource is the tracer as the monitor sees it; satisfied by
// *servicetrace.Tracer and by test fakes.
type serviceEventSource interface {
	Start(ctx context.Context, handle func(servicetrace.Event))
	Stats() servicetrace.Stats
	Close() error
}

// serviceProber receives the SERVICE_TRACING targets of one device.
type serviceProber interface {
	UpdateServiceTargets(targets []*controller_agent.PingTarget)
}

// ServiceDevice is one local RNIC the service monitor builds targets for:
// the device the traced applications open and the prober that probes from
// the agent's queue on it.
type ServiceDevice struct {
	Name string
	// GID is the agent's probing GID on the device (canonical string), sent
	// as requester_gid; IPAddr is its address, compared with the source GID
	// of the traced flows. Port and GIDIndex are the probing port and GID
	// table index.
	GID      string
	IPAddr   string
	Port     uint8
	GIDIndex uint8
	Prober   serviceProber
}

// serviceFlowKey identifies one service flow of a local RNIC: the 5-tuple
// minus the local address, which the device fixes. The flow label stands in
// for the UDP source port it determines.
type serviceFlowKey struct {
	remoteGID [16]byte
	flowLabel uint32
}

// resolvedTarget is the controller's answer for one remote GID; a nil target
// means the GID is not registered (no agent on that RNIC).
type resolvedTarget struct {
	target     *controller_agent.PingTarget
	resolvedAt time.Time
}

type serviceDeviceState struct {
	ServiceDevice
	// cache holds the resolved targets by remote GID string. Owned by the
	// monitor goroutine.
	cache map[string]*resolvedTarget
	// warnedSGID records the source GID indexes already checked against the
	// probing GID, so each mismatch is reported once.
	warnedSGID map[uint8]bool
	// Last rebuild's counts, for the metrics callback. Guarded by statsMu.
	connections, flowsProbed, flowsUnresolved int
}

// ServiceMonitor turns the tracer's QP lifecycle events into SERVICE_TRACING
// probe targets (paper section 4.2.2): it folds the events into a connection
// table, groups the live connections of each local RNIC into flows (remote
// GID and effective flow label), asks the controller for the responder QPN
// and ToR of each remote GID, and pushes one target per flow, stamped with
// the flow's label, to the device's prober. Targets are rebuilt shortly
// after the connection set changes and re-resolved on every refresh
// interval, since a peer agent that restarts gets a new responder QPN.
type ServiceMonitor struct {
	lifecycle
	agentID  string
	resolver serviceTargetResolver
	source   serviceEventSource
	table    *servicetrace.Table

	devices map[string]*serviceDeviceState
	// devNumbers maps the uverbs device number of Event.Dev to the RDMA
	// device name, read from sysfs and re-read on an unknown number (a
	// device that appeared after startup). Owned by the monitor goroutine.
	devNumbers map[uint32]string
	sysfsRoot  string

	refreshInterval time.Duration
	debounce        time.Duration
	// unresolvedRetry is how long a negative or failed resolution is kept
	// before the remote is asked for again; a rebuild that left flows
	// unresolved arms a timer for it, so the retry does not depend on
	// further connection events.
	unresolvedRetry time.Duration
	// changed is signalled (non-blockingly) by the event handler when the
	// connection set changed; capacity 1 coalesces bursts.
	changed chan struct{}

	// procRoot is where process directories are looked up to reap the
	// contexts of exited processes (see servicetrace.Table.ReapContexts).
	procRoot string

	nowFn func() time.Time

	statsMu             sync.Mutex
	active              bool
	otherDeviceConns    uint64
	unimplementedWarned bool
	// lastDropped is the tracer's drop count at the previous rebuild, to
	// warn once per increase.
	lastDropped uint64

	logger zerolog.Logger
}

// NewServiceMonitor creates a monitor for the given devices. refreshIntervalSec
// is the full re-resolution period (the pinglist update interval);
// serviceRebuildDebounce paces event-driven rebuilds.
func NewServiceMonitor(
	resolver serviceTargetResolver,
	source serviceEventSource,
	agentID string,
	devices []ServiceDevice,
	refreshIntervalSec uint32,
) *ServiceMonitor {
	interval := time.Duration(refreshIntervalSec) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	m := &ServiceMonitor{
		agentID:         agentID,
		resolver:        resolver,
		source:          source,
		table:           servicetrace.NewTable(),
		devices:         make(map[string]*serviceDeviceState, len(devices)),
		devNumbers:      make(map[uint32]string),
		sysfsRoot:       servicetrace.DefaultSysfsRoot,
		procRoot:        "/proc",
		refreshInterval: interval,
		debounce:        serviceRebuildDebounce,
		unresolvedRetry: serviceUnresolvedRetry,
		changed:         make(chan struct{}, 1),
		nowFn:           time.Now,
		logger:          log.With().Str("component", "service_monitor").Logger(),
	}
	for _, d := range devices {
		m.devices[d.Name] = &serviceDeviceState{
			ServiceDevice: d,
			cache:         make(map[string]*resolvedTarget),
			warnedSGID:    make(map[uint8]bool),
		}
	}
	m.stopCh = make(chan struct{})
	return m
}

// Start attaches the event handler to the tracer and launches the rebuild
// loop. It returns nil if already running.
func (m *ServiceMonitor) Start(ctx context.Context) error {
	if !m.lifecycle.start() {
		return nil
	}
	m.loadDeviceNumbers()
	m.source.Start(ctx, m.handleEvent)
	m.statsMu.Lock()
	m.active = true
	m.statsMu.Unlock()
	m.wg.Add(1)
	go m.run(ctx)
	m.logger.Info().
		Int("devices", len(m.devices)).
		Dur("refresh_interval", m.refreshInterval).
		Msg("Service monitor started")
	return nil
}

// Stop ends the rebuild loop, detaches the tracer and clears every device's
// service targets. Safe to call more than once.
func (m *ServiceMonitor) Stop() {
	if !m.lifecycle.stop() {
		return
	}
	if err := m.source.Close(); err != nil {
		m.logger.Warn().Err(err).Msg("Closing the service tracer failed")
	}
	m.statsMu.Lock()
	m.active = false
	m.statsMu.Unlock()
	for _, d := range m.devices {
		d.Prober.UpdateServiceTargets(nil)
	}
	m.logger.Info().Msg("Service monitor stopped")
}

// handleEvent runs on the tracer's reader goroutine: it must stay cheap.
func (m *ServiceMonitor) handleEvent(ev servicetrace.Event) {
	if m.table.Apply(ev) {
		select {
		case m.changed <- struct{}{}:
		default:
		}
	}
}

// run rebuilds the targets after a debounced change signal, on every refresh
// interval, and, while some flows are unresolved, after every retry period.
func (m *ServiceMonitor) run(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.refreshInterval)
	defer ticker.Stop()

	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	pending := false

	retry := time.NewTimer(time.Hour)
	retry.Stop()
	armRetry := func(unresolved bool) {
		retry.Stop()
		if unresolved {
			retry.Reset(m.unresolvedRetry)
		}
	}

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-m.changed:
			if !pending {
				pending = true
				debounce.Reset(m.debounce)
			}
		case <-debounce.C:
			pending = false
			armRetry(m.rebuild(ctx, false))
		case <-retry.C:
			armRetry(m.rebuild(ctx, false))
		case <-ticker.C:
			armRetry(m.rebuild(ctx, true))
		}
	}
}

// processAlive reports whether pid still exists, by its /proc entry. The
// tracer reports pids of the initial pid namespace, the one the agent runs
// in as a host service.
func (m *ServiceMonitor) processAlive(pid uint32) bool {
	_, err := os.Stat(filepath.Join(m.procRoot, strconv.FormatUint(uint64(pid), 10)))
	return err == nil
}

// reconcile repairs what lost events may have left behind before a rebuild:
// it warns when the tracer dropped events since the last rebuild, and drops
// the contexts of processes that no longer exist, whose close event is the
// one a drop can lose for good (a lost create or destroy is bounded by the
// process's lifetime for the same reason).
func (m *ServiceMonitor) reconcile() {
	if dropped := m.source.Stats().RingBufferDropped; dropped > m.lastDropped {
		m.logger.Warn().
			Uint64("dropped_total", dropped).
			Uint64("dropped_since_last_rebuild", dropped-m.lastDropped).
			Msg("The service tracer dropped events (ring buffer full); connections of exited processes are reaped, " +
				"but a lost create or destroy stays uncorrected until its process exits")
		m.lastDropped = dropped
	}
	if removed, _ := m.table.ReapContexts(m.processAlive); removed > 0 {
		m.logger.Info().
			Int("contexts", removed).
			Msg("Dropped traced contexts whose process no longer exists (their close event was lost)")
	}
}

// loadDeviceNumbers (re)reads the uverbs device number table from sysfs.
func (m *ServiceMonitor) loadDeviceNumbers() {
	devs, err := servicetrace.UverbsDevices(m.sysfsRoot)
	if err != nil {
		m.logger.Warn().Err(err).Msg("Cannot list uverbs devices in sysfs; traced connections cannot be attributed to RDMA devices")
		return
	}
	m.devNumbers = devs
}

// deviceName resolves a uverbs device number, re-reading sysfs once per
// rebuild for numbers it has not seen. rescanned is the per-rebuild guard.
func (m *ServiceMonitor) deviceName(dev uint32, rescanned *bool) (string, bool) {
	if name, ok := m.devNumbers[dev]; ok {
		return name, true
	}
	if !*rescanned {
		*rescanned = true
		m.loadDeviceNumbers()
		if name, ok := m.devNumbers[dev]; ok {
			return name, true
		}
	}
	return "", false
}

// rebuild groups the live connections into flows per device, resolves their
// remote GIDs (all of them when resolveAll, else only the unknown ones) and
// pushes the resulting targets to each device's prober. It reports whether
// any flow is left unresolved, so the caller can schedule a retry.
func (m *ServiceMonitor) rebuild(ctx context.Context, resolveAll bool) (unresolvedLeft bool) {
	m.reconcile()
	conns := m.table.Connections()
	perDevice := make(map[string][]servicetrace.Connection)
	rescanned := false
	var other uint64
	for _, c := range conns {
		name, ok := m.deviceName(c.Dev, &rescanned)
		if !ok || m.devices[name] == nil {
			other++
			continue
		}
		perDevice[name] = append(perDevice[name], c)
	}

	for name, d := range m.devices {
		flows := make(map[serviceFlowKey]int)
		for _, c := range perDevice[name] {
			m.checkSourceGID(d, c)
			flows[serviceFlowKey{remoteGID: c.RemoteGID, flowLabel: c.EffectiveFlowLabel()}]++
		}
		targets, unresolved := m.resolveFlows(ctx, d, flows, resolveAll)
		d.Prober.UpdateServiceTargets(targets)
		if unresolved > 0 {
			unresolvedLeft = true
		}

		m.statsMu.Lock()
		d.connections = len(perDevice[name])
		d.flowsProbed = len(targets)
		d.flowsUnresolved = unresolved
		m.statsMu.Unlock()

		m.logger.Info().
			Str("device", name).
			Int("connections", len(perDevice[name])).
			Int("flows", len(flows)).
			Int("probed", len(targets)).
			Int("unresolved", unresolved).
			Bool("resolve_all", resolveAll).
			Msg("Rebuilt service tracing targets")
	}

	m.statsMu.Lock()
	m.otherDeviceConns = other
	m.statsMu.Unlock()
	if other > 0 {
		m.logger.Debug().
			Uint64("connections", other).
			Msg("Traced connections on RDMA devices the agent does not probe from; ignored")
	}
	return unresolvedLeft
}

// resolveFlows returns one SERVICE_TRACING target per flow whose remote GID
// the controller resolved, plus the number of flows left unresolved. The
// device's cache keeps earlier answers; GIDs with no answer, or with a
// negative answer older than serviceUnresolvedRetry, are asked again, and
// every GID is asked when resolveAll is set.
func (m *ServiceMonitor) resolveFlows(ctx context.Context, d *serviceDeviceState, flows map[serviceFlowKey]int, resolveAll bool) ([]*controller_agent.PingTarget, int) {
	now := m.nowFn()
	wanted := make(map[string]struct{}, len(flows))
	var ask []string
	for key := range flows {
		gid := probe.FormatGID(key.remoteGID)
		if _, seen := wanted[gid]; seen {
			continue
		}
		wanted[gid] = struct{}{}
		entry := d.cache[gid]
		switch {
		case resolveAll, entry == nil:
			ask = append(ask, gid)
		case entry.target == nil && now.Sub(entry.resolvedAt) >= m.unresolvedRetry:
			ask = append(ask, gid)
		}
	}
	for gid := range d.cache {
		if _, ok := wanted[gid]; !ok {
			delete(d.cache, gid)
		}
	}
	sort.Strings(ask)
	m.resolve(ctx, d, ask, now)

	targets := make([]*controller_agent.PingTarget, 0, len(flows))
	unresolved := 0
	for key := range flows {
		entry := d.cache[probe.FormatGID(key.remoteGID)]
		if entry == nil || entry.target == nil {
			unresolved++
			continue
		}
		t := proto.Clone(entry.target).(*controller_agent.PingTarget)
		// The flow's own label, and only it: the probe must take the flow's
		// path, not an ECMP sample.
		t.FlowLabel = key.flowLabel
		t.FlowLabelSeed = 0
		t.FlowLabelCount = 1
		t.PinglistType = controller_agent.PinglistType_SERVICE_TRACING
		t.Sampled = false
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].GetTargetGid() != targets[j].GetTargetGid() {
			return targets[i].GetTargetGid() < targets[j].GetTargetGid()
		}
		return targets[i].GetFlowLabel() < targets[j].GetFlowLabel()
	})
	return targets, unresolved
}

// resolve asks the controller for gids in batches and records every answer,
// including the absence of one, in the device's cache. A failed batch leaves
// its GIDs as they were, to be asked again on the next rebuild.
func (m *ServiceMonitor) resolve(ctx context.Context, d *serviceDeviceState, gids []string, now time.Time) {
	for len(gids) > 0 {
		n := min(len(gids), serviceResolveBatch)
		batch := gids[:n]
		gids = gids[n:]

		resolved, err := m.resolver.GetTargetRnicInfo(ctx, m.agentID, d.GID, batch)
		if err != nil {
			if status.Code(err) == codes.Unimplemented {
				m.warnUnimplemented(err)
				return
			}
			m.logger.Warn().Err(err).
				Str("device", d.Name).
				Int("gids", len(batch)).
				Msg("Resolving service tracing targets failed; keeping the previous targets")
			return
		}
		byGID := make(map[string]*controller_agent.PingTarget, len(resolved))
		for _, t := range resolved {
			if t != nil {
				byGID[t.GetTargetGid()] = t
			}
		}
		for _, gid := range batch {
			d.cache[gid] = &resolvedTarget{target: byGID[gid], resolvedAt: now}
		}
	}
}

// warnUnimplemented logs once that the controller predates service tracing.
func (m *ServiceMonitor) warnUnimplemented(err error) {
	m.statsMu.Lock()
	warned := m.unimplementedWarned
	m.unimplementedWarned = true
	m.statsMu.Unlock()
	if !warned {
		m.logger.Warn().Err(err).
			Msg("Controller does not implement GetTargetRnicInfo (it predates service tracing); traced flows cannot be probed. Upgrade the controller")
	}
}

// checkSourceGID warns once per device and GID index when a traced flow's
// source GID differs from the agent's probing GID on that device: the probe
// then shares the flow's destination and UDP source port but not its source
// address, so it may hash onto a different path.
func (m *ServiceMonitor) checkSourceGID(d *serviceDeviceState, c servicetrace.Connection) {
	if d.warnedSGID[c.SGIDIndex] {
		return
	}
	d.warnedSGID[c.SGIDIndex] = true
	if c.Port == d.Port && c.SGIDIndex == d.GIDIndex {
		return
	}
	gid, err := servicetrace.PortGID(m.sysfsRoot, d.Name, c.Port, c.SGIDIndex)
	if err != nil {
		m.logger.Debug().Err(err).
			Str("device", d.Name).
			Uint8("port", c.Port).
			Uint8("sgid_index", c.SGIDIndex).
			Msg("Cannot read the source GID of a traced flow")
		return
	}
	ip := probe.GIDToIPv4(gid)
	if ip == d.IPAddr {
		return
	}
	m.logger.Warn().
		Str("device", d.Name).
		Uint8("port", c.Port).
		Uint8("sgid_index", c.SGIDIndex).
		Str("flow_source_ip", ip).
		Uint8("probe_gid_index", d.GIDIndex).
		Str("probe_source_ip", d.IPAddr).
		Str("comm", c.Comm).
		Msg("Traced flows use a different source GID than the agent probes from; " +
			"probes share their destination and UDP source port but not their source address. " +
			"Set gid_index to the index the applications use")
}

// Stats returns the sample for the service tracing metrics.
func (m *ServiceMonitor) Stats() telemetry.ServiceTracingSample {
	counters := m.table.Counters()
	src := m.source.Stats()
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	s := telemetry.ServiceTracingSample{
		Active:            m.active,
		Creates:           counters.Creates,
		Connects:          counters.Connects,
		Resets:            counters.Resets,
		Destroys:          counters.Destroys,
		ContextCloses:     counters.ContextCloses,
		UnknownQPs:        counters.UnknownQPs,
		RingBufferDropped: src.RingBufferDropped,
		ParseErrors:       src.ParseErrors,
		DecodeErrors:      src.DecodeErrors,
	}
	names := make([]string, 0, len(m.devices))
	for name := range m.devices {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		d := m.devices[name]
		s.Devices = append(s.Devices, telemetry.ServiceTracingDevice{
			RdmaDevice:      name,
			Connections:     d.connections,
			FlowsProbed:     d.flowsProbed,
			FlowsUnresolved: d.flowsUnresolved,
		})
	}
	return s
}
