// Package agent implements the R-Pingmesh agent: it opens the host's RDMA
// devices and, on each of them, runs a Responder, a Prober and a
// ClusterMonitor, registers the RNICs with the controller and exports probe
// results as metrics and per-path analysis reports.
package agent

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/agent/controller_client"
	"github.com/yuuki/rpingmesh/internal/agent/servicetrace"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/lldp"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/internal/telemetry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

const (
	metricsShutdownTimeout = 5 * time.Second

	// heartbeatInterval is the period of the re-registration heartbeat. The
	// controller considers an agent dead once last_updated_epoch is older
	// than 300s, so this must be well under that.
	heartbeatInterval = 60 * time.Second

	// heartbeatFailureEscalationThreshold is the number of consecutive
	// heartbeat failures after which the log level escalates from Warn to
	// Error.
	heartbeatFailureEscalationThreshold = 3

	// Initial registration retries with exponential backoff.
	registerRetryInitialBackoff = 1 * time.Second
	registerRetryMaxBackoff     = 30 * time.Second
	registerRetryMaxAttempts    = 6
)

// rnic is one opened RDMA device together with everything the agent runs on
// it. Every RNIC of a multi-rail host probes actively and is registered with
// the controller, so each one gets its own prober, responder, event rings
// and cluster monitor.
type rnic struct {
	dev *rdmabridge.Device

	// torID is the device's canonical ToR: its device_tor_ids entry, else
	// its LLDP-discovered ToR, else the host-wide tor_id. Empty means
	// untagged.
	torID string
	// netdev is the netdev bound to the device's active port/GID ("" when
	// it cannot be resolved). It feeds LLDP discovery, the source_netdev
	// metric attribute and the registration.
	netdev string
	// planeID is the device's canonical plane (rail): its device_plane_ids
	// entry, else the host-wide plane_id. Empty means no plane restriction.
	planeID string

	proberRing *rdmabridge.EventRing
	respRing   *rdmabridge.EventRing
	prober     *Prober
	responder  *Responder
	monitor    *ClusterMonitor

	// watch identifies the device's uverbs node so its removal can be
	// detected; nil when the node could not be found (see device_watch.go).
	watch *watchedDevice
}

// Agent orchestrates all agent components and handles initialization,
// registration with the controller, and graceful shutdown.
type Agent struct {
	cfg        *config.AgentConfig
	rdmaCtx    *rdmabridge.Context
	rnics      []*rnic
	grpcClient *controller_client.GRPCControllerClient
	metrics    *telemetry.MetricsCollector
	logger     zerolog.Logger

	// results is the fan-in of every prober's Results() channel, consumed
	// by the metrics result consumer as one stream (see createResultsFanIn).
	results   chan *probe.ProbeResult
	resultsWg sync.WaitGroup

	// resultsDone is closed by stopResultsFanIn so every fan-in goroutine
	// stops forwarding at once, even one blocked on a full results channel
	// that nothing drains any more.
	resultsDone chan struct{}

	// analysisResults is the secondary branch of the fan-in feeding the
	// AnalysisReporter; nil when analysis reporting is disabled. The fan-in
	// tees onto it non-blockingly so a backed-up aggregator can never stall
	// the metrics path.
	analysisResults  chan *probe.ProbeResult
	analysisReporter *AnalysisReporter

	// watchdog throttles every prober under CPU/memory pressure; nil when
	// self-protection is disabled.
	watchdog *Watchdog

	// serviceMonitor turns traced application connections into service
	// tracing targets; nil when service tracing is disabled or its eBPF
	// tracer could not start (see createServiceTracing).
	serviceMonitor *ServiceMonitor

	// metricsResultsActive records whether a metrics consumer will drain
	// a.results. When false the fan-in never sends on it: a full channel
	// nobody drains would block the fan-in and starve the analysis tee.
	metricsResultsActive bool

	// agentIP is the host's outbound IP toward the controller, reported in
	// the registration. Best-effort: empty if undetermined.
	agentIP string

	// canonicalTorID is cfg.TorID after whitespace trim; empty means
	// untagged (registry storage key "").
	canonicalTorID string

	// lldpQuerier and sysfsRoot are the discovery dependencies; tests
	// replace them.
	lldpQuerier lldp.Querier
	sysfsRoot   string

	// perRnicTorLossWarned, planeSupportWarned and servicePathSummariesWarned
	// make the "controller lacks feature" errors log once, not every
	// heartbeat.
	perRnicTorLossWarned       bool
	planeSupportWarned         bool
	servicePathSummariesWarned bool

	// servicePathSummaries is set from the registration response when the
	// controller evaluates SERVICE_TRACING path summaries apart from the
	// cluster ones; until then the results fan-in keeps service results out
	// of the analysis branch. Atomic because the fan-in goroutines read it
	// while registration (and every heartbeat re-registration) writes it.
	servicePathSummaries atomic.Bool

	heartbeatStopCh chan struct{}
	heartbeatWg     sync.WaitGroup

	// deviceLost carries the first lost device to Run; deviceWatchPeriod
	// overrides deviceWatchInterval in tests.
	deviceLost        chan error
	deviceWatchStopCh chan struct{}
	deviceWatchWg     sync.WaitGroup
	deviceWatchPeriod time.Duration
}

// NewAgent creates an Agent; it is not started until Initialize and Start.
func NewAgent(cfg *config.AgentConfig) (*Agent, error) {
	if cfg == nil {
		return nil, fmt.Errorf("agent config must not be nil")
	}

	canonicalTorID := probe.CanonicalTorID(cfg.TorID)
	if probe.IsReservedTorID(canonicalTorID) {
		return nil, fmt.Errorf("tor_id %q is reserved for untagged agents", probe.UnspecifiedTorLabel)
	}

	a := &Agent{
		cfg:            cfg,
		canonicalTorID: canonicalTorID,
		logger:         log.With().Str("component", "agent").Logger(),
		lldpQuerier:    lldp.CLIQuerier{Path: cfg.LLDPCLIPath},
		sysfsRoot:      lldp.DefaultSysfsRoot,
		deviceLost:     make(chan error, 1),
	}

	// As early as possible, so a soft memory limit governs the whole
	// process lifetime.
	applyRuntimeLimits(cfg, a.logger)
	return a, nil
}

// Sources reported in the "Resolved device plane" / "Resolved device ToR"
// logs.
const (
	planeSourceDeviceMap = "device_plane_ids"
	planeSourceAgent     = "plane_id"

	torSourceDeviceMap = "device_tor_ids"
	torSourceLLDP      = "lldp"
	torSourceAgent     = "tor_id"
)

// applyRuntimeLimits applies the optional soft memory limit (GOMEMLIMIT) and
// GOMAXPROCS cap. Both are opt-in (0 leaves the Go default) and independent
// of self_protection_enabled; the memory limit is also the budget the
// watchdog throttles against.
func applyRuntimeLimits(cfg *config.AgentConfig, logger zerolog.Logger) {
	if cfg.MaxMemoryMB > 0 {
		limit := int64(cfg.MaxMemoryMB) * bytesPerMiB
		debug.SetMemoryLimit(limit)
		logger.Info().
			Int("max_memory_mb", cfg.MaxMemoryMB).
			Int64("gomemlimit_bytes", limit).
			Msg("Applied soft memory limit (GOMEMLIMIT)")
	}
	if cfg.MaxProcs > 0 {
		prev := runtime.GOMAXPROCS(cfg.MaxProcs)
		logger.Info().
			Int("max_procs", cfg.MaxProcs).
			Int("previous_gomaxprocs", prev).
			Msg("Capped GOMAXPROCS")
	}
}

// Initialize opens the RDMA devices and builds every component, registers
// with the controller and creates the cluster monitors. Stop releases
// whatever was allocated when it fails part-way.
func (a *Agent) Initialize(ctx context.Context) error {
	a.logger.Info().Msg("Initializing RDMA context")
	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize RDMA context: %w", err)
	}
	a.rdmaCtx = rdmaCtx

	a.logger.Info().Msg("Opening RDMA devices")
	if err := a.openDevices(); err != nil {
		return fmt.Errorf("failed to open RDMA devices: %w", err)
	}
	if len(a.rnics) == 0 {
		if len(a.cfg.ExcludedDeviceNames) > 0 || len(a.cfg.ExcludedGIDCIDRs) > 0 || a.cfg.MappedDevicesOnly {
			return fmt.Errorf("no RDMA devices available (excluded_device_names: %v, excluded_gid_cidrs: %v, mapped_devices_only: %v)",
				a.cfg.ExcludedDeviceNames, a.cfg.ExcludedGIDCIDRs, a.cfg.MappedDevicesOnly)
		}
		return fmt.Errorf("no RDMA devices available")
	}
	a.logger.Info().Int("device_count", len(a.rnics)).Msg("RDMA devices opened")
	a.resolveDeviceNetdevs()
	a.recordWatchedDevices()
	a.resolveDeviceTorIDs(a.discoverLLDPTorIDs(ctx))
	a.resolveDevicePlaneIDs()

	a.logger.Info().
		Str("controller_addr", a.cfg.ControllerAddr).
		Msg("Creating gRPC controller client")
	grpcClient, err := controller_client.NewGRPCControllerClient(a.cfg.ControllerAddr, &config.TLSClientConfig{
		Mode:       a.cfg.TLSMode,
		CertFile:   a.cfg.TLSCertFile,
		KeyFile:    a.cfg.TLSKeyFile,
		CAFile:     a.cfg.TLSCAFile,
		ServerName: a.cfg.TLSServerName,
	})
	if err != nil {
		return fmt.Errorf("failed to create gRPC controller client: %w", err)
	}
	a.grpcClient = grpcClient

	if err := a.createEventRings(); err != nil {
		return fmt.Errorf("failed to create event rings: %w", err)
	}
	if err := a.createProbers(); err != nil {
		return err
	}

	// The metrics collector must exist before the fan-in so the fan-in
	// knows whether a metrics consumer will drain a.results.
	a.createMetricsCollector(ctx)
	a.metricsResultsActive = a.metrics != nil
	a.createResultsFanIn()
	a.createAnalysisReporter()
	a.createWatchdog()
	a.createServiceTracing()

	if err := a.createResponders(); err != nil {
		return err
	}
	a.registerTimestampModeMetric()

	a.agentIP = outboundIP(a.cfg.ControllerAddr)
	if a.agentIP != "" {
		a.logger.Info().Str("agent_ip", a.agentIP).Msg("Determined agent outbound IP")
	} else {
		a.logger.Warn().
			Str("controller_addr", a.cfg.ControllerAddr).
			Msg("Could not determine agent outbound IP; registering without agent_ip")
	}

	a.logger.Info().Msg("Registering with controller")
	if err := a.registerWithController(ctx); err != nil {
		return fmt.Errorf("failed to register with controller: %w", err)
	}

	// After registration: applyRegistrationTorSupport may have changed the
	// ToRs the monitors capture.
	a.createClusterMonitors()

	a.logger.Info().Msg("Agent initialization complete")
	return nil
}

// deviceOpener opens one candidate RDMA device; desc names it in logs.
type deviceOpener struct {
	desc string
	open func() (*rdmabridge.Device, error)
}

// deviceOpeners lists the devices to open: the allowed_device_names by name
// when set, else every device by index. excluded_device_names are dropped
// here, before any verbs resources are allocated on them.
func (a *Agent) deviceOpeners(gidIndex int, sl, tc uint8) ([]deviceOpener, error) {
	var openers []deviceOpener
	if len(a.cfg.AllowedDeviceNames) > 0 {
		for _, name := range a.cfg.AllowedDeviceNames {
			// Config.Validate rejects overlaps; kept so an unvalidated
			// config still honours the exclusion.
			if a.cfg.IsDeviceExcluded(name) {
				a.logger.Info().Str("device_name", name).Msg("Skipping excluded RDMA device")
				continue
			}
			openers = append(openers, deviceOpener{desc: name, open: func() (*rdmabridge.Device, error) {
				return a.rdmaCtx.OpenDeviceByName(name, gidIndex, sl, tc)
			}})
		}
		return openers, nil
	}

	count := a.rdmaCtx.GetDeviceCount()
	if count == 0 {
		return nil, fmt.Errorf("no RDMA devices found on this host")
	}
	for i := 0; i < count; i++ {
		if len(a.cfg.ExcludedDeviceNames) > 0 {
			name, err := a.rdmaCtx.GetDeviceName(i)
			if err != nil {
				// Without a name the exclusion cannot be checked; skip rather
				// than risk opening an excluded device.
				a.logger.Warn().Err(err).Int("index", i).Msg("Failed to read RDMA device name, skipping")
				continue
			}
			if a.cfg.IsDeviceExcluded(name) {
				a.logger.Info().Str("device_name", name).Int("index", i).Msg("Skipping excluded RDMA device")
				continue
			}
		}
		openers = append(openers, deviceOpener{desc: fmt.Sprintf("index %d", i), open: func() (*rdmabridge.Device, error) {
			return a.rdmaCtx.OpenDevice(i, gidIndex, sl, tc)
		}})
	}
	return openers, nil
}

// openDevices opens the configured RDMA devices. A device that fails to open
// is skipped with a warning; one rejected by excluded_gid_cidrs or
// mapped_devices_only is closed right after opening (see admitDevice).
func (a *Agent) openDevices() error {
	// Config.Validate guarantees ServiceLevel in [0,7] and TrafficClass in
	// [0,255], so both narrow to uint8 without loss.
	sl := uint8(a.cfg.ServiceLevel)
	tc := uint8(a.cfg.TrafficClass)
	cqMode, err := rdmabridge.ParseCQPollMode(a.cfg.CQPollMode)
	if err != nil {
		return err
	}
	openers, err := a.deviceOpeners(a.cfg.GIDIndex, sl, tc)
	if err != nil {
		return err
	}
	for _, o := range openers {
		dev, err := o.open()
		if err != nil {
			a.logger.Warn().Err(err).Str("device", o.desc).Msg("Failed to open RDMA device, skipping")
			continue
		}
		if !a.admitDevice(dev) {
			continue
		}
		dev.CQPollMode = cqMode
		a.rnics = append(a.rnics, &rnic{dev: dev})
		a.logger.Info().
			Str("device_name", dev.Info.DeviceName).
			Str("gid", dev.Info.GID).
			Str("ip", dev.Info.IPAddr).
			Msg("Opened RDMA device")
	}
	return nil
}

// deviceSkipReason reports why an opened device must not be used, or "" to
// keep it. These filters need the device's GID, so unlike
// excluded_device_names they run after the device is opened.
func deviceSkipReason(cfg *config.AgentConfig, info rdmabridge.DeviceInfo) string {
	if cidr, ok := cfg.ExcludedGIDCIDR(info.IPAddr); ok {
		return "excluded_gid_cidrs:" + cidr
	}
	if cfg.MappedDevicesOnly {
		if _, ok := cfg.DeviceTorID(info.DeviceName); !ok {
			return "mapped_devices_only"
		}
	}
	return ""
}

// admitDevice applies deviceSkipReason to a freshly opened device, closing
// and logging a skipped one. A device missing from device_tor_ids is logged
// at Warn: in a mapped deployment it usually means a device was renamed or
// appeared unexpectedly (e.g. a bond's RDMA device registered before RoCE
// LAG formed).
func (a *Agent) admitDevice(dev *rdmabridge.Device) bool {
	reason := deviceSkipReason(a.cfg, dev.Info)
	if reason == "" {
		return true
	}
	netdev, _ := a.lookupNetdev(dev)
	event := a.logger.Info()
	msg := "Skipping RDMA device whose GID is in excluded_gid_cidrs"
	if reason == "mapped_devices_only" {
		event = a.logger.Warn()
		msg = "Skipping RDMA device without a device_tor_ids entry (mapped_devices_only); " +
			"check whether a device was renamed or registered unexpectedly"
	}
	event.
		Str("device_name", dev.Info.DeviceName).
		Str("netdev", netdev).
		Str("gid", dev.Info.GID).
		Str("ip", dev.Info.IPAddr).
		Str("reason", reason).
		Msg(msg)
	dev.Close()
	return false
}

// lookupNetdev resolves the netdev bound to dev's active port/GID from sysfs.
func (a *Agent) lookupNetdev(dev *rdmabridge.Device) (string, error) {
	return lldp.NetdevForRDMAPort(a.sysfsRoot, dev.Info.DeviceName, dev.Info.ActivePort, dev.Info.ActiveGIDIndex)
}

// resolveDeviceNetdevs resolves each device's netdev. Best-effort: a device
// without an unambiguous netdev (e.g. a bonded RNIC) keeps "" and its probe
// metrics carry the "unspecified" source_netdev label.
func (a *Agent) resolveDeviceNetdevs() {
	for _, r := range a.rnics {
		netdev, err := a.lookupNetdev(r.dev)
		if err != nil {
			a.logger.Warn().Err(err).
				Str("device", r.dev.Info.DeviceName).
				Msg("Cannot resolve the device's netdev; source_netdev metric label will be unspecified")
			continue
		}
		r.netdev = netdev
		a.logger.Info().
			Str("device", r.dev.Info.DeviceName).
			Str("netdev", netdev).
			Msg("Resolved device netdev")
	}
}

// discoverLLDPTorIDs returns, parallel to rnics, the ToR each device's LLDP
// neighbor names when lldp_tor_discovery is enabled (nil otherwise). Devices
// with a device_tor_ids entry are skipped, since that entry wins anyway.
// Failures are logged and leave the affected devices empty, so they fall
// back to tor_id; LLDP problems never stop the agent. Requires
// resolveDeviceNetdevs to have run.
func (a *Agent) discoverLLDPTorIDs(ctx context.Context) []string {
	if !a.cfg.LLDPTorDiscovery {
		return nil
	}
	field := a.cfg.LLDPTorIDField
	if field == "" {
		field = lldp.FieldSystemName
	}

	var targets []lldp.Device
	var targetIdx []int
	for i, r := range a.rnics {
		if _, ok := a.cfg.DeviceTorID(r.dev.Info.DeviceName); ok {
			continue
		}
		if r.netdev == "" {
			a.logger.Warn().
				Str("device", r.dev.Info.DeviceName).
				Msg("LLDP ToR discovery: cannot find the device's netdev; using tor_id")
		}
		targets = append(targets, lldp.Device{Name: r.dev.Info.DeviceName, Netdev: r.netdev})
		targetIdx = append(targetIdx, i)
	}
	if len(targets) == 0 {
		return nil
	}

	timeout := time.Duration(a.cfg.LLDPDiscoveryTimeoutSec) * time.Second
	a.logger.Info().
		Int("devices", len(targets)).
		Str("field", field).
		Dur("timeout", timeout).
		Msg("Discovering device ToRs from LLDP neighbors")
	results, err := lldp.Discover(ctx, a.lldpQuerier, targets, lldp.DiscoverOptions{Field: field, Timeout: timeout})
	if err != nil {
		a.logger.Warn().Err(err).
			Msg("LLDP ToR discovery failed (is lldpd running and its socket accessible?); using tor_id")
	}

	tors := make([]string, len(a.rnics))
	for k, r := range results {
		tor := probe.CanonicalTorID(r.TorID)
		ev := a.logger.Info()
		if tor == "" || probe.IsReservedTorID(tor) {
			ev = a.logger.Warn()
		}
		ev = ev.Str("device", r.Device.Name).
			Str("netdev", r.Device.Netdev).
			Str("neighbor_system_name", r.Neighbor.SystemName).
			Str("neighbor_chassis_id", r.Neighbor.ChassisID).
			Str("neighbor_port_id", r.Neighbor.PortID)
		switch {
		case r.Device.Netdev == "":
			continue // already warned above
		case tor == "":
			ev.Msg("LLDP ToR discovery: no neighbor " + field + " on the device's netdev; using tor_id")
		case probe.IsReservedTorID(tor):
			ev.Msg("LLDP ToR discovery: neighbor " + field + " is the reserved untagged label; using tor_id")
		default:
			ev.Msg("LLDP ToR discovery: found neighbor")
			tors[targetIdx[k]] = tor
		}
	}
	return tors
}

// unmatchedKeys returns the keys of m that match no opened device name.
func (a *Agent) unmatchedKeys(m map[string]string) []string {
	var unmatched []string
	for key := range m {
		found := false
		for _, r := range a.rnics {
			if strings.EqualFold(strings.TrimSpace(key), r.dev.Info.DeviceName) {
				found = true
				break
			}
		}
		if !found {
			unmatched = append(unmatched, key)
		}
	}
	return unmatched
}

// resolveDeviceTorIDs assigns each device its ToR: its device_tor_ids entry,
// then lldpTors[i] (may be nil), then the host-wide tor_id. device_tor_ids
// keys matching no opened device are warned about, since a typo there
// silently leaves that RNIC under the host-wide ToR.
func (a *Agent) resolveDeviceTorIDs(lldpTors []string) {
	untagged := 0
	for i, r := range a.rnics {
		tor, source := a.canonicalTorID, torSourceAgent
		if t, ok := a.cfg.DeviceTorID(r.dev.Info.DeviceName); ok {
			tor, source = t, torSourceDeviceMap
		} else if i < len(lldpTors) && lldpTors[i] != "" {
			tor, source = lldpTors[i], torSourceLLDP
		}
		r.torID = tor
		if tor == "" {
			untagged++
		}
		a.logger.Info().
			Str("device", r.dev.Info.DeviceName).
			Str("tor_id", tor).
			Str("source", source).
			Msg("Resolved device ToR")
		if source == torSourceAgent && len(a.cfg.DeviceTorIDs) > 0 {
			// In a mapped deployment an unmapped device is usually one that
			// was renamed or registered unexpectedly, and tor_id is often a
			// placeholder, so its probes would be attributed to the wrong ToR.
			a.logger.Warn().
				Str("device", r.dev.Info.DeviceName).
				Str("netdev", r.netdev).
				Str("gid", r.dev.Info.GID).
				Str("tor_id", tor).
				Msg("Device has no device_tor_ids entry and falls back to tor_id; " +
					"check whether it was renamed, or set mapped_devices_only to skip it")
		}
	}
	for _, key := range a.unmatchedKeys(a.cfg.DeviceTorIDs) {
		a.logger.Warn().
			Str("device", key).
			Msg("device_tor_ids entry matches no opened RDMA device; ignored")
	}
	if untagged > 0 {
		a.logger.Warn().
			Int("untagged_devices", untagged).
			Str("otel_tor_label", probe.UnspecifiedTorLabel).
			Msg("Some devices have no ToR; they register under an empty ToR whose ToR-mesh includes other untagged RNICs")
	}
}

// resolveDevicePlaneIDs assigns each device its plane (rail): its
// device_plane_ids entry, else the host-wide plane_id (empty = none).
// device_plane_ids keys matching no opened device are warned about, with the
// reason when the device is excluded or not allowed.
func (a *Agent) resolveDevicePlaneIDs() {
	configured := probe.CanonicalPlaneID(a.cfg.PlaneID) != "" || len(a.cfg.DevicePlaneIDs) > 0
	for _, r := range a.rnics {
		r.planeID = a.cfg.PlaneIDForDevice(r.dev.Info.DeviceName)
		source := planeSourceAgent
		if _, ok := a.cfg.DevicePlaneID(r.dev.Info.DeviceName); ok {
			source = planeSourceDeviceMap
		}
		if configured {
			a.logger.Info().
				Str("device", r.dev.Info.DeviceName).
				Str("plane_id", r.planeID).
				Str("source", source).
				Msg("Resolved device plane")
		}
	}
	for _, key := range a.unmatchedKeys(a.cfg.DevicePlaneIDs) {
		reason := "device_plane_ids entry matches no opened RDMA device; ignored"
		switch {
		case a.cfg.IsDeviceExcluded(key):
			reason = "device_plane_ids entry names a device in excluded_device_names; ignored"
		case !a.cfg.IsDeviceAllowed(key):
			reason = "device_plane_ids entry names a device not in allowed_device_names; ignored"
		}
		a.logger.Warn().Str("device", key).Msg(reason)
	}
	if configured {
		for _, r := range a.rnics {
			if r.planeID == "" {
				a.logger.Warn().
					Str("device", r.dev.Info.DeviceName).
					Msg("Device has no plane while others do; its pinglists are not plane-restricted")
			}
		}
	}
}

// usesPlanes reports whether any device has a plane, i.e. whether pinglists
// depend on the controller supporting plane_id.
func (a *Agent) usesPlanes() bool {
	for _, r := range a.rnics {
		if r.planeID != "" {
			return true
		}
	}
	return false
}

// checkRegistrationPlaneSupport warns (once) when devices have planes but the
// controller predates plane support. Nothing needs to fall back: an older
// controller ignores plane_id, but its pinglists may include cross-plane
// targets, which time out on fabrics whose rails are not routed to each other.
func (a *Agent) checkRegistrationPlaneSupport(resp *controller_agent.AgentRegistrationResponse) {
	if resp.GetPerRnicPlaneId() || !a.usesPlanes() || a.planeSupportWarned {
		return
	}
	a.planeSupportWarned = true
	a.logger.Warn().
		Msg("Controller does not support plane_id (it predates planes); pinglists are not " +
			"restricted to each device's plane, so cross-plane targets may time out. Upgrade the controller")
}

// applyRegistrationServiceAnalysisSupport records whether the controller
// evaluates service path summaries apart from the cluster ones, which gates
// the service branch of the analysis tee (see createResultsFanIn). It warns
// once when service tracing and analysis reporting are both on but the
// controller predates the support: service results then stay out of the
// analysis reports rather than being judged as cluster paths. Runs on the
// initial registration and on every heartbeat re-registration, so a
// controller upgrade (or downgrade) takes effect without an agent restart.
func (a *Agent) applyRegistrationServiceAnalysisSupport(resp *controller_agent.AgentRegistrationResponse) {
	supported := resp.GetServicePathSummaries()
	a.servicePathSummaries.Store(supported)
	if supported || !a.cfg.ServiceTracingEnabled || !a.cfg.AnalysisReportEnabled || a.servicePathSummariesWarned {
		return
	}
	a.servicePathSummariesWarned = true
	a.logger.Warn().
		Msg("Controller does not evaluate service-tracing path summaries (it predates them); " +
			"service results are reported to the agent's rpingmesh.service.* metrics only, " +
			"not to the analyzer. Upgrade the controller")
}

// usesPerDeviceTorIDs reports whether any device's ToR differs from the
// host-wide tor_id.
func (a *Agent) usesPerDeviceTorIDs() bool {
	for _, r := range a.rnics {
		if r.torID != a.canonicalTorID {
			return true
		}
	}
	return false
}

// applyRegistrationTorSupport falls back to the host-wide tor_id for every
// device when the controller did not keep per-RNIC ToRs (an older controller
// overwrites them with the request-wide value and still reports success).
// Without the fallback each device would request pinglists for a ToR under
// which no RNIC is registered and get an empty ToR-mesh. It must run before
// the cluster monitors are created, since they capture the ToR.
func (a *Agent) applyRegistrationTorSupport(resp *controller_agent.AgentRegistrationResponse) {
	if resp.GetPerRnicTorId() || !a.usesPerDeviceTorIDs() {
		return
	}
	a.logger.Error().
		Str("tor_id", a.canonicalTorID).
		Msg("Controller does not support per-RNIC ToR IDs (it predates them); " +
			"every device falls back to tor_id. Upgrade the controller, then restart the agent")
	for _, r := range a.rnics {
		r.torID = a.canonicalTorID
		if r.prober != nil {
			r.prober.SetSourceTorID(a.canonicalTorID)
		}
	}
}

// createEventRings creates one prober ring and one responder ring per
// device: lock-free SPSC buffers delivering CQ completion events from the
// Zig poller thread to Go.
func (a *Agent) createEventRings() error {
	capacity := a.cfg.EffectiveEventRingCapacity()
	for _, r := range a.rnics {
		var err error
		if r.proberRing, err = rdmabridge.NewEventRing(capacity); err != nil {
			return fmt.Errorf("failed to create prober event ring for device %s: %w", r.dev.Info.DeviceName, err)
		}
		if r.respRing, err = rdmabridge.NewEventRing(capacity); err != nil {
			return fmt.Errorf("failed to create responder event ring for device %s: %w", r.dev.Info.DeviceName, err)
		}
	}
	a.logger.Info().
		Int("devices", len(a.rnics)).
		Int("capacity", capacity).
		Msg("Event rings created")
	return nil
}

// createProbers creates one prober per device with the configured per-type
// rate caps and flow-label rotation period.
func (a *Agent) createProbers() error {
	torMeshRate := a.cfg.EffectiveTorMeshProbeRate()
	interTorRate := a.cfg.EffectiveInterTorProbeRate()
	for _, r := range a.rnics {
		prober, err := NewProber(r.dev, r.proberRing, a.cfg.ProbeIntervalMS)
		if err != nil {
			return fmt.Errorf("failed to create prober for device %s: %w", r.dev.Info.DeviceName, err)
		}
		prober.SetSourceTorID(r.torID)
		prober.SetSourceNetdev(r.netdev)
		if torMeshRate > 0 || interTorRate > 0 {
			// The cap is per TARGET, not per flow label: a target's ECMP
			// label set shares this budget, bounding probe amplification.
			prober.SetPerTypeRateLimit(float64(torMeshRate), float64(interTorRate))
		}
		prober.SetFlowLabelRotationPeriod(a.cfg.FlowLabelRotationPeriodSec)
		r.prober = prober
		a.logger.Info().
			Str("device", r.dev.Info.DeviceName).
			Uint32("qpn", prober.GetQueueInfo().QPN).
			Msg("Prober created")
	}
	return nil
}

// createResponders creates one responder per device.
func (a *Agent) createResponders() error {
	for _, r := range a.rnics {
		resp, err := NewResponder(r.dev, r.respRing)
		if err != nil {
			return fmt.Errorf("failed to create responder for device %s: %w", r.dev.Info.DeviceName, err)
		}
		r.responder = resp
		a.logger.Info().
			Str("device", r.dev.Info.DeviceName).
			Uint32("qpn", resp.GetQueueInfo().QPN).
			Msg("Responder created")
	}
	return nil
}

// createAnalysisReporter creates the per-path window aggregation and SLA
// reporting to the controller, if enabled. It consumes the analysis branch
// created by createResultsFanIn.
func (a *Agent) createAnalysisReporter() {
	if !a.cfg.AnalysisReportEnabled {
		return
	}
	a.analysisReporter = NewAnalysisReporter(
		a.grpcClient,
		a.cfg.AgentID,
		probe.TorMetricLabel(a.canonicalTorID),
		a.cfg.AnalysisWindowSec,
		a.analysisResults,
	)
	// Service summaries go out only while the controller evaluates them
	// apart from the cluster paths (set by registration, see
	// applyRegistrationServiceAnalysisSupport); checked at send time so a
	// downgrade seen at a heartbeat also stops summaries already aggregated.
	a.analysisReporter.SetServiceSummariesAllowed(a.servicePathSummaries.Load)
	a.logger.Info().
		Uint32("window_sec", a.cfg.AnalysisWindowSec).
		Msg("Analysis reporter created")
}

// createWatchdog creates the self-protection watchdog, if enabled. It is
// created after the probers (which it throttles) and the metrics collector
// (whose self_throttle gauge reads its multiplier).
func (a *Agent) createWatchdog() {
	if !a.cfg.SelfProtectionEnabled {
		return
	}
	throttlers := make([]rateThrottler, 0, len(a.rnics))
	for _, r := range a.rnics {
		throttlers = append(throttlers, r.prober)
	}
	a.watchdog = NewWatchdog(a.cfg, throttlers)
	if a.metrics != nil {
		if err := a.metrics.RegisterSelfThrottleCallback(a.watchdog.CurrentMultiplier); err != nil {
			a.logger.Warn().Err(err).Msg("Failed to register self-throttle metric callback")
		}
	}
	a.logger.Info().
		Int("prober_count", len(throttlers)).
		Msg("Self-protection watchdog created")
}

// createServiceTracing starts the eBPF tracer and creates the service
// monitor that turns traced application connections into SERVICE_TRACING
// targets for every prober, if service tracing is enabled. A tracer that
// cannot start (no eBPF on this platform, no kernel BTF, missing CAP_BPF /
// CAP_PERFMON, ib_uverbs not loaded) is logged and the agent continues
// without service tracing, the way it continues without metrics. Requires
// the probers, the gRPC client and the metrics collector.
func (a *Agent) createServiceTracing() {
	if !a.cfg.ServiceTracingEnabled {
		return
	}
	tracer, err := servicetrace.Open()
	if err != nil {
		a.logger.Warn().Err(err).
			Msg("Service tracing is enabled but the eBPF tracer could not start; continuing without it")
		// Still export service_trace_active = 0, so the degradation is visible.
		a.registerServiceTracingMetrics(func() telemetry.ServiceTracingSample { return telemetry.ServiceTracingSample{} })
		return
	}

	devices := make([]ServiceDevice, 0, len(a.rnics))
	for _, r := range a.rnics {
		r.prober.SetServiceTracingRate(float64(a.cfg.ServiceTracingProbeRatePerSecond), a.cfg.ServiceTracingProbeIntervalMS)
		devices = append(devices, ServiceDevice{
			Name:     r.dev.Info.DeviceName,
			GID:      r.dev.Info.GID,
			IPAddr:   r.dev.Info.IPAddr,
			Port:     r.dev.Info.ActivePort,
			GIDIndex: r.dev.Info.ActiveGIDIndex,
			Prober:   r.prober,
		})
	}
	a.serviceMonitor = NewServiceMonitor(a.grpcClient, tracer, a.cfg.AgentID, devices, a.cfg.PinglistUpdateIntervalSec)
	a.registerServiceTracingMetrics(a.serviceMonitor.Stats)
	a.logger.Info().
		Int("devices", len(devices)).
		Int("probe_rate_per_second", a.cfg.ServiceTracingProbeRatePerSecond).
		Uint32("probe_interval_ms", a.cfg.ServiceTracingProbeIntervalMS).
		Msg("Service tracing started: eBPF tracer attached to the uverbs entry points")
}

// registerServiceTracingMetrics wires the service tracing gauges to read,
// when metrics are enabled.
func (a *Agent) registerServiceTracingMetrics(read func() telemetry.ServiceTracingSample) {
	if a.metrics == nil {
		return
	}
	if err := a.metrics.RegisterServiceTracingCallback(read); err != nil {
		a.logger.Warn().Err(err).Msg("Failed to register service tracing metric callback")
	}
}

// createClusterMonitors creates one ClusterMonitor per device, each
// requesting its pinglist with that device's own GID as requester_gid and
// feeding the targets to that device's prober. Requires the probers.
func (a *Agent) createClusterMonitors() {
	a.logger.Info().Int("device_count", len(a.rnics)).Msg("Creating cluster monitors")
	for _, r := range a.rnics {
		a.logger.Info().
			Str("device", r.dev.Info.DeviceName).
			Str("requester_gid", r.dev.Info.GID).
			Str("tor_id", r.torID).
			Str("plane_id", r.planeID).
			Uint32("update_interval_sec", a.cfg.PinglistUpdateIntervalSec).
			Msg("Creating cluster monitor")
		r.monitor = NewClusterMonitor(a.grpcClient, r.prober, a.cfg.AgentID, r.torID, r.dev.Info.GID, a.cfg.PinglistUpdateIntervalSec)
		r.monitor.SetPlaneID(r.planeID)
	}
}

// buildRegistrationRequest builds the registration request from the agent's
// configuration and RNIC state. Used for the initial registration and for
// the heartbeats.
func (a *Agent) buildRegistrationRequest() *controller_agent.AgentRegistrationRequest {
	rnics := make([]*controller_agent.RnicInfo, 0, len(a.rnics))
	for _, r := range a.rnics {
		info := &controller_agent.RnicInfo{
			Gid:        r.dev.Info.GID,
			Qpn:        r.responder.GetQueueInfo().QPN,
			IpAddress:  r.dev.Info.IPAddr,
			HostName:   a.cfg.HostName,
			TorId:      r.torID,
			DeviceName: r.dev.Info.DeviceName,
			PlaneId:    r.planeID,
			Netdev:     r.netdev,
		}
		rnics = append(rnics, info)
		a.logger.Debug().
			Str("gid", info.Gid).
			Uint32("qpn", info.Qpn).
			Str("ip", info.IpAddress).
			Str("device", info.DeviceName).
			Str("tor_id", info.TorId).
			Str("plane_id", info.PlaneId).
			Msg("Prepared RNIC info for registration")
	}
	return &controller_agent.AgentRegistrationRequest{
		AgentId:  a.cfg.AgentID,
		AgentIp:  a.agentIP,
		Hostname: a.cfg.HostName,
		TorId:    a.canonicalTorID,
		Rnics:    rnics,
	}
}

// outboundIP returns the local source IP the kernel would use to reach
// controllerAddr: dialing a UDP address performs a route lookup and binds a
// local address but sends nothing. Best-effort; "" on any error (e.g. an
// addr with no host such as ":50051").
func outboundIP(controllerAddr string) string {
	conn, err := net.Dial("udp", controllerAddr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP != nil && !udpAddr.IP.IsUnspecified() {
		return udpAddr.IP.String()
	}
	return ""
}

// registerAttemptErr describes why one registration attempt failed. The
// controller may signal failure through a gRPC error or a false Success with
// a Message, so both are checked.
func registerAttemptErr(resp *controller_agent.AgentRegistrationResponse, err error) error {
	if err != nil {
		return fmt.Errorf("RegisterAgent failed: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("agent registration rejected by controller: %s", resp.GetMessage())
	}
	return nil
}

// registerWithController registers the agent, retrying with exponential
// backoff; it errors only when every attempt fails.
func (a *Agent) registerWithController(ctx context.Context) error {
	req := a.buildRegistrationRequest()
	backoff := registerRetryInitialBackoff
	var lastErr error

	for attempt := 1; attempt <= registerRetryMaxAttempts; attempt++ {
		resp, err := a.grpcClient.RegisterAgent(ctx, req)
		lastErr = registerAttemptErr(resp, err)
		if lastErr == nil {
			a.applyRegistrationTorSupport(resp)
			a.checkRegistrationPlaneSupport(resp)
			a.applyRegistrationServiceAnalysisSupport(resp)
			a.logger.Info().
				Str("agent_id", a.cfg.AgentID).
				Int("rnic_count", len(req.GetRnics())).
				Str("message", resp.GetMessage()).
				Msg("Agent registered with controller")
			return nil
		}
		if attempt == registerRetryMaxAttempts {
			break
		}
		a.logger.Warn().Err(lastErr).
			Int("attempt", attempt).
			Int("max_attempts", registerRetryMaxAttempts).
			Dur("backoff", backoff).
			Msg("Agent registration attempt failed, retrying")
		select {
		case <-ctx.Done():
			return fmt.Errorf("registration cancelled: %w", ctx.Err())
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, registerRetryMaxBackoff)
	}
	return fmt.Errorf("agent registration failed after %d attempts: %w", registerRetryMaxAttempts, lastErr)
}

// Start starts every component; Initialize must have succeeded.
func (a *Agent) Start(ctx context.Context) error {
	for _, r := range a.rnics {
		if err := r.responder.Start(ctx); err != nil {
			return fmt.Errorf("failed to start responder for %s: %w", r.dev.Info.DeviceName, err)
		}
	}
	for _, r := range a.rnics {
		if err := r.prober.Start(ctx); err != nil {
			return fmt.Errorf("failed to start prober for %s: %w", r.dev.Info.DeviceName, err)
		}
	}
	for _, r := range a.rnics {
		if err := r.monitor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start cluster monitor for %s: %w", r.dev.Info.DeviceName, err)
		}
	}
	if a.serviceMonitor != nil {
		if err := a.serviceMonitor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start service monitor: %w", err)
		}
	}

	a.startHeartbeat(ctx)

	// A device the kernel removes (RoCE LAG change, NIC reset, driver
	// reload) stops the agent instead of leaving it probing through a dead
	// context.
	a.startDeviceWatch(ctx)

	if a.metrics != nil {
		a.metrics.StartResultConsumer(ctx, a.results, probe.TorMetricLabel(a.canonicalTorID))
		a.logger.Info().Msg("Metrics result consumer started")
	}
	if a.analysisReporter != nil {
		a.analysisReporter.Start(ctx)
	}
	if a.watchdog != nil {
		a.watchdog.Start(ctx)
	}

	a.logger.Info().Msg("Agent started")
	return nil
}

// Stop shuts every component down in reverse order of startup. Every step is
// nil-guarded, so it is safe after a partial Initialize.
func (a *Agent) Stop(ctx context.Context) {
	a.logger.Info().Msg("Stopping agent")

	a.stopDeviceWatch()

	// Monitors first so no new pinglists or service targets arrive; the
	// heartbeat before the gRPC client closes, since both use it.
	for _, r := range a.rnics {
		if r.monitor != nil {
			r.monitor.Stop()
		}
	}
	if a.serviceMonitor != nil {
		a.serviceMonitor.Stop()
	}
	a.stopHeartbeat()

	// The watchdog before the probers, since it calls SetRateMultiplier on
	// them.
	if a.watchdog != nil {
		a.watchdog.Stop()
	}

	// Destroy closes each prober's Results() channel, letting the fan-in
	// goroutines finish once they drained any buffered values.
	for _, r := range a.rnics {
		if r.prober != nil {
			r.prober.Destroy()
		}
	}

	// Wind the fan-in down here, deterministically, so shutdown never leaves
	// a fan-in goroutine blocked on a full a.results that nothing drains.
	a.stopResultsFanIn()

	// The reporter drains the now-closed analysis branch and ships its final
	// window over the gRPC client, so it must finish before the client closes.
	if a.analysisReporter != nil {
		a.analysisReporter.Wait()
	}

	for _, r := range a.rnics {
		if r.responder != nil {
			r.responder.Destroy()
		}
	}

	if a.metrics != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, metricsShutdownTimeout)
		defer cancel()
		if err := a.metrics.Shutdown(shutdownCtx); err != nil {
			a.logger.Error().Err(err).Msg("Failed to shutdown metrics collector")
		}
	}

	if a.grpcClient != nil {
		if err := a.grpcClient.Close(); err != nil {
			a.logger.Error().Err(err).Msg("Failed to close gRPC controller client")
		}
	}

	for _, r := range a.rnics {
		if r.dev != nil {
			r.dev.Close()
		}
	}
	if a.rdmaCtx != nil {
		a.rdmaCtx.Destroy()
		a.rdmaCtx = nil
	}
	for _, r := range a.rnics {
		if r.proberRing != nil {
			r.proberRing.Destroy()
		}
		if r.respRing != nil {
			r.respRing.Destroy()
		}
	}
	a.rnics = nil

	a.logger.Info().Msg("Agent stopped")
}

// startHeartbeat launches the goroutine that periodically re-sends the
// registration. This refreshes the controller's last_updated_epoch, without
// which the registry considers the agent dead ~5 minutes after startup and
// drops it from pinglists.
func (a *Agent) startHeartbeat(ctx context.Context) {
	a.heartbeatStopCh = make(chan struct{})
	a.heartbeatWg.Add(1)
	go a.heartbeatLoop(ctx)
}

// stopHeartbeat stops the heartbeat goroutine; no-op if never started.
func (a *Agent) stopHeartbeat() {
	if a.heartbeatStopCh == nil {
		return
	}
	close(a.heartbeatStopCh)
	a.heartbeatWg.Wait()
}

// heartbeatLoop re-registers every heartbeatInterval. Failures are logged
// but never terminate the process: a transient controller outage should not
// bring down a healthy agent, and the next tick retries.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	defer a.heartbeatWg.Done()

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	consecutiveFailures := 0
	for {
		select {
		case <-a.heartbeatStopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		resp, err := a.grpcClient.RegisterAgent(ctx, a.buildRegistrationRequest())
		if attemptErr := registerAttemptErr(resp, err); attemptErr != nil {
			consecutiveFailures++
			event := a.logger.Warn()
			if consecutiveFailures >= heartbeatFailureEscalationThreshold {
				event = a.logger.Error()
			}
			event.Err(attemptErr).
				Int("consecutive_failures", consecutiveFailures).
				Msg("Heartbeat re-registration failed, agent continues running")
			continue
		}
		consecutiveFailures = 0
		if !resp.GetPerRnicTorId() && a.usesPerDeviceTorIDs() && !a.perRnicTorLossWarned {
			// The controller was replaced by an older one while running. The
			// monitors keep their per-device ToRs, so ToR-meshes go empty
			// until the agent restarts (and falls back to tor_id).
			a.perRnicTorLossWarned = true
			a.logger.Error().
				Msg("Controller no longer supports per-RNIC ToR IDs; ToR-mesh pinglists will be empty. Restart the agent or upgrade the controller")
		}
		a.checkRegistrationPlaneSupport(resp)
		a.applyRegistrationServiceAnalysisSupport(resp)
		a.logger.Debug().
			Str("agent_id", a.cfg.AgentID).
			Msg("Heartbeat re-registration succeeded")
	}
}

// Run initializes and starts the agent, blocks until ctx is cancelled or an
// opened device disappears, then stops it. Stop also runs after a failed
// Initialize or Start so partially allocated resources are released.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Initialize(ctx); err != nil {
		a.Stop(ctx)
		return fmt.Errorf("agent initialization failed: %w", err)
	}
	if err := a.Start(ctx); err != nil {
		a.Stop(ctx)
		return fmt.Errorf("agent start failed: %w", err)
	}

	select {
	case <-ctx.Done():
	case err := <-a.deviceLost:
		return a.stopAfterDeviceLoss(err)
	}
	a.logger.Info().Msg("Context cancelled, initiating shutdown")

	// The parent context is cancelled, so shut down on a fresh one.
	a.Stop(context.Background())
	return nil
}

// stopAfterDeviceLoss stops the agent after an opened device disappeared and
// returns an error, so the process exits non-zero and systemd
// (Restart=on-failure) restarts it against the current devices. The stop is
// bounded by deviceLostStopTimeout so a teardown stuck on the removed device
// cannot keep the process alive.
func (a *Agent) stopAfterDeviceLoss(lost error) error {
	a.logger.Error().Err(lost).Msg("RDMA device lost, shutting down")
	done := make(chan struct{})
	go func() {
		a.Stop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(deviceLostStopTimeout):
		a.logger.Error().
			Dur("timeout", deviceLostStopTimeout).
			Msg("Shutdown after device loss timed out; exiting anyway")
	}
	return fmt.Errorf("RDMA device lost: %w", lost)
}

// createMetricsCollector creates the OTel MetricsCollector when metrics are
// enabled, leaving a.metrics nil (and logging) when disabled or on failure.
func (a *Agent) createMetricsCollector(ctx context.Context) {
	if !a.cfg.MetricsEnabled {
		a.logger.Info().Msg("Metrics collection is disabled")
		return
	}

	a.logger.Info().
		Str("collector_addr", a.cfg.OtelCollectorAddr).
		Msg("Creating metrics collector")
	mc, err := telemetry.NewMetricsCollector(ctx, a.cfg.OtelCollectorAddr,
		telemetry.WithTargetRnicLabels(targetRnicLabels(a.cfg)),
		telemetry.WithCardinalityLimit(a.cfg.MetricsCardinalityLimit),
		telemetry.WithProberDelayTargetTor(a.cfg.MetricsProberDelayTargetTor),
		telemetry.WithResponderDelayTargetTor(a.cfg.MetricsResponderDelayTargetTor),
		telemetry.WithServiceTracing(a.cfg.ServiceTracingEnabled))
	if err != nil {
		a.logger.Warn().Err(err).
			Msg("Failed to create metrics collector, continuing without metrics")
		return
	}
	a.metrics = mc

	// Ring drops and occupancy are aggregated across every device's rings
	// under one "prober"/"responder" label to keep cardinality low. A growing
	// drop count means the Go consumer is not draining the ring fast enough.
	if err := a.metrics.RegisterEventRingDropCallback(map[string]func() uint64{
		"prober":    func() uint64 { return ringDropCount(a.proberRings()) },
		"responder": func() uint64 { return ringDropCount(a.responderRings()) },
	}); err != nil {
		a.logger.Warn().Err(err).Msg("Failed to register event ring drop count callback")
	}
	if err := a.metrics.RegisterEventRingOccupancyCallback(map[string]func() telemetry.EventRingOccupancy{
		"prober":    func() telemetry.EventRingOccupancy { return takeRingOccupancy(a.proberRings()) },
		"responder": func() telemetry.EventRingOccupancy { return takeRingOccupancy(a.responderRings()) },
	}); err != nil {
		a.logger.Warn().Err(err).Msg("Failed to register event ring occupancy callback")
	}
}

func (a *Agent) proberRings() []*rdmabridge.EventRing {
	rings := make([]*rdmabridge.EventRing, 0, len(a.rnics))
	for _, r := range a.rnics {
		if r.proberRing != nil {
			rings = append(rings, r.proberRing)
		}
	}
	return rings
}

func (a *Agent) responderRings() []*rdmabridge.EventRing {
	rings := make([]*rdmabridge.EventRing, 0, len(a.rnics))
	for _, r := range a.rnics {
		if r.respRing != nil {
			rings = append(rings, r.respRing)
		}
	}
	return rings
}

// ringDropCount sums the drop counters of rings.
func ringDropCount(rings []*rdmabridge.EventRing) uint64 {
	var total uint64
	for _, ring := range rings {
		total += ring.DropCount()
	}
	return total
}

// takeRingOccupancy samples rings for rpingmesh.event_ring_occupancy_max:
// the highest occupancy of any ring since the previous sample (resetting
// each ring's mark) and the capacity. The fullest ring is the one that
// matters.
func takeRingOccupancy(rings []*rdmabridge.EventRing) telemetry.EventRingOccupancy {
	var sample telemetry.EventRingOccupancy
	for _, ring := range rings {
		sample.Max = max(sample.Max, ring.TakeMaxOccupancy())
		sample.Capacity = max(sample.Capacity, ring.Capacity())
	}
	return sample
}

// registerTimestampModeMetric warns about every queue that uses software
// timestamps and, with metrics enabled, reports each queue's timestamp
// source on rpingmesh.agent.hw_timestamps. The modes are captured once here
// (they are fixed at queue creation), so the callback never touches the
// queues, which Stop destroys before the final metrics flush.
func (a *Agent) registerTimestampModeMetric() {
	modes := make([]telemetry.QueueTimestampMode, 0, 2*len(a.rnics))
	for _, r := range a.rnics {
		modes = append(modes,
			telemetry.QueueTimestampMode{RdmaDevice: r.dev.Info.DeviceName, Queue: "prober", HWTimestamps: !r.prober.GetQueueInfo().UsesSWTimestamps},
			telemetry.QueueTimestampMode{RdmaDevice: r.dev.Info.DeviceName, Queue: "responder", HWTimestamps: !r.responder.GetQueueInfo().UsesSWTimestamps},
		)
	}
	for _, m := range modes {
		if !m.HWTimestamps {
			a.logger.Warn().
				Str("device", m.RdmaDevice).
				Str("queue", m.Queue).
				Msg("Queue uses software timestamps: T2-T5 are taken when the CQ is polled, so host CPU contention adds to its RTT and delay measurements")
		}
	}
	if a.metrics == nil {
		return
	}
	if err := a.metrics.RegisterTimestampModeCallback(func() []telemetry.QueueTimestampMode { return modes }); err != nil {
		a.logger.Warn().Err(err).Msg("Failed to register timestamp mode callback")
	}
}

// targetRnicLabels maps metrics_target_rnic_labels(_scope) onto
// telemetry.TargetRnicLabels. Empty values mean the defaults, off and stable.
func targetRnicLabels(cfg *config.AgentConfig) telemetry.TargetRnicLabels {
	mode := cfg.MetricsTargetRnicLabels
	return telemetry.TargetRnicLabels{
		Enabled:        mode == config.MetricsTargetRnicLabelsCounters || mode == config.MetricsTargetRnicLabelsAll,
		Histograms:     mode == config.MetricsTargetRnicLabelsAll,
		IncludeSampled: cfg.MetricsTargetRnicLabelsScope == config.MetricsTargetRnicLabelsScopeAll,
	}
}

// createResultsFanIn creates the shared results channel and one goroutine
// per prober forwarding its Results() into it, plus the analysis branch when
// analysis reporting is enabled.
//
// The tee onto the analysis branch is non-blocking (dropped when full) so a
// slow aggregator can never stall the metrics path. The metrics send is
// skipped entirely when no consumer will drain a.results, and otherwise
// selects on resultsDone so stopResultsFanIn can always unblock it.
func (a *Agent) createResultsFanIn() {
	a.results = make(chan *probe.ProbeResult, resultChanSize)
	a.resultsDone = make(chan struct{})
	if a.cfg.AnalysisReportEnabled {
		a.analysisResults = make(chan *probe.ProbeResult, resultChanSize)
	}

	for _, r := range a.rnics {
		if r.prober == nil {
			continue
		}
		a.resultsWg.Add(1)
		go func(p *Prober) {
			defer a.resultsWg.Done()
			for result := range p.Results() {
				// Service tracing results are summarized apart from the
				// cluster paths (the aggregator keys on the pinglist type)
				// and evaluated against the service-network SLO thresholds
				// by the controller. A controller that predates that would
				// mix them into the cluster evaluation, so they are teed
				// only once registration reported the support.
				if a.analysisResults != nil &&
					(!result.IsServiceTracing() || a.servicePathSummaries.Load()) {
					select {
					case a.analysisResults <- result:
					default:
					}
				}
				if !a.metricsResultsActive {
					continue
				}
				select {
				case a.results <- result:
				case <-a.resultsDone:
					// Shutting down with nothing guaranteed to drain
					// a.results: stop forwarding; remaining results drop.
					return
				}
			}
		}(r.prober)
	}
}

// stopResultsFanIn stops every fan-in goroutine, waits for them, and closes
// the shared channels exactly once. No-op if createResultsFanIn never ran.
// Call it only after every prober has been destroyed (closing its Results()
// channel), so goroutines waiting for the next value also exit.
func (a *Agent) stopResultsFanIn() {
	if a.resultsDone == nil {
		return
	}
	close(a.resultsDone)
	a.resultsWg.Wait()
	close(a.results)
	// Only after every fan-in goroutine exited, so no tee send races the
	// close. This ends the AnalysisReporter's loop and final flush.
	if a.analysisResults != nil {
		close(a.analysisResults)
	}
}
