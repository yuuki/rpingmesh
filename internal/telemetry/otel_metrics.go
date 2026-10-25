// Package telemetry provides OpenTelemetry metrics collection for the
// R-Pingmesh agent. It records probe RTT measurements and success/failure
// counts as OTLP metrics exported to a configured collector.
//
// Design principle: metric attributes use ToR-level cardinality
// (source_tor, target_tor) plus the local source RNIC to avoid metric
// cardinality explosion. Destination-RNIC labels (target_hostname,
// target_rdma_device, target_netdev) are opt-in via WithTargetRnicLabels and
// go to separate rpingmesh.target_rnic.* instruments.
// GID-level details are emitted as structured log fields at Debug level via
// zerolog.
package telemetry

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/buildinfo"
	"github.com/yuuki/rpingmesh/internal/probe"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	// Pinned to v1.43.0 to match the schema URL baked into resource.Default()
	// by go.opentelemetry.io/otel/sdk v1.47.0's process/telemetry-sdk resource
	// detectors. A mismatched semconv version here (e.g. v1.39.0, which
	// matched sdk v1.40.0) makes resource.Merge fail with "conflicting Schema
	// URL" on every call, breaking MetricsCollector initialization entirely.
	// Bump this in lockstep with go.opentelemetry.io/otel/sdk.
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// networkRTTBucketBoundaries are the explicit bucket boundaries (ns) of the
// network RTT histograms. They are sized from production RoCEv2 leaf-spine
// distributions, where 99.99% of samples fall in 2-25us (a few us on the same
// leaf, up to ~10us cross-leaf, tens of us across a remote deep-buffer tier):
// resolution is densest there, so a regression within that range moves
// between buckets and shows up in histogram_quantile. Explicit-bucket
// histograms export every bucket of every series, including empty ones, so
// boundaries where no samples land are dropped. The tail keeps the
// 1ms-2.5ms-5ms-10ms steps so congestion (e.g. PFC pause storms) still has a
// magnitude: histogram_quantile interpolates linearly inside a bucket, so a
// single 1ms-10ms bucket would report every sample in it as ~5.5ms at p50.
// It also keeps 500us, the default
// analyzer_sla_network_rtt_p99_ns, so the fraction of samples above the SLA
// threshold can be read off one bucket.
//
// These boundaries are independent of internal/probe's rttBucketBoundariesNs:
// the analyzer aggregates inside the agent from its own ladder and never reads
// the exported histograms.
var networkRTTBucketBoundaries = []float64{
	2_000, 2_500, 3_000, 3_500, 4_000,
	5_000, 6_000, 7_000, 8_000, 9_000, 10_000,
	12_500, 15_000, 20_000, 25_000, 50_000,
	100_000, 500_000,
	1_000_000, 2_500_000, 5_000_000, 10_000_000,
}

// delayBucketBoundaries are the explicit bucket boundaries (ns) of the prober
// and responder delay histograms. These are host-side processing delays
// (completion polling, Go scheduling, ACK posting); in production they fall in
// 25us-2.5ms with p50s of roughly 45-120us, two orders of magnitude above
// network RTT, so they get their own ladder instead of the RTT one.
var delayBucketBoundaries = []float64{
	25_000, 50_000, 75_000, 100_000, 150_000, 250_000,
	500_000, 1_000_000, 2_500_000, 10_000_000,
}

// IsNetworkRTTBucketBoundary reports whether ns is an explicit bucket
// boundary of rpingmesh.network_rtt_ns. The controller uses it to warn when
// its analyzer SLA threshold cannot be read off a single histogram bucket.
func IsNetworkRTTBucketBoundary(ns uint64) bool {
	for _, b := range networkRTTBucketBoundaries {
		if uint64(b) == ns {
			return true
		}
	}
	return false
}

// periodicReaderInterval is the interval at which the OTLP periodic reader
// flushes accumulated metrics to the collector.
const periodicReaderInterval = 10 * time.Second

// Failure reason values attached to the "reason" attribute of
// rpingmesh.probe_failed_total. Keeping this to a small fixed set avoids
// metric cardinality blowup while still distinguishing regression classes
// that require different remediation:
//
//   - reasonTimeout: the ACK-matching path never completed (probe.ProbeResult
//     built by Prober.cleanupStalePending, ErrorMessage "timed out waiting
//     for ACKs"). This indicates a real protocol/connectivity regression.
//   - reasonSendError: ibv_post_send (or the Cgo call wrapping it) failed
//     outright before any ACK could be expected.
//   - reasonInvalidRTT: all 6 timestamps arrived (result.Success == true) but
//     probe.CalculateRTT rejected the measurement (rtt.Valid == false), e.g.
//     a small negative NetworkRTT from SW-timestamp jitter on soft-RoCE, or a
//     ResponderDelay above probe.MaxSaneDelay from a responder that fell
//     behind. It is not a protocol failure; rpingmesh.probe_invalid_total
//     splits it by probe.InvalidKind.
//   - reasonUnknown: a failed result whose ErrorMessage does not match a
//     known pattern; kept so new failure paths are still visible instead of
//     silently falling into one of the above buckets.
const (
	reasonTimeout    = "timeout"
	reasonSendError  = "send_error"
	reasonInvalidRTT = "invalid_rtt"
	reasonUnknown    = "unknown"
)

// invalidRTTWarnInterval is the minimum interval between the Warn-level
// logs of rejected measurements (see logInvalidRTT). Rejections are counted
// on rpingmesh.probe_invalid_total regardless; the Warn log only samples
// them so a burst of hundreds per second cannot flood the journal.
const invalidRTTWarnInterval = 10 * time.Second

// probeFailureReason classifies a non-successful probe outcome into one of
// the fixed reason buckets documented above. It is the single place that
// derives the "reason" metric attribute so callers cannot diverge on the
// classification logic.
func probeFailureReason(result *probe.ProbeResult) string {
	if !result.Success {
		switch result.FailureReason {
		case probe.FailureTimeout:
			return reasonTimeout
		case probe.FailureSendError:
			return reasonSendError
		case "":
			// Results built without a classification (e.g. by older code
			// paths or tests) fall back to their error message.
			switch {
			case strings.Contains(result.ErrorMessage, "timed out"):
				return reasonTimeout
			case strings.Contains(result.ErrorMessage, "send failed"):
				return reasonSendError
			}
		}
		return reasonUnknown
	}
	// result.Success means all 6 timestamps were collected (see
	// PendingMeasurement.Complete), so CalculateRTT rejected the measurement
	// itself.
	return reasonInvalidRTT
}

// unspecifiedDeviceLabel is the source_rdma_device / source_netdev metric
// label for a result whose source RNIC name is unknown (e.g. a netdev that
// could not be resolved). It matches probe.UnspecifiedTorLabel so every
// "unknown" label value reads the same in dashboards.
const unspecifiedDeviceLabel = probe.UnspecifiedTorLabel

// sampledTargetLabel is the value of every destination-RNIC label on a probe
// to a sampled target (see probe.ProbeResult.TargetSampled) when
// TargetRnicLabels.IncludeSampled is false. Keeping the attribute keys
// present with a fixed value gives every series of a metric the same label
// set, while targets the controller re-samples on every pinglist refresh
// cannot churn series.
const sampledTargetLabel = "_sampled"

// targetRnicMetricPrefix prefixes the instruments that carry the
// destination-RNIC labels. They are separate from the default ToR-level
// instruments so that when they reach the OTel SDK cardinality limit, only
// they fold into the otel.metric.overflow series; the ToR-level series that
// dashboards and alerts use are never affected.
const targetRnicMetricPrefix = "rpingmesh.target_rnic."

// TargetRnicLabels selects the optional destination-RNIC metrics, which
// carry target_hostname, target_rdma_device and target_netdev on top of the
// default attributes. The zero value disables them.
type TargetRnicLabels struct {
	// Enabled records rpingmesh.target_rnic.probe_total, probe_success_total
	// and probe_failed_total, enough to localize loss to an RNIC.
	Enabled bool
	// Histograms also records the three RTT histograms under the same
	// prefix, which cost ~33 series per label set each. Ignored unless
	// Enabled is set.
	Histograms bool
	// IncludeSampled labels sampled targets (inter-ToR, capped untagged
	// ToR-mesh) with their real identity too. When false they carry
	// sampledTargetLabel, because they change on every pinglist refresh.
	IncludeSampled bool
}

// deviceMetricLabel returns name, or unspecifiedDeviceLabel when it is empty,
// so the attribute is always present with a fixed, non-empty value.
func deviceMetricLabel(name string) string {
	if name = strings.TrimSpace(name); name != "" {
		return name
	}
	return unspecifiedDeviceLabel
}

// defaultServiceName is the OTel resource service.name used when
// NewMetricsCollector is called without a WithServiceName option.
const defaultServiceName = "rpingmesh-agent"

// Option configures optional parameters for NewMetricsCollector.
type Option func(*collectorOptions)

// collectorOptions holds the configurable parameters applied via Option.
type collectorOptions struct {
	serviceName      string
	targetRnicLabels TargetRnicLabels
	cardinalityLimit int
	// proberDelayTargetTor and responderDelayTargetTor keep target_tor on
	// the delay histograms (see WithProberDelayTargetTor,
	// WithResponderDelayTargetTor).
	proberDelayTargetTor    bool
	responderDelayTargetTor bool
	// serviceTracing registers the rpingmesh.service.* instruments and the
	// tracer gauges (see WithServiceTracing).
	serviceTracing bool
	serviceLabels  map[string]bool
}

// serviceMetricPrefix prefixes the instruments that record the probes sent
// along traced service flows (probe.ProbeResult.IsServiceTracing). They are
// separate from the default instruments so the cluster-monitoring series,
// which measure controller-chosen paths at a fixed rate, are never mixed
// with service-network samples taken at the service-tracing rate.
const serviceMetricPrefix = "rpingmesh.service."

// WithServiceTracing registers the rpingmesh.service.* probe instruments and
// the rpingmesh.agent.service_* tracer gauges. Without it, service-tracing
// results are logged but not recorded.
func WithServiceTracing(enabled bool) Option {
	return func(o *collectorOptions) {
		o.serviceTracing = enabled
	}
}

// defaultCollectorOptions returns the options applied before any Option.
func defaultCollectorOptions() collectorOptions {
	return collectorOptions{
		serviceName:             defaultServiceName,
		responderDelayTargetTor: true,
	}
}

// WithServiceName overrides the OTel resource service.name reported by the
// MetricsCollector. If not supplied, NewMetricsCollector uses
// defaultServiceName ("rpingmesh-agent"), preserving prior behavior.
func WithServiceName(serviceName string) Option {
	return func(o *collectorOptions) {
		o.serviceName = serviceName
	}
}

// WithTargetRnicLabels enables the optional destination-RNIC metric
// attributes described by labels. Without it they are never recorded.
func WithTargetRnicLabels(labels TargetRnicLabels) Option {
	return func(o *collectorOptions) {
		o.targetRnicLabels = labels
	}
}

// WithProberDelayTargetTor attaches target_tor to rpingmesh.prober_delay_ns.
// It is off by default: the prober delay is time spent on the probing host,
// so splitting it by the remote ToR adds no information and multiplies its
// series by the ToRs probed.
func WithProberDelayTargetTor(enabled bool) Option {
	return func(o *collectorOptions) {
		o.proberDelayTargetTor = enabled
	}
}

// WithResponderDelayTargetTor controls target_tor on
// rpingmesh.responder_delay_ns. It is on by default: the responder delay is
// time spent on the remote host, network RTT subtracts it, and the analyzer's
// path summaries do not carry it, so target_tor is the only default signal
// that localizes slow responders. Without it, a slow ToR's responders are
// diluted by every other target of the source RNIC.
// rpingmesh.network_rtt_ns, the probe counters and the
// rpingmesh.target_rnic.* histograms always carry target_tor.
func WithResponderDelayTargetTor(enabled bool) Option {
	return func(o *collectorOptions) {
		o.responderDelayTargetTor = enabled
	}
}

// WithCardinalityLimit caps the number of attribute sets each instrument
// keeps per collection cycle; label sets beyond it are folded into a single
// otel.metric.overflow=true series. Zero or a negative value keeps the OTel
// SDK default (2000, or OTEL_GO_X_CARDINALITY_LIMIT). It is a MeterProvider
// setting, so it applies to every instrument (the default ToR-level ones
// too) and only NewMetricsCollector applies it.
func WithCardinalityLimit(limit int) Option {
	return func(o *collectorOptions) {
		o.cardinalityLimit = limit
	}
}

// MetricsCollector collects and exports R-Pingmesh probe metrics via OTLP.
// The default instruments use ToR-level attributes (source_tor, target_tor)
// plus the local RNIC to maintain low cardinality; destination-RNIC detail
// goes only to the opt-in target instruments. GID-level detail is emitted
// only in debug logs.
type MetricsCollector struct {
	meterProvider *sdkmetric.MeterProvider
	meter         metric.Meter
	// probeInstruments are the default ToR-level rpingmesh.* instruments.
	probeInstruments
	eventRingDropped   metric.Int64ObservableCounter
	eventRingOccupancy metric.Int64ObservableGauge
	eventRingCapacity  metric.Int64ObservableGauge
	hwTimestamps       metric.Int64ObservableGauge
	selfThrottle       metric.Float64ObservableGauge
	// invalidWarn rate-limits the Warn log of rejected measurements.
	invalidWarn invalidRTTWarnLimiter
	// target holds the rpingmesh.target_rnic.* instruments; nil unless
	// WithTargetRnicLabels enabled them.
	target           *probeInstruments
	targetRnicLabels TargetRnicLabels
	// service holds the rpingmesh.service.* instruments and the tracer
	// gauges; nil unless WithServiceTracing enabled them.
	service             *probeInstruments
	serviceLabels       map[string]bool
	serviceTraceActive  metric.Int64ObservableGauge
	serviceConnections  metric.Int64ObservableGauge
	serviceFlows        metric.Int64ObservableGauge
	serviceTraceEvents  metric.Int64ObservableCounter
	serviceTraceDropped metric.Int64ObservableCounter
	// proberDelayTargetTor and responderDelayTargetTor keep target_tor on
	// the delay histograms (see WithProberDelayTargetTor,
	// WithResponderDelayTargetTor).
	proberDelayTargetTor    bool
	responderDelayTargetTor bool
	logger                  zerolog.Logger
}

// probeInstruments are the seven per-probe instruments. They exist as the
// default ToR-level set (rpingmesh.*) and, when WithTargetRnicLabels enables
// them, as the destination-RNIC-labelled rpingmesh.target_rnic.* set, whose
// histograms stay nil unless TargetRnicLabels.Histograms is set.
type probeInstruments struct {
	networkRTT     metric.Int64Histogram // nanoseconds
	proberDelay    metric.Int64Histogram // nanoseconds
	responderDelay metric.Int64Histogram // nanoseconds
	probeSuccess   metric.Int64Counter
	probeFailed    metric.Int64Counter
	probeTotal     metric.Int64Counter
	// probeInvalid splits the reason="invalid_rtt" failures by
	// probe.InvalidKind (attribute "kind").
	probeInvalid metric.Int64Counter
}

// invalidRTTWarnLimiter lets one Warn log through per invalidRTTWarnInterval
// and counts the rejections it suppressed in between.
type invalidRTTWarnLimiter struct {
	mu         sync.Mutex
	last       time.Time
	suppressed uint64
}

// allow reports whether a Warn log may be emitted at now and, if so, how
// many rejections were suppressed since the previous one.
func (l *invalidRTTWarnLimiter) allow(now time.Time) (bool, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < invalidRTTWarnInterval {
		l.suppressed++
		return false, 0
	}
	suppressed := l.suppressed
	l.last = now
	l.suppressed = 0
	return true, suppressed
}

// instanceID returns a value suitable for the OTel resource's
// service.instance.id attribute: the machine's hostname, which is stable
// across an agent's lifetime and distinct per host in the common case of
// one agent per machine. os.Hostname() essentially never fails on Linux,
// but if it does (e.g. a container with an unusual /proc setup), fall back
// to a random UUID rather than leaving service.instance.id unset -- an
// unset instance ID is exactly the bug this exists to prevent (see
// buildResource): multiple agents would collide onto the same Prometheus
// series after prometheusremotewrite derives `instance` from this
// attribute.
func instanceID() string {
	host, err := os.Hostname()
	if err != nil {
		log.Warn().Err(err).Msg("os.Hostname failed; falling back to a random service.instance.id")
		return uuid.NewString()
	}
	return host
}

// buildResource builds the OTel resource identifying this service, merging
// process/host defaults with the given service name, the build version, and a
// per-process service.instance.id (see instanceID).
// Extracted as its own function so tests can verify service-name
// parameterization without dialing a real OTLP collector.
//
// service.instance.id matters beyond identification: the collector's
// prometheusremotewrite exporter derives the Prometheus `instance` label
// from it (as it derives `job` from service.name). Without it, every agent
// process reporting the same metric name+ToR-pair attributes collides onto
// one Prometheus series -- rate() then mixes counters from unrelated
// processes, corrupting every rate/quantile derived from it. See
// docs/design/grafana-dashboards.md's "identity contract" note.
//
// host.name is set alongside it because some collector pipelines strip
// service.instance.id as a "redundant" label before export and identify
// sources by host.name instead; without host.name such a pipeline would
// again collapse every agent onto one series.
func buildResource(serviceName string) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(buildinfo.Version),
		semconv.ServiceInstanceID(instanceID()),
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		attrs = append(attrs, semconv.HostName(host))
	}
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, attrs...),
	)
}

// NewMetricsCollector creates a MetricsCollector that exports OTLP metrics
// over insecure gRPC to collectorAddr (e.g., "localhost:4317"), flushing
// every periodicReaderInterval, and registers every instrument on it.
//
// By default the OTel resource reports service.name="rpingmesh-agent"; pass
// WithServiceName to override it (e.g. for non-agent processes reusing this
// collector).
func NewMetricsCollector(ctx context.Context, collectorAddr string, opts ...Option) (*MetricsCollector, error) {
	options := defaultCollectorOptions()
	for _, opt := range opts {
		opt(&options)
	}

	var providerOpts []sdkmetric.Option
	if options.cardinalityLimit > 0 {
		providerOpts = append(providerOpts, sdkmetric.WithCardinalityLimit(options.cardinalityLimit))
	}
	provider, err := NewMeterProvider(ctx, collectorAddr, options.serviceName, providerOpts...)
	if err != nil {
		return nil, err
	}

	mc, err := registerInstruments(provider, options)
	if err != nil {
		return nil, err
	}

	mc.logger.Info().
		Str("collector_addr", collectorAddr).
		Dur("flush_interval", periodicReaderInterval).
		Bool("target_rnic_labels", options.targetRnicLabels.Enabled).
		Bool("target_rnic_labels_histograms", options.targetRnicLabels.Histograms).
		Bool("target_rnic_labels_sampled", options.targetRnicLabels.IncludeSampled).
		Int("cardinality_limit", options.cardinalityLimit).
		Bool("prober_delay_target_tor", options.proberDelayTargetTor).
		Bool("responder_delay_target_tor", options.responderDelayTargetTor).
		Msg("MetricsCollector initialized")

	return mc, nil
}

// NewMeterProvider builds an OTLP-exporting MeterProvider tagged with the
// given service.name and a periodic reader flushing every periodicReaderInterval.
// It centralizes the OTLP exporter + resource + reader wiring so that any
// in-process metric producer can reuse it: the agent's MetricsCollector, and
// the controller-side analyzer (service.name="rpingmesh-analyzer"), which
// registers its own instruments on the returned provider. The caller owns the
// provider's lifecycle (Shutdown).
func NewMeterProvider(ctx context.Context, collectorAddr, serviceName string, opts ...sdkmetric.Option) (*sdkmetric.MeterProvider, error) {
	exporter, err := otlpmetricgrpc.New(
		ctx,
		otlpmetricgrpc.WithEndpoint(collectorAddr),
		otlpmetricgrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := buildResource(serviceName)
	if err != nil {
		return nil, err
	}

	providerOpts := append([]sdkmetric.Option{
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(
				exporter,
				sdkmetric.WithInterval(periodicReaderInterval),
			),
		),
	}, opts...)
	provider := sdkmetric.NewMeterProvider(providerOpts...)
	return provider, nil
}

// NewMetricsCollectorWithProvider creates a MetricsCollector using the given
// MeterProvider. This is intended for testing where the caller supplies a
// provider backed by a ManualReader for in-memory metric verification.
// WithServiceName and WithCardinalityLimit are ignored here: the caller
// configures its own provider.
func NewMetricsCollectorWithProvider(provider *sdkmetric.MeterProvider, opts ...Option) (*MetricsCollector, error) {
	options := defaultCollectorOptions()
	for _, opt := range opts {
		opt(&options)
	}
	return registerInstruments(provider, options)
}

// defaultMetricPrefix prefixes the default ToR-level instruments.
const defaultMetricPrefix = "rpingmesh."

// instrumentRegistrar creates instruments on one meter and keeps the first
// error, so a registration sequence reads as straight-line assignments and
// is checked once at the end.
type instrumentRegistrar struct {
	meter metric.Meter
	err   error
}

func (r *instrumentRegistrar) keep(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *instrumentRegistrar) histogram(name, desc string, boundaries []float64) metric.Int64Histogram {
	h, err := r.meter.Int64Histogram(name, metric.WithDescription(desc), metric.WithUnit("ns"),
		metric.WithExplicitBucketBoundaries(boundaries...))
	r.keep(err)
	return h
}

func (r *instrumentRegistrar) counter(name, desc, unit string) metric.Int64Counter {
	c, err := r.meter.Int64Counter(name, metric.WithDescription(desc), metric.WithUnit(unit))
	r.keep(err)
	return c
}

func (r *instrumentRegistrar) observableCounter(name, desc, unit string) metric.Int64ObservableCounter {
	c, err := r.meter.Int64ObservableCounter(name, metric.WithDescription(desc), metric.WithUnit(unit))
	r.keep(err)
	return c
}

func (r *instrumentRegistrar) gauge(name, desc, unit string) metric.Int64ObservableGauge {
	g, err := r.meter.Int64ObservableGauge(name, metric.WithDescription(desc), metric.WithUnit(unit))
	r.keep(err)
	return g
}

func (r *instrumentRegistrar) float64Gauge(name, desc, unit string) metric.Float64ObservableGauge {
	g, err := r.meter.Float64ObservableGauge(name, metric.WithDescription(desc), metric.WithUnit(unit))
	r.keep(err)
	return g
}

// register creates p's instruments under prefix. In the target set (target
// is true) every description gets a ", per target RNIC" suffix unless the
// row names its own targetDesc, and the histograms are created only when
// histograms is set. The RTT histogram and the two delay histograms have
// separate bucket ladders (see networkRTTBucketBoundaries,
// delayBucketBoundaries).
func (p *probeInstruments) register(r *instrumentRegistrar, prefix string, target, histograms bool) {
	describe := func(desc, targetDesc string) string {
		switch {
		case !target:
			return desc
		case targetDesc != "":
			return targetDesc
		default:
			return desc + ", per target RNIC"
		}
	}
	if histograms {
		for _, h := range []struct {
			dst        *metric.Int64Histogram
			name, desc string
			boundaries []float64
		}{
			{&p.networkRTT, "network_rtt_ns", "Network round-trip time in nanoseconds", networkRTTBucketBoundaries},
			{&p.proberDelay, "prober_delay_ns", "Prober-side processing delay in nanoseconds", delayBucketBoundaries},
			{&p.responderDelay, "responder_delay_ns", "Responder-side processing delay in nanoseconds", delayBucketBoundaries},
		} {
			*h.dst = r.histogram(prefix+h.name, describe(h.desc, ""), h.boundaries)
		}
	}
	for _, c := range []struct {
		dst                    *metric.Int64Counter
		name, desc, targetDesc string
	}{
		{&p.probeSuccess, "probe_success_total", "Total number of successful probes with valid RTT", ""},
		{&p.probeFailed, "probe_failed_total", "Total number of failed probes or probes with invalid RTT", ""},
		{&p.probeTotal, "probe_total", "Total number of probes recorded", ""},
		{&p.probeInvalid, "probe_invalid_total",
			"Total number of probes whose 6 timestamps arrived but whose RTT was rejected, by rejection kind",
			"Total number of probes whose RTT was rejected, by rejection kind, per target RNIC"},
	} {
		*c.dst = r.counter(prefix+c.name, describe(c.desc, c.targetDesc), "{probe}")
	}
}

// registerInstruments creates every instrument on the given provider's meter
// and returns a MetricsCollector with them wired up, including the target
// instruments that options enable.
func registerInstruments(provider *sdkmetric.MeterProvider, options collectorOptions) (*MetricsCollector, error) {
	r := &instrumentRegistrar{meter: provider.Meter("rpingmesh.agent")}
	mc := &MetricsCollector{
		meterProvider:           provider,
		meter:                   r.meter,
		targetRnicLabels:        options.targetRnicLabels,
		serviceLabels:           options.serviceLabels,
		proberDelayTargetTor:    options.proberDelayTargetTor,
		responderDelayTargetTor: options.responderDelayTargetTor,
		logger:                  log.With().Str("component", "telemetry").Logger(),
	}
	mc.probeInstruments.register(r, defaultMetricPrefix, false, true)

	// The observable instruments are registered without callbacks: the
	// values they report are owned by the agent package (the EventRings in
	// internal/agent/agent.go, the Watchdog's rate multiplier), not
	// telemetry. The Register*Callback methods wire them in once the agent
	// has created those objects.
	mc.eventRingDropped = r.observableCounter("rpingmesh.event_ring_dropped_total",
		"Total number of completion events dropped because an event ring was full", "{event}")
	mc.eventRingOccupancy = r.gauge("rpingmesh.event_ring_occupancy_max",
		"Highest number of completion events waiting in an event ring since the previous collection", "{event}")
	mc.eventRingCapacity = r.gauge("rpingmesh.event_ring_capacity",
		"Number of completion events an event ring can hold", "{event}")
	mc.hwTimestamps = r.gauge("rpingmesh.agent.hw_timestamps",
		"Whether a queue reads NIC hardware completion timestamps (1) or falls back to software timestamps taken when the CQ is polled (0)", "1")
	// The self-throttle gauge carries no attributes: it is a single
	// process-wide value (1.0 = unthrottled, down to 0.1 = maximally throttled).
	mc.selfThrottle = r.float64Gauge("rpingmesh.agent.self_throttle",
		"Current self-protection probe-rate multiplier (1.0 = unthrottled, lower = throttled to protect local CPU/memory)", "1")

	if options.targetRnicLabels.Enabled {
		mc.target = &probeInstruments{}
		mc.target.register(r, targetRnicMetricPrefix, true, options.targetRnicLabels.Histograms)
	}
	if options.serviceTracing {
		mc.service = &probeInstruments{}
		mc.service.register(r, serviceMetricPrefix, false, true)
		mc.serviceTraceActive = r.gauge("rpingmesh.agent.service_trace_active",
			"Whether the eBPF service tracer is attached (1) or service tracing is degraded (0)", "1")
		mc.serviceConnections = r.gauge("rpingmesh.agent.service_connections",
			"Connected application queue pairs traced on a local RNIC", "{connection}")
		mc.serviceFlows = r.gauge("rpingmesh.agent.service_flows",
			"Distinct traced service flows of a local RNIC, by whether their remote RNIC resolved to a probe target", "{flow}")
		mc.serviceTraceEvents = r.observableCounter("rpingmesh.agent.service_trace_events_total",
			"Queue pair lifecycle events the service tracer processed, by kind", "{event}")
		mc.serviceTraceDropped = r.observableCounter("rpingmesh.agent.service_trace_dropped_total",
			"Service tracer events lost before they reached the connection table, by reason", "{event}")
	}
	if r.err != nil {
		return nil, r.err
	}
	return mc, nil
}

// probeLabels are the attribute values every default probe instrument
// carries: the ToR pair plus the local (source) RNIC. The source RNIC labels
// are bounded by the RNICs on this host, and device and netdev map 1:1, so
// together they multiply series only by the local RNIC count. NEVER use GIDs
// or any destination-RNIC identity as attributes of the default instruments;
// that goes only to the opt-in target instruments.
type probeLabels struct {
	sourceTor, targetTor, sourceRdmaDevice, sourceNetdev string
}

func newProbeLabels(result *probe.ProbeResult, sourceTorID string) probeLabels {
	return probeLabels{
		sourceTor:        probe.TorMetricLabel(sourceTorID),
		targetTor:        probe.TorMetricLabel(result.TargetTorID),
		sourceRdmaDevice: deviceMetricLabel(result.SourceRdmaDevice),
		sourceNetdev:     deviceMetricLabel(result.SourceNetdev),
	}
}

// attributes returns the default attribute set. withTargetTor is false for
// the delay histograms that drop target_tor (see WithProberDelayTargetTor,
// WithResponderDelayTargetTor).
func (l probeLabels) attributes(withTargetTor bool) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 4)
	attrs = append(attrs, attribute.String("source_tor", l.sourceTor))
	if withTargetTor {
		attrs = append(attrs, attribute.String("target_tor", l.targetTor))
	}
	return append(attrs,
		attribute.String("source_rdma_device", l.sourceRdmaDevice),
		attribute.String("source_netdev", l.sourceNetdev))
}

// probeOutcome is the classification of one probe that the default and the
// target instruments both record.
type probeOutcome struct {
	rtt *probe.RTTResult
	// success is true when all six timestamps arrived and probe.CalculateRTT
	// accepted the measurement.
	success bool
	// reason is the probe_failed_total "reason" attribute (see
	// probeFailureReason); "" on success.
	reason string
}

func classifyProbe(result *probe.ProbeResult, rtt *probe.RTTResult) probeOutcome {
	if result.Success && rtt != nil && rtt.Valid {
		return probeOutcome{rtt: rtt, success: true}
	}
	return probeOutcome{rtt: rtt, reason: probeFailureReason(result)}
}

// invalid reports whether the measurement was rejected by CalculateRTT.
func (o probeOutcome) invalid() bool { return o.reason == reasonInvalidRTT }

// withAttribute returns attrSet plus one attribute as a measurement option.
// The three-index slice forces a copy so attrSet's backing array is never
// aliased by the appended set.
func withAttribute(attrSet []attribute.KeyValue, key, value string) metric.MeasurementOption {
	return metric.WithAttributes(append(attrSet[:len(attrSet):len(attrSet)], attribute.String(key, value))...)
}

// record counts o on p's counters with attrSet: probe_total always, then
// probe_success_total, or probe_failed_total with the reason and, for a
// rejected measurement, probe_invalid_total with the kind. On a success it
// also records the histograms when p has them; the two delay histograms take
// their own attributes because the default set may drop target_tor from them.
func (p *probeInstruments) record(ctx context.Context, o probeOutcome, attrSet []attribute.KeyValue,
	proberDelayAttrs, responderDelayAttrs metric.MeasurementOption) {
	attrs := metric.WithAttributes(attrSet...)
	p.probeTotal.Add(ctx, 1, attrs)
	if !o.success {
		p.probeFailed.Add(ctx, 1, withAttribute(attrSet, "reason", o.reason))
		if o.invalid() {
			p.probeInvalid.Add(ctx, 1, withAttribute(attrSet, "kind", invalidKindLabel(o.rtt)))
		}
		return
	}
	p.probeSuccess.Add(ctx, 1, attrs)
	if p.networkRTT != nil {
		p.networkRTT.Record(ctx, o.rtt.NetworkRTT, attrs)
		p.proberDelay.Record(ctx, o.rtt.ProberDelay, proberDelayAttrs)
		p.responderDelay.Record(ctx, o.rtt.ResponderDelay, responderDelayAttrs)
	}
}

// RecordProbeResult records metrics for a single completed probe.
// It uses ToR-level attributes (source_tor, target_tor) and the local source
// RNIC for metric dimensions to keep cardinality low. When enabled via
// WithTargetRnicLabels it also records the rpingmesh.target_rnic.*
// instruments with the destination RNIC (see targetAttributes). GID-level
// details are logged at Debug level for troubleshooting without inflating
// metric series count.
//
// If result.Success is true and rtt.Valid is true, the RTT histograms and
// success counter are incremented. Otherwise, the failure counter is
// incremented with an additional "reason" attribute (see probeFailureReason)
// so timeout/send/measurement-noise failures can be distinguished without
// per-GID cardinality cost. The total counter is always incremented.
func (mc *MetricsCollector) RecordProbeResult(result *probe.ProbeResult, rtt *probe.RTTResult, sourceTorID string) {
	if result == nil {
		return
	}
	ctx := context.Background()
	labels := newProbeLabels(result, sourceTorID)
	outcome := classifyProbe(result, rtt)

	attrSet := labels.attributes(true)
	attrs := metric.WithAttributes(attrSet...)
	noTargetTorAttrs := metric.WithAttributes(labels.attributes(false)...)
	proberDelayAttrs, responderDelayAttrs := noTargetTorAttrs, noTargetTorAttrs
	if mc.proberDelayTargetTor {
		proberDelayAttrs = attrs
	}
	if mc.responderDelayTargetTor {
		responderDelayAttrs = attrs
	}

	// A probe along a traced service flow measures the service network: it
	// goes to the rpingmesh.service.* instruments only, with the same
	// ToR-level attributes, and never to the destination-RNIC instruments.
	if result.IsServiceTracing() {
		if mc.service != nil {
			mc.recordServiceProbe(ctx, result, outcome, labels)
		}
		if outcome.invalid() {
			mc.logInvalidRTT(result, rtt, labels)
		}
		mc.logProbeResult(result, labels, outcome)
		return
	}

	mc.probeInstruments.record(ctx, outcome, attrSet, proberDelayAttrs, responderDelayAttrs)
	if outcome.invalid() {
		mc.logInvalidRTT(result, rtt, labels)
	}

	if mc.target != nil {
		targetAttrSet := mc.targetAttributes(attrSet, result)
		targetAttrs := metric.WithAttributes(targetAttrSet...)
		mc.target.record(ctx, outcome, targetAttrSet, targetAttrs, targetAttrs)
	}

	mc.logProbeResult(result, labels, outcome)
}

// targetAttributes returns baseAttrs (the default instruments' attributes)
// plus target_hostname, target_rdma_device and target_netdev for the
// rpingmesh.target_rnic.* instruments. An unknown value (e.g. a target
// registered by an older agent that does not report its netdev) becomes
// unspecifiedDeviceLabel. Sampled targets get sampledTargetLabel for all
// three unless IncludeSampled is set.
func (mc *MetricsCollector) targetAttributes(baseAttrs []attribute.KeyValue, result *probe.ProbeResult) []attribute.KeyValue {
	host, device, netdev := sampledTargetLabel, sampledTargetLabel, sampledTargetLabel
	if mc.targetRnicLabels.IncludeSampled || !result.TargetSampled {
		host = deviceMetricLabel(result.TargetHostname)
		device = deviceMetricLabel(result.TargetRdmaDevice)
		netdev = deviceMetricLabel(result.TargetNetdev)
	}
	attrSet := make([]attribute.KeyValue, 0, len(baseAttrs)+3)
	attrSet = append(attrSet, baseAttrs...)
	return append(attrSet,
		attribute.String("target_hostname", host),
		attribute.String("target_rdma_device", device),
		attribute.String("target_netdev", netdev),
	)
}

// logProbeResult logs one probe with its GID-level detail at Debug level,
// which gives per-flow visibility without metric cardinality cost.
// scripts/topology/rtt_tor_check.py reads these records, so the field set is
// a contract (pinned by probe_log_json_test.go). invalid_kind and
// validation_error are set only for a rejected measurement
// (reason=invalid_rtt), not for a probe that never completed.
func (mc *MetricsCollector) logProbeResult(result *probe.ProbeResult, l probeLabels, o probeOutcome) {
	var rejectedKind, rejectedError string
	if o.invalid() {
		rejectedKind, rejectedError = invalidKindLabel(o.rtt), validationErrorOf(o.rtt)
	}
	mc.logger.Debug().
		Str("source_gid", probe.FormatGID(result.SourceGID)).
		Str("target_gid", probe.FormatGID(result.TargetGID)).
		Str("source_tor", l.sourceTor).
		Str("target_tor", l.targetTor).
		Str("source_rdma_device", l.sourceRdmaDevice).
		Str("source_netdev", l.sourceNetdev).
		Str("target_ip", result.TargetIP).
		Uint32("flow_label", result.FlowLabel).
		Uint64("seq", result.SequenceNum).
		Uint64("t1", result.T1).
		Uint64("t2", result.T2).
		Uint64("t3", result.T3).
		Uint64("t4", result.T4).
		Uint64("t5", result.T5).
		Uint64("t6", result.T6).
		Bool("success", result.Success).
		Str("error", result.ErrorMessage).
		Bool("rtt_valid", o.success).
		Str("invalid_kind", rejectedKind).
		Str("validation_error", rejectedError).
		Msg("Probe result recorded")
}

// validationErrorOf returns rtt's ValidationError ("" when rtt is nil).
func validationErrorOf(rtt *probe.RTTResult) string {
	if rtt == nil {
		return ""
	}
	return rtt.ValidationError
}

// invalidKindLabel returns the "kind" attribute of
// rpingmesh.probe_invalid_total. A rejected result always has a kind; the
// fallback keeps the attribute non-empty if a future validation path forgets
// to set one.
func invalidKindLabel(rtt *probe.RTTResult) string {
	if rtt != nil && rtt.InvalidKind != probe.InvalidKindNone {
		return string(rtt.InvalidKind)
	}
	return reasonUnknown
}

// logInvalidRTT logs a rejected measurement at Warn level, at most once per
// invalidRTTWarnInterval, with the rejection kind, the validation error and
// all six timestamps, so an operator can tell a slow responder
// (responder_delay_too_large) from clock or timestamp trouble without
// enabling debug logs. Per the cardinality convention, GIDs and IPs stay in
// the Debug log; this one names the RNICs by hostname and device instead.
func (mc *MetricsCollector) logInvalidRTT(result *probe.ProbeResult, rtt *probe.RTTResult, l probeLabels) {
	ok, suppressed := mc.invalidWarn.allow(time.Now())
	if !ok {
		return
	}
	ev := mc.logger.Warn().
		Str("invalid_kind", invalidKindLabel(rtt)).
		Str("validation_error", validationErrorOf(rtt)).
		Str("source_tor", l.sourceTor).
		Str("target_tor", l.targetTor).
		Str("source_rdma_device", l.sourceRdmaDevice).
		Str("target_hostname", result.TargetHostname).
		Str("target_rdma_device", result.TargetRdmaDevice).
		Uint64("t1", result.T1).
		Uint64("t2", result.T2).
		Uint64("t3", result.T3).
		Uint64("t4", result.T4).
		Uint64("t5", result.T5).
		Uint64("t6", result.T6).
		Uint64("suppressed_since_last", suppressed)
	if rtt != nil {
		ev = ev.Int64("network_rtt_ns", rtt.NetworkRTT).
			Int64("prober_delay_ns", rtt.ProberDelay).
			Int64("responder_delay_ns", rtt.ResponderDelay)
	}
	ev.Msg("Probe measurement rejected (sampled; see rpingmesh.probe_invalid_total for the full count)")
}

// RegisterEventRingDropCallback registers an OTel callback that reports the
// current cumulative drop count for each named event ring (e.g. "prober",
// "responder") as a "ring" attribute on rpingmesh.event_ring_dropped_total.
// readers maps a ring label to a function returning that ring's current
// drop count.
//
// MetricsCollector deliberately does not import internal/rdmabridge (the
// package that owns *EventRing) to avoid coupling telemetry to the RDMA
// bridge; callers (the Agent, which owns the ring values) supply plain
// closures instead. The callback is invoked once per collection cycle by
// the MeterProvider's PeriodicReader/ManualReader, so readers should be
// cheap (an atomic load, per EventRing.DropCount).
func (mc *MetricsCollector) RegisterEventRingDropCallback(readers map[string]func() uint64) error {
	_, err := mc.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			for label, read := range readers {
				o.ObserveInt64(mc.eventRingDropped, int64(read()), metric.WithAttributes(
					attribute.String("ring", label),
				))
			}
			return nil
		},
		mc.eventRingDropped,
	)
	if err != nil {
		return fmt.Errorf("register event ring drop callback: %w", err)
	}
	return nil
}

// EventRingOccupancy is one sample of an event ring's fill level for
// RegisterEventRingOccupancyCallback.
type EventRingOccupancy struct {
	// Max is the highest number of events waiting in the ring since the
	// previous sample.
	Max uint64
	// Capacity is the number of events the ring can hold.
	Capacity uint64
}

// RegisterEventRingOccupancyCallback registers an OTel callback that reports,
// for each named ring, rpingmesh.event_ring_occupancy_max (the highest fill
// level since the previous collection) and rpingmesh.event_ring_capacity,
// both with a "ring" attribute. A max occupancy that approaches the capacity
// warns that the consumer is falling behind before
// rpingmesh.event_ring_dropped_total starts to grow. readers maps a ring
// label to a function that returns that ring's sample and resets its max, so
// it is called exactly once per collection cycle.
func (mc *MetricsCollector) RegisterEventRingOccupancyCallback(readers map[string]func() EventRingOccupancy) error {
	_, err := mc.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			for label, read := range readers {
				sample := read()
				attrs := metric.WithAttributes(attribute.String("ring", label))
				o.ObserveInt64(mc.eventRingOccupancy, int64(sample.Max), attrs)
				o.ObserveInt64(mc.eventRingCapacity, int64(sample.Capacity), attrs)
			}
			return nil
		},
		mc.eventRingOccupancy, mc.eventRingCapacity,
	)
	if err != nil {
		return fmt.Errorf("register event ring occupancy callback: %w", err)
	}
	return nil
}

// QueueTimestampMode reports the completion timestamp source of one queue
// for RegisterTimestampModeCallback.
type QueueTimestampMode struct {
	RdmaDevice string // e.g. "mlx5_0"
	Queue      string // "prober" or "responder"
	// HWTimestamps is true when the queue reads NIC wallclock completion
	// timestamps, false when it fell back to software timestamps.
	HWTimestamps bool
}

// RegisterTimestampModeCallback registers an OTel callback that reports
// rpingmesh.agent.hw_timestamps (1 = hardware, 0 = software) for every queue
// read returns, with rdma_device and queue attributes. The series count is
// bounded by twice the local RNIC count. A queue in software mode stamps
// T2-T5 when its CQ poller reads the completion, so CPU contention on the
// host shows up in its RTTs; the gauge makes that mode visible.
func (mc *MetricsCollector) RegisterTimestampModeCallback(read func() []QueueTimestampMode) error {
	_, err := mc.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			for _, q := range read() {
				var v int64
				if q.HWTimestamps {
					v = 1
				}
				o.ObserveInt64(mc.hwTimestamps, v, metric.WithAttributes(
					attribute.String("rdma_device", deviceMetricLabel(q.RdmaDevice)),
					attribute.String("queue", q.Queue),
				))
			}
			return nil
		},
		mc.hwTimestamps,
	)
	if err != nil {
		return fmt.Errorf("register timestamp mode callback: %w", err)
	}
	return nil
}

// RegisterSelfThrottleCallback registers an OTel callback that reports the
// agent's current self-protection rate multiplier on the
// rpingmesh.agent.self_throttle gauge. read returns the live multiplier
// (1.0 = unthrottled, down to 0.1 = maximally throttled) and must be cheap
// (an atomic load, per Watchdog.CurrentMultiplier): it is invoked once per
// collection cycle by the reader. Like RegisterEventRingDropCallback, the
// value is owned by the agent package (the Watchdog), so telemetry takes a
// plain closure rather than importing it. The gauge is intentionally
// attribute-free to keep it a single, low-cardinality process-wide series.
func (mc *MetricsCollector) RegisterSelfThrottleCallback(read func() float64) error {
	_, err := mc.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			o.ObserveFloat64(mc.selfThrottle, read())
			return nil
		},
		mc.selfThrottle,
	)
	if err != nil {
		return fmt.Errorf("register self throttle callback: %w", err)
	}
	return nil
}

// ServiceTracingDevice is the service-tracing state of one local RNIC for
// RegisterServiceTracingCallback.
type ServiceTracingDevice struct {
	RdmaDevice string
	// Service is a configured name, or empty when attribution is disabled.
	Service string
	// Connections is the number of connected application QPs traced on the
	// device.
	Connections int
	// FlowsProbed and FlowsUnresolved count the distinct service flows
	// (remote GID and flow label) whose remote RNIC the controller did or
	// did not resolve to a probe target.
	FlowsProbed     int
	FlowsUnresolved int
}

// ServiceTracingSample is one reading of the service tracer's state for
// RegisterServiceTracingCallback. The counters are cumulative.
type ServiceTracingSample struct {
	// Active is true while the eBPF tracer is attached.
	Active  bool
	Devices []ServiceTracingDevice
	// Events by kind, as processed by the connection table.
	Creates       uint64
	Connects      uint64
	Resets        uint64
	Destroys      uint64
	ContextCloses uint64
	// UnknownQPs counts events for QPs the table never saw created.
	UnknownQPs uint64
	// Events lost by reason.
	RingBufferDropped uint64
	ParseErrors       uint64
	DecodeErrors      uint64
}

// labelledCount pairs a counter with its attribute value for the
// observable counters below.
type labelledCount struct {
	label string
	n     uint64
}

// RegisterServiceTracingCallback registers an OTel callback reporting the
// service tracer's state: rpingmesh.agent.service_trace_active,
// service_connections and service_flows (by source_rdma_device and, for the
// flows, by state probed/unresolved), service_trace_events_total (by kind)
// and service_trace_dropped_total (by reason). read must be cheap; it runs
// once per collection cycle. It is an error to call this without
// WithServiceTracing.
func (mc *MetricsCollector) RegisterServiceTracingCallback(read func() ServiceTracingSample) error {
	if mc.service == nil {
		return fmt.Errorf("service tracing instruments are not registered")
	}
	_, err := mc.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			s := read()
			var active int64
			if s.Active {
				active = 1
			}
			o.ObserveInt64(mc.serviceTraceActive, active)
			for _, d := range mc.serviceDeviceSamples(s.Devices) {
				dev := attribute.String("source_rdma_device", deviceMetricLabel(d.RdmaDevice))
				attrs := []attribute.KeyValue{dev}
				if len(mc.serviceLabels) > 0 {
					attrs = append(attrs, attribute.String("service", d.Service))
				}
				o.ObserveInt64(mc.serviceConnections, int64(d.Connections), metric.WithAttributes(attrs...))
				o.ObserveInt64(mc.serviceFlows, int64(d.FlowsProbed),
					withAttribute(attrs, "state", "probed"))
				o.ObserveInt64(mc.serviceFlows, int64(d.FlowsUnresolved),
					withAttribute(attrs, "state", "unresolved"))
			}
			for _, e := range []labelledCount{
				{"create", s.Creates}, {"connect", s.Connects}, {"reset", s.Resets},
				{"destroy", s.Destroys}, {"context_close", s.ContextCloses}, {"unknown_qp", s.UnknownQPs},
			} {
				o.ObserveInt64(mc.serviceTraceEvents, int64(e.n), metric.WithAttributes(attribute.String("kind", e.label)))
			}
			for _, e := range []labelledCount{
				{"ring_buffer", s.RingBufferDropped}, {"parse", s.ParseErrors}, {"decode", s.DecodeErrors},
			} {
				o.ObserveInt64(mc.serviceTraceDropped, int64(e.n), metric.WithAttributes(attribute.String("reason", e.label)))
			}
			return nil
		},
		mc.serviceTraceActive, mc.serviceConnections, mc.serviceFlows, mc.serviceTraceEvents, mc.serviceTraceDropped,
	)
	if err != nil {
		return fmt.Errorf("register service tracing callback: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the MeterProvider, flushing any buffered
// metrics to the collector before returning.
func (mc *MetricsCollector) Shutdown(ctx context.Context) error {
	mc.logger.Info().Msg("Shutting down MetricsCollector")
	return mc.meterProvider.Shutdown(ctx)
}

// StartResultConsumer starts a goroutine that reads probe results from
// resultChan, calculates RTT metrics via probe.CalculateRTT, and records
// them. The goroutine runs until ctx is cancelled or resultChan is closed.
// sourceTorID is the default source_tor for results that do not carry their
// own SourceTorID; the agent's probers stamp each result with their device's
// ToR, so on multi-rail hosts with per-device ToRs the result's value wins.
func (mc *MetricsCollector) StartResultConsumer(ctx context.Context, resultChan <-chan *probe.ProbeResult, sourceTorID string) {
	go func() {
		mc.logger.Info().
			Str("source_tor", sourceTorID).
			Msg("Result consumer started")

		for {
			select {
			case <-ctx.Done():
				mc.logger.Info().Msg("Result consumer stopping: context cancelled")
				return

			case result, ok := <-resultChan:
				if !ok {
					mc.logger.Info().Msg("Result consumer stopping: channel closed")
					return
				}

				rtt := probe.CalculateRTT(result)
				src := sourceTorID
				if result != nil && result.SourceTorID != "" {
					src = result.SourceTorID
				}
				mc.RecordProbeResult(result, rtt, src)
			}
		}
	}()
}
