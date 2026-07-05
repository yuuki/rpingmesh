// Package telemetry provides OpenTelemetry metrics collection for the
// R-Pingmesh agent. It records probe RTT measurements and success/failure
// counts as OTLP metrics exported to a configured collector.
//
// Design principle: metric attributes use ToR-level cardinality only
// (source_tor, target_tor) to avoid metric cardinality explosion. GID-level
// details are emitted as structured log fields at Debug level via zerolog.
package telemetry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	// Pinned to v1.41.0 to match the schema URL baked into resource.Default()
	// by go.opentelemetry.io/otel/sdk v1.44.0's process/telemetry-sdk resource
	// detectors. A mismatched semconv version here (e.g. v1.39.0, which
	// matched sdk v1.40.0) makes resource.Merge fail with "conflicting Schema
	// URL" on every call, breaking MetricsCollector initialization entirely.
	// Bump this in lockstep with go.opentelemetry.io/otel/sdk.
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

// Histogram bucket boundaries in nanoseconds, covering sub-microsecond to
// 10ms ranges typical for datacenter RDMA networks:
//
//	100ns, 500ns, 1us, 5us, 10us, 50us, 100us, 500us, 1ms, 5ms, 10ms
var rttBucketBoundaries = []float64{
	100, 500, 1_000, 5_000, 10_000,
	50_000, 100_000, 500_000, 1_000_000, 5_000_000, 10_000_000,
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
//     a small negative NetworkRTT from SW-timestamp jitter on soft-RoCE. This
//     is measurement noise, not a protocol failure.
//   - reasonUnknown: a failed result whose ErrorMessage does not match a
//     known pattern; kept so new failure paths are still visible instead of
//     silently falling into one of the above buckets.
const (
	reasonTimeout    = "timeout"
	reasonSendError  = "send_error"
	reasonInvalidRTT = "invalid_rtt"
	reasonUnknown    = "unknown"
)

// probeFailureReason classifies a non-successful probe outcome into one of
// the fixed reason buckets documented above. It is the single place that
// derives the "reason" metric attribute so RecordProbeResult and any future
// callers cannot diverge on the classification logic.
func probeFailureReason(result *probe.ProbeResult, rtt *probe.RTTResult) string {
	if !result.Success {
		switch {
		case strings.Contains(result.ErrorMessage, "timed out"):
			return reasonTimeout
		case strings.Contains(result.ErrorMessage, "send failed"):
			return reasonSendError
		default:
			return reasonUnknown
		}
	}
	// result.Success == true means all 6 timestamps were collected
	// (see PendingMeasurement.Complete()); a non-success path here means
	// CalculateRTT rejected the measurement itself.
	return reasonInvalidRTT
}

// defaultServiceName is the OTel resource service.name used when
// NewMetricsCollector is called without a WithServiceName option.
const defaultServiceName = "rpingmesh-agent"

// Option configures optional parameters for NewMetricsCollector.
type Option func(*collectorOptions)

// collectorOptions holds the configurable parameters applied via Option.
type collectorOptions struct {
	serviceName string
}

// WithServiceName overrides the OTel resource service.name reported by the
// MetricsCollector. If not supplied, NewMetricsCollector uses
// defaultServiceName ("rpingmesh-agent"), preserving prior behavior.
func WithServiceName(serviceName string) Option {
	return func(o *collectorOptions) {
		o.serviceName = serviceName
	}
}

// MetricsCollector collects and exports R-Pingmesh probe metrics via OTLP.
// All recorded metrics use ToR-level attributes (source_tor, target_tor) to
// maintain low cardinality. GID-level detail is emitted only in debug logs.
type MetricsCollector struct {
	meterProvider    *sdkmetric.MeterProvider
	meter            metric.Meter
	networkRTT       metric.Int64Histogram // nanoseconds
	proberDelay      metric.Int64Histogram // nanoseconds
	responderDelay   metric.Int64Histogram // nanoseconds
	probeSuccess     metric.Int64Counter
	probeFailed      metric.Int64Counter
	probeTotal       metric.Int64Counter
	eventRingDropped metric.Int64ObservableCounter
	logger           zerolog.Logger
}

// buildResource builds the OTel resource identifying this service, merging
// process/host defaults with the given service name and a fixed service
// version. Extracted as its own function so tests can verify service-name
// parameterization without dialing a real OTLP collector.
func buildResource(serviceName string) (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("0.1.0"),
		),
	)
}

// NewMetricsCollector creates a MetricsCollector that exports OTLP metrics
// to the given gRPC collector address (e.g., "localhost:4317"). It sets up:
//   - An OTLP gRPC exporter (insecure) targeting collectorAddr
//   - A MeterProvider with a periodic reader flushing every 10 seconds
//   - Histogram instruments for network RTT, prober delay, responder delay
//   - Counter instruments for probe success, failure, and total counts
//
// By default the OTel resource reports service.name="rpingmesh-agent"; pass
// WithServiceName to override it (e.g. for non-agent processes reusing this
// collector).
func NewMetricsCollector(ctx context.Context, collectorAddr string, opts ...Option) (*MetricsCollector, error) {
	options := collectorOptions{serviceName: defaultServiceName}
	for _, opt := range opts {
		opt(&options)
	}

	provider, err := NewMeterProvider(ctx, collectorAddr, options.serviceName)
	if err != nil {
		return nil, err
	}

	mc, err := registerInstruments(provider)
	if err != nil {
		return nil, err
	}

	mc.logger.Info().
		Str("collector_addr", collectorAddr).
		Dur("flush_interval", periodicReaderInterval).
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
func NewMeterProvider(ctx context.Context, collectorAddr, serviceName string) (*sdkmetric.MeterProvider, error) {
	// Create OTLP gRPC exporter targeting the collector.
	exporter, err := otlpmetricgrpc.New(
		ctx,
		otlpmetricgrpc.WithEndpoint(collectorAddr),
		otlpmetricgrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	// Build the OTel resource identifying this service.
	res, err := buildResource(serviceName)
	if err != nil {
		return nil, err
	}

	// Create a MeterProvider with a periodic reader that flushes metrics
	// to the collector at a fixed interval.
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(
				exporter,
				sdkmetric.WithInterval(periodicReaderInterval),
			),
		),
	)
	return provider, nil
}

// NewMetricsCollectorWithProvider creates a MetricsCollector using the given
// MeterProvider. This is intended for testing where the caller supplies a
// provider backed by a ManualReader for in-memory metric verification.
func NewMetricsCollectorWithProvider(provider *sdkmetric.MeterProvider) (*MetricsCollector, error) {
	return registerInstruments(provider)
}

// registerInstruments creates histogram and counter instruments on the given
// provider's meter and returns a MetricsCollector with all instruments wired up.
func registerInstruments(provider *sdkmetric.MeterProvider) (*MetricsCollector, error) {
	meter := provider.Meter("rpingmesh.agent")

	// Register histogram instruments with explicit bucket boundaries
	// covering datacenter RDMA RTT ranges (100ns to 10ms).
	networkRTT, err := meter.Int64Histogram(
		"rpingmesh.network_rtt_ns",
		metric.WithDescription("Network round-trip time in nanoseconds"),
		metric.WithUnit("ns"),
		metric.WithExplicitBucketBoundaries(rttBucketBoundaries...),
	)
	if err != nil {
		return nil, err
	}

	proberDelay, err := meter.Int64Histogram(
		"rpingmesh.prober_delay_ns",
		metric.WithDescription("Prober-side processing delay in nanoseconds"),
		metric.WithUnit("ns"),
		metric.WithExplicitBucketBoundaries(rttBucketBoundaries...),
	)
	if err != nil {
		return nil, err
	}

	responderDelay, err := meter.Int64Histogram(
		"rpingmesh.responder_delay_ns",
		metric.WithDescription("Responder-side processing delay in nanoseconds"),
		metric.WithUnit("ns"),
		metric.WithExplicitBucketBoundaries(rttBucketBoundaries...),
	)
	if err != nil {
		return nil, err
	}

	// Register counter instruments for probe outcome tracking.
	probeSuccess, err := meter.Int64Counter(
		"rpingmesh.probe_success_total",
		metric.WithDescription("Total number of successful probes with valid RTT"),
		metric.WithUnit("{probe}"),
	)
	if err != nil {
		return nil, err
	}

	probeFailed, err := meter.Int64Counter(
		"rpingmesh.probe_failed_total",
		metric.WithDescription("Total number of failed probes or probes with invalid RTT"),
		metric.WithUnit("{probe}"),
	)
	if err != nil {
		return nil, err
	}

	probeTotal, err := meter.Int64Counter(
		"rpingmesh.probe_total",
		metric.WithDescription("Total number of probes recorded"),
		metric.WithUnit("{probe}"),
	)
	if err != nil {
		return nil, err
	}

	// Registered without a callback here: the EventRing values it reads are
	// owned by the agent package (internal/agent/agent.go), not telemetry.
	// RegisterEventRingDropCallback wires the callback in once the agent has
	// created its rings.
	eventRingDropped, err := meter.Int64ObservableCounter(
		"rpingmesh.event_ring_dropped_total",
		metric.WithDescription("Total number of completion events dropped because an event ring was full"),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, err
	}

	return &MetricsCollector{
		meterProvider:    provider,
		meter:            meter,
		networkRTT:       networkRTT,
		proberDelay:      proberDelay,
		responderDelay:   responderDelay,
		probeSuccess:     probeSuccess,
		probeFailed:      probeFailed,
		probeTotal:       probeTotal,
		eventRingDropped: eventRingDropped,
		logger:           log.With().Str("component", "telemetry").Logger(),
	}, nil
}

// RecordProbeResult records metrics for a single completed probe.
// It uses only ToR-level attributes (source_tor, target_tor) for metric
// dimensions to keep cardinality low. GID-level details are logged at
// Debug level for troubleshooting without inflating metric series count.
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

	// Build low-cardinality attribute set: ToR IDs only.
	// NEVER use GIDs as metric attributes to avoid cardinality explosion.
	attrs := metric.WithAttributes(
		attribute.String("source_tor", sourceTorID),
		attribute.String("target_tor", result.TargetTorID),
	)

	// Always increment total probe count.
	mc.probeTotal.Add(ctx, 1, attrs)

	if result.Success && rtt != nil && rtt.Valid {
		// Record RTT histogram values for successful probes.
		mc.networkRTT.Record(ctx, rtt.NetworkRTT, attrs)
		mc.proberDelay.Record(ctx, rtt.ProberDelay, attrs)
		mc.responderDelay.Record(ctx, rtt.ResponderDelay, attrs)
		mc.probeSuccess.Add(ctx, 1, attrs)
	} else {
		mc.probeFailed.Add(ctx, 1, metric.WithAttributes(
			attribute.String("source_tor", sourceTorID),
			attribute.String("target_tor", result.TargetTorID),
			attribute.String("reason", probeFailureReason(result, rtt)),
		))
	}

	// Log GID-level detail at Debug level. This provides per-flow
	// visibility without metric cardinality cost.
	mc.logger.Debug().
		Str("target_gid", probe.FormatGID(result.TargetGID)).
		Str("source_tor", sourceTorID).
		Str("target_tor", result.TargetTorID).
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
		Msg("Probe result recorded")
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

// Shutdown gracefully shuts down the MeterProvider, flushing any buffered
// metrics to the collector before returning.
func (mc *MetricsCollector) Shutdown(ctx context.Context) error {
	mc.logger.Info().Msg("Shutting down MetricsCollector")
	return mc.meterProvider.Shutdown(ctx)
}

// StartResultConsumer starts a goroutine that reads probe results from
// resultChan, calculates RTT metrics via probe.CalculateRTT, and records
// them. The goroutine runs until ctx is cancelled or resultChan is closed.
// sourceTorID identifies the local agent's ToR switch for metric attribution.
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

				// Calculate RTT from the 6-timestamp probe result.
				rtt := probe.CalculateRTT(result)
				mc.RecordProbeResult(result, rtt, sourceTorID)
			}
		}
	}()
}
