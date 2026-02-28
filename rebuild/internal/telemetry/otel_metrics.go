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
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
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

// MetricsCollector collects and exports R-Pingmesh probe metrics via OTLP.
// All recorded metrics use ToR-level attributes (source_tor, target_tor) to
// maintain low cardinality. GID-level detail is emitted only in debug logs.
type MetricsCollector struct {
	meterProvider  *sdkmetric.MeterProvider
	networkRTT     metric.Int64Histogram // nanoseconds
	proberDelay    metric.Int64Histogram // nanoseconds
	responderDelay metric.Int64Histogram // nanoseconds
	probeSuccess   metric.Int64Counter
	probeFailed    metric.Int64Counter
	probeTotal     metric.Int64Counter
	logger         zerolog.Logger
}

// NewMetricsCollector creates a MetricsCollector that exports OTLP metrics
// to the given gRPC collector address (e.g., "localhost:4317"). It sets up:
//   - An OTLP gRPC exporter (insecure) targeting collectorAddr
//   - A MeterProvider with a periodic reader flushing every 10 seconds
//   - Histogram instruments for network RTT, prober delay, responder delay
//   - Counter instruments for probe success, failure, and total counts
func NewMetricsCollector(ctx context.Context, collectorAddr string) (*MetricsCollector, error) {
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
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("rpingmesh-agent"),
			semconv.ServiceVersion("0.1.0"),
		),
	)
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

	logger := log.With().Str("component", "telemetry").Logger()
	logger.Info().
		Str("collector_addr", collectorAddr).
		Dur("flush_interval", periodicReaderInterval).
		Msg("MetricsCollector initialized")

	return &MetricsCollector{
		meterProvider:  provider,
		networkRTT:     networkRTT,
		proberDelay:    proberDelay,
		responderDelay: responderDelay,
		probeSuccess:   probeSuccess,
		probeFailed:    probeFailed,
		probeTotal:     probeTotal,
		logger:         logger,
	}, nil
}

// RecordProbeResult records metrics for a single completed probe.
// It uses only ToR-level attributes (source_tor, target_tor) for metric
// dimensions to keep cardinality low. GID-level details are logged at
// Debug level for troubleshooting without inflating metric series count.
//
// If result.Success is true and rtt.Valid is true, the RTT histograms and
// success counter are incremented. Otherwise, only the failure counter is
// incremented. The total counter is always incremented.
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
		mc.probeFailed.Add(ctx, 1, attrs)
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
