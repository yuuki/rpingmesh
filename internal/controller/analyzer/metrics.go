package analyzer

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds the analyzer's OTLP instruments. All attributes are ToR-level
// only (network, source_tor, target_tor, kind), matching the project-wide
// convention of never using GID-level cardinality on metrics; GID detail goes
// to findings logs. A nil *Metrics is a valid no-op, so the analyzer can run
// (logs only) when metrics export is unavailable.
type Metrics struct {
	slaViolations metric.Int64Counter
	pathSummaries metric.Int64Counter
}

// NewMetrics registers the analyzer instruments on the given meter. The meter
// is expected to come from a MeterProvider tagged service.name=rpingmesh-analyzer.
func NewMetrics(meter metric.Meter) (*Metrics, error) {
	pathSummaries, err := meter.Int64Counter(
		"rpingmesh.analyzer.path_summaries_total",
		metric.WithDescription("Total number of per-path window summaries ingested by the analyzer"),
		metric.WithUnit("{summary}"),
	)
	if err != nil {
		return nil, fmt.Errorf("create path_summaries_total counter: %w", err)
	}

	slaViolations, err := meter.Int64Counter(
		"rpingmesh.analyzer.sla_violations_total",
		metric.WithDescription("Total number of SLO violations detected (by network: cluster or service; by kind: loss or rtt)"),
		metric.WithUnit("{violation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("create sla_violations_total counter: %w", err)
	}

	return &Metrics{
		slaViolations: slaViolations,
		pathSummaries: pathSummaries,
	}, nil
}

// recordSummary increments the ingested-summary counter.
func (m *Metrics) recordSummary(ctx context.Context) {
	if m == nil {
		return
	}
	m.pathSummaries.Add(ctx, 1)
}

// recordViolation increments the violation counter for the given network
// (NetworkCluster or NetworkService), ToR pair and violation kind. The
// network attribute is what lets a dashboard keep the two networks apart;
// a sum over it gives the series the counter carried before service paths
// were evaluated.
func (m *Metrics) recordViolation(ctx context.Context, network, sourceTor, targetTor, kind string) {
	if m == nil {
		return
	}
	m.slaViolations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("network", network),
		attribute.String("source_tor", sourceTor),
		attribute.String("target_tor", targetTor),
		attribute.String("kind", kind),
	))
}
