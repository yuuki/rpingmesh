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
	// meter registers the localization instruments, which exist only when
	// localization is enabled (see registerLocalization).
	meter metric.Meter

	sloViolations metric.Int64Counter
	pathSummaries metric.Int64Counter

	// Localization instruments; nil until registerLocalization succeeds.
	localizationRuns    metric.Int64Counter
	localizationDropped metric.Int64Counter
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

	sloViolations, err := meter.Int64Counter(
		"rpingmesh.analyzer.slo_violations_total",
		metric.WithDescription("Total number of SLO violations detected (by network: cluster or service; by kind: loss or rtt)"),
		metric.WithUnit("{violation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("create slo_violations_total counter: %w", err)
	}

	return &Metrics{
		meter:         meter,
		sloViolations: sloViolations,
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
	m.sloViolations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("network", network),
		attribute.String("source_tor", sourceTor),
		attribute.String("target_tor", targetTor),
		attribute.String("kind", kind),
	))
}

// registerLocalization creates the Phase 2 instruments. They are registered
// only when localization is enabled, so a controller without it exports
// exactly the metrics it exported before. read returns the findings of the
// latest evaluation and is called once per collection cycle.
//
// The two gauges are observed from the current findings only, so a series
// ends when its finding clears instead of staying at zero. Their attributes
// are bounded by the fabric, never by its RNICs:
//
//   - kind: loss or rtt (2 values).
//   - state: localized, ambiguous or not_localizable (3 values).
//   - component: the seven component kinds.
//   - tor: a ToR ID, on rnic, tor and tor_uplink suspects (at most the
//     number of ToRs that report).
//   - spine_group, rail: names from the topology file (at most the number
//     of spine groups and rails it names).
//
// A suspected RNIC or host is counted under its kind (and, for an RNIC, its
// ToR); its GID and agent ID go to the finding's log line only. One
// evaluation reports at most maxSuspectsPerSignal findings of at most
// maxCandidates candidates per signal, so the series exported at any time
// are bounded by that product whatever the fabric's size.
func (m *Metrics) registerLocalization(read func() []Finding) error {
	if m == nil {
		return nil
	}
	runs, err := m.meter.Int64Counter(
		"rpingmesh.analyzer.localization_runs_total",
		metric.WithDescription("Total number of fault localization evaluations (one per change of the evidence span)"),
		metric.WithUnit("{run}"),
	)
	if err != nil {
		return fmt.Errorf("create localization_runs_total counter: %w", err)
	}
	dropped, err := m.meter.Int64Counter(
		"rpingmesh.analyzer.localization_dropped_paths_total",
		metric.WithDescription("Total number of path summaries left out of the localization evidence because a window reached analyzer_localization_max_paths_per_window"),
		metric.WithUnit("{path}"),
	)
	if err != nil {
		return fmt.Errorf("create localization_dropped_paths_total counter: %w", err)
	}
	suspects, err := m.meter.Int64ObservableGauge(
		"rpingmesh.analyzer.localization_suspects",
		metric.WithDescription("Components currently suspected by fault localization (by signal kind, component kind, state and ToR, spine group or rail)"),
		metric.WithUnit("{component}"),
	)
	if err != nil {
		return fmt.Errorf("create localization_suspects gauge: %w", err)
	}
	confidence, err := m.meter.Float64ObservableGauge(
		"rpingmesh.analyzer.localization_suspect_confidence",
		metric.WithDescription("Highest posterior probability (0..1) among the suspected components of an attribute set"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("create localization_suspect_confidence gauge: %w", err)
	}

	_, err = m.meter.RegisterCallback(
		func(_ context.Context, o metric.Observer) error {
			type series struct {
				count      int64
				confidence float64
			}
			// Several suspects can share an attribute set (two RNICs under
			// one ToR): they are counted, and the gauge of confidences
			// carries the highest.
			bySet := make(map[attribute.Set]*series)
			var order []attribute.Set
			for _, f := range read() {
				for _, s := range f.Suspects {
					set := suspectAttributes(f, s.Component)
					agg := bySet[set]
					if agg == nil {
						agg = &series{}
						bySet[set] = agg
						order = append(order, set)
					}
					agg.count++
					agg.confidence = max(agg.confidence, s.Confidence)
				}
			}
			for _, set := range order {
				agg := bySet[set]
				o.ObserveInt64(suspects, agg.count, metric.WithAttributeSet(set))
				o.ObserveFloat64(confidence, agg.confidence, metric.WithAttributeSet(set))
			}
			return nil
		},
		suspects, confidence,
	)
	if err != nil {
		return fmt.Errorf("register localization callback: %w", err)
	}

	m.localizationRuns = runs
	m.localizationDropped = dropped
	return nil
}

// suspectAttributes returns the metric attributes of one suspect of a
// finding: the signal kind, the state, the component kind and whichever of
// tor, spine_group and rail the component has. It never includes a GID or an
// agent ID.
func suspectAttributes(f Finding, c Component) attribute.Set {
	attrs := []attribute.KeyValue{
		attribute.String("kind", f.Signal),
		attribute.String("state", f.State),
		attribute.String("component", c.Kind),
	}
	if c.Tor != "" {
		attrs = append(attrs, attribute.String("tor", c.Tor))
	}
	if c.SpineGroup != "" {
		attrs = append(attrs, attribute.String("spine_group", c.SpineGroup))
	}
	if c.Rail != "" {
		attrs = append(attrs, attribute.String("rail", c.Rail))
	}
	return attribute.NewSet(attrs...)
}

// recordLocalizationRun increments the evaluation counter.
func (m *Metrics) recordLocalizationRun(ctx context.Context) {
	if m == nil || m.localizationRuns == nil {
		return
	}
	m.localizationRuns.Add(ctx, 1)
}

// recordDroppedPaths counts the path summaries a full window refused.
func (m *Metrics) recordDroppedPaths(ctx context.Context, n int) {
	if m == nil || m.localizationDropped == nil || n <= 0 {
		return
	}
	m.localizationDropped.Add(ctx, int64(n))
}
