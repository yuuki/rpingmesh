package telemetry

import (
	"context"
	"sort"

	"github.com/yuuki/rpingmesh/internal/probe"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// WithServiceLabels enables the service attribute on service probe metrics
// and connection/flow gauges. Only these configured names and _unspecified
// can be exported. An empty allow-list preserves the default attributes.
func WithServiceLabels(labels []string) Option {
	return func(o *collectorOptions) {
		o.serviceLabels = make(map[string]bool, len(labels))
		for _, label := range labels {
			if label != "" {
				o.serviceLabels[label] = true
			}
		}
	}
}

func (mc *MetricsCollector) serviceLabel(label string) string {
	if mc.serviceLabels[label] {
		return label
	}
	return probe.UnspecifiedServiceLabel
}

func (mc *MetricsCollector) services(labels []string) []string {
	if len(mc.serviceLabels) == 0 {
		return []string{""}
	}
	seen := make(map[string]bool)
	for _, label := range labels {
		seen[mc.serviceLabel(label)] = true
	}
	if len(seen) == 0 {
		seen[probe.UnspecifiedServiceLabel] = true
	}
	out := make([]string, 0, len(seen))
	for label := range seen {
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

func (mc *MetricsCollector) recordServiceProbe(ctx context.Context, result *probe.ProbeResult, outcome probeOutcome, labels probeLabels) {
	for _, service := range mc.services(result.Services) {
		attrs := labels.attributes(true)
		noTarget := labels.attributes(false)
		if len(mc.serviceLabels) > 0 {
			label := attribute.String("service", service)
			attrs = append(attrs, label)
			noTarget = append(noTarget, label)
		}
		prober, responder := metric.WithAttributes(noTarget...), metric.WithAttributes(noTarget...)
		if mc.proberDelayTargetTor {
			prober = metric.WithAttributes(attrs...)
		}
		if mc.responderDelayTargetTor {
			responder = metric.WithAttributes(attrs...)
		}
		mc.service.record(ctx, outcome, attrs, prober, responder)
	}
}

// Aggregate after normalization so several unknown names cannot produce
// duplicate observations of one gauge series in a collection cycle.
func (mc *MetricsCollector) serviceDeviceSamples(samples []ServiceTracingDevice) []ServiceTracingDevice {
	type key struct{ device, service string }
	counts := make(map[key]ServiceTracingDevice)
	for _, d := range samples {
		service := ""
		if len(mc.serviceLabels) > 0 {
			service = mc.serviceLabel(d.Service)
		}
		k := key{deviceMetricLabel(d.RdmaDevice), service}
		total := counts[k]
		total.RdmaDevice, total.Service = k.device, k.service
		total.Connections += d.Connections
		total.FlowsProbed += d.FlowsProbed
		total.FlowsUnresolved += d.FlowsUnresolved
		counts[k] = total
	}
	out := make([]ServiceTracingDevice, 0, len(counts))
	for _, d := range counts {
		out = append(out, d)
	}
	return out
}
