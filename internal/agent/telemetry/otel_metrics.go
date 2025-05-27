package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Metrics contains all the metrics instruments for the agent
type Metrics struct {
	provider *sdkmetric.MeterProvider
	meter    metric.Meter

	// Network RTT (Round-Trip Time)
	nwRttGauge     metric.Int64Gauge
	nwRttHistogram metric.Int64Histogram

	// Host processing delay as Histogram
	proberDelayGauge        metric.Int64Gauge
	proberDelayHistogram    metric.Int64Histogram
	responderDelayGauge     metric.Int64Gauge
	responderDelayHistogram metric.Int64Histogram

	// Timeout counter
	timeoutCounter metric.Int64Counter
}

// NewMetrics creates a new metrics instance
func NewMetrics(ctx context.Context, agentID, collectorAddr string) (*Metrics, error) {
	// Parse the collector address
	parsedURL, err := url.Parse(collectorAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse otel-collector-addr '%s': %w", collectorAddr, err)
	}

	// Determine exporter endpoint (host and port)
	exporterEndpoint := parsedURL.Host
	if parsedURL.Host == "" { // If host is empty (e.g. schemeless addr like "localhost:4317")
		if parsedURL.Path != "" && !strings.Contains(parsedURL.Path, "/") { // Path might contain host:port
			exporterEndpoint = parsedURL.Path
		} else if parsedURL.Opaque != "" && !strings.Contains(parsedURL.Opaque, "/") { // Opaque might contain host:port for some schemeless URIs
			exporterEndpoint = parsedURL.Opaque
		} else if collectorAddr != "" && !strings.Contains(collectorAddr, "/") && strings.Contains(collectorAddr, ":") { // Original addr as last resort if it looks like host:port
			exporterEndpoint = collectorAddr
		} else {
			return nil, fmt.Errorf("otel-collector-addr '%s' is missing a host or is not a valid schemeless address (e.g. localhost:4317)", collectorAddr)
		}
	}

	// Default scheme to grpc if not specified and we derived a valid endpoint
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "grpc"
	}

	// Create a resource that identifies our agent
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("rpingmesh-agent"),
			semconv.ServiceVersion("0.1.0"),
			semconv.ServiceInstanceID(agentID),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create OTLP exporter based on configuration
	var exporter sdkmetric.Exporter
	switch strings.ToLower(parsedURL.Scheme) {
	case "grpc":
		exporter, err = otlpmetricgrpc.New(
			ctx,
			otlpmetricgrpc.WithEndpoint(exporterEndpoint),
			otlpmetricgrpc.WithInsecure(),
		)
	case "grpcs":
		exporter, err = otlpmetricgrpc.New(
			ctx,
			otlpmetricgrpc.WithEndpoint(exporterEndpoint),
		)
	case "http", "https":
		options := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpoint(exporterEndpoint),
		}
		if parsedURL.Scheme == "http" {
			options = append(options, otlpmetrichttp.WithInsecure())
		} // For https, secure transport is default
		exporter, err = otlpmetrichttp.New(ctx, options...)
	default:
		return nil, fmt.Errorf("unsupported OTLP exporter protocol scheme: '%s' in %s. Use 'grpc', 'grpcs', 'http', or 'https'", parsedURL.Scheme, collectorAddr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter (%s://%s): %w", parsedURL.Scheme, exporterEndpoint, err)
	}

	// Create meter provider with the exporter
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(
				exporter,
				sdkmetric.WithInterval(10*time.Second),
			),
		),
	)

	// Set the global meter provider
	otel.SetMeterProvider(provider)

	// Get a meter
	meter := provider.Meter("github.com/yuuki/rpingmesh/agent")

	// Create Network RTT meter
	nwRttGauge, err := meter.Int64Gauge(
		"rpingmesh.nwrtt",
		metric.WithDescription("Network Round-Trip Time in nanoseconds"),
		metric.WithUnit("ns"),
	)
	if err != nil {
		return nil, err
	}
	nwRttHistogram, err := meter.Int64Histogram(
		"rpingmesh.nwrtt",
		metric.WithDescription("Network Round-Trip Time in nanoseconds"),
		metric.WithUnit("ns"),
	)
	if err != nil {
		return nil, err
	}

	proberDelayGauge, err := meter.Int64Gauge(
		"rpingmesh.prober_delay",
		metric.WithDescription("Prober processing delay in nanoseconds"),
		metric.WithUnit("ns"),
	)
	if err != nil {
		return nil, err
	}
	proberDelayHistogram, err := meter.Int64Histogram(
		"rpingmesh.prober_delay",
		metric.WithDescription("Prober processing delay in nanoseconds"),
		metric.WithUnit("ns"),
	)
	if err != nil {
		return nil, err
	}

	responderDelayGauge, err := meter.Int64Gauge(
		"rpingmesh.responder_delay",
		metric.WithDescription("Responder processing delay in nanoseconds"),
		metric.WithUnit("ns"),
	)
	if err != nil {
		return nil, err
	}
	responderDelayHistogram, err := meter.Int64Histogram(
		"rpingmesh.responder_delay",
		metric.WithDescription("Responder processing delay in nanoseconds"),
		metric.WithUnit("ns"),
	)
	if err != nil {
		return nil, err
	}
	// Create timeout counter
	timeoutCounter, err := meter.Int64Counter(
		"rpingmesh.timeout",
		metric.WithDescription("Number of probe timeouts"),
		metric.WithUnit("{count}"),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		provider:                provider,
		meter:                   meter,
		nwRttGauge:              nwRttGauge,
		nwRttHistogram:          nwRttHistogram,
		proberDelayGauge:        proberDelayGauge,
		proberDelayHistogram:    proberDelayHistogram,
		responderDelayGauge:     responderDelayGauge,
		responderDelayHistogram: responderDelayHistogram,
		timeoutCounter:          timeoutCounter,
	}, nil
}

// RecordRTT records a RTT measurement
func (m *Metrics) RecordRTT(ctx context.Context, rttNs int64, attributes ...metric.RecordOption) {
	m.nwRttGauge.Record(ctx, rttNs, attributes...)
	m.nwRttHistogram.Record(ctx, rttNs, attributes...)
}

// RecordTimeout records a probe timeout
func (m *Metrics) RecordTimeout(ctx context.Context, attributes ...metric.AddOption) {
	m.timeoutCounter.Add(ctx, 1, attributes...)
}

// RecordProberDelay records a prober processing delay
func (m *Metrics) RecordProberDelay(ctx context.Context, delayNs int64, attributes ...metric.RecordOption) {
	m.proberDelayGauge.Record(ctx, delayNs, attributes...)
	m.proberDelayHistogram.Record(ctx, delayNs, attributes...)
}

// RecordResponderDelay records a responder processing delay
func (m *Metrics) RecordResponderDelay(ctx context.Context, delayNs int64, attributes ...metric.RecordOption) {
	m.responderDelayGauge.Record(ctx, delayNs, attributes...)
	m.responderDelayHistogram.Record(ctx, delayNs, attributes...)
}

// Shutdown stops the metrics provider
func (m *Metrics) Shutdown(ctx context.Context) error {
	return m.provider.Shutdown(ctx)
}
