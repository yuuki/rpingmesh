package telemetry

import (
	"testing"

	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
)

// serviceNameOf returns the service.name attribute value from a resource
// built by buildResource, or ("", false) if it is not present.
func serviceNameOf(t *testing.T, serviceName string) (string, bool) {
	t.Helper()

	res, err := buildResource(serviceName)
	if err != nil {
		t.Fatalf("buildResource(%q) returned error: %v", serviceName, err)
	}

	for _, kv := range res.Attributes() {
		if kv.Key == semconv.ServiceNameKey {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

// TestBuildResource_DefaultServiceName verifies that NewMetricsCollector's
// zero-option behavior (service.name="rpingmesh-agent") is preserved.
func TestBuildResource_DefaultServiceName(t *testing.T) {
	got, ok := serviceNameOf(t, defaultServiceName)
	if !ok {
		t.Fatal("service.name attribute not found in resource")
	}
	if got != "rpingmesh-agent" {
		t.Errorf("service.name = %q, want rpingmesh-agent", got)
	}
}

// TestWithServiceName_Overrides verifies that the WithServiceName option
// value flows through to the OTel resource's service.name attribute.
func TestWithServiceName_Overrides(t *testing.T) {
	options := collectorOptions{serviceName: defaultServiceName}
	WithServiceName("rpingmesh-controller")(&options)

	if options.serviceName != "rpingmesh-controller" {
		t.Fatalf("collectorOptions.serviceName = %q, want rpingmesh-controller", options.serviceName)
	}

	got, ok := serviceNameOf(t, options.serviceName)
	if !ok {
		t.Fatal("service.name attribute not found in resource")
	}
	if got != "rpingmesh-controller" {
		t.Errorf("service.name = %q, want rpingmesh-controller", got)
	}
}
