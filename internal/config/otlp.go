package config

import (
	"fmt"
	"strings"
)

// validateOTLPEndpoint rejects collector addresses carrying a URL scheme.
// The OTLP gRPC exporter is configured with WithEndpoint, which expects a
// bare host:port; a value such as "grpc://host:4317" is accepted at startup
// but every export then fails ("too many colons in address"), leaving the
// process running with no metrics. Failing fast at config load surfaces the
// mistake immediately.
func validateOTLPEndpoint(addr string) error {
	if strings.Contains(addr, "://") {
		return fmt.Errorf("otel_collector_addr must be host:port without a URL scheme, got: %q", addr)
	}
	return nil
}
