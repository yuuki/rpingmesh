package telemetry

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if a goroutine its tests started (result
// consumers, meter providers and OTLP test servers) is still running once
// they have finished.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
