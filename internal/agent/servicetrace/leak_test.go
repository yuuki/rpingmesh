package servicetrace

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if a goroutine its tests started (tracer
// readers and bounded snapshot workers) is still running once they have
// finished.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
