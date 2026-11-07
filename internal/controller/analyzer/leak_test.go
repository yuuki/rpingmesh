package analyzer

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if a goroutine its tests started (meter
// providers and readers) is still running once they have finished.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
