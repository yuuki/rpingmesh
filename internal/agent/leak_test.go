package agent

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if a goroutine its tests started (probers,
// responders, monitors and their ring loops) is still running once they have
// finished.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
