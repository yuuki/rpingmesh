package controller

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if a goroutine its tests started (gRPC servers
// of the mTLS integration tests) is still running once they have finished.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
