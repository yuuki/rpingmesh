package controller_client

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if a goroutine its tests started (gRPC servers
// and client connections) is still running once they have finished.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
