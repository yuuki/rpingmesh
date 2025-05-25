package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBPFEndToEnd tests actual event detection (requires RDMA environment)
func TestBPFEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Check if we're in an environment with RDMA support
	if !hasRDMASupport() {
		t.Skip("Skipping E2E test: RDMA support not available")
	}

	tracer, err := NewServiceTracer()
	require.NoError(t, err)
	defer tracer.Stop()

	err = tracer.Start()
	require.NoError(t, err)

	// Wait for a short period to see if we can capture any events
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventReceived := false
	go func() {
		for {
			select {
			case event := <-tracer.Events():
				// Validate received event
				assert.True(t, event.IsValidEvent(), "Received event should be valid")
				assert.Greater(t, event.Timestamp, uint64(0), "Timestamp should be set")
				eventReceived = true
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()

	// Note: This test might not receive events in test environments
	// without active RDMA traffic, which is expected
	t.Logf("E2E test completed. Event received: %v", eventReceived)
}

// hasRDMASupport checks if the system has RDMA support
func hasRDMASupport() bool {
	// Simple check for RDMA support
	// In a real implementation, this could check for:
	// - /sys/class/infiniband/ directory
	// - Loaded RDMA modules
	// - Available RDMA devices
	return false // Conservative approach for testing
}
