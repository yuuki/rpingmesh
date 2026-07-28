package rdma

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRDMAManager tests the RDMAManager functionality
func TestRDMAManager(t *testing.T) {
	// Create a new mock RDMA manager for testing
	mockManager := NewMockRDMAManager()
	assert.NotNil(t, mockManager)
	assert.Equal(t, 2, len(mockManager.Devices))

	// Verify the mock devices were created correctly
	assert.Equal(t, "fe80::1", mockManager.Devices[0].GID)
	assert.Equal(t, "192.168.1.1", mockManager.Devices[0].IPAddr)
	assert.Equal(t, uint32(1234), mockManager.Devices[0].QPN)

	assert.Equal(t, "fe80::2", mockManager.Devices[1].GID)
	assert.Equal(t, "192.168.1.2", mockManager.Devices[1].IPAddr)
	assert.Equal(t, uint32(5678), mockManager.Devices[1].QPN)

	// Test basic send/receive functions
	// --------------------------------

	// Send a probe from device 1 to device 2
	seq := uint64(42)
	sendTime, err := mockManager.MockSendProbe("fe80::1", "fe80::2", 5678, seq)
	assert.NoError(t, err)
	assert.False(t, sendTime.IsZero())

	// Verify the packet was stored correctly
	packets, ok := mockManager.packets["fe80::2"]
	assert.True(t, ok)
	assert.Equal(t, 1, len(packets))
	assert.Equal(t, seq, packets[0].SequenceNum)
	assert.Equal(t, uint8(0), packets[0].IsAck)

	// Receive the probe at device 2
	packet, receiveTime, err := mockManager.MockReceiveProbe("fe80::2")
	assert.NoError(t, err)
	assert.False(t, receiveTime.IsZero())
	assert.NotNil(t, packet)
	assert.Equal(t, seq, packet.SequenceNum)

	// Send an ACK from device 2 back to device 1
	ackTime, err := mockManager.MockSendAck("fe80::2", "fe80::1", 1234, packet, receiveTime, 1)
	assert.NoError(t, err)
	assert.False(t, ackTime.IsZero())

	// Verify the ACK packet was created correctly
	packets, ok = mockManager.packets["fe80::1"]
	assert.True(t, ok)
	assert.Equal(t, 1, len(packets))
	assert.Equal(t, seq, packets[0].SequenceNum)
	assert.Equal(t, uint8(1), packets[0].IsAck)
	assert.Equal(t, uint8(1), packets[0].AckType)

	// Receive the ACK at device 1
	ackPacket, _, err := mockManager.MockReceiveProbe("fe80::1")
	assert.NoError(t, err)
	assert.NotNil(t, ackPacket)
	assert.Equal(t, seq, ackPacket.SequenceNum)
	assert.Equal(t, uint8(1), ackPacket.IsAck)

	// Test a different sequence number
	// --------------------------------

	// Send another probe with a different sequence number
	seq2 := uint64(99)
	_, err = mockManager.MockSendProbe("fe80::1", "fe80::2", 5678, seq2)
	assert.NoError(t, err)

	// Receive the second probe
	probe2, receiveTime2, err := mockManager.MockReceiveProbe("fe80::2")
	assert.NoError(t, err)
	assert.NotNil(t, probe2)
	assert.Equal(t, seq2, probe2.SequenceNum, "Second probe should have sequence number 99")

	// Send ACK for the second probe
	_, err = mockManager.MockSendAck("fe80::2", "fe80::1", 1234, probe2, receiveTime2, 0)
	assert.NoError(t, err)

	// Receive the second ACK
	ack2, _, err := mockManager.MockReceiveProbe("fe80::1")
	assert.NoError(t, err)
	assert.NotNil(t, ack2)
	assert.Equal(t, seq2, ack2.SequenceNum, "Second ACK should have sequence number 99")
	assert.Equal(t, uint8(1), ack2.IsAck)

	// Calculate RTT as would be done in a real application
	rtt := ack2.T4 - ack2.T3
	assert.Greater(t, rtt, uint64(0), "RTT should be greater than 0")
}

// TestRDMAEnvironmentDetection tests whether the RDMA environment is properly detected
// This test will be skipped if no RDMA devices are present
func TestRDMAEnvironmentDetection(t *testing.T) {
	// Skip this test if running in a CI environment without RDMA hardware
	if os.Getenv("CI") != "" {
		t.Skip("Skipping RDMA hardware detection test in CI environment")
	}

	// Try to create a real RDMA manager
	manager, err := NewRDMAManager()
	if err != nil {
		t.Skipf("RDMA environment not detected, skipping test: %v", err)
	}
	if manager == nil {
		t.Skipf("RDMA environment not detected (manager is nil after successful NewRDMAManager call), skipping test")
	}
	defer manager.Close()

	// Verify we found some devices
	if len(manager.Devices) == 0 {
		t.Skip("No RDMA devices found, skipping test")
	}

	t.Logf("Found %d RDMA devices", len(manager.Devices))
	for i, device := range manager.Devices {
		t.Logf("Device %d: %s", i, device.DeviceName)
	}

	// Test opening a device
	device := manager.Devices[0]
	if err := device.OpenDevice(0); err != nil {
		t.Errorf("Failed to open RDMA device: %v", err)
	}

	// Log device information
	t.Logf("Opened device: %s, GID: %s, IP: %s", device.DeviceName, device.GID, device.IPAddr)
}

// TestRNICOperations tests the RNIC operations
func TestRNICOperations(t *testing.T) {
	// Currently skipping until we can resolve import issues
	t.Skip("Skipping TestRNICOperations until import issues are resolved")
}
