package rdma

import (
	"context"
	"os"
	"testing"
	"time"
	"unsafe"
)

// TestProbePacket tests the structure and alignment of ProbePacket
func TestProbePacket(t *testing.T) {
	packet := ProbePacket{
		SequenceNum: 12345,
		T1:          uint64(time.Now().UnixNano()),
		T3:          uint64(time.Now().UnixNano() + 1000000),
		T4:          uint64(time.Now().UnixNano() + 2000000),
		IsAck:       1,
		AckType:     2,
		Flags:       3,
	}

	// Test structure size
	if size := unsafe.Sizeof(packet); size != 40 {
		t.Errorf("ProbePacket size is %d bytes, expected 40 bytes", size)
	}

	// Test field access
	if packet.SequenceNum != 12345 {
		t.Errorf("SequenceNum field is not correctly set")
	}

	if packet.IsAck != 1 || packet.AckType != 2 || packet.Flags != 3 {
		t.Errorf("Flag fields are not correctly set")
	}
}

// MockRDMADevice provides a mock implementation for testing RDMA devices
type MockRDMADevice struct {
	GID    string
	IPAddr string
	QPN    uint32
}

// MockRDMAManager provides a mock implementation for testing RDMA manager
type MockRDMAManager struct {
	Devices []*MockRDMADevice
	packets map[string][]ProbePacket // Map of target GID to packets sent
}

// NewMockRDMAManager creates a new mock RDMA manager
func NewMockRDMAManager() *MockRDMAManager {
	return &MockRDMAManager{
		Devices: []*MockRDMADevice{
			{GID: "fe80::1", IPAddr: "192.168.1.1", QPN: 1234},
			{GID: "fe80::2", IPAddr: "192.168.1.2", QPN: 5678},
		},
		packets: make(map[string][]ProbePacket),
	}
}

// MockSendProbe simulates sending a probe packet
func (m *MockRDMAManager) MockSendProbe(sourceGID, targetGID string, targetQPN uint32, seq uint64) (time.Time, error) {
	// Create a new probe packet
	now := time.Now()
	packet := ProbePacket{
		SequenceNum: seq,
		T1:          uint64(now.UnixNano()),
		IsAck:       0,
	}

	// Store the packet in the map
	m.packets[targetGID] = append(m.packets[targetGID], packet)
	return now, nil
}

// MockReceiveProbe simulates receiving a probe packet
func (m *MockRDMAManager) MockReceiveProbe(targetGID string) (*ProbePacket, time.Time, error) {
	// Check if there are any packets sent to this target
	packets, ok := m.packets[targetGID]
	if !ok || len(packets) == 0 {
		return nil, time.Time{}, nil
	}

	// Get the first packet (FIFO)
	packet := packets[0]
	m.packets[targetGID] = packets[1:]

	// Set T3 timestamp (receive time)
	receiveTime := time.Now()
	return &packet, receiveTime, nil
}

// MockSendAck simulates sending an ACK packet
func (m *MockRDMAManager) MockSendAck(sourceGID, targetGID string, targetQPN uint32, origPacket *ProbePacket, receiveTime time.Time, ackType uint8) (time.Time, error) {
	// Create a new ACK packet
	now := time.Now()
	packet := ProbePacket{
		SequenceNum: origPacket.SequenceNum,
		T1:          origPacket.T1,
		T3:          uint64(receiveTime.UnixNano()),
		T4:          uint64(now.UnixNano()),
		IsAck:       1,
		AckType:     ackType,
	}

	// Store the packet in the map
	m.packets[targetGID] = append(m.packets[targetGID], packet)
	return now, nil
}

// TestPacketSendReceive tests the packet send and receive flows using mocks
func TestPacketSendReceive(t *testing.T) {
	// Create mock manager
	mockManager := NewMockRDMAManager()

	// Define source and target
	sourceGID := mockManager.Devices[0].GID
	targetGID := mockManager.Devices[1].GID
	targetQPN := mockManager.Devices[1].QPN
	seqNum := uint64(1)

	// Step 1: Send probe from source to target
	sendTime, err := mockManager.MockSendProbe(sourceGID, targetGID, targetQPN, seqNum)
	if err != nil {
		t.Fatalf("Failed to send probe: %v", err)
	}

	// Step 2: Target receives the probe
	probePacket, receiveTime, err := mockManager.MockReceiveProbe(targetGID)
	if err != nil {
		t.Fatalf("Failed to receive probe: %v", err)
	}
	if probePacket == nil {
		t.Fatalf("No probe packet received")
	}

	// Verify probe packet
	if probePacket.SequenceNum != seqNum {
		t.Errorf("Wrong sequence number: got %d, want %d", probePacket.SequenceNum, seqNum)
	}
	if probePacket.IsAck != 0 {
		t.Errorf("Expected probe packet (IsAck=0), got ACK packet (IsAck=%d)", probePacket.IsAck)
	}

	// Step 3: Target sends first ACK
	_, err = mockManager.MockSendAck(targetGID, sourceGID, mockManager.Devices[0].QPN, probePacket, receiveTime, 1)
	if err != nil {
		t.Fatalf("Failed to send first ACK: %v", err)
	}

	// Step 4: Source receives first ACK
	firstAckPacket, _, err := mockManager.MockReceiveProbe(sourceGID)
	if err != nil {
		t.Fatalf("Failed to receive first ACK: %v", err)
	}
	if firstAckPacket == nil {
		t.Fatalf("No first ACK packet received")
	}

	// Verify first ACK packet
	if firstAckPacket.SequenceNum != seqNum {
		t.Errorf("Wrong sequence number in first ACK: got %d, want %d", firstAckPacket.SequenceNum, seqNum)
	}
	if firstAckPacket.IsAck != 1 {
		t.Errorf("Expected ACK packet (IsAck=1), got %d", firstAckPacket.IsAck)
	}
	if firstAckPacket.AckType != 1 {
		t.Errorf("Expected first ACK type (AckType=1), got %d", firstAckPacket.AckType)
	}

	// Step 5: Target sends second ACK with processing delay
	_, err = mockManager.MockSendAck(targetGID, sourceGID, mockManager.Devices[0].QPN, probePacket, receiveTime, 2)
	if err != nil {
		t.Fatalf("Failed to send second ACK: %v", err)
	}

	// Step 6: Source receives second ACK
	secondAckPacket, secondAckReceiveTime, err := mockManager.MockReceiveProbe(sourceGID)
	if err != nil {
		t.Fatalf("Failed to receive second ACK: %v", err)
	}
	if secondAckPacket == nil {
		t.Fatalf("No second ACK packet received")
	}

	// Verify second ACK packet
	if secondAckPacket.SequenceNum != seqNum {
		t.Errorf("Wrong sequence number in second ACK: got %d, want %d", secondAckPacket.SequenceNum, seqNum)
	}
	if secondAckPacket.IsAck != 1 {
		t.Errorf("Expected ACK packet (IsAck=1), got %d", secondAckPacket.IsAck)
	}
	if secondAckPacket.AckType != 2 {
		t.Errorf("Expected second ACK type (AckType=2), got %d", secondAckPacket.AckType)
	}

	// Verify timestamps
	if secondAckPacket.T3 <= 0 {
		t.Error("T3 timestamp in second ACK should be set")
	}
	if secondAckPacket.T4 <= 0 {
		t.Error("T4 timestamp in second ACK should be set")
	}
	if secondAckPacket.T4 <= secondAckPacket.T3 {
		t.Errorf("T4 (%d) should be greater than T3 (%d)", secondAckPacket.T4, secondAckPacket.T3)
	}

	// Calculate network RTT (as in the paper's formula)
	// Network RTT = (T5-T2) - (T4-T3)
	// Here we use t5 = secondAckReceiveTime, t2 = sendTime
	// and t4, t3 from the second ACK packet
	networkRTT := secondAckReceiveTime.Sub(sendTime) - time.Duration(secondAckPacket.T4-secondAckPacket.T3)
	t.Logf("Calculated network RTT: %v", networkRTT)

	// Verify RTT is reasonable (likely very small in mock case)
	if networkRTT < 0 {
		t.Errorf("Network RTT is negative: %v", networkRTT)
	}
}

// TestWorkCompletion tests the WorkCompletion structure
func TestWorkCompletion(t *testing.T) {
	wc := WorkCompletion{
		Status:    0, // IBV_WC_SUCCESS
		SrcQP:     1234,
		SGID:      "fe80::1",
		DGID:      "fe80::2",
		IMM:       5678,
		VendorErr: 0,
	}

	// Test field access
	if wc.Status != 0 || wc.SrcQP != 1234 || wc.SGID != "fe80::1" || wc.DGID != "fe80::2" || wc.IMM != 5678 || wc.VendorErr != 0 {
		t.Errorf("WorkCompletion fields are not correctly set")
	}
}

// CgoMock provides a way to mock C functions for testing without real RDMA hardware
type CgoMock struct {
	// Mock C function return values
	RetCodes map[string]int
	// Mock GID for devices
	MockGID string
}

func NewCgoMock() *CgoMock {
	return &CgoMock{
		RetCodes: map[string]int{
			"ibv_open_device":  0,
			"ibv_alloc_pd":     0,
			"ibv_query_port":   0,
			"ibv_query_gid":    0,
			"ibv_create_cq":    0,
			"ibv_create_qp":    0,
			"ibv_modify_qp":    0,
			"ibv_post_recv":    0,
			"ibv_post_send":    0,
			"ibv_poll_cq":      0,
			"ibv_create_ah":    0,
			"ibv_destroy_ah":   0,
			"ibv_destroy_qp":   0,
			"ibv_destroy_cq":   0,
			"ibv_dealloc_pd":   0,
			"ibv_close_device": 0,
		},
		MockGID: "fe80::3",
	}
}

// TestUDQueueOperations tests the UDQueue operations with mocked C functions
func TestUDQueueOperationsWithMock(t *testing.T) {
	t.Skip("This test requires additional mocking of C functions")

	// This test would require creating a mock version of the RDMA library calls
	// Since we're using C bindings (CGo), this requires more complex setup to intercept
	// the C function calls, which is beyond the scope of a simple unit test.
	//
	// In a real-world scenario, we would create a proper abstraction layer
	// around the C functions to make them more testable, or use a library
	// that supports mocking C functions.
	//
	// For now, we'll focus on testing the Go logic and data structures.
}

// TestAddressHandle tests the address handle creation functionality
func TestAddressHandle(t *testing.T) {
	t.Skip("This test requires a real RDMA environment or complex CGo mocking")

	// This test would verify that CreateAddressHandle properly formats
	// the address handle attributes and correctly calls the C functions.
	//
	// Without real hardware or advanced mocking of CGo functions, we can only
	// verify the packet structure and communication flow logic.
}

// TestRDMAEnvironmentDetection tests whether the RDMA environment is properly detected
// This test will be skipped if no RDMA devices are present
func TestRDMAEnvironmentDetection(t *testing.T) {
	// Skip this test if running in a CI environment without RDMA hardware
	// CI環境の検出にはCI環境変数を使用する
	if os.Getenv("CI") != "" {
		t.Skip("Skipping RDMA hardware detection test in CI environment")
	}

	// Try to create a real RDMA manager
	manager, err := NewRDMAManager()
	if err != nil {
		t.Skipf("RDMA environment not detected, skipping test: %v", err)
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
	err = device.OpenDevice()
	if err != nil {
		t.Errorf("Failed to open RDMA device: %v", err)
	}

	// Log device information
	t.Logf("Opened device: %s, GID: %s, IP: %s", device.DeviceName, device.GID, device.IPAddr)
}

// If hardware is available, run an actual end-to-end test
func TestEndToEndWithRealHardware(t *testing.T) {
	// Skip this test in CI environments or if hardware not available
	if os.Getenv("CI") != "" {
		t.Skip("Skipping end-to-end test in CI environment")
	}

	// Create an RDMA manager
	manager, err := NewRDMAManager()
	if err != nil {
		t.Skipf("Could not create RDMA manager: %v", err)
	}
	defer manager.Close()

	// Skip if no devices
	if len(manager.Devices) == 0 {
		t.Skip("No RDMA devices found")
	}

	// Open first device
	device := manager.Devices[0]
	err = device.OpenDevice()
	if err != nil {
		t.Skipf("Could not open device: %v", err)
	}

	// Create UDQueue (requires real RDMA device)
	udQueue, err := manager.CreateUDQueue(device, UDQueueTypeSender)
	if err != nil {
		t.Skipf("Could not create UDQueue: %v", err)
	}
	defer udQueue.Destroy()

	// Log UDQueue information
	t.Logf("Created UDQueue with QPN: %d on device: %s", udQueue.QPN, device.DeviceName)

	// Post a receive buffer
	err = udQueue.PostRecv()
	if err != nil {
		t.Fatalf("Failed to post receive buffer: %v", err)
	}
	t.Log("Successfully posted receive buffer")

	// Only attempt to send to self if we have proper permissions and this is not a CI environment
	if os.Getenv("TEST_RDMA_LOOPBACK") == "1" {
		// Send a probe to ourselves (loopback test) - requires special permissions
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		sendTime, err := udQueue.SendProbePacket(ctx, device.GID, udQueue.QPN, 12345, 0, 0)
		if err != nil {
			t.Logf("Send probe failed (expected in some environments): %v", err)
		} else {
			t.Logf("Successfully sent probe packet at %v", sendTime)

			// Try to receive the packet (with short timeout)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			packet, receiveTime, wc, err := udQueue.ReceivePacket(ctx)
			if err != nil {
				t.Logf("Receive failed (may be expected): %v", err)
			} else if packet != nil {
				t.Logf("Received packet: seq=%d, ack=%d at %v",
					packet.SequenceNum, packet.IsAck, receiveTime)
				t.Logf("WorkCompletion: srcQP=%d, sgid=%s", wc.SrcQP, wc.SGID)
			}
		}
	}
}
