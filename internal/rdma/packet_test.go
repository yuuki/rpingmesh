package rdma

import (
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
