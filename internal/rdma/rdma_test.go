package rdma

import (
	"time"
)

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

	// Make a copy of the packet to return (to avoid modifying the original)
	returnPacket := packet

	// Remove the packet from the queue
	m.packets[targetGID] = packets[1:]

	// Set receive time
	receiveTime := time.Now()
	return &returnPacket, receiveTime, nil
}

// MockSendAck simulates sending an ACK packet
func (m *MockRDMAManager) MockSendAck(sourceGID, targetGID string, targetQPN uint32, origPacket *ProbePacket, receiveTime time.Time, ackType uint8) (time.Time, error) {
	// Create a new ACK packet - preserve the sequence number from the original packet
	now := time.Now()
	packet := ProbePacket{
		SequenceNum: origPacket.SequenceNum, // Important: Keep the same sequence number
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
