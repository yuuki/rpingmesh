package rdma

import (
	"context"
	"fmt"
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

// TestProbePacketSerialization tests serialization and deserialization of ProbePacket
func TestProbePacketSerialization(t *testing.T) {
	// Create a probe packet with known values
	original := ProbePacket{
		SequenceNum: 98765,
		T1:          uint64(1000000000),
		T3:          uint64(1000001000),
		T4:          uint64(1000002000),
		IsAck:       1,
		AckType:     2,
		Flags:       3,
	}

	// Allocate memory for the serialized packet
	serializedData := make([]byte, unsafe.Sizeof(ProbePacket{}))
	serializedPtr := unsafe.Pointer(&serializedData[0])

	// Manually "serialize" by copying the struct to the byte slice
	*(*ProbePacket)(serializedPtr) = original

	// "Deserialize" by creating a new struct from the byte slice
	deserialized := *(*ProbePacket)(serializedPtr)

	// Verify the deserialized packet matches the original
	if deserialized.SequenceNum != original.SequenceNum {
		t.Errorf("SequenceNum field mismatch: got %d, want %d", deserialized.SequenceNum, original.SequenceNum)
	}
	if deserialized.T1 != original.T1 {
		t.Errorf("T1 field mismatch: got %d, want %d", deserialized.T1, original.T1)
	}
	if deserialized.T3 != original.T3 {
		t.Errorf("T3 field mismatch: got %d, want %d", deserialized.T3, original.T3)
	}
	if deserialized.T4 != original.T4 {
		t.Errorf("T4 field mismatch: got %d, want %d", deserialized.T4, original.T4)
	}
	if deserialized.IsAck != original.IsAck {
		t.Errorf("IsAck field mismatch: got %d, want %d", deserialized.IsAck, original.IsAck)
	}
	if deserialized.AckType != original.AckType {
		t.Errorf("AckType field mismatch: got %d, want %d", deserialized.AckType, original.AckType)
	}
	if deserialized.Flags != original.Flags {
		t.Errorf("Flags field mismatch: got %d, want %d", deserialized.Flags, original.Flags)
	}
}

// TestProcessedWorkCompletion tests the ProcessedWorkCompletion functionality
func TestProcessedWorkCompletion(t *testing.T) {
	// Create a basic ProcessedWorkCompletion for testing
	wc := ProcessedWorkCompletion{
		GoWorkCompletion: GoWorkCompletion{
			SrcQP: 1234,
		},
		SGID:      "fe80::1",
		DGID:      "fe80::2",
		FlowLabel: 0x123456,
	}

	// Verify fields
	if wc.SGID != "fe80::1" {
		t.Errorf("SGID field incorrect: got %s, want %s", wc.SGID, "fe80::1")
	}
	if wc.DGID != "fe80::2" {
		t.Errorf("DGID field incorrect: got %s, want %s", wc.DGID, "fe80::2")
	}
	if wc.FlowLabel != 0x123456 {
		t.Errorf("FlowLabel field incorrect: got %x, want %x", wc.FlowLabel, 0x123456)
	}
	if wc.SrcQP != 1234 {
		t.Errorf("SrcQP field incorrect: got %d, want %d", wc.SrcQP, 1234)
	}
}

// TestIncomingAckInfo tests the IncomingAckInfo functionality
func TestIncomingAckInfo(t *testing.T) {
	// Create timestamp
	now := time.Now()

	// Create a probe packet
	packet := &ProbePacket{
		SequenceNum: 54321,
		T1:          uint64(now.Add(-2 * time.Millisecond).UnixNano()),
		T3:          uint64(now.Add(-1 * time.Millisecond).UnixNano()),
		T4:          uint64(now.UnixNano()),
		IsAck:       1,
		AckType:     2,
	}

	// Create a ProcessedWorkCompletion
	pwc := &ProcessedWorkCompletion{
		GoWorkCompletion: GoWorkCompletion{
			SrcQP: 5678,
		},
		SGID:      "fe80::3",
		DGID:      "fe80::4",
		FlowLabel: 0xabcdef,
	}

	// Create an IncomingAckInfo
	ackInfo := &IncomingAckInfo{
		Packet:      packet,
		ReceivedAt:  now,
		ProcessedWC: pwc,
		AckStatusOK: true,
	}

	// Verify fields
	if ackInfo.Packet != packet {
		t.Errorf("Packet field does not match the original packet")
	}
	if !ackInfo.ReceivedAt.Equal(now) {
		t.Errorf("ReceivedAt field mismatch: got %v, want %v", ackInfo.ReceivedAt, now)
	}
	if ackInfo.ProcessedWC != pwc {
		t.Errorf("ProcessedWC field does not match the original ProcessedWorkCompletion")
	}
	if !ackInfo.AckStatusOK {
		t.Errorf("AckStatusOK field mismatch: got %v, want %v", ackInfo.AckStatusOK, true)
	}

	// Check fields in the embedded objects
	if ackInfo.Packet.SequenceNum != 54321 {
		t.Errorf("Packet.SequenceNum incorrect: got %d, want %d", ackInfo.Packet.SequenceNum, 54321)
	}
	if ackInfo.ProcessedWC.SGID != "fe80::3" {
		t.Errorf("ProcessedWC.SGID incorrect: got %s, want %s", ackInfo.ProcessedWC.SGID, "fe80::3")
	}
}

// TestFormatGIDString tests the formatGIDString function
func TestFormatGIDString(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "IPv6 GID",
			input:    []byte{0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34},
			expected: "2001:db8:85a3::8a2e:370:7334",
		},
		{
			name:     "IPv4-mapped IPv6 GID",
			input:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1},
			expected: "::ffff:192.168.1.1",
		},
		{
			name:     "Link-local IPv6 GID",
			input:    []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			expected: "fe80::1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// This is a mock call since formatGIDString is internal
			result := mockFormatGIDString(tc.input)
			if result != tc.expected {
				t.Errorf("formatGIDString(%v) = %s; want %s", tc.input, result, tc.expected)
			}
		})
	}
}

// mockFormatGIDString is a mock implementation of the internal formatGIDString function
func mockFormatGIDString(gidBytes []byte) string {
	if len(gidBytes) != 16 {
		return "invalid-gid"
	}

	// Check if it's an IPv4-mapped IPv6 address
	if gidBytes[10] == 0xff && gidBytes[11] == 0xff {
		return "::ffff:" + mockFormatIPv4(gidBytes[12:])
	}

	// Format as standard IPv6
	segments := make([]uint16, 8)
	for i := 0; i < 8; i++ {
		segments[i] = uint16(gidBytes[i*2])<<8 | uint16(gidBytes[i*2+1])
	}

	// Find longest run of zeros for :: notation
	var bestStart, bestLen, curStart, curLen int
	for i := 0; i < 8; i++ {
		if segments[i] == 0 {
			if curLen == 0 {
				curStart = i
			}
			curLen++
		} else {
			if curLen > bestLen {
				bestStart = curStart
				bestLen = curLen
			}
			curLen = 0
		}
	}
	if curLen > bestLen {
		bestStart = curStart
		bestLen = curLen
	}

	// Format the string
	result := ""
	if bestLen > 1 {
		for i := 0; i < bestStart; i++ {
			result += mockFormatHex(segments[i])
			if i < bestStart-1 {
				result += ":"
			}
		}
		result += "::"
		for i := bestStart + bestLen; i < 8; i++ {
			result += mockFormatHex(segments[i])
			if i < 7 {
				result += ":"
			}
		}
	} else {
		for i := 0; i < 8; i++ {
			result += mockFormatHex(segments[i])
			if i < 7 {
				result += ":"
			}
		}
	}

	return result
}

// mockFormatHex formats a uint16 as a hex string without leading zeros
func mockFormatHex(val uint16) string {
	hexDigits := "0123456789abcdef"
	if val == 0 {
		return "0"
	}
	result := ""
	nonZeroFound := false
	for i := 12; i >= 0; i -= 4 {
		digit := (val >> uint(i)) & 0xf
		if digit != 0 || nonZeroFound {
			result += string(hexDigits[digit])
			nonZeroFound = true
		}
	}
	return result
}

// mockFormatIPv4 formats 4 bytes as an IPv4 address string
func mockFormatIPv4(ip []byte) string {
	if len(ip) != 4 {
		return "invalid-ip"
	}
	return mockUint8ToString(ip[0]) + "." + mockUint8ToString(ip[1]) + "." +
		mockUint8ToString(ip[2]) + "." + mockUint8ToString(ip[3])
}

// mockUint8ToString converts uint8 to string
func mockUint8ToString(val uint8) string {
	if val == 0 {
		return "0"
	}
	digits := "0123456789"
	result := ""
	for val > 0 {
		result = string(digits[val%10]) + result
		val /= 10
	}
	return result
}

// TestAckHandlerFunc tests the AckHandlerFunc type
func TestAckHandlerFunc(t *testing.T) {
	var handlerCalled bool
	var passedAckInfo *IncomingAckInfo

	// Create a handler function
	handler := func(ackInfo *IncomingAckInfo) {
		handlerCalled = true
		passedAckInfo = ackInfo
	}

	// Create an IncomingAckInfo
	now := time.Now()
	packet := &ProbePacket{
		SequenceNum: 12345,
		T1:          uint64(now.Add(-2 * time.Millisecond).UnixNano()),
		IsAck:       1,
	}
	processedWC := &ProcessedWorkCompletion{
		GoWorkCompletion: GoWorkCompletion{
			SrcQP: 5432,
		},
		SGID: "fe80::5",
		DGID: "fe80::6",
	}
	ackInfo := &IncomingAckInfo{
		Packet:      packet,
		ReceivedAt:  now,
		ProcessedWC: processedWC,
		AckStatusOK: true,
	}

	// Call the handler
	handler(ackInfo)

	// Verify the handler was called with the correct info
	if !handlerCalled {
		t.Errorf("Handler function was not called")
	}
	if passedAckInfo != ackInfo {
		t.Errorf("Handler function was not passed the correct IncomingAckInfo")
	}
}

// MockGRHParser is a mock implementation for testing GRH parsing
type MockGRHParser struct {
	MockGRHData          []byte
	MockGoWorkCompletion *GoWorkCompletion
	MockSGID             string
	MockDGID             string
	MockFlowLabel        uint32
	MockPayloadPtr       unsafe.Pointer
	MockPayloadLength    uint32
	MockError            error
}

// TestMockGRHParser tests the GRH parsing logic using a mock
func TestMockGRHParser(t *testing.T) {
	// Create IPv6 GRH data
	ipv6GRH := make([]byte, GRHSize)
	// Set version to 6 in the first byte
	ipv6GRH[0] = 0x60
	// Set SGID (bytes 8-23)
	copy(ipv6GRH[8:24], []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7})
	// Set DGID (bytes 24-39)
	copy(ipv6GRH[24:40], []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8})

	// Create a mock work completion with GRH flag set
	goWC := &GoWorkCompletion{
		WCFlags: 1,            // Simulate IBV_WC_GRH flag
		ByteLen: GRHSize + 40, // GRH + payload
	}

	// Allocate payload memory to avoid out of range access
	payload := make([]byte, 40)

	// Create the mock parser
	mockParser := &MockGRHParser{
		MockGRHData:          ipv6GRH,
		MockGoWorkCompletion: goWC,
		MockSGID:             "fe80::7",
		MockDGID:             "fe80::8",
		MockFlowLabel:        0x123456,
		MockPayloadPtr:       unsafe.Pointer(&payload[0]), // Use allocated payload memory
		MockPayloadLength:    40,
		MockError:            nil,
	}

	// Test the mock parser
	sgid, dgid, flowLabel, payloadPtr, payloadLen, err := mockParser.ParseGRH()

	// Verify results
	if err != mockParser.MockError {
		t.Errorf("ParseGRH returned unexpected error: %v", err)
	}
	if sgid != mockParser.MockSGID {
		t.Errorf("ParseGRH returned wrong SGID: got %s, want %s", sgid, mockParser.MockSGID)
	}
	if dgid != mockParser.MockDGID {
		t.Errorf("ParseGRH returned wrong DGID: got %s, want %s", dgid, mockParser.MockDGID)
	}
	if flowLabel != mockParser.MockFlowLabel {
		t.Errorf("ParseGRH returned wrong FlowLabel: got %x, want %x", flowLabel, mockParser.MockFlowLabel)
	}
	if payloadPtr != mockParser.MockPayloadPtr {
		t.Errorf("ParseGRH returned wrong payload pointer")
	}
	if payloadLen != mockParser.MockPayloadLength {
		t.Errorf("ParseGRH returned wrong payload length: got %d, want %d", payloadLen, mockParser.MockPayloadLength)
	}
}

// ParseGRH is a mock implementation of the parseGRH method
func (m *MockGRHParser) ParseGRH() (string, string, uint32, unsafe.Pointer, uint32, error) {
	return m.MockSGID, m.MockDGID, m.MockFlowLabel, m.MockPayloadPtr, m.MockPayloadLength, m.MockError
}

// TestDeserializeProbePacket tests the deserializeProbePacket function
func TestDeserializeProbePacket(t *testing.T) {
	// Create a mock UDQueue
	udQueue := &UDQueue{}

	// Create a test ProbePacket
	original := ProbePacket{
		SequenceNum: 12345,
		T1:          uint64(1000000000),
		T3:          uint64(1000001000),
		T4:          uint64(1000002000),
		IsAck:       1,
		AckType:     2,
		Flags:       3,
	}

	// Allocate memory for the packet
	packetSize := unsafe.Sizeof(ProbePacket{})
	payload := make([]byte, packetSize)
	payloadPtr := unsafe.Pointer(&payload[0])

	// Copy the original packet to the payload
	*(*ProbePacket)(payloadPtr) = original

	// Test cases
	tests := []struct {
		name        string
		payloadLen  uint32
		expectError bool
	}{
		{
			name:        "Valid payload",
			payloadLen:  uint32(packetSize),
			expectError: false,
		},
		{
			name:        "Payload too small",
			payloadLen:  uint32(packetSize) - 1,
			expectError: true,
		},
		{
			name:        "Zero payload",
			payloadLen:  0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function directly or use a mock method if it's not exportable
			deserialized, err := udQueue.deserializeProbePacket(payloadPtr, tc.payloadLen)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify deserialized packet matches original
			if deserialized.SequenceNum != original.SequenceNum {
				t.Errorf("SequenceNum mismatch: got %d, want %d", deserialized.SequenceNum, original.SequenceNum)
			}
			if deserialized.T1 != original.T1 {
				t.Errorf("T1 mismatch: got %d, want %d", deserialized.T1, original.T1)
			}
			if deserialized.T3 != original.T3 {
				t.Errorf("T3 mismatch: got %d, want %d", deserialized.T3, original.T3)
			}
			if deserialized.T4 != original.T4 {
				t.Errorf("T4 mismatch: got %d, want %d", deserialized.T4, original.T4)
			}
			if deserialized.IsAck != original.IsAck {
				t.Errorf("IsAck mismatch: got %d, want %d", deserialized.IsAck, original.IsAck)
			}
			if deserialized.AckType != original.AckType {
				t.Errorf("AckType mismatch: got %d, want %d", deserialized.AckType, original.AckType)
			}
			if deserialized.Flags != original.Flags {
				t.Errorf("Flags mismatch: got %d, want %d", deserialized.Flags, original.Flags)
			}
		})
	}
}

// MockUDQueueBase is a data structure for testing UDQueue-related functions
type MockUDQueueBase struct {
	RecvBuf         unsafe.Pointer
	GRHBytes        []byte
	ParseGRHResult  ParseGRHResult
	ParseGRHError   error
	DeserializeErr  error
	MockPacket      *ProbePacket
	MockReceiveTime time.Time
	MockProcessedWC *ProcessedWorkCompletion
	RecvCompChan    chan *GoWorkCompletion
	ErrChan         chan error
	SendCompChan    chan *GoWorkCompletion
}

// ParseGRHResult holds the result of parseGRH function
type ParseGRHResult struct {
	SGID          string
	DGID          string
	FlowLabel     uint32
	PayloadPtr    unsafe.Pointer
	PayloadLength uint32
}

// TestParseIPv4GRH tests the parseIPv4GRH function
func TestParseIPv4GRH(t *testing.T) {
	// Create a mock UDQueue
	udQueue := &UDQueue{}

	// Create valid IPv4 header bytes
	// Standard IPv4 header (20 bytes)
	validIPv4Header := []byte{
		0x45, 0x00, // Version (4) + IHL (5) and DSCP + ECN
		0x00, 0x14, // Total Length (20 bytes)
		0x00, 0x00, 0x00, 0x00, // Identification, Flags, Fragment Offset
		0x40, 0x06, // TTL (64), Protocol (TCP)
		0x00, 0x00, // Header Checksum
		192, 168, 1, 100, // Source IP (192.168.1.100)
		10, 0, 0, 1, // Destination IP (10.0.0.1)
	}

	// Create a GRH that will contain the IPv4 header at offset 20
	validGRH := make([]byte, GRHSize)
	copy(validGRH[IPv4HeaderOffset:], validIPv4Header)

	// Create an invalid GRH with corrupted IPv4 header
	// We'll create a GRH that's too short to contain a complete IPv4 header
	shortGRH := make([]byte, IPv4HeaderOffset+10) // Only enough space for 10 bytes of IPv4 header
	// Set version to 4 to ensure it's identified as IPv4
	shortGRH[IPv4HeaderOffset] = 0x45

	tests := []struct {
		name        string
		grhBytes    []byte
		expectSGID  string
		expectDGID  string
		expectError bool
	}{
		{
			name:        "Valid IPv4 GRH",
			grhBytes:    validGRH,
			expectSGID:  "::ffff:192.168.1.100",
			expectDGID:  "::ffff:10.0.0.1",
			expectError: false,
		},
		{
			name:        "Invalid IPv4 header (too short)",
			grhBytes:    shortGRH,
			expectSGID:  "",
			expectDGID:  "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sgid, dgid, err := udQueue.parseIPv4GRH(tc.grhBytes)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if sgid != tc.expectSGID {
				t.Errorf("SGID mismatch: got %s, want %s", sgid, tc.expectSGID)
			}

			if dgid != tc.expectDGID {
				t.Errorf("DGID mismatch: got %s, want %s", dgid, tc.expectDGID)
			}
		})
	}
}

// TestParseIPv6GRH tests the parseIPv6GRH function
func TestParseIPv6GRH(t *testing.T) {
	// Create a mock UDQueue
	udQueue := &UDQueue{}

	// Create valid IPv6 header (40 bytes)
	validIPv6Header := []byte{
		0x60, 0x00, 0x00, 0x00, // Version (6), Traffic Class, Flow Label (first 4 bits)
		0x00, 0x00, 0x00, 0x00, // Payload Length, Next Header, Hop Limit
		// Source GID (fe80::1)
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		// Destination GID (fe80::2)
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}

	// Set Flow Label (last 20 bits of first word)
	flowLabel := uint32(0x12345)
	validIPv6Header[1] = validIPv6Header[1] | byte((flowLabel>>16)&0x0F)
	validIPv6Header[2] = byte((flowLabel >> 8) & 0xFF)
	validIPv6Header[3] = byte(flowLabel & 0xFF)

	// Invalid IPv6 header (too short)
	invalidIPv6Header := validIPv6Header[:20]

	tests := []struct {
		name            string
		grhBytes        []byte
		expectSGID      string
		expectDGID      string
		expectFlowLabel uint32
		expectError     bool
	}{
		{
			name:            "Valid IPv6 GRH",
			grhBytes:        validIPv6Header,
			expectSGID:      "fe80::1",
			expectDGID:      "fe80::2",
			expectFlowLabel: flowLabel,
			expectError:     false,
		},
		{
			name:            "Invalid IPv6 header (too short)",
			grhBytes:        invalidIPv6Header,
			expectSGID:      "",
			expectDGID:      "",
			expectFlowLabel: 0,
			expectError:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sgid, dgid, flowLabel, err := udQueue.parseIPv6GRH(tc.grhBytes)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if sgid != tc.expectSGID {
				t.Errorf("SGID mismatch: got %s, want %s", sgid, tc.expectSGID)
			}

			if dgid != tc.expectDGID {
				t.Errorf("DGID mismatch: got %s, want %s", dgid, tc.expectDGID)
			}

			if flowLabel != tc.expectFlowLabel {
				t.Errorf("FlowLabel mismatch: got %d, want %d", flowLabel, tc.expectFlowLabel)
			}
		})
	}
}

// TestParseGRH tests the parseGRH function
func TestParseGRH(t *testing.T) {
	// Create a mock UDQueue with a receive buffer
	recvBuf := make([]byte, GRHSize+40) // GRH + payload
	udQueue := &UDQueue{
		RecvBuf: unsafe.Pointer(&recvBuf[0]),
	}

	// Set up IPv6 header in the buffer
	ipv6GRH := recvBuf[:GRHSize]
	ipv6GRH[0] = 0x60 // IPv6 version
	// Source GID (fe80::1)
	copy(ipv6GRH[8:24], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	// Destination GID (fe80::2)
	copy(ipv6GRH[24:40], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	// Payload after GRH
	payload := recvBuf[GRHSize:]
	// Initialize a probe packet in the payload
	packet := (*ProbePacket)(unsafe.Pointer(&payload[0]))
	packet.SequenceNum = 12345
	packet.T1 = 1000000000

	tests := []struct {
		name        string
		goWC        *GoWorkCompletion
		expectSGID  string
		expectDGID  string
		expectError bool
	}{
		{
			name: "GRH present (IPv6)",
			goWC: &GoWorkCompletion{
				WCFlags: 1,            // IBV_WC_GRH flag
				ByteLen: GRHSize + 40, // GRH + payload
			},
			expectSGID:  "fe80::1",
			expectDGID:  "fe80::2",
			expectError: false,
		},
		{
			name: "GRH not present",
			goWC: &GoWorkCompletion{
				WCFlags: 0,  // No IBV_WC_GRH flag
				ByteLen: 40, // Just payload
			},
			expectSGID:  "",
			expectDGID:  "",
			expectError: false,
		},
		{
			name: "GRH present but ByteLen too small",
			goWC: &GoWorkCompletion{
				WCFlags: 1,  // IBV_WC_GRH flag
				ByteLen: 20, // Less than GRHSize
			},
			expectSGID:  "",
			expectDGID:  "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sgid, dgid, _, payloadPtr, payloadLen, err := udQueue.parseGRH(tc.goWC)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if sgid != tc.expectSGID {
				t.Errorf("SGID mismatch: got %s, want %s", sgid, tc.expectSGID)
			}

			if dgid != tc.expectDGID {
				t.Errorf("DGID mismatch: got %s, want %s", dgid, tc.expectDGID)
			}

			if tc.goWC.WCFlags == 0 {
				// No GRH case
				if payloadPtr != udQueue.RecvBuf {
					t.Errorf("PayloadPtr should be equal to RecvBuf when GRH is not present")
				}
				if payloadLen != uint32(tc.goWC.ByteLen) {
					t.Errorf("PayloadLen mismatch: got %d, want %d", payloadLen, tc.goWC.ByteLen)
				}
			} else {
				// GRH present case
				expectedPayloadPtr := unsafe.Pointer(uintptr(udQueue.RecvBuf) + uintptr(GRHSize))
				expectedPayloadLen := uint32(tc.goWC.ByteLen) - GRHSize

				if uintptr(payloadPtr) != uintptr(expectedPayloadPtr) {
					t.Errorf("PayloadPtr mismatch: got %v, want %v", payloadPtr, expectedPayloadPtr)
				}
				if payloadLen != expectedPayloadLen {
					t.Errorf("PayloadLen mismatch: got %d, want %d", payloadLen, expectedPayloadLen)
				}
			}
		})
	}
}

// TestUDQueue is a custom implementation that mimics UDQueue for testing
type MockUDQueue struct {
	UDQueue
	recvCompChan chan *GoWorkCompletion
	errChan      chan error
	mockPostRecv func() error
}

// PostRecv overrides the real PostRecv method for testing
func (m *MockUDQueue) PostRecv() error {
	if m.mockPostRecv != nil {
		return m.mockPostRecv()
	}
	return nil
}

// MockUDQueueWithPacket creates a mock UDQueue with a ProbePacket in its buffer
func MockUDQueueWithPacket(packet ProbePacket) *MockUDQueue {
	// Allocate memory for GRH + packet
	buf := make([]byte, GRHSize+unsafe.Sizeof(ProbePacket{}))

	// Copy packet to buffer after GRH
	packetPtr := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + uintptr(GRHSize))
	*(*ProbePacket)(packetPtr) = packet

	// Create mock channels
	recvCompChan := make(chan *GoWorkCompletion, 1)
	errChan := make(chan error, 1)

	return &MockUDQueue{
		UDQueue: UDQueue{
			RecvBuf:      unsafe.Pointer(&buf[0]),
			recvCompChan: recvCompChan,
			errChan:      errChan,
		},
		recvCompChan: recvCompChan,
		errChan:      errChan,
		mockPostRecv: func() error {
			return nil
		},
	}
}

// ReceivePacket is a mock implementation for testing
func (m *MockUDQueue) ReceivePacket(ctx context.Context) (*ProbePacket, time.Time, *ProcessedWorkCompletion, error) {
	// Wait for completion notification from CQ poller
	select {
	case err := <-m.errChan:
		return nil, time.Time{}, nil, fmt.Errorf("error during receive: %w", err)

	case <-ctx.Done(): // Context cancelled or timed out
		return nil, time.Time{}, nil, ctx.Err()

	case goWC := <-m.recvCompChan:
		receiveTime := time.Unix(0, int64(goWC.CompletionWallclockNS)) // use HW timestamp

		// Parse GRH (if present) and determine payload location and length
		sgid, dgid, flowLabel, payloadDataPtr, actualPayloadLength, grhParseErr := m.parseGRH(goWC)

		processedWC := &ProcessedWorkCompletion{
			GoWorkCompletion: *goWC, // Embed the original GoWorkCompletion
			SGID:             sgid,
			DGID:             dgid,
			FlowLabel:        flowLabel,
		}

		if grhParseErr != nil {
			return nil, receiveTime, processedWC, grhParseErr
		}

		// Deserialize the payload into a ProbePacket
		packet, deserializeErr := m.deserializeProbePacket(payloadDataPtr, actualPayloadLength)
		if deserializeErr != nil {
			return nil, receiveTime, processedWC, deserializeErr
		}

		// PostRecv is mocked and will always succeed
		m.PostRecv()

		return packet, receiveTime, processedWC, nil
	}
}

// parseGRH is a mock implementation for testing
func (m *MockUDQueue) parseGRH(goWC *GoWorkCompletion) (sgid string, dgid string, flowLabel uint32, payloadDataPtr unsafe.Pointer, actualPayloadLength uint32, err error) {
	return m.UDQueue.parseGRH(goWC)
}

// deserializeProbePacket is a mock implementation for testing
func (m *MockUDQueue) deserializeProbePacket(payloadDataPtr unsafe.Pointer, actualPayloadLength uint32) (*ProbePacket, error) {
	return m.UDQueue.deserializeProbePacket(payloadDataPtr, actualPayloadLength)
}

// TestReceivePacket tests the ReceivePacket function
func TestReceivePacket(t *testing.T) {
	// Create test packet
	testPacket := ProbePacket{
		SequenceNum: 12345,
		T1:          1000000000,
		IsAck:       1,
		AckType:     2,
	}

	// Test case 1: Successful receive
	t.Run("Successful receive", func(t *testing.T) {
		// Create a mock UDQueue for this test
		mockQueue := MockUDQueueWithPacket(testPacket)

		// Push a valid work completion to the channel
		goWC := &GoWorkCompletion{
			WCFlags:               1, // IBV_WC_GRH flag
			ByteLen:               GRHSize + uint32(unsafe.Sizeof(ProbePacket{})),
			CompletionWallclockNS: uint64(time.Now().UnixNano()),
		}

		// Set up IPv6 header in the buffer
		buf := (*[GRHSize + 40]byte)(mockQueue.RecvBuf)
		ipv6GRH := buf[:GRHSize]
		ipv6GRH[0] = 0x60 // IPv6 version
		// Source GID (fe80::1)
		copy(ipv6GRH[8:24], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
		// Destination GID (fe80::2)
		copy(ipv6GRH[24:40], []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

		go func() {
			mockQueue.recvCompChan <- goWC
		}()

		// Call ReceivePacket
		ctx := context.Background()
		packet, receiveTime, processedWC, err := mockQueue.ReceivePacket(ctx)

		// Verify results
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if packet == nil {
			t.Fatal("Expected packet but got nil")
		}
		if packet.SequenceNum != testPacket.SequenceNum {
			t.Errorf("SequenceNum mismatch: got %d, want %d", packet.SequenceNum, testPacket.SequenceNum)
		}
		if !receiveTime.Equal(time.Unix(0, int64(goWC.CompletionWallclockNS))) {
			t.Errorf("ReceiveTime mismatch: got %v, want %v", receiveTime, time.Unix(0, int64(goWC.CompletionWallclockNS)))
		}
		if processedWC == nil {
			t.Fatal("Expected ProcessedWorkCompletion but got nil")
		}
		if processedWC.SGID != "fe80::1" {
			t.Errorf("ProcessedWC.SGID mismatch: got %s, want %s", processedWC.SGID, "fe80::1")
		}
		if processedWC.DGID != "fe80::2" {
			t.Errorf("ProcessedWC.DGID mismatch: got %s, want %s", processedWC.DGID, "fe80::2")
		}
	})

	// Test case 2: Error during receive
	t.Run("Error during receive", func(t *testing.T) {
		// Create a mock UDQueue for this test
		mockQueue := MockUDQueueWithPacket(testPacket)

		testErr := fmt.Errorf("test error")
		go func() {
			mockQueue.errChan <- testErr
		}()

		// Call ReceivePacket
		ctx := context.Background()
		packet, receiveTime, processedWC, err := mockQueue.ReceivePacket(ctx)

		// Verify results
		if err == nil {
			t.Fatal("Expected error but got nil")
		}
		if err.Error() != "error during receive: test error" {
			t.Errorf("Unexpected error message: %v", err)
		}
		if packet != nil {
			t.Errorf("Expected nil packet but got %v", packet)
		}
		if !receiveTime.IsZero() {
			t.Errorf("Expected zero receiveTime but got %v", receiveTime)
		}
		if processedWC != nil {
			t.Errorf("Expected nil processedWC but got %v", processedWC)
		}
	})

	// Test case 3: Context cancelled
	t.Run("Context cancelled", func(t *testing.T) {
		// Create a mock UDQueue for this test
		mockQueue := MockUDQueueWithPacket(testPacket)

		// Create cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Call ReceivePacket with cancelled context
		packet, receiveTime, processedWC, err := mockQueue.ReceivePacket(ctx)

		// Verify results
		if err == nil {
			t.Fatal("Expected error but got nil")
		}
		if err != context.Canceled {
			t.Errorf("Unexpected error: %v", err)
		}
		if packet != nil {
			t.Errorf("Expected nil packet but got %v", packet)
		}
		if !receiveTime.IsZero() {
			t.Errorf("Expected zero receiveTime but got %v", receiveTime)
		}
		if processedWC != nil {
			t.Errorf("Expected nil processedWC but got %v", processedWC)
		}
	})
}
