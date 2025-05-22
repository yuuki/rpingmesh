package rdma

import (
	"net"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// TestUDQueueOperationsWithMock tests the UDQueue operations with mocked C functions
func TestUDQueueOperationsWithMock(t *testing.T) {
	// Create a mock RNIC
	mockRNIC := &RNIC{
		DeviceName:     "mock-device",
		GID:            "fe80::1",
		IsOpen:         true,
		ActivePortNum:  1,
		ActiveGIDIndex: 0,
		UDQueues:       make(map[string]*UDQueue),
	}

	// Create a UDQueue with minimal initialized fields for testing
	queue := &UDQueue{
		RNIC:         mockRNIC,
		QPN:          1234,
		QueueType:    UDQueueTypeSender,
		sendCompChan: make(chan *GoWorkCompletion, SendCompChanBufferSize),
		recvCompChan: make(chan *GoWorkCompletion, RecvCompChanBufferSize),
		errChan:      make(chan error, ErrChanBufferSize),
		cqPollerDone: make(chan struct{}),
	}

	// Test basic properties
	assert.Equal(t, "mock-device", queue.RNIC.DeviceName)
	assert.Equal(t, uint32(1234), queue.QPN)
	assert.Equal(t, UDQueueTypeSender, queue.QueueType)
	assert.Equal(t, "Sender", getQueueTypeString(queue.QueueType))

	// Test channels are initialized correctly
	assert.NotNil(t, queue.sendCompChan)
	assert.NotNil(t, queue.recvCompChan)
	assert.NotNil(t, queue.errChan)
	assert.NotNil(t, queue.cqPollerDone)

	// Test sending a work completion through channels
	testWC := &GoWorkCompletion{
		WRID:                  42,
		Status:                0, // IBV_WC_SUCCESS
		Opcode:                0, // IBV_WC_SEND
		ByteLen:               100,
		SrcQP:                 5678,
		CompletionWallclockNS: 12345678,
	}

	// Test async channel operations
	go func() {
		queue.sendCompChan <- testWC
	}()

	// Receive from channel and verify
	receivedWC := <-queue.sendCompChan
	assert.Equal(t, testWC.WRID, receivedWC.WRID)
	assert.Equal(t, testWC.Status, receivedWC.Status)
	assert.Equal(t, testWC.ByteLen, receivedWC.ByteLen)

	// Clean up
	queue.Destroy()

	// Verify channels are closed
	_, sendOk := <-queue.sendCompChan
	_, recvOk := <-queue.recvCompChan
	_, errOk := <-queue.errChan

	assert.False(t, sendOk, "sendCompChan should be closed")
	assert.False(t, recvOk, "recvCompChan should be closed")
	assert.False(t, errOk, "errChan should be closed")
}

// TestAddressHandle tests the address handle creation functionality
func TestAddressHandle(t *testing.T) {
	// Create a mock RNIC
	mockRNIC := &RNIC{
		DeviceName:     "mock-device",
		GID:            "fe80::1",
		IsOpen:         true,
		ActivePortNum:  1,
		ActiveGIDIndex: 0,
		PD:             nil, // In a real test, we would need a valid protection domain
	}

	// Create a UDQueue with minimal initialized fields for testing
	queue := &UDQueue{
		RNIC:         mockRNIC,
		QPN:          1234,
		QueueType:    UDQueueTypeSender,
		sendCompChan: make(chan *GoWorkCompletion, SendCompChanBufferSize),
		recvCompChan: make(chan *GoWorkCompletion, RecvCompChanBufferSize),
		errChan:      make(chan error, ErrChanBufferSize),
		cqPollerDone: make(chan struct{}),
	}

	// Since we can't actually create an address handle without a real RDMA device,
	// we'll test the validation logic in the CreateAddressHandle function

	// Test with invalid GID
	_, err := queue.CreateAddressHandle("invalid-gid", 0)
	assert.Error(t, err, "Invalid GID should return an error")
	assert.Contains(t, err.Error(), "failed to parse target GID", "Error message should indicate GID parsing issue")

	// Test with valid IPv6 GID
	// In a real test with actual RDMA devices, this would create an address handle
	// Here we just confirm the code path for validation works correctly
	// The actual C function calls can't be tested without a real device or a more complex mock

	// We can't test successful address handle creation without a real device or more complex mocking,
	// so we just test that the validation logic works as expected

	// Clean up
	queue.Destroy()
}

// TestSimpleGoWorkCompletion tests creating and checking fields of GoWorkCompletion
func TestSimpleGoWorkCompletion(t *testing.T) {
	// Create a new GoWorkCompletion based on actual structure
	wc := &GoWorkCompletion{
		WRID:                  42,
		Status:                0, // IBV_WC_SUCCESS
		Opcode:                0, // IBV_WC_SEND
		VendorErr:             0,
		ByteLen:               100,
		SrcQP:                 5678,
		WCFlags:               0,
		CompletionWallclockNS: 12345678,
	}

	// Test the values are correctly set
	assert.Equal(t, uint64(42), wc.WRID)
	assert.Equal(t, 0, wc.Status)
	assert.Equal(t, 0, wc.Opcode)
	assert.Equal(t, uint32(0), wc.VendorErr)
	assert.Equal(t, uint32(100), wc.ByteLen)
	assert.Equal(t, uint32(5678), wc.SrcQP)
	assert.Equal(t, uint32(0), wc.WCFlags)
	assert.Equal(t, uint64(12345678), wc.CompletionWallclockNS)
}

// TestSimpleProcessedWorkCompletion tests creating and checking fields of ProcessedWorkCompletion
func TestSimpleProcessedWorkCompletion(t *testing.T) {
	// Create a new ProcessedWorkCompletion
	pwc := &ProcessedWorkCompletion{
		GoWorkCompletion: GoWorkCompletion{
			WRID:                  42,
			Status:                0, // IBV_WC_SUCCESS
			Opcode:                0, // IBV_WC_SEND
			ByteLen:               100,
			SrcQP:                 5678,
			CompletionWallclockNS: 12345678,
		},
		SGID:      "fe80::1",
		DGID:      "fe80::2",
		FlowLabel: 0x123456,
	}

	// Test the embedded GoWorkCompletion values
	assert.Equal(t, uint64(42), pwc.WRID)
	assert.Equal(t, 0, pwc.Status)
	assert.Equal(t, 0, pwc.Opcode)
	assert.Equal(t, uint32(100), pwc.ByteLen)
	assert.Equal(t, uint32(5678), pwc.SrcQP)
	assert.Equal(t, uint64(12345678), pwc.CompletionWallclockNS)

	// Test the GRH-parsed information
	assert.Equal(t, "fe80::1", pwc.SGID)
	assert.Equal(t, "fe80::2", pwc.DGID)
	assert.Equal(t, uint32(0x123456), pwc.FlowLabel)
}

// TestUDQueueCleaner tests the cleanup methods of UDQueue
func TestUDQueueCleaner(t *testing.T) {
	// Create a mock UDQueue with nil C pointers to test the cleanup logic
	queue := &UDQueue{
		RNIC: &RNIC{
			DeviceName: "mock-device",
			GID:        "fe80::1",
		},
		QPN:          1234,
		QueueType:    UDQueueTypeSender,
		sendCompChan: make(chan *GoWorkCompletion, SendCompChanBufferSize),
		recvCompChan: make(chan *GoWorkCompletion, RecvCompChanBufferSize),
		errChan:      make(chan error, ErrChanBufferSize),
		cqPollerDone: make(chan struct{}),
	}

	// Test channel closing
	queue.Destroy()

	// Check that channels are closed
	_, sendOk := <-queue.sendCompChan
	_, recvOk := <-queue.recvCompChan
	_, errOk := <-queue.errChan

	assert.False(t, sendOk, "sendCompChan should be closed")
	assert.False(t, recvOk, "recvCompChan should be closed")
	assert.False(t, errOk, "errChan should be closed")
}

// TestAddressHandleIPValidation tests the IP address validation logic
// that would be used by CreateAddressHandle without making cgo calls
func TestAddressHandleIPValidation(t *testing.T) {
	// Test with invalid GID
	ipAddr := net.ParseIP("invalid-gid")
	assert.Nil(t, ipAddr, "Invalid GID should not parse as an IP address")

	// Test with IPv4 address
	ipAddr = net.ParseIP("192.168.1.1")
	assert.NotNil(t, ipAddr, "Valid IPv4 address should parse")
	ipv6 := ipAddr.To16()
	assert.NotNil(t, ipv6, "IPv4 address should convert to IPv6 format")

	// Test with valid IPv6 address
	ipAddr = net.ParseIP("fe80::1")
	assert.NotNil(t, ipAddr, "Valid IPv6 address should parse")
	ipv6 = ipAddr.To16()
	assert.NotNil(t, ipv6, "IPv6 address should convert to IPv6 format")
	assert.Equal(t, 16, len(ipv6), "IPv6 address should be 16 bytes")
}

// TestGetQueueTypeString tests the getQueueTypeString function
func TestGetQueueTypeString(t *testing.T) {
	assert.Equal(t, "Sender", getQueueTypeString(UDQueueTypeSender))
	assert.Equal(t, "Responder", getQueueTypeString(UDQueueTypeResponder))
	assert.Equal(t, "Unknown", getQueueTypeString(UDQueueType(99)))
}

// TestSimpleProbePacket tests creating and checking fields of ProbePacket
func TestSimpleProbePacket(t *testing.T) {
	// Create a probe packet
	packet := ProbePacket{
		SequenceNum: 42,
		T1:          123456789,
		T3:          0,
		T4:          0,
		IsAck:       0,
		AckType:     0,
	}

	// Test that fields are correctly set
	assert.Equal(t, uint64(42), packet.SequenceNum)
	assert.Equal(t, uint64(123456789), packet.T1)
	assert.Equal(t, uint8(0), packet.IsAck)
	assert.Equal(t, uint8(0), packet.AckType)
}

// TestSimpleProbePacketSerialization tests simple memory serialization of ProbePacket
func TestSimpleProbePacketSerialization(t *testing.T) {
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
	assert.Equal(t, original.SequenceNum, deserialized.SequenceNum)
	assert.Equal(t, original.T1, deserialized.T1)
	assert.Equal(t, original.T3, deserialized.T3)
	assert.Equal(t, original.T4, deserialized.T4)
	assert.Equal(t, original.IsAck, deserialized.IsAck)
	assert.Equal(t, original.AckType, deserialized.AckType)
	assert.Equal(t, original.Flags, deserialized.Flags)
}
