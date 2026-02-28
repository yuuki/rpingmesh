// Package rdmabridge provides a Go wrapper around the Zig RDMA static library
// (librdmabridge.a) via Cgo. It exposes Go-native types and methods for RDMA
// device management, queue pair operations, and the R-Pingmesh probing protocol.
//
// The underlying Zig library implements the C-ABI defined in rdma_bridge.h.
// All opaque handles (context, device, queue, event ring) are managed by the
// Zig side; Go code must not interpret or modify them directly.
package rdmabridge

/*
#cgo LDFLAGS: -L${SRCDIR}/../../zig/zig-out/lib -lrdmabridge -lrdmacm -libverbs -lpthread
#cgo CFLAGS: -I${SRCDIR}/../../zig/include
#include "rdma_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"
)

// Queue type constants matching RDMA_QUEUE_TYPE_* in rdma_bridge.h.
const (
	QueueTypeSender    = C.RDMA_QUEUE_TYPE_SENDER
	QueueTypeResponder = C.RDMA_QUEUE_TYPE_RESPONDER
)

// Protocol constants for probe packet wire format.
const (
	PacketVersion   = 1
	MsgTypeProbe    = 0
	MsgTypeAck      = 1
	AckTypeNone     = 0
	AckTypeFirst    = 1
	AckTypeSecond   = 2
	ProbePacketSize = 40 // Must match RDMA_PROBE_PACKET_SIZE in rdma_bridge.h
)

// Context wraps the RDMA subsystem context. Exactly one context should be
// created per process. It owns the device list and shared resources.
type Context struct {
	handle C.rdma_context_t
}

// Device wraps an opened RDMA device with its parent context reference.
type Device struct {
	handle    C.rdma_context_t // parent context for device operations
	devHandle C.rdma_device_t
	Info      DeviceInfo
}

// DeviceInfo contains human-readable device metadata returned after opening.
type DeviceInfo struct {
	DeviceName     string
	GID            string
	IPAddr         string
	ActivePort     uint8
	ActiveGIDIndex uint8
}

// Queue wraps a UD Queue Pair with all associated resources (QP, CQ, MRs).
type Queue struct {
	handle C.rdma_queue_t
	ring   *EventRing
	Info   QueueInfo
}

// QueueInfo contains queue metadata returned after queue creation.
type QueueInfo struct {
	QPN              uint32
	UsesSWTimestamps bool
}

// EventRing wraps the Zig SPSC (Single Producer, Single Consumer) ring buffer
// used to deliver completion events from the CQ poller thread to Go.
type EventRing struct {
	handle C.rdma_event_ring_t
}

// CompletionEvent represents a CQ completion delivered via the ring buffer.
// Fields are decoded from the C rdma_completion_event_t struct.
type CompletionEvent struct {
	SequenceNum uint64
	T1          uint64
	T3          uint64
	T4          uint64
	IsAck       bool
	AckType     uint8 // AckTypeFirst or AckTypeSecond
	Flags       uint8
	TimestampNS uint64
	SourceGID   [16]byte
	SourceQPN   uint32
	FlowLabel   uint32
	Status      int32
	IsSend      bool
}

// SendResult contains the result of a synchronous probe send operation,
// including timestamps and error information.
type SendResult struct {
	T1NS  uint64
	T2NS  uint64
	Error error
}

// ProbePacket represents the R-Pingmesh probe/ACK wire format (40 bytes).
// Serialized in big-endian byte order for network transmission.
type ProbePacket struct {
	Version     uint8
	MsgType     uint8
	AckType     uint8
	Flags       uint8
	SequenceNum uint64
	T1          uint64
	T3          uint64
	T4          uint64
}

// ---------------------------------------------------------------------------
// Context Lifecycle
// ---------------------------------------------------------------------------

// Init initializes the RDMA subsystem and returns a new Context.
// The context must be destroyed with Destroy() when no longer needed.
func Init() (*Context, error) {
	var handle C.rdma_context_t
	rc := C.rdma_init(&handle)
	if rc != 0 {
		return nil, fmt.Errorf("rdma_init failed: %s", GetLastError())
	}
	return &Context{handle: handle}, nil
}

// Destroy tears down the RDMA context and releases all resources.
// All devices and queues must be closed/destroyed before calling this.
func (ctx *Context) Destroy() {
	if ctx.handle != nil {
		C.rdma_destroy(ctx.handle)
		ctx.handle = nil
	}
}

// ---------------------------------------------------------------------------
// Device Operations
// ---------------------------------------------------------------------------

// GetDeviceCount returns the number of available RDMA devices.
func (ctx *Context) GetDeviceCount() int {
	rc := C.rdma_get_device_count(ctx.handle)
	if rc < 0 {
		return 0
	}
	return int(rc)
}

// OpenDevice opens an RDMA device by its index in the device list.
// The gidIndex specifies which GID table entry to use on the active port.
func (ctx *Context) OpenDevice(index int, gidIndex int) (*Device, error) {
	var devHandle C.rdma_device_t
	var cInfo C.rdma_device_info_t

	rc := C.rdma_open_device(
		ctx.handle,
		C.int32_t(index),
		C.int32_t(gidIndex),
		&devHandle,
		&cInfo,
	)
	if rc != 0 {
		return nil, fmt.Errorf("rdma_open_device(index=%d, gid_index=%d) failed: %s",
			index, gidIndex, GetLastError())
	}

	dev := &Device{
		handle:    ctx.handle,
		devHandle: devHandle,
		Info:      convertDeviceInfo(&cInfo),
	}
	return dev, nil
}

// OpenDeviceByName opens an RDMA device by its name (e.g., "mlx5_0", "rxe0").
// The gidIndex specifies which GID table entry to use on the active port.
func (ctx *Context) OpenDeviceByName(name string, gidIndex int) (*Device, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	var devHandle C.rdma_device_t
	var cInfo C.rdma_device_info_t

	rc := C.rdma_open_device_by_name(
		ctx.handle,
		cName,
		C.int32_t(gidIndex),
		&devHandle,
		&cInfo,
	)
	if rc != 0 {
		return nil, fmt.Errorf("rdma_open_device_by_name(%q, gid_index=%d) failed: %s",
			name, gidIndex, GetLastError())
	}

	dev := &Device{
		handle:    ctx.handle,
		devHandle: devHandle,
		Info:      convertDeviceInfo(&cInfo),
	}
	return dev, nil
}

// Close closes the RDMA device and frees its resources (PD, device context).
// All queues associated with this device must be destroyed first.
func (dev *Device) Close() {
	if dev.devHandle != nil {
		C.rdma_close_device(dev.devHandle)
		dev.devHandle = nil
	}
}

// ---------------------------------------------------------------------------
// Event Ring Operations
// ---------------------------------------------------------------------------

// NewEventRing creates a lock-free SPSC ring buffer for completion event
// delivery. The capacity should be a power of 2 for optimal performance.
func NewEventRing(capacity int) (*EventRing, error) {
	handle := C.rdma_event_ring_create(C.uint32_t(capacity))
	if handle == nil {
		return nil, fmt.Errorf("rdma_event_ring_create(capacity=%d) failed: %s",
			capacity, GetLastError())
	}
	return &EventRing{handle: handle}, nil
}

// Poll retrieves up to maxEvents completion events from the ring buffer.
// This is non-blocking: it returns immediately with an empty slice if no
// events are available.
func (ring *EventRing) Poll(maxEvents int) []CompletionEvent {
	if maxEvents <= 0 {
		return nil
	}

	// Allocate C array on the stack for small counts, heap for large.
	cEvents := make([]C.rdma_completion_event_t, maxEvents)
	n := C.rdma_event_ring_poll(
		ring.handle,
		&cEvents[0],
		C.int32_t(maxEvents),
	)
	if n <= 0 {
		return nil
	}

	count := int(n)
	events := make([]CompletionEvent, count)
	for i := 0; i < count; i++ {
		events[i] = convertCompletionEvent(&cEvents[i])
	}
	return events
}

// Destroy frees the event ring buffer and its resources.
func (ring *EventRing) Destroy() {
	if ring.handle != nil {
		C.rdma_event_ring_destroy(ring.handle)
		ring.handle = nil
	}
}

// ---------------------------------------------------------------------------
// Queue Operations
// ---------------------------------------------------------------------------

// CreateQueue creates a UD Queue Pair on this device. The queueType must be
// QueueTypeSender or QueueTypeResponder. The ring is used by the CQ poller
// to deliver completion events asynchronously.
func (dev *Device) CreateQueue(queueType int, ring *EventRing) (*Queue, error) {
	var qHandle C.rdma_queue_t
	var cInfo C.rdma_queue_info_t

	rc := C.rdma_create_queue(
		dev.devHandle,
		C.int32_t(queueType),
		ring.handle,
		&qHandle,
		&cInfo,
	)
	if rc != 0 {
		return nil, fmt.Errorf("rdma_create_queue(type=%d) failed: %s",
			queueType, GetLastError())
	}

	q := &Queue{
		handle: qHandle,
		ring:   ring,
		Info: QueueInfo{
			QPN:              uint32(cInfo.qpn),
			UsesSWTimestamps: cInfo.uses_sw_timestamps != 0,
		},
	}
	return q, nil
}

// Destroy stops the CQ poller, deregisters memory regions, and destroys
// the QP and CQ associated with this queue.
func (q *Queue) Destroy() {
	if q.handle != nil {
		C.rdma_destroy_queue(q.handle)
		q.handle = nil
	}
}

// ---------------------------------------------------------------------------
// Data Path - Probe and ACK Operations
// ---------------------------------------------------------------------------

// SendProbe sends a probe packet to the specified remote target. It constructs
// a ProbePacket, posts it via the UD QP, and waits for send completion within
// the given timeout. Returns timestamps T1 (post time) and T2 (completion time).
func (q *Queue) SendProbe(targetGID [16]byte, targetQPN uint32, seqNum uint64, flowLabel uint32, timeoutMS uint32) SendResult {
	cGID := goGIDToC(targetGID)

	cResult := C.rdma_send_probe(
		q.handle,
		&cGID,
		C.uint32_t(targetQPN),
		C.uint64_t(seqNum),
		C.uint32_t(flowLabel),
		C.uint32_t(timeoutMS),
	)

	result := SendResult{
		T1NS: uint64(cResult.t1_ns),
		T2NS: uint64(cResult.t2_ns),
	}
	if cResult.error != 0 {
		result.Error = fmt.Errorf("rdma_send_probe failed (error=%d): %s",
			int(cResult.error), GetLastError())
	}
	return result
}

// SendFirstAck sends the first ACK in response to a received probe (step 2
// of the R-Pingmesh protocol). It echoes T1 from the probe, records T3
// (receive time), and outputs T4 (the send completion timestamp of this ACK).
func (q *Queue) SendFirstAck(targetGID [16]byte, targetQPN uint32, flowLabel uint32, recvPacket []byte, recvTimestampNS uint64, timeoutMS uint32) (uint64, error) {
	cGID := goGIDToC(targetGID)
	var outT4 C.uint64_t

	var pktPtr *C.uint8_t
	if len(recvPacket) > 0 {
		pktPtr = (*C.uint8_t)(unsafe.Pointer(&recvPacket[0]))
	}

	rc := C.rdma_send_first_ack(
		q.handle,
		&cGID,
		C.uint32_t(targetQPN),
		C.uint32_t(flowLabel),
		pktPtr,
		C.uint64_t(recvTimestampNS),
		&outT4,
		C.uint32_t(timeoutMS),
	)
	if rc != 0 {
		return 0, fmt.Errorf("rdma_send_first_ack failed (rc=%d): %s",
			int(rc), GetLastError())
	}
	return uint64(outT4), nil
}

// SendSecondAck sends the second ACK containing T3 and T4 so the prober can
// compute responder processing delay (step 3 of the R-Pingmesh protocol).
func (q *Queue) SendSecondAck(targetGID [16]byte, targetQPN uint32, flowLabel uint32, recvPacket []byte, t3NS uint64, t4NS uint64, timeoutMS uint32) error {
	cGID := goGIDToC(targetGID)

	var pktPtr *C.uint8_t
	if len(recvPacket) > 0 {
		pktPtr = (*C.uint8_t)(unsafe.Pointer(&recvPacket[0]))
	}

	rc := C.rdma_send_second_ack(
		q.handle,
		&cGID,
		C.uint32_t(targetQPN),
		C.uint32_t(flowLabel),
		pktPtr,
		C.uint64_t(t3NS),
		C.uint64_t(t4NS),
		C.uint32_t(timeoutMS),
	)
	if rc != 0 {
		return fmt.Errorf("rdma_send_second_ack failed (rc=%d): %s",
			int(rc), GetLastError())
	}
	return nil
}

// ---------------------------------------------------------------------------
// Event Poller
// ---------------------------------------------------------------------------

// StartEventPoller starts a goroutine that continuously polls the event ring
// buffer and dispatches completion events to the provided handler function.
// The poller runs until the context is cancelled. It sleeps briefly (100us)
// between polls when no events are available to avoid busy-spinning.
func (q *Queue) StartEventPoller(ctx context.Context, handler func(CompletionEvent)) {
	go func() {
		const (
			maxBatch  = 32
			idleSleep = 100 * time.Microsecond
		)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			events := q.ring.Poll(maxBatch)
			if len(events) == 0 {
				time.Sleep(idleSleep)
				continue
			}

			for _, ev := range events {
				handler(ev)
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Error Reporting
// ---------------------------------------------------------------------------

// GetLastError returns the last error message from the Zig RDMA library.
// The string is valid only until the next call to any rdma_* function on
// the same thread.
func GetLastError() string {
	cStr := C.rdma_get_last_error()
	if cStr == nil {
		return ""
	}
	return C.GoString(cStr)
}

// ---------------------------------------------------------------------------
// Wire Format - Probe Packet Serialization
// ---------------------------------------------------------------------------

// SerializeProbePacket serializes a ProbePacket into the provided byte slice
// using big-endian byte order. The buffer must be at least ProbePacketSize
// (40) bytes long.
//
// Wire layout (40 bytes):
//
//	[0]      Version
//	[1]      MsgType
//	[2]      AckType
//	[3]      Flags
//	[4:8]    Reserved (zero padding)
//	[8:16]   SequenceNum (big-endian uint64)
//	[16:24]  T1 (big-endian uint64)
//	[24:32]  T3 (big-endian uint64)
//	[32:40]  T4 (big-endian uint64)
func SerializeProbePacket(pkt *ProbePacket, buf []byte) {
	_ = buf[ProbePacketSize-1] // bounds check hint

	buf[0] = pkt.Version
	buf[1] = pkt.MsgType
	buf[2] = pkt.AckType
	buf[3] = pkt.Flags
	// bytes 4-7: reserved padding
	buf[4] = 0
	buf[5] = 0
	buf[6] = 0
	buf[7] = 0
	binary.BigEndian.PutUint64(buf[8:16], pkt.SequenceNum)
	binary.BigEndian.PutUint64(buf[16:24], pkt.T1)
	binary.BigEndian.PutUint64(buf[24:32], pkt.T3)
	binary.BigEndian.PutUint64(buf[32:40], pkt.T4)
}

// DeserializeProbePacket deserializes a ProbePacket from the provided byte
// slice. Returns nil if the buffer is too small (< ProbePacketSize bytes).
func DeserializeProbePacket(buf []byte) *ProbePacket {
	if len(buf) < ProbePacketSize {
		return nil
	}
	return &ProbePacket{
		Version:     buf[0],
		MsgType:     buf[1],
		AckType:     buf[2],
		Flags:       buf[3],
		SequenceNum: binary.BigEndian.Uint64(buf[8:16]),
		T1:          binary.BigEndian.Uint64(buf[16:24]),
		T3:          binary.BigEndian.Uint64(buf[24:32]),
		T4:          binary.BigEndian.Uint64(buf[32:40]),
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// convertDeviceInfo converts a C rdma_device_info_t to a Go DeviceInfo,
// copying string data out of the C char arrays.
func convertDeviceInfo(info *C.rdma_device_info_t) DeviceInfo {
	return DeviceInfo{
		DeviceName:     cCharArrayToString(info.device_name[:]),
		GID:            cCharArrayToString(info.gid[:]),
		IPAddr:         cCharArrayToString(info.ip_addr[:]),
		ActivePort:     uint8(info.active_port),
		ActiveGIDIndex: uint8(info.active_gid_index),
	}
}

// convertCompletionEvent converts a C rdma_completion_event_t to a Go
// CompletionEvent struct.
func convertCompletionEvent(ev *C.rdma_completion_event_t) CompletionEvent {
	var gid [16]byte
	for i := 0; i < 16; i++ {
		gid[i] = byte(ev.source_gid.raw[i])
	}
	return CompletionEvent{
		SequenceNum: uint64(ev.sequence_num),
		T1:          uint64(ev.t1),
		T3:          uint64(ev.t3),
		T4:          uint64(ev.t4),
		IsAck:       ev.is_ack != 0,
		AckType:     uint8(ev.ack_type),
		Flags:       uint8(ev.flags),
		TimestampNS: uint64(ev.timestamp_ns),
		SourceGID:   gid,
		SourceQPN:   uint32(ev.source_qpn),
		FlowLabel:   uint32(ev.flow_label),
		Status:      int32(ev.status),
		IsSend:      ev.is_send != 0,
	}
}

// cCharArrayToString converts a C char slice (null-terminated) to a Go string.
// It scans for the null terminator and returns the string up to that point.
func cCharArrayToString(arr []C.char) string {
	n := 0
	for n < len(arr) && arr[n] != 0 {
		n++
	}
	if n == 0 {
		return ""
	}
	// Convert []C.char to []byte without allocation by reinterpreting memory.
	bytes := make([]byte, n)
	for i := 0; i < n; i++ {
		bytes[i] = byte(arr[i])
	}
	return string(bytes)
}

// goGIDToC converts a Go [16]byte GID to the C rdma_gid_t struct.
func goGIDToC(gid [16]byte) C.rdma_gid_t {
	var cGID C.rdma_gid_t
	for i := 0; i < 16; i++ {
		cGID.raw[i] = C.uint8_t(gid[i])
	}
	return cGID
}
