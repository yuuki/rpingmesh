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
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Queue type constants matching RDMA_QUEUE_TYPE_* in rdma_bridge.h.
const (
	QueueTypeSender    = C.RDMA_QUEUE_TYPE_SENDER
	QueueTypeResponder = C.RDMA_QUEUE_TYPE_RESPONDER
)

// CQ poll mode constants matching RDMA_CQ_POLL_* in rdma_bridge.h. They
// select how a queue's Zig CQ poller thread waits for completions.
const (
	// CQPollAuto uses CQPollEvent with hardware timestamps and CQPollBusy
	// with software timestamps (which are taken when the poller reads the
	// completion, so its wakeup latency would become timestamp error).
	CQPollAuto = C.RDMA_CQ_POLL_AUTO
	// CQPollEvent sleeps on a completion channel until the CQ raises an
	// event: no CPU while idle.
	CQPollEvent = C.RDMA_CQ_POLL_EVENT
	// CQPollBusy polls with a ~50us sleep between polls (~1% of a CPU per
	// queue).
	CQPollBusy = C.RDMA_CQ_POLL_BUSY
)

// ParseCQPollMode maps a configuration value ("auto", "event", "busy") to
// a CQPoll* constant. An empty string means "auto".
func ParseCQPollMode(s string) (int, error) {
	switch s {
	case "", "auto":
		return CQPollAuto, nil
	case "event":
		return CQPollEvent, nil
	case "busy":
		return CQPollBusy, nil
	}
	return 0, fmt.Errorf("unknown CQ poll mode %q (want auto, event or busy)", s)
}

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

// Device wraps an opened RDMA device.
type Device struct {
	devHandle C.rdma_device_t
	Info      DeviceInfo
	// CQPollMode is the CQPoll* mode applied to queues created on this
	// device by CreateQueue. The zero value is CQPollAuto.
	CQPollMode int
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
	Info   QueueInfo
}

// QueueInfo contains queue metadata returned after queue creation.
type QueueInfo struct {
	QPN              uint32
	UsesSWTimestamps bool
	// UsesCQEvents reports whether the Zig CQ poller sleeps on a completion
	// channel (true) or busy-polls (false), either because busy polling was
	// selected (see CQPollMode) or because the provider lacks CQ event
	// support. Busy polling costs ~1% of a CPU per queue.
	UsesCQEvents bool
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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

// GetDeviceName returns the name (e.g., "mlx5_0") of the device at index
// without opening it, so callers can filter devices before allocating any
// verbs resources.
func (ctx *Context) GetDeviceName(index int) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var buf [64]C.char
	rc := C.rdma_get_device_name(ctx.handle, C.int32_t(index), &buf[0], C.size_t(len(buf)))
	if rc != 0 {
		return "", fmt.Errorf("rdma_get_device_name(index=%d) failed: %s", index, GetLastError())
	}
	return cCharArrayToString(buf[:]), nil
}

// OpenDevice opens an RDMA device by its index in the device list.
// The gidIndex specifies which GID table entry to use on the active port.
// sl and tc are the Service Level (PFC priority, 0-7) and GRH traffic class
// (DSCP << 2) applied to every Address Handle created for this device.
func (ctx *Context) OpenDevice(index int, gidIndex int, sl uint8, tc uint8) (*Device, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var devHandle C.rdma_device_t
	var cInfo C.rdma_device_info_t

	rc := C.rdma_open_device(
		ctx.handle,
		C.int32_t(index),
		C.int32_t(gidIndex),
		C.uint8_t(sl),
		C.uint8_t(tc),
		&devHandle,
		&cInfo,
	)
	if rc != 0 {
		return nil, fmt.Errorf("rdma_open_device(index=%d, gid_index=%d) failed: %s",
			index, gidIndex, GetLastError())
	}
	return newDevice(devHandle, &cInfo), nil
}

// OpenDeviceByName opens an RDMA device by its name (e.g., "mlx5_0", "rxe0").
// The gidIndex specifies which GID table entry to use on the active port.
// sl and tc are the Service Level (PFC priority, 0-7) and GRH traffic class
// (DSCP << 2) applied to every Address Handle created for this device.
func (ctx *Context) OpenDeviceByName(name string, gidIndex int, sl uint8, tc uint8) (*Device, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	var devHandle C.rdma_device_t
	var cInfo C.rdma_device_info_t

	rc := C.rdma_open_device_by_name(
		ctx.handle,
		cName,
		C.int32_t(gidIndex),
		C.uint8_t(sl),
		C.uint8_t(tc),
		&devHandle,
		&cInfo,
	)
	if rc != 0 {
		return nil, fmt.Errorf("rdma_open_device_by_name(%q, gid_index=%d) failed: %s",
			name, gidIndex, GetLastError())
	}
	return newDevice(devHandle, &cInfo), nil
}

func newDevice(devHandle C.rdma_device_t, cInfo *C.rdma_device_info_t) *Device {
	return &Device{devHandle: devHandle, Info: convertDeviceInfo(cInfo)}
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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

// DropCount returns the total number of completion events dropped because
// the ring was full, i.e. Poll was not called fast enough to keep up with
// the Zig CQ poller thread. It is monotonically increasing for the
// lifetime of the ring and safe to call from any goroutine. Returns 0 if
// the ring has already been destroyed.
func (ring *EventRing) DropCount() uint64 {
	if ring.handle == nil {
		return 0
	}
	return uint64(C.rdma_event_ring_drop_count(ring.handle))
}

// TakeMaxOccupancy returns the highest number of events that were waiting in
// the ring at once since the previous call (a dropped event counts as full
// capacity) and resets it to zero. It is meant for one periodic reader (the
// agent's metrics callback); concurrent callers would split the samples.
// Returns 0 if the ring has already been destroyed.
func (ring *EventRing) TakeMaxOccupancy() uint64 {
	if ring.handle == nil {
		return 0
	}
	return uint64(C.rdma_event_ring_take_max_occupancy(ring.handle))
}

// Capacity returns the number of events the ring holds: the capacity passed
// to NewEventRing rounded up to a power of two. Returns 0 if the ring has
// already been destroyed.
func (ring *EventRing) Capacity() uint64 {
	if ring.handle == nil {
		return 0
	}
	return uint64(C.rdma_event_ring_capacity(ring.handle))
}

// ---------------------------------------------------------------------------
// Queue Operations
// ---------------------------------------------------------------------------

// CreateQueue creates a UD Queue Pair on this device. The queueType must be
// QueueTypeSender or QueueTypeResponder. The ring is used by the CQ poller
// to deliver completion events asynchronously. The CQ poller waits in the
// device's CQPollMode; Info.UsesCQEvents reports the mode in effect.
func (dev *Device) CreateQueue(queueType int, ring *EventRing) (*Queue, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var qHandle C.rdma_queue_t
	var cInfo C.rdma_queue_info_t

	rc := C.rdma_create_queue(
		dev.devHandle,
		C.int32_t(queueType),
		C.int32_t(dev.CQPollMode),
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
		Info: QueueInfo{
			QPN:              uint32(cInfo.qpn),
			UsesSWTimestamps: cInfo.uses_sw_timestamps != 0,
			UsesCQEvents:     cInfo.uses_cq_events != 0,
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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

// ErrNoFreeSendSlot is returned by SendAckPair when every send slot of the
// queue holds an in-flight send. It is transient: the CQ poller returns a
// slot with each completion.
var ErrNoFreeSendSlot = errors.New("no free send slot")

// SendAckPair answers a received probe with both ACKs without waiting for
// any send completion. It posts the first ACK (echoing T1, carrying T3 =
// recvTimestampNS) and returns; when that ACK's send completion arrives, the
// queue's CQ poller writes the completion timestamp as T4 into the second
// ACK, which was staged in the same send slot, and posts it. T4 is that
// first ACK's send completion timestamp.
//
// Because nothing blocks on a completion, the caller can keep draining its
// event ring while completions are slow, and no thread spins while waiting.
// Failures after SendAckPair returns are counted by AsyncAckFailures.
// It returns ErrNoFreeSendSlot when all send slots are in flight.
func (q *Queue) SendAckPair(targetGID [16]byte, targetQPN uint32, flowLabel uint32, recvPacket []byte, recvTimestampNS uint64) error {
	// The Zig side unconditionally reads ProbePacketSize bytes from recvPacket.
	if len(recvPacket) < ProbePacketSize {
		return fmt.Errorf("recvPacket too short: got %d bytes, need at least %d", len(recvPacket), ProbePacketSize)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cGID := goGIDToC(targetGID)
	pktPtr := (*C.uint8_t)(unsafe.Pointer(&recvPacket[0]))

	rc := C.rdma_send_ack_pair(
		q.handle,
		&cGID,
		C.uint32_t(targetQPN),
		C.uint32_t(flowLabel),
		pktPtr,
		C.uint64_t(recvTimestampNS),
	)
	switch {
	case rc == 0:
		return nil
	case rc == C.RDMA_ACK_PAIR_NO_FREE_SLOT:
		return ErrNoFreeSendSlot
	default:
		return fmt.Errorf("rdma_send_ack_pair failed (rc=%d): %s", int(rc), GetLastError())
	}
}

// AsyncAckFailures returns how many ACK pairs posted by SendAckPair failed
// after it returned: a first or second ACK that completed with an error, or a
// second ACK the CQ poller could not post. It is monotonically increasing.
// Returns 0 once the queue has been destroyed.
func (q *Queue) AsyncAckFailures() uint64 {
	if q.handle == nil {
		return 0
	}
	return uint64(C.rdma_queue_async_ack_failures(q.handle))
}

// ---------------------------------------------------------------------------
// Error Reporting
// ---------------------------------------------------------------------------

// GetLastError returns the last error message from the Zig RDMA library.
// The Zig buffer is thread-local: the failing rdma_* call and this read
// must run on the same OS thread. Bridge wrappers that interpolate the
// string lock the OS thread around both Cgo calls. The string is valid
// only until the next rdma_* call on that thread.
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
// Wire layout (40 bytes) — must match zig/src/wire.zig serializeProbePacket:
//
//	[0]      Version
//	[1]      MsgType
//	[2]      AckType
//	[3]      Flags
//	[4:12]   SequenceNum (big-endian uint64)
//	[12:20]  T1 (big-endian uint64)
//	[20:28]  T3 (big-endian uint64)
//	[28:36]  T4 (big-endian uint64)
//	[36:40]  Reserved (zero padding)
func SerializeProbePacket(pkt *ProbePacket, buf []byte) {
	_ = buf[ProbePacketSize-1] // bounds check hint

	buf[0] = pkt.Version
	buf[1] = pkt.MsgType
	buf[2] = pkt.AckType
	buf[3] = pkt.Flags
	binary.BigEndian.PutUint64(buf[4:12], pkt.SequenceNum)
	binary.BigEndian.PutUint64(buf[12:20], pkt.T1)
	binary.BigEndian.PutUint64(buf[20:28], pkt.T3)
	binary.BigEndian.PutUint64(buf[28:36], pkt.T4)
	clear(buf[36:40]) // reserved
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
