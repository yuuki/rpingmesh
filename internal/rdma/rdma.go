package rdma

// #cgo LDFLAGS: -libverbs
// #include <stdlib.h>
// #include <infiniband/verbs.h>
// #include <string.h>
// #include <arpa/inet.h>
// #include <errno.h>
//
// // Helper function to access ibv_port_attr safely
// int my_ibv_query_port(struct ibv_context *context, uint8_t port_num, struct ibv_port_attr *port_attr) {
//     return ibv_query_port(context, port_num, port_attr);
// }
//
// // Helper function to get phys_port_cnt
// int get_phys_port_cnt(struct ibv_context *context, uint8_t *phys_port_cnt) {
//     struct ibv_device_attr device_attr; // Declared and used only within C
//     if (ibv_query_device(context, &device_attr)) {
//         return -1; // Error
//     }
//     *phys_port_cnt = device_attr.phys_port_cnt;
//     return 0; // Success
// }
//
// // Helper function to copy bytes to a GID's raw field
// void copy_to_gid_raw(union ibv_gid *gid, const void *src, size_t n) {
//     memcpy(gid->raw, src, n);
// }
//
// // Helper functions for UD operations
// void set_ud_send_params(struct ibv_send_wr *wr, struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey) {
//     wr->wr.ud.ah = ah;
//     wr->wr.ud.remote_qpn = remote_qpn;
//     wr->wr.ud.remote_qkey = remote_qkey;
// }
//
// // Helper function to post receive WR without Go pointers
// int post_recv(struct ibv_qp *qp, uint64_t addr, uint32_t length, uint32_t lkey) {
//     struct ibv_sge sge;
//     struct ibv_recv_wr wr;
//     struct ibv_recv_wr *bad_wr = NULL;
//
//     memset(&sge, 0, sizeof(sge));
//     sge.addr = addr;
//     sge.length = length;
//     sge.lkey = lkey;
//
//     memset(&wr, 0, sizeof(wr));
//     wr.sg_list = &sge;
//     wr.num_sge = 1;
//
//     return ibv_post_recv(qp, &wr, &bad_wr);
// }
//
// // Helper function to post send WR without Go pointers
// int post_send(struct ibv_qp *qp, uint64_t addr, uint32_t length, uint32_t lkey,
//              struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey) {
//     struct ibv_sge sge;
//     struct ibv_send_wr wr;
//     struct ibv_send_wr *bad_wr = NULL;
//
//     memset(&sge, 0, sizeof(sge));
//     sge.addr = addr;
//     sge.length = length;
//     sge.lkey = lkey;
//
//     memset(&wr, 0, sizeof(wr));
//     wr.sg_list = &sge;
//     wr.num_sge = 1;
//     wr.opcode = IBV_WR_SEND;
//     wr.send_flags = IBV_SEND_SIGNALED;
//     wr.wr.ud.ah = ah;
//     wr.wr.ud.remote_qpn = remote_qpn;
//     wr.wr.ud.remote_qkey = remote_qkey;
//
//     return ibv_post_send(qp, &wr, &bad_wr);
// }
//
// // Helper function to request notification on completion queue
// int req_notify_cq(struct ibv_cq *cq, int solicited_only) {
//     return ibv_req_notify_cq(cq, solicited_only);
// }
//
// // Helper function to get a completion event
// int get_cq_event(struct ibv_comp_channel *channel, struct ibv_cq **cq, void **cq_context) {
//     return ibv_get_cq_event(channel, cq, cq_context);
// }
//
// // Helper function to acknowledge completion events
// void ack_cq_events(struct ibv_cq *cq, unsigned int nevents) {
//     ibv_ack_cq_events(cq, nevents);
// }
//
// // Helper function to get port state
// int get_port_state(struct ibv_context *context, uint8_t port_num, enum ibv_port_state *port_state) {
//     struct ibv_port_attr port_attr;
//     if (ibv_query_port(context, port_num, &port_attr)) {
//         return -1; // Error
//     }
//     *port_state = port_attr.state;
//     return 0; // Success
// }
import "C"

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Constants
const (
	// Protocol constants
	DefaultQKey uint32 = 0x11111111 // Standard QKey for UD operations
	GRHSize            = 40         // Size of GRH header
	// GIDIndex           = 3          // GID index for IPv4-mapped IPv6 addresses // Commented out: Now handled by preferredGIDIndex or fallback

	// Buffer and Queue sizes
	MRSize                 = 4096 // Size of memory region for send/recv buffers
	CQSize                 = 50   // Size of Completion Queue
	InitialRecvBuffers     = 32   // Number of initial receive buffers to post
	SendCompChanBufferSize = 100  // Buffer size for send completion channel
	RecvCompChanBufferSize = 100  // Buffer size for receive completion channel
	ErrChanBufferSize      = 100  // Buffer size for error channel
	MaxWorkCompletions     = 10   // Max number of work completions to poll at once

	// Timeout durations
	SendCompletionTimeout = 5 * time.Second       // Timeout for waiting for send completion
	AckSendTimeout        = 10 * time.Millisecond // Timeout for waiting for ACK send completion

	// GRH/IPv4 parsing constants
	IPv4HeaderOffset    = 20 // Offset to the supposed IPv4 header within the GRH region
	IPv4HeaderMinLength = 20 // Minimum length of an IPv4 header
)

// GRHHeaderInfo holds extracted information from the GRH.
type GRHHeaderInfo struct {
	SourceGID string
	DestGID   string
	FlowLabel uint32
	// Add other relevant GRH fields if needed by the handler
}

// IncomingAckInfo holds information about a received ACK packet to be passed to the handler.
type IncomingAckInfo struct {
	Packet      *ProbePacket     // The deserialized ProbePacket
	ReceivedAt  time.Time        // Timestamp when the ACK was processed by the CQ poller
	GRHInfo     *GRHHeaderInfo   // Information from GRH, if present
	SourceQP    uint32           // Source QP from the work completion (remote QPN)
	RawWC       *C.struct_ibv_wc // Raw work completion for any other details. Use with caution.
	AckStatusOK bool             // True if the RDMA work completion for this ACK was successful.
}

// AckHandlerFunc is a callback function type for processing incoming ACK packets.
// It's called by the CQ poller when an ACK is received on a sender queue.
type AckHandlerFunc func(ackInfo *IncomingAckInfo)

// UDQueueType defines the role of the UDQueue
type UDQueueType int

const (
	// UDQueueTypeSender is used for sending probes and receiving ACKs
	UDQueueTypeSender UDQueueType = iota
	// UDQueueTypeResponder is used for receiving probes and sending ACKs
	UDQueueTypeResponder
)

// RNIC represents an RDMA NIC device
type RNIC struct {
	Context        *C.struct_ibv_context
	Device         *C.struct_ibv_device
	DeviceName     string
	GID            string
	IPAddr         string
	PD             *C.struct_ibv_pd
	IsOpen         bool
	ActiveGIDIndex uint8               // Added to store the active GID index
	ActivePortNum  uint8               // Added to store the active port number
	SenderQueue    *UDQueue            // Queue for sending probes and receiving ACKs
	ResponderQueue *UDQueue            // Queue for receiving probes and sending ACKs
	UDQueues       map[string]*UDQueue // Map of keys to UDQueue for backward compatibility
}

// UDQueue represents a UD QP and associated resources
type UDQueue struct {
	RNIC        *RNIC
	QP          *C.struct_ibv_qp
	CQ          *C.struct_ibv_cq
	CompChannel *C.struct_ibv_comp_channel
	SendMR      *C.struct_ibv_mr
	RecvMR      *C.struct_ibv_mr
	SendBuf     unsafe.Pointer
	RecvBuf     unsafe.Pointer
	QPN         uint32
	QueueType   UDQueueType // Type of queue (sender or responder)

	// Channels for CQ completion event notifications
	sendCompChan chan *C.struct_ibv_wc // Channel for send completion events
	recvCompChan chan *C.struct_ibv_wc // Channel for receive completion events (non-ACKs or if no handler)
	errChan      chan error            // Channel for error notifications

	// CQ polling goroutine control
	cqPollerRunning bool
	cqPollerDone    chan struct{}
	cqPollerMutex   sync.Mutex

	// ACK handler for sender queues
	ackHandler AckHandlerFunc
}

// CompletionType defines the type of work completion
type CompletionType int

const (
	// CompletionTypeSend indicates a send completion
	CompletionTypeSend CompletionType = iota
	// CompletionTypeRecv indicates a receive completion
	CompletionTypeRecv
)

// WorkCompletionEvent represents a work completion event with its metadata
type WorkCompletionEvent struct {
	WC             C.struct_ibv_wc
	CompletionType CompletionType
	Timestamp      time.Time
}

// RDMAManager manages RDMA devices and operations
type RDMAManager struct {
	Devices           []*RNIC
	SenderUDQueues    map[string]*UDQueue // Map of GID to sender UDQueue
	ResponderUDQueues map[string]*UDQueue // Map of GID to responder UDQueue
	UDQueues          map[string]*UDQueue // Map of unique keys to UDQueue for backward compatibility
}

// ProbePacket represents the format of a probe packet
type ProbePacket struct {
	SequenceNum uint64
	T1          uint64 // Timestamp 1 (post send time in ns)
	T3          uint64 // Timestamp 3 (receive time in ns)
	T4          uint64 // Timestamp 4 (responder ACK time in ns)
	IsAck       uint8  // 0 for probe, 1 for ACK
	AckType     uint8  // 1 for first ACK, 2 for second ACK with processing delay
	Flags       uint8  // Reserved for future use
	Padding     [1]byte
}

// WorkCompletion contains extracted work completion info
type WorkCompletion struct {
	Status    uint32
	SrcQP     uint32
	SGID      string
	DGID      string
	IMM       uint32
	VendorErr uint32
	FlowLabel uint32
}

// Placeholder structure for go build to succeed even if we don't have the actual header
type ibv_wc struct {
	status     uint32
	vendor_err uint32
	byte_len   uint32
	imm_data   uint32
	qp_num     uint32
	src_qp     uint32
	wc_flags   uint32
}

// NewRDMAManager creates a new RDMA manager
func NewRDMAManager() (*RDMAManager, error) {
	// Seed the random number generator for PSN generation
	rand.Seed(time.Now().UnixNano())

	manager := &RDMAManager{
		SenderUDQueues:    make(map[string]*UDQueue),
		ResponderUDQueues: make(map[string]*UDQueue),
		UDQueues:          make(map[string]*UDQueue),
	}

	// Get list of RDMA devices
	var numDevices C.int
	deviceList := C.ibv_get_device_list(&numDevices)
	if deviceList == nil {
		return nil, fmt.Errorf("failed to get RDMA device list")
	}
	defer C.ibv_free_device_list(deviceList)

	if numDevices == 0 {
		return nil, fmt.Errorf("no RDMA devices found")
	}

	// Iterate through all devices
	for i := 0; i < int(numDevices); i++ {
		device := *(**C.struct_ibv_device)(unsafe.Pointer(uintptr(unsafe.Pointer(deviceList)) + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		if device == nil {
			continue
		}

		deviceName := C.GoString(C.ibv_get_device_name(device))
		log.Debug().Str("device", deviceName).Msg("Found RDMA device")

		rnic := &RNIC{
			Device:     device,
			DeviceName: deviceName,
			IsOpen:     false,
		}
		manager.Devices = append(manager.Devices, rnic)
	}

	return manager, nil
}

// isIPv4MappedIPv6 checks if the given IP byte slice represents an IPv4-mapped IPv6 address
// (::ffff:A.B.C.D format) by checking if bytes 10 and 11 are 0xFF
func isIPv4MappedIPv6(ipBytes []byte) bool {
	return len(ipBytes) == 16 && ipBytes[10] == 0xff && ipBytes[11] == 0xff
}

// formatGIDString creates the appropriate string representation of a GID.
// For IPv4-mapped IPv6 addresses, it preserves the ::ffff: prefix.
func formatGIDString(gidBytes []byte) string {
	if isIPv4MappedIPv6(gidBytes) {
		// Extract the IPv4 part and prepend the ::ffff: prefix
		ipv4Part := fmt.Sprintf("%d.%d.%d.%d", gidBytes[12], gidBytes[13], gidBytes[14], gidBytes[15])
		return "::ffff:" + ipv4Part
	}
	// For normal IPv6 addresses, use the standard string representation
	return net.IP(gidBytes).String()
}

// releaseDeviceResources deallocates PD and closes device context
func (r *RNIC) releaseDeviceResources() {
	if r.PD != nil {
		C.ibv_dealloc_pd(r.PD)
		r.PD = nil
	}
	if r.Context != nil {
		C.ibv_close_device(r.Context)
		r.Context = nil
	}
}

// OpenDevice opens the RDMA device and initializes its resources using the specified GID index.
func (r *RNIC) OpenDevice(gidIndex int) error {
	if r.IsOpen {
		return nil
	}

	if gidIndex < 0 {
		return fmt.Errorf("gidIndex must be >= 0, got %d for device %s", gidIndex, r.DeviceName)
	}

	// Open device context
	context := C.ibv_open_device(r.Device)
	if context == nil {
		return fmt.Errorf("failed to open device %s", r.DeviceName)
	}
	r.Context = context

	// Allocate protection domain
	pd := C.ibv_alloc_pd(r.Context)
	if pd == nil {
		C.ibv_close_device(r.Context)
		return fmt.Errorf("failed to allocate protection domain for device %s", r.DeviceName)
	}
	r.PD = pd

	// Query device attributes to get the number of physical ports
	var physPortCnt C.uint8_t
	if C.get_phys_port_cnt(r.Context, &physPortCnt) != 0 {
		r.releaseDeviceResources()
		return fmt.Errorf("failed to query device attributes for %s", r.DeviceName)
	}

	if physPortCnt == 0 {
		r.releaseDeviceResources()
		return fmt.Errorf("device %s has 0 physical ports", r.DeviceName)
	}

	var activePortNumFound C.uint8_t = 0
	var gidFound C.union_ibv_gid
	var usableGIDFound bool = false

	// Iterate over physical ports to find an active one and use the specified gidIndex
	for portNum := C.uint8_t(1); portNum <= physPortCnt; portNum++ {
		var portAttr C.struct_ibv_port_attr
		if ret := C.my_ibv_query_port(r.Context, portNum, &portAttr); ret != 0 {
			log.Warn().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", gidIndex).Msg("Failed to query port, skipping port.")
			continue
		}

		if portAttr.state != C.IBV_PORT_ACTIVE {
			log.Debug().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", gidIndex).Msg("Port not active, skipping port.")
			continue
		}

		// Port is active, try to query the GID at the specified index
		var currentGid C.union_ibv_gid
		if ret := C.ibv_query_gid(r.Context, portNum, C.int(gidIndex), &currentGid); ret == 0 {
			gidBytes := unsafe.Slice((*byte)(unsafe.Pointer(&currentGid)), C.sizeof_union_ibv_gid)
			// Basic validation: ensure GID is not all zeros
			isZeroGid := true
			for _, b := range gidBytes {
				if b != 0 {
					isZeroGid = false
					break
				}
			}
			if !isZeroGid {
				log.Info().
					Str("device", r.DeviceName).
					Uint8("port", uint8(portNum)).
					Int("gid_index", gidIndex).
					Str("gid", formatGIDString(gidBytes)).
					Msg("Found and using GID from specified GID index on active port.")
				activePortNumFound = portNum
				gidFound = currentGid
				usableGIDFound = true
				break // Found a usable GID on an active port, stop searching
			} else {
				log.Warn().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", gidIndex).Msg("Specified GID index resulted in a zero GID on this active port.")
			}
		} else {
			log.Warn().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", gidIndex).Msg("Failed to query GID at specified GID index on this active port.")
		}
	}

	if !usableGIDFound {
		r.releaseDeviceResources()
		return fmt.Errorf("no usable GID found for device %s on any active port with GID index %d", r.DeviceName, gidIndex)
	}

	r.ActiveGIDIndex = uint8(gidIndex) // Store the specified GID index
	r.ActivePortNum = uint8(activePortNumFound)

	// Get GID bytes and format GID string
	gidBytes := unsafe.Slice((*byte)(unsafe.Pointer(&gidFound)), C.sizeof_union_ibv_gid)
	r.GID = formatGIDString(gidBytes)

	// Extract IPv6 for address resolution
	ipv6 := net.IP(gidBytes)

	// Get IP address from network interface or fall back to GID
	r.IPAddr = r.getIPAddress(ipv6)

	r.IsOpen = true
	log.Info().Str("device", r.DeviceName).Str("gid", r.GID).Str("ip", r.IPAddr).Int("used_gid_index", int(r.ActiveGIDIndex)).Msg("Opened RDMA device")
	return nil
}

// getIPAddress tries to get the IP address from the network interface
// and falls back to GID-based extraction if that fails
func (r *RNIC) getIPAddress(ipv6 net.IP) string {
	// Try to get IP address from the network interface
	if ipAddr := r.getIPAddressFromInterface(); ipAddr != "" {
		return ipAddr
	}

	// Fall back to GID-based extraction
	// For IPAddr field, we want a clean IPv4 or IPv6 address without ::ffff: prefix
	return r.getIPAddressFromGID(ipv6, false)
}

// getIPAddressFromInterface gets the IPv4 address from the network interface
// associated with the RNIC, returns empty string if not found
func (r *RNIC) getIPAddressFromInterface() string {
	// Get network interface name from /sys/class/infiniband/<device>/device/net
	netDir := fmt.Sprintf("/sys/class/infiniband/%s/device/net", r.DeviceName)
	netDirEntries, err := os.ReadDir(netDir)
	if err != nil {
		log.Warn().Str("device", r.DeviceName).Err(err).Msg("Failed to read network interfaces directory")
		return ""
	}

	// Check if there are any interfaces
	if len(netDirEntries) == 0 {
		log.Warn().Str("device", r.DeviceName).Msg("No network interfaces found")
		return ""
	}

	// Get the first interface (there should typically be only one)
	ifName := netDirEntries[0].Name()
	log.Debug().Str("device", r.DeviceName).Str("interface", ifName).Msg("Found network interface for RDMA device")

	// Get the IPv4 address for this interface
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Warn().Str("device", r.DeviceName).Str("interface", ifName).Err(err).Msg("Failed to get interface")
		return ""
	}

	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		log.Warn().Str("device", r.DeviceName).Str("interface", ifName).Err(err).Msg("Failed to get interface addresses")
		return ""
	}

	// Find the first IPv4 address
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipv4 := ipNet.IP.To4(); ipv4 != nil {
			log.Debug().Str("device", r.DeviceName).Str("interface", ifName).Str("ipv4", ipv4.String()).Msg("Found IPv4 address for interface")
			return ipv4.String()
		}
	}

	log.Warn().Str("device", r.DeviceName).Str("interface", ifName).Msg("No IPv4 address found for interface")
	return ""
}

// getIPAddressFromGID extracts IPv4 from IPv6 GID if it's an IPv4-mapped IPv6 address
// If preserveFormat is true, IPv4-mapped IPv6 addresses are returned in ::ffff:A.B.C.D format
func (r *RNIC) getIPAddressFromGID(ipv6 net.IP, preserveFormat ...bool) string {
	// Check if it's an IPv4-mapped IPv6 address
	if ipv4 := ipv6.To4(); ipv4 != nil {
		// If preserveFormat flag is set to true, keep the ::ffff: prefix
		if len(preserveFormat) > 0 && preserveFormat[0] {
			// Extract the raw bytes
			gidBytes := []byte(ipv6)
			// Check if it has the IPv4-mapped IPv6 pattern (bytes 10-11 are 0xFF)
			if len(gidBytes) == 16 && gidBytes[10] == 0xff && gidBytes[11] == 0xff {
				// Get the IPv4 part and format it with the prefix
				ipv4Part := fmt.Sprintf("%d.%d.%d.%d", gidBytes[12], gidBytes[13], gidBytes[14], gidBytes[15])
				return "::ffff:" + ipv4Part
			}
		}
		// Default behavior: convert to native IPv4 format
		return ipv4.String()
	}
	// Not an IPv4-mapped address, return the normal IPv6 representation
	return ipv6.String()
}

// CloseDevice closes the RDMA device and frees its resources
func (r *RNIC) CloseDevice() {
	if !r.IsOpen {
		return
	}

	if r.PD != nil {
		C.ibv_dealloc_pd(r.PD)
		r.PD = nil
	}

	if r.Context != nil {
		C.ibv_close_device(r.Context)
		r.Context = nil
	}

	r.IsOpen = false
	log.Debug().Str("device", r.DeviceName).Msg("Closed RDMA device")
}

// processCQCompletions polls for work completions and processes them.
func (u *UDQueue) processCQCompletions(wc *C.struct_ibv_wc, numWCElements int) {
	for i := 0; i < numWCElements; i++ {
		// It's crucial to create a new C.struct_ibv_wc for each completion.
		// Otherwise, if we pass &wc[i] directly to the channel,
		// all channel receivers might end up with a pointer to the same memory location
		// (the last element in the original wc array after the loop finishes),
		// leading to incorrect data processing.
		// C.memcpy ensures that we are copying the content of the work completion
		// into a newly allocated memory for each event.
		//
		// The Go garbage collector is not aware of memory allocated by C.malloc.
		// This memory must be explicitly freed using C.free() when it's no longer needed.
		// In this CQ poller, the responsibility to free wcCopy lies with the goroutine
		// that receives it from the sendCompChan or recvCompChan.
		// For ACK packets processed by ackHandler, if rawWC is used, its lifetime
		// must be managed carefully or copied into Go-managed memory.
		wcSize := unsafe.Sizeof(C.struct_ibv_wc{})
		wcCopy := (*C.struct_ibv_wc)(C.malloc((C.size_t)(wcSize)))
		if wcCopy == nil {
			log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("Failed to allocate memory for wcCopy")
			continue
		}

		// Correct pointer arithmetic to access the i-th element of the C array wc
		currentWc := (*C.struct_ibv_wc)(unsafe.Pointer(uintptr(unsafe.Pointer(wc)) + uintptr(i)*wcSize))

		C.memcpy(unsafe.Pointer(wcCopy), unsafe.Pointer(currentWc), (C.size_t)(wcSize))

		// currentWc is already a pointer to the correct wc element due to the above calculation
		log.Trace().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Uint32("status", (uint32)(currentWc.status)).
			Uint64("wr_id", uint64(currentWc.wr_id)).
			Uint32("opcode", uint32(currentWc.opcode)).
			Msg("Processing WC")

		if currentWc.status != C.IBV_WC_SUCCESS {
			u.handleWCError(currentWc)
			C.free(unsafe.Pointer(wcCopy)) // Free if there was an error and not sending
			continue
		}

		switch currentWc.opcode {
		case C.IBV_WC_RECV:
			u.handleRecvCompletion(currentWc, wcCopy) // wcCopy is freed by handleRecvCompletion or receiver
		case C.IBV_WC_SEND:
			u.handleSendCompletion(wcCopy) // wcCopy is freed by receiver
		default:
			log.Warn().
				Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
				Str("type", getQueueTypeString(u.QueueType)).
				Int("opcode", int(currentWc.opcode)).
				Msg("Received unknown WC opcode")
			C.free(unsafe.Pointer(wcCopy)) // Free if not handled
		}
	}
}

func (u *UDQueue) handleWCError(wc *C.struct_ibv_wc) {
	errMsg := fmt.Sprintf("CQ Poller: WC error for QPN 0x%x, Type: %s, Status: %s (%d), Vendor Syndrome: 0x%x, Opcode: %d",
		u.QPN,
		getQueueTypeString(u.QueueType),
		C.GoString(C.ibv_wc_status_str(wc.status)),
		wc.status,
		wc.vendor_err,
		wc.opcode)
	log.Error().Msg(errMsg)
	select {
	case u.errChan <- fmt.Errorf(errMsg):
	default:
		log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping WC error")
	}
}

func (u *UDQueue) handleRecvCompletion(wc *C.struct_ibv_wc, wcCopy *C.struct_ibv_wc) {
	receivedAt := time.Now()
	log.Debug().
		Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
		Str("type", getQueueTypeString(u.QueueType)).
		Uint32("bytes", (uint32)(wc.byte_len)).
		Uint32("src_qp", (uint32)(wc.src_qp)).
		Uint32("wc_flags", (uint32)(wc.wc_flags)).
		Msg("IBV_WC_RECV")

	var probePkt *ProbePacket
	var grhInfo *GRHHeaderInfo

	// The GRH is at the beginning of the u.RecvBuf (or the specific buffer for this WR_ID).
	// Data starts after GRH.
	probePacketStructSize := unsafe.Sizeof(ProbePacket{})
	expectedMinLengthWithGRH := GRHSize + int(probePacketStructSize)
	expectedMinLengthNoGRH := int(probePacketStructSize)

	var currentExpectedMinLength int
	if (wc.wc_flags & C.IBV_WC_GRH) == 0 {
		// If no GRH flag, assume packet starts immediately. This is unusual for UD but handle defensively.
		currentExpectedMinLength = expectedMinLengthNoGRH
		log.Warn().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Msg("IBV_WC_RECV without IBV_WC_GRH flag. Assuming ProbePacket is at buffer start.")
	} else {
		currentExpectedMinLength = expectedMinLengthWithGRH
	}

	if wc.byte_len < C.uint32_t(currentExpectedMinLength) {
		log.Error().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Uint32("received_bytes", (uint32)(wc.byte_len)).
			Int("expected_min_bytes", currentExpectedMinLength). // Changed to Int
			Bool("grh_flag_present", (wc.wc_flags&C.IBV_WC_GRH) != 0).
			Msg("Received packet too small")
		C.free(unsafe.Pointer(wcCopy))
		if err := u.PostRecv(); err != nil { // Attempt to repost buffer even on error
			log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msgf("Failed to repost recv buffer after small packet error: %v", err)
		}
		return
	}

	var payloadStartPtr unsafe.Pointer
	if (wc.wc_flags & C.IBV_WC_GRH) != 0 {
		grhStartPtr := u.RecvBuf // Assuming RecvBuf points to the start of the received data including GRH for WR_ID.
		payloadStartPtr = unsafe.Pointer(uintptr(grhStartPtr) + GRHSize)
		probePkt = (*ProbePacket)(payloadStartPtr)

		grhRaw := (*C.struct_ibv_grh)(grhStartPtr)
		sgidBytes := make([]byte, 16)
		// Use address of the union itself, as 'raw' is the first field.
		C.memcpy(unsafe.Pointer(&sgidBytes[0]), unsafe.Pointer(&grhRaw.sgid), 16)
		dgidBytes := make([]byte, 16)
		// Use address of the union itself, as 'raw' is the first field.
		C.memcpy(unsafe.Pointer(&dgidBytes[0]), unsafe.Pointer(&grhRaw.dgid), 16)

		flowLabelRawN := grhRaw.version_tclass_flow
		flowLabelRawH := C.ntohl(flowLabelRawN)
		flowLabel := uint32(flowLabelRawH & 0x000FFFFF)

		grhInfo = &GRHHeaderInfo{
			SourceGID: formatGIDString(sgidBytes),
			DestGID:   formatGIDString(dgidBytes),
			FlowLabel: flowLabel,
		}
		log.Trace().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Str("sgid", grhInfo.SourceGID).
			Str("dgid", grhInfo.DestGID).
			Uint32("flow_label", grhInfo.FlowLabel).
			Msg("GRH Info Extracted")
	} else {
		// No GRH flag, ProbePacket is at the start of u.RecvBuf
		probePkt = (*ProbePacket)(u.RecvBuf)
	}

	if u.QueueType == UDQueueTypeSender && u.ackHandler != nil && probePkt.IsAck == 1 {
		log.Trace().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Uint64("seq", probePkt.SequenceNum).
			Msg("ACK packet received on Sender Queue, calling ackHandler")

		ackInfo := &IncomingAckInfo{
			Packet:      probePkt,
			ReceivedAt:  receivedAt,
			GRHInfo:     grhInfo,
			SourceQP:    uint32(wc.src_qp),
			RawWC:       wc, // Pass original wc (not wcCopy) for inspection. Handler should not store this pointer.
			AckStatusOK: true,
		}
		u.ackHandler(ackInfo)
		C.free(unsafe.Pointer(wcCopy)) // Free wcCopy after handler returns.
	} else {
		log.Debug().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Uint64("seq", func() uint64 { // Defensive access to SequenceNum
				if probePkt != nil {
					return probePkt.SequenceNum
				}
				return 0
			}()).
			Msg("Non-ACK packet or no handler/responder queue, sending to recvCompChan")
		select {
		case u.recvCompChan <- wcCopy:
		default:
			log.Warn().
				Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
				Str("type", getQueueTypeString(u.QueueType)).
				Msg("Receive completion channel full, dropping WC_RECV event. wcCopy will be freed.")
			C.free(unsafe.Pointer(wcCopy))
		}
	}

	if err := u.PostRecv(); err != nil {
		errMsg := fmt.Sprintf("CQ Poller: Failed to repost receive buffer for QPN 0x%x, Type: %s: %v", u.QPN, getQueueTypeString(u.QueueType), err)
		log.Error().Msg(errMsg)
		select {
		case u.errChan <- fmt.Errorf(errMsg):
		default:
			log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping repost error")
		}
	}
}

func (u *UDQueue) handleSendCompletion(wcCopy *C.struct_ibv_wc) {
	log.Debug().
		Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
		Str("type", getQueueTypeString(u.QueueType)).
		Msg("IBV_WC_SEND")
	select {
	case u.sendCompChan <- wcCopy:
	default:
		log.Warn().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Msg("Send completion channel full, dropping WC_SEND event. wcCopy will be freed.")
		C.free(unsafe.Pointer(wcCopy))
	}
}

// StartCQPoller starts the Completion Queue (CQ) poller goroutine.
// This goroutine listens for completion events on the CQ's completion channel,
// polls the CQ for work completions (WCs), and dispatches them appropriately.
func (u *UDQueue) StartCQPoller() {
	u.cqPollerMutex.Lock()
	if u.cqPollerRunning {
		u.cqPollerMutex.Unlock()
		log.Info().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ poller already running.")
		return
	}
	u.cqPollerRunning = true
	u.cqPollerDone = make(chan struct{})
	u.cqPollerMutex.Unlock()

	log.Info().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("Starting CQ poller...")

	go func() {
		defer func() {
			u.cqPollerMutex.Lock()
			u.cqPollerRunning = false
			log.Info().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ poller stopped.")
			u.cqPollerMutex.Unlock()
		}()

		wc := make([]C.struct_ibv_wc, MaxWorkCompletions)

		if u.CompChannel == nil {
			errMsg := fmt.Sprintf("CQ Poller: Completion channel is nil for QPN 0x%x, Type: %s. Poller cannot start.", u.QPN, getQueueTypeString(u.QueueType))
			log.Error().Msg(errMsg)
			select {
			case u.errChan <- fmt.Errorf(errMsg):
			default:
				log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping nil completion channel error")
			}
			return
		}

		// Initial request for CQ notification.
		retValInitialNotify := C.ibv_req_notify_cq(u.CQ, 0) // 0 for any completion
		if retValInitialNotify != 0 {
			errMsg := fmt.Sprintf("CQ Poller: Failed to request initial CQ notification for QPN 0x%x, Type: %s: %s. Poller exiting.", u.QPN, getQueueTypeString(u.QueueType), syscall.Errno(retValInitialNotify).Error())
			log.Error().Msg(errMsg)
			select {
			case u.errChan <- fmt.Errorf(errMsg):
			default:
				log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping initial CQ notification error")
			}
			return
		}

		for {
			select {
			case <-u.cqPollerDone:
				log.Info().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ poller received done signal. Exiting.")
				return
			default:
				// Proceed to wait for CQ event.
			}

			var cqEv *C.struct_ibv_cq
			var cqCtx unsafe.Pointer

			log.Trace().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ poller: Waiting for CQ event...")
			retGetEvent := C.ibv_get_cq_event(u.CompChannel, &cqEv, &cqCtx)
			if retGetEvent != 0 {
				select {
				case <-u.cqPollerDone: // Check if stopping, to suppress error spam during shutdown.
					log.Info().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ poller: ibv_get_cq_event failed during shutdown. Normal.")
					return
				default:
					// For ibv_get_cq_event, a non-zero return usually indicates an error with the comp_channel fd itself
					log.Error().
						Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
						Str("type", getQueueTypeString(u.QueueType)).
						Int("ret", int(retGetEvent)). // Cast C int to Go int for logger
						Msg("ibv_get_cq_event failed")
					select {
					case u.errChan <- fmt.Errorf("ibv_get_cq_event failed"):
					default:
						log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping ibv_get_cq_event error")
					}
					return
				}
			}

			// It is important to check if cqEv is nil, or if it matches u.CQ.
			// According to examples, cqEv should be the CQ associated with the event.
			if cqEv == nil {
				log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ Poller: ibv_get_cq_event returned nil cqEv. This is unexpected. Continuing after ack and re-arm.")
				// Acknowledge on u.CQ if cqEv is nil, assuming it's for our CQ.
				C.ibv_ack_cq_events(u.CQ, 1)
				if C.ibv_req_notify_cq(u.CQ, 0) != 0 {
					log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("CQ Poller: Failed to re-request CQ notification on u.CQ after nil cqEv.")
				}
				continue // Try to recover.
			}

			if cqEv != u.CQ {
				log.Warn().
					Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
					Str("type", getQueueTypeString(u.QueueType)).
					Msgf("CQ Poller: Event from cq %p does not match expected cq %p. Acking event on cqEv and re-arming u.CQ.", cqEv, u.CQ)
				C.ibv_ack_cq_events(cqEv, 1)           // Ack on the CQ that generated the event.
				if C.ibv_req_notify_cq(u.CQ, 0) != 0 { // Re-arm our CQ.
					log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("CQ Poller: Failed to re-request CQ notification on u.CQ after mismatched event.")
				}
				continue // This situation is odd; continue and hope our CQ gets events.
			}

			C.ibv_ack_cq_events(cqEv, 1) // Acknowledge the event on the correct CQ.

			// Re-request notification for the next completion event.
			retReNotify := C.ibv_req_notify_cq(u.CQ, 0)
			if retReNotify != 0 {
				errMsg := fmt.Sprintf("CQ Poller: Failed to re-request CQ notification for QPN 0x%x, Type: %s: %s. Continuing, but may miss events.", u.QPN, getQueueTypeString(u.QueueType), syscall.Errno(retReNotify).Error())
				log.Error().Msg(errMsg)
				// Non-fatal, but log it. Polling might still pick up WCs already there.
				select {
				case u.errChan <- fmt.Errorf(errMsg):
				default:
					log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping CQ re-request notification error")
				}
			}

			numWCElements := int(C.ibv_poll_cq(u.CQ, C.int(MaxWorkCompletions), &wc[0]))
			if numWCElements < 0 {
				errMsg := fmt.Sprintf("CQ Poller: ibv_poll_cq failed for QPN 0x%x, Type: %s, Return: %d. Poller exiting.", u.QPN, getQueueTypeString(u.QueueType), numWCElements)
				log.Error().Msg(errMsg)
				select {
				case u.errChan <- fmt.Errorf(errMsg):
				default:
					log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping ibv_poll_cq error")
				}
				return
			}

			if numWCElements > 0 {
				log.Debug().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Int("count", numWCElements).Msg("Polled work completions")
				u.processCQCompletions(&wc[0], numWCElements)
			} else {
				log.Trace().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ poller: ibv_poll_cq returned 0 WCs after event.")
			}
		}
	}()
}

// StopCQPoller stops the CQ poller goroutine.
func (u *UDQueue) StopCQPoller() {
	u.cqPollerMutex.Lock()
	defer u.cqPollerMutex.Unlock()

	if !u.cqPollerRunning {
		return
	}

	close(u.cqPollerDone)
	// Wait for goroutine to exit
	for u.cqPollerRunning {
		u.cqPollerMutex.Unlock()
		time.Sleep(10 * time.Millisecond)
		u.cqPollerMutex.Lock()
	}
}

// CreateUDQueue creates a UD queue pair for sending and receiving probe packets
func (m *RDMAManager) CreateUDQueue(rnic *RNIC, queueType UDQueueType, ackHandler AckHandlerFunc) (*UDQueue, error) {
	if !rnic.IsOpen {
		// If RNIC is not open, it implies OpenDevice was not called from AgentState with a specific GID index.
		// Opening it here without a gidIndex from config is problematic.
		// Consider making it mandatory for RNIC to be open before this call.
		return nil, fmt.Errorf("RNIC device %s is not open. CreateUDQueue requires an already opened RNIC.", rnic.DeviceName)
	}

	// Lazy initialization of RNIC's UDQueues map
	if rnic.UDQueues == nil {
		rnic.UDQueues = make(map[string]*UDQueue)
	}

	// Step 1: Create QP resources
	qp, cq, compChannel, psn, err := m.createQueuePair(rnic)
	if err != nil {
		return nil, err
	}

	// Step 2: Allocate memory resources
	sendBuf, recvBuf, sendMR, recvMR, err := m.allocateMemoryResources(rnic, qp, cq, compChannel)
	if err != nil {
		// Ensure resources from Step 1 are cleaned up if Step 2 fails
		if qp != nil {
			C.ibv_destroy_qp(qp)
		}
		if cq != nil {
			C.ibv_destroy_cq(cq)
		}
		if compChannel != nil {
			C.ibv_destroy_comp_channel(compChannel)
		}
		return nil, err
	}

	// Step 3: Create UDQueue struct
	udQueue := &UDQueue{
		RNIC:         rnic,
		QP:           qp,
		CQ:           cq,
		CompChannel:  compChannel,
		SendMR:       sendMR,
		RecvMR:       recvMR,
		SendBuf:      sendBuf,
		RecvBuf:      recvBuf,
		QPN:          uint32(qp.qp_num),
		QueueType:    queueType,
		sendCompChan: make(chan *C.struct_ibv_wc, SendCompChanBufferSize), // Buffered channel
		recvCompChan: make(chan *C.struct_ibv_wc, RecvCompChanBufferSize), // Buffered channel
		errChan:      make(chan error, ErrChanBufferSize),                 // Buffered channel
		cqPollerDone: make(chan struct{}),
		ackHandler:   ackHandler,
	}

	// Set ackHandler only for Sender queues
	if queueType == UDQueueTypeSender {
		udQueue.ackHandler = ackHandler
		if ackHandler == nil {
			log.Warn().Str("device", rnic.DeviceName).Uint32("qpn", udQueue.QPN).Msg("Creating Sender UDQueue without an ACK handler. ACKs will be sent to recvCompChan.")
		}
	}

	// Store the UDQueue in the maps based on its type
	mapKey := rnic.GID
	if queueType == UDQueueTypeSender {
		mapKey = mapKey + "_sender"
		rnic.SenderQueue = udQueue
		m.SenderUDQueues[rnic.GID] = udQueue
	} else {
		mapKey = mapKey + "_responder"
		rnic.ResponderQueue = udQueue
		m.ResponderUDQueues[rnic.GID] = udQueue
	}

	m.UDQueues[mapKey] = udQueue
	rnic.UDQueues[mapKey] = udQueue

	// Start CQ polling goroutine
	udQueue.StartCQPoller()

	// Post initial receive buffers
	numInitialRecvBuffers := InitialRecvBuffers // Using the constant
	log.Info().
		Str("device", rnic.DeviceName).
		Uint32("qpn", udQueue.QPN).
		Str("queueType", getQueueTypeString(queueType)).
		Int("num_initial_recv_buffers_to_post", numInitialRecvBuffers).
		Msg("Attempting to post initial receive buffers")

	for i := 0; i < numInitialRecvBuffers; i++ {
		if err := udQueue.PostRecv(); err != nil {
			log.Error().Err(err).
				Str("device", rnic.DeviceName).
				Uint32("qpn", udQueue.QPN).
				Str("queueType", getQueueTypeString(queueType)).
				Int("posted_count", i).
				Int("total_to_post", numInitialRecvBuffers).
				Msg("Failed to post an initial receive buffer")
			// Cleanup and return error
			udQueue.Destroy() // Important to clean up partially created queue
			return nil, fmt.Errorf("failed to post initial receive buffer %d/%d for device %s qpn %d: %w", i+1, numInitialRecvBuffers, rnic.DeviceName, udQueue.QPN, err)
		}
	}

	log.Info().
		Str("device", rnic.DeviceName).
		Uint32("qpn", udQueue.QPN).
		Uint32("psn", psn).
		Uint32("qkey", DefaultQKey).
		Str("queueType", getQueueTypeString(queueType)).
		Msg("Created UD queue pair")

	return udQueue, nil
}

// createQueuePair creates a Queue Pair and puts it in the RTS state
func (m *RDMAManager) createQueuePair(rnic *RNIC) (*C.struct_ibv_qp, *C.struct_ibv_cq, *C.struct_ibv_comp_channel, uint32, error) {
	// Create a completion event channel
	compChannel := C.ibv_create_comp_channel(rnic.Context)
	if compChannel == nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to create completion channel for device %s", rnic.DeviceName)
	}

	// Create completion queue with more entries for better throughput
	cq := C.ibv_create_cq(rnic.Context, CQSize, nil, compChannel, 0)
	if cq == nil {
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, fmt.Errorf("failed to create CQ for device %s", rnic.DeviceName)
	}

	// Generate random PSN as in ud_pingpong.c (24 bit value)
	psn := uint32(rand.Int31n(1 << 24))

	// QP creation attribute setting to standard
	var qpInitAttr C.struct_ibv_qp_init_attr
	qpInitAttr.qp_type = C.IBV_QPT_UD
	qpInitAttr.sq_sig_all = 0 // Set to 0 to match standard (flags specified in each WR)
	qpInitAttr.send_cq = cq
	qpInitAttr.recv_cq = cq

	// Set appropriate capacity for performance
	qpInitAttr.cap.max_send_wr = C.uint32_t(len(m.Devices) * 100)
	qpInitAttr.cap.max_recv_wr = C.uint32_t(len(m.Devices) * 100)
	qpInitAttr.cap.max_send_sge = 1
	qpInitAttr.cap.max_recv_sge = 1

	// Create the QP
	qp := C.ibv_create_qp(rnic.PD, &qpInitAttr)
	if qp == nil {
		C.ibv_destroy_cq(cq)
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, fmt.Errorf("failed to create QP for device %s", rnic.DeviceName)
	}

	// Modify QP to INIT state
	if err := m.modifyQPToInit(rnic, qp); err != nil {
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, err
	}

	// Modify QP to RTR state
	if err := m.modifyQPToRTR(rnic, qp); err != nil {
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, err
	}

	// Modify QP to RTS state
	if err := m.modifyQPToRTS(rnic, qp, psn); err != nil {
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, err
	}

	return qp, cq, compChannel, psn, nil
}

// modifyQPToInit transitions the QP to INIT state
func (m *RDMAManager) modifyQPToInit(rnic *RNIC, qp *C.struct_ibv_qp) error {
	var qpAttr C.struct_ibv_qp_attr
	qpAttr.qp_state = C.IBV_QPS_INIT
	qpAttr.pkey_index = 0
	qpAttr.port_num = C.uint8_t(rnic.ActivePortNum) // Use active port number from RNIC with cast
	qpAttr.qkey = C.uint32_t(DefaultQKey)

	if ret := C.ibv_modify_qp(qp, &qpAttr,
		C.IBV_QP_STATE|C.IBV_QP_PKEY_INDEX|C.IBV_QP_PORT|C.IBV_QP_QKEY); ret != 0 {
		return fmt.Errorf("failed to modify QP to INIT: %d", ret)
	}
	log.Debug().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Msg("QP state changed to INIT")

	// Query QP state after INIT
	var queriedQPAttr C.struct_ibv_qp_attr
	var queriedQPInitAttr C.struct_ibv_qp_init_attr
	if C.ibv_query_qp(qp, &queriedQPAttr, C.IBV_QP_STATE, &queriedQPInitAttr) == 0 {
		log.Debug().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Uint32("state", uint32(queriedQPAttr.qp_state)).Msg("Queried QP state after INIT")
	} else {
		log.Warn().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Msg("Failed to query QP state after INIT")
	}

	return nil
}

// modifyQPToRTR transitions the QP to RTR state
func (m *RDMAManager) modifyQPToRTR(rnic *RNIC, qp *C.struct_ibv_qp) error {
	var qpAttr C.struct_ibv_qp_attr
	qpAttr.qp_state = C.IBV_QPS_RTR
	if ret := C.ibv_modify_qp(qp, &qpAttr, C.IBV_QP_STATE); ret != 0 {
		return fmt.Errorf("failed to modify QP to RTR: %d", ret)
	}
	log.Debug().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Msg("QP state changed to RTR")

	// Query QP state after RTR
	var queriedQPAttr C.struct_ibv_qp_attr
	var queriedQPInitAttr C.struct_ibv_qp_init_attr
	if C.ibv_query_qp(qp, &queriedQPAttr, C.IBV_QP_STATE, &queriedQPInitAttr) == 0 {
		log.Debug().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Uint32("state", uint32(queriedQPAttr.qp_state)).Msg("Queried QP state after RTR")
	} else {
		log.Warn().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Msg("Failed to query QP state after RTR")
	}

	return nil
}

// modifyQPToRTS transitions the QP to RTS state
func (m *RDMAManager) modifyQPToRTS(rnic *RNIC, qp *C.struct_ibv_qp, psn uint32) error {
	var qpAttr C.struct_ibv_qp_attr
	qpAttr.qp_state = C.IBV_QPS_RTS
	qpAttr.sq_psn = C.uint32_t(psn)
	if ret := C.ibv_modify_qp(qp, &qpAttr, C.IBV_QP_STATE|C.IBV_QP_SQ_PSN); ret != 0 {
		return fmt.Errorf("failed to modify QP to RTS: %d", ret)
	}
	log.Debug().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Msg("QP state changed to RTS")

	// Query QP state after RTS
	var queriedQPAttr C.struct_ibv_qp_attr
	var queriedQPInitAttr C.struct_ibv_qp_init_attr
	if C.ibv_query_qp(qp, &queriedQPAttr, C.IBV_QP_STATE, &queriedQPInitAttr) == 0 {
		log.Debug().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Uint32("state", uint32(queriedQPAttr.qp_state)).Msg("Queried QP state after RTS")
	} else {
		log.Warn().Str("device", rnic.DeviceName).Uint32("qpn", uint32(qp.qp_num)).Msg("Failed to query QP state after RTS")
	}

	return nil
}

// allocateMemoryResources allocates memory buffers and registers memory regions
func (m *RDMAManager) allocateMemoryResources(rnic *RNIC, qp *C.struct_ibv_qp, cq *C.struct_ibv_cq, compChannel *C.struct_ibv_comp_channel) (unsafe.Pointer, unsafe.Pointer, *C.struct_ibv_mr, *C.struct_ibv_mr, error) {
	// Allocate send buffers
	bufferSize := C.size_t(MRSize + GRHSize)
	sendBuf := C.aligned_alloc(C.size_t(os.Getpagesize()), bufferSize)
	if sendBuf == nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to allocate send buffer")
	}
	C.memset(sendBuf, 0, bufferSize)

	recvBuf := C.aligned_alloc(C.size_t(os.Getpagesize()), bufferSize)
	if recvBuf == nil {
		C.free(sendBuf)
		return nil, nil, nil, nil, fmt.Errorf("failed to allocate receive buffer")
	}
	C.memset(recvBuf, 0, bufferSize)

	// Register memory regions with all necessary access flags
	sendMR := C.ibv_reg_mr(rnic.PD, sendBuf, bufferSize, C.IBV_ACCESS_LOCAL_WRITE)
	if sendMR == nil {
		C.free(recvBuf)
		C.free(sendBuf)
		return nil, nil, nil, nil, fmt.Errorf("failed to register send buffer MR")
	}

	recvMR := C.ibv_reg_mr(rnic.PD, recvBuf, bufferSize, C.IBV_ACCESS_LOCAL_WRITE)
	if recvMR == nil {
		C.ibv_dereg_mr(sendMR)
		C.free(recvBuf)
		C.free(sendBuf)
		return nil, nil, nil, nil, fmt.Errorf("failed to register receive buffer MR")
	}

	return sendBuf, recvBuf, sendMR, recvMR, nil
}

// CreateSenderAndResponderQueues creates both sender and responder UDQueues for a given RNIC
func (m *RDMAManager) CreateSenderAndResponderQueues(rnic *RNIC, senderAckHandler AckHandlerFunc) error {
	if !rnic.IsOpen {
		// Similar to CreateUDQueue, RNIC should be opened by AgentState with a specific GID index.
		return fmt.Errorf("RNIC device %s is not open. CreateSenderAndResponderQueues requires an already opened RNIC.", rnic.DeviceName)
	}

	// Create sender queue
	senderQueue, err := m.CreateUDQueue(rnic, UDQueueTypeSender, senderAckHandler)
	if err != nil {
		return fmt.Errorf("failed to create sender queue for device %s: %w", rnic.DeviceName, err)
	}
	log.Info().Str("device", rnic.DeviceName).Uint32("qpn", senderQueue.QPN).Msg("Created sender queue")

	// Create responder queue (no ack handler for responder)
	responderQueue, err := m.CreateUDQueue(rnic, UDQueueTypeResponder, nil)
	if err != nil {
		// Clean up sender queue if responder queue creation fails
		senderQueue.Destroy()
		return fmt.Errorf("failed to create responder queue for device %s: %w", rnic.DeviceName, err)
	}
	log.Info().Str("device", rnic.DeviceName).Uint32("qpn", responderQueue.QPN).Msg("Created responder queue")

	rnic.SenderQueue = senderQueue
	rnic.ResponderQueue = responderQueue

	return nil
}

// getQueueTypeString returns the string representation of the UDQueueType
func getQueueTypeString(queueType UDQueueType) string {
	switch queueType {
	case UDQueueTypeSender:
		return "Sender"
	case UDQueueTypeResponder:
		return "Responder"
	default:
		return "Unknown"
	}
}

// PostRecv posts a receive work request
func (u *UDQueue) PostRecv() error {
	// Use the C helper function that manages work request memory on C side
	// This avoids the "cgo argument has Go pointers to unpinned Go pointers" error
	ret := C.post_recv(
		u.QP,
		C.uint64_t(uintptr(u.RecvBuf)),
		C.uint32_t(MRSize+GRHSize),
		u.RecvMR.lkey,
	)
	if ret != 0 {
		return fmt.Errorf("ibv_post_recv failed: %d", ret)
	}
	return nil
}

// CreateAddressHandle creates a UD address handle for the target
func (u *UDQueue) CreateAddressHandle(targetGID string, flowLabel uint32) (*C.struct_ibv_ah, error) {
	log.Debug().
		Str("targetGID_input", targetGID).
		Uint8("portNum_input", u.RNIC.ActivePortNum). // Log active port from RNIC
		Uint32("flowLabel_input", flowLabel).
		Str("local_rnic_device", u.RNIC.DeviceName).
		Str("local_rnic_gid", u.RNIC.GID).
		Uint8("local_rnic_active_gid_idx", u.RNIC.ActiveGIDIndex).
		Msg("CreateAddressHandle: Input parameters")

	// Validate targetGID before creating address handle
	ipAddr := net.ParseIP(targetGID)
	if ipAddr == nil {
		log.Error().Str("invalid_target_gid", targetGID).Msg("CreateAddressHandle: Failed to parse target GID as IP address for AH creation")
		return nil, fmt.Errorf("failed to parse target GID '%s' as IP address for AH creation", targetGID)
	}
	log.Debug().Str("parsed_target_gid_for_ah", ipAddr.String()).Msg("CreateAddressHandle: Successfully parsed target GID for AH creation")

	ahAttr := C.struct_ibv_ah_attr{}
	ahAttr.is_global = 1
	ahAttr.port_num = C.uint8_t(u.RNIC.ActivePortNum) // Use active port from RNIC
	// ahAttr.sl = 0 // Service Level, typically 0
	// ahAttr.dlid = 0 // Destination LID, not used for RoCEv2 if is_global=1
	// ahAttr.src_path_bits = 0 // Source Path Bits, not typically used

	// GRH settings
	ahAttr.grh.flow_label = C.uint32_t(flowLabel)
	ahAttr.grh.sgid_index = C.uint8_t(u.RNIC.ActiveGIDIndex) // Use GID index from RNIC struct
	ahAttr.grh.hop_limit = 255                               // Max hop limit
	ahAttr.grh.traffic_class = 0                             // Default traffic class

	// Convert targetGID string to C.struct_ibv_gid
	ipv6 := ipAddr.To16()
	if ipv6 == nil {
		log.Error().Str("targetGID", targetGID).Msg("CreateAddressHandle: Target GID is not a valid IPv6 address after parsing")
		return nil, fmt.Errorf("target GID '%s' is not a valid IPv6 address", targetGID)
	}

	// Copy IPv6 GID bytes to ahAttr.grh.dgid using our C helper function
	C.copy_to_gid_raw(&ahAttr.grh.dgid, unsafe.Pointer(&ipv6[0]), 16)

	ah := C.ibv_create_ah(u.RNIC.PD, &ahAttr)
	if ah == nil {
		return nil, fmt.Errorf("failed to create address handle for GID %s, device: %s, targetGID: %s", u.RNIC.GID, u.RNIC.DeviceName, targetGID)
	}

	return ah, nil
}

// SendProbePacket sends a probe packet to the target
func (u *UDQueue) SendProbePacket(
	ctx context.Context,
	targetGID string,
	targetQPN uint32,
	sequenceNum uint64,
	sourcePort uint32,
	flowLabel uint32,
) (time.Time, error) {
	log.Debug().
		Str("target_dest_rnic_gid", targetGID).
		Uint32("target_dest_rnic_qpn", targetQPN).
		Uint32("source_port", sourcePort).
		Uint32("flow_label", flowLabel).
		Uint64("sequence_num", sequenceNum).
		Msg("sendProbe: Details of target for SendProbePacket")

	ah, err := u.CreateAddressHandle(targetGID, flowLabel)
	if err != nil {
		return time.Time{}, err
	}
	defer C.ibv_destroy_ah(ah)

	// Prepare the packet
	packet := (*ProbePacket)(u.SendBuf)
	C.memset(u.SendBuf, 0, C.size_t(unsafe.Sizeof(ProbePacket{})))
	packet.SequenceNum = sequenceNum
	packet.T1 = uint64(time.Now().UnixNano())
	packet.IsAck = 0 // Not an ACK

	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(DefaultQKey),
	); ret != 0 {
		return time.Time{}, fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.sendCompChan:
		// Received send completion event
		if wc.status != C.IBV_WC_SUCCESS {
			return time.Time{}, fmt.Errorf("send completion failed: %d", wc.status)
		}
		return time.Now(), nil
	case err := <-u.errChan:
		// Error occurred
		return time.Time{}, fmt.Errorf("error during send: %w", err)
	case <-ctx.Done(): // Context cancelled or timed out
		return time.Time{}, fmt.Errorf("send probe to (%s, %d, %d) timed out: %w", targetGID, targetQPN, sequenceNum, ctx.Err())
	}
}

// ReceivePacket waits for and processes a received packet using completion channel
func (u *UDQueue) ReceivePacket(ctx context.Context) (*ProbePacket, time.Time, *WorkCompletion, error) {
	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.recvCompChan:
		receiveTime := time.Now()
		workComp := &WorkCompletion{
			Status:    uint32(wc.status),
			SrcQP:     uint32(wc.src_qp),
			VendorErr: uint32(wc.vendor_err),
		}

		var packetDataPtr unsafe.Pointer
		var actualPayloadLength uint32
		expectedMinimumPayloadSize := uint32(unsafe.Sizeof(ProbePacket{}))
		grhPresent := (wc.wc_flags & C.IBV_WC_GRH) == C.IBV_WC_GRH

		if grhPresent {
			log.Debug().Msg("IBV_WC_GRH is set. Parsing GRH.")

			if uint32(wc.byte_len) < GRHSize { // GRHSize is 40
				log.Error().Uint32("wc_byte_len", uint32(wc.byte_len)).Msg("IBV_WC_GRH is set, but wc.byte_len is less than GRHSize (40 bytes).")
				return nil, receiveTime, workComp, fmt.Errorf("IBV_WC_GRH set but wc.byte_len (%d) < GRHSize (%d)", wc.byte_len, GRHSize)
			}

			// GRH is at the beginning of u.RecvBuf
			grhBytes := unsafe.Slice((*byte)(u.RecvBuf), GRHSize)
			ipVersion := (grhBytes[0] >> 4) & 0x0F

			if ipVersion == 4 {
				// User's "current IPv4 processing" - assumes IPv4 header info is at offset 20 within GRH
				// This interpretation of GRH for IPv4 is unusual. Standard RoCEv2 GRH is IPv6-formatted.
				log.Debug().Msg("GRH IP Version field is 4. Applying custom IPv4 header parsing logic (from GRH offset 20).")

				const ipv4HeaderOffsetInGRH = 20 // Current code's assumption
				const ipv4HeaderMinLength = 20   // Standard IPv4 header length

				if GRHSize < ipv4HeaderOffsetInGRH+ipv4HeaderMinLength {
					log.Error().Int("GRHSize", GRHSize).Int("ipv4HeaderOffsetInGRH", ipv4HeaderOffsetInGRH).Int("ipv4HeaderMinLength", ipv4HeaderMinLength).Msg("GRH is too small to contain an IPv4 header at the specified offset.")
					return nil, receiveTime, workComp, fmt.Errorf("GRH too small for IPv4 header at offset %d", ipv4HeaderOffsetInGRH)
				}

				ipv4HeaderBytes := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(u.RecvBuf)+uintptr(ipv4HeaderOffsetInGRH))), ipv4HeaderMinLength)
				parsedIPv4Header, err := ipv4.ParseHeader(ipv4HeaderBytes)
				if err != nil {
					log.Warn().Err(err).Bytes("data", ipv4HeaderBytes).Msg("Failed to parse bytes from GRH offset 20 as IPv4 header.")
					return nil, receiveTime, workComp, fmt.Errorf("failed to parse GRH region's IPv4 header part (offset 20): %w", err)
				}

				if parsedIPv4Header.Src == nil || parsedIPv4Header.Dst == nil {
					log.Error().Msg("Parsed IPv4 header from GRH offset 20, but Src or Dst IP is nil.")
					return nil, receiveTime, workComp, fmt.Errorf("parsed IPv4 header from GRH (offset 20), but Src/Dst IP is nil")
				}
				log.Debug().Str("parsed_ipv4_header", parsedIPv4Header.String()).Msg("Successfully parsed IPv4 Header from GRH offset 20")

				srcIPv4 := parsedIPv4Header.Src.To4()
				dstIPv4 := parsedIPv4Header.Dst.To4()

				if srcIPv4 == nil || dstIPv4 == nil {
					log.Error().Str("ipv4.Src", parsedIPv4Header.Src.String()).Str("ipv4.Dst", parsedIPv4Header.Dst.String()).Msg("Could not convert parsed Src/Dst IP (from GRH offset 20) to IPv4.")
					return nil, receiveTime, workComp, fmt.Errorf("could not convert GRH region's IPv4 Src/Dst (offset 20) to 4-byte format")
				}

				// Convert to IPv4-mapped IPv6 GID strings for workComp
				srcMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, srcIPv4[0], srcIPv4[1], srcIPv4[2], srcIPv4[3]}
				dstMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, dstIPv4[0], dstIPv4[1], dstIPv4[2], dstIPv4[3]}
				workComp.SGID = formatGIDString(srcMappedIPv6Bytes)
				workComp.DGID = formatGIDString(dstMappedIPv6Bytes)

			} else if ipVersion == 6 {
				log.Debug().Msg("GRH IP Version field is 6. Parsing SGID/DGID from standard GRH fields.")
				// Standard RoCEv2 GRH (IPv6 Format)
				// Source GID: GRH bytes 8-23
				sgidSlice := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(u.RecvBuf)+8)), 16)
				// Destination GID: GRH bytes 24-39
				dgidSlice := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(u.RecvBuf)+24)), 16)

				workComp.SGID = formatGIDString(sgidSlice)
				workComp.DGID = formatGIDString(dgidSlice)

				// Optionally parse IPv6 header fields for flow label, etc.
				ipv6Header, err := ipv6.ParseHeader(grhBytes) // Parse the whole GRH as an IPv6 header
				if err == nil && ipv6Header != nil {
					workComp.FlowLabel = uint32(ipv6Header.FlowLabel)
					log.Debug().Str("sgid", workComp.SGID).Str("dgid", workComp.DGID).Uint32("flow_label", workComp.FlowLabel).Msg("Parsed IPv6 GRH")
				} else {
					log.Warn().Err(err).Msg("Failed to parse GRH as IPv6 header to get FlowLabel, but SGID/DGID extracted directly.")
				}

			} else {
				log.Error().Uint8("ip_version", ipVersion).Msg("GRH has an unknown or unsupported IP Version in its first byte.")
				return nil, receiveTime, workComp, fmt.Errorf("GRH has unknown IP version: %d", ipVersion)
			}
			// Payload is after GRH
			actualPayloadLength = uint32(wc.byte_len) - GRHSize
			packetDataPtr = unsafe.Pointer(uintptr(u.RecvBuf) + uintptr(GRHSize))

		} else { // GRH not present
			log.Debug().Msg("IBV_WC_GRH is NOT set. Assuming payload starts at the beginning of the buffer.")
			actualPayloadLength = uint32(wc.byte_len)
			packetDataPtr = u.RecvBuf
		}

		// Now check the actualPayloadLength against the expected size for ProbePacket
		if actualPayloadLength < expectedMinimumPayloadSize {
			log.Warn().
				Uint32("actualPayloadLength", actualPayloadLength).
				Uint32("expectedMinimumPayloadSize", expectedMinimumPayloadSize).
				Uint32("wc_byte_len", uint32(wc.byte_len)).
				Bool("grh_present", grhPresent).
				Msg("Actual received payload is smaller than ProbePacket size. Ignoring packet.")
			if errPost := u.PostRecv(); errPost != nil {
				log.Warn().Err(errPost).Str("device", u.RNIC.DeviceName).Uint32("qpn", u.QPN).Msg("Failed to post replacement receive buffer after small/bad packet")
			}
			return nil, receiveTime, workComp, fmt.Errorf("actual received payload too small (len: %d), expected at least %d", actualPayloadLength, expectedMinimumPayloadSize)
		}

		// Access the packet data
		packet := (*ProbePacket)(packetDataPtr)
		packetCopy := *packet // Make a copy

		log.Debug().
			Uint64("seqNum", packet.SequenceNum).
			Uint8("isAck", packet.IsAck).
			Uint8("ackType", packet.AckType).
			Uint64("t1", packet.T1).
			Uint64("t3", packet.T3).
			Uint64("t4", packet.T4).
			Str("workComp_SGID", workComp.SGID).
			Str("workComp_DGID", workComp.DGID).
			Uint32("workComp_FlowLabel", workComp.FlowLabel).
			Uint32("srcQP", workComp.SrcQP).
			Msg("Received packet data (ProbePacket content)")

		if packet.IsAck == 0 && (workComp.SGID == "" || workComp.SGID == "::") {
			log.Warn().Msg("Received a probe, but SGID could not be determined (e.g. no GRH or GRH parsing issue). Sending ACK might fail if SGID is required for AH creation.")
		}

		if errPost := u.PostRecv(); errPost != nil {
			log.Warn().Err(errPost).
				Str("device", u.RNIC.DeviceName).
				Uint32("qpn", u.QPN).
				Msg("Failed to post replacement receive buffer after processing packet")
		}

		return &packetCopy, receiveTime, workComp, nil

	case err := <-u.errChan:
		return nil, time.Time{}, nil, fmt.Errorf("error during receive: %w", err)
	case <-ctx.Done(): // Context cancelled or timed out
		return nil, time.Time{}, nil, ctx.Err()
	}
}

// SendFirstAckPacket sends the first ACK packet in response to a probe
// This corresponds to step 2 in the paper's Figure 4
func (u *UDQueue) SendFirstAckPacket(
	targetGID string,
	targetQPN uint32,
	flowLabel uint32,
	originalPacket *ProbePacket,
	receiveTime time.Time,
) (time.Time, error) {
	// Use consistent QKey across all UD operations (0x11111111 as in ud_pingpong.c)
	const qkey uint32 = DefaultQKey

	ah, err := u.CreateAddressHandle(targetGID, flowLabel)
	if err != nil {
		return time.Time{}, err
	}
	defer C.ibv_destroy_ah(ah)

	// Clear the send buffer completely to avoid junk data
	clearSize := unsafe.Sizeof(ProbePacket{})
	C.memset(u.SendBuf, 0, C.size_t(clearSize))

	// Prepare the first ACK packet
	packet := (*ProbePacket)(u.SendBuf)
	packet.SequenceNum = originalPacket.SequenceNum
	packet.T1 = originalPacket.T1
	packet.T3 = uint64(receiveTime.UnixNano()) // Record T3 timestamp
	packet.T4 = 0                              // T4 is not known yet
	packet.IsAck = 1
	packet.AckType = 1 // First ACK
	packet.Flags = 0

	// Use the C helper function to post a send WR from C-allocated memory
	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(qkey),
	); ret != 0 {
		return time.Time{}, fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.sendCompChan:
		// Received send completion event
		if wc.status != C.IBV_WC_SUCCESS {
			return time.Time{}, fmt.Errorf("First ACK send completion failed: %d", wc.status)
		}
		return time.Now(), nil
	case err := <-u.errChan:
		// Error occurred
		return time.Time{}, fmt.Errorf("error during First ACK send: %w", err)
	case <-time.After(AckSendTimeout): // Timeout
		return time.Time{}, fmt.Errorf("timeout waiting for First ACK send completion")
	}
}

// SendSecondAckPacket sends the second ACK packet with processing delay information
// This corresponds to step 3 in the paper's Figure 4
func (u *UDQueue) SendSecondAckPacket(
	targetGID string,
	targetQPN uint32,
	flowLabel uint32,
	originalPacket *ProbePacket,
	receiveTime time.Time,
	sendCompletionTime time.Time,
) error {
	// Use consistent QKey across all UD operations (0x11111111 as in ud_pingpong.c)
	const qkey uint32 = DefaultQKey

	ah, err := u.CreateAddressHandle(targetGID, flowLabel)
	if err != nil {
		return err
	}
	defer C.ibv_destroy_ah(ah)

	// Clear the send buffer completely to avoid junk data
	clearSize := unsafe.Sizeof(ProbePacket{})
	C.memset(u.SendBuf, 0, C.size_t(clearSize))

	// Calculate processing delay (T4-T3)
	t3 := receiveTime.UnixNano()
	t4 := sendCompletionTime.UnixNano()

	// Prepare the second ACK packet with processing delay information
	packet := (*ProbePacket)(u.SendBuf)
	packet.SequenceNum = originalPacket.SequenceNum
	packet.T1 = originalPacket.T1
	packet.T3 = uint64(t3)
	packet.T4 = uint64(t4)
	packet.IsAck = 1
	packet.AckType = 2 // Second ACK with processing delay
	packet.Flags = 0

	// Use the C helper function to post a send WR from C-allocated memory
	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(qkey),
	); ret != 0 {
		return fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.sendCompChan:
		// Received send completion event
		if wc.status != C.IBV_WC_SUCCESS {
			return fmt.Errorf("Second ACK send completion failed: %d", wc.status)
		}
		return nil
	case err := <-u.errChan:
		// Error occurred
		return fmt.Errorf("error during Second ACK send: %w", err)
	case <-time.After(AckSendTimeout): // Timeout
		return fmt.Errorf("timeout waiting for Second ACK send completion")
	}
}

// SendAckPacket sends an ACK packet in response to a probe (legacy method)
// Deprecated: Use SendFirstAckPacket and SendSecondAckPacket instead
func (u *UDQueue) SendAckPacket(
	targetGID string,
	targetQPN uint32,
	flowLabel uint32,
	originalPacket *ProbePacket,
	receiveTime time.Time,
) error {
	// Use standard QKey for UD operations (0x11111111 as in ud_pingpong.c)
	const qkey uint32 = DefaultQKey

	ah, err := u.CreateAddressHandle(targetGID, flowLabel)
	if err != nil {
		return err
	}
	defer C.ibv_destroy_ah(ah)

	// Prepare a simple ACK packet
	packet := (*ProbePacket)(u.SendBuf)
	C.memset(u.SendBuf, 0, C.size_t(unsafe.Sizeof(ProbePacket{})))
	packet.SequenceNum = originalPacket.SequenceNum
	packet.T1 = originalPacket.T1
	packet.T3 = uint64(receiveTime.UnixNano())
	packet.T4 = uint64(time.Now().UnixNano())
	packet.IsAck = 1

	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(qkey),
	); ret != 0 {
		return fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.sendCompChan:
		// Received send completion event
		if wc.status != C.IBV_WC_SUCCESS {
			return fmt.Errorf("ACK send completion failed: %d", wc.status)
		}
		return nil
	case err := <-u.errChan:
		// Error occurred
		return fmt.Errorf("error during ACK send: %w", err)
	case <-time.After(AckSendTimeout): // Timeout
		return fmt.Errorf("timeout waiting for ACK send completion")
	}
}

// Destroy releases all resources associated with the UD queue
func (u *UDQueue) Destroy() {
	// Stop CQ polling goroutine
	u.StopCQPoller()

	// Close channels
	if u.sendCompChan != nil {
		close(u.sendCompChan)
	}
	if u.recvCompChan != nil {
		close(u.recvCompChan)
	}
	if u.errChan != nil {
		close(u.errChan)
	}

	if u.RecvMR != nil {
		C.ibv_dereg_mr(u.RecvMR)
		u.RecvMR = nil
	}

	if u.SendMR != nil {
		C.ibv_dereg_mr(u.SendMR)
		u.SendMR = nil
	}

	if u.RecvBuf != nil {
		C.free(u.RecvBuf)
		u.RecvBuf = nil
	}

	if u.SendBuf != nil {
		C.free(u.SendBuf)
		u.SendBuf = nil
	}

	if u.QP != nil {
		C.ibv_destroy_qp(u.QP)
		u.QP = nil
	}

	if u.CQ != nil {
		C.ibv_destroy_cq(u.CQ)
		u.CQ = nil
	}

	if u.CompChannel != nil {
		C.ibv_destroy_comp_channel(u.CompChannel)
		u.CompChannel = nil
	}

	log.Debug().Str("device", u.RNIC.DeviceName).Uint32("qpn", u.QPN).Msg("Destroyed UD queue pair")
}

// Close releases all resources associated with the RDMA manager
func (m *RDMAManager) Close() {
	for gid, udQueue := range m.UDQueues {
		log.Debug().Str("gid", gid).Msg("Destroying UD queue pair")
		udQueue.Destroy()
		delete(m.UDQueues, gid)
	}

	for _, rnic := range m.Devices {
		rnic.CloseDevice()
	}
}
