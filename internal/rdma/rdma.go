package rdma

// #cgo LDFLAGS: -libverbs
// #include <stdlib.h>
// #include <infiniband/verbs.h>
// #include <string.h>
// #include <arpa/inet.h>
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
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/ipv4"
)

// Constants
const (
	// Protocol constants
	DefaultQKey uint32 = 0x11111111 // Standard QKey for UD operations
	GRHSize            = 40         // Size of GRH header
	GIDIndex           = 3          // GID index for IPv4-mapped IPv6 addresses

	// Buffer and Queue sizes
	MRSize                 = 4096                  // Size of memory region for send/recv buffers
	CQSize                 = 50                    // Size of Completion Queue
	InitialRecvBuffers     = 32                    // Number of initial receive buffers to post
	CQPollerSleepDuration  = 10 * time.Microsecond // Sleep duration in CQ poller when no events
	SendCompChanBufferSize = 100                   // Buffer size for send completion channel
	RecvCompChanBufferSize = 100                   // Buffer size for receive completion channel
	ErrChanBufferSize      = 100                   // Buffer size for error channel
	MaxWorkCompletions     = 10                    // Max number of work completions to poll at once

	// Timeout durations
	SendCompletionTimeout = 5 * time.Second       // Timeout for waiting for send completion
	AckSendTimeout        = 10 * time.Millisecond // Timeout for waiting for ACK send completion

	// GRH/IPv4 parsing constants
	IPv4HeaderOffset    = 20 // Offset to the supposed IPv4 header within the GRH region
	IPv4HeaderMinLength = 20 // Minimum length of an IPv4 header
)

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
	recvCompChan chan *C.struct_ibv_wc // Channel for receive completion events
	errChan      chan error            // Channel for error notifications

	// CQ polling goroutine control
	cqPollerRunning bool
	cqPollerDone    chan struct{}
	cqPollerMutex   sync.Mutex
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

// findPreferredGID searches for a preferred GID (IPv4-mapped IPv6 on Ethernet port)
// Returns port number, GID index, GID data, and whether a preferred GID was found
func (r *RNIC) findPreferredGID(physPortCnt C.uint8_t) (C.uint8_t, C.int, C.union_ibv_gid, bool) {
	// Iterate over physical ports to find an active one with an IPv4-mapped IPv6 GID on Ethernet
	for portNum := C.uint8_t(1); portNum <= physPortCnt; portNum++ {
		var portAttr C.struct_ibv_port_attr
		if ret := C.my_ibv_query_port(r.Context, portNum, &portAttr); ret != 0 {
			log.Warn().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Msg("Failed to query port, skipping")
			continue
		}

		if portAttr.state != C.IBV_PORT_ACTIVE {
			log.Debug().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Msg("Port is not active, skipping")
			continue
		}

		// Check if link layer is Ethernet (common for RoCE v2)
		// enum ibv_link_layer { IBV_LINK_LAYER_UNSPECIFIED, IBV_LINK_LAYER_INFINIBAND, IBV_LINK_LAYER_ETHERNET };
		// IBV_LINK_LAYER_ETHERNET is typically 2
		if portAttr.link_layer == C.IBV_LINK_LAYER_ETHERNET {
			log.Debug().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Msg("Port is Ethernet. Iterating GIDs for IPv4-mapped RoCE v2 type.")
			var gid C.union_ibv_gid
			if ret := C.ibv_query_gid(r.Context, portNum, C.int(GIDIndex), &gid); ret == 0 {
				gidBytes := unsafe.Slice((*byte)(unsafe.Pointer(&gid)), C.sizeof_union_ibv_gid)
				log.Debug().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", int(GIDIndex)).Str("gid", formatGIDString(gidBytes)).Msg("Found GID")

				// Detect IPv4-mapped IPv6 address by byte pattern
				if isIPv4MappedIPv6(gidBytes) {
					log.Info().
						Str("device", r.DeviceName).
						Uint8("port", uint8(portNum)).
						Int("gid_index", int(GIDIndex)).
						Str("gid", formatGIDString(gidBytes)).
						Msg("Found preferred IPv4-mapped GID on Ethernet port.")
					return portNum, GIDIndex, gid, true
				}
			} else {
				log.Warn().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", int(GIDIndex)).Msg("Failed to query GID on active Ethernet port.")
			}
		}
	}
	return 0, -1, C.union_ibv_gid{}, false
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

// OpenDevice opens the RDMA device and initializes its resources
func (r *RNIC) OpenDevice() error {
	if r.IsOpen {
		return nil
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
	if C.get_phys_port_cnt(r.Context, &physPortCnt) != 0 { // Use new helper
		r.releaseDeviceResources()
		return fmt.Errorf("failed to query device attributes for %s", r.DeviceName)
	}

	// Validate that the device has physical ports
	if physPortCnt == 0 {
		r.releaseDeviceResources()
		return fmt.Errorf("device %s has 0 physical ports", r.DeviceName)
	}

	// Try to find a preferred GID (IPv4-mapped IPv6 on Ethernet port)
	activePort, activeGIDIndex, gid, found := r.findPreferredGID(physPortCnt)

	// If no suitable GID was found, fail
	if !found || activePort == 0 || activeGIDIndex == -1 {
		r.releaseDeviceResources()
		return fmt.Errorf("no active port with a usable GID found for device %s", r.DeviceName)
	}

	r.ActiveGIDIndex = uint8(activeGIDIndex) // Store the GID index
	r.ActivePortNum = uint8(activePort)      // Store the active port number

	// Get GID bytes and format GID string
	gidBytes := unsafe.Slice((*byte)(unsafe.Pointer(&gid)), C.sizeof_union_ibv_gid)
	r.GID = formatGIDString(gidBytes)

	// Extract IPv6 for address resolution
	ipv6 := net.IP(gidBytes)

	// Get IP address from network interface or fall back to GID
	r.IPAddr = r.getIPAddress(ipv6)

	r.IsOpen = true
	log.Info().Str("device", r.DeviceName).Str("gid", r.GID).Str("ip", r.IPAddr).Msg("Opened RDMA device")
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

// StartCQPoller starts a goroutine to poll CQ continuously
func (u *UDQueue) StartCQPoller() {
	u.cqPollerMutex.Lock()
	defer u.cqPollerMutex.Unlock()

	if u.cqPollerRunning {
		return // Already running
	}

	u.cqPollerDone = make(chan struct{})
	u.cqPollerRunning = true

	go func() {
		log.Debug().
			Str("device", u.RNIC.DeviceName).
			Uint32("qpn", u.QPN).
			Msg("Starting CQ poller goroutine")

		defer func() {
			u.cqPollerMutex.Lock()
			u.cqPollerRunning = false
			u.cqPollerMutex.Unlock()
			log.Debug().
				Str("device", u.RNIC.DeviceName).
				Uint32("qpn", u.QPN).
				Msg("CQ poller goroutine exited")
		}()

		// Work completion buffer with capacity for multiple entries
		const maxCompletions = 10
		wc := make([]C.struct_ibv_wc, maxCompletions)

		for {
			select {
			case <-u.cqPollerDone:
				return // Stop requested
			default:
				// Poll CQ to get completion events
				ne := C.ibv_poll_cq(u.CQ, maxCompletions, &wc[0])
				if ne < 0 {
					// Polling error
					u.errChan <- fmt.Errorf("ibv_poll_cq failed: %d", ne)
					continue
				}

				if ne == 0 {
					// No completion events
					// Add a short sleep to reduce CPU usage
					time.Sleep(CQPollerSleepDuration)
					continue
				}

				// Process received completion events
				for i := 0; i < int(ne); i++ {
					completion := wc[i]

					// First check for errors
					if completion.status != C.IBV_WC_SUCCESS {
						u.errChan <- fmt.Errorf("completion failed: status=%d, vendor_err=%d, qp_num=%d",
							completion.status, completion.vendor_err, completion.qp_num)
						continue
					}

					// Distinguish between send and receive based on opcode
					if completion.opcode == C.IBV_WC_SEND {
						// Send completion event
						wcCopy := completion
						select {
						case u.sendCompChan <- &wcCopy:
						default:
							// Channel is blocked (no receiver)
							log.Warn().
								Str("device", u.RNIC.DeviceName).
								Uint32("qpn", u.QPN).
								Uint32("wc_opcode", completion.opcode).
								Uint32("byte_len", uint32(completion.byte_len)).
								Msg("Send completion channel (sendCompChan) is blocked, discarding event")
						}
					} else if completion.opcode == C.IBV_WC_RECV {
						// Receive completion event
						wcCopy := completion
						select {
						case u.recvCompChan <- &wcCopy:
						default:
							// Channel is blocked (no receiver)
							log.Warn().
								Str("device", u.RNIC.DeviceName).
								Uint32("qpn", u.QPN).
								Uint32("wc_opcode", completion.opcode).
								Uint32("byte_len", uint32(completion.byte_len)).
								Msg("Receive completion channel (recvCompChan) is blocked, discarding event")
						}
					} else {
						// Handle other completion types or log an error/warning
						log.Error().
							Str("device", u.RNIC.DeviceName).
							Uint32("qpn", u.QPN).
							Uint32("wc_qp_num", uint32(completion.qp_num)).
							Uint32("wc_status", uint32(completion.status)).
							Uint32("wc_opcode", completion.opcode).
							Uint32("byte_len", uint32(completion.byte_len)).
							Msgf("CQPoller: Polled an event with unhandled opcode: %d", completion.opcode)
						// Optionally, push to errChan if this is considered a critical error for the application
						// u.errChan <- fmt.Errorf("unhandled completion opcode: %d on QPN %d", opcodeValue, u.QPN)
					}
				}
			}
		}
	}()
}

// StopCQPoller stops the CQ polling goroutine
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
func (m *RDMAManager) CreateUDQueue(rnic *RNIC, queueType UDQueueType) (*UDQueue, error) {
	if !rnic.IsOpen {
		if err := rnic.OpenDevice(); err != nil {
			return nil, err
		}
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
func (m *RDMAManager) CreateSenderAndResponderQueues(rnic *RNIC) error {
	if !rnic.IsOpen {
		if err := rnic.OpenDevice(); err != nil {
			return err
		}
	}

	// Create sender queue
	senderQueue, err := m.CreateUDQueue(rnic, UDQueueTypeSender)
	if err != nil {
		return fmt.Errorf("failed to create sender queue for device %s: %w", rnic.DeviceName, err)
	}
	log.Info().Str("device", rnic.DeviceName).Uint32("qpn", senderQueue.QPN).Msg("Created sender queue")

	// Create responder queue
	responderQueue, err := m.CreateUDQueue(rnic, UDQueueTypeResponder)
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
			// GRH is present according to wc_flags.
			// User hypothesis: actual L3 info is in an IPv4 header at offset 20 of the GRH area.
			log.Debug().Msg("IBV_WC_GRH is set. Attempting to parse IPv4 header from offset 20 of GRH area.")
		}

		// Log the full content of u.RecvBuf up to wc.byte_len for context
		if byteLenLog := uint32(wc.byte_len); byteLenLog > 0 {
			fullRecvBufContent := unsafe.Slice((*byte)(u.RecvBuf), byteLenLog)
			log.Debug().
				Bytes("u_RecvBuf_full_content_on_grh_custom_parse", fullRecvBufContent).
				Uint32("wc_byte_len", byteLenLog).
				Msg("Full content of u.RecvBuf (custom GRH parsing logic)")
		}

		if uint32(wc.byte_len) < GRHSize { // GRHSize is 40
			log.Error().Uint32("wc_byte_len", uint32(wc.byte_len)).Msg("IBV_WC_GRH is set, but wc.byte_len is less than GRHSize (40 bytes). Cannot apply custom IPv4 parsing.")
			return nil, receiveTime, workComp, fmt.Errorf("IBV_WC_GRH set but wc.byte_len (%d) < GRHSize (%d)", wc.byte_len, GRHSize)
		}

		// Extract the supposed IPv4 header part (offset 20, length 20)
		const ipv4HeaderOffset = 20
		const ipv4HeaderMinLength = 20 // Standard IPv4 header length
		ipv4HeaderBytes := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(u.RecvBuf)+uintptr(ipv4HeaderOffset))), ipv4HeaderMinLength)
		ipv4Header, err := ipv4.ParseHeader(ipv4HeaderBytes)
		if err != nil {
			log.Warn().Err(err).Bytes("data", ipv4HeaderBytes).Msg("Failed to parse bytes from offset 20 as IPv4 header.")
			return nil, receiveTime, workComp, fmt.Errorf("failed to parse GRH region's IPv4 header part: %w", err)
		}

		// Successfully parsed IPv4 header. Extract Src and Dst IP.
		if ipv4Header.Src == nil || ipv4Header.Dst == nil {
			log.Error().Msg("Parsed IPv4 header, but Src or Dst IP is nil.")
			return nil, receiveTime, workComp, fmt.Errorf("parsed IPv4 header from GRH region, but Src/Dst IP is nil")
		}

		srcIPv4 := ipv4Header.Src.To4()
		dstIPv4 := ipv4Header.Dst.To4()

		if srcIPv4 == nil || dstIPv4 == nil {
			log.Error().Str("ipv4.Src", ipv4Header.Src.String()).Str("ipv4.Dst", ipv4Header.Dst.String()).Msg("Could not convert parsed Src/Dst IP to IPv4 (To4() returned nil).")
			return nil, receiveTime, workComp, fmt.Errorf("could not convert GRH region's IPv4 Src/Dst to 4-byte format")
		}

		// Convert to IPv4-mapped IPv6 GID strings
		srcMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, srcIPv4[0], srcIPv4[1], srcIPv4[2], srcIPv4[3]}
		dstMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, dstIPv4[0], dstIPv4[1], dstIPv4[2], dstIPv4[3]}

		workComp.SGID = formatGIDString(srcMappedIPv6Bytes) // formatGIDString expects 16 bytes and will add ::ffff if bytes 10,11 are ff
		workComp.DGID = formatGIDString(dstMappedIPv6Bytes)

		// The payload is still after the full GRHSize (40 bytes)
		actualPayloadLength = uint32(wc.byte_len) - GRHSize
		packetDataPtr = unsafe.Pointer(uintptr(u.RecvBuf) + uintptr(GRHSize))

		// Now check the actualPayloadLength against the expected size
		if actualPayloadLength < expectedMinimumPayloadSize {
			log.Warn().
				Uint32("actualPayloadLength", actualPayloadLength).
				Uint32("expectedMinimumPayloadSize", expectedMinimumPayloadSize).
				Uint32("wc_byte_len", uint32(wc.byte_len)).
				Bool("grh_present", grhPresent).
				Msg("Actual received payload is smaller than ProbePacket size. Ignoring packet.")
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
			Str("srcGID", workComp.SGID).
			Str("dstGID", workComp.DGID).
			Uint32("srcQP", workComp.SrcQP).
			Msg("Received packet data")

		// If an ACK requires the sender's GID, and GRH was not present (so SGID is unknown from GRH)
		if !grhPresent && (workComp.SGID == "" || workComp.SGID == "::") {
			// This error is returned if GID from GRH is critical for an ACK.
			// Depending on the application, wc.src_qp might be used if a mapping to GID exists,
			// but typically for UD, AH creation for the ACK needs the peer's GID.
			log.Error().Msg("IBV_WC_GRH not set, and SGID could not be determined from GRH. Cannot send ACK if GID is required.")
			// Decide if this is a fatal error for ReceivePacket or if the caller handles it.
			// The original code returned an error here.
			return nil, receiveTime, workComp, fmt.Errorf("IBV_WC_GRH not set, cannot reliably determine sender GID for ACK")
		}
		// SGID/SrcQP validation:
		// If GRH was present but SGID is still invalid (e.g. "::"), it's a problem for ACKs.
		// This was handled inside the grhPresent block partially.
		// The CreateAddressHandle will fail if SGID is invalid.

		// Replenish the receive buffer for the one just consumed
		if errPost := u.PostRecv(); errPost != nil {
			log.Warn().Err(errPost).
				Str("device", u.RNIC.DeviceName).
				Uint32("qpn", u.QPN).
				Msg("Failed to post replacement receive buffer after processing packet")
			// Non-fatal for this received packet, but indicates a potential issue
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
	originalPacket *ProbePacket,
	receiveTime time.Time,
) (time.Time, error) {
	// Use consistent QKey across all UD operations (0x11111111 as in ud_pingpong.c)
	const qkey uint32 = DefaultQKey

	// Use the same flow label from the original packet to ensure the response follows the same path
	// In production environment, might need to use 0 for all responses to avoid ECMP issues
	flowLabel := uint32(0) // Set to 0 for ACK packets to ensure consistent path

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
	originalPacket *ProbePacket,
	receiveTime time.Time,
	sendCompletionTime time.Time,
) error {
	// Use consistent QKey across all UD operations (0x11111111 as in ud_pingpong.c)
	const qkey uint32 = DefaultQKey

	// Use flow label 0 for ACK packets to ensure consistent path
	flowLabel := uint32(0)

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
	originalPacket *ProbePacket,
	receiveTime time.Time,
) error {
	// Use standard QKey for UD operations (0x11111111 as in ud_pingpong.c)
	const qkey uint32 = DefaultQKey

	ah, err := u.CreateAddressHandle(targetGID, 0)
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
	close(u.sendCompChan)
	close(u.recvCompChan)
	close(u.errChan)

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
