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
// // Helper function to poll completion queue
// int poll_cq_once(struct ibv_cq *cq, struct ibv_wc *wc) {
//     return ibv_poll_cq(cq, 1, wc);
// }
import "C"

import (
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
)

// Constants for RDMA operations
const (
	MaxWorkRequests   = 256  // Maximum number of work requests in a queue
	MaxWorkCompletion = 16   // Maximum number of work completions to poll at once
	MRSize            = 4096 // Size of memory region for send/recv buffers
)

// RNIC represents an RDMA NIC device
type RNIC struct {
	Context    *C.struct_ibv_context
	Device     *C.struct_ibv_device
	DeviceName string
	GID        string
	IPAddr     string
	PD         *C.struct_ibv_pd
	IsOpen     bool
	UDQueues   map[string]*UDQueue // Map of GID to UDQueue
}

// UDQueue represents a UD QP and associated resources
type UDQueue struct {
	RNIC    *RNIC
	QP      *C.struct_ibv_qp
	CQ      *C.struct_ibv_cq
	SendMR  *C.struct_ibv_mr
	RecvMR  *C.struct_ibv_mr
	SendBuf unsafe.Pointer
	RecvBuf unsafe.Pointer
	QPN     uint32
	GRHSize int // Size of GRH header
}

// RDMAManager manages RDMA devices and operations
type RDMAManager struct {
	Devices  []*RNIC
	UDQueues map[string]*UDQueue // Map of GID to UDQueue
}

// ProbePacket represents the format of a probe packet
type ProbePacket struct {
	SequenceNum uint64
	T1          uint64 // Timestamp 1 (post send time in ns)
	T3          uint64 // Timestamp 3 (receive time in ns)
	T4          uint64 // Timestamp 4 (responder ACK time in ns)
	IsAck       uint8  // 0 for probe, 1 for ACK
	Flags       uint8  // Reserved for future use
	Padding     [2]byte
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
	manager := &RDMAManager{
		UDQueues: make(map[string]*UDQueue),
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
			UDQueues:   make(map[string]*UDQueue),
		}
		manager.Devices = append(manager.Devices, rnic)
	}

	return manager, nil
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

	// Query port info to get GID
	var portAttr C.struct_ibv_port_attr
	port := C.uint8_t(1) // Assuming first port

	// Use the helper function to call ibv_query_port
	if ret := C.my_ibv_query_port(r.Context, port, &portAttr); ret != 0 {
		C.ibv_dealloc_pd(r.PD)
		C.ibv_close_device(r.Context)
		return fmt.Errorf("failed to query port for device %s: %d", r.DeviceName, ret)
	}

	// Get GID
	var gid C.union_ibv_gid
	if ret := C.ibv_query_gid(r.Context, port, 0, &gid); ret != 0 {
		C.ibv_dealloc_pd(r.PD)
		C.ibv_close_device(r.Context)
		return fmt.Errorf("failed to query GID for device %s: %d", r.DeviceName, ret)
	}

	// Format GID as string (IPv6 format)
	gidBytes := C.GoBytes(unsafe.Pointer(&gid), C.sizeof_union_ibv_gid)
	ipv6 := net.IP(gidBytes)
	r.GID = ipv6.String()

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
	return r.getIPAddressFromGID(ipv6)
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
func (r *RNIC) getIPAddressFromGID(ipv6 net.IP) string {
	if ipv4 := ipv6.To4(); ipv4 != nil {
		return ipv4.String()
	}
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

// CreateUDQueue creates a UD queue pair for sending and receiving probe packets
func (m *RDMAManager) CreateUDQueue(rnic *RNIC) (*UDQueue, error) {
	if !rnic.IsOpen {
		if err := rnic.OpenDevice(); err != nil {
			return nil, err
		}
	}

	// Create completion queue
	cq := C.ibv_create_cq(rnic.Context, C.int(MaxWorkRequests), nil, nil, 0)
	if cq == nil {
		return nil, fmt.Errorf("failed to create CQ for device %s", rnic.DeviceName)
	}

	// Create QP
	var qpInitAttr C.struct_ibv_qp_init_attr
	qpInitAttr.qp_type = C.IBV_QPT_UD
	qpInitAttr.sq_sig_all = 1
	qpInitAttr.send_cq = cq
	qpInitAttr.recv_cq = cq
	qpInitAttr.cap.max_send_wr = MaxWorkRequests
	qpInitAttr.cap.max_recv_wr = MaxWorkRequests
	qpInitAttr.cap.max_send_sge = 1
	qpInitAttr.cap.max_recv_sge = 1

	qp := C.ibv_create_qp(rnic.PD, &qpInitAttr)
	if qp == nil {
		C.ibv_destroy_cq(cq)
		return nil, fmt.Errorf("failed to create QP for device %s", rnic.DeviceName)
	}

	// Modify QP to INIT state
	var qpAttr C.struct_ibv_qp_attr
	qpAttr.qp_state = C.IBV_QPS_INIT
	qpAttr.pkey_index = 0
	qpAttr.port_num = 1
	qpAttr.qkey = 0x11111111

	if ret := C.ibv_modify_qp(qp, &qpAttr,
		C.IBV_QP_STATE|C.IBV_QP_PKEY_INDEX|C.IBV_QP_PORT|C.IBV_QP_QKEY); ret != 0 {
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		return nil, fmt.Errorf("failed to modify QP to INIT: %d", ret)
	}

	// Modify QP to RTR state
	qpAttr.qp_state = C.IBV_QPS_RTR
	if ret := C.ibv_modify_qp(qp, &qpAttr, C.IBV_QP_STATE); ret != 0 {
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		return nil, fmt.Errorf("failed to modify QP to RTR: %d", ret)
	}

	// Modify QP to RTS state
	qpAttr.qp_state = C.IBV_QPS_RTS
	qpAttr.sq_psn = 0
	if ret := C.ibv_modify_qp(qp, &qpAttr, C.IBV_QP_STATE|C.IBV_QP_SQ_PSN); ret != 0 {
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		return nil, fmt.Errorf("failed to modify QP to RTS: %d", ret)
	}

	// Allocate send and receive buffers
	sendBuf := C.malloc(C.size_t(MRSize))
	if sendBuf == nil {
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		return nil, fmt.Errorf("failed to allocate send buffer")
	}

	recvBuf := C.malloc(C.size_t(MRSize))
	if recvBuf == nil {
		C.free(sendBuf)
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		return nil, fmt.Errorf("failed to allocate receive buffer")
	}

	// Register memory regions
	sendMR := C.ibv_reg_mr(rnic.PD, sendBuf, C.size_t(MRSize),
		C.IBV_ACCESS_LOCAL_WRITE|C.IBV_ACCESS_REMOTE_WRITE)
	if sendMR == nil {
		C.free(recvBuf)
		C.free(sendBuf)
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		return nil, fmt.Errorf("failed to register send buffer MR")
	}

	recvMR := C.ibv_reg_mr(rnic.PD, recvBuf, C.size_t(MRSize),
		C.IBV_ACCESS_LOCAL_WRITE|C.IBV_ACCESS_REMOTE_WRITE)
	if recvMR == nil {
		C.ibv_dereg_mr(sendMR)
		C.free(recvBuf)
		C.free(sendBuf)
		C.ibv_destroy_qp(qp)
		C.ibv_destroy_cq(cq)
		return nil, fmt.Errorf("failed to register receive buffer MR")
	}

	udQueue := &UDQueue{
		RNIC:    rnic,
		QP:      qp,
		CQ:      cq,
		SendMR:  sendMR,
		RecvMR:  recvMR,
		SendBuf: sendBuf,
		RecvBuf: recvBuf,
		QPN:     uint32(qp.qp_num),
		GRHSize: 40, // Global Routing Header size is 40 bytes
	}

	m.UDQueues[rnic.GID] = udQueue
	rnic.UDQueues[rnic.GID] = udQueue
	log.Info().Str("device", rnic.DeviceName).Uint32("qpn", udQueue.QPN).Msg("Created UD queue pair")

	// Post a few receive WRs to start
	for i := 0; i < 10; i++ {
		if err := udQueue.PostRecv(); err != nil {
			udQueue.Destroy()
			return nil, fmt.Errorf("failed to post initial receive WRs: %w", err)
		}
	}

	return udQueue, nil
}

// PostRecv posts a receive work request
func (u *UDQueue) PostRecv() error {
	// Use the C helper function that manages work request memory on C side
	// This avoids the "cgo argument has Go pointers to unpinned Go pointers" error
	ret := C.post_recv(
		u.QP,
		C.uint64_t(uintptr(u.RecvBuf)),
		C.uint32_t(MRSize),
		u.RecvMR.lkey,
	)

	if ret != 0 {
		return fmt.Errorf("ibv_post_recv failed: %d", ret)
	}

	return nil
}

// CreateAddressHandle creates a UD address handle for the target
func (u *UDQueue) CreateAddressHandle(targetGID string, portNum uint8) (*C.struct_ibv_ah, error) {
	var gid C.union_ibv_gid

	// Parse GID string to bytes
	ip := net.ParseIP(targetGID)
	if ip == nil {
		return nil, fmt.Errorf("invalid GID format: %s", targetGID)
	}

	// Copy IPv6 address to gid
	copy((*[16]byte)(unsafe.Pointer(&gid))[:], ip.To16())

	var ahAttr C.struct_ibv_ah_attr
	ahAttr.dlid = 0
	ahAttr.sl = 0
	ahAttr.src_path_bits = 0
	ahAttr.static_rate = 0
	ahAttr.is_global = 1
	ahAttr.port_num = C.uint8_t(portNum)

	// Set the GID in the global routing attributes
	ahAttr.grh.dgid = gid
	ahAttr.grh.flow_label = 0
	ahAttr.grh.sgid_index = 0
	ahAttr.grh.hop_limit = 64
	ahAttr.grh.traffic_class = 0

	ah := C.ibv_create_ah(u.RNIC.PD, &ahAttr)
	if ah == nil {
		return nil, fmt.Errorf("failed to create address handle for GID %s", targetGID)
	}

	return ah, nil
}

// SendProbePacket sends a probe packet to the target
func (u *UDQueue) SendProbePacket(
	targetGID string,
	targetQPN uint32,
	sequenceNum uint64,
	sourcePort uint32,
	flowLabel uint32,
) (time.Time, error) {
	ah, err := u.CreateAddressHandle(targetGID, 1)
	if err != nil {
		return time.Time{}, err
	}
	defer C.ibv_destroy_ah(ah)

	// Prepare the packet
	packet := (*ProbePacket)(u.SendBuf)
	packet.SequenceNum = sequenceNum
	packet.T1 = uint64(time.Now().UnixNano())
	packet.T3 = 0
	packet.T4 = 0
	packet.IsAck = 0
	packet.Flags = 0

	// Use the C helper function to post a send WR from C-allocated memory
	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		0x11111111,
	); ret != 0 {
		return time.Time{}, fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	// Get send completion
	var wc C.struct_ibv_wc
	for {
		ne := C.poll_cq_once(u.CQ, &wc)
		if ne < 0 {
			return time.Time{}, fmt.Errorf("ibv_poll_cq failed")
		}
		if ne == 0 {
			// No completion yet, try again
			continue
		}

		// Check completion status
		if wc.status != C.IBV_WC_SUCCESS {
			return time.Time{}, fmt.Errorf("send completion failed: %d", wc.status)
		}

		// Send completed successfully
		break
	}

	// Return the timestamp of when we got the completion
	return time.Now(), nil
}

// ReceivePacket waits for and processes a received packet
func (u *UDQueue) ReceivePacket(timeout time.Duration) (*ProbePacket, time.Time, *WorkCompletion, error) {
	// Poll for completion
	var wc C.struct_ibv_wc
	start := time.Now()
	for {
		ne := C.poll_cq_once(u.CQ, &wc)
		if ne < 0 {
			return nil, time.Time{}, nil, fmt.Errorf("ibv_poll_cq failed")
		}

		if ne == 0 {
			// No completion yet, check timeout
			if time.Since(start) > timeout {
				return nil, time.Time{}, nil, fmt.Errorf("receive timeout")
			}
			// Sleep a bit to avoid busy-waiting
			time.Sleep(10 * time.Microsecond)
			continue
		}

		// Check completion status
		if wc.status != C.IBV_WC_SUCCESS {
			// Post another receive buffer to replace the failed one
			u.PostRecv()
			return nil, time.Time{}, nil, fmt.Errorf("receive completion failed: %d", wc.status)
		}

		// Receive completed successfully
		receiveTime := time.Now()

		// Extract work completion information
		workComp := &WorkCompletion{
			Status:    uint32(wc.status),
			SrcQP:     uint32(wc.src_qp), // Source QP number from WC
			VendorErr: uint32(wc.vendor_err),
		}

		// Extract GRH header information (for UD transport)
		// GRH header is at the beginning of the receive buffer for UD transport
		if u.GRHSize > 0 {
			// Source GID is at offset 8 (SGID field) in the GRH header
			sgidOffset := 8
			sgidSize := 16 // IPv6 size in bytes
			sgidBytes := C.GoBytes(unsafe.Pointer(uintptr(u.RecvBuf)+uintptr(sgidOffset)), C.int(sgidSize))
			workComp.SGID = net.IP(sgidBytes).String()

			// Destination GID is also in the GRH header
			dgidOffset := 24
			dgidBytes := C.GoBytes(unsafe.Pointer(uintptr(u.RecvBuf)+uintptr(dgidOffset)), C.int(sgidSize))
			workComp.DGID = net.IP(dgidBytes).String()
		}

		// The UD transport adds a GRH header to the packet
		// Skip over it to get to our data
		packetData := unsafe.Pointer(uintptr(u.RecvBuf) + uintptr(u.GRHSize))
		packet := (*ProbePacket)(packetData)

		// Make a copy of the packet data
		packetCopy := *packet

		// Post another receive buffer to replace the one we just consumed
		u.PostRecv()

		return &packetCopy, receiveTime, workComp, nil
	}
}

// SendAckPacket sends an ACK packet in response to a probe
func (u *UDQueue) SendAckPacket(
	targetGID string,
	targetQPN uint32,
	originalPacket *ProbePacket,
	receiveTime time.Time,
) error {
	ah, err := u.CreateAddressHandle(targetGID, 1)
	if err != nil {
		return err
	}
	defer C.ibv_destroy_ah(ah)

	// Prepare the ACK packet
	packet := (*ProbePacket)(u.SendBuf)
	packet.SequenceNum = originalPacket.SequenceNum
	packet.T1 = originalPacket.T1
	packet.T3 = uint64(receiveTime.UnixNano())
	packet.T4 = uint64(time.Now().UnixNano())
	packet.IsAck = 1
	packet.Flags = 0

	// Use the C helper function to post a send WR from C-allocated memory
	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		0x11111111,
	); ret != 0 {
		return fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	// Get send completion (can be asynchronous in real implementation)
	var wc C.struct_ibv_wc
	for {
		ne := C.poll_cq_once(u.CQ, &wc)
		if ne < 0 {
			return fmt.Errorf("ibv_poll_cq failed")
		}
		if ne == 0 {
			// No completion yet, try again
			continue
		}

		// Check completion status
		if wc.status != C.IBV_WC_SUCCESS {
			return fmt.Errorf("ACK send completion failed: %d", wc.status)
		}

		// Send completed successfully
		break
	}

	return nil
}

// Destroy releases all resources associated with the UD queue
func (u *UDQueue) Destroy() {
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

	log.Debug().Str("device", u.RNIC.DeviceName).Uint32("qpn", u.QPN).Msg("Destroyed UD queue pair")
}

// Close releases all resources associated with the RDMA manager
func (m *RDMAManager) Close() {
	for gid, udQueue := range m.UDQueues {
		udQueue.Destroy()
		delete(m.UDQueues, gid)
	}

	for _, rnic := range m.Devices {
		rnic.CloseDevice()
	}
}
