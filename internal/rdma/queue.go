package rdma

// #cgo LDFLAGS: -libverbs
// #include <stdlib.h>
// #include <infiniband/verbs.h>
//
// static int get_errno(void) {
//     return errno;
// }
import "C"
import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/rs/zerolog/log"
)

// UDQueueType defines the role of the UDQueue
type UDQueueType int

const (
	// UDQueueTypeSender is used for sending probes and receiving ACKs
	UDQueueTypeSender UDQueueType = iota
	// UDQueueTypeResponder is used for receiving probes and sending ACKs
	UDQueueTypeResponder

	// MRSize is the size of memory region for send/recv buffers
	MRSize = 4096
	// CQSize is the size of Completion Queue
	CQSize = 256
	// InitialRecvBuffers is the number of initial receive buffers to post
	InitialRecvBuffers = 32

	// SendCompChanBufferSize is the buffer size for send completion channel
	SendCompChanBufferSize = 100
	// RecvCompChanBufferSize is the buffer size for receive completion channel
	RecvCompChanBufferSize = 100
	// ErrChanBufferSize is the buffer size for error channel
	ErrChanBufferSize = 100
)

// UDQueue represents a UD QP and associated resources
type UDQueue struct {
	RNIC        *RNIC
	QP          *C.struct_ibv_qp
	CQ          *C.struct_ibv_cq_ex
	CompChannel *C.struct_ibv_comp_channel
	SendMR      *C.struct_ibv_mr
	RecvMR      *C.struct_ibv_mr
	SendBuf     unsafe.Pointer
	RecvBuf     unsafe.Pointer
	QPN         uint32
	QueueType   UDQueueType // Type of queue (sender or responder)

	// Channels for CQ completion event notifications
	sendCompChan chan *GoWorkCompletion // Channel for send completion events
	recvCompChan chan *GoWorkCompletion // Channel for receive completion events (non-ACKs or if no handler)
	errChan      chan error             // Channel for error notifications

	// CQ polling goroutine control
	cqPollerRunning bool
	cqPollerDone    chan struct{}
	cqPollerMutex   sync.Mutex

	// ACK handler for sender queues
	ackHandler AckHandlerFunc
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
			base_cq_to_destroy := C.ibv_cq_ex_to_cq(cq) // Direct call
			if base_cq_to_destroy != nil {
				C.ibv_destroy_cq(base_cq_to_destroy)
			} else {
				log.Error().Str("device", rnic.DeviceName).Msg("Failed to get base CQ from extended CQ during CreateUDQueue failure path")
			}
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
		sendCompChan: make(chan *GoWorkCompletion, SendCompChanBufferSize), // Buffered channel
		recvCompChan: make(chan *GoWorkCompletion, RecvCompChanBufferSize), // Buffered channel
		errChan:      make(chan error, ErrChanBufferSize),                  // Buffered channel
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
		rnic.ProberQueue = udQueue
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
func (m *RDMAManager) createQueuePair(rnic *RNIC) (*C.struct_ibv_qp, *C.struct_ibv_cq_ex, *C.struct_ibv_comp_channel, uint32, error) {
	// Create a completion event channel
	compChannel := C.ibv_create_comp_channel(rnic.Context)
	if compChannel == nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to create completion channel for device %s", rnic.DeviceName)
	}

	// Create extended completion queue
	var cqAttr C.struct_ibv_cq_init_attr_ex
	// It's good practice to zero out C structs allocated on Go side before filling them.
	// However, C.memset might not be the most idiomatic way from Go if we fill all relevant fields.
	// Explicitly setting fields ensures clarity.
	cqAttr.cqe = C.uint32_t(CQSize) // Ensure correct type for cqe
	cqAttr.cq_context = nil
	cqAttr.channel = compChannel
	cqAttr.comp_vector = 0
	// Ensure all parts of the bitwise OR are C.uint64_t
	cqAttr.wc_flags = C.uint64_t(C.IBV_WC_EX_WITH_BYTE_LEN) |
		C.uint64_t(C.IBV_WC_EX_WITH_SRC_QP) |
		C.uint64_t(C.IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK)
	// All other fields in cqAttr will be zero by default Go struct initialization if not set.

	cqEx := C.ibv_create_cq_ex(rnic.Context, &cqAttr)
	if cqEx == nil {
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, fmt.Errorf("failed to create extended CQ for device %s: %s", rnic.DeviceName, syscall.Errno(C.get_errno()).Error())
	}

	// Generate random PSN as in ud_pingpong.c (24 bit value)
	psn := uint32(rand.Int31n(1 << 24))

	// QP creation attribute setting to standard
	var qpInitAttr C.struct_ibv_qp_init_attr
	qpInitAttr.qp_type = C.IBV_QPT_UD
	qpInitAttr.sq_sig_all = 0 // Set to 0 to match standard (flags specified in each WR)
	base_send_cq := C.ibv_cq_ex_to_cq(cqEx)
	base_recv_cq := C.ibv_cq_ex_to_cq(cqEx)
	if base_send_cq == nil || base_recv_cq == nil {
		C.ibv_destroy_comp_channel(compChannel)
		// If cqEx was created, try to destroy its base part
		if cqEx != nil {
			base_cq_to_destroy := C.ibv_cq_ex_to_cq(cqEx) // Direct call
			if base_cq_to_destroy != nil {
				C.ibv_destroy_cq(base_cq_to_destroy)
			} else {
				// This case should ideally not happen if cqEx itself is not nil
				log.Error().Msg("Failed to get base CQ from non-nil extended CQ during QP creation failure path")
			}
		}
		return nil, nil, nil, 0, fmt.Errorf("failed to get base CQ from extended CQ for device %s", rnic.DeviceName)
	}
	qpInitAttr.send_cq = base_send_cq
	qpInitAttr.recv_cq = base_recv_cq

	// Set appropriate capacity for performance
	qpInitAttr.cap.max_send_wr = C.uint32_t(len(m.Devices) * 100)
	qpInitAttr.cap.max_recv_wr = C.uint32_t(len(m.Devices) * 100)
	qpInitAttr.cap.max_send_sge = 1
	qpInitAttr.cap.max_recv_sge = 1

	// Create the QP
	qp := C.ibv_create_qp(rnic.PD, &qpInitAttr)
	if qp == nil {
		base_cq_to_destroy := C.ibv_cq_ex_to_cq(cqEx) // Direct call
		if base_cq_to_destroy != nil {
			C.ibv_destroy_cq(base_cq_to_destroy)
		} else {
			log.Error().Str("device", rnic.DeviceName).Msg("Failed to get base CQ from extended CQ for destruction during QP creation failure")
		}
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, fmt.Errorf("failed to create QP for device %s", rnic.DeviceName)
	}

	// Modify QP to INIT state
	if err := m.modifyQPToInit(rnic, qp); err != nil {
		C.ibv_destroy_qp(qp)
		base_cq_to_destroy := C.ibv_cq_ex_to_cq(cqEx) // Direct call
		if base_cq_to_destroy != nil {
			C.ibv_destroy_cq(base_cq_to_destroy)
		} else {
			log.Error().Str("device", rnic.DeviceName).Msg("Failed to get base CQ from extended CQ for destruction during INIT failure")
		}
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, err
	}

	// Modify QP to RTR state
	if err := m.modifyQPToRTR(rnic, qp); err != nil {
		C.ibv_destroy_qp(qp)
		base_cq_to_destroy := C.ibv_cq_ex_to_cq(cqEx) // Direct call
		if base_cq_to_destroy != nil {
			C.ibv_destroy_cq(base_cq_to_destroy)
		} else {
			log.Error().Str("device", rnic.DeviceName).Msg("Failed to get base CQ from extended CQ for destruction during RTR failure")
		}
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, err
	}

	// Modify QP to RTS state
	if err := m.modifyQPToRTS(rnic, qp, psn); err != nil {
		C.ibv_destroy_qp(qp)
		base_cq_to_destroy := C.ibv_cq_ex_to_cq(cqEx) // Direct call
		if base_cq_to_destroy != nil {
			C.ibv_destroy_cq(base_cq_to_destroy)
		} else {
			log.Error().Str("device", rnic.DeviceName).Msg("Failed to get base CQ from extended CQ for destruction during RTS failure")
		}
		C.ibv_destroy_comp_channel(compChannel)
		return nil, nil, nil, 0, err
	}

	return qp, cqEx, compChannel, psn, nil
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
func (m *RDMAManager) allocateMemoryResources(rnic *RNIC, qp *C.struct_ibv_qp, cq *C.struct_ibv_cq_ex, compChannel *C.struct_ibv_comp_channel) (unsafe.Pointer, unsafe.Pointer, *C.struct_ibv_mr, *C.struct_ibv_mr, error) {
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

	rnic.ProberQueue = senderQueue
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

// CreateAddressHandle creates a UD address handle for the target
func (u *UDQueue) CreateAddressHandle(targetGID string, flowLabel uint32) (*C.struct_ibv_ah, error) {
	log.Trace().
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

	// Copy IPv6 GID bytes to ahAttr.grh.dgid
	C.memcpy(unsafe.Pointer(&ahAttr.grh.dgid), unsafe.Pointer(&ipv6[0]), 16)

	ah := C.ibv_create_ah(u.RNIC.PD, &ahAttr)
	if ah == nil {
		return nil, fmt.Errorf("failed to create address handle for GID %s, device: %s, targetGID: %s", u.RNIC.GID, u.RNIC.DeviceName, targetGID)
	}

	return ah, nil
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
		base_cq_to_destroy := C.ibv_cq_ex_to_cq(u.CQ) // Direct call
		if base_cq_to_destroy != nil {
			C.ibv_destroy_cq(base_cq_to_destroy)
		} else {
			log.Error().Str("device", u.RNIC.DeviceName).Uint32("qpn", u.QPN).Msg("Failed to get base CQ from extended CQ for destruction in UDQueue.Destroy")
		}
		u.CQ = nil
	}

	if u.CompChannel != nil {
		C.ibv_destroy_comp_channel(u.CompChannel)
		u.CompChannel = nil
	}

	log.Debug().Str("device", u.RNIC.DeviceName).Uint32("qpn", u.QPN).Msg("Destroyed UD queue pair")
}

// Close now delegates queue destruction to each UDQueue and then closes devices.
func (m *RDMAManager) Close() {
	for gid, udQueue := range m.UDQueues {
		log.Debug().Str("gid", gid).Msg("Destroying UD queue pair")
		udQueue.Destroy()
		// Do not delete from m.UDQueues here as it will be iterated by other goroutines.
		// Instead, mark it as destroyed or let the GC handle it after all references are gone.
	}
	// Clear the maps after destroying all queues
	m.UDQueues = make(map[string]*UDQueue)
	m.SenderUDQueues = make(map[string]*UDQueue)
	m.ResponderUDQueues = make(map[string]*UDQueue)

	// Then close all RNIC devices
	for _, rnic := range m.Devices {
		rnic.CloseDevice()
	}
}
