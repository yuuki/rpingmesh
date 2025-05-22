package rdma

// #cgo LDFLAGS: -libverbs
// #include <stdlib.h>
// #include <arpa/inet.h>
// #include <infiniband/verbs.h>
// #include <errno.h>
//
// static int get_errno(void) {
//     return errno;
// }
import "C"
import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
)

const (
	// CQSize is the size of Completion Queue
	CQSize = 50
)

// WorkCompletion contains extracted work completion info
// Note: This is a Go representation, distinct from GoWorkCompletion which is closer to C.struct_ibv_wc
type WorkCompletion struct {
	Status    uint32
	SrcQP     uint32
	SGID      string
	DGID      string
	IMM       uint32
	VendorErr uint32
	FlowLabel uint32
}

// GoWorkCompletion represents the Go version of C.struct_ibv_wc
type GoWorkCompletion struct {
	WRID                  uint64
	Status                int // Using int for C.enum_ibv_wc_status
	Opcode                int // Using int for C.enum_ibv_wc_opcode
	VendorErr             uint32
	ByteLen               uint32
	SrcQP                 uint32
	WCFlags               uint32
	CompletionWallclockNS uint64 // Hardware wallclock timestamp in nanoseconds
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
	WC             C.struct_ibv_wc // Consider changing to GoWorkCompletion if appropriate
	CompletionType CompletionType
	Timestamp      time.Time
}

// processCQCompletions polls for work completions and processes them.
func (u *UDQueue) processCQCompletions(cqEx *C.struct_ibv_cq_ex) {
	// ibv_start_poll was successful, so cqEx points to the first completion.
	// Process the first completion.
	u.processSingleWC(cqEx) // New helper function to process one WC

	// Then, iterate with ibv_next_poll for subsequent completions.
	for {
		retNextPoll := C.ibv_next_poll(cqEx)
		if retNextPoll == C.ENOENT { // No more completions in this batch
			log.Trace().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("ibv_next_poll returned ENOENT, no more completions in this batch")
			break
		}
		if retNextPoll != 0 { // An error occurred
			// errno might be set by ibv_next_poll on error.
			errMsg := fmt.Sprintf("CQ Poller: ibv_next_poll failed for QPN 0x%x, Type: %s, Ret: %d, Errno: %d. Stopping poll for this batch.", u.QPN, getQueueTypeString(u.QueueType), retNextPoll, syscall.Errno(retNextPoll))
			log.Error().Msg(errMsg)
			select {
			case u.errChan <- fmt.Errorf(errMsg):
			default:
				log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping ibv_next_poll error")
			}
			break // Stop processing this batch on error
		}

		// cqEx now points to the next valid completion. Process it.
		u.processSingleWC(cqEx)
	}
}

// processSingleWC extracts and handles a single Work Completion from cqEx.
// cqEx must point to a valid WC when this function is called.
func (u *UDQueue) processSingleWC(cqEx *C.struct_ibv_cq_ex) {
	// At this point, cqEx points to the current valid completion
	// Fields like wr_id and status can be accessed directly from cqEx if it's defined to expose them.
	// For extended WCs, typically we use the ibv_wc_read_* functions.
	gwc := &GoWorkCompletion{
		WRID:                  uint64(cqEx.wr_id),
		Status:                int(cqEx.status),
		Opcode:                int(C.ibv_wc_read_opcode(cqEx)),
		VendorErr:             uint32(C.ibv_wc_read_vendor_err(cqEx)),
		ByteLen:               uint32(C.ibv_wc_read_byte_len(cqEx)),
		SrcQP:                 uint32(C.ibv_wc_read_src_qp(cqEx)),
		WCFlags:               uint32(C.ibv_wc_read_wc_flags(cqEx)),
		CompletionWallclockNS: uint64(C.ibv_wc_read_completion_wallclock_ns(cqEx)),
	}
	log.Trace().
		Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
		Str("type", getQueueTypeString(u.QueueType)).
		Int("status", gwc.Status).
		Uint64("wr_id", gwc.WRID).
		Int("opcode", gwc.Opcode).
		Uint64("hw_ts_ns", gwc.CompletionWallclockNS).
		Msg("Processing WC with HW Timestamp")

	if gwc.Status != C.IBV_WC_SUCCESS {
		u.handleWCError(gwc)
		return
	}

	switch gwc.Opcode {
	case C.IBV_WC_RECV:
		u.handleRecvCompletion(gwc)
	case C.IBV_WC_SEND:
		u.handleSendCompletion(gwc)
	default:
		log.Warn().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Int("opcode", gwc.Opcode).
			Msg("Received unknown WC opcode")
	}
}

func (u *UDQueue) handleWCError(gwc *GoWorkCompletion) {
	errMsg := fmt.Sprintf("CQ Poller: WC error for QPN 0x%x, Type: %s, Status: %s (%d), Vendor Syndrome: 0x%x, Opcode: %d, HWTimestamp: %d ns",
		u.QPN,
		getQueueTypeString(u.QueueType),
		C.GoString(C.ibv_wc_status_str(C.enum_ibv_wc_status(gwc.Status))),
		gwc.Status,
		gwc.VendorErr,
		gwc.Opcode,
		gwc.CompletionWallclockNS)
	log.Error().Msg(errMsg)
	select {
	case u.errChan <- fmt.Errorf(errMsg):
	default:
		log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping WC error")
	}
}

func (u *UDQueue) handleRecvCompletion(gwc *GoWorkCompletion) { // Removed cqEx from args
	log.Trace().
		Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
		Str("type", getQueueTypeString(u.QueueType)).
		Uint32("bytes", gwc.ByteLen).
		Uint32("src_qp", gwc.SrcQP).
		Uint32("wc_flags", gwc.WCFlags).
		Uint64("hw_ts_ns", gwc.CompletionWallclockNS).
		Msg("IBV_WC_RECV (HW Timestamp)")

	var probePkt *ProbePacket
	var grhInfo *GRHHeaderInfo

	// The GRH is at the beginning of the u.RecvBuf (or the specific buffer for this WR_ID).
	// Data starts after GRH.
	probePacketStructSize := unsafe.Sizeof(ProbePacket{})
	expectedMinLengthWithGRH := GRHSize + int(probePacketStructSize)
	expectedMinLengthNoGRH := int(probePacketStructSize)

	var currentExpectedMinLength int
	if (gwc.WCFlags & C.IBV_WC_GRH) == 0 {
		// If no GRH flag, assume packet starts immediately. This is unusual for UD but handle defensively.
		currentExpectedMinLength = expectedMinLengthNoGRH
		log.Warn().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Msg("IBV_WC_RECV without IBV_WC_GRH flag. Assuming ProbePacket is at buffer start.")
	} else {
		currentExpectedMinLength = expectedMinLengthWithGRH
	}

	if gwc.ByteLen < uint32(currentExpectedMinLength) {
		log.Error().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Uint32("received_bytes", gwc.ByteLen).
			Int("expected_min_bytes", currentExpectedMinLength). // Changed to Int
			Bool("grh_flag_present", (gwc.WCFlags&C.IBV_WC_GRH) != 0).
			Msg("Received packet too small")
		if errPost := u.PostRecv(); errPost != nil { // Attempt to repost buffer even on error
			log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msgf("Failed to repost recv buffer after small packet error: %v", errPost)
		}
		return
	}

	var payloadStartPtr unsafe.Pointer
	if (gwc.WCFlags & C.IBV_WC_GRH) != 0 {
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
			ReceivedAt:  time.Unix(0, int64(gwc.CompletionWallclockNS)), // use HW timestamp
			GRHInfo:     grhInfo,
			SourceQP:    gwc.SrcQP,
			RawWC:       gwc, // Pass original wc (not wcCopy) for inspection. Handler should not store this pointer.
			AckStatusOK: true,
		}
		u.ackHandler(ackInfo)
	} else {
		log.Trace().
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
		case u.recvCompChan <- gwc:
		default:
			log.Warn().
				Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
				Str("type", getQueueTypeString(u.QueueType)).
				Msg("Receive completion channel full, dropping WC_RECV event. gwc will be freed.")
		}
	}

	if errPost := u.PostRecv(); errPost != nil {
		errMsg := fmt.Sprintf("CQ Poller: Failed to repost receive buffer for QPN 0x%x, Type: %s: %v", u.QPN, getQueueTypeString(u.QueueType), errPost)
		log.Error().Msg(errMsg)
		select {
		case u.errChan <- fmt.Errorf(errMsg):
		default:
			log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping repost error")
		}
	}
}

func (u *UDQueue) handleSendCompletion(gwc *GoWorkCompletion) {
	log.Trace().
		Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
		Str("type", getQueueTypeString(u.QueueType)).
		Uint32("bytes", gwc.ByteLen).
		Uint32("src_qp", gwc.SrcQP).
		Uint32("wc_flags", gwc.WCFlags).
		Uint64("hw_ts_ns", gwc.CompletionWallclockNS).
		Msg("IBV_WC_SEND")
	select {
	case u.sendCompChan <- gwc:
	default:
		log.Warn().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Msg("Send completion channel full, dropping WC_SEND event. gwc will be freed.")
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

		baseCQ := C.ibv_cq_ex_to_cq(u.CQ)
		if baseCQ == nil {
			errMsg := fmt.Sprintf("CQ Poller: Failed to get base CQ from extended CQ for QPN 0x%x, Type: %s. Poller exiting.", u.QPN, getQueueTypeString(u.QueueType))
			log.Error().Msg(errMsg)
			select {
			case u.errChan <- fmt.Errorf(errMsg):
			default:
				log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping base CQ retrieval error")
			}
			return
		}

		// // Initial request for CQ notification
		if C.ibv_req_notify_cq(baseCQ, 0) != 0 {
			errMsg := fmt.Sprintf("CQ Poller: Failed to request initial CQ notification for QPN 0x%x, Type: %s: %s. Poller exiting.", u.QPN, getQueueTypeString(u.QueueType), syscall.Errno(C.get_errno()).Error())
			log.Error().Msg(errMsg)
			select {
			case u.errChan <- fmt.Errorf(errMsg):
			default:
				log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping initial CQ notification error")
			}
			return
		}

		var ibvPollCqAttr C.struct_ibv_poll_cq_attr
		for {
			select {
			case <-u.cqPollerDone:
				log.Info().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).
					Msg("CQ poller received done signal. Exiting.")
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
				case <-u.cqPollerDone:
					log.Info().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ poller: ibv_get_cq_event failed during shutdown. Normal.")
					return
				default:
					log.Error().
						Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
						Str("type", getQueueTypeString(u.QueueType)).
						Int("ret", int(retGetEvent)).
						Str("errno", syscall.Errno(C.get_errno()).Error()).
						Msg("ibv_get_cq_event failed")
					select {
					case u.errChan <- fmt.Errorf("ibv_get_cq_event failed: %s", syscall.Errno(C.get_errno()).Error()):
					default:
						log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping ibv_get_cq_event error")
					}
					return // Critical error, poller stops
				}
			}

			if cqEv == nil {
				log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("CQ Poller: ibv_get_cq_event returned nil cqEv. This is unexpected. Continuing after ack and re-arm.")
				C.ibv_ack_cq_events(baseCQ, 1) // Ack on baseCQ as cqEv is nil
				if C.ibv_req_notify_cq(baseCQ, 0) != 0 {
					log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msgf("CQ Poller: Failed to re-request CQ notification on baseCQ after nil cqEv: %s", syscall.Errno(C.get_errno()).Error())
				}
				continue
			}

			// Check if the event is for the CQ we are interested in.
			if cqEv != baseCQ { // Compare with the base CQ derived from u.CQ
				log.Warn().
					Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
					Str("type", getQueueTypeString(u.QueueType)).
					Msgf("CQ Poller: Event from cq %p does not match expected base cq %p. Acking event on cqEv and re-arming baseCQ.", cqEv, baseCQ)
				C.ibv_ack_cq_events(cqEv, 1)             // Ack on the CQ that generated the event.
				if C.ibv_req_notify_cq(baseCQ, 0) != 0 { // Re-arm our CQ.
					log.Error().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msgf("CQ Poller: Failed to re-request CQ notification on baseCQ after mismatched event: %s", syscall.Errno(C.get_errno()).Error())
				}
				continue
			}

			C.ibv_ack_cq_events(cqEv, 1) // Ack on the CQ that generated the event.

			if C.ibv_req_notify_cq(baseCQ, 0) != 0 {
				errMsg := fmt.Sprintf("CQ Poller: Failed to re-request CQ notification for QPN 0x%x, Type: %s: %s. Continuing, but may miss events.", u.QPN, getQueueTypeString(u.QueueType), syscall.Errno(C.get_errno()).Error())
				log.Error().Msg(errMsg)
				select {
				case u.errChan <- fmt.Errorf(errMsg):
				default:
					log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping CQ re-request notification error")
				}
			}

			// Use ibv_start_poll, processCQCompletions, ibv_end_poll pattern
			retStartPoll := C.ibv_start_poll(u.CQ, &ibvPollCqAttr)
			if retStartPoll == 0 {
				log.Trace().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).Msg("ibv_start_poll successful, processing completions.")
				u.processCQCompletions(u.CQ)
				C.ibv_end_poll(u.CQ)
			} else if retStartPoll == C.ENOENT {
				log.Trace().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Str("type", getQueueTypeString(u.QueueType)).
					Msg("CQ poller: ibv_start_poll returned ENOENT (no completions). This is normal after event if completions were already processed.")
				// No need to call C.ibv_end_poll if C.ibv_start_poll didn't return 0
			} else {
				// An error other than ENOENT occurred with ibv_start_poll
				errMsg := fmt.Sprintf("CQ Poller: ibv_start_poll failed for QPN 0x%x, Type: %s, Ret: %d, Errno: %d. Poller may miss events.", u.QPN, getQueueTypeString(u.QueueType), retStartPoll, syscall.Errno(retStartPoll))
				log.Error().Msg(errMsg)
				select {
				case u.errChan <- fmt.Errorf(errMsg):
				default:
					log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping ibv_start_poll error")
				}
				// No C.ibv_end_poll if C.ibv_start_poll failed with an error other than ENOENT
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
