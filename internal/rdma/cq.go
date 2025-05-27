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
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// WorkCompletion was previously defined here. It will be removed.
// We will define ProcessedWorkCompletion below GoWorkCompletion.

// GoWorkCompletion represents the Go version of C.struct_ibv_wc_ex
type GoWorkCompletion struct {
	WRID                  uint64
	Status                int    // Using int for C.enum_ibv_wc_status (ibv_wc_status)
	Opcode                int    // Using int for C.enum_ibv_wc_opcode (ibv_wc_opcode)
	VendorErr             uint32 // vendor_err
	ByteLen               uint32 // byte_len (includes GRH length if GRH is present)
	SrcQP                 uint32 // src_qp (remote QP number for received packets)
	WCFlags               uint32 // wc_flags (e.g., C.IBV_WC_GRH) - crucial for interpretation
	CompletionWallclockNS uint64 // Hardware wallclock timestamp in nanoseconds
}

// ProcessedWorkCompletion embeds GoWorkCompletion and adds GRH-parsed information.
// This replaces the old WorkCompletion struct.
type ProcessedWorkCompletion struct {
	GoWorkCompletion // Embedded low-level work completion details

	// Information parsed from GRH (if GRH was present in the received packet)
	SGID      string // Source GID (string format)
	DGID      string // Destination GID (string format)
	FlowLabel uint32 // Flow Label from GRH
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
			pollerErr := fmt.Errorf("CQ Poller: ibv_next_poll failed for QPN 0x%x, Type: %s, Ret: %d, ErrnoCode: %d. Stopping poll for this batch", u.QPN, getQueueTypeString(u.QueueType), retNextPoll, syscall.Errno(retNextPoll))
			log.Error().Err(pollerErr).Msg("ibv_next_poll error")
			select {
			case u.errChan <- pollerErr:
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
		if errPost := u.PostRecv(); errPost != nil {
			repostErr := fmt.Errorf("CQ Poller: Failed to repost receive buffer for QPN 0x%x, Type: %s: %w", u.QPN, getQueueTypeString(u.QueueType), errPost)
			log.Error().Err(repostErr).Msg("Failed to repost receive buffer")
			select {
			case u.errChan <- repostErr:
			default:
				log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping repost error")
			}
		}
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
	// errMsg := fmt.Sprintf("CQ Poller: WC error for QPN 0x%x, Type: %s, Status: %s (%d), Vendor Syndrome: 0x%x, Opcode: %d, HWTimestamp: %d ns",
	// 	u.QPN,
	// 	getQueueTypeString(u.QueueType),
	// 	C.GoString(C.ibv_wc_status_str(C.enum_ibv_wc_status(gwc.Status))),
	// 	gwc.Status,
	// 	gwc.VendorErr,
	// 	gwc.Opcode,
	// 	gwc.CompletionWallclockNS)
	// log.Error().Msg(errMsg)
	wcErr := fmt.Errorf("CQ Poller: WC error for QPN 0x%x, Type: %s, Status: %s (%d), Vendor Syndrome: 0x%x, Opcode: %d, HWTimestamp: %d ns", u.QPN, getQueueTypeString(u.QueueType), C.GoString(C.ibv_wc_status_str(C.enum_ibv_wc_status(gwc.Status))), gwc.Status, gwc.VendorErr, gwc.Opcode, gwc.CompletionWallclockNS)
	log.Error().Err(wcErr).Msg("Work Completion Error")
	select {
	case u.errChan <- wcErr:
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

		log.Trace().
			Str("qpn", fmt.Sprintf("0x%x", u.QPN)).
			Str("type", getQueueTypeString(u.QueueType)).
			Msg("GRH present on received ACK")

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

		var sgid, dgid string
		var flowLabel uint32
		var payloadPtr unsafe.Pointer
		var payloadLen uint32
		var grhParseErr error

		if (gwc.WCFlags & C.IBV_WC_GRH) == C.IBV_WC_GRH {
			// Temporarily use the parsing logic from packet.go - this might need refactoring
			// to avoid direct dependency or to have a shared GRH parsing utility.
			// This is a simplified version for now, assuming u.RecvBuf is the one.
			if uint32(gwc.ByteLen) >= GRHSize {
				grhBytes := unsafe.Slice((*byte)(u.RecvBuf), GRHSize)
				ipVersion := (grhBytes[0] >> 4) & 0x0F
				if ipVersion == 6 {
					sgid, dgid, flowLabel, grhParseErr = u.parseIPv6GRHFromBytes(grhBytes) // Assumes this helper exists or is added
				} else if ipVersion == 4 {
					sgid, dgid, grhParseErr = u.parseIPv4GRHFromBytes(grhBytes) // Assumes this helper exists or is added
				}
				if grhParseErr != nil {
					log.Warn().Err(grhParseErr).Msg("GRH parsing failed in handleRecvCompletion for ACK")
				}
				payloadPtr = unsafe.Pointer(uintptr(u.RecvBuf) + uintptr(GRHSize))
				payloadLen = uint32(gwc.ByteLen) - GRHSize
			} else {
				log.Warn().Msg("GRH flag set but ByteLen too small in handleRecvCompletion for ACK")
				payloadPtr = u.RecvBuf
				payloadLen = uint32(gwc.ByteLen)
			}
		} else {
			payloadPtr = u.RecvBuf
			payloadLen = uint32(gwc.ByteLen)
		}

		// Deserialize ProbePacket from payload if it's an ACK
		if probePkt == nil && payloadPtr != nil { // probePkt might have been parsed earlier if logic changes
			packetStructSize := uint32(unsafe.Sizeof(ProbePacket{}))
			if payloadLen >= packetStructSize {
				probePkt = (*ProbePacket)(payloadPtr) // Still points to RecvBuf, handler must copy if needed
			} else {
				log.Warn().Uint32("payloadLen", payloadLen).Uint32("expected", packetStructSize).Msg("Payload too small to be ProbePacket for ACK")
				// Cannot proceed if we can't get the ACK type, etc.
				u.PostRecv() // Attempt to repost buffer
				return
			}
		}

		if probePkt == nil || probePkt.IsAck != 1 { // Defensive check
			log.Warn().Msg("Not a valid ACK packet for ackHandler, or failed to parse.")
			// This path might indicate a logic error or unexpected packet. If it's not an ACK,
			// it should go to recvCompChan. The `if u.QueueType == UDQueueTypeSender ...` handles this.
			// For now, let the original logic send gwc to recvCompChan if not ACK for sender.
			// This block mainly ensures probePkt is valid if we proceed to ackHandler.
		}

		processedWCForAck := &ProcessedWorkCompletion{
			GoWorkCompletion: *gwc,
			SGID:             sgid,
			DGID:             dgid,
			FlowLabel:        flowLabel,
		}

		ackInfo := &IncomingAckInfo{
			Packet:      probePkt, // This is a pointer to RecvBuf, be careful.
			ReceivedAt:  time.Unix(0, int64(gwc.CompletionWallclockNS)),
			ProcessedWC: processedWCForAck,
			AckStatusOK: gwc.Status == C.IBV_WC_SUCCESS, // Set AckStatusOK based on gwc.Status
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
			// errMsg := fmt.Sprintf("CQ Poller: Completion channel is nil for QPN 0x%x, Type: %s. Poller cannot start.", u.QPN, getQueueTypeString(u.QueueType))
			// log.Error().Msg(errMsg)
			nilChanErr := fmt.Errorf("CQ Poller: Completion channel is nil for QPN 0x%x, Type: %s. Poller cannot start", u.QPN, getQueueTypeString(u.QueueType))
			log.Error().Err(nilChanErr).Msg("Completion channel is nil")
			select {
			case u.errChan <- nilChanErr:
			default:
				log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping nil completion channel error")
			}
			return
		}

		baseCQ := C.ibv_cq_ex_to_cq(u.CQ)
		if baseCQ == nil {
			// errMsg := fmt.Sprintf("CQ Poller: Failed to get base CQ from extended CQ for QPN 0x%x, Type: %s. Poller exiting.", u.QPN, getQueueTypeString(u.QueueType))
			// log.Error().Msg(errMsg)
			baseCqErr := fmt.Errorf("CQ Poller: Failed to get base CQ from extended CQ for QPN 0x%x, Type: %s. Poller exiting", u.QPN, getQueueTypeString(u.QueueType))
			log.Error().Err(baseCqErr).Msg("Failed to get base CQ")
			select {
			case u.errChan <- baseCqErr:
			default:
				log.Warn().Str("qpn", fmt.Sprintf("0x%x", u.QPN)).Msg("Error channel full, dropping base CQ retrieval error")
			}
			return
		}

		// // Initial request for CQ notification
		if C.ibv_req_notify_cq(baseCQ, 0) != 0 {
			// errMsg := fmt.Sprintf("CQ Poller: Failed to request initial CQ notification for QPN 0x%x, Type: %s: %s. Poller exiting.", u.QPN, getQueueTypeString(u.QueueType), syscall.Errno(C.get_errno()).Error())
			// log.Error().Msg(errMsg)
			notifyErr := fmt.Errorf("CQ Poller: Failed to request initial CQ notification for QPN 0x%x, Type: %s: %w. Poller exiting", u.QPN, getQueueTypeString(u.QueueType), syscall.Errno(C.get_errno()))
			log.Error().Err(notifyErr).Msg("Failed to request initial CQ notification")
			select {
			case u.errChan <- notifyErr:
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
					// case u.errChan <- fmt.Errorf("ibv_get_cq_event failed: %s", syscall.Errno(C.get_errno()).Error()):
					case u.errChan <- fmt.Errorf("ibv_get_cq_event failed: %w", syscall.Errno(C.get_errno())):
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
				// errMsg := fmt.Sprintf("CQ Poller: Failed to re-request CQ notification for QPN 0x%x, Type: %s: %s. Continuing, but may miss events.", u.QPN, getQueueTypeString(u.QueueType), syscall.Errno(C.get_errno()).Error())
				// log.Error().Msg(errMsg)
				rereqErr := fmt.Errorf("CQ Poller: Failed to re-request CQ notification for QPN 0x%x, Type: %s: %w. Continuing, but may miss events", u.QPN, getQueueTypeString(u.QueueType), syscall.Errno(C.get_errno()))
				log.Error().Err(rereqErr).Msg("Failed to re-request CQ notification")
				select {
				case u.errChan <- rereqErr:
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
				// errMsg := fmt.Sprintf("CQ Poller: ibv_start_poll failed for QPN 0x%x, Type: %s, Ret: %d, Errno: %d. Poller may miss events.", u.QPN, getQueueTypeString(u.QueueType), retStartPoll, syscall.Errno(retStartPoll))
				// log.Error().Msg(errMsg)
				startPollErr := fmt.Errorf("CQ Poller: ibv_start_poll failed for QPN 0x%x, Type: %s, Ret: %d, ErrnoCode: %d. Poller may miss events", u.QPN, getQueueTypeString(u.QueueType), retStartPoll, syscall.Errno(retStartPoll))
				log.Error().Err(startPollErr).Msg("ibv_start_poll error")
				select {
				case u.errChan <- startPollErr:
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

func (u *UDQueue) parseIPv6GRHFromBytes(grhBytes []byte) (sgid string, dgid string, flowLabel uint32, err error) {
	// Simplified parsing logic, similar to packet.go, or call a shared utility.
	// This is a placeholder for the actual implementation.
	if len(grhBytes) < 40 {
		return "", "", 0, fmt.Errorf("grhBytes too short for IPv6 GID extraction (len: %d)", len(grhBytes))
	}
	sgid = formatGIDString(grhBytes[8:24])
	dgid = formatGIDString(grhBytes[24:40])
	ipv6Header, parseErr := ipv6.ParseHeader(grhBytes)
	if parseErr == nil && ipv6Header != nil {
		flowLabel = uint32(ipv6Header.FlowLabel)
	} else {
		log.Warn().Err(parseErr).Msg("Failed to parse GRH as IPv6 header to get FlowLabel in UDQueue helper")
	}
	return sgid, dgid, flowLabel, nil
}

func (u *UDQueue) parseIPv4GRHFromBytes(grhBytes []byte) (sgid string, dgid string, err error) {
	// Simplified parsing logic, similar to packet.go, or call a shared utility.
	// This is a placeholder for the actual implementation.
	const ipv4HeaderOffsetInGRH = 20
	const ipv4HeaderMinLength = 20
	if GRHSize < ipv4HeaderOffsetInGRH+ipv4HeaderMinLength {
		return "", "", fmt.Errorf("GRH too small for IPv4 header at offset %d", ipv4HeaderOffsetInGRH)
	}
	ipv4HeaderBytes := grhBytes[ipv4HeaderOffsetInGRH : ipv4HeaderOffsetInGRH+ipv4HeaderMinLength]
	parsedIPv4Header, parseErr := ipv4.ParseHeader(ipv4HeaderBytes)
	if parseErr != nil {
		return "", "", fmt.Errorf("failed to parse GRH region's IPv4 header part: %w", parseErr)
	}
	if parsedIPv4Header.Src == nil || parsedIPv4Header.Dst == nil {
		return "", "", fmt.Errorf("parsed IPv4 header from GRH, but Src/Dst IP is nil")
	}
	srcIPv4 := parsedIPv4Header.Src.To4()
	dstIPv4 := parsedIPv4Header.Dst.To4()
	if srcIPv4 == nil || dstIPv4 == nil {
		return "", "", fmt.Errorf("could not convert GRH region's IPv4 Src/Dst to 4-byte format")
	}
	srcMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, srcIPv4[0], srcIPv4[1], srcIPv4[2], srcIPv4[3]}
	dstMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, dstIPv4[0], dstIPv4[1], dstIPv4[2], dstIPv4[3]}
	return formatGIDString(srcMappedIPv6Bytes), formatGIDString(dstMappedIPv6Bytes), nil
}
