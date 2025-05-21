package probe

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/rdma"
	"github.com/yuuki/rpingmesh/internal/state"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PingSession holds the state for a single probe transaction.
type PingSession struct {
	SequenceNum   uint64
	SourceRnicGid string
	TargetGid     string
	FlowLabel     uint32 // For logging/debugging

	Ack1Chan chan *ackEvent // Receives the first ACK (type 1)
	Ack2Chan chan *ackEvent // Receives the second ACK (type 2)

	CreationTime time.Time
}

// ackEvent is a wrapper for ACK data received.
type ackEvent struct {
	Packet     *rdma.ProbePacket
	ReceivedAt time.Time
	WorkComp   *rdma.WorkCompletion
}

// Prober is responsible for sending probes to targets and processing their responses
type Prober struct {
	rdmaManager  *rdma.RDMAManager
	agentState   *state.AgentState
	sequenceNum  uint64
	probeResults chan *agent_analyzer.ProbeResult
	timeout      time.Duration
	stopCh       chan struct{}
	wg           sync.WaitGroup
	running      bool

	pendingSessions *sync.Map // Key: sequence number
}

const (
	probeResultChanBufferSize = 1000
	responderStatsInterval    = 30 * time.Second
)

// NewProber creates a new prober
func NewProber(rdmaManager *rdma.RDMAManager, agentState *state.AgentState, timeoutMs uint32) *Prober {
	return &Prober{
		rdmaManager:     rdmaManager,
		agentState:      agentState,
		sequenceNum:     0,
		probeResults:    make(chan *agent_analyzer.ProbeResult, probeResultChanBufferSize),
		timeout:         time.Duration(timeoutMs) * time.Millisecond,
		stopCh:          make(chan struct{}),
		running:         false,
		pendingSessions: new(sync.Map),
	}
}

// Start starts the prober
func (p *Prober) Start() error {
	if p.running {
		return nil
	}

	p.running = true
	p.stopCh = make(chan struct{})

	detectedRNICs := p.agentState.GetDetectedRNICs()
	log.Debug().Int("count", len(detectedRNICs)).Msg("RNICs detected by AgentState for Prober.Start")

	for _, rnic := range detectedRNICs {
		log.Debug().Str("rnic_gid", rnic.GID).Str("rnic_device_name", rnic.DeviceName).Msg("Processing RNIC in Prober.Start")

		// Start responderLoop for RESPONDER UDQueues
		responderUdq := p.agentState.GetResponderUDQueue(rnic.GID)
		if responderUdq != nil {
			p.wg.Add(1)
			go p.responderLoop(responderUdq)
		} else {
			log.Warn().Str("rnic_gid", rnic.GID).Str("rnic_device_name", rnic.DeviceName).Msg("Responder UDQueue is nil for this RNIC, responderLoop will not start")
		}

		// Start ackDispatcherLoop for SENDER UDQueues
		senderUdq := p.agentState.GetSenderUDQueue(rnic.GID)
		if senderUdq != nil {
			log.Info().Str("rnic_gid", rnic.GID).Msg("Sender UDQueue found; ACK handler should be registered by AgentState.")
		} else {
			log.Warn().Str("rnic_gid", rnic.GID).Str("rnic_device_name", rnic.DeviceName).Msg("Sender UDQueue is nil for this RNIC, ACK handler cannot be set up here.")
		}
	}
	return nil
}

// Stop stops the prober
func (p *Prober) Stop() {
	if !p.running {
		return
	}

	close(p.stopCh)
	p.wg.Wait()
	p.running = false
}

// ProbeTarget sends a probe to a target and waits for a response
func (p *Prober) ProbeTarget(
	ctx context.Context, // Overall timeout for this probe operation
	sourceRnic *rdma.RNIC,
	targetGID string,
	targetQPN uint32,
	sourcePort uint32,
	flowLabel uint32,
	probeType string,
	targetRnicInfo *agent_analyzer.RnicIdentifier,
) {
	seqNum := atomic.AddUint64(&p.sequenceNum, 1)

	srcUdQueue := p.agentState.GetSenderUDQueue(sourceRnic.GID)
	if srcUdQueue == nil {
		log.Error().
			Str("gid", sourceRnic.GID).
			Uint64("seqNum", seqNum).
			Msg("Failed to get sender UDQueue for source RNIC in ProbeTarget")
		return
	}

	// Create and register the session
	session := &PingSession{
		SequenceNum:   seqNum,
		SourceRnicGid: sourceRnic.GID,
		TargetGid:     targetGID,
		FlowLabel:     flowLabel,
		Ack1Chan:      make(chan *ackEvent, 1), // Buffered to allow dispatcher to send without blocking if ProbeTarget is slow
		Ack2Chan:      make(chan *ackEvent, 1), // Same buffering reason
		CreationTime:  time.Now(),
	}

	p.pendingSessions.Store(flowLabel, session)

	// Ensure session is cleaned up
	defer func() {
		p.pendingSessions.Delete(flowLabel)

		// Close channels to unblock dispatcher if it's trying to send to a timed-out session,
		// and to prevent leaks.
		// The dispatcher has a non-blocking send attempt (select with default).
		if session.Ack1Chan != nil { // Check if already nilled out by ACK processing
			close(session.Ack1Chan)
		}
		if session.Ack2Chan != nil { // Check if already nilled out
			close(session.Ack2Chan)
		}
		log.Debug().Uint32("flowLabel", flowLabel).Msg("Cleaned up session")
	}()

	result := &agent_analyzer.ProbeResult{
		SourceRnic: &agent_analyzer.RnicIdentifier{
			Gid:       sourceRnic.GID,
			Qpn:       srcUdQueue.QPN, // Safe now as srcUdQueue is not nil
			IpAddress: sourceRnic.IPAddr,
			HostName:  sourceRnic.DeviceName,
			// TorId:     "", // Populate if available
		},
		DestinationRnic: targetRnicInfo,
		FiveTuple: &agent_analyzer.ProbeFiveTuple{
			SrcGid:    sourceRnic.GID,
			SrcQpn:    srcUdQueue.QPN,
			DstGid:    targetGID,
			DstQpn:    targetQPN,
			FlowLabel: flowLabel,
		},
		ProbeType: probeType,
		Status:    agent_analyzer.ProbeResult_UNKNOWN, // Initial status
	}

	log.Debug().
		Str("srcGID", sourceRnic.GID).
		Uint32("srcQPN", srcUdQueue.QPN).
		Str("dstGID", targetGID).
		Uint32("dstQPN", targetQPN).
		Uint32("flowLabel", flowLabel).
		Str("probeType", probeType).
		Uint64("seqNum", seqNum).
		Msg("Starting probe to target (session based)")

	// Send probe packet
	// The context passed to SendProbePacket should be derived from the overall 'ctx' for ProbeTarget
	// or be a shorter one specific to the send operation if needed.
	// For now, let's use a derived context that respects the overall timeout for this specific send.
	sendCtx, sendCancel := context.WithTimeout(ctx, p.timeout) // Use prober's general timeout for the send itself
	t1, t2, err := srcUdQueue.SendProbePacket(sendCtx, targetGID, targetQPN, seqNum, sourcePort, flowLabel)
	sendCancel() // Release sendCtx resources
	result.T1 = timestamppb.New(t1)
	result.T2 = timestamppb.New(t2)

	if err != nil {
		log.Error().Err(err).
			Str("srcGID", sourceRnic.GID).
			Uint32("srcQPN", srcUdQueue.QPN).
			Str("targetGID", targetGID).
			Uint64("seqNum", seqNum).
			Uint32("flowLabel", flowLabel).
			Msg("[prober]: Failed to send probe packet")
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			result.Status = agent_analyzer.ProbeResult_TIMEOUT // Or a more specific send timeout error
		} else {
			result.Status = agent_analyzer.ProbeResult_ERROR
		}
		p.probeResults <- result
		return
	}
	result.T2 = timestamppb.New(t2)

	log.Trace().
		Str("srcGID", sourceRnic.GID).
		Uint32("srcQPN", srcUdQueue.QPN).
		Str("targetGID", targetGID).
		Uint64("seqNum", seqNum).
		Uint32("flowLabel", flowLabel).
		Msg("[prober]: Probe sent, waiting for ACKs via session channels")

	var ack1Event, ack2Event *ackEvent
	ack1Received, ack2Received := false, false

	for !(ack1Received && ack2Received) {
		// Define local copies of channel references for the select statement.
		// This allows nilling them out after an ACK is received to prevent re-selection.
		currentAck1Chan := session.Ack1Chan
		currentAck2Chan := session.Ack2Chan

		if ack1Received { // If already received, don't select on it.
			currentAck1Chan = nil
		}
		if ack2Received {
			currentAck2Chan = nil
		}
		// If both channels are nil (both ACKs received), the loop condition handles exit.
		// If one is nil, select will ignore it.

		select {
		case <-ctx.Done(): // Overall timeout for ProbeTarget
			log.Debug().Err(ctx.Err()).
				Uint64("seqNum", seqNum).
				Str("srcGID", sourceRnic.GID).
				Uint32("srcQPN", srcUdQueue.QPN).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Uint32("flowLabel", flowLabel).
				Bool("ack1Rcvd", ack1Received).
				Bool("ack2Rcvd", ack2Received).
				Msg("[prober]: Context timed out/cancelled while waiting for ACKs")
			result.Status = agent_analyzer.ProbeResult_TIMEOUT
			p.probeResults <- result
			return // Exit ProbeTarget

		case event, ok := <-currentAck1Chan: // currentAck1Chan could be nil
			if !ok { // Channel closed by defer or dispatcher
				log.Warn().
					Uint64("seqNum", seqNum).
					Uint32("flowLabel", flowLabel).
					Msg("[prober]: Ack1Chan closed unexpectedly")
				session.Ack1Chan = nil // Ensure it's nil for future selects if loop somehow continues
				if !ack1Received {     // If we genuinely needed it, this is a problem
					result.Status = agent_analyzer.ProbeResult_ERROR // Indicate missing ACK
					p.probeResults <- result
					return
				}
				continue // Re-evaluate loop condition
			}
			if !ack1Received { // Process only the first one
				ack1Event = event
				ack1Received = true
				log.Debug().
					Uint64("seqNum", seqNum).
					Uint32("flowLabel", flowLabel).
					Msg("[prober]: Received first ACK (type 1)")
				// session.Ack1Chan = nil // Done with this channel, effectively handled by currentAck1Chan logic
			} else {
				log.Warn().
					Uint64("seqNum", seqNum).
					Uint32("flowLabel", flowLabel).
					Msg("[prober]: Received duplicate/late first ACK on Ack1Chan")
			}

		case event, ok := <-currentAck2Chan: // currentAck2Chan could be nil
			if !ok {
				log.Warn().
					Uint64("seqNum", seqNum).
					Uint32("flowLabel", flowLabel).
					Msg("[prober]: Ack2Chan closed unexpectedly")
				session.Ack2Chan = nil
				if !ack2Received {
					result.Status = agent_analyzer.ProbeResult_ERROR
					p.probeResults <- result
					return
				}
				continue
			}
			if !ack2Received {
				ack2Event = event
				ack2Received = true
				log.Debug().
					Uint64("seqNum", seqNum).
					Uint32("flowLabel", flowLabel).
					Msg("[prober]: Received second ACK (type 2)")
				// session.Ack2Chan = nil
			} else {
				log.Warn().
					Uint64("seqNum", seqNum).
					Uint32("flowLabel", flowLabel).
					Msg("[prober]: Received duplicate/late second ACK on Ack2Chan")
			}
		}
	} // End of ackLoop

	// If we exited the loop, it means ack1Received and ack2Received are true.
	// Or, a channel closed and we errored out (handled above).
	// Or, ctx.Done() was hit (handled above).

	if !(ack1Received && ack2Received) {
		// This path should ideally not be reached if timeout/error handling in select is correct.
		// It implies the loop condition was met without both ACKs, or an unhandled case.
		if result.Status == agent_analyzer.ProbeResult_UNKNOWN || result.Status == agent_analyzer.ProbeResult_OK { // If not already set to TIMEOUT or ERROR
			log.Error().
				Uint64("seqNum", seqNum).
				Bool("ack1", ack1Received).
				Bool("ack2", ack2Received).
				Msg("[prober]: Exited ACK loop logic error: not all ACKs received and not due to reported timeout/error.")
			result.Status = agent_analyzer.ProbeResult_ERROR
		}
		p.probeResults <- result
		return
	}

	// Process ACKs
	result.T5 = timestamppb.New(ack1Event.ReceivedAt) // T5 is receive time of first ACK at prober

	t3Time := time.Unix(0, int64(ack2Event.Packet.T3))
	t4Time := time.Unix(0, int64(ack2Event.Packet.T4))
	result.T3 = timestamppb.New(t3Time)
	result.T4 = timestamppb.New(t4Time)

	t6 := time.Now() // T6 is prober's post-processing time
	result.T6 = timestamppb.New(t6)

	// Calculations
	networkRTT := ack1Event.ReceivedAt.Sub(t2) - (t4Time.Sub(t3Time))
	result.NetworkRtt = networkRTT.Nanoseconds()

	proberDelay := t6.Sub(t1) - ack1Event.ReceivedAt.Sub(t2)
	result.ProberDelay = proberDelay.Nanoseconds()

	responderDelay := t4Time.Sub(t3Time)
	result.ResponderDelay = responderDelay.Nanoseconds()

	result.Status = agent_analyzer.ProbeResult_OK

	log.Debug().
		Uint64("seqNum", seqNum).
		Str("targetGID", targetGID).
		Int64("networkRTT_ns", result.NetworkRtt).
		Int64("proberDelay_ns", result.ProberDelay).
		Int64("responderDelay_ns", result.ResponderDelay).
		Msg("[prober]: Probe completed successfully")

	p.probeResults <- result
}

// GetProbeResults returns the channel where probe results are published
func (p *Prober) GetProbeResults() <-chan *agent_analyzer.ProbeResult {
	return p.probeResults
}

// responderLoop handles incoming probe packets and sends ACKs
func (p *Prober) responderLoop(udq *rdma.UDQueue) {
	defer p.wg.Done()

	log.Info().
		Str("device", udq.RNIC.DeviceName).
		Uint32("qpn", udq.QPN).
		Str("gid", udq.RNIC.GID).
		Str("queueType", "Responder").
		Msg("[responder]: Starting responder loop to handle incoming probe packets on responder UDQueue")

	// Track statistics for debugging
	var (
		totalPackets   uint64
		probePackets   uint64
		invalidPackets uint64
		errorPackets   uint64
	)

	// Log stats periodically
	statsTicker := time.NewTicker(responderStatsInterval)
	defer statsTicker.Stop()

	for {
		select {
		case <-p.stopCh:
			log.Info().
				Uint64("totalPackets", totalPackets).
				Uint64("probePackets", probePackets).
				Uint64("invalidPackets", invalidPackets).
				Uint64("errorPackets", errorPackets).
				Msg("Stopping responder loop")
			return

		case <-statsTicker.C:
			// Log stats periodically
			log.Debug().
				Uint64("totalPackets", totalPackets).
				Uint64("probePackets", probePackets).
				Uint64("invalidPackets", invalidPackets).
				Uint64("errorPackets", errorPackets).
				Msg("Responder loop stats")

		default:
			// Create a context with timeout for ReceivePacket
			ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
			packet, receiveTime, workComp, err := udq.ReceivePacket(ctx)
			cancel() // Important to call cancel to free resources associated with the context
			if err != nil {
				if !errors.Is(err, context.DeadlineExceeded) {
					log.Error().Err(err).
						Str("device", udq.RNIC.DeviceName).
						Uint32("qpn", udq.QPN).
						Str("gid", udq.RNIC.GID).
						Msg("[responder]: Error receiving packet")
					atomic.AddUint64(&errorPackets, 1)
				}
				continue
			}

			// Count packets
			atomic.AddUint64(&totalPackets, 1)

			if packet.IsAck != 0 {
				log.Warn().
					Str("device", udq.RNIC.DeviceName).
					Str("GID", udq.RNIC.GID).
					Uint32("QPN", udq.QPN).
					Uint32("flowLabel", workComp.FlowLabel).
					Uint64("seqNum", packet.SequenceNum).
					Msg("[responder]: Received ACK packet (this is invalid, ignoring)")
				continue
			}
			atomic.AddUint64(&probePackets, 1)

			// Get source information
			sourceGID := workComp.SGID
			sourceQPN := workComp.SrcQP

			// Validate source
			if sourceGID == "" || sourceGID == "::" || sourceQPN == 0 {
				atomic.AddUint64(&invalidPackets, 1)
				log.Error().
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Uint32("flowLabel", workComp.FlowLabel).
					Uint64("seqNum", packet.SequenceNum).
					Msg("[responder]: Invalid source GID or QPN in work completion, cannot send ACK")
				continue
			}

			log.Debug().
				Str("sending_device", udq.RNIC.DeviceName).
				Uint32("sendingQPN", udq.QPN).
				Str("sendingGID", udq.RNIC.GID).
				Str("targetGID", sourceGID).
				Uint32("targetQPN", sourceQPN).
				Uint32("flowLabel", workComp.FlowLabel).
				Uint64("seqNum", packet.SequenceNum).
				Msg("[responder]: Received probe packet, sending ACKs")

			// Step 2: Send first ACK packet immediately (without processing delay info)
			firstAckCompletionTime, err := udq.SendFirstAckPacket(sourceGID, sourceQPN, workComp.FlowLabel, packet, receiveTime)
			if err != nil {
				atomic.AddUint64(&errorPackets, 1)
				log.Error().Err(err).
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Str("targetGID", sourceGID).
					Uint32("targetQPN", sourceQPN).
					Uint32("flowLabel", workComp.FlowLabel).
					Uint64("seqNum", packet.SequenceNum).
					Msg("[responder]: Failed to send first ACK packet")
				continue
			}

			// Step 3: Send second ACK packet with processing delay information
			err = udq.SendSecondAckPacket(sourceGID, sourceQPN, workComp.FlowLabel, packet, receiveTime, firstAckCompletionTime)
			if err != nil {
				atomic.AddUint64(&errorPackets, 1)
				log.Error().Err(err).
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Str("targetGID", sourceGID).
					Uint32("targetQPN", sourceQPN).
					Uint32("flowLabel", workComp.FlowLabel).
					Uint64("seqNum", packet.SequenceNum).
					Msg("[responder]: Failed to send second ACK packet")
				continue
			}
		}
	}
}

// Close cleans up the prober resources
func (p *Prober) Close() error {
	p.Stop()
	close(p.probeResults)
	return nil
}

// HandleIncomingRDMAPacket is the callback function for rdma.AckHandlerFunc.
// It processes ACK packets received by the RDMA layer and dispatches them to the correct session.
func (p *Prober) HandleIncomingRDMAPacket(ackInfo *rdma.IncomingAckInfo) {
	if ackInfo == nil || ackInfo.Packet == nil {
		log.Error().Msg("[prober_handler]: Received nil ackInfo or ackInfo.Packet")
		return
	}

	// The user's latest change indicates FlowLabel from GRH is used as the session key.
	// Ensure GRHInfo is present and FlowLabel is valid.
	if ackInfo.GRHInfo == nil {
		log.Warn().Uint64("seqNum_from_packet", ackInfo.Packet.SequenceNum).Msg("[prober_handler]: ACK packet missing GRHInfo, cannot determine FlowLabel for session lookup.")
		return
	}
	sessionKey := ackInfo.GRHInfo.FlowLabel // Using FlowLabel as the key, per user's latest changes.

	log.Debug().
		Uint32("sessionKey_flowLabel", sessionKey).
		Uint64("packet_seqNum", ackInfo.Packet.SequenceNum).
		Uint8("packet_ackType", ackInfo.Packet.AckType).
		Str("source_gid_from_grh", ackInfo.GRHInfo.SourceGID).
		Uint32("source_qp_from_wc", ackInfo.SourceQP).
		Msg("[prober_handler]: Processing incoming ACK packet via callback")

	rawSession, exists := p.pendingSessions.Load(sessionKey)
	if exists {
		session, _ := rawSession.(*PingSession) // ignore ok because ok always becomes false
		// Construct probe.ackEvent from rdma.IncomingAckInfo
		// Note: ackInfo.Packet is a pointer into RDMA recv buffer. If Prober needs to hold onto it
		// beyond the scope of this handler call, it *must* be deep-copied.
		// For now, we assume PingSession channels consume it quickly or copy if needed.
		probeEvent := &ackEvent{
			Packet:     ackInfo.Packet, // This is a direct pointer, be cautious.
			ReceivedAt: ackInfo.ReceivedAt,
			WorkComp: &rdma.WorkCompletion{ // Populate with available info
				// Status:    uint32(ackInfo.RawWC.status), // Avoid direct access to C struct fields
				// Instead, rdma.IncomingAckInfo should provide a Go-friendly status, e.g., AckStatusOK bool
				Status:    0, // Placeholder, to be replaced by a status from IncomingAckInfo if needed beyond simple success
				SrcQP:     ackInfo.SourceQP,
				SGID:      ackInfo.GRHInfo.SourceGID,
				DGID:      ackInfo.GRHInfo.DestGID, // Assuming DestGID is populated in GRHInfo
				FlowLabel: ackInfo.GRHInfo.FlowLabel,
			},
		}

		// Check if the ACK itself was successful based on a field from IncomingAckInfo
		if !ackInfo.AckStatusOK { // Now use the AckStatusOK field from rdma.IncomingAckInfo
			log.Error().Uint32("sessionKey_flowLabel", sessionKey).Msg("[prober_handler]: Received ACK but RDMA completion status was not OK.")
			return
		}

		var targetChan chan *ackEvent
		var chanName string

		if ackInfo.Packet.AckType == 1 {
			targetChan = session.Ack1Chan
			chanName = "Ack1Chan"
		} else if ackInfo.Packet.AckType == 2 {
			targetChan = session.Ack2Chan
			chanName = "Ack2Chan"
		} else {
			log.Warn().Uint32("sessionKey_flowLabel", sessionKey).Uint8("ackType", ackInfo.Packet.AckType).Msg("[prober_handler]: Received ACK with unknown type")
			return
		}

		if targetChan == nil {
			log.Warn().
				Uint32("sessionKey_flowLabel", sessionKey).
				Str("chan", chanName).
				Msg("[prober_handler]: Session channel is nil. Session likely ended or cleaned up.")
			return
		}

		// Non-blocking send to the session channel
		select {
		case targetChan <- probeEvent:
			log.Debug().Uint32("sessionKey_flowLabel", sessionKey).Str("chan", chanName).Msg("[prober_handler]: Successfully sent ACK event to session channel")
		default:
			log.Warn().Uint32("sessionKey_flowLabel", sessionKey).Str("chan", chanName).Msg("[prober_handler]: Session channel blocked or closed (likely late ACK or session ended).")
		}
	} else {
		log.Warn().Uint32("sessionKey_flowLabel", sessionKey).Uint64("packet_seqNum", ackInfo.Packet.SequenceNum).Msg("[prober_handler]: Received ACK for non-existent or already cleaned-up session")
	}
}
