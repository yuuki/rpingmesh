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
}

const (
	probeResultChanBufferSize = 1000
	responderStatsInterval    = 30 * time.Second
)

// NewProber creates a new prober
func NewProber(rdmaManager *rdma.RDMAManager, agentState *state.AgentState, timeoutMs uint32) *Prober {
	return &Prober{
		rdmaManager:  rdmaManager,
		agentState:   agentState,
		sequenceNum:  0,
		probeResults: make(chan *agent_analyzer.ProbeResult, probeResultChanBufferSize),
		timeout:      time.Duration(timeoutMs) * time.Millisecond,
		stopCh:       make(chan struct{}),
		running:      false,
	}
}

// Start starts the prober
func (p *Prober) Start() error {
	if p.running {
		return nil
	}

	p.running = true
	p.stopCh = make(chan struct{})

	// Log all detected RNICs by AgentState
	detectedRNICs := p.agentState.GetDetectedRNICs()
	log.Debug().Int("count", len(detectedRNICs)).Msg("RNICs detected by AgentState for Prober.Start")
	for _, rnic := range detectedRNICs {
		log.Debug().Str("rnic_gid", rnic.GID).Str("rnic_device_name", rnic.DeviceName).Msg("Processing RNIC in Prober.Start")
		// Get the RESPONDER UDQueue for handling incoming probes
		udq := p.agentState.GetResponderUDQueue(rnic.GID)
		if udq != nil {
			p.wg.Add(1)
			go p.responderLoop(udq)
		} else {
			log.Warn().Str("rnic_gid", rnic.GID).Str("rnic_device_name", rnic.DeviceName).Msg("Responder UDQueue is nil for this RNIC in Prober.Start, responderLoop will not start")
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
	ctx context.Context,
	sourceRnic *rdma.RNIC,
	targetGID string,
	targetQPN uint32,
	sourcePort uint32,
	flowLabel uint32,
	probeType string,
	targetRnicInfo *agent_analyzer.RnicIdentifier,
) {
	// Increment sequence number
	seqNum := atomic.AddUint64(&p.sequenceNum, 1)

	// Get the SENDER UDQueue for the source RNIC (for sending probes and receiving ACKs)
	srcUdQueue := p.agentState.GetSenderUDQueue(sourceRnic.GID)
	if srcUdQueue == nil {
		log.Error().
			Str("gid", sourceRnic.GID).
			Uint32("qpn", srcUdQueue.QPN).
			Uint64("seqNum", seqNum).
			Msg("Failed to get sender UDQueue for source RNIC in ProbeTarget")
		return
	}

	// Create result object
	result := &agent_analyzer.ProbeResult{
		SourceRnic: &agent_analyzer.RnicIdentifier{
			Gid:       sourceRnic.GID,
			Qpn:       srcUdQueue.QPN,
			IpAddress: sourceRnic.IPAddr,
			HostName:  sourceRnic.DeviceName,
			TorId:     "", // This would need to be populated from config or controller
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
	}

	log.Debug().
		Str("srcGID", sourceRnic.GID).
		Uint32("srcQPN", srcUdQueue.QPN).
		Str("dstGID", targetGID).
		Uint32("dstQPN", targetQPN).
		Uint32("flowLabel", flowLabel).
		Str("probeType", probeType).
		Uint64("seqNum", seqNum).
		Msg("Starting probe to target")

	// Record T1 timestamp (post send time)
	t1 := time.Now()
	result.T1 = timestamppb.New(t1)

	// Step 1: Send probe packet
	t2Time, err := srcUdQueue.SendProbePacket(ctx, targetGID, targetQPN, seqNum, sourcePort, flowLabel)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			log.Debug().Err(err).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Uint64("seqNum", seqNum).
				Msg("[prober]: Timeout or error waiting for probe packet")
			result.Status = agent_analyzer.ProbeResult_TIMEOUT
			p.probeResults <- result
		} else {
			log.Error().Err(err).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Uint64("seqNum", seqNum).
				Msg("[prober]: Failed to send probe packet")
			result.Status = agent_analyzer.ProbeResult_ERROR
		}
		return
	}

	// Record T2 timestamp (prober CQE time)
	result.T2 = timestamppb.New(t2Time)
	log.Debug().
		Str("targetGID", targetGID).
		Uint32("targetQPN", targetQPN).
		Time("t1", t1).
		Time("t2", t2Time).
		Uint64("seqNum", seqNum).
		Msg("[prober]: Probe sent successfully, waiting for ACKs")

	var (
		ack2Packet *rdma.ProbePacket
		t5Time     time.Time
	)
	ack1Received := false
	ack2Received := false
	result.Status = agent_analyzer.ProbeResult_UNKNOWN // Initialize status, will be updated

	// Loop to receive both ACKs. The overall timeout is handled by the input context 'ctx'.
	for !(ack1Received && ack2Received) {
		select {
		case <-ctx.Done():
			log.Debug().Err(ctx.Err()).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Bool("ack1Received", ack1Received).
				Bool("ack2Received", ack2Received).
				Uint64("seqNum", seqNum).
				Msg("[prober]: Context cancelled or timed out while waiting for ACKs")
			result.Status = agent_analyzer.ProbeResult_TIMEOUT
			p.probeResults <- result
			return
		default:
			// Non-blocking check for context, proceed to receive.
		}

		receivedPacket, receivedTime, workComp, err := srcUdQueue.ReceivePacket(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				log.Debug().Err(err).
					Str("targetGID", targetGID).
					Uint32("targetQPN", targetQPN).
					Bool("ack1Received", ack1Received).
					Bool("ack2Received", ack2Received).
					Uint64("seqNum", seqNum).
					Msg("[prober]: Timeout waiting for an ACK")
				result.Status = agent_analyzer.ProbeResult_TIMEOUT
			} else {
				log.Error().Err(err).
					Str("targetGID", targetGID).
					Uint32("targetQPN", targetQPN).
					Uint64("seqNum", seqNum).
					Msg("[prober]: Error waiting for an ACK")
				result.Status = agent_analyzer.ProbeResult_ERROR
			}
			p.probeResults <- result
			return
		}

		if receivedPacket.IsAck != 1 {
			log.Warn().
				Uint64("receivedSeq", receivedPacket.SequenceNum).
				Uint8("ackType", receivedPacket.AckType).
				Str("srcGID", sourceRnic.GID).
				Str("dstGID", targetGID).
				Str("receivedPacketSGID", workComp.SGID).
				Uint32("receivedPacketSrcQPN", workComp.SrcQP).
				Uint64("seqNum", seqNum).
				Msg("[prober]: Received a packet that is not an ACK, ignoring")
			continue
		}

		if receivedPacket.SequenceNum != seqNum {
			log.Warn().
				Uint64("expectedSeq", seqNum).
				Uint64("receivedSeq", receivedPacket.SequenceNum).
				Uint8("ackType", receivedPacket.AckType).
				Str("srcGID", sourceRnic.GID).
				Str("dstGID", targetGID).
				Str("receivedPacketSGID", workComp.SGID).
				Uint32("receivedPacketSrcQPN", workComp.SrcQP).
				Msg("[prober]: Received ACK with mismatched sequence number, ignoring")
			continue
		}

		switch receivedPacket.AckType {
		case 1:
			if !ack1Received {
				t5Time = receivedTime
				ack1Received = true
				log.Debug().
					Uint64("seqNum", seqNum).
					Str("targetGID", targetGID).
					Msg("[prober]: Received first ACK (type 1)")
			} else {
				log.Warn().
					Uint64("seqNum", seqNum).
					Str("targetGID", targetGID).
					Msg("[prober]: Received duplicate first ACK (type 1), ignoring")
			}
		case 2:
			if !ack2Received {
				ack2Packet = receivedPacket
				ack2Received = true
				log.Debug().
					Uint64("seqNum", seqNum).
					Str("targetGID", targetGID).
					Msg("[prober]: Received second ACK (type 2)")
			} else {
				log.Warn().
					Uint64("seqNum", seqNum).
					Str("targetGID", targetGID).
					Msg("[prober]: Received duplicate second ACK (type 2), ignoring")
			}
		default:
			log.Warn().
				Uint64("seqNum", seqNum).
				Uint8("ackType", receivedPacket.AckType).
				Str("targetGID", targetGID).
				Str("receivedPacketSGID", workComp.SGID).
				Uint32("receivedPacketSrcQPN", workComp.SrcQP).
				Msg("[prober]: Received ACK with unknown AckType, ignoring")
		}
	} // End of ACK receive loop

	// At this point, if we haven't returned, the loop exited because (ack1Received && ack2Received) is true.
	// Or, in a very unlikely scenario, the loop condition was met but ctx.Done() was simultaneously true.
	// The select case for ctx.Done() should handle timeout/cancellation primarily.

	// Double-check that both ACKs were actually processed and packets stored if logic depends on them beyond flags.
	if !ack1Received || !ack2Received {
		// This should not be reached if the loop and timeout logic is correct.
		// If it is, it implies a logic flaw or an unhandled exit from the loop.
		log.Error().
			Uint64("seqNum", seqNum).
			Str("targetGID", targetGID).
			Bool("ack1Received", ack1Received).
			Bool("ack2Received", ack2Received).
			Msg("[prober]: Logic error: exited ACK loop but not all ACKs received and no timeout/error reported.")
		result.Status = agent_analyzer.ProbeResult_ERROR // Indicate an internal logic error
		p.probeResults <- result
		return
	}

	result.T5 = timestamppb.New(t5Time) // t5Time is set when ackType=1 is received

	// ack2Packet should be non-nil if ack2Received is true
	t3Time := time.Unix(0, int64(ack2Packet.T3))
	t4Time := time.Unix(0, int64(ack2Packet.T4))
	result.T3 = timestamppb.New(t3Time)
	result.T4 = timestamppb.New(t4Time)

	// Record T6 timestamp
	t6 := time.Now()
	result.T6 = timestamppb.New(t6)

	// Network RTT = (T5-T2)-(T4-T3)
	networkRTT := t5Time.Sub(t2Time) - (t4Time.Sub(t3Time))
	result.NetworkRtt = networkRTT.Nanoseconds()

	// Prober delay = (T6-T1)-(T5-T2)
	proberDelay := t6.Sub(t1) - t5Time.Sub(t2Time)
	result.ProberDelay = proberDelay.Nanoseconds()

	// Responder delay = (T4-T3)
	responderDelay := t4Time.Sub(t3Time)
	result.ResponderDelay = responderDelay.Nanoseconds()

	result.Status = agent_analyzer.ProbeResult_OK

	log.Debug().
		Str("targetGID", targetGID).
		Uint32("targetQPN", targetQPN).
		Time("t1", t1).
		Time("t2", t2Time).
		Time("t3", t3Time).
		Time("t4", t4Time).
		Time("t5", t5Time).
		Time("t6", t6).
		Int64("networkRTT_ns", result.NetworkRtt).
		Int64("proberDelay_ns", result.ProberDelay).
		Int64("responderDelay_ns", result.ResponderDelay).
		Uint64("seqNum", seqNum).
		Msg("[prober]: Probe completed successfully with unordered ACKs")

	// Send result to channel for upload
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
			log.Info().
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
					Str("gid", udq.RNIC.GID).
					Uint32("qpn", udq.QPN).
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
					Uint64("seqNum", packet.SequenceNum).
					Msg("[responder]: Invalid source GID or QPN in work completion, cannot send ACK")
				continue
			}

			log.Debug().
				Str("sending_device", udq.RNIC.DeviceName).
				Uint32("sending_qpn", udq.QPN).
				Str("sending_gid", udq.RNIC.GID).
				Str("target_gid", sourceGID).
				Uint32("target_qpn", sourceQPN).
				Uint64("seqNum", packet.SequenceNum).
				Msg("[responder]: Received probe packet, sending ACKs")

			// Step 2: Send first ACK packet immediately (without processing delay info)
			firstAckCompletionTime, err := udq.SendFirstAckPacket(sourceGID, sourceQPN, packet, receiveTime)
			if err != nil {
				atomic.AddUint64(&errorPackets, 1)
				log.Error().Err(err).
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Msg("[responder]: Failed to send first ACK packet")
				continue
			}

			// Step 3: Send second ACK packet with processing delay information
			err = udq.SendSecondAckPacket(sourceGID, sourceQPN, packet, receiveTime, firstAckCompletionTime)
			if err != nil {
				atomic.AddUint64(&errorPackets, 1)
				log.Error().Err(err).
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
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
