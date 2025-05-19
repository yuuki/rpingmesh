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
		udq := p.agentState.GetUDQueue(rnic.GID)
		if udq != nil {
			p.wg.Add(1)
			go p.responderLoop(udq)
		} else {
			log.Warn().Str("rnic_gid", rnic.GID).Str("rnic_device_name", rnic.DeviceName).Msg("UDQueue is nil for this RNIC in Prober.Start, responderLoop will not start")
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

	// Get the UDQueue for the source RNIC
	srcUdQueue := p.agentState.GetUDQueue(sourceRnic.GID)
	if srcUdQueue == nil {
		log.Error().Str("gid", sourceRnic.GID).Msg("Failed to get UDQueue for source RNIC in ProbeTarget")
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
				Msg("Timeout or error waiting for probe packet")
			result.Status = agent_analyzer.ProbeResult_TIMEOUT
			p.probeResults <- result
		} else {
			log.Error().Err(err).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Msg("Failed to send probe packet")
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
		Msg("Probe sent successfully, waiting for first ACK")

	// Step 4: Wait for the first ACK
	// Use parent context with timeout
	ackPacket1, t5Time, workComp, err := srcUdQueue.ReceivePacket(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			log.Debug().Err(err).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Msg("Timeout or error waiting for first ACK")
			result.Status = agent_analyzer.ProbeResult_TIMEOUT
			p.probeResults <- result
		} else {
			log.Error().Err(err).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Msg("Error waiting for first ACK")
			result.Status = agent_analyzer.ProbeResult_ERROR
			p.probeResults <- result
		}
		return
	}

	// Verify this is the first ACK we're waiting for
	if ackPacket1.IsAck != 1 || ackPacket1.AckType != 1 || ackPacket1.SequenceNum != seqNum {
		log.Warn().
			Uint64("expectedSeq", seqNum).
			Uint64("receivedSeq", ackPacket1.SequenceNum).
			Bool("isAck", ackPacket1.IsAck == 1).
			Uint8("ackType", ackPacket1.AckType).
			Str("srcGID", sourceRnic.GID).
			Uint32("srcQPN", srcUdQueue.QPN).
			Str("dstGID", targetGID).
			Uint32("dstQPN", targetQPN).
			Msg("Received invalid first ACK packet, ignoring")

		result.Status = agent_analyzer.ProbeResult_UNKNOWN
		p.probeResults <- result
		return
	}

	// Record T5 timestamp from first ACK
	result.T5 = timestamppb.New(t5Time)

	// Step 5: Wait for the second ACK with processing delay information
	ackPacket2, _, workComp2, err := srcUdQueue.ReceivePacket(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			log.Debug().Err(err).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Msg("Timeout or error waiting for second ACK")
			result.Status = agent_analyzer.ProbeResult_TIMEOUT
			p.probeResults <- result
		} else {
			log.Error().Err(err).
				Str("targetGID", targetGID).
				Uint32("targetQPN", targetQPN).
				Msg("Error waiting for second ACK")
			result.Status = agent_analyzer.ProbeResult_ERROR
			p.probeResults <- result
		}
		return
	}

	// Verify this is the second ACK we're waiting for
	if ackPacket2.IsAck != 1 || ackPacket2.AckType != 2 || ackPacket2.SequenceNum != seqNum {
		log.Debug().
			Uint64("expectedSeq", seqNum).
			Uint64("receivedSeq", ackPacket2.SequenceNum).
			Bool("isAck", ackPacket2.IsAck == 1).
			Uint8("ackType", ackPacket2.AckType).
			Msg("Received invalid second ACK packet, ignoring")

		result.Status = agent_analyzer.ProbeResult_TIMEOUT
		p.probeResults <- result
		return
	}

	// Additional debug info about the received work completion
	if workComp != nil {
		log.Debug().
			Str("recvSGID", workComp.SGID).
			Str("recvDGID", workComp.DGID).
			Uint32("recvSrcQP", workComp.SrcQP).
			Msg("Work completion details for first ACK")
	}

	if workComp2 != nil {
		log.Debug().
			Str("recvSGID", workComp2.SGID).
			Str("recvDGID", workComp2.DGID).
			Uint32("recvSrcQP", workComp2.SrcQP).
			Msg("Work completion details for second ACK")
	}

	// Get the timestamps from the second ACK which contains both T3 and T4
	t3Time := time.Unix(0, int64(ackPacket2.T3))
	t4Time := time.Unix(0, int64(ackPacket2.T4))
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
		Msg("Probe completed successfully")

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
		Msg("Starting responder loop to handle incoming probe packets on specific UDQueue")

	// Track statistics for debugging
	var (
		totalPackets   uint64
		probePackets   uint64
		ackPackets     uint64
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
				Uint64("ackPackets", ackPackets).
				Uint64("invalidPackets", invalidPackets).
				Uint64("errorPackets", errorPackets).
				Msg("Stopping responder loop")
			return

		case <-statsTicker.C:
			// Log stats periodically
			log.Info().
				Uint64("totalPackets", totalPackets).
				Uint64("probePackets", probePackets).
				Uint64("ackPackets", ackPackets).
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
						Msg("ResponderLoop: Error receiving packet")
					atomic.AddUint64(&errorPackets, 1)
				}
				continue
			}

			// Count packets
			atomic.AddUint64(&totalPackets, 1)

			log.Debug().
				Uint8("isAck", packet.IsAck).
				Uint64("seqNum", packet.SequenceNum).
				Str("sgid", workComp.SGID).
				Uint32("srcQP", workComp.SrcQP).
				Msg("Received RDMA packet")

			if packet.IsAck != 0 {
				// ACK packet processing
				atomic.AddUint64(&ackPackets, 1)
				log.Debug().
					Uint64("seqNum", packet.SequenceNum).
					Msg("Received ACK packet (not processing as responder)")
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
					Msg("Invalid source GID or QPN in work completion, cannot send ACK")
				continue
			}

			log.Debug().
				Str("sending_device", udq.RNIC.DeviceName).
				Uint32("sending_qpn", udq.QPN).
				Str("sending_gid", udq.RNIC.GID).
				Str("target_gid", sourceGID).
				Uint32("target_qpn", sourceQPN).
				Uint64("seqNum", packet.SequenceNum).
				Msg("ResponderLoop: Received probe packet, sending ACKs")

			// Step 2: Send first ACK packet immediately (without processing delay info)
			firstAckCompletionTime, err := udq.SendFirstAckPacket(sourceGID, sourceQPN, packet, receiveTime)
			if err != nil {
				atomic.AddUint64(&errorPackets, 1)
				log.Error().Err(err).
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Msg("Failed to send first ACK packet")
				continue
			}

			// Step 3: Send second ACK packet with processing delay information
			err = udq.SendSecondAckPacket(sourceGID, sourceQPN, packet, receiveTime, firstAckCompletionTime)
			if err != nil {
				atomic.AddUint64(&errorPackets, 1)
				log.Error().Err(err).
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Msg("Failed to send second ACK packet")
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
