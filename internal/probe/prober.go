package probe

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/rdma"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Prober is responsible for sending probes to targets and processing their responses
type Prober struct {
	rdmaManager  *rdma.RDMAManager
	udQueue      *rdma.UDQueue
	sequenceNum  uint64
	probeResults chan *agent_analyzer.ProbeResult
	timeout      time.Duration
	stopCh       chan struct{}
	wg           sync.WaitGroup
	running      bool
	mutex        sync.Mutex
}

// NewProber creates a new prober
func NewProber(rdmaManager *rdma.RDMAManager, udQueue *rdma.UDQueue, timeoutMs uint32) *Prober {
	return &Prober{
		rdmaManager:  rdmaManager,
		udQueue:      udQueue,
		sequenceNum:  0,
		probeResults: make(chan *agent_analyzer.ProbeResult, 1000),
		timeout:      time.Duration(timeoutMs) * time.Millisecond,
		stopCh:       make(chan struct{}),
		running:      false,
	}
}

// Start starts the prober
func (p *Prober) Start() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.running {
		return nil
	}

	p.running = true
	p.stopCh = make(chan struct{})

	// Start responder goroutine to handle incoming probes
	p.wg.Add(1)
	go p.responderLoop()

	log.Info().Msg("Prober started")
	return nil
}

// Stop stops the prober
func (p *Prober) Stop() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.running {
		return
	}

	close(p.stopCh)
	p.wg.Wait()
	p.running = false
	log.Info().Msg("Prober stopped")
}

// ProbeTarget sends a probe to a target and waits for a response
func (p *Prober) ProbeTarget(
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

	// Create result object
	result := &agent_analyzer.ProbeResult{
		SourceRnic: &agent_analyzer.RnicIdentifier{
			Gid:       sourceRnic.GID,
			Qpn:       p.udQueue.QPN,
			IpAddress: sourceRnic.IPAddr,
			HostName:  sourceRnic.DeviceName,
			TorId:     "", // This would need to be populated from config or controller
		},
		DestinationRnic: targetRnicInfo,
		FiveTuple: &agent_analyzer.ProbeFiveTuple{
			SrcGid:    sourceRnic.GID,
			SrcQpn:    p.udQueue.QPN,
			DstGid:    targetGID,
			DstQpn:    targetQPN,
			FlowLabel: flowLabel,
		},
		ProbeType: probeType,
	}

	// Record T1 timestamp (post send time)
	t1 := time.Now()
	result.T1 = timestamppb.New(t1)

	// Send probe packet
	t2Time, err := p.udQueue.SendProbePacket(targetGID, targetQPN, seqNum, sourcePort, flowLabel)
	if err != nil {
		log.Error().Err(err).
			Str("targetGID", targetGID).
			Uint32("targetQPN", targetQPN).
			Msg("Failed to send probe packet")

		result.Status = agent_analyzer.ProbeResult_ERROR
		p.probeResults <- result
		return
	}

	// Record T2 timestamp (prober CQE time)
	result.T2 = timestamppb.New(t2Time)

	// Wait for ACK with timeout
	ackPacket, t5Time, _, err := p.udQueue.ReceivePacket(p.timeout)
	if err != nil {
		log.Debug().Err(err).
			Str("targetGID", targetGID).
			Uint32("targetQPN", targetQPN).
			Msg("Timeout or error waiting for ACK")

		result.Status = agent_analyzer.ProbeResult_TIMEOUT
		p.probeResults <- result
		return
	}

	// Verify this is the ACK we're waiting for
	if ackPacket.IsAck != 1 || ackPacket.SequenceNum != seqNum {
		log.Debug().
			Uint64("expectedSeq", seqNum).
			Uint64("receivedSeq", ackPacket.SequenceNum).
			Bool("isAck", ackPacket.IsAck == 1).
			Msg("Received invalid ACK packet, ignoring")

		// Continue waiting for the correct ACK
		result.Status = agent_analyzer.ProbeResult_TIMEOUT
		p.probeResults <- result
		return
	}

	// Record T6 timestamp (poll complete time)
	t6 := time.Now()
	result.T6 = timestamppb.New(t6)

	// Record T5 timestamp (ACK receive time)
	result.T5 = timestamppb.New(t5Time)

	// Record T3 and T4 from ACK packet
	result.T3 = timestamppb.New(time.Unix(0, int64(ackPacket.T3)))
	result.T4 = timestamppb.New(time.Unix(0, int64(ackPacket.T4)))

	// Calculate metrics
	// Network RTT = (T5-T2)-(T4-T3)
	networkRTT := t5Time.Sub(t2Time) - time.Duration(ackPacket.T4-ackPacket.T3)
	result.NetworkRtt = networkRTT.Nanoseconds()

	// Prober delay = (T6-T1)-(T5-T2)
	proberDelay := t6.Sub(t1) - t5Time.Sub(t2Time)
	result.ProberDelay = proberDelay.Nanoseconds()

	// Responder delay = (T4-T3)
	responderDelay := time.Duration(ackPacket.T4 - ackPacket.T3)
	result.ResponderDelay = responderDelay.Nanoseconds()

	result.Status = agent_analyzer.ProbeResult_OK

	log.Debug().
		Str("targetGID", targetGID).
		Uint32("targetQPN", targetQPN).
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
func (p *Prober) responderLoop() {
	defer p.wg.Done()

	for {
		select {
		case <-p.stopCh:
			return
		default:
			// Poll for incoming packets with a short timeout
			packet, receiveTime, workComp, err := p.udQueue.ReceivePacket(10 * time.Millisecond)
			if err != nil {
				// This is expected on timeout, so don't log unless it's a real error
				if err.Error() != "receive timeout" {
					log.Error().Err(err).Msg("Error receiving packet")
				}
				continue
			}

			// Check if this is a probe packet (not an ACK)
			if packet.IsAck == 0 {
				// Get source GID and QPN from work completion
				// Now we get this information directly from the WorkCompletion
				sourceGID := workComp.SGID
				sourceQPN := workComp.SrcQP

				log.Debug().
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Uint64("seqNum", packet.SequenceNum).
					Msg("Received probe packet, sending ACK")

				// Send ACK packet back to the sender
				err = p.udQueue.SendAckPacket(sourceGID, sourceQPN, packet, receiveTime)
				if err != nil {
					log.Error().Err(err).
						Str("sourceGID", sourceGID).
						Uint32("sourceQPN", sourceQPN).
						Msg("Failed to send ACK packet")
				}
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
