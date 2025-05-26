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

// ProbeTypeServiceTracing is a constant for service tracing probe type
// const ProbeTypeServiceTracing = "SERVICE_TRACING" // Moved to types.go

// ServiceFlowTuple holds the specific 5-tuple for a service flow.
// type ServiceFlowTuple struct { // Moved to types.go
// 	SrcGID    string
// 	SrcQPN    uint32
// 	DstGID    string // Destination GID of the flow
// 	DstQPN    uint32 // Destination QPN of the flow
// 	FlowLabel uint32 // Actual flow label of the service, if available (otherwise 0)
// }

// PingSession holds the state for a single probe transaction.
type PingSession struct {
	SequenceNum   uint64
	SourceRnicGid string
	TargetGid     string
	ProbeType     string // Added ProbeType to PingSession

	Ack1Chan chan *ackEvent // Receives the first ACK (type 1)
	Ack2Chan chan *ackEvent // Receives the second ACK (type 2)

	CreationTime time.Time
}

// ackEvent is a wrapper for ACK data received.
type ackEvent struct {
	Packet     *rdma.ProbePacket
	ReceivedAt time.Time
	WorkComp   *rdma.ProcessedWorkCompletion
}

// Prober is responsible for sending probe packets and collecting results.
type Prober struct {
	rdmaManager   *rdma.RDMAManager
	agentState    *state.AgentState
	probeResults  chan *agent_analyzer.ProbeResult
	stopCh        chan struct{}
	wg            sync.WaitGroup
	timeout       time.Duration
	sessions      map[uint64]*PingSession // Key: Sequence Number
	sessionsMutex sync.RWMutex
	nextSeqNum    uint64
	metricMutex   sync.Mutex // To protect metrics if any are directly managed here

	// For Service Flow Tracing
	// Using PingTarget from the same package now
	serviceFlowTargets      []*PingTarget // Changed from monitor.PingTarget
	serviceFlowTargetsMutex sync.RWMutex
}

const (
	probeResultChanBufferSize = 1000
	responderStatsInterval    = 30 * time.Second
)

// NewProber creates a new Prober.
func NewProber(manager *rdma.RDMAManager, agentState *state.AgentState, timeoutMs uint32) *Prober {
	return &Prober{
		rdmaManager:        manager,
		agentState:         agentState,
		probeResults:       make(chan *agent_analyzer.ProbeResult, probeResultChanBufferSize),
		stopCh:             make(chan struct{}),
		timeout:            time.Duration(timeoutMs) * time.Millisecond,
		sessions:           make(map[uint64]*PingSession),
		nextSeqNum:         0,
		serviceFlowTargets: make([]*PingTarget, 0), // Changed from monitor.PingTarget
	}
}

// UpdateServiceFlowTargets is called by ServiceFlowMonitor to update the list of service flow targets.
// It is expected that PingTarget will have its ProbeType and ServiceFlowTuple fields populated.
func (p *Prober) UpdateServiceFlowTargets(targets []*PingTarget) { // Changed from monitor.PingTarget
	p.serviceFlowTargetsMutex.Lock()
	defer p.serviceFlowTargetsMutex.Unlock()
	p.serviceFlowTargets = targets
	log.Debug().Int("count", len(targets)).Msg("Prober: service flow targets updated.")

	// This function updates the list. The actual probing of these targets
	// will be initiated by ServiceFlowMonitor calling Prober.ProbeTarget with these targets.
}

// Start initializes the prober and starts its background processing.
func (p *Prober) Start() error {
	// Start responder loops for all detected RNICs
	detectedRnics := p.agentState.GetDetectedRNICs()
	for _, rnic := range detectedRnics {
		if rnic == nil {
			continue
		}

		// Get responder UD queue for this RNIC
		responderQueue := p.agentState.GetResponderUDQueue(rnic.GID)
		if responderQueue == nil {
			log.Warn().Str("rnic_gid", rnic.GID).Msg("No responder UD queue available for RNIC")
			continue
		}

		// Start responder loop for this queue
		p.wg.Add(1)
		go p.responderLoop(responderQueue)
		log.Debug().Str("rnic_gid", rnic.GID).Uint32("qpn", responderQueue.QPN).Msg("Started responder loop for RNIC")
	}

	// Start service probing loop
	p.wg.Add(1)
	go p.runServiceProbingLoop()

	log.Info().Msg("Prober started with responder loops and service probing loop.")
	return nil
}

// Close stops the prober and cleans up resources.
func (p *Prober) Close() error {
	log.Info().Msg("Closing prober...")
	close(p.stopCh) // Signal all internal goroutines to stop
	p.wg.Wait()     // Wait for all goroutines (like runServiceProbingLoop) to finish

	p.sessionsMutex.Lock()
	// Close any active session channels
	for _, session := range p.sessions {
		if session.Ack1Chan != nil {
			close(session.Ack1Chan)
		}
		if session.Ack2Chan != nil {
			close(session.Ack2Chan)
		}
	}
	p.sessions = make(map[uint64]*PingSession) // Clear sessions map
	p.sessionsMutex.Unlock()

	close(p.probeResults)
	log.Info().Msg("Prober closed.")
	return nil
}

func (p *Prober) runServiceProbingLoop() {
	defer p.wg.Done()

	// Use a configurable interval for service probes. For now, using agent's global ProbeIntervalMS.
	// probeInterval := time.Duration(p.agentState.GetProbeIntervalMS()) * time.Millisecond
	// TODO: Make probe interval configurable, e.g., through agentState or Prober config
	probeInterval := time.Second // Default to 1 second
	// if probeInterval <= 0 {
	// 	probeInterval = time.Second // Default to 1 second if not configured or zero
	// }
	log.Warn().Msgf("Service probe interval is using a default of %s. Consider making it configurable.", probeInterval)

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	log.Info().Dur("interval", probeInterval).Msg("Prober: Service flow probing loop started.")

	for {
		select {
		case <-p.stopCh:
			log.Info().Msg("Prober: Service flow probing loop stopping.")
			return
		case <-ticker.C:
			p.serviceFlowTargetsMutex.RLock()
			// Create a copy of the slice to avoid holding the lock during probes
			targetsToProbe := make([]*PingTarget, len(p.serviceFlowTargets))
			copy(targetsToProbe, p.serviceFlowTargets)
			p.serviceFlowTargetsMutex.RUnlock()

			if len(targetsToProbe) == 0 {
				log.Trace().Msg("Prober: No service flow targets to probe in this cycle.")
				continue
			}

			log.Debug().Int("count", len(targetsToProbe)).Msg("Prober: Probing current service flow targets.")
			for _, target := range targetsToProbe {
				if target == nil || target.ServiceFlowTuple == nil {
					log.Warn().Msg("Prober: Nil target or nil ServiceFlowTuple in serviceFlowTargets list, skipping.")
					continue
				}

				sourceRnic := p.getRnicByGid(target.ServiceFlowTuple.SrcGID)
				if sourceRnic == nil {
					log.Warn().Str("flow_src_gid", target.ServiceFlowTuple.SrcGID).Msg("Prober: Could not find local RNIC for service flow source GID, skipping probe.")
					continue
				}

				// Ensure ProbeType is correctly set for service tracing (it should be by SFM)
				if target.ProbeType != ProbeTypeServiceTracing {
					log.Warn().Str("target_dst_gid", target.GID).Str("expected_type", ProbeTypeServiceTracing).Str("actual_type", target.ProbeType).Msg("Prober: Target in serviceFlowTargets list has incorrect ProbeType, correcting.")
					target.ProbeType = ProbeTypeServiceTracing
				}

				probeCtx, cancelProbe := context.WithTimeout(context.Background(), p.timeout)

				// Launch as goroutine to prevent one slow probe from blocking the entire loop.
				// The ProbeTarget method itself is blocking.
				go func(ctx context.Context, srcRnic *rdma.RNIC, tgt *PingTarget) { // Changed from monitor.PingTarget
					defer cancelProbe() // Ensure context is cancelled when goroutine finishes
					p.ProbeTarget(ctx, srcRnic, tgt)
				}(probeCtx, sourceRnic, target)

				// cancelProbe() here would be too early for the goroutine.
				// The context `probeCtx` will be cancelled by its own timeout if ProbeTarget exceeds it.
				// Or, if `p.stopCh` is closed, ProbeTarget should ideally respect `probeCtx.Done()` if it has long waits.
				// We need to ensure that cancelProbe is called eventually, e.g. after the goroutine finishes or ProbeTarget returns.
				// A common pattern is `defer cancelProbe()` if the function call is blocking and synchronous.
				// With a goroutine, the goroutine itself should ideally call cancel if it finishes early, or the timeout will handle it.
				// For now, the timeout on probeCtx is the main mechanism for context cleanup for the goroutine.
			}
		}
	}
}

// ProbeTarget sends a single probe to a target RNIC.
func (p *Prober) ProbeTarget(
	ctx context.Context,
	sourceRnic *rdma.RNIC, // Local RNIC used for sending the probe
	target *PingTarget, // Target details, including potential ServiceFlowTuple
) {
	if sourceRnic == nil {
		log.Error().Msg("ProbeTarget called with nil sourceRnic")
		return
	}
	if target == nil {
		log.Error().Msg("ProbeTarget called with nil target")
		return
	}

	seqNum := atomic.AddUint64(&p.nextSeqNum, 1)
	session := &PingSession{
		SequenceNum:   seqNum,
		SourceRnicGid: sourceRnic.GID,
		TargetGid:     target.GID,
		ProbeType:     target.ProbeType,
		Ack1Chan:      make(chan *ackEvent, 1),
		Ack2Chan:      make(chan *ackEvent, 1),
		CreationTime:  time.Now(),
	}
	p.addSession(session)
	defer p.removeSession(seqNum)

	var actualSrcGid, actualDstGid string
	var actualSrcQpn, actualDstQpn, actualFlowLabel uint32
	var srcPortForPacket uint32

	// Default to values from PingTarget for cluster monitoring
	actualSrcGid = sourceRnic.GID
	srcUdQueue := p.agentState.GetSenderUDQueue(actualSrcGid)
	if srcUdQueue == nil {
		log.Error().Str("srcGID", actualSrcGid).Msg("No sender UDQueue available for source RNIC")
		// Populate and send error result via probeResults
		result := &agent_analyzer.ProbeResult{
			SourceRnic: &agent_analyzer.RnicIdentifier{
				Gid:       actualSrcGid,
				IpAddress: sourceRnic.IPAddr,
				HostName:  p.agentState.GetHostName(),
			},
			DestinationRnic: &agent_analyzer.RnicIdentifier{
				Gid:       target.GID,
				Qpn:       target.QPN,
				IpAddress: target.IPAddress,
				HostName:  target.HostName,
				TorId:     target.TorID,
			},
			FiveTuple: &agent_analyzer.ProbeFiveTuple{
				SrcGid:    actualSrcGid,
				DstGid:    target.GID,
				DstQpn:    target.QPN,
				FlowLabel: target.FlowLabel,
			},
			ProbeType: target.ProbeType,
			Status:    agent_analyzer.ProbeResult_ERROR,
		}
		p.probeResults <- result
		return
	}
	actualSrcQpn = srcUdQueue.QPN
	actualDstGid = target.GID
	actualDstQpn = target.QPN
	actualFlowLabel = target.FlowLabel
	srcPortForPacket = target.SourcePort

	// If it's a service tracing probe, override with ServiceFlowTuple specifics
	if target.ProbeType == ProbeTypeServiceTracing && target.ServiceFlowTuple != nil {
		flow := target.ServiceFlowTuple
		actualSrcGid = flow.SrcGID       // Use the service flow's actual source GID
		actualSrcQpn = flow.SrcQPN       // CRITICAL: Use the service flow's actual source QPN
		actualDstGid = flow.DstGID       // Use the service flow's actual destination GID
		actualDstQpn = flow.DstQPN       // Use the service flow's actual destination QPN
		actualFlowLabel = flow.FlowLabel // Use the service flow's actual flow label (or 0 if not known)
		// srcPortForPacket for service flow might be different, or use a default.
		// For now, we can keep it as target.SourcePort or define a specific one for service tracing.
		// Assuming target.SourcePort is suitable or will be set appropriately by ServiceFlowMonitor.

		// IMPORTANT: Sending from a specific QPN (actualSrcQpn from ServiceFlowTuple)
		// requires the RDMA layer to support it. The current `agentState.GetSenderUDQueue(actualSrcGid)`
		// gets a generic UD queue for that GID. This will NOT be the service's actual QPN.
		// This is a known limitation in this iteration.
		log.Warn().Str("probeType", target.ProbeType).
			Str("serviceSrcGid", actualSrcGid).Uint32("serviceSrcQpn", actualSrcQpn).
			Msg("Service Tracing: Attempting to use service flow QPNs. Ensure RDMA layer supports sending from specified SrcQPN.")

		// Re-evaluate srcUdQueue if actualSrcGid for the service flow might be on a different local RNIC
		// than the `sourceRnic` initially passed (though they should match if logic is correct).
		// And more importantly, the QPN needs to be the service's one.
		// This part remains a placeholder for future RDMA layer enhancements.
		tmpSrcUdQueue := p.agentState.GetSenderUDQueue(actualSrcGid) // Still gets generic queue
		if tmpSrcUdQueue == nil {
			log.Error().Str("srcGID", actualSrcGid).Msg("No sender UDQueue for service flow's source GID")
			// Populate and send error result via probeResults
			result := &agent_analyzer.ProbeResult{
				SourceRnic: &agent_analyzer.RnicIdentifier{
					Gid:       actualSrcGid,
					IpAddress: p.getRnicByGid(actualSrcGid).IPAddr,
					HostName:  p.agentState.GetHostName(),
				},
				DestinationRnic: &agent_analyzer.RnicIdentifier{
					Gid:       target.GID,
					Qpn:       target.QPN,
					IpAddress: target.IPAddress,
					HostName:  target.HostName,
					TorId:     target.TorID,
				},
				FiveTuple: &agent_analyzer.ProbeFiveTuple{
					SrcGid:    actualSrcGid,
					SrcQpn:    flow.SrcQPN,
					DstGid:    actualDstGid,
					DstQpn:    actualDstQpn,
					FlowLabel: actualFlowLabel,
				},
				ProbeType: target.ProbeType,
				Status:    agent_analyzer.ProbeResult_ERROR,
			}
			p.probeResults <- result
			return
		}
		// WARNING: Overriding actualSrcQpn to the generic UD QPN due to current limitations.
		// This means the probe will not originate from the service's true QPN.
		log.Warn().Uint32("serviceActualSrcQpn", actualSrcQpn).Uint32("usingGenericUdQpn", tmpSrcUdQueue.QPN).Msg("Service Tracing: Overriding service SrcQPN with generic UD QPN due to RDMA layer limitation.")
		actualSrcQpn = tmpSrcUdQueue.QPN
		srcUdQueue = tmpSrcUdQueue // Use this UD queue for sending.
	}

	// Get RNIC info for result construction with proper error handling
	sourceRnicInfo := p.getRnicByGid(actualSrcGid)
	if sourceRnicInfo == nil {
		log.Error().Str("actualSrcGid", actualSrcGid).Msg("Could not find source RNIC info for result construction")
		// Use basic info from sourceRnic parameter
		sourceRnicInfo = sourceRnic
	}

	result := &agent_analyzer.ProbeResult{
		SourceRnic: &agent_analyzer.RnicIdentifier{
			Gid:       actualSrcGid,
			Qpn:       actualSrcQpn,
			IpAddress: sourceRnicInfo.IPAddr,
			HostName:  p.agentState.GetHostName(),
		},
		DestinationRnic: &agent_analyzer.RnicIdentifier{
			Gid:       target.GID,
			Qpn:       target.QPN,
			IpAddress: target.IPAddress,
			HostName:  target.HostName,
			TorId:     target.TorID,
		},
		FiveTuple: &agent_analyzer.ProbeFiveTuple{
			SrcGid:    actualSrcGid,
			SrcQpn:    actualSrcQpn,
			DstGid:    actualDstGid,
			DstQpn:    actualDstQpn,
			FlowLabel: actualFlowLabel,
		},
		ProbeType: target.ProbeType,
		Status:    agent_analyzer.ProbeResult_UNKNOWN,
	}

	log.Debug().
		Str("probeType", target.ProbeType).
		Str("actualSrcGID", actualSrcGid).Uint32("actualSrcQPN", actualSrcQpn).
		Str("actualDstGID", actualDstGid).Uint32("actualDstQPN", actualDstQpn).
		Uint32("actualFlowLabel", actualFlowLabel).
		Uint64("seqNum", seqNum).
		Msg("[prober]: Starting probe to target")

	sendCtx, sendCancel := context.WithTimeout(ctx, p.timeout)
	defer sendCancel()

	t1, t2, err := srcUdQueue.SendProbePacket(sendCtx, actualDstGid, actualDstQpn, seqNum, srcPortForPacket, actualFlowLabel)
	if err != nil {
		log.Error().Err(err).
			Str("actualSrcGID", actualSrcGid).Uint32("actualSrcQPN", actualSrcQpn).
			Str("actualDstGID", actualDstGid).Uint32("actualDstQPN", actualDstQpn).
			Uint32("actualFlowLabel", actualFlowLabel).
			Uint64("seqNum", seqNum).
			Msg("Failed to send probe packet")
		result.Status = agent_analyzer.ProbeResult_ERROR
		p.probeResults <- result
		return
	}
	result.T1 = timestamppb.New(t1)
	result.T2 = timestamppb.New(t2)

	log.Trace().
		Str("actualSrcGID", actualSrcGid).Uint32("actualSrcQPN", actualSrcQpn).
		Str("actualDstGID", actualDstGid).Uint32("actualDstQPN", actualDstQpn).
		Uint32("actualFlowLabel", actualFlowLabel).
		Uint64("seqNum", seqNum).
		Time("t1", t1).Time("t2", t2).
		Msg("[prober]: Probe packet sent successfully, waiting for ACKs")

	// Wait for ACK in session
	select {
	case ack1Event, ok := <-session.Ack1Chan:
		if !ok {
			log.Warn().Uint64("seqNum", seqNum).
				Str("actualDstGID", actualDstGid).
				Msg("[prober]: Session Ack1Chan channel closed prematurely")
			result.Status = agent_analyzer.ProbeResult_ERROR
			p.probeResults <- result
			return
		}

		log.Trace().Uint64("seqNum", seqNum).
			Str("actualDstGID", actualDstGid).
			Msg("[prober]: Received first ACK, waiting for second ACK")

		// Now wait for the second ACK
		select {
		case ack2Event, ok := <-session.Ack2Chan: // Listen on Ack2Chan
			if !ok {
				log.Warn().Uint64("seqNum", seqNum).
					Str("actualDstGID", actualDstGid).
					Msg("[prober]: Session Ack2Chan channel closed prematurely")
				result.Status = agent_analyzer.ProbeResult_ERROR
				p.probeResults <- result
				return
			}
			// Both ACKs received
			result.Status = agent_analyzer.ProbeResult_OK
			log.Trace().Uint64("seqNum", seqNum).
				Str("actualDstGID", actualDstGid).
				Msg("[prober]: Received both ACKs, processing timestamps and delays")

			// T1 and T2 are set before sending.
			// T3 and T4 are from the first ACK (responder's perspective on original probe)
			// ack1Event.Packet should contain T3 and T4 as set by the responder.
			if ack1Event.Packet != nil {
				result.T3 = timestamppb.New(time.Unix(0, int64(ack1Event.Packet.T3)))
				result.T4 = timestamppb.New(time.Unix(0, int64(ack1Event.Packet.T4)))
			} else {
				log.Warn().Uint64("seqNum", seqNum).
					Str("actualDstGID", actualDstGid).
					Msg("[prober]: ack1Event.Packet is nil, cannot set T3/T4")
				// Potentially set status to error or handle missing T3/T4 in calculations
			}

			// T5 is when the prober received the *second* ACK.
			// T6 is when the prober finished processing the *second* ACK (poll complete).
			result.T5 = timestamppb.New(ack2Event.ReceivedAt) // When second ACK was physically received
			result.T6 = timestamppb.New(ack2Event.ReceivedAt) // Placeholder: prober poll complete for second ACK.

			// Calculate delays (ensure Packet fields are correct)
			// These calculations need to be revisited based on the two-ACK model.
			// For now, using fields from ack2Event.Packet for responder delay and ack1Event.Packet potentially for others.
			// This part is highly dependent on what timestamps are carried in each ACK.

			// For now, let's assume ack2Event.Packet contains the final calculated delays from responder
			// This is a simplification. The actual calculation is more complex with two ACKs.
			if ack2Event.Packet != nil {
				// Let's assume for now that T3, T4 are from the first ACK's payload
				// and the RDMA layer calculates/passes these.
				// The current ackEvent.Packet might not have direct NetworkRttNS etc.
				// These are calculated based on T1-T6.

				// Re-calculate based on T1-T6
				if result.T2 != nil && result.T3 != nil && result.T4 != nil && result.T5 != nil {
					t2Time := result.T2.AsTime()
					t3Time := result.T3.AsTime()
					t4Time := result.T4.AsTime()
					t5Time := result.T5.AsTime()

					responderDelay := t4Time.Sub(t3Time).Nanoseconds()
					result.ResponderDelay = responderDelay
					result.NetworkRtt = (t5Time.Sub(t2Time).Nanoseconds()) - responderDelay
				} else {
					log.Warn().Uint64("seqNum", seqNum).
						Bool("t2_valid", result.T2 != nil).
						Bool("t3_valid", result.T3 != nil).
						Bool("t4_valid", result.T4 != nil).
						Bool("t5_valid", result.T5 != nil).
						Msg("[prober]: Cannot calculate responder delay and network RTT due to missing timestamps")
				}

				if result.T1 != nil && result.T6 != nil && result.T2 != nil && result.T5 != nil {
					// Prober delay: (T6-T1) - (T5-T2)
					// (T6-T1) is total time at prober for the transaction.
					// (T5-T2) is network RTT + responder processing for the *probe* packet's lifecycle.
					// This definition of ProberDelay = (T6-T1) - (T5-T2) needs to be re-checked with the paper's definition.
					// (T6-T1) - ((T5-T2) - (T4-T3)) - (T4-T3)
					// If T6 is poll complete of second ACK, T1 is post send of probe.
					// If T5 is receive of second ACK, T2 is CQE of probe send.
					// The current ProbeResult proto has: ProberDelay = (T6-T1)-(T5-T2)
					t1Time := result.T1.AsTime()
					t6Time := result.T6.AsTime()
					t2Time := result.T2.AsTime()
					t5Time := result.T5.AsTime()
					if result.T6.IsValid() && result.T1.IsValid() && result.T5.IsValid() && result.T2.IsValid() {
						result.ProberDelay = (t6Time.Sub(t1Time).Nanoseconds()) - (t5Time.Sub(t2Time).Nanoseconds())
						log.Trace().Uint64("seqNum", seqNum).
							Int64("proberDelay_ns", result.ProberDelay).
							Msg("[prober]: Calculated prober delay")
					} else {
						log.Warn().Uint64("seqNum", seqNum).
							Bool("t1_valid", result.T1 != nil && result.T1.IsValid()).
							Bool("t6_valid", result.T6 != nil && result.T6.IsValid()).
							Bool("t2_valid", result.T2 != nil && result.T2.IsValid()).
							Bool("t5_valid", result.T5 != nil && result.T5.IsValid()).
							Msg("[prober]: Cannot calculate prober delay due to invalid timestamps")
					}
				}
			} else {
				log.Warn().Uint64("seqNum", seqNum).
					Str("actualDstGID", actualDstGid).
					Msg("[prober]: ack2Event.Packet is nil, cannot calculate delays accurately.")
			}

			log.Debug().Uint64("seqNum", seqNum).
				Str("actualDstGID", actualDstGid).
				Int64("networkRtt_ns", result.NetworkRtt).
				Int64("responderDelay_ns", result.ResponderDelay).
				Int64("proberDelay_ns", result.ProberDelay).
				Int64("t1_ns", result.T1.AsTime().UnixNano()).
				Int64("t2_ns", result.T2.AsTime().UnixNano()).
				Int64("t3_ns", result.T3.AsTime().UnixNano()).
				Int64("t4_ns", result.T4.AsTime().UnixNano()).
				Int64("t5_ns", result.T5.AsTime().UnixNano()).
				Int64("t6_ns", result.T6.AsTime().UnixNano()).
				Msg("[prober]: Probe completed successfully with both ACKs")

		case <-ctx.Done(): // Timeout waiting for the second ACK
			log.Warn().Uint64("seqNum", seqNum).
				Str("targetGID", actualDstGid).
				Str("probeType", target.ProbeType).
				Msg("[prober]: Probe timed out waiting for second ACK")
			result.Status = agent_analyzer.ProbeResult_TIMEOUT
			// If first ACK was received, we might have partial data, but status is still TIMEOUT overall.
		}

	case <-ctx.Done(): // Timeout waiting for the first ACK
		log.Warn().Uint64("seqNum", seqNum).
			Str("targetGID", actualDstGid).
			Str("probeType", target.ProbeType).
			Msg("[prober]: Probe timed out waiting for first ACK")
		result.Status = agent_analyzer.ProbeResult_TIMEOUT
	}

	log.Trace().Uint64("seqNum", seqNum).
		Str("actualDstGID", actualDstGid).
		Str("status", result.Status.String()).
		Msg("Sending probe result to results channel")

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
			packet, receiveTime, processedWC, err := udq.ReceivePacket(ctx)
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

			// Ensure processedWC is not nil before accessing its fields, especially if ReceivePacket can return nil for it on some errors
			if processedWC == nil {
				log.Error().
					Str("device", udq.RNIC.DeviceName).
					Uint32("qpn", udq.QPN).
					Msg("[responder]: Received nil processedWorkCompletion from ReceivePacket, skipping packet")
				atomic.AddUint64(&errorPackets, 1)
				continue
			}

			// Count packets
			atomic.AddUint64(&totalPackets, 1)

			if packet.IsAck != 0 { // packet can be nil if deserialize failed but processedWC might still be returned
				log.Warn().
					Str("device", udq.RNIC.DeviceName).
					Str("GID", udq.RNIC.GID).
					Uint32("QPN", udq.QPN).
					Uint32("flowLabel", processedWC.FlowLabel). // Use FlowLabel from ProcessedWorkCompletion
					Msg("[responder]: Received ACK packet (this is invalid, ignoring)")
				continue
			}
			atomic.AddUint64(&probePackets, 1)

			// Get source information
			sourceGID := processedWC.SGID
			sourceQPN := processedWC.SrcQP // SrcQP is from the embedded GoWorkCompletion

			// Validate source
			if sourceGID == "" || sourceGID == "::" || sourceQPN == 0 {
				atomic.AddUint64(&invalidPackets, 1)
				log.Error().
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Uint32("flowLabel", processedWC.FlowLabel).
					Msg("[responder]: Invalid source GID or QPN in work completion, cannot send ACK")
				continue
			}

			log.Trace().
				Str("sending_device", udq.RNIC.DeviceName).
				Uint32("sendingQPN", udq.QPN).
				Str("sendingGID", udq.RNIC.GID).
				Str("targetGID", sourceGID).
				Uint32("targetQPN", sourceQPN).
				Uint32("flowLabel", processedWC.FlowLabel).
				Msg("[responder]: Received probe packet, sending ACKs")

			// Step 2: Send first ACK packet immediately (without processing delay info)
			firstAckCompletionTime, err := udq.SendFirstAckPacket(sourceGID, sourceQPN, processedWC.FlowLabel, packet, receiveTime)
			if err != nil {
				atomic.AddUint64(&errorPackets, 1)
				log.Error().Err(err).
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Str("targetGID", sourceGID).    // This should be sending_device for logging consistency? No, target is the original prober.
					Uint32("targetQPN", sourceQPN). // Same as above.
					Uint32("flowLabel", processedWC.FlowLabel).
					Msg("[responder]: Failed to send first ACK packet")
				continue
			}

			log.Trace().
				Str("sourceGID", sourceGID).
				Uint32("sourceQPN", sourceQPN).
				Uint32("flowLabel", processedWC.FlowLabel).
				Msg("[responder]: Sent first ACK packet")

			// Step 3: Send second ACK packet with processing delay information
			err = udq.SendSecondAckPacket(sourceGID, sourceQPN, processedWC.FlowLabel, packet, receiveTime, firstAckCompletionTime)
			if err != nil {
				atomic.AddUint64(&errorPackets, 1)
				log.Error().Err(err).
					Str("sourceGID", sourceGID).
					Uint32("sourceQPN", sourceQPN).
					Str("targetGID", sourceGID).
					Uint32("targetQPN", sourceQPN).
					Uint32("flowLabel", processedWC.FlowLabel).
					Msg("[responder]: Failed to send second ACK packet")
				continue
			}

			log.Trace().
				Str("sourceGID", sourceGID).
				Uint32("sourceQPN", sourceQPN).
				Uint32("flowLabel", processedWC.FlowLabel).
				Msg("[responder]: Sent second ACK packet")
		}
	}
}

// HandleIncomingRDMAPacket is the callback function for rdma.AckHandlerFunc.
// It processes ACK packets received by the RDMA layer and dispatches them to the correct session.
func (p *Prober) HandleIncomingRDMAPacket(ackInfo *rdma.IncomingAckInfo) {
	if ackInfo == nil || ackInfo.Packet == nil || ackInfo.ProcessedWC == nil {
		log.Error().Msg("[prober_handler]: Received nil ackInfo, ackInfo.Packet, or ackInfo.ProcessedWC")
		return
	}

	// sessionKey is now sequence number, which should be in Packet.SequenceNum
	// The FlowLabel from GRH was previously used, but that can collide.
	// The PingSession map key is uint64 (seqNum).
	// We need to get the session using SequenceNum from the packet.
	sessionKey := ackInfo.Packet.SequenceNum // Use SequenceNum from packet as the session key

	log.Trace().
		Uint64("sessionKey_seqNum", sessionKey). // Changed from flowLabel to seqNum
		Uint64("packet_seqNum", ackInfo.Packet.SequenceNum).
		Uint8("packet_ackType", ackInfo.Packet.AckType).
		Str("source_gid_from_grh", ackInfo.ProcessedWC.SGID).   // From ProcessedWC
		Uint32("source_qp_from_wc", ackInfo.ProcessedWC.SrcQP). // From ProcessedWC (embedded GoWorkCompletion)
		Int("wc_status_from_pwc", ackInfo.ProcessedWC.Status).  // Status from embedded GoWorkCompletion
		Msg("[prober_handler]: Processing incoming ACK packet via callback")

	session := p.getSession(sessionKey) // Use getSession helper
	if session != nil {
		// Construct probe.ackEvent from rdma.IncomingAckInfo
		probeEvent := &ackEvent{
			Packet:     ackInfo.Packet, // This is a direct pointer, be cautious.
			ReceivedAt: ackInfo.ReceivedAt,
			WorkComp:   ackInfo.ProcessedWC, // Directly use the ProcessedWorkCompletion from ackInfo
		}

		// Check if the ACK itself was successful based on AckStatusOK field from IncomingAckInfo
		// AckStatusOK should ideally be set based on ackInfo.ProcessedWC.Status == C.IBV_WC_SUCCESS
		if !ackInfo.AckStatusOK { // This flag should be set correctly by the caller (e.g. CQ poller in rdma package)
			log.Error().
				Uint64("sessionKey_seqNum", sessionKey).           // Changed
				Int("rdma_wc_status", ackInfo.ProcessedWC.Status). // Log the actual RDMA status
				Msg("[prober_handler]: Received ACK but RDMA completion status was not OK (indicated by AckStatusOK flag).")
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
			log.Warn().Uint64("sessionKey_seqNum", sessionKey).Uint8("ackType", ackInfo.Packet.AckType).Msg("[prober_handler]: Received ACK with unknown type") // Changed
			return
		}

		if targetChan == nil {
			log.Warn().
				Uint64("sessionKey_seqNum", sessionKey). // Changed
				Str("chan", chanName).
				Msg("[prober_handler]: Session channel is nil. Session likely ended or cleaned up.")
			return
		}

		// Non-blocking send to the session channel
		select {
		case targetChan <- probeEvent:
			log.Trace().Uint64("sessionKey_seqNum", sessionKey).Str("chan", chanName). // Changed
													Msg("[prober_handler]: Successfully sent ACK event to session channel")
		default:
			log.Warn().Uint64("sessionKey_seqNum", sessionKey).Str("chan", chanName). // Changed
													Msg("[prober_handler]: Session channel blocked or closed (likely late ACK or session ended).")
		}
	} else {
		log.Warn().Uint64("sessionKey_seqNum", sessionKey).Uint64("packet_seqNum", ackInfo.Packet.SequenceNum).Msg("[prober_handler]: Received ACK for non-existent or already cleaned-up session") // Changed
	}
}

// Helper function to get RNIC by GID from agent state
func (p *Prober) getRnicByGid(gid string) *rdma.RNIC {
	rnics := p.agentState.GetDetectedRNICs()
	for _, rnic := range rnics {
		if rnic.GID == gid {
			return rnic
		}
	}
	return nil
}

// addSession adds a session to the map.
func (p *Prober) addSession(session *PingSession) {
	p.sessionsMutex.Lock()
	defer p.sessionsMutex.Unlock()
	p.sessions[session.SequenceNum] = session
}

// removeSession removes a session from the map.
func (p *Prober) removeSession(seqNum uint64) {
	p.sessionsMutex.Lock()
	defer p.sessionsMutex.Unlock()
	session, ok := p.sessions[seqNum]
	if ok {
		if session.Ack1Chan != nil {
			close(session.Ack1Chan)
		}
		if session.Ack2Chan != nil {
			close(session.Ack2Chan)
		}
		delete(p.sessions, seqNum)
	}
}

// getSession retrieves a session by sequence number.
func (p *Prober) getSession(seqNum uint64) *PingSession {
	p.sessionsMutex.RLock()
	defer p.sessionsMutex.RUnlock()
	session, exists := p.sessions[seqNum]
	if !exists {
		return nil
	}
	return session
}
