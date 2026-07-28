package probe

import (
	"context"
	"errors"
	"fmt"
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
	SessionKey    string // Changed: Use composite key instead of just FlowLabel
	FlowLabel     uint32 // Keep for reference
	SequenceNum   uint64
	SourceRnicGid string
	TargetGid     string
	ProbeType     string // Added ProbeType to PingSession

	Ack1Chan chan *ackEvent // Receives the first ACK (type 1)
	Ack2Chan chan *ackEvent // Receives the second ACK (type 2)

	CreationTime time.Time

	// Use sync.Once for elegant channel closing and chan struct{} for status check
	closeOnce sync.Once
	closed    chan struct{} // Closed when session is terminated
}

// ackEvent is a wrapper for ACK data received.
type ackEvent struct {
	Packet     *rdma.ProbePacket
	ReceivedAt time.Time
	WorkComp   *rdma.ProcessedWorkCompletion
}

// Prober is responsible for sending probe packets and collecting results.
type Prober struct {
	rdmaManager  *rdma.RDMAManager
	agentState   *state.AgentState
	probeResults chan *agent_analyzer.ProbeResult
	stopCh       chan struct{}
	wg           sync.WaitGroup
	sessions     sync.Map // Key: string (composite session key), Value: *PingSession
	seqNumIndex  sync.Map // Key: uint64 (sequence number), Value: string (session key) - for faster lookup
	nextSeqNum   uint64
	metricMutex  sync.Mutex // To protect metrics if any are directly managed here

	// Diagnostic statistics (using atomic operations for thread-safe access)
	stats struct {
		SessionsCreated       uint64 // Use atomic.AddUint64 and atomic.LoadUint64
		SessionsFoundByFlow   uint64 // Use atomic.AddUint64 and atomic.LoadUint64
		SessionsFoundBySeqNum uint64 // Use atomic.AddUint64 and atomic.LoadUint64
		SessionsNotFound      uint64 // Use atomic.AddUint64 and atomic.LoadUint64
		AckTimeouts           uint64 // Use atomic.AddUint64 and atomic.LoadUint64
		SuccessfulProbes      uint64 // Use atomic.AddUint64 and atomic.LoadUint64
		FailedProbes          uint64 // Use atomic.AddUint64 and atomic.LoadUint64
		SessionCleanups       uint64 // Use atomic.AddUint64 and atomic.LoadUint64
	}

	// For Service Flow Tracing
	// Using PingTarget from the same package now
	serviceFlowTargets      []*PingTarget // Changed from monitor.PingTarget
	serviceFlowTargetsMutex sync.RWMutex
}

const (
	probeResultChanBufferSize = 1000
	responderStatsInterval    = 30 * time.Second
	sessionCleanupInterval    = 60 * time.Second // New: Session cleanup interval
	sessionTimeout            = 5 * time.Minute  // New: Session timeout duration
)

// NewProber creates a new Prober.
func NewProber(manager *rdma.RDMAManager, agentState *state.AgentState) *Prober {
	return &Prober{
		rdmaManager:        manager,
		agentState:         agentState,
		probeResults:       make(chan *agent_analyzer.ProbeResult, probeResultChanBufferSize),
		stopCh:             make(chan struct{}),
		sessions:           sync.Map{},
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

	// Start session cleanup loop
	p.wg.Add(1)
	go p.runSessionCleanupLoop()

	// Start statistics logging loop
	p.wg.Add(1)
	go p.runStatsLoggingLoop()

	log.Info().Msg("Prober started with responder loops, service probing loop, session cleanup loop, and statistics logging loop.")
	return nil
}

// Close stops the prober and cleans up resources.
func (p *Prober) Close() error {
	log.Info().Msg("Closing prober...")
	close(p.stopCh) // Signal all internal goroutines to stop
	p.wg.Wait()     // Wait for all goroutines (like runServiceProbingLoop) to finish

	// Close any active session channels
	p.sessions.Range(func(key, value interface{}) bool {
		session := value.(*PingSession)
		session.closeOnce.Do(func() {
			close(session.closed)
			if session.Ack1Chan != nil {
				close(session.Ack1Chan)
			}
			if session.Ack2Chan != nil {
				close(session.Ack2Chan)
			}
		})
		p.sessions.Delete(key) // Remove session from sync.Map
		return true            // Continue iteration
	})

	// Clear sequence number index
	p.seqNumIndex.Range(func(key, value interface{}) bool {
		p.seqNumIndex.Delete(key)
		return true
	})

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

				probeCtx, cancelProbe := context.WithTimeout(context.Background(), 500*time.Millisecond) // TODO: make this configurable

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

// generateSessionKey creates a unique session key for probe tracking
func (p *Prober) generateSessionKey(sourceGid, targetGid string, seqNum uint64) string {
	return fmt.Sprintf("%s->%s:%d", sourceGid, targetGid, seqNum)
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
	flowLabel := target.FlowLabel // Use target's flow label as session key

	// Generate composite session key for better tracking
	sessionKey := p.generateSessionKey(sourceRnic.GID, target.GID, seqNum)

	session := &PingSession{
		SessionKey:    sessionKey,
		FlowLabel:     flowLabel,
		SequenceNum:   seqNum,
		SourceRnicGid: sourceRnic.GID,
		TargetGid:     target.GID,
		ProbeType:     target.ProbeType,
		Ack1Chan:      make(chan *ackEvent, 1),
		Ack2Chan:      make(chan *ackEvent, 1),
		CreationTime:  time.Now(),
		closed:        make(chan struct{}), // Initialize closed channel
	}
	p.addSession(session)
	defer p.removeSession(sessionKey)

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
				Gid:        actualSrcGid,
				IpAddress:  sourceRnic.IPAddr,
				HostName:   p.agentState.GetHostName(),
				DeviceName: sourceRnic.DeviceName,
			},
			DestinationRnic: &agent_analyzer.RnicIdentifier{
				Gid:        target.GID,
				Qpn:        target.QPN,
				IpAddress:  target.IPAddress,
				HostName:   target.HostName,
				TorId:      target.TorID,
				DeviceName: target.DeviceName,
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
					Gid:        actualSrcGid,
					IpAddress:  p.getRnicByGid(actualSrcGid).IPAddr,
					HostName:   p.agentState.GetHostName(),
					DeviceName: p.getRnicByGid(actualSrcGid).DeviceName,
				},
				DestinationRnic: &agent_analyzer.RnicIdentifier{
					Gid:        target.GID,
					Qpn:        target.QPN,
					IpAddress:  target.IPAddress,
					HostName:   target.HostName,
					TorId:      target.TorID,
					DeviceName: target.DeviceName,
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
			Gid:        actualSrcGid,
			Qpn:        actualSrcQpn,
			IpAddress:  sourceRnicInfo.IPAddr,
			HostName:   p.agentState.GetHostName(),
			DeviceName: sourceRnicInfo.DeviceName,
		},
		DestinationRnic: &agent_analyzer.RnicIdentifier{
			Gid:        target.GID,
			Qpn:        target.QPN,
			IpAddress:  target.IPAddress,
			HostName:   target.HostName,
			TorId:      target.TorID,
			DeviceName: target.DeviceName,
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

	t1, t2, err := srcUdQueue.SendProbePacket(ctx, actualDstGid, actualDstQpn, seqNum, srcPortForPacket, actualFlowLabel)
	if err != nil {
		log.Error().Err(err).
			Str("actualSrcGID", actualSrcGid).Uint32("actualSrcQPN", actualSrcQpn).
			Str("actualDstGID", actualDstGid).Uint32("actualDstQPN", actualDstQpn).
			Uint32("actualFlowLabel", actualFlowLabel).
			Uint64("seqNum", seqNum).
			Msg("Failed to send probe packet")
		result.Status = agent_analyzer.ProbeResult_ERROR

		// Update statistics for failed probe using atomic operation
		atomic.AddUint64(&p.stats.FailedProbes, 1)

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

	// Wait for both ACKs in any order
	var ack1Event *ackEvent
	var ack2Event *ackEvent
	var ack1Received, ack2Received bool
	var t5, t6 time.Time // T5: first ACK received time, T6: processing complete time

	for !ack1Received || !ack2Received {
		select {
		case <-ctx.Done():
			if !ack1Received && !ack2Received {
				log.Warn().Uint64("seqNum", seqNum).
					Str("targetGID", actualDstGid).
					Str("probeType", target.ProbeType).
					Msg("[prober]: Probe timed out waiting for ACKs")
			} else {
				log.Warn().Uint64("seqNum", seqNum).
					Str("targetGID", actualDstGid).
					Str("probeType", target.ProbeType).
					Bool("ack1Received", ack1Received).
					Bool("ack2Received", ack2Received).
					Msg("[prober]: Probe timed out waiting for remaining ACK")
			}
			result.Status = agent_analyzer.ProbeResult_TIMEOUT
			// Update statistics using atomic operation
			atomic.AddUint64(&p.stats.AckTimeouts, 1)

			p.probeResults <- result
			return

		case ackEvent, ok := <-session.Ack1Chan:
			if !ok {
				log.Warn().Uint64("seqNum", seqNum).
					Str("actualDstGID", actualDstGid).
					Msg("[prober]: Session Ack1Chan channel closed prematurely")
				result.Status = agent_analyzer.ProbeResult_ERROR

				// Update statistics for failed probe using atomic operation
				atomic.AddUint64(&p.stats.FailedProbes, 1)

				p.probeResults <- result
				return
			}
			if !ack1Received {
				ack1Event = ackEvent
				ack1Received = true

				// If this is the first ACK to arrive (regardless of type), record T5
				if !ack2Received {
					t5 = ackEvent.ReceivedAt
					result.T5 = timestamppb.New(t5)
				}

				log.Trace().Uint64("seqNum", seqNum).
					Str("actualDstGID", actualDstGid).
					Uint8("ackType", ackEvent.Packet.AckType).
					Msg("[prober]: Received ACK type 1")
			}

		case ackEvent, ok := <-session.Ack2Chan:
			if !ok {
				log.Warn().Uint64("seqNum", seqNum).
					Str("actualDstGID", actualDstGid).
					Msg("[prober]: Session Ack2Chan channel closed prematurely")
				result.Status = agent_analyzer.ProbeResult_ERROR

				// Update statistics for failed probe using atomic operation
				atomic.AddUint64(&p.stats.FailedProbes, 1)

				p.probeResults <- result
				return
			}
			if !ack2Received {
				ack2Event = ackEvent
				ack2Received = true

				// If this is the first ACK to arrive (regardless of type), record T5
				if !ack1Received {
					t5 = ackEvent.ReceivedAt
					result.T5 = timestamppb.New(t5)
				}

				log.Trace().Uint64("seqNum", seqNum).
					Str("actualDstGID", actualDstGid).
					Uint8("ackType", ackEvent.Packet.AckType).
					Msg("[prober]: Received ACK type 2")
			}
		}
	}

	// Both ACKs received, process timestamps and calculate delays
	result.Status = agent_analyzer.ProbeResult_OK
	t6 = time.Now() // T6 is when both ACKs have been processed
	result.T6 = timestamppb.New(t6)

	// Update statistics for successful probe using atomic operation
	atomic.AddUint64(&p.stats.SuccessfulProbes, 1)

	log.Trace().Uint64("seqNum", seqNum).
		Str("actualDstGID", actualDstGid).
		Msg("[prober]: Received both ACKs, processing timestamps and delays")

	// Extract T3 and T4 from the appropriate ACK packets
	var t3, t4 time.Time

	// Find the first ACK (AckType == 1) for T3
	var firstAckEvent *ackEvent
	if ack1Event != nil && ack1Event.Packet != nil && ack1Event.Packet.AckType == 1 {
		firstAckEvent = ack1Event
	} else if ack2Event != nil && ack2Event.Packet != nil && ack2Event.Packet.AckType == 1 {
		firstAckEvent = ack2Event
	}

	// Find the second ACK (AckType == 2) for T4
	var secondAckEvent *ackEvent
	if ack1Event != nil && ack1Event.Packet != nil && ack1Event.Packet.AckType == 2 {
		secondAckEvent = ack1Event
	} else if ack2Event != nil && ack2Event.Packet != nil && ack2Event.Packet.AckType == 2 {
		secondAckEvent = ack2Event
	}

	// Extract T3 from the first ACK
	if firstAckEvent != nil {
		t3 = time.Unix(0, int64(firstAckEvent.Packet.T3))
		result.T3 = timestamppb.New(t3)
	} else {
		log.Warn().Uint64("seqNum", seqNum).
			Str("actualDstGID", actualDstGid).
			Msg("[prober]: First ACK (AckType=1) not found, cannot extract T3")
	}

	// Extract T4 from the second ACK
	if secondAckEvent != nil {
		t4 = time.Unix(0, int64(secondAckEvent.Packet.T4))
		result.T4 = timestamppb.New(t4)
	} else {
		log.Warn().Uint64("seqNum", seqNum).
			Str("actualDstGID", actualDstGid).
			Msg("[prober]: Second ACK (AckType=2) not found, cannot extract T4")
	}

	// Calculate delays if all timestamps are available
	if result.T2 != nil && result.T3 != nil && result.T4 != nil && result.T5 != nil {
		responderDelay := t4.Sub(t3)
		result.ResponderDelay = responderDelay.Nanoseconds()
		result.NetworkRtt = (t5.Sub(t2) - responderDelay).Nanoseconds()
		result.ProberDelay = (t6.Sub(t1) - (t5.Sub(t2))).Nanoseconds()

		log.Debug().Uint64("seqNum", seqNum).
			Str("actualDstGID", actualDstGid).
			Int64("networkRtt_ns", result.NetworkRtt).
			Int64("responderDelay_ns", result.ResponderDelay).
			Int64("proberDelay_ns", result.ProberDelay).
			Int64("t1_ns", int64(t1.UnixNano())).
			Int64("t2_ns", int64(t2.UnixNano())).
			Int64("t3_ns", int64(t3.UnixNano())).
			Int64("t4_ns", int64(t4.UnixNano())).
			Int64("t5_ns", int64(t5.UnixNano())).
			Int64("t6_ns", int64(t6.UnixNano())).
			Msg("[prober]: Probe completed successfully with both ACKs")
	} else {
		log.Warn().Uint64("seqNum", seqNum).
			Bool("t2_valid", result.T2 != nil).
			Bool("t3_valid", result.T3 != nil).
			Bool("t4_valid", result.T4 != nil).
			Bool("t5_valid", result.T5 != nil).
			Msg("[prober]: Cannot calculate responder delay and network RTT due to missing timestamps")
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
		timeoutCount   uint64
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
				Uint64("timeoutCount", timeoutCount).
				Msg("Stopping responder loop")
			return

		case <-statsTicker.C:
			// Log stats periodically
			log.Debug().
				Uint64("totalPackets", totalPackets).
				Uint64("probePackets", probePackets).
				Uint64("invalidPackets", invalidPackets).
				Uint64("errorPackets", errorPackets).
				Uint64("timeoutCount", timeoutCount).
				Msg("Responder loop stats")

		default:
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			packet, receiveTime, processedWC, err := udq.ReceivePacket(ctx)
			cancel()
			if err != nil {
				if !errors.Is(err, context.DeadlineExceeded) {
					log.Error().Err(err).
						Str("device", udq.RNIC.DeviceName).
						Uint32("qpn", udq.QPN).
						Str("gid", udq.RNIC.GID).
						Msg("[responder]: Error receiving packet")
					atomic.AddUint64(&errorPackets, 1)
				} else {
					atomic.AddUint64(&timeoutCount, 1)
					// Log timeout every 1000 occurrences to avoid spam
					if timeoutCount%1000 == 0 {
						log.Trace().
							Str("device", udq.RNIC.DeviceName).
							Uint32("qpn", udq.QPN).
							Uint64("timeout_count", timeoutCount).
							Msg("[responder]: Receive timeout (normal)")
					}
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

			log.Trace().
				Str("device", udq.RNIC.DeviceName).
				Uint32("qpn", udq.QPN).
				Str("gid", udq.RNIC.GID).
				Uint64("seqNum", func() uint64 {
					if packet != nil {
						return packet.SequenceNum
					}
					return 0
				}()).
				Uint8("isAck", func() uint8 {
					if packet != nil {
						return packet.IsAck
					}
					return 255 // Invalid value to indicate packet is nil
				}()).
				Str("sourceGID", processedWC.SGID).
				Uint32("sourceQPN", processedWC.SrcQP).
				Uint32("flowLabel", processedWC.FlowLabel).
				Msg("[responder]: Received packet on responder queue")

			if packet.IsAck != 0 { // packet can be nil if deserialize failed but processedWC might still be returned
				log.Warn().
					Str("device", udq.RNIC.DeviceName).
					Str("GID", udq.RNIC.GID).
					Uint32("QPN", udq.QPN).
					Uint32("flowLabel", processedWC.FlowLabel). // Use FlowLabel from ProcessedWorkCompletion
					Uint64("seqNum", packet.SequenceNum).
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
					Uint64("seqNum", packet.SequenceNum).
					Str("device", udq.RNIC.DeviceName).
					Uint32("qpn", udq.QPN).
					Msg("[responder]: Invalid source GID or QPN in work completion, cannot send ACK")
				continue
			}

			log.Debug().
				Str("sending_device", udq.RNIC.DeviceName).
				Uint32("sendingQPN", udq.QPN).
				Str("sendingGID", udq.RNIC.GID).
				Str("targetGID", sourceGID).
				Uint32("targetQPN", sourceQPN).
				Uint32("flowLabel", processedWC.FlowLabel).
				Uint64("seqNum", packet.SequenceNum).
				Uint64("packet_t1", packet.T1).
				Time("receiveTime", receiveTime).
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
					Uint64("seqNum", packet.SequenceNum).
					Msg("[responder]: Failed to send first ACK packet")
				continue
			}

			log.Trace().
				Str("sourceGID", sourceGID).
				Uint32("sourceQPN", sourceQPN).
				Uint32("flowLabel", processedWC.FlowLabel).
				Uint64("seqNum", packet.SequenceNum).
				Time("firstAckCompletionTime", firstAckCompletionTime).
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
					Uint64("seqNum", packet.SequenceNum).
					Msg("[responder]: Failed to send second ACK packet")
				continue
			}

			log.Trace().
				Str("sourceGID", sourceGID).
				Uint32("sourceQPN", sourceQPN).
				Uint32("flowLabel", processedWC.FlowLabel).
				Uint64("seqNum", packet.SequenceNum).
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

	// Try to find session using multiple strategies (prefer seqNum to avoid flow label collisions)
	var session *PingSession
	var sessionKey string

	flowLabelKey := ackInfo.ProcessedWC.FlowLabel
	sourceGid := ackInfo.ProcessedWC.SGID

	// Strategy 1: Search by sequence number and (optional) source GID
	session = p.findSessionByPacketInfo(ackInfo.Packet.SequenceNum, sourceGid)
	if session != nil {
		sessionKey = session.SessionKey
		// Update statistics using atomic operation
		atomic.AddUint64(&p.stats.SessionsFoundBySeqNum, 1)

		log.Trace().
			Uint64("found_by_seqNum", ackInfo.Packet.SequenceNum).
			Str("sourceGid", sourceGid).
			Str("sessionKey", sessionKey).
			Msg("[prober_handler]: Found session by sequence number and GID")
	} else {
		// Strategy 2: Fallback to flow label only when it's non-zero and unique
		if flowLabelKey != 0 {
			session = p.getSessionByFlowLabel(flowLabelKey)
			if session != nil {
				sessionKey = session.SessionKey
				// Update statistics using atomic operation
				atomic.AddUint64(&p.stats.SessionsFoundByFlow, 1)

				log.Trace().
					Uint32("found_by_flowLabel", flowLabelKey).
					Str("sessionKey", sessionKey).
					Msg("[prober_handler]: Found session by flow label (fallback)")
			} else {
				// Update statistics for not found using atomic operation
				atomic.AddUint64(&p.stats.SessionsNotFound, 1)
			}
		} else {
			// Update statistics for not found using atomic operation
			atomic.AddUint64(&p.stats.SessionsNotFound, 1)
		}
	}

	log.Trace().
		Uint32("flowLabel", flowLabelKey).
		Uint64("packet_seqNum", ackInfo.Packet.SequenceNum).
		Uint8("packet_ackType", ackInfo.Packet.AckType).
		Str("source_gid_from_grh", ackInfo.ProcessedWC.SGID).
		Uint32("source_qp_from_wc", ackInfo.ProcessedWC.SrcQP).
		Int("wc_status_from_pwc", ackInfo.ProcessedWC.Status).
		Str("sessionKey", sessionKey).
		Bool("session_found", session != nil).
		Msg("[prober_handler]: Processing incoming ACK packet via callback")

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
				Str("sessionKey", sessionKey).
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
			log.Warn().Str("sessionKey", sessionKey).Uint8("ackType", ackInfo.Packet.AckType).Msg("[prober_handler]: Received ACK with unknown type")
			return
		}

		if targetChan == nil {
			log.Warn().
				Str("sessionKey", sessionKey).
				Str("chan", chanName).
				Msg("[prober_handler]: Session channel is nil. Session likely ended or cleaned up.")
			return
		}

		// Non-blocking send to the session channel
		// Use select to safely check if session is closed and send to channel
		select {
		case <-session.closed:
			// Session is closed, cannot send
			log.Warn().
				Str("sessionKey", sessionKey).
				Str("chan", chanName).
				Msg("[prober_handler]: Session is closed, cannot send ACK event.")
		case targetChan <- probeEvent:
			// Successfully sent
			log.Trace().Str("sessionKey", sessionKey).Str("chan", chanName).
				Msg("[prober_handler]: Successfully sent ACK event to session channel")
		default:
			// Channel is blocked or nil
			log.Warn().
				Str("sessionKey", sessionKey).
				Str("chan", chanName).
				Bool("closed", func() bool {
					select {
					case <-session.closed:
						return true
					default:
						return false
					}
				}()).
				Bool("chanNil", targetChan == nil).
				Msg("[prober_handler]: Session channel blocked or closed (likely late ACK or session ended).")
		}
	} else {
		log.Warn().
			Uint32("flowLabel", flowLabelKey).
			Uint64("packet_seqNum", ackInfo.Packet.SequenceNum).
			Str("source_gid", ackInfo.ProcessedWC.SGID).
			Msg("[prober_handler]: Received ACK for non-existent or already cleaned-up session")
	}
}

// Helper function to get RNIC by GID from agent state
func (p *Prober) getRnicByGid(gid string) *rdma.RNIC {
	return p.agentState.GetRnicByGID(gid)
}

// addSession adds a session to the map.
func (p *Prober) addSession(session *PingSession) {
	p.sessions.Store(session.SessionKey, session)
	p.seqNumIndex.Store(session.SequenceNum, session.SessionKey)

	// Update statistics using atomic operation
	atomic.AddUint64(&p.stats.SessionsCreated, 1)
}

// removeSession removes a session from the map.
func (p *Prober) removeSession(sessionKey string) {
	if value, ok := p.sessions.LoadAndDelete(sessionKey); ok {
		session := value.(*PingSession)
		// Remove from sequence number index
		p.seqNumIndex.Delete(session.SequenceNum)
		// Safely close the session channels using sync.Once
		session.closeOnce.Do(func() {
			close(session.closed)
			if session.Ack1Chan != nil {
				close(session.Ack1Chan)
			}
			if session.Ack2Chan != nil {
				close(session.Ack2Chan)
			}
		})
	}
}

// getSession retrieves a session by session key.
func (p *Prober) getSession(sessionKey string) *PingSession {
	if value, ok := p.sessions.Load(sessionKey); ok {
		return value.(*PingSession)
	}
	return nil
}

// getSessionByFlowLabel retrieves a session by flow label (fallback method).
func (p *Prober) getSessionByFlowLabel(flowLabel uint32) *PingSession {
	var foundSession *PingSession
	var foundCount int
	p.sessions.Range(func(key, value interface{}) bool {
		session := value.(*PingSession)
		if session.FlowLabel == flowLabel {
			foundSession = session
			foundCount++
			if foundCount > 1 {
				// Ambiguous flow label, do not select a session
				foundSession = nil
				return false // Stop iteration
			}
		}
		return true // Continue iteration
	})
	return foundSession
}

// findSessionByPacketInfo finds a session by sequence number and source GID.
func (p *Prober) findSessionByPacketInfo(seqNum uint64, sourceGid string) *PingSession {
	// First, try to find by sequence number index (O(1) lookup)
	if sessionKeyValue, ok := p.seqNumIndex.Load(seqNum); ok {
		sessionKey := sessionKeyValue.(string)
		if session := p.getSession(sessionKey); session != nil {
			// Verify the source GID matches (additional validation)
			if sourceGid == "" || session.TargetGid == sourceGid {
				log.Trace().
					Uint64("seqNum", seqNum).
					Str("sourceGid", sourceGid).
					Str("sessionKey", sessionKey).
					Msg("Found session using sequence number index")
				return session
			} else {
				log.Warn().
					Uint64("seqNum", seqNum).
					Str("expected_sourceGid", sourceGid).
					Str("session_targetGid", session.TargetGid).
					Str("sessionKey", sessionKey).
					Msg("Sequence number found but GID mismatch - possible sequence number collision")
			}
		}
	}

	// Fallback to linear search if index lookup fails
	log.Trace().
		Uint64("seqNum", seqNum).
		Str("sourceGid", sourceGid).
		Msg("Falling back to linear search for session")

	var foundSession *PingSession
	p.sessions.Range(func(key, value interface{}) bool {
		session := value.(*PingSession)
		if session.SequenceNum == seqNum && (sourceGid == "" || session.TargetGid == sourceGid) {
			foundSession = session
			return false // Stop iteration
		}
		return true // Continue iteration
	})

	if foundSession != nil {
		log.Trace().
			Uint64("seqNum", seqNum).
			Str("sourceGid", sourceGid).
			Str("sessionKey", foundSession.SessionKey).
			Msg("Found session using linear search")
	}

	return foundSession
}

// runSessionCleanupLoop periodically cleans up expired sessions to prevent memory leaks.
func (p *Prober) runSessionCleanupLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(sessionCleanupInterval)
	defer ticker.Stop()

	log.Info().
		Dur("cleanup_interval", sessionCleanupInterval).
		Dur("session_timeout", sessionTimeout).
		Msg("Starting session cleanup loop")

	for {
		select {
		case <-p.stopCh:
			log.Info().Msg("Session cleanup loop stopping")
			return
		case <-ticker.C:
			p.cleanupExpiredSessions()
		}
	}
}

// cleanupExpiredSessions removes sessions that have exceeded the timeout duration.
func (p *Prober) cleanupExpiredSessions() {
	now := time.Now()
	var expiredKeys []string
	var totalSessions int

	// Collect expired session keys
	p.sessions.Range(func(key, value interface{}) bool {
		totalSessions++
		session := value.(*PingSession)
		if now.Sub(session.CreationTime) > sessionTimeout {
			expiredKeys = append(expiredKeys, key.(string))
		}
		return true // Continue iteration
	})

	// Remove expired sessions
	for _, sessionKey := range expiredKeys {
		p.removeSession(sessionKey)
		log.Debug().
			Str("sessionKey", sessionKey).
			Msg("Cleaned up expired session")
	}

	if len(expiredKeys) > 0 {
		// Update statistics using atomic operation
		atomic.AddUint64(&p.stats.SessionCleanups, uint64(len(expiredKeys)))

		log.Info().
			Int("expired_sessions", len(expiredKeys)).
			Int("total_sessions", totalSessions).
			Int("remaining_sessions", totalSessions-len(expiredKeys)).
			Msg("Session cleanup completed")
	}
}

// runStatsLoggingLoop periodically logs diagnostic statistics.
func (p *Prober) runStatsLoggingLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(1 * time.Minute) // Log stats every 5 minutes
	defer ticker.Stop()

	log.Info().Msg("Starting statistics logging loop")

	for {
		select {
		case <-p.stopCh:
			log.Info().Msg("Statistics logging loop stopping")
			return
		case <-ticker.C:
			p.logDiagnosticStats()
		}
	}
}

// logDiagnosticStats logs current diagnostic statistics.
func (p *Prober) logDiagnosticStats() {
	// Count active sessions
	var activeSessions int
	p.sessions.Range(func(key, value interface{}) bool {
		activeSessions++
		return true
	})

	// Use atomic loads for statistics
	log.Info().
		Uint64("sessions_created", atomic.LoadUint64(&p.stats.SessionsCreated)).
		Uint64("sessions_found_by_flow", atomic.LoadUint64(&p.stats.SessionsFoundByFlow)).
		Uint64("sessions_found_by_seq_num", atomic.LoadUint64(&p.stats.SessionsFoundBySeqNum)).
		Uint64("sessions_not_found", atomic.LoadUint64(&p.stats.SessionsNotFound)).
		Uint64("ack_timeouts", atomic.LoadUint64(&p.stats.AckTimeouts)).
		Uint64("successful_probes", atomic.LoadUint64(&p.stats.SuccessfulProbes)).
		Uint64("failed_probes", atomic.LoadUint64(&p.stats.FailedProbes)).
		Uint64("session_cleanups", atomic.LoadUint64(&p.stats.SessionCleanups)).
		Int("active_sessions", activeSessions).
		Msg("Prober diagnostic statistics")
}

// GetDiagnosticStats returns current diagnostic statistics.
func (p *Prober) GetDiagnosticStats() map[string]uint64 {
	// Use atomic loads for statistics
	return map[string]uint64{
		"sessions_created":          atomic.LoadUint64(&p.stats.SessionsCreated),
		"sessions_found_by_flow":    atomic.LoadUint64(&p.stats.SessionsFoundByFlow),
		"sessions_found_by_seq_num": atomic.LoadUint64(&p.stats.SessionsFoundBySeqNum),
		"sessions_not_found":        atomic.LoadUint64(&p.stats.SessionsNotFound),
		"ack_timeouts":              atomic.LoadUint64(&p.stats.AckTimeouts),
		"successful_probes":         atomic.LoadUint64(&p.stats.SuccessfulProbes),
		"failed_probes":             atomic.LoadUint64(&p.stats.FailedProbes),
		"session_cleanups":          atomic.LoadUint64(&p.stats.SessionCleanups),
	}
}
