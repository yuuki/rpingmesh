package serviceflowmonitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/agent/controller_client"
	"github.com/yuuki/rpingmesh/internal/ebpf"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/state" // For AgentState if needed for local GID correlation
)

const (
	// IB_QPS_RTR as defined in include/uapi/rdma/ib_user_verbs.h and eBPF code
	// Ensure this matches the value used in the eBPF program (typically 3).
	ibQpsRTR = 3
)

// ServiceFlow represents an active RDMA connection being monitored for service tracing.
type ServiceFlow struct {
	SrcGID string
	SrcQPN uint32
	DstGID string
	DstQPN uint32
	// Add other relevant info like DstIP if obtained from Controller
	DstIP string
}

// Key generates a unique key for the service flow.
func (sf *ServiceFlow) Key() string {
	return fmt.Sprintf("%s:%d-%s:%d", sf.SrcGID, sf.SrcQPN, sf.DstGID, sf.DstQPN)
}

// ServiceFlowMonitor manages the detection and lifecycle of service flows
// using eBPF events and interacts with the Controller to enrich flow information.
type ServiceFlowMonitor struct {
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	ebpfTracer       *ebpf.ServiceTracer
	controllerClient *controller_client.ControllerClient
	prober           *probe.Prober     // To provide pinglist to
	agentState       *state.AgentState // To get local RNIC GIDs for correlation

	activeFlows      map[string]*ServiceFlow
	activeFlowsMutex sync.RWMutex

	// Channel for Prober to request the service pinglist
	// pinglistRequestChan chan chan []*probe.PingTarget // This might be better handled by prober calling a method
}

// NewServiceFlowMonitor creates a new ServiceFlowMonitor.
func NewServiceFlowMonitor(
	ctx context.Context,
	ebpfTracer *ebpf.ServiceTracer,
	controllerClient *controller_client.ControllerClient,
	prober *probe.Prober,
	agentState *state.AgentState,
) (*ServiceFlowMonitor, error) {
	if ebpfTracer == nil {
		return nil, fmt.Errorf("eBPF tracer cannot be nil")
	}
	if controllerClient == nil {
		return nil, fmt.Errorf("controller client cannot be nil")
	}
	if prober == nil {
		return nil, fmt.Errorf("prober cannot be nil")
	}
	if agentState == nil {
		return nil, fmt.Errorf("agentState cannot be nil")
	}

	derivedCtx, cancel := context.WithCancel(ctx)

	return &ServiceFlowMonitor{
		ctx:              derivedCtx,
		cancel:           cancel,
		ebpfTracer:       ebpfTracer,
		controllerClient: controllerClient,
		prober:           prober,
		agentState:       agentState,
		activeFlows:      make(map[string]*ServiceFlow),
		// pinglistRequestChan: make(chan chan []*probe.PingTarget),
	}, nil
}

// Start begins monitoring eBPF events for service flows.
func (sfm *ServiceFlowMonitor) Start() {
	sfm.wg.Add(1)
	go sfm.eventLoop()
	log.Info().Msg("ServiceFlowMonitor started")
}

// Stop terminates the ServiceFlowMonitor.
func (sfm *ServiceFlowMonitor) Stop() {
	log.Info().Msg("Stopping ServiceFlowMonitor")
	sfm.cancel()
	sfm.wg.Wait()
	log.Info().Msg("ServiceFlowMonitor stopped")
}

func (sfm *ServiceFlowMonitor) eventLoop() {
	defer sfm.wg.Done()
	log.Debug().Msg("ServiceFlowMonitor event loop started")

	eventChan := sfm.ebpfTracer.Events()

	// Create ticker for periodic statistics logging
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()

	for {
		select {
		case <-sfm.ctx.Done():
			log.Debug().Msg("ServiceFlowMonitor event loop stopping due to context cancellation")
			return
		case event, ok := <-eventChan:
			if !ok {
				log.Info().Msg("eBPF event channel closed, ServiceFlowMonitor event loop stopping")
				return
			}
			sfm.handleEbpfEvent(event)
		case <-statsTicker.C:
			// Log eBPF statistics periodically to monitor GID read failures
			sfm.logEbpfStatistics()
		}
	}
}

// fillMissingSrcGID uses the agent's known RNICs to find a GID matching the event's SrcQPN.
func (sfm *ServiceFlowMonitor) fillMissingSrcGID(event *ebpf.RdmaConnTuple) string {
	for _, rnic := range sfm.agentState.GetDetectedRNICs() {
		if rnic.UDQueues != nil {
			// Check sender queue
			senderKey := rnic.GID + "_sender"
			if q, ok := rnic.UDQueues[senderKey]; ok && q.QPN == event.SrcQPN {
				return rnic.GID
			}
			// Check responder queue
			responderKey := rnic.GID + "_responder"
			if q, ok := rnic.UDQueues[responderKey]; ok && q.QPN == event.SrcQPN {
				return rnic.GID
			}
		}
		if rnic.ProberQueue != nil && rnic.ProberQueue.QPN == event.SrcQPN {
			return rnic.GID
		}
	}
	log.Warn().Uint32("src_qpn", event.SrcQPN).Msg("Could not find matching local GID for SrcQPN in ServiceFlowMonitor")
	return ""
}

func (sfm *ServiceFlowMonitor) handleEbpfEvent(event ebpf.RdmaConnTuple) {
	log.Trace().
		Str("event_type", event.EventTypeString()).
		Uint32("src_qpn", event.SrcQPN).
		Uint32("dst_qpn", event.DstQPN).
		Str("src_gid", event.SrcGIDString()).
		Str("dst_gid", event.DstGIDString()).
		Int32("qp_state", event.QPState).
		Uint8("port_num", event.PortNum).
		Uint64("timestamp", event.Timestamp).
		Str("comm", event.CommString()).
		Msg("ServiceFlowMonitor received eBPF event")

		// Validate struct alignment and data integrity
	if err := ebpf.ValidateStructAlignment(&event); err != nil {
		log.Warn().
			Err(err).
			Uint32("src_qpn", event.SrcQPN).
			Uint32("dst_qpn", event.DstQPN).
			Str("src_gid", event.SrcGIDString()).
			Str("dst_gid", event.DstGIDString()).
			Msg("Invalid eBPF event data - possible struct alignment issue")

		// Run detailed diagnostic on first alignment failure
		ebpf.DiagnoseStructAlignment(&event)

		// For now, skip processing events with invalid data to avoid creating bad service flows
		log.Warn().Msg("Skipping event due to invalid data")
		return
	}

	switch event.EventType {
	case 2: // MODIFY_QP
		if event.QPState != ibQpsRTR {
			log.Trace().Msgf("Ignoring MODIFY_QP event with QPState %d, expected %d (RTR)", event.QPState, ibQpsRTR)
			return
		}

		srcGidStr := event.SrcGIDString()
		if srcGidStr == "00000000000000000000000000000000" || srcGidStr == "" {
			log.Debug().Uint32("src_qpn", event.SrcQPN).Msg("SrcGID is zero in eBPF event, attempting to find local GID for MODIFY_QP.")
			localSrcGid := sfm.fillMissingSrcGID(&event)
			if localSrcGid != "" {
				srcGidStr = localSrcGid
				log.Debug().Str("src_gid", srcGidStr).Uint32("src_qpn", event.SrcQPN).Msg("Successfully correlated SrcQPN to local SrcGID for service flow.")
			} else {
				log.Warn().Uint32("src_qpn", event.SrcQPN).Msg("Failed to correlate SrcQPN to local SrcGID for MODIFY_QP. Cannot process service flow event.")
				return
			}
		}

		dstGidStr := event.DstGIDString()
		if event.DstQPN == 0 {
			log.Warn().Msgf("MODIFY_QP event (RTR) has invalid DstQPN (%d). Cannot establish service flow.", event.DstQPN)
			return
		}

		// Handle legitimate zero destination GID (common for local connections)
		if dstGidStr == "00000000000000000000000000000000" || dstGidStr == "" {
			log.Warn().
				Uint32("dst_qpn", event.DstQPN).
				Str("src_gid", srcGidStr).
				Uint32("src_qpn", event.SrcQPN).
				Msg("Destination GID is zero, skipping service flow")
			return
		}

		log.Info().
			Str("src_gid", srcGidStr).
			Uint32("src_qpn", event.SrcQPN).
			Str("dst_gid", dstGidStr).
			Uint32("dst_qpn", event.DstQPN).
			Msg("Service connection established (eBPF modify_qp to RTR)")

		flow := &ServiceFlow{
			SrcGID: srcGidStr,
			SrcQPN: event.SrcQPN,
			DstGID: dstGidStr,
			DstQPN: event.DstQPN,
		}

		targetRnicInfoResponse, err := sfm.controllerClient.GetTargetRnicInfo(dstGidStr, "")
		if err != nil {
			log.Warn().Err(err).Str("dst_gid", dstGidStr).Msg("Failed to get target RNIC info from controller for service flow")
		} else if targetRnicInfoResponse != nil {
			flow.DstIP = targetRnicInfoResponse.IpAddress
			log.Debug().Str("dst_gid", dstGidStr).Str("dst_ip", flow.DstIP).Msg("Enriched service flow with DstIP from controller")
		}

		sfm.activeFlowsMutex.Lock()
		sfm.activeFlows[flow.Key()] = flow
		sfm.activeFlowsMutex.Unlock()

		log.Debug().Str("flow_key", flow.Key()).Int("current_active_flows", len(sfm.activeFlows)).Msg("Added new service flow.")
		sfm.notifyProberUpdate()

	case 3: // DESTROY_QP
		srcGidStr := event.SrcGIDString() // May be zero from eBPF
		if srcGidStr == "00000000000000000000000000000000" || srcGidStr == "" {
			log.Debug().Uint32("src_qpn", event.SrcQPN).Msg("SrcGID is zero in eBPF event for DESTROY_QP, attempting to find local GID.")
			localSrcGid := sfm.fillMissingSrcGID(&event)
			if localSrcGid != "" {
				srcGidStr = localSrcGid
			} else {
				log.Warn().Uint32("src_qpn", event.SrcQPN).Msg("Failed to correlate SrcQPN to local SrcGID for DESTROY_QP.")
				// Continue, will try to remove based on SrcQPN alone if SrcGID is unknown
			}
		}

		log.Info().Uint32("src_qpn", event.SrcQPN).Str("src_gid_resolved", srcGidStr).Msg("Service connection closing (eBPF destroy_qp)")

		var removedKey string
		sfm.activeFlowsMutex.Lock()
		for key, flow := range sfm.activeFlows {
			// SrcQPN must match. If resolved SrcGID is available, it must also match.
			if flow.SrcQPN == event.SrcQPN {
				if srcGidStr == "" || flow.SrcGID == srcGidStr { // If srcGidStr is empty, match any SrcGID with that QPN
					delete(sfm.activeFlows, key)
					removedKey = key
					log.Debug().Str("flow_key", key).Msg("Service flow marked for removal.")
					break
				}
			}
		}
		sfm.activeFlowsMutex.Unlock()

		if removedKey != "" {
			log.Debug().Str("flow_key", removedKey).Int("current_active_flows", len(sfm.activeFlows)).Msg("Removed service flow.")
			sfm.notifyProberUpdate()
		} else {
			log.Warn().Uint32("src_qpn", event.SrcQPN).Str("src_gid_resolved", srcGidStr).Msg("Could not find active service flow to remove for DESTROY_QP event.")
		}
	default:
		log.Trace().Msgf("Ignoring eBPF event type: %s", event.EventTypeString())
	}
}

// GetServiceTracingTargets returns the current list of service flows as PingTarget objects
// for the prober. This method will be called by the Prober.
func (sfm *ServiceFlowMonitor) GetServiceTracingTargets() []*probe.PingTarget {
	sfm.activeFlowsMutex.RLock()
	defer sfm.activeFlowsMutex.RUnlock()

	if len(sfm.activeFlows) == 0 {
		return nil
	}

	pingTargets := make([]*probe.PingTarget, 0, len(sfm.activeFlows))
	for _, flow := range sfm.activeFlows {
		pingTargets = append(pingTargets, &probe.PingTarget{
			// For service tracing, the PingTarget's GID/QPN fields refer to the *destination* of the probe.
			GID:       flow.DstGID,
			QPN:       flow.DstQPN,
			IPAddress: flow.DstIP, // May be empty if controller lookup failed
			HostName:  "",         // Not critical if GID/QPN are present

			// This new field will carry the specific 5-tuple for service flow probing
			ServiceFlowTuple: &probe.ServiceFlowTuple{
				SrcGID:    flow.SrcGID,
				SrcQPN:    flow.SrcQPN,
				DstGID:    flow.DstGID, // Redundant here but good for completeness in the tuple
				DstQPN:    flow.DstQPN, // Redundant here
				FlowLabel: 0,           // Default flow label for now
			},
			ProbeType: probe.ProbeTypeServiceTracing, // Indicate this is for service tracing
		})
	}
	log.Debug().Int("count", len(pingTargets)).Msg("SFM: Providing service tracing targets.")
	return pingTargets
}

// notifyProberUpdate informs the prober that its list of service flow targets might have changed.
func (sfm *ServiceFlowMonitor) notifyProberUpdate() {
	log.Debug().Msg("SFM: Notifying prober of service flow list update.")
	if sfm.prober != nil {
		targets := sfm.GetServiceTracingTargets()
		sfm.prober.UpdateServiceFlowTargets(targets)
		// After updating the list, we need to trigger the Prober to actually probe these.
		// This could be a direct call to a new Prober method, e.g., sfm.prober.ProbeServiceTargetsNow()
		// or Prober has its own loop that will pick up the changes.
		// For now, UpdateServiceFlowTargets just updates the list.
		// Prober will need its own goroutine to act on this list.
	}
}

// logEbpfStatistics logs eBPF statistics to help debug GID read failures
func (sfm *ServiceFlowMonitor) logEbpfStatistics() {
	stats, err := sfm.ebpfTracer.GetStatistics()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get eBPF statistics")
		return
	}

	// Check for concerning patterns
	errorCount := stats["error_count"]
	gidReadSuccess := stats["gid_read_success"]
	gidReadFailure := stats["gid_read_failure"]
	portDataFailure := stats["port_data_failure"]
	gidTableFailure := stats["gid_table_failure"]
	modifyCount := stats["modify_count"]

	// Calculate success rate if we have any GID read attempts
	totalGidReads := gidReadSuccess + gidReadFailure
	var successRate float64
	if totalGidReads > 0 {
		successRate = float64(gidReadSuccess) / float64(totalGidReads) * 100
	}

	logLevel := log.Debug()
	if errorCount > 0 || gidReadFailure > 0 || portDataFailure > 0 || gidTableFailure > 0 {
		logLevel = log.Warn()
	}

	logLevel.
		Uint64("modify_events", modifyCount).
		Uint64("errors", errorCount).
		Uint64("gid_read_success", gidReadSuccess).
		Uint64("gid_read_failure", gidReadFailure).
		Uint64("port_data_failure", portDataFailure).
		Uint64("gid_table_failure", gidTableFailure).
		Float64("gid_success_rate", successRate).
		Int("active_flows", len(sfm.activeFlows)).
		Msg("eBPF ServiceFlowMonitor statistics")

	// Log specific warnings for troubleshooting
	if gidReadFailure > 0 && gidReadSuccess == 0 {
		log.Error().Msg("All GID reads are failing - check RDMA driver compatibility and kernel structure alignment")

		// Provide detailed diagnosis on first failure detection
		// Note: This is a simple check to avoid spamming logs. In production, you might want a more sophisticated approach.
		if modifyCount <= 5 { // Only show detailed diagnosis for first few events
			ebpf.DiagnoseGidReadFailures(stats)
			ebpf.PrintBpfTraceLog()
		}
	} else if gidReadFailure > gidReadSuccess {
		log.Warn().Msg("GID read failure rate is high - RDMA structure access may be unstable")
	}
}
