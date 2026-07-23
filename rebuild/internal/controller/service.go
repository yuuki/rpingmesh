package controller

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// registryClient is the subset of registry.RnicRegistry's API used directly
// by ControllerService (RegisterRNICs) and, via the embedded
// PinglistGenerator, its read methods (GetRNICsByToR,
// GetActiveRNICsInOtherToRs, ResolveHostnameByGID). It is declared here, at the
// point of use, so that RegisterAgent and GetPinglist can be unit tested
// against a fake instead of a real rqlite-backed registry.
type registryClient interface {
	pinglist.RnicSource
	RegisterRNICs(ctx context.Context, agentID, agentIP string, rnics []*controller_agent.RnicInfo) error
}

// probeAnalyzer is the subset of the analyzer used by ReportProbeAnalysis,
// declared at the point of use so the service can be unit tested against a
// fake and so the controller package does not hard-depend on the analyzer's
// concrete type. Ingest returns the number of SLA-violating summaries.
type probeAnalyzer interface {
	Ingest(ctx context.Context, report *controller_agent.ProbeAnalysisReport) int
}

// ControllerService implements the gRPC ControllerService defined in
// controller_agent.proto. It handles agent registration and pinglist
// distribution.
type ControllerService struct {
	controller_agent.UnimplementedControllerServiceServer
	registry registryClient
	pinglist *pinglist.PinglistGenerator
	// analyzer ingests reported per-path summaries and detects SLA violations.
	// nil when the analyzer is disabled, in which case ReportProbeAnalysis
	// accepts-and-drops.
	analyzer probeAnalyzer
}

// NewControllerService creates a new ControllerService backed by the given
// RNIC registry. A PinglistGenerator is automatically created from the
// registry, the ECMP config (which sizes how many distinct flow labels each
// target is probed with, Eq.(1) coverage), and interTorSampleSize (the number
// of distinct foreign ToRs sampled per inter-ToR pinglist).
func NewControllerService(reg registryClient, ecmp pinglist.ECMPConfig, interTorSampleSize int) *ControllerService {
	return &ControllerService{
		registry: reg,
		pinglist: pinglist.NewPinglistGenerator(reg, ecmp, interTorSampleSize),
	}
}

// SetAnalyzer wires an analyzer into the service so ReportProbeAnalysis ingests
// reported summaries. It is optional: with no analyzer set, ReportProbeAnalysis
// accepts-and-drops. Call before serving.
func (s *ControllerService) SetAnalyzer(a probeAnalyzer) {
	s.analyzer = a
}

// RegisterAgent registers an agent and all of its RNICs with the controller.
// Both agent_id and tor_id are required fields. For each RNIC in the request,
// the hostname and tor_id from the top-level request fields are applied before
// registration.
func (s *ControllerService) RegisterAgent(
	ctx context.Context,
	req *controller_agent.AgentRegistrationRequest,
) (*controller_agent.AgentRegistrationResponse, error) {
	// Validate required fields.
	if req.GetAgentId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "agent_id is required")
	}
	if req.GetTorId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "tor_id is required")
	}

	log.Info().
		Str("agentID", req.GetAgentId()).
		Str("agentIP", req.GetAgentIp()).
		Str("hostname", req.GetHostname()).
		Str("torID", req.GetTorId()).
		Int("rnicCount", len(req.GetRnics())).
		Msg("Agent registration request")

	// Apply hostname and tor_id from the top-level request to every RNIC.
	rnics := req.GetRnics()
	for _, rnic := range rnics {
		rnic.HostName = req.GetHostname()
		rnic.TorId = req.GetTorId()
	}

	// Register all RNICs for this agent as a single atomic operation. A
	// partial failure (e.g. one malformed RNIC) must not silently leave
	// some of the agent's RNICs registered while others are dropped, so any
	// error here fails the whole registration rather than being swallowed.
	if err := s.registry.RegisterRNICs(ctx, req.GetAgentId(), req.GetAgentIp(), rnics); err != nil {
		log.Error().Err(err).
			Str("agentID", req.GetAgentId()).
			Int("rnicCount", len(rnics)).
			Msg("Failed to register RNICs")

		return &controller_agent.AgentRegistrationResponse{
			Success: false,
			Message: fmt.Sprintf("failed to register RNICs: %s", err.Error()),
		}, status.Errorf(codes.Internal, "failed to register RNICs: %v", err)
	}

	log.Info().
		Str("agentID", req.GetAgentId()).
		Int("rnicCount", len(req.GetRnics())).
		Msg("Agent registered successfully")

	return &controller_agent.AgentRegistrationResponse{
		Success: true,
		Message: "Successfully registered agent",
	}, nil
}

// GetPinglist returns a list of probe targets for the requesting agent. The
// type field determines whether intra-ToR (TOR_MESH) or inter-ToR (INTER_TOR)
// targets are returned.
func (s *ControllerService) GetPinglist(
	ctx context.Context,
	req *controller_agent.PinglistRequest,
) (*controller_agent.PinglistResponse, error) {
	// Validate required fields.
	if req.GetAgentId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "agent_id is required")
	}
	if req.GetRequesterGid() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "requester_gid is required")
	}

	log.Info().
		Str("agentID", req.GetAgentId()).
		Str("requesterGID", req.GetRequesterGid()).
		Str("torID", req.GetTorId()).
		Str("type", req.GetType().String()).
		Msg("Pinglist request")

	var targets []*controller_agent.PingTarget
	var err error

	switch req.GetType() {
	case controller_agent.PinglistType_TOR_MESH:
		targets, err = s.pinglist.GenerateTorMeshPinglist(ctx, req.GetRequesterGid(), req.GetTorId())
	case controller_agent.PinglistType_INTER_TOR:
		targets, err = s.pinglist.GenerateInterTorPinglist(ctx, req.GetRequesterGid(), req.GetTorId())
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown pinglist type: %s", req.GetType().String())
	}

	if err != nil {
		log.Error().Err(err).
			Str("agentID", req.GetAgentId()).
			Str("type", req.GetType().String()).
			Msg("Failed to generate pinglist")

		return nil, status.Errorf(codes.Internal, "failed to generate pinglist: %v", err)
	}

	return &controller_agent.PinglistResponse{
		Targets: targets,
		Type:    req.GetType(),
	}, nil
}

// ReportProbeAnalysis ingests a batch of per-path window summaries reported by
// an agent and returns an ack carrying the number of SLA-violating summaries
// the analyzer detected. When no analyzer is configured, it accepts-and-drops
// (Accepted=false) so agents (which treat reporting as best-effort) are not
// forced to error.
func (s *ControllerService) ReportProbeAnalysis(
	ctx context.Context,
	req *controller_agent.ProbeAnalysisReport,
) (*controller_agent.ProbeAnalysisAck, error) {
	if req.GetAgentId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "agent_id is required")
	}

	if s.analyzer == nil {
		log.Debug().
			Str("agentID", req.GetAgentId()).
			Int("summaryCount", len(req.GetSummaries())).
			Msg("ReportProbeAnalysis received but analyzer is disabled; dropping")
		return &controller_agent.ProbeAnalysisAck{Accepted: false}, nil
	}

	violations := s.analyzer.Ingest(ctx, req)

	log.Debug().
		Str("agentID", req.GetAgentId()).
		Int("summaryCount", len(req.GetSummaries())).
		Int("slaViolations", violations).
		Msg("Ingested probe analysis report")

	return &controller_agent.ProbeAnalysisAck{
		Accepted:      true,
		SlaViolations: uint32(violations),
	}, nil
}
