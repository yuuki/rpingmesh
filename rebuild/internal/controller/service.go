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
// GetSampleRNICsFromOtherToRs). It is declared here, at the point of use, so
// that RegisterAgent and GetPinglist can be unit tested against a fake
// instead of a real rqlite-backed registry.
type registryClient interface {
	pinglist.RnicSource
	RegisterRNICs(ctx context.Context, agentID, agentIP string, rnics []*controller_agent.RnicInfo) error
}

// ControllerService implements the gRPC ControllerService defined in
// controller_agent.proto. It handles agent registration and pinglist
// distribution.
type ControllerService struct {
	controller_agent.UnimplementedControllerServiceServer
	registry registryClient
	pinglist *pinglist.PinglistGenerator
}

// NewControllerService creates a new ControllerService backed by the given
// RNIC registry. A PinglistGenerator is automatically created from the
// registry.
func NewControllerService(reg registryClient) *ControllerService {
	return &ControllerService{
		registry: reg,
		pinglist: pinglist.NewPinglistGenerator(reg),
	}
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
