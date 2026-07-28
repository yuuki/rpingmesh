package controller

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/internal/controller/registry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ControllerService implements the gRPC service for the controller
type ControllerService struct {
	controller_agent.UnimplementedControllerServiceServer
	registry   *registry.RnicRegistry
	pingLister *pinglist.PingLister
}

// NewControllerService creates a new controller service
func NewControllerService(registry *registry.RnicRegistry, pingLister *pinglist.PingLister) *ControllerService {
	return &ControllerService{
		registry:   registry,
		pingLister: pingLister,
	}
}

// RegisterAgent registers an agent and its RNICs
func (s *ControllerService) RegisterAgent(
	ctx context.Context,
	req *controller_agent.AgentRegistrationRequest,
) (*controller_agent.AgentRegistrationResponse, error) {
	log.Info().
		Str("agentID", req.AgentId).
		Str("agentIP", req.AgentIp).
		Int("rnicCount", len(req.Rnics)).
		Msg("Agent registration request")

	// Register each RNIC
	for _, rnic := range req.Rnics {
		if err := s.registry.RegisterRNIC(ctx, req.AgentId, req.AgentIp, rnic); err != nil {
			log.Error().Err(err).
				Str("agentID", req.AgentId).
				Str("rnicGID", rnic.Gid).
				Msg("Failed to register RNIC")

			return &controller_agent.AgentRegistrationResponse{
				Success: false,
				Message: "Failed to register RNIC: " + err.Error(),
			}, nil
		}
	}

	return &controller_agent.AgentRegistrationResponse{
		Success: true,
		Message: "Successfully registered agent",
	}, nil
}

// GetPinglist gets a pinglist for an agent
func (s *ControllerService) GetPinglist(
	ctx context.Context,
	req *controller_agent.PinglistRequest,
) (*controller_agent.PinglistResponse, error) {
	log.Info().
		Str("rnicGID", req.RequesterRnic.Gid).
		Str("type", req.Type.String()).
		Msg("Pinglist request")

	// Generate pinglist
	targets, err := s.pingLister.GeneratePinglist(ctx, req.RequesterRnic, req.Type)
	if err != nil {
		log.Error().Err(err).
			Str("rnicGID", req.RequesterRnic.Gid).
			Str("type", req.Type.String()).
			Msg("Failed to generate pinglist")

		return nil, status.Errorf(codes.Internal, "failed to generate pinglist: %v", err)
	}

	// Return pinglist with probe interval and timeout
	return &controller_agent.PinglistResponse{
		Targets:         targets,
		ProbeIntervalMs: 1000, // Default 1 second
		TimeoutMs:       500,  // Default 500 ms
	}, nil
}

// GetTargetRnicInfo gets RNIC info for a target
func (s *ControllerService) GetTargetRnicInfo(
	ctx context.Context,
	req *controller_agent.TargetRnicInfoRequest,
) (*controller_agent.TargetRnicInfoResponse, error) {
	log.Info().
		Str("targetIP", req.TargetIp).
		Str("targetGID", req.TargetGid).
		Msg("Target RNIC info request")

	// Get RNIC info from registry
	rnic, err := s.registry.GetRNICInfo(ctx, req.TargetIp, req.TargetGid)
	if err != nil {
		log.Error().Err(err).
			Str("targetIP", req.TargetIp).
			Str("targetGID", req.TargetGid).
			Msg("Failed to get RNIC info")

		return &controller_agent.TargetRnicInfoResponse{
			Success: false,
			Message: "Failed to get RNIC info: " + err.Error(),
		}, nil
	}

	// Check if RNIC was found
	if rnic == nil {
		log.Warn().
			Str("targetIP", req.TargetIp).
			Str("targetGID", req.TargetGid).
			Msg("RNIC not found")

		return &controller_agent.TargetRnicInfoResponse{
			Success: false,
			Message: "RNIC not found",
		}, nil
	}

	// Return RNIC info
	return &controller_agent.TargetRnicInfoResponse{
		Success:    true,
		Message:    "RNIC found",
		TargetRnic: rnic,
	}, nil
}
