package controller

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/internal/controller/registry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// Service implements the ControllerService gRPC service
type Service struct {
	controller_agent.UnimplementedControllerServiceServer
	registry   *registry.RnicRegistry
	pingLister *pinglist.PingLister
}

// NewService creates a new controller service
func NewService(registry *registry.RnicRegistry, pingLister *pinglist.PingLister) *Service {
	return &Service{
		registry:   registry,
		pingLister: pingLister,
	}
}

// RegisterAgent registers an agent with the controller
func (s *Service) RegisterAgent(ctx context.Context, req *controller_agent.AgentRegistrationRequest) (*controller_agent.AgentRegistrationResponse, error) {
	log.Info().
		Str("agentID", req.AgentId).
		Str("agentIP", req.AgentIp).
		Int("rnics", len(req.Rnics)).
		Msg("Agent registration request")

	// Register RNICs in registry
	for _, rnic := range req.Rnics {
		if err := s.registry.RegisterRNIC(ctx, req.AgentId, req.AgentIp, rnic); err != nil {
			log.Error().
				Err(err).
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
		Message: "Registration successful",
	}, nil
}

// GetPinglist returns a pinglist for an agent
func (s *Service) GetPinglist(ctx context.Context, req *controller_agent.PinglistRequest) (*controller_agent.PinglistResponse, error) {
	log.Info().
		Str("requesterGID", req.RequesterRnic.Gid).
		Str("type", req.Type.String()).
		Msg("Pinglist request")

	// Get pinglist based on type
	targets, err := s.pingLister.GeneratePinglist(ctx, req.RequesterRnic, req.Type)
	if err != nil {
		log.Error().
			Err(err).
			Str("requesterGID", req.RequesterRnic.Gid).
			Str("type", req.Type.String()).
			Msg("Failed to generate pinglist")

		return &controller_agent.PinglistResponse{
			Targets:         []*controller_agent.PingTarget{},
			ProbeIntervalMs: 1000, // Default 1s interval
			TimeoutMs:       5000, // Default 5s timeout
		}, nil
	}

	return &controller_agent.PinglistResponse{
		Targets:         targets,
		ProbeIntervalMs: 1000, // Default 1s interval
		TimeoutMs:       5000, // Default 5s timeout
	}, nil
}

// GetTargetRnicInfo returns RNIC info for a target IP or GID
func (s *Service) GetTargetRnicInfo(ctx context.Context, req *controller_agent.TargetRnicInfoRequest) (*controller_agent.TargetRnicInfoResponse, error) {
	log.Info().
		Str("targetIP", req.TargetIp).
		Str("targetGID", req.TargetGid).
		Msg("Target RNIC info request")

	// Query registry for RNIC info
	rnicInfo, err := s.registry.GetRNICInfo(ctx, req.TargetIp, req.TargetGid)
	if err != nil {
		log.Error().
			Err(err).
			Str("targetIP", req.TargetIp).
			Str("targetGID", req.TargetGid).
			Msg("Failed to get RNIC info")

		return &controller_agent.TargetRnicInfoResponse{
			Success: false,
			Message: "Failed to get RNIC info: " + err.Error(),
		}, nil
	}

	if rnicInfo == nil {
		return &controller_agent.TargetRnicInfoResponse{
			Success: false,
			Message: "RNIC not found",
		}, nil
	}

	return &controller_agent.TargetRnicInfoResponse{
		Success:  true,
		RnicInfo: rnicInfo,
	}, nil
}
