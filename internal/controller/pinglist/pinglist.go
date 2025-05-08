package pinglist

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/controller/registry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// PingLister generates pinglists for agents
type PingLister struct {
	registry *registry.RnicRegistry
}

// NewPingLister creates a new ping lister
func NewPingLister(registry *registry.RnicRegistry) *PingLister {
	return &PingLister{
		registry: registry,
	}
}

// GeneratePinglist generates a pinglist for the requester RNIC
func (p *PingLister) GeneratePinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
	pinglistType controller_agent.PinglistRequest_PinglistType,
) ([]*controller_agent.PingTarget, error) {
	// Different pinglist generation strategies based on type
	switch pinglistType {
	case controller_agent.PinglistRequest_TOR_MESH:
		return p.generateTorMeshPinglist(ctx, requesterRnic)
	case controller_agent.PinglistRequest_INTER_TOR:
		return p.generateInterTorPinglist(ctx, requesterRnic)
	default:
		log.Warn().
			Str("type", pinglistType.String()).
			Msg("Unknown pinglist type, using TOR_MESH")
		return p.generateTorMeshPinglist(ctx, requesterRnic)
	}
}

// generateTorMeshPinglist generates a ToR-mesh pinglist
func (p *PingLister) generateTorMeshPinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
) ([]*controller_agent.PingTarget, error) {
	// Get all RNICs in the same ToR
	rnics, err := p.registry.GetRNICsByToR(ctx, requesterRnic.TorId)
	if err != nil {
		return nil, err
	}

	// Convert to ping targets
	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		// Skip the requester RNIC
		if rnic.Gid == requesterRnic.Gid {
			continue
		}

		targets = append(targets, &controller_agent.PingTarget{
			Gid:       rnic.Gid,
			Qpn:       rnic.Qpn,
			IpAddress: rnic.IpAddress,
			// Add 5-tuple details later
		})
	}

	return targets, nil
}

// generateInterTorPinglist generates an Inter-ToR pinglist
func (p *PingLister) generateInterTorPinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
) ([]*controller_agent.PingTarget, error) {
	// Get sample RNICs from other ToRs
	rnics, err := p.registry.GetSampleRNICsFromOtherToRs(ctx, requesterRnic.TorId)
	if err != nil {
		return nil, err
	}

	// Convert to ping targets
	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		targets = append(targets, &controller_agent.PingTarget{
			Gid:       rnic.Gid,
			Qpn:       rnic.Qpn,
			IpAddress: rnic.IpAddress,
			// Add 5-tuple details later
		})
	}

	return targets, nil
}
