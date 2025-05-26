package pinglist

import (
	"context"
	"math/rand"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/controller/registry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// PingLister generates pinglists for agents
type PingLister struct {
	registry *registry.RnicRegistry
	rand     *rand.Rand
}

// NewPingLister creates a new ping lister
func NewPingLister(registry *registry.RnicRegistry) *PingLister {
	// Initialize random number generator with a seed
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	return &PingLister{
		registry: registry,
		rand:     rng,
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
	for i, rnic := range rnics {
		// Skip the requester RNIC
		if rnic.Gid == requesterRnic.Gid {
			continue
		}

		// Create target with source-destination mapping and requester-specific 5-tuple details
		targets = append(targets, &controller_agent.PingTarget{
			TargetRnic: rnic,
			SourceRnic: requesterRnic, // Explicit source RNIC information
			SourcePort: p.generateRequesterSpecificPort(requesterRnic.Gid, rnic.Gid),
			FlowLabel:  p.generateRequesterSpecificFlowLabel(requesterRnic.Gid, rnic.Gid, i),
			Priority:   p.generateRequesterSpecificPriority(requesterRnic.Gid, rnic.Gid),
		})
	}

	log.Info().
		Str("requesterGID", requesterRnic.Gid).
		Str("torID", requesterRnic.TorId).
		Int("targetCount", len(targets)).
		Msg("Generated ToR-mesh pinglist")

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
	for i, rnic := range rnics {
		// Create target with source-destination mapping and requester-specific 5-tuple details
		targets = append(targets, &controller_agent.PingTarget{
			TargetRnic: rnic,
			SourceRnic: requesterRnic, // Explicit source RNIC information
			SourcePort: p.generateRequesterSpecificPort(requesterRnic.Gid, rnic.Gid),
			FlowLabel:  p.generateRequesterSpecificFlowLabel(requesterRnic.Gid, rnic.Gid, i),
			Priority:   p.generateRequesterSpecificPriority(requesterRnic.Gid, rnic.Gid),
		})
	}

	log.Info().
		Str("requesterGID", requesterRnic.Gid).
		Str("excludeTorID", requesterRnic.TorId).
		Int("targetCount", len(targets)).
		Msg("Generated Inter-ToR pinglist")

	return targets, nil
}

// generateRandomPort generates a random port number in the ephemeral range
func (p *PingLister) generateRandomPort() uint32 {
	// Use ephemeral port range (49152-65535)
	return uint32(p.rand.Intn(16384) + 49152)
}

// generateRandomFlowLabel generates a random IPv6 flow label
func (p *PingLister) generateRandomFlowLabel() uint32 {
	// Flow label is 20 bits (0-1048575)
	return uint32(p.rand.Intn(1048576))
}

// generateRandomPriority generates a random priority value
func (p *PingLister) generateRandomPriority() uint32 {
	// Priority is typically 0-7 for IPv6 traffic class
	return uint32(p.rand.Intn(8))
}

// generateRequesterSpecificPort generates a port number specific to the requester-target pair
func (p *PingLister) generateRequesterSpecificPort(requesterGID, targetGID string) uint32 {
	// Create a deterministic but unique port based on requester and target GIDs
	hash := p.hashGIDPair(requesterGID, targetGID)
	// Use ephemeral port range (49152-65535)
	return uint32((hash % 16384) + 49152)
}

// generateRequesterSpecificFlowLabel generates a flow label specific to the requester-target pair
func (p *PingLister) generateRequesterSpecificFlowLabel(requesterGID, targetGID string, index int) uint32 {
	// Create a deterministic but unique flow label based on requester GID, target GID, and index
	hash := p.hashGIDPair(requesterGID, targetGID)
	// Add index to ensure uniqueness within the same requester-target relationship
	hash = hash + uint32(index)*1000
	// Flow label is 20 bits (0-1048575)
	return hash % 1048576
}

// generateRequesterSpecificPriority generates a priority specific to the requester-target pair
func (p *PingLister) generateRequesterSpecificPriority(requesterGID, targetGID string) uint32 {
	// Create a deterministic but unique priority based on requester and target GIDs
	hash := p.hashGIDPair(requesterGID, targetGID)
	// Priority is typically 0-7 for IPv6 traffic class
	return hash % 8
}

// hashGIDPair creates a hash from two GID strings for deterministic but unique values
func (p *PingLister) hashGIDPair(gid1, gid2 string) uint32 {
	// Simple hash function combining two GID strings
	combined := gid1 + ":" + gid2
	hash := uint32(0)
	for _, char := range combined {
		hash = hash*31 + uint32(char)
	}
	return hash
}
