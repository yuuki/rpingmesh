package pinglist

import (
	"context"
	"hash/fnv"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/controller/registry"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// PinglistGenerator generates probe target lists for agents.
type PinglistGenerator struct {
	registry *registry.RnicRegistry
}

// NewPinglistGenerator creates a new PinglistGenerator backed by the given RNIC registry.
func NewPinglistGenerator(registry *registry.RnicRegistry) *PinglistGenerator {
	return &PinglistGenerator{
		registry: registry,
	}
}

// GenerateTorMeshPinglist returns PingTargets for all RNICs in the same ToR,
// excluding the requester's own RNIC. Each target carries deterministic
// 5-tuple values derived from the requester-target GID pair.
func (g *PinglistGenerator) GenerateTorMeshPinglist(
	ctx context.Context,
	requesterGID, torID string,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := g.registry.GetRNICsByToR(ctx, torID)
	if err != nil {
		return nil, err
	}

	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		// Skip the requester's own RNIC.
		if rnic.GetGid() == requesterGID {
			continue
		}

		targets = append(targets, buildPingTarget(requesterGID, rnic))
	}

	log.Info().
		Str("requesterGID", requesterGID).
		Str("torID", torID).
		Int("targetCount", len(targets)).
		Msg("Generated ToR-mesh pinglist")

	return targets, nil
}

// GenerateInterTorPinglist returns PingTargets sampled from ToRs other than
// the requester's own. Each target carries deterministic 5-tuple values.
func (g *PinglistGenerator) GenerateInterTorPinglist(
	ctx context.Context,
	requesterGID, torID string,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := g.registry.GetSampleRNICsFromOtherToRs(ctx, torID)
	if err != nil {
		return nil, err
	}

	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		targets = append(targets, buildPingTarget(requesterGID, rnic))
	}

	log.Info().
		Str("requesterGID", requesterGID).
		Str("excludeTorID", torID).
		Int("targetCount", len(targets)).
		Msg("Generated Inter-ToR pinglist")

	return targets, nil
}

// buildPingTarget creates a PingTarget from an RnicInfo with deterministic
// 5-tuple values based on the requester-target GID pair.
func buildPingTarget(requesterGID string, rnic *controller_agent.RnicInfo) *controller_agent.PingTarget {
	targetGID := rnic.GetGid()
	return &controller_agent.PingTarget{
		TargetGid:        targetGID,
		TargetQpn:        rnic.GetQpn(),
		TargetIp:         rnic.GetIpAddress(),
		TargetHostname:   rnic.GetHostName(),
		TargetTorId:      rnic.GetTorId(),
		TargetDeviceName: rnic.GetDeviceName(),
		FlowLabel:        deterministicFlowLabel(requesterGID, targetGID),
		SourcePort:       deterministicSourcePort(requesterGID, targetGID),
		Priority:         deterministicPriority(requesterGID, targetGID),
	}
}

// deterministicFlowLabel generates a deterministic flow label for ECMP path diversity.
// Uses FNV-1a 32-bit hash of requesterGID + targetGID, masked to 20 bits (0-0xFFFFF).
func deterministicFlowLabel(requesterGID, targetGID string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(requesterGID))
	h.Write([]byte(targetGID))
	return h.Sum32() & 0xFFFFF // 20-bit mask
}

// deterministicSourcePort generates a deterministic source port (metadata only).
// NOT enforced at the RDMA layer -- RoCEv2 UD source_port is driver-generated.
// Range: 49152-65535 (ephemeral ports).
func deterministicSourcePort(requesterGID, targetGID string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(requesterGID))
	h.Write([]byte("port")) // salt to differentiate from flow label hash
	h.Write([]byte(targetGID))
	return (h.Sum32() % 16384) + 49152
}

// deterministicPriority generates a deterministic priority value (0-7).
func deterministicPriority(requesterGID, targetGID string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(requesterGID))
	h.Write([]byte("prio")) // salt to differentiate from other hashes
	h.Write([]byte(targetGID))
	return h.Sum32() % 8
}
