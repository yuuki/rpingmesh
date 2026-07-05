package pinglist

import (
	"context"
	"hash/fnv"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// RnicSource is the subset of registry.RnicRegistry's read API required to
// generate pinglists. It is declared here, at the point of use, so that
// PinglistGenerator can be unit tested against a fake instead of a real
// rqlite-backed registry.
type RnicSource interface {
	GetRNICsByToR(ctx context.Context, torID string) ([]*controller_agent.RnicInfo, error)
	GetSampleRNICsFromOtherToRs(ctx context.Context, excludeTorID string) ([]*controller_agent.RnicInfo, error)
}

// PinglistGenerator generates probe target lists for agents.
type PinglistGenerator struct {
	registry RnicSource
	// flowLabelCount is the number of distinct ECMP flow labels each target
	// should be probed with, computed once from the ECMP config via
	// ComputeFlowLabelCount (R-Pingmesh Eq.(1)). It is stamped into every
	// PingTarget; the agent expands seed+count into the concrete label set.
	flowLabelCount uint32
}

// NewPinglistGenerator creates a new PinglistGenerator backed by the given
// RNIC source. The ECMP config sizes how many distinct flow labels each
// target is probed with (Eq.(1) coverage), computed once here.
func NewPinglistGenerator(registry RnicSource, ecmp ECMPConfig) *PinglistGenerator {
	return &PinglistGenerator{
		registry: registry,
		flowLabelCount: ComputeFlowLabelCount(
			ecmp.PathsAssumed,
			ecmp.CoverageProbability,
			ecmp.MaxFlowLabels,
		),
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

		targets = append(targets, g.buildPingTarget(requesterGID, rnic, controller_agent.PinglistType_TOR_MESH))
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
		targets = append(targets, g.buildPingTarget(requesterGID, rnic, controller_agent.PinglistType_INTER_TOR))
	}

	log.Info().
		Str("requesterGID", requesterGID).
		Str("excludeTorID", torID).
		Int("targetCount", len(targets)).
		Msg("Generated Inter-ToR pinglist")

	return targets, nil
}

// buildPingTarget creates a PingTarget from an RnicInfo with deterministic
// 5-tuple values based on the requester-target GID pair, plus the ECMP
// flow-label set sizing (seed + count) the agent expands into concrete labels.
// ptype records which pinglist the target came from so the agent can apply a
// differentiated, per-pinglist-type probe rate.
func (g *PinglistGenerator) buildPingTarget(requesterGID string, rnic *controller_agent.RnicInfo, ptype controller_agent.PinglistType) *controller_agent.PingTarget {
	targetGID := rnic.GetGid()
	seed := flowLabelSeed(requesterGID, targetGID)
	return &controller_agent.PingTarget{
		TargetGid:        targetGID,
		TargetQpn:        rnic.GetQpn(),
		TargetIp:         rnic.GetIpAddress(),
		TargetHostname:   rnic.GetHostName(),
		TargetTorId:      rnic.GetTorId(),
		TargetDeviceName: rnic.GetDeviceName(),
		PinglistType:     ptype,
		// FlowLabel is the legacy base label (low 20 bits of the seed), kept
		// for backward compatibility and used verbatim when FlowLabelCount<=1.
		FlowLabel: seed & 0xFFFFF,
		// FlowLabelSeed/FlowLabelCount let the agent derive FlowLabelCount
		// distinct 20-bit labels without the controller enumerating them.
		FlowLabelSeed:  seed,
		FlowLabelCount: g.flowLabelCount,
		SourcePort:     deterministicSourcePort(requesterGID, targetGID),
		Priority:       deterministicPriority(requesterGID, targetGID),
	}
}

// flowLabelSeed is the full 32-bit FNV-1a hash of requesterGID+targetGID. It
// seeds agent-side flow-label expansion; its low 20 bits double as the legacy
// single flow label (see deterministicFlowLabel).
func flowLabelSeed(requesterGID, targetGID string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(requesterGID))
	h.Write([]byte(targetGID))
	return h.Sum32()
}

// deterministicFlowLabel generates a deterministic flow label for ECMP path
// diversity: the low 20 bits (0-0xFFFFF) of flowLabelSeed. Retained so the
// legacy single-label semantics and its tests are preserved unchanged.
func deterministicFlowLabel(requesterGID, targetGID string) uint32 {
	return flowLabelSeed(requesterGID, targetGID) & 0xFFFFF // 20-bit mask
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
