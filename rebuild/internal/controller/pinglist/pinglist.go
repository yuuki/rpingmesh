package pinglist

import (
	"context"
	"hash/fnv"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// DefaultInterTorSampleSize is the fallback number of distinct foreign ToRs
// sampled for an inter-ToR pinglist when NewPinglistGenerator is given a
// non-positive size. It mirrors config.DefaultInterTorSampleSize.
const DefaultInterTorSampleSize = 5

// RnicSource is the subset of registry.RnicRegistry's read API required to
// generate pinglists. It is declared here, at the point of use, so that
// PinglistGenerator can be unit tested against a fake instead of a real
// rqlite-backed registry.
type RnicSource interface {
	GetRNICsByToR(ctx context.Context, torID string) ([]*controller_agent.RnicInfo, error)
	// GetActiveRNICsInOtherToRs returns all active RNICs in ToRs other than
	// excludeTorID, in random order. The generator - not the registry -
	// samples one representative per ToR, after same-host / same-family
	// filtering, so coverage is preserved (see GenerateInterTorPinglist).
	GetActiveRNICsInOtherToRs(ctx context.Context, excludeTorID string) ([]*controller_agent.RnicInfo, error)
	// ResolveHostnameByGID returns the hostname the requester GID is
	// registered under, or "" when it is not registered (disabling same-host
	// filtering and falling back to GID self-exclusion).
	ResolveHostnameByGID(ctx context.Context, gid string) (string, error)
}

// PinglistGenerator generates probe target lists for agents.
type PinglistGenerator struct {
	registry RnicSource
	// flowLabelCount is the number of distinct ECMP flow labels each target
	// should be probed with, computed once from the ECMP config via
	// ComputeFlowLabelCount (R-Pingmesh Eq.(1)). It is stamped into every
	// PingTarget; the agent expands seed+count into the concrete label set.
	flowLabelCount uint32
	// interTorSampleSize caps the number of distinct foreign ToRs sampled for
	// an inter-ToR pinglist. Sampling lives here (not in the registry) because
	// it must run after same-host / same-family filtering to keep coverage.
	interTorSampleSize int
}

// NewPinglistGenerator creates a new PinglistGenerator backed by the given
// RNIC source. The ECMP config sizes how many distinct flow labels each
// target is probed with (Eq.(1) coverage), computed once here.
// interTorSampleSize caps distinct foreign ToRs per inter-ToR pinglist; a
// non-positive value falls back to DefaultInterTorSampleSize.
func NewPinglistGenerator(registry RnicSource, ecmp ECMPConfig, interTorSampleSize int) *PinglistGenerator {
	if interTorSampleSize <= 0 {
		interTorSampleSize = DefaultInterTorSampleSize
	}
	return &PinglistGenerator{
		registry: registry,
		flowLabelCount: ComputeFlowLabelCount(
			ecmp.PathsAssumed,
			ecmp.CoverageProbability,
			ecmp.MaxFlowLabels,
		),
		interTorSampleSize: interTorSampleSize,
	}
}

// requesterContext bundles the per-request filtering criteria derived once for
// a pinglist request: the hostname the requester is registered under ("" when
// it is not registered, which disables same-host filtering) and the requester
// GID's address family.
type requesterContext struct {
	gid      string
	hostname string
	family   string
}

// resolveRequester derives the requester's same-host / same-family filtering
// criteria. A hostname-lookup failure degrades to GID-based self-exclusion
// (empty hostname) rather than failing the request: pinglist generation is
// best-effort, and self-exclusion still prevents the requester from probing
// itself. The address family is derived directly from the requester GID string.
func (g *PinglistGenerator) resolveRequester(ctx context.Context, requesterGID string) requesterContext {
	hostname, err := g.registry.ResolveHostnameByGID(ctx, requesterGID)
	if err != nil {
		log.Warn().Err(err).Str("requesterGID", requesterGID).
			Msg("Failed to resolve requester hostname; falling back to GID self-exclusion only")
		hostname = ""
	}
	return requesterContext{
		gid:      requesterGID,
		hostname: hostname,
		family:   probe.GIDFamily(requesterGID),
	}
}

// shouldProbe reports whether the requester should probe the given target RNIC.
// It applies, in order:
//   - self / same-host exclusion (issue #39): skip the requester's own RNIC and
//     every RNIC on the same host. When the requester's hostname is known, all
//     of its host's RNICs are matched by hostname; the GID check additionally
//     covers the fallback case where the requester is unregistered (hostname
//     unknown) so at least its own RNIC is still excluded. Same-host probes can
//     hairpin without reaching the fabric, so their RTTs would skew ToR-level
//     aggregates while telling nothing about the network.
//   - same-address-family requirement (issue #41): skip targets whose GID
//     address family differs from the requester's. A cross-family probe fails
//     at ibv_create_ah() (route lookup) before reaching the wire, so pairing
//     them would retry-and-fail forever and inflate probe_failed_total.
func (rc requesterContext) shouldProbe(target *controller_agent.RnicInfo) bool {
	if target.GetGid() == rc.gid {
		return false
	}
	if rc.hostname != "" && target.GetHostName() == rc.hostname {
		return false
	}
	return probe.GIDFamily(target.GetGid()) == rc.family
}

// GenerateTorMeshPinglist returns PingTargets for the RNICs in the same ToR
// that the requester should probe: its own RNIC and every other RNIC on the
// same host are excluded (issue #39), and cross-address-family targets are
// dropped (issue #41). Each target carries deterministic 5-tuple values derived
// from the requester-target GID pair.
func (g *PinglistGenerator) GenerateTorMeshPinglist(
	ctx context.Context,
	requesterGID, torID string,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := g.registry.GetRNICsByToR(ctx, torID)
	if err != nil {
		return nil, err
	}

	rc := g.resolveRequester(ctx, requesterGID)

	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		if !rc.shouldProbe(rnic) {
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

// GenerateInterTorPinglist returns PingTargets sampled from ToRs other than the
// requester's own: at most one representative RNIC per foreign ToR, up to
// interTorSampleSize ToRs. Same-host (issue #39, for rail-optimized fabrics
// where a host's NICs register under different ToR IDs) and cross-address-family
// (issue #41) RNICs are filtered out BEFORE sampling, so a foreign ToR is only
// dropped from coverage when it has no valid representative for this requester.
// Each target carries deterministic 5-tuple values.
func (g *PinglistGenerator) GenerateInterTorPinglist(
	ctx context.Context,
	requesterGID, torID string,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := g.registry.GetActiveRNICsInOtherToRs(ctx, torID)
	if err != nil {
		return nil, err
	}

	rc := g.resolveRequester(ctx, requesterGID)

	// Rows arrive in random order, so picking the first valid RNIC per ToR
	// yields a randomly-varying representative and ToR set across calls.
	seenToRs := make(map[string]bool, g.interTorSampleSize)
	targets := make([]*controller_agent.PingTarget, 0, g.interTorSampleSize)
	for _, rnic := range rnics {
		if !rc.shouldProbe(rnic) {
			continue
		}
		if seenToRs[rnic.GetTorId()] {
			continue
		}
		seenToRs[rnic.GetTorId()] = true
		targets = append(targets, g.buildPingTarget(requesterGID, rnic, controller_agent.PinglistType_INTER_TOR))
		if len(targets) >= g.interTorSampleSize {
			break
		}
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
