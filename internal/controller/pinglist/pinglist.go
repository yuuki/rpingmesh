package pinglist

import (
	"context"
	"hash/fnv"
	"math/rand/v2"
	"sort"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
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
	// GetRNICByGID returns the requester's active registry row, or nil when
	// it is not registered. Its hostname drives same-host filtering (nil
	// falls back to GID self-exclusion) and its plane_id the plane
	// restriction (see resolveRequester).
	GetRNICByGID(ctx context.Context, gid string) (*controller_agent.RnicInfo, error)
}

// DefaultUnspecifiedMeshMaxTargets is the fallback cap on ToR-mesh targets
// generated for the untagged (empty tor_id) bucket. It mirrors
// config.DefaultUnspecifiedMeshMaxTargets. 0 means unlimited.
const DefaultUnspecifiedMeshMaxTargets = 32

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
	// unspecifiedMeshMax caps ToR-mesh targets when the requester's ToR is
	// unset (empty). 0 means unlimited. Named ToR-mesh is never capped.
	unspecifiedMeshMax int
}

// NewPinglistGenerator creates a new PinglistGenerator backed by the given
// RNIC source. The ECMP config sizes how many distinct flow labels each
// target is probed with (Eq.(1) coverage), computed once here.
// interTorSampleSize caps distinct foreign ToRs per inter-ToR pinglist; a
// non-positive value falls back to DefaultInterTorSampleSize.
// unspecifiedMeshMax caps ToR-mesh size for the untagged bucket only; 0
// means unlimited, and a negative value falls back to
// DefaultUnspecifiedMeshMaxTargets.
func NewPinglistGenerator(registry RnicSource, ecmp ECMPConfig, interTorSampleSize, unspecifiedMeshMax int) *PinglistGenerator {
	if interTorSampleSize <= 0 {
		interTorSampleSize = DefaultInterTorSampleSize
	}
	if unspecifiedMeshMax < 0 {
		unspecifiedMeshMax = DefaultUnspecifiedMeshMaxTargets
	}
	return &PinglistGenerator{
		registry: registry,
		flowLabelCount: ComputeFlowLabelCount(
			ecmp.PathsAssumed,
			ecmp.CoverageProbability,
			ecmp.MaxFlowLabels,
		),
		interTorSampleSize: interTorSampleSize,
		unspecifiedMeshMax: unspecifiedMeshMax,
	}
}

// Sources of a requester's plane, reported in pinglist logs.
const (
	planeSourceRegistry = "registry"
	planeSourceRequest  = "request"
	planeSourceNone     = "none"
)

// requesterContext bundles the per-request filtering criteria derived once for
// a pinglist request: the hostname the requester is registered under ("" when
// it is not registered, which disables same-host filtering), the requester
// GID's address family, and the requester's plane ("" = no plane restriction).
type requesterContext struct {
	gid         string
	hostname    string
	family      string
	plane       string
	planeSource string
}

// resolveRequester derives the requester's filtering criteria from its
// registry row. A lookup failure degrades to GID-based self-exclusion (empty
// hostname) rather than failing the request: pinglist generation is
// best-effort, and self-exclusion still prevents the requester from probing
// itself. The address family is derived directly from the requester GID string.
//
// The plane is the one registered for requester_gid when non-empty, and
// otherwise requestPlane (PinglistRequest.plane_id). The registry is preferred
// because targets are classified by their registered planes too, so both
// sides of the comparison come from the same source; the request value only
// covers a requester that is not (yet) registered or whose row predates plane
// support (written by an older controller and not yet refreshed by a
// heartbeat), which would otherwise go unrestricted.
func (g *PinglistGenerator) resolveRequester(ctx context.Context, requesterGID, requestPlane string) requesterContext {
	rc := requesterContext{
		gid:    requesterGID,
		family: probe.GIDFamily(requesterGID),
	}
	row, err := g.registry.GetRNICByGID(ctx, requesterGID)
	if err != nil {
		log.Warn().Err(err).Str("requesterGID", requesterGID).
			Msg("Failed to look up requester RNIC; falling back to GID self-exclusion and the requested plane")
		row = nil
	}
	if row != nil {
		rc.hostname = row.GetHostName()
	}
	switch {
	case row != nil && probe.CanonicalPlaneID(row.GetPlaneId()) != "":
		rc.plane, rc.planeSource = probe.CanonicalPlaneID(row.GetPlaneId()), planeSourceRegistry
	case probe.CanonicalPlaneID(requestPlane) != "":
		rc.plane, rc.planeSource = probe.CanonicalPlaneID(requestPlane), planeSourceRequest
	default:
		rc.planeSource = planeSourceNone
	}
	return rc
}

// samePlane reports whether target may be paired with the requester under the
// plane restriction: always when the requester's plane is unknown (empty),
// otherwise only when the target is registered on the same plane. Targets with
// an empty plane are excluded for a requester with a plane, since nothing says
// they are reachable from it.
func (rc requesterContext) samePlane(target *controller_agent.RnicInfo) bool {
	return rc.plane == "" || probe.CanonicalPlaneID(target.GetPlaneId()) == rc.plane
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
// dropped (issue #41). When torID is empty (untagged agents), targets are
// restricted to the requester's plane (see resolveRequester; no restriction
// when it has none) and the result is additionally capped at
// unspecifiedMeshMax (0 = unlimited) after a shuffle so an omitted fleet-wide
// ToR setting cannot become an N² mesh. Named ToR-mesh is neither
// plane-restricted nor capped: RNICs under one leaf share its plane, so a ToR
// mixing planes is a configuration error and is logged as one. Each target
// carries deterministic 5-tuple values derived from the requester-target GID
// pair. requestPlane is PinglistRequest.plane_id.
func (g *PinglistGenerator) GenerateTorMeshPinglist(
	ctx context.Context,
	requesterGID, torID, requestPlane string,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := g.registry.GetRNICsByToR(ctx, torID)
	if err != nil {
		return nil, err
	}

	rc := g.resolveRequester(ctx, requesterGID, requestPlane)
	unspecified := probe.CanonicalTorID(torID) == ""
	if !unspecified {
		warnMixedPlanes(torID, rnics)
	}

	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		if !rc.shouldProbe(rnic) {
			continue
		}
		if unspecified && !rc.samePlane(rnic) {
			continue
		}
		targets = append(targets, g.buildPingTarget(requesterGID, rnic, controller_agent.PinglistType_TOR_MESH))
	}

	if unspecified && g.unspecifiedMeshMax > 0 && len(targets) > g.unspecifiedMeshMax {
		eligible := len(targets)
		rand.Shuffle(len(targets), func(i, j int) {
			targets[i], targets[j] = targets[j], targets[i]
		})
		targets = targets[:g.unspecifiedMeshMax]
		log.Warn().
			Str("requesterGID", requesterGID).
			Str("planeID", rc.plane).
			Int("kept", len(targets)).
			Int("eligible", eligible).
			Int("cap", g.unspecifiedMeshMax).
			Msg("Capped untagged ToR-mesh pinglist")
	}

	log.Info().
		Str("requesterGID", requesterGID).
		Str("torID", torID).
		Str("planeID", rc.plane).
		Str("planeSource", rc.planeSource).
		Int("targetCount", len(targets)).
		Msg("Generated ToR-mesh pinglist")

	return targets, nil
}

// GenerateInterTorPinglist returns PingTargets sampled from ToRs other than the
// requester's own: at most one representative RNIC per foreign ToR, up to
// interTorSampleSize ToRs. Same-host (issue #39, for rail-optimized fabrics
// where a host's NICs register under different ToR IDs), cross-address-family
// (issue #41), and, when the requester has a plane, cross-plane RNICs are
// filtered out BEFORE sampling, so a foreign ToR is only dropped from coverage
// when it has no valid representative for this requester, and the sampled
// ToRs are all on the requester's plane (rail). Each target carries
// deterministic 5-tuple values. requestPlane is PinglistRequest.plane_id.
func (g *PinglistGenerator) GenerateInterTorPinglist(
	ctx context.Context,
	requesterGID, torID, requestPlane string,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := g.registry.GetActiveRNICsInOtherToRs(ctx, torID)
	if err != nil {
		return nil, err
	}

	rc := g.resolveRequester(ctx, requesterGID, requestPlane)

	// Rows arrive in random order, so picking the first valid RNIC per ToR
	// yields a randomly-varying representative and ToR set across calls.
	seenToRs := make(map[string]bool, g.interTorSampleSize)
	targets := make([]*controller_agent.PingTarget, 0, g.interTorSampleSize)
	for _, rnic := range rnics {
		if !rc.shouldProbe(rnic) || !rc.samePlane(rnic) {
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
		Str("planeID", rc.plane).
		Str("planeSource", rc.planeSource).
		Int("targetCount", len(targets)).
		Msg("Generated Inter-ToR pinglist")

	return targets, nil
}

// warnMixedPlanes logs a warning when the RNICs registered under one named ToR
// report more than one non-empty plane. A leaf switch belongs to exactly one
// plane, so this means a wrong plane_id/device_plane_ids or ToR mapping. The
// ToR-mesh is still generated unrestricted (as without planes). RNICs with an
// empty plane are ignored, so a partially upgraded fleet does not warn.
func warnMixedPlanes(torID string, rnics []*controller_agent.RnicInfo) {
	planes := make(map[string]struct{})
	for _, rnic := range rnics {
		if p := probe.CanonicalPlaneID(rnic.GetPlaneId()); p != "" {
			planes[p] = struct{}{}
		}
	}
	if len(planes) < 2 {
		return
	}
	list := make([]string, 0, len(planes))
	for p := range planes {
		list = append(list, p)
	}
	sort.Strings(list)
	log.Warn().
		Str("torID", torID).
		Strs("planeIDs", list).
		Msg("RNICs of one ToR report different planes; check plane_id/device_plane_ids and the ToR mapping")
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
		TargetNetdev:     rnic.GetNetdev(),
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
