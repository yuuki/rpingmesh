package pinglist

import "math"

// ECMPConfig parameterizes how many distinct flow labels the controller asks
// an agent to probe each target with, so that the target's set of
// equal-cost (ECMP) paths is covered with a target probability.
//
// These come from controller configuration:
//   - PathsAssumed          -> ecmp_paths_assumed        (m)
//   - CoverageProbability    -> ecmp_coverage_probability (p)
//   - MaxFlowLabels          -> ecmp_max_flow_labels      (hard cap on n)
type ECMPConfig struct {
	// PathsAssumed is the assumed number of equal-probability ECMP paths (m)
	// between any prober and target. It cannot be measured from the agent, so
	// it is an operator-supplied fabric-width assumption.
	PathsAssumed int
	// CoverageProbability is the desired probability p (0 < p < 1) that all m
	// paths are exercised by the generated flow-label set.
	CoverageProbability float64
	// MaxFlowLabels caps n to bound probe amplification: n distinct labels
	// share one target's probe budget, but a large n still costs memory and
	// slows per-label revisit cadence, so we never exceed this ceiling.
	MaxFlowLabels int
}

// DefaultECMP* mirror the controller config defaults so the two stay in sync
// without the config package importing this one.
const (
	DefaultECMPPathsAssumed        = 16
	DefaultECMPCoverageProbability = 0.9
	DefaultECMPMaxFlowLabels       = 64
)

// ComputeFlowLabelCount returns n, the number of distinct random flow labels
// required to cover all m equal-probability ECMP paths with probability at
// least p, capped at maxLabels. It implements R-Pingmesh (SIGCOMM 2024)
// Eq.(1), a coupon-collector coverage sizing.
//
// Derivation (coupon-collector, per-path independence closed form):
//
//	Model each probe as drawing one of m paths uniformly at random. Let
//	q = (m-1)/m be the probability a probe MISSES a given path. After n
//	independent draws, that path is still uncovered with probability q^n, so
//	it is covered with probability (1 - q^n). Treating the m paths' coverage
//	events as independent (a standard, slightly conservative closed form —
//	the true events are negatively correlated, so this never underestimates
//	the labels needed), the probability that ALL m paths are covered is
//	approximately:
//
//	    P(cover all) ≈ (1 - q^n)^m
//
//	Requiring P(cover all) >= p and solving for n:
//
//	    (1 - q^n)^m >= p
//	    1 - q^n     >= p^(1/m)
//	    q^n         <= 1 - p^(1/m)
//	    n           >= ln(1 - p^(1/m)) / ln(q)          [ln(q) < 0 flips >=]
//
//	giving  n = ceil( ln(1 - p^(1/m)) / ln((m-1)/m) ).
//
//	This agrees to within one probe with the strict union bound
//	P(cover all) >= 1 - m*q^n (which yields n = ceil(ln((1-p)/m)/ln(q))); we
//	use the closed form above as directed. At the defaults (m=16, p=0.9) both
//	give ~78, so the MaxFlowLabels cap (64) is the binding constraint and the
//	choice between the two forms is immaterial.
//
// Edge cases:
//   - m <= 1: a single path is covered by any one label -> n = 1.
//   - p <= 0: coverage is trivially satisfied -> n = 1.
//   - p >= 1: exact certainty is unreachable by random sampling -> cap.
//   - result is always clamped to [1, maxLabels].
func ComputeFlowLabelCount(m int, p float64, maxLabels int) uint32 {
	if maxLabels < 1 {
		maxLabels = 1
	}
	// With one (or zero) assumed path, a single flow label already covers it.
	if m <= 1 {
		return 1
	}
	// Non-positive coverage targets are trivially met by one label.
	if p <= 0 {
		return 1
	}
	// p >= 1 makes 1 - p^(1/m) <= 0 and ln() undefined/-Inf; certainty is not
	// achievable via random sampling, so fall back to the amplification cap.
	if p >= 1 {
		return uint32(maxLabels)
	}

	mf := float64(m)
	q := (mf - 1) / mf // per-probe miss probability
	numerator := math.Log(1 - math.Pow(p, 1/mf))
	denominator := math.Log(q) // < 0 for m >= 2

	n := math.Ceil(numerator / denominator)

	// Guard against NaN/Inf from floating-point extremes; clamp into range.
	if math.IsNaN(n) || n < 1 {
		n = 1
	}
	if n > float64(maxLabels) {
		n = float64(maxLabels)
	}
	return uint32(n)
}
