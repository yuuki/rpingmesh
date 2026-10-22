package probe

import (
	"encoding/binary"
	"hash/fnv"
)

// ECMP flow-label generation shared by the agent's prober (which expands a
// target's (seed, count) pair into the labels it cycles through) and its tests.
const (
	// FlowLabelRotateStride selects the rotating subset of a target's label
	// set: every FlowLabelRotateStride-th index (0, 5, 10, ...) mixes the
	// rotation epoch into its hash, so ~20% of the set shifts each rotation
	// period while the rest stays stable for time-series continuity. This
	// matches the R-Pingmesh paper's ~20% 5-tuple rotation.
	FlowLabelRotateStride = 5

	// FlowLabelMask is the 20-bit IPv6 flow-label field width; generated
	// labels are masked to it before reaching ibv_ah_attr.grh.flow_label.
	FlowLabelMask = 0xFFFFF

	// MaxDistinctFlowLabels caps how many labels one target's set may hold,
	// so a bad or malicious controller value can neither make the agent build
	// a huge set nor spin the dedup loop forever. 4096 labels is ~16KB per
	// target and covers even extreme Eq.(1) configurations (m=256, p=0.99
	// needs ~2600), far below the 2^20 distinct 20-bit values. The controller
	// enforces the same ceiling on ecmp_max_flow_labels
	// (config.MaxEcmpFlowLabels references this constant).
	MaxDistinctFlowLabels = 4096
)

// ClampDistinctFlowLabelCount bounds a requested flow-label count to
// MaxDistinctFlowLabels.
func ClampDistinctFlowLabelCount(count uint32) uint32 {
	return min(count, MaxDistinctFlowLabels)
}

// FlowLabelAt deterministically derives the candidate flow label for index
// within a target's set from the controller-provided seed and, for the
// rotating indices (multiples of FlowLabelRotateStride), the rotation epoch.
// attempt is a collision-resolution nonce: attempt 0 is the primary candidate
// (its bytes are omitted so the value equals a plain hash) and
// GenerateFlowLabels advances it only when a candidate collides with an
// already-chosen label. The function is pure, so the set is reproducible
// across agents.
func FlowLabelAt(seed, index uint32, rotationEpoch uint64, attempt uint32) uint32 {
	h := fnv.New32a()
	var buf [16]byte
	binary.BigEndian.PutUint32(buf[0:4], seed)
	binary.BigEndian.PutUint32(buf[4:8], index)
	n := 8
	if index%FlowLabelRotateStride == 0 {
		binary.BigEndian.PutUint64(buf[8:16], rotationEpoch)
		n = 16
	}
	_, _ = h.Write(buf[:n])
	if attempt > 0 {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], attempt)
		_, _ = h.Write(a[:])
	}
	return h.Sum32() & FlowLabelMask
}

// GenerateFlowLabels expands (seed, count) into exactly count DISTINCT 20-bit
// flow labels for rotationEpoch. A count of 0 is treated as 1 so every target
// yields at least one label.
//
// Distinctness matters because the controller sizes count via Eq.(1)
// assuming n distinct labels. Masking a 32-bit hash to 20 bits can collide,
// so each slot advances FlowLabelAt's attempt nonce until its candidate is
// new. Stable slots (index % stride != 0) are resolved before rotating ones,
// so a stable slot's dedup never depends on the epoch-varying rotating slots
// and the stable subset is byte-for-byte identical across epochs.
func GenerateFlowLabels(seed, count uint32, rotationEpoch uint64) []uint32 {
	if count == 0 {
		count = 1
	}
	count = ClampDistinctFlowLabelCount(count)
	labels := make([]uint32, count)
	used := make(map[uint32]struct{}, count)

	assign := func(i uint32) {
		for attempt := uint32(0); ; attempt++ {
			v := FlowLabelAt(seed, i, rotationEpoch, attempt)
			if _, dup := used[v]; !dup {
				used[v] = struct{}{}
				labels[i] = v
				return
			}
		}
	}
	for i := uint32(0); i < count; i++ {
		if i%FlowLabelRotateStride != 0 {
			assign(i)
		}
	}
	for i := uint32(0); i < count; i++ {
		if i%FlowLabelRotateStride == 0 {
			assign(i)
		}
	}
	return labels
}
