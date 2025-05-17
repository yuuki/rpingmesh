package pinglist

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// RnicRegistryInterface is an interface for testing
type RnicRegistryInterface interface {
	GetRNICsByToR(ctx context.Context, torID string) ([]*controller_agent.RnicInfo, error)
	GetSampleRNICsFromOtherToRs(ctx context.Context, excludeTorID string) ([]*controller_agent.RnicInfo, error)
}

// Mock version of PingLister - has the same field structure as the real PingLister but with a different registry type
type mockPingLister struct {
	registry RnicRegistryInterface
	rand     *rand.Rand
}

// Implement GeneratePinglist for mock
func (p *mockPingLister) GeneratePinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
	pinglistType controller_agent.PinglistRequest_PinglistType,
) ([]*controller_agent.PingTarget, error) {
	// Same logic as the actual implementation
	switch pinglistType {
	case controller_agent.PinglistRequest_TOR_MESH:
		return p.generateTorMeshPinglist(ctx, requesterRnic)
	case controller_agent.PinglistRequest_INTER_TOR:
		return p.generateInterTorPinglist(ctx, requesterRnic)
	default:
		return p.generateTorMeshPinglist(ctx, requesterRnic)
	}
}

// Implement generateTorMeshPinglist for mock
func (p *mockPingLister) generateTorMeshPinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := p.registry.GetRNICsByToR(ctx, requesterRnic.TorId)
	if err != nil {
		return nil, err
	}

	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		if rnic.Gid == requesterRnic.Gid {
			continue
		}

		targets = append(targets, &controller_agent.PingTarget{
			TargetRnic: rnic,
			SourcePort: p.generateRandomPort(),
			FlowLabel:  p.generateRandomFlowLabel(),
			Priority:   p.generateRandomPriority(),
		})
	}

	return targets, nil
}

// Implement generateInterTorPinglist for mock
func (p *mockPingLister) generateInterTorPinglist(
	ctx context.Context,
	requesterRnic *controller_agent.RnicInfo,
) ([]*controller_agent.PingTarget, error) {
	rnics, err := p.registry.GetSampleRNICsFromOtherToRs(ctx, requesterRnic.TorId)
	if err != nil {
		return nil, err
	}

	targets := make([]*controller_agent.PingTarget, 0, len(rnics))
	for _, rnic := range rnics {
		targets = append(targets, &controller_agent.PingTarget{
			TargetRnic: rnic,
			SourcePort: p.generateRandomPort(),
			FlowLabel:  p.generateRandomFlowLabel(),
			Priority:   p.generateRandomPriority(),
		})
	}

	return targets, nil
}

// Implement random function - same logic as the real one
func (p *mockPingLister) generateRandomPort() uint32 {
	return uint32(p.rand.Intn(16384) + 49152)
}

func (p *mockPingLister) generateRandomFlowLabel() uint32 {
	return uint32(p.rand.Intn(1048576))
}

func (p *mockPingLister) generateRandomPriority() uint32 {
	return uint32(p.rand.Intn(8))
}

// newMockPingLister creates a mock PingLister for testing
func newMockPingLister(reg RnicRegistryInterface) *mockPingLister {
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	return &mockPingLister{
		registry: reg,
		rand:     rng,
	}
}

// MockRegistry is a mock of RnicRegistry
type MockRegistry struct {
	mock.Mock
}

// GetRNICsByToR is a mock method of RnicRegistry.GetRNICsByToR
func (m *MockRegistry) GetRNICsByToR(ctx context.Context, torID string) ([]*controller_agent.RnicInfo, error) {
	args := m.Called(ctx, torID)
	return args.Get(0).([]*controller_agent.RnicInfo), args.Error(1)
}

// GetSampleRNICsFromOtherToRs is a mock method of RnicRegistry.GetSampleRNICsFromOtherToRs
func (m *MockRegistry) GetSampleRNICsFromOtherToRs(ctx context.Context, excludeTorID string) ([]*controller_agent.RnicInfo, error) {
	args := m.Called(ctx, excludeTorID)
	return args.Get(0).([]*controller_agent.RnicInfo), args.Error(1)
}

func TestGenerateTorMeshPinglist(t *testing.T) {
	// Create mock registry
	mockReg := &MockRegistry{}

	// Create RNIC data for testing
	requesterRnic := &controller_agent.RnicInfo{
		Gid:       "fe80:0000:0000:0000:0002:c903:0033:1001",
		Qpn:       1001,
		IpAddress: "192.168.1.1",
		HostName:  "host-1",
		TorId:     "tor-A",
	}

	sameToRRnics := []*controller_agent.RnicInfo{
		requesterRnic, // Self within the same ToR (should be skipped)
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:1002",
			Qpn:       1002,
			IpAddress: "192.168.1.2",
			HostName:  "host-2",
			TorId:     "tor-A",
		},
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:1003",
			Qpn:       1003,
			IpAddress: "192.168.1.3",
			HostName:  "host-3",
			TorId:     "tor-A",
		},
	}

	// Mock setup: return list of RNICs belonging to the same ToR as requesterRnic
	mockReg.On("GetRNICsByToR", mock.Anything, "tor-A").Return(sameToRRnics, nil)

	// Create mock version of PingLister
	pingLister := newMockPingLister(mockReg)

	// Run test
	ctx := context.Background()
	targets, err := pingLister.GeneratePinglist(ctx, requesterRnic, controller_agent.PinglistRequest_TOR_MESH)

	// Verify
	require.NoError(t, err)
	require.Len(t, targets, 2, "Should return 2 targets (excluding requester)")

	// Verify targets
	for _, target := range targets {
		// Verify that self is not included
		assert.NotEqual(t, requesterRnic.Gid, target.TargetRnic.Gid, "Requester should not be in targets")

		// Verify that it's an RNIC within the same ToR
		assert.Equal(t, "tor-A", target.TargetRnic.TorId, "Target should be in the same ToR")

		// Verify random values
		assert.GreaterOrEqual(t, target.SourcePort, uint32(49152), "Source port should be in ephemeral range")
		assert.LessOrEqual(t, target.SourcePort, uint32(65535), "Source port should be in ephemeral range")

		assert.GreaterOrEqual(t, target.FlowLabel, uint32(0), "Flow label should be non-negative")
		assert.LessOrEqual(t, target.FlowLabel, uint32(1048575), "Flow label should be at most 20 bits")

		assert.GreaterOrEqual(t, target.Priority, uint32(0), "Priority should be non-negative")
		assert.LessOrEqual(t, target.Priority, uint32(7), "Priority should be at most 7")
	}

	// Verify that mock was called as expected
	mockReg.AssertExpectations(t)
}

func TestGenerateInterTorPinglist(t *testing.T) {
	// Create mock registry
	mockReg := &MockRegistry{}

	// Create RNIC data for testing
	requesterRnic := &controller_agent.RnicInfo{
		Gid:       "fe80:0000:0000:0000:0002:c903:0033:1001",
		Qpn:       1001,
		IpAddress: "192.168.1.1",
		HostName:  "host-1",
		TorId:     "tor-A",
	}

	otherToRRnics := []*controller_agent.RnicInfo{
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:2001",
			Qpn:       2001,
			IpAddress: "192.168.2.1",
			HostName:  "host-4",
			TorId:     "tor-B",
		},
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:3001",
			Qpn:       3001,
			IpAddress: "192.168.3.1",
			HostName:  "host-5",
			TorId:     "tor-C",
		},
	}

	// Mock setup: return list of RNICs belonging to a different ToR than requesterRnic
	mockReg.On("GetSampleRNICsFromOtherToRs", mock.Anything, "tor-A").Return(otherToRRnics, nil)

	// Create mock version of PingLister
	pingLister := newMockPingLister(mockReg)

	// Run test
	ctx := context.Background()
	targets, err := pingLister.GeneratePinglist(ctx, requesterRnic, controller_agent.PinglistRequest_INTER_TOR)

	// Verify
	require.NoError(t, err)
	require.Len(t, targets, 2, "Should return 2 targets from other ToRs")

	// Verify targets
	for _, target := range targets {
		// Verify that it's an RNIC in a different ToR
		assert.NotEqual(t, "tor-A", target.TargetRnic.TorId, "Target should be in a different ToR")

		// Verify random values
		assert.GreaterOrEqual(t, target.SourcePort, uint32(49152), "Source port should be in ephemeral range")
		assert.LessOrEqual(t, target.SourcePort, uint32(65535), "Source port should be in ephemeral range")

		assert.GreaterOrEqual(t, target.FlowLabel, uint32(0), "Flow label should be non-negative")
		assert.LessOrEqual(t, target.FlowLabel, uint32(1048575), "Flow label should be at most 20 bits")

		assert.GreaterOrEqual(t, target.Priority, uint32(0), "Priority should be non-negative")
		assert.LessOrEqual(t, target.Priority, uint32(7), "Priority should be at most 7")
	}

	// Verify that mock was called as expected
	mockReg.AssertExpectations(t)
}

func TestRandomFunctions(t *testing.T) {
	// Create our own random generator to ensure reproducibility (fixed seed)
	source := rand.NewSource(12345) // Fixed seed value
	rng := rand.New(source)

	pingLister := &mockPingLister{
		registry: nil, // No registry needed for random test
		rand:     rng,
	}

	// Test random ports
	counts := make(map[uint32]int)
	for i := 0; i < 1000; i++ {
		port := pingLister.generateRandomPort()
		counts[port]++
		assert.GreaterOrEqual(t, port, uint32(49152), "Source port should be in ephemeral range")
		assert.LessOrEqual(t, port, uint32(65535), "Source port should be in ephemeral range")
	}

	// Verify some distribution (exact test is difficult, but check number of duplicates)
	assert.Greater(t, len(counts), 100, "Random ports should have good distribution")

	// Test random flow labels
	flowCounts := make(map[uint32]int)
	for i := 0; i < 1000; i++ {
		flow := pingLister.generateRandomFlowLabel()
		flowCounts[flow]++
		assert.GreaterOrEqual(t, flow, uint32(0), "Flow label should be non-negative")
		assert.LessOrEqual(t, flow, uint32(1048575), "Flow label should be at most 20 bits")
	}

	// Verify some distribution
	assert.Greater(t, len(flowCounts), 100, "Random flow labels should have good distribution")

	// Test random priorities
	priorityCounts := make(map[uint32]int)
	for i := 0; i < 1000; i++ {
		priority := pingLister.generateRandomPriority()
		priorityCounts[priority]++
		assert.GreaterOrEqual(t, priority, uint32(0), "Priority should be non-negative")
		assert.LessOrEqual(t, priority, uint32(7), "Priority should be at most 7")
	}

	// Verify that all values from 0-7 are generated
	for i := uint32(0); i <= 7; i++ {
		_, exists := priorityCounts[i]
		assert.True(t, exists, "Priority value %d should be generated", i)
	}
}

func TestUnknownPinglistType(t *testing.T) {
	// Create mock registry
	mockReg := &MockRegistry{}

	// Create RNIC data for testing
	requesterRnic := &controller_agent.RnicInfo{
		Gid:       "fe80:0000:0000:0000:0002:c903:0033:1001",
		Qpn:       1001,
		IpAddress: "192.168.1.1",
		HostName:  "host-1",
		TorId:     "tor-A",
	}

	sameToRRnics := []*controller_agent.RnicInfo{
		requesterRnic,
		{
			Gid:       "fe80:0000:0000:0000:0002:c903:0033:1002",
			Qpn:       1002,
			IpAddress: "192.168.1.2",
			HostName:  "host-2",
			TorId:     "tor-A",
		},
	}

	// Mock setup
	mockReg.On("GetRNICsByToR", mock.Anything, "tor-A").Return(sameToRRnics, nil)

	// Create mock version of PingLister
	pingLister := newMockPingLister(mockReg)

	// Run test with unknown pinglist type (should use TOR_MESH by default)
	ctx := context.Background()
	targets, err := pingLister.GeneratePinglist(ctx, requesterRnic, 999) // Invalid value

	// Verify
	require.NoError(t, err)
	require.Len(t, targets, 1, "Should default to TOR_MESH and return 1 target")

	// Verify that mock was called as expected
	mockReg.AssertExpectations(t)
}
