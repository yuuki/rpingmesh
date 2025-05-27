package monitor

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/rdma"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// AgentStateInterface defines the interface for AgentState
type AgentStateInterface interface {
	GetHostName() string
	GetDetectedRNICs() []*rdma.RNIC
	GetRnicByGID(gid string) *rdma.RNIC
	GetLocalTorID() string
	GetSenderUDQueue(gid string) *rdma.UDQueue
}

// ProberInterface defines the interface for Prober
type ProberInterface interface {
	ProbeTarget(ctx context.Context, sourceRnic *rdma.RNIC, target *probe.PingTarget)
}

// MockAgentState is a mock implementation of AgentStateInterface
type MockAgentState struct {
	mock.Mock
}

func (m *MockAgentState) GetHostName() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAgentState) GetDetectedRNICs() []*rdma.RNIC {
	args := m.Called()
	return args.Get(0).([]*rdma.RNIC)
}

func (m *MockAgentState) GetRnicByGID(gid string) *rdma.RNIC {
	args := m.Called(gid)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*rdma.RNIC)
}

func (m *MockAgentState) GetLocalTorID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAgentState) GetSenderUDQueue(gid string) *rdma.UDQueue {
	args := m.Called(gid)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*rdma.UDQueue)
}

// MockProber is a mock implementation of ProberInterface
type MockProber struct {
	mock.Mock
	probeCount int
	mutex      sync.Mutex
}

func (m *MockProber) ProbeTarget(ctx context.Context, sourceRnic *rdma.RNIC, target *probe.PingTarget) {
	m.mutex.Lock()
	m.probeCount++
	m.mutex.Unlock()
	m.Called(ctx, sourceRnic, target)
}

func (m *MockProber) GetProbeCount() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.probeCount
}

func (m *MockProber) ResetProbeCount() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.probeCount = 0
}

// TestableClusterMonitor wraps ClusterMonitor to accept interfaces for testing
type TestableClusterMonitor struct {
	agentState         AgentStateInterface
	prober             ProberInterface
	intervalMs         uint32
	probeRatePerSecond int
	scheduler          *ProbeScheduler
	stopCh             chan struct{}
	wg                 sync.WaitGroup
	running            bool
}

// NewTestableClusterMonitor creates a new TestableClusterMonitor
func NewTestableClusterMonitor(
	agentState AgentStateInterface,
	prober ProberInterface,
	intervalMs uint32,
	probeRatePerSecond int,
) *TestableClusterMonitor {
	return &TestableClusterMonitor{
		agentState:         agentState,
		prober:             prober,
		intervalMs:         intervalMs,
		probeRatePerSecond: probeRatePerSecond,
		scheduler:          NewProbeScheduler(),
		stopCh:             make(chan struct{}),
		running:            false,
	}
}

// Start starts the testable cluster monitor
func (c *TestableClusterMonitor) Start() error {
	if c.running {
		return nil
	}

	c.running = true
	c.stopCh = make(chan struct{})

	// Start the sequential probe worker
	c.wg.Add(1)
	go c.runSequentialProbeWorker()

	return nil
}

// Stop stops the testable cluster monitor
func (c *TestableClusterMonitor) Stop() {
	if !c.running {
		return
	}

	close(c.stopCh)
	c.wg.Wait()
	c.running = false
}

// UpdatePinglist updates the list of targets to ping
func (c *TestableClusterMonitor) UpdatePinglist(pinglist []*controller_agent.PingTarget) {
	// Convert controller targets to probe targets
	probeTargets := make([]probe.PingTarget, 0, len(pinglist))
	localHostName := c.agentState.GetHostName()

	for _, target := range pinglist {
		// Skip targets without proper source or destination information
		if target.TargetRnic == nil || target.SourceRnic == nil {
			continue
		}

		// Skip targets on the same host
		if target.TargetRnic.HostName == localHostName {
			continue
		}

		// Create probe target
		probeTarget := probe.PingTarget{
			GID:              target.TargetRnic.Gid,
			QPN:              target.TargetRnic.Qpn,
			IPAddress:        target.TargetRnic.IpAddress,
			HostName:         target.TargetRnic.HostName,
			TorID:            target.TargetRnic.TorId,
			DeviceName:       target.TargetRnic.DeviceName,
			SourceRnicGID:    target.SourceRnic.Gid,
			SourceRnicQPN:    target.SourceRnic.Qpn,
			SourceRnicIP:     target.SourceRnic.IpAddress,
			SourceHostName:   target.SourceRnic.HostName,
			SourceTorID:      target.SourceRnic.TorId,
			SourceDeviceName: target.SourceRnic.DeviceName,
			SourcePort:       target.SourcePort,
			FlowLabel:        target.FlowLabel,
			Priority:         target.Priority,
		}

		probeTargets = append(probeTargets, probeTarget)
	}

	// Update the scheduler with new targets
	c.scheduler.UpdateTargets(probeTargets, c.probeRatePerSecond)
}

// runSequentialProbeWorker runs the main sequential probe loop
func (c *TestableClusterMonitor) runSequentialProbeWorker() {
	defer c.wg.Done()

	minInterval := time.Duration(c.intervalMs) * time.Millisecond
	if minInterval <= 0 {
		minInterval = 10 * time.Millisecond
	}

	ticker := time.NewTicker(minInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.processNextProbe()
		}
	}
}

// processNextProbe processes the next available probe target
func (c *TestableClusterMonitor) processNextProbe() {
	target := c.scheduler.GetNextTarget()
	if target == nil {
		return
	}

	sourceRnic := c.agentState.GetRnicByGID(target.SourceRnicGID)
	if sourceRnic == nil {
		return
	}

	if target.GID == target.SourceRnicGID {
		return
	}

	localHostName := c.agentState.GetHostName()
	if target.HostName == localHostName {
		return
	}

	// Determine probe type based on TOR relationship
	probeType := probe.ProbeTypeInterTor
	if target.TorID == c.agentState.GetLocalTorID() {
		probeType = probe.ProbeTypeTorMesh
	}

	// Create probe details
	probeDetails := probe.PingTarget{
		GID:              target.GID,
		QPN:              target.QPN,
		IPAddress:        target.IPAddress,
		HostName:         target.HostName,
		DeviceName:       target.DeviceName,
		TorID:            target.TorID,
		SourcePort:       target.SourcePort,
		FlowLabel:        target.FlowLabel,
		Priority:         target.Priority,
		ServiceFlowTuple: target.ServiceFlowTuple,
		ProbeType:        probeType,
	}

	senderUDQueue := c.agentState.GetSenderUDQueue(sourceRnic.GID)
	if senderUDQueue == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.intervalMs)*time.Millisecond)
	defer cancel()

	c.prober.ProbeTarget(ctx, sourceRnic, &probeDetails)
}

func TestProbeScheduler_UpdateTargets(t *testing.T) {
	scheduler := NewProbeScheduler()

	targets := []probe.PingTarget{
		{GID: "gid1", QPN: 1001},
		{GID: "gid2", QPN: 1002},
		{GID: "gid1", QPN: 1003}, // Same GID as first target
	}

	scheduler.UpdateTargets(targets, 10)

	assert.Equal(t, 3, scheduler.GetTargetCount())
	assert.Equal(t, 10, scheduler.probeRatePerSecond)
}

func TestProbeScheduler_GetNextTarget(t *testing.T) {
	scheduler := NewProbeScheduler()

	targets := []probe.PingTarget{
		{GID: "gid1", QPN: 1001},
		{GID: "gid2", QPN: 1002},
	}

	scheduler.UpdateTargets(targets, 1000) // High rate to avoid rate limiting

	// Debug: Check scheduler state
	t.Logf("Target count: %d", scheduler.GetTargetCount())
	t.Logf("Rate per second: %d", scheduler.probeRatePerSecond)

	// Should return targets in round-robin fashion
	target1 := scheduler.GetNextTarget()
	if target1 == nil {
		t.Fatal("target1 is nil")
	}
	assert.Equal(t, "gid1", target1.GID)

	target2 := scheduler.GetNextTarget()
	if target2 == nil {
		t.Fatal("target2 is nil")
	}
	assert.Equal(t, "gid2", target2.GID)

	target3 := scheduler.GetNextTarget()
	if target3 == nil {
		t.Fatal("target3 is nil")
	}
	assert.Equal(t, "gid1", target3.GID) // Back to first target
}

func TestProbeScheduler_RateLimiting(t *testing.T) {
	scheduler := NewProbeScheduler()

	targets := []probe.PingTarget{
		{GID: "gid1", QPN: 1001},
	}

	scheduler.UpdateTargets(targets, 1) // Very low rate (1 per second)

	// First call should succeed
	target1 := scheduler.GetNextTarget()
	assert.NotNil(t, target1)

	// Immediate second call should be rate limited (return nil)
	target2 := scheduler.GetNextTarget()
	assert.Nil(t, target2)

	// Wait for rate limit to reset and try again
	time.Sleep(1100 * time.Millisecond) // Wait slightly more than 1 second
	target3 := scheduler.GetNextTarget()
	assert.NotNil(t, target3)
}

func TestClusterMonitor_SequentialProbing(t *testing.T) {
	mockAgentState := &MockAgentState{}
	mockProber := &MockProber{}

	// Setup mock expectations
	mockAgentState.On("GetHostName").Return("test-host")
	mockAgentState.On("GetLocalTorID").Return("tor1")

	sourceRnic := &rdma.RNIC{
		GID:        "source-gid",
		DeviceName: "mlx5_0",
	}
	mockAgentState.On("GetRnicByGID", "source-gid").Return(sourceRnic)

	udQueue := &rdma.UDQueue{QPN: 1001}
	mockAgentState.On("GetSenderUDQueue", "source-gid").Return(udQueue)

	mockProber.On("ProbeTarget", mock.Anything, mock.Anything, mock.Anything).Return()

	// Create testable cluster monitor
	monitor := NewTestableClusterMonitor(mockAgentState, mockProber, 100, 10)

	// Create test pinglist
	pinglist := []*controller_agent.PingTarget{
		{
			SourceRnic: &controller_agent.RnicInfo{
				Gid:        "source-gid",
				Qpn:        1001,
				IpAddress:  "10.0.0.1",
				HostName:   "test-host",
				TorId:      "tor1",
				DeviceName: "mlx5_0",
			},
			TargetRnic: &controller_agent.RnicInfo{
				Gid:        "target-gid",
				Qpn:        1002,
				IpAddress:  "10.0.0.2",
				HostName:   "other-host",
				TorId:      "tor2",
				DeviceName: "mlx5_1",
			},
			SourcePort: 12345,
			FlowLabel:  100,
			Priority:   1,
		},
	}

	// Update pinglist
	monitor.UpdatePinglist(pinglist)

	// Start monitor
	err := monitor.Start()
	assert.NoError(t, err)

	// Wait for some probes to be executed
	time.Sleep(200 * time.Millisecond)

	// Stop monitor
	monitor.Stop()

	// Verify that probes were executed
	probeCount := mockProber.GetProbeCount()
	assert.Greater(t, probeCount, 0, "Expected at least one probe to be executed")

	// Verify mock expectations
	mockAgentState.AssertExpectations(t)
	mockProber.AssertExpectations(t)
}

func TestClusterMonitor_SkipSameHost(t *testing.T) {
	mockAgentState := &MockAgentState{}
	mockProber := &MockProber{}

	// Setup mock expectations
	mockAgentState.On("GetHostName").Return("same-host")

	// Create testable cluster monitor
	monitor := NewTestableClusterMonitor(mockAgentState, mockProber, 100, 10)

	// Create test pinglist with target on same host
	pinglist := []*controller_agent.PingTarget{
		{
			SourceRnic: &controller_agent.RnicInfo{
				Gid:        "source-gid",
				Qpn:        1001,
				IpAddress:  "10.0.0.1",
				HostName:   "same-host",
				TorId:      "tor1",
				DeviceName: "mlx5_0",
			},
			TargetRnic: &controller_agent.RnicInfo{
				Gid:        "target-gid",
				Qpn:        1002,
				IpAddress:  "10.0.0.2",
				HostName:   "same-host", // Same host as source
				TorId:      "tor1",
				DeviceName: "mlx5_1",
			},
		},
	}

	// Update pinglist
	monitor.UpdatePinglist(pinglist)

	// Verify that no targets were added (same host targets should be filtered out)
	assert.Equal(t, 0, monitor.scheduler.GetTargetCount())

	// Verify mock expectations
	mockAgentState.AssertExpectations(t)
}

func TestClusterMonitor_ProbeTypeDetection(t *testing.T) {
	mockAgentState := &MockAgentState{}
	mockProber := &MockProber{}

	// Setup mock expectations
	mockAgentState.On("GetHostName").Return("test-host")
	mockAgentState.On("GetLocalTorID").Return("tor1")

	sourceRnic := &rdma.RNIC{
		GID:        "source-gid",
		DeviceName: "mlx5_0",
	}
	mockAgentState.On("GetRnicByGID", "source-gid").Return(sourceRnic)

	udQueue := &rdma.UDQueue{QPN: 1001}
	mockAgentState.On("GetSenderUDQueue", "source-gid").Return(udQueue)

	// Capture the probe details to verify probe type
	var capturedProbeDetails *probe.PingTarget
	mockProber.On("ProbeTarget", mock.Anything, mock.Anything, mock.MatchedBy(func(target *probe.PingTarget) bool {
		capturedProbeDetails = target
		return true
	})).Return()

	// Create testable cluster monitor
	monitor := NewTestableClusterMonitor(mockAgentState, mockProber, 100, 10)

	// Test case 1: Inter-ToR probe (different ToR)
	pinglist1 := []*controller_agent.PingTarget{
		{
			SourceRnic: &controller_agent.RnicInfo{
				Gid:        "source-gid",
				Qpn:        1001,
				HostName:   "test-host",
				TorId:      "tor1",
				DeviceName: "mlx5_0",
			},
			TargetRnic: &controller_agent.RnicInfo{
				Gid:        "target-gid",
				Qpn:        1002,
				HostName:   "other-host",
				TorId:      "tor2", // Different ToR
				DeviceName: "mlx5_1",
			},
		},
	}

	monitor.UpdatePinglist(pinglist1)
	monitor.processNextProbe()

	assert.NotNil(t, capturedProbeDetails)
	assert.Equal(t, probe.ProbeTypeInterTor, capturedProbeDetails.ProbeType)

	// Test case 2: ToR-mesh probe (same ToR)
	pinglist2 := []*controller_agent.PingTarget{
		{
			SourceRnic: &controller_agent.RnicInfo{
				Gid:        "source-gid",
				Qpn:        1001,
				HostName:   "test-host",
				TorId:      "tor1",
				DeviceName: "mlx5_0",
			},
			TargetRnic: &controller_agent.RnicInfo{
				Gid:        "target-gid2",
				Qpn:        1003,
				HostName:   "other-host2",
				TorId:      "tor1", // Same ToR
				DeviceName: "mlx5_2",
			},
		},
	}

	monitor.UpdatePinglist(pinglist2)
	monitor.processNextProbe()

	assert.NotNil(t, capturedProbeDetails)
	assert.Equal(t, probe.ProbeTypeTorMesh, capturedProbeDetails.ProbeType)

	// Verify mock expectations
	mockAgentState.AssertExpectations(t)
	mockProber.AssertExpectations(t)
}
