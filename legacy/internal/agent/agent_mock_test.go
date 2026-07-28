package agent

import (
	"github.com/yuuki/rpingmesh/internal/rdma"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// mockAgentState is a mock implementation of AgentState for testing
type mockAgentState struct {
	agentID     string
	agentIP     string
	localTorID  string
	primaryRNIC *rdma.RNIC
}

func newMockAgentState(agentID string) *mockAgentState {
	return &mockAgentState{
		agentID:    agentID,
		agentIP:    "192.168.1.100",
		localTorID: "mock_tor",
		primaryRNIC: &rdma.RNIC{
			DeviceName: "mock_device",
			GID:        "mock_gid",
			IPAddr:     "192.168.1.100",
		},
	}
}

func (m *mockAgentState) Initialize() error {
	return nil
}

func (m *mockAgentState) Close() {}

func (m *mockAgentState) GetAgentID() string {
	return m.agentID
}

func (m *mockAgentState) GetAgentIP() string {
	return m.agentIP
}

func (m *mockAgentState) GetLocalTorID() string {
	return m.localTorID
}

func (m *mockAgentState) GetPrimaryRNIC() *rdma.RNIC {
	return m.primaryRNIC
}

func (m *mockAgentState) GetDetectedRNICs() []*rdma.RNIC {
	return []*rdma.RNIC{m.primaryRNIC}
}

func (m *mockAgentState) GetUDQueue(gid string) *rdma.UDQueue {
	return &rdma.UDQueue{QPN: 1234}
}

func (m *mockAgentState) GetRDMAManager() *rdma.RDMAManager {
	return nil
}

func (m *mockAgentState) SetLocalTorID(torID string) {
	m.localTorID = torID
}

// mockControllerClient is a mock implementation of the controller client for testing
type mockControllerClient struct {
	connected bool
}

func newMockControllerClient() *mockControllerClient {
	return &mockControllerClient{}
}

func (m *mockControllerClient) Connect() error {
	m.connected = true
	return nil
}

func (m *mockControllerClient) Close() error {
	m.connected = false
	return nil
}

func (m *mockControllerClient) GetPinglist(
	requesterRnic *rdma.RNIC,
	hostName string,
	pinglistType controller_agent.PinglistRequest_PinglistType,
) ([]*controller_agent.PingTarget, uint32, uint32, error) {
	return []*controller_agent.PingTarget{}, 1000, 500, nil
}

func (m *mockControllerClient) RegisterAgent(
	agentID string,
	agentIP string,
	rnics []*rdma.RNIC,
) error {
	return nil
}

func (m *mockControllerClient) GetTargetRnicInfo(
	targetIP string,
	targetGID string,
) (*controller_agent.RnicInfo, error) {
	return nil, nil
}
