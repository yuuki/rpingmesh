package state

import (
	"net"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/rdma"
)

// AgentState holds the current state of the agent
type AgentState struct {
	agentID       string
	agentIP       string
	localTorID    string
	rdmaManager   *rdma.RDMAManager
	primaryRNIC   *rdma.RNIC
	detectedRNICs []*rdma.RNIC
	udQueues      map[string]*rdma.UDQueue // Map of GID to UDQueue
	mutex         sync.RWMutex
}

// NewAgentState creates a new agent state
func NewAgentState(agentID, localTorID string) *AgentState {
	return &AgentState{
		agentID:    agentID,
		localTorID: localTorID,
		udQueues:   make(map[string]*rdma.UDQueue),
	}
}

// Initialize initializes the agent state
func (a *AgentState) Initialize() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Get the agent's IP address
	ip, err := getLocalIP()
	if err != nil {
		return err
	}
	a.agentIP = ip.String()

	// Initialize RDMA manager
	rdmaManager, err := rdma.NewRDMAManager()
	if err != nil {
		return err
	}
	a.rdmaManager = rdmaManager

	// Detect and open RDMA devices
	for _, rnic := range rdmaManager.Devices {
		if err := rnic.OpenDevice(); err != nil {
			log.Error().Err(err).Str("device", rnic.DeviceName).Msg("Failed to open RDMA device")
			continue
		}

		a.detectedRNICs = append(a.detectedRNICs, rnic)

		// Select the first device as the primary RNIC
		if a.primaryRNIC == nil {
			a.primaryRNIC = rnic
		}
	}

	if len(a.detectedRNICs) == 0 {
		return err
	}

	// Create UD queues for each RNIC
	for _, rnic := range a.detectedRNICs {
		udQueue, err := a.rdmaManager.CreateUDQueue(rnic)
		if err != nil {
			log.Error().Err(err).Str("device", rnic.DeviceName).Msg("Failed to create UD queue")
			continue
		}
		a.udQueues[rnic.GID] = udQueue
	}

	log.Info().
		Str("agentID", a.agentID).
		Str("agentIP", a.agentIP).
		Str("torID", a.localTorID).
		Int("rnics", len(a.detectedRNICs)).
		Msg("Agent state initialized")

	return nil
}

// GetLocalTorID returns the local ToR ID
func (a *AgentState) GetLocalTorID() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.localTorID
}

// SetLocalTorID sets the local ToR ID
func (a *AgentState) SetLocalTorID(torID string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.localTorID = torID
}

// GetAgentID returns the agent ID
func (a *AgentState) GetAgentID() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.agentID
}

// GetAgentIP returns the agent IP
func (a *AgentState) GetAgentIP() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.agentIP
}

// GetPrimaryRNIC returns the primary RNIC
func (a *AgentState) GetPrimaryRNIC() *rdma.RNIC {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.primaryRNIC
}

// GetDetectedRNICs returns all detected RNICs
func (a *AgentState) GetDetectedRNICs() []*rdma.RNIC {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.detectedRNICs
}

// GetUDQueue returns the UD queue for the given RNIC GID
func (a *AgentState) GetUDQueue(gid string) *rdma.UDQueue {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.udQueues[gid]
}

// GetRDMAManager returns the RDMA manager
func (a *AgentState) GetRDMAManager() *rdma.RDMAManager {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.rdmaManager
}

// FindRNICByIP searches for an RNIC with the given IP address.
// It returns the RNIC if found, otherwise nil.
func (a *AgentState) FindRNICByIP(ipAddress string) *rdma.RNIC {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	for _, rnic := range a.detectedRNICs {
		if rnic.IPAddr == ipAddress {
			return rnic
		}
		// Also check if the GID, when interpreted as an IP, matches.
		// This is less likely to be the primary match key but can be a fallback.
		parsedGIDIP := net.ParseIP(rnic.GID)
		if parsedGIDIP != nil {
			if parsedGIDIP.String() == ipAddress {
				return rnic
			}
			if ipv4 := parsedGIDIP.To4(); ipv4 != nil && ipv4.String() == ipAddress {
				return rnic
			}
		}
	}
	return nil
}

// Close releases all resources
func (a *AgentState) Close() {
	if a.rdmaManager != nil {
		a.rdmaManager.Close()
		a.rdmaManager = nil
	}

	a.primaryRNIC = nil
	a.detectedRNICs = nil
	a.udQueues = nil
}

// getLocalIP returns the non-loopback IP address of the host
func getLocalIP() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP, nil
			}
		}
	}

	return nil, nil
}
