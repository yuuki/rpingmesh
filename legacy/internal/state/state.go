package state

import (
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/rdma"
)

// Constants
const (
	DefaultLocalTorID = "" // Default value for local Tor ID
)

// AgentState holds the current state of the agent
type AgentState struct {
	agentID         string
	hostName        string
	agentIP         string
	localTorID      string
	rdmaManager     *rdma.RDMAManager
	primaryRNIC     *rdma.RNIC
	detectedRNICs   []*rdma.RNIC
	senderQueues    map[string]*rdma.UDQueue // Map of GID to Sender UDQueue
	responderQueues map[string]*rdma.UDQueue // Map of GID to Responder UDQueue
	rnicByGID       map[string]*rdma.RNIC    // Map of GID to RNIC for quick lookup
	gidIndex        int                      // Changed: preferredGIDIndex to gidIndex
	mutex           sync.RWMutex
	ackHandler      rdma.AckHandlerFunc // Store the ACK handler directly
}

// NewAgentState creates a new agent state
func NewAgentState(agentID, hostName, localTorID string, gidIndex int) *AgentState {
	return &AgentState{
		agentID:         agentID,
		hostName:        hostName,
		localTorID:      DefaultLocalTorID,
		senderQueues:    make(map[string]*rdma.UDQueue),
		responderQueues: make(map[string]*rdma.UDQueue),
		gidIndex:        gidIndex,
	}
}

// SetAckHandler sets the ACK handler function for the agent state.
func (a *AgentState) SetAckHandler(handler rdma.AckHandlerFunc) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.ackHandler = handler
}

// InitializeRDMAInfrastructure initializes the RDMA manager, detects and opens RNIC devices.
func (a *AgentState) InitializeRDMAInfrastructure(allowedDeviceNames []string) error {
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

	// Filter devices by name BEFORE opening them or creating queues
	var devicesToProcess []*rdma.RNIC
	if len(allowedDeviceNames) > 0 {
		log.Info().Strs("allowed_devices", allowedDeviceNames).Msg("Pre-filtering RNIC devices by name")
		nameSet := make(map[string]struct{})
		for _, name := range allowedDeviceNames {
			nameSet[name] = struct{}{}
		}
		for _, rnic := range rdmaManager.Devices {
			if _, ok := nameSet[rnic.DeviceName]; ok {
				devicesToProcess = append(devicesToProcess, rnic)
			} else {
				log.Debug().Str("device_name", rnic.DeviceName).Msg("RNIC device skipped due to whitelist filter (before open)")
			}
		}
		if len(devicesToProcess) == 0 {
			log.Error().Strs("allowed_devices", allowedDeviceNames).Msg("No RNIC devices match the allowed list. Agent cannot use any RDMA devices.")
			// Return an error here or let it be caught by the check after device opening
		}
	} else {
		devicesToProcess = rdmaManager.Devices
	}

	// Detect and open RDMA devices from the filtered list
	for _, rnic := range devicesToProcess {
		// Pass gidIndex to OpenDevice
		if err := rnic.OpenDevice(a.gidIndex); err != nil {
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
		if len(allowedDeviceNames) > 0 {
			return fmt.Errorf("no RDMA devices available after filtering by allowed names: %v", allowedDeviceNames)
		}
		return fmt.Errorf("no RDMA devices found or initialized successfully")
	}

	log.Info().Msg("Agent RDMA infrastructure initialized")
	return nil
}

// InitializeUDQueues creates UD queues for all detected RNICs.
// This should be called after InitializeRDMAInfrastructure and after SetAckHandler has been called.
func (a *AgentState) InitializeUDQueues() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.ackHandler == nil {
		return fmt.Errorf("ackHandler not set in AgentState, cannot initialize UD queues with ACK handler. Call SetAckHandler first.")
	}
	if len(a.detectedRNICs) == 0 {
		return fmt.Errorf("no detected RNICs to initialize UD queues for")
	}
	if a.rdmaManager == nil {
		return fmt.Errorf("RDMA manager not initialized")
	}

	// Initialize rnicByGID map
	a.rnicByGID = make(map[string]*rdma.RNIC)

	// Create separate UD queues for each RNIC - one for sending probes, one for receiving probes
	for _, rnic := range a.detectedRNICs {
		err := a.rdmaManager.CreateSenderAndResponderQueues(rnic, a.ackHandler)
		if err != nil {
			log.Error().Err(err).Str("device", rnic.DeviceName).Msg("Failed to create sender and responder UD queues")
			continue // Or collect errors and return them
		}
		a.senderQueues[rnic.GID] = rnic.ProberQueue
		a.responderQueues[rnic.GID] = rnic.ResponderQueue

		// Build rnicByGID map for quick lookup
		if rnic.GID != "" {
			a.rnicByGID[rnic.GID] = rnic
		}
	}

	log.Info().
		Str("agentID", a.agentID).
		Str("agentIP", a.agentIP).
		Str("torID", a.localTorID).
		Int("rnics_with_queues", len(a.detectedRNICs)). // Assuming queues are created for all detected if no error
		Msg("Agent UD queues initialized")

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

// GetHostName returns the OS hostname
func (a *AgentState) GetHostName() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.hostName
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

// GetSenderUDQueue returns the sender UD queue for the given RNIC GID
func (a *AgentState) GetSenderUDQueue(gid string) *rdma.UDQueue {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.senderQueues[gid]
}

// GetResponderUDQueue returns the responder UD queue for the given RNIC GID
func (a *AgentState) GetResponderUDQueue(gid string) *rdma.UDQueue {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.responderQueues[gid]
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
	a.senderQueues = nil
	a.responderQueues = nil
	a.rnicByGID = nil
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

// GetRnicByGID returns the RNIC for the given GID
func (a *AgentState) GetRnicByGID(gid string) *rdma.RNIC {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.rnicByGID[gid]
}
