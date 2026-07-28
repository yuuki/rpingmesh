package probe

// ProbeType constants
const (
	ProbeTypeTorMesh        = "TOR_MESH"
	ProbeTypeInterTor       = "INTER_TOR"
	ProbeTypeServiceTracing = "SERVICE_TRACING"
)

// Default Values
const (
	DefaultFlowLabel = 0  // Default flow label for ACK packets
	EmptyIPString    = "" // Empty string for IP address checks
)

// ServiceFlowTuple holds the specific 5-tuple for a service flow.
type ServiceFlowTuple struct {
	SrcGID    string
	SrcQPN    uint32
	DstGID    string // Destination GID of the flow
	DstQPN    uint32 // Destination QPN of the flow
	FlowLabel uint32 // Actual flow label of the service, if available (otherwise 0)
}

// PingTarget represents a target for probing
type PingTarget struct {
	// Destination RNIC information
	GID        string
	QPN        uint32
	IPAddress  string
	HostName   string
	TorID      string
	DeviceName string

	// Source RNIC information (which local RNIC should send the probe)
	SourceRnicGID    string
	SourceRnicQPN    uint32
	SourceRnicIP     string
	SourceHostName   string
	SourceTorID      string
	SourceDeviceName string

	// 5-tuple details
	SourcePort       uint32
	FlowLabel        uint32
	Priority         uint32
	ServiceFlowTuple *ServiceFlowTuple // Pointer to ServiceFlowTuple from the same package
	ProbeType        string            // e.g., ProbeTypeTorMesh, ProbeTypeInterTor, ProbeTypeServiceTracing
}
