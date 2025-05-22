package rdma

// #cgo LDFLAGS: -libverbs
// #include <stdlib.h>
// #include <infiniband/verbs.h>
//
// // Helper function to access ibv_port_attr safely
// int my_ibv_query_port(struct ibv_context *context, uint8_t port_num, struct ibv_port_attr *port_attr) {
//     return ibv_query_port(context, port_num, port_attr);
// }
//
// // Helper function to get phys_port_cnt
// int get_phys_port_cnt(struct ibv_context *context, uint8_t *phys_port_cnt) {
//     struct ibv_device_attr device_attr; // Declared and used only within C
//     if (ibv_query_device(context, &device_attr)) {
//         return -1; // Error
//     }
//     *phys_port_cnt = device_attr.phys_port_cnt;
//     return 0;
// }
import "C"
import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
)

// RNIC represents an RDMA NIC device
type RNIC struct {
	Context        *C.struct_ibv_context
	Device         *C.struct_ibv_device
	DeviceName     string
	GID            string
	IPAddr         string
	PD             *C.struct_ibv_pd
	IsOpen         bool
	ActiveGIDIndex uint8               // Added to store the active GID index
	ActivePortNum  uint8               // Added to store the active port number
	SenderQueue    *UDQueue            // Queue for sending probes and receiving ACKs
	ResponderQueue *UDQueue            // Queue for receiving probes and sending ACKs
	UDQueues       map[string]*UDQueue // Map of keys to UDQueue for backward compatibility
}

// RDMAManager manages RDMA devices and operations
type RDMAManager struct {
	Devices           []*RNIC
	SenderUDQueues    map[string]*UDQueue // Map of GID to sender UDQueue
	ResponderUDQueues map[string]*UDQueue // Map of GID to responder UDQueue
	UDQueues          map[string]*UDQueue // Map of unique keys to UDQueue for backward compatibility
}

// NewRDMAManager creates a new RDMA manager
func NewRDMAManager() (*RDMAManager, error) {
	// Seed the random number generator for PSN generation
	rand.Seed(time.Now().UnixNano())

	manager := &RDMAManager{
		SenderUDQueues:    make(map[string]*UDQueue),
		ResponderUDQueues: make(map[string]*UDQueue),
		UDQueues:          make(map[string]*UDQueue),
	}

	// Get list of RDMA devices
	var numDevices C.int
	deviceList := C.ibv_get_device_list(&numDevices)
	if deviceList == nil {
		return nil, fmt.Errorf("failed to get RDMA device list")
	}
	defer C.ibv_free_device_list(deviceList)

	if numDevices == 0 {
		return nil, fmt.Errorf("no RDMA devices found")
	}

	// Iterate through all devices
	for i := 0; i < int(numDevices); i++ {
		device := *(**C.struct_ibv_device)(unsafe.Pointer(uintptr(unsafe.Pointer(deviceList)) + uintptr(i)*unsafe.Sizeof(uintptr(0))))
		if device == nil {
			continue
		}

		deviceName := C.GoString(C.ibv_get_device_name(device))
		log.Debug().Str("device", deviceName).Msg("Found RDMA device")

		rnic := &RNIC{
			Device:     device,
			DeviceName: deviceName,
			IsOpen:     false,
		}
		manager.Devices = append(manager.Devices, rnic)
	}

	return manager, nil
}

// isIPv4MappedIPv6 checks if the given IP byte slice represents an IPv4-mapped IPv6 address
// (::ffff:A.B.C.D format) by checking if bytes 10 and 11 are 0xFF
func isIPv4MappedIPv6(ipBytes []byte) bool {
	return len(ipBytes) == 16 && ipBytes[10] == 0xff && ipBytes[11] == 0xff
}

// formatGIDString creates the appropriate string representation of a GID.
// For IPv4-mapped IPv6 addresses, it preserves the ::ffff: prefix.
func formatGIDString(gidBytes []byte) string {
	if isIPv4MappedIPv6(gidBytes) {
		// Extract the IPv4 part and prepend the ::ffff: prefix
		ipv4Part := fmt.Sprintf("%d.%d.%d.%d", gidBytes[12], gidBytes[13], gidBytes[14], gidBytes[15])
		return "::ffff:" + ipv4Part
	}
	// For normal IPv6 addresses, use the standard string representation
	return net.IP(gidBytes).String()
}

// releaseDeviceResources deallocates PD and closes device context
func (r *RNIC) releaseDeviceResources() {
	if r.PD != nil {
		C.ibv_dealloc_pd(r.PD)
		r.PD = nil
	}
	if r.Context != nil {
		C.ibv_close_device(r.Context)
		r.Context = nil
	}
}

// OpenDevice opens the RDMA device and initializes its resources using the specified GID index.
func (r *RNIC) OpenDevice(gidIndex int) error {
	if r.IsOpen {
		return nil
	}

	if gidIndex < 0 {
		return fmt.Errorf("gidIndex must be >= 0, got %d for device %s", gidIndex, r.DeviceName)
	}

	// Open device context
	context := C.ibv_open_device(r.Device)
	if context == nil {
		return fmt.Errorf("failed to open device %s", r.DeviceName)
	}
	r.Context = context

	// Allocate protection domain
	pd := C.ibv_alloc_pd(r.Context)
	if pd == nil {
		C.ibv_close_device(r.Context)
		return fmt.Errorf("failed to allocate protection domain for device %s", r.DeviceName)
	}
	r.PD = pd

	// Query device attributes to get the number of physical ports
	var physPortCnt C.uint8_t
	if C.get_phys_port_cnt(r.Context, &physPortCnt) != 0 {
		r.releaseDeviceResources()
		return fmt.Errorf("failed to query device attributes for %s", r.DeviceName)
	}

	if physPortCnt == 0 {
		r.releaseDeviceResources()
		return fmt.Errorf("device %s has 0 physical ports", r.DeviceName)
	}

	var activePortNumFound C.uint8_t = 0
	var gidFound C.union_ibv_gid
	var usableGIDFound bool = false

	// Iterate over physical ports to find an active one and use the specified gidIndex
	for portNum := C.uint8_t(1); portNum <= physPortCnt; portNum++ {
		var portAttr C.struct_ibv_port_attr
		if ret := C.my_ibv_query_port(r.Context, portNum, &portAttr); ret != 0 {
			log.Warn().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", gidIndex).Msg("Failed to query port, skipping port.")
			continue
		}

		if portAttr.state != C.IBV_PORT_ACTIVE {
			log.Debug().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", gidIndex).Msg("Port not active, skipping port.")
			continue
		}

		// Port is active, try to query the GID at the specified index
		var currentGid C.union_ibv_gid
		if ret := C.ibv_query_gid(r.Context, portNum, C.int(gidIndex), &currentGid); ret == 0 {
			gidBytes := unsafe.Slice((*byte)(unsafe.Pointer(&currentGid)), C.sizeof_union_ibv_gid)
			// Basic validation: ensure GID is not all zeros
			isZeroGid := true
			for _, b := range gidBytes {
				if b != 0 {
					isZeroGid = false
					break
				}
			}
			if !isZeroGid {
				log.Info().
					Str("device", r.DeviceName).
					Uint8("port", uint8(portNum)).
					Int("gid_index", gidIndex).
					Str("gid", formatGIDString(gidBytes)).
					Msg("Found and using GID from specified GID index on active port.")
				activePortNumFound = portNum
				gidFound = currentGid
				usableGIDFound = true
				break // Found a usable GID on an active port, stop searching
			} else {
				log.Warn().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", gidIndex).Msg("Specified GID index resulted in a zero GID on this active port.")
			}
		} else {
			log.Warn().Str("device", r.DeviceName).Uint8("port", uint8(portNum)).Int("gid_index", gidIndex).Msg("Failed to query GID at specified GID index on this active port.")
		}
	}

	if !usableGIDFound {
		r.releaseDeviceResources()
		return fmt.Errorf("no usable GID found for device %s on any active port with GID index %d", r.DeviceName, gidIndex)
	}

	r.ActiveGIDIndex = uint8(gidIndex) // Store the specified GID index
	r.ActivePortNum = uint8(activePortNumFound)

	// Get GID bytes and format GID string
	gidBytes := unsafe.Slice((*byte)(unsafe.Pointer(&gidFound)), C.sizeof_union_ibv_gid)
	r.GID = formatGIDString(gidBytes)

	// Extract IPv6 for address resolution
	ipv6 := net.IP(gidBytes)

	// Get IP address from network interface or fall back to GID
	r.IPAddr = r.getIPAddress(ipv6)

	r.IsOpen = true
	log.Info().Str("device", r.DeviceName).Str("gid", r.GID).Str("ip", r.IPAddr).Int("used_gid_index", int(r.ActiveGIDIndex)).Msg("Opened RDMA device")
	return nil
}

// getIPAddress tries to get the IP address from the network interface
// and falls back to GID-based extraction if that fails
func (r *RNIC) getIPAddress(ipv6 net.IP) string {
	// Try to get IP address from the network interface
	if ipAddr := r.getIPAddressFromInterface(); ipAddr != "" {
		return ipAddr
	}

	// Fall back to GID-based extraction
	// For IPAddr field, we want a clean IPv4 or IPv6 address without ::ffff: prefix
	return r.getIPAddressFromGID(ipv6, false)
}

// getIPAddressFromInterface gets the IPv4 address from the network interface
// associated with the RNIC, returns empty string if not found
func (r *RNIC) getIPAddressFromInterface() string {
	// Get network interface name from /sys/class/infiniband/<device>/device/net
	netDir := fmt.Sprintf("/sys/class/infiniband/%s/device/net", r.DeviceName)
	netDirEntries, err := os.ReadDir(netDir)
	if err != nil {
		log.Warn().Str("device", r.DeviceName).Err(err).Msg("Failed to read network interfaces directory")
		return ""
	}

	// Check if there are any interfaces
	if len(netDirEntries) == 0 {
		log.Warn().Str("device", r.DeviceName).Msg("No network interfaces found")
		return ""
	}

	// Get the first interface (there should typically be only one)
	ifName := netDirEntries[0].Name()
	log.Debug().Str("device", r.DeviceName).Str("interface", ifName).Msg("Found network interface for RDMA device")

	// Get the IPv4 address for this interface
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Warn().Str("device", r.DeviceName).Str("interface", ifName).Err(err).Msg("Failed to get interface")
		return ""
	}

	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		log.Warn().Str("device", r.DeviceName).Str("interface", ifName).Err(err).Msg("Failed to get interface addresses")
		return ""
	}

	// Find the first IPv4 address
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipv4 := ipNet.IP.To4(); ipv4 != nil {
			log.Debug().Str("device", r.DeviceName).Str("interface", ifName).Str("ipv4", ipv4.String()).Msg("Found IPv4 address for interface")
			return ipv4.String()
		}
	}

	log.Warn().Str("device", r.DeviceName).Str("interface", ifName).Msg("No IPv4 address found for interface")
	return ""
}

// getIPAddressFromGID extracts IPv4 from IPv6 GID if it's an IPv4-mapped IPv6 address
// If preserveFormat is true, IPv4-mapped IPv6 addresses are returned in ::ffff:A.B.C.D format
func (r *RNIC) getIPAddressFromGID(ipv6 net.IP, preserveFormat ...bool) string {
	// Check if it's an IPv4-mapped IPv6 address
	if ipv4 := ipv6.To4(); ipv4 != nil {
		// If preserveFormat flag is set to true, keep the ::ffff: prefix
		if len(preserveFormat) > 0 && preserveFormat[0] {
			// Extract the raw bytes
			gidBytes := []byte(ipv6)
			// Check if it has the IPv4-mapped IPv6 pattern (bytes 10-11 are 0xFF)
			if len(gidBytes) == 16 && gidBytes[10] == 0xff && gidBytes[11] == 0xff {
				// Get the IPv4 part and format it with the prefix
				ipv4Part := fmt.Sprintf("%d.%d.%d.%d", gidBytes[12], gidBytes[13], gidBytes[14], gidBytes[15])
				return "::ffff:" + ipv4Part
			}
		}
		// Default behavior: convert to native IPv4 format
		return ipv4.String()
	}
	// Not an IPv4-mapped address, return the normal IPv6 representation
	return ipv6.String()
}

// CloseDevice closes the RDMA device and frees its resources
func (r *RNIC) CloseDevice() {
	if !r.IsOpen {
		return
	}

	if r.PD != nil {
		C.ibv_dealloc_pd(r.PD)
		r.PD = nil
	}

	if r.Context != nil {
		C.ibv_close_device(r.Context)
		r.Context = nil
	}

	r.IsOpen = false
	log.Debug().Str("device", r.DeviceName).Msg("Closed RDMA device")
}
