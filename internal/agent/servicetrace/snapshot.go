package servicetrace

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// QPResource is the generic RDMA netlink view of a QP. Dev is the uverbs
// device number resolved from the RDMA device name. Neither the uverbs
// context/handle nor the remote GID/address vector is available in this ABI.
type QPResource struct {
	Dev       uint32
	LocalQPN  uint32
	RemoteQPN uint32
	QPType    uint32
	QPState   uint8
	PID       uint32
	Port      uint32
	// Kernel identifies RES_KERN_NAME independently of PID: a user QP
	// can outlive the creator task and then omit the PID attribute.
	Kernel bool
	// OwnerTGID is resolved from /proc/PID/status by the monitor. PID in
	// the netlink ABI is an owning task ID, not necessarily a group leader.
	OwnerTGID uint32
	// Recovered is present only after validating a supported driver dump.
	Recovered *Connection
}

// Values from include/uapi/rdma/rdma_netlink.h. Attributes use native byte
// order, unlike the network-order GIDs carried by tracer events.
const (
	rdmaNLDev       = 5 << 10
	rdmaCmdGet      = rdmaNLDev | 1
	rdmaCmdResQPGet = rdmaNLDev | 10

	rdmaAttrDevIndex   = 1
	rdmaAttrDevName    = 2
	rdmaAttrPortIndex  = 3
	rdmaAttrRaw        = 85
	rdmaCmdResQPGetRaw = rdmaNLDev | 19
	rdmaAttrResQP      = 19
	rdmaAttrQPEntry    = 20
	rdmaAttrLQPN       = 21
	rdmaAttrRQPN       = 22
	rdmaAttrQPType     = 26
	rdmaAttrQPState    = 27
	rdmaAttrPID        = 28
	rdmaAttrKernelName = 29
)

type rdmaDump func(context.Context, uint16, []byte) ([][]byte, error)

// snapshotQPs separates resource decoding from socket I/O for portable tests.
// A failed device dump invalidates the entire snapshot, so callers never
// replace their inventory with an accidentally partial one.
func snapshotQPs(ctx context.Context, devices map[uint32]string, dump rdmaDump) ([]QPResource, error) {
	devs, err := dump(ctx, rdmaCmdGet, nil)
	if err != nil {
		return nil, fmt.Errorf("list RDMA devices: %w", err)
	}
	byName := make(map[string]uint32, len(devices))
	for dev, name := range devices {
		byName[name] = dev
	}
	var out []QPResource
	for _, msg := range devs {
		attrs, err := rdmaAttrs(msg)
		if err != nil {
			return nil, err
		}
		name := attrs[rdmaAttrDevName]
		if len(name) < 2 || name[len(name)-1] != 0 || len(attrs[rdmaAttrDevIndex]) != 4 {
			return nil, fmt.Errorf("invalid RDMA device identity")
		}
		dev, monitored := byName[string(name[:len(name)-1])]
		if !monitored {
			continue
		}
		// RDMA_NLDEV_CMD_RES_QP_GET requires a device index, even for a dump.
		request := make([]byte, 8)
		binary.NativeEndian.PutUint16(request, 8)
		binary.NativeEndian.PutUint16(request[2:], rdmaAttrDevIndex)
		copy(request[4:], attrs[rdmaAttrDevIndex])
		msgs, err := dump(ctx, rdmaCmdResQPGet, request)
		if err != nil {
			return nil, fmt.Errorf("dump QPs of %s: %w", name[:len(name)-1], err)
		}
		for _, msg := range msgs {
			qps, err := decodeQPResources(msg, dev)
			if err != nil {
				return nil, err
			}
			out = append(out, qps...)
		}
	}
	return out, nil
}

// rdmaAttrs decodes nlattr framing, including nested and unknown attributes.
func rdmaAttrs(data []byte) (map[uint16][]byte, error) {
	out := make(map[uint16][]byte)
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("truncated RDMA netlink attribute header")
		}
		n := int(binary.NativeEndian.Uint16(data))
		if n < 4 || n > len(data) || (n+3)&^3 > len(data) {
			return nil, fmt.Errorf("invalid RDMA netlink attribute length %d", n)
		}
		kind := binary.NativeEndian.Uint16(data[2:]) & 0x3fff
		out[kind] = data[4:n]
		data = data[(n+3)&^3:]
	}
	return out, nil
}

func decodeQPResources(msg []byte, dev uint32) ([]QPResource, error) {
	attrs, err := rdmaAttrs(msg)
	if err != nil {
		return nil, err
	}
	// Unlike scalar attributes, RES_QP_ENTRY repeats within RES_QP.
	data, ok := attrs[rdmaAttrResQP]
	if !ok {
		return nil, fmt.Errorf("RDMA QP dump has no resource table")
	}
	var out []QPResource
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("truncated RDMA QP entry")
		}
		n := int(binary.NativeEndian.Uint16(data))
		if n < 4 || (n+3)&^3 > len(data) {
			return nil, fmt.Errorf("invalid RDMA QP entry length %d", n)
		}
		kind := binary.NativeEndian.Uint16(data[2:]) & 0x3fff
		if kind == rdmaAttrQPEntry {
			a, err := rdmaAttrs(data[4:n])
			if err != nil {
				return nil, err
			}
			qp, err := decodeQPResource(a, dev)
			if err != nil {
				return nil, err
			}
			out = append(out, qp)
		}
		data = data[(n+3)&^3:]
	}
	return out, nil
}

// At most one kernel dump may outlive its caller. A stalled driver must
// not accumulate goroutines, sockets or firmware queries on each refresh.
var qpSnapshotInFlight = make(chan struct{}, 1)

func boundedQPSnapshot(ctx context.Context, devices map[uint32]string, collect func(context.Context, map[uint32]string) ([]QPResource, error)) ([]QPResource, error) {
	return boundedQPCollection(ctx, devices, 5*time.Second, collect)
}

func boundedQPCollection(ctx context.Context, devices map[uint32]string, timeout time.Duration, collect func(context.Context, map[uint32]string) ([]QPResource, error)) ([]QPResource, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case qpSnapshotInFlight <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// The worker can outlive this call; it must not retain the caller's
	// mutable map after cancellation.
	ownedDevices := make(map[uint32]string, len(devices))
	for dev, name := range devices {
		ownedDevices[dev] = name
	}
	type result struct {
		qps []QPResource
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-qpSnapshotInFlight }()
		qps, err := collect(ctx, ownedDevices)
		done <- result{qps, err}
	}()
	select {
	case r := <-done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return r.qps, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func decodeQPResource(a map[uint16][]byte, dev uint32) (QPResource, error) {
	if len(a[rdmaAttrLQPN]) != 4 || len(a[rdmaAttrQPType]) != 1 || len(a[rdmaAttrQPState]) != 1 {
		return QPResource{}, fmt.Errorf("RDMA QP entry is missing its QPN, type or state")
	}
	_, kernel := a[rdmaAttrKernelName]
	qp := QPResource{Kernel: kernel, Dev: dev, LocalQPN: binary.NativeEndian.Uint32(a[rdmaAttrLQPN]), QPType: uint32(a[rdmaAttrQPType][0]), QPState: a[rdmaAttrQPState][0]}
	for attr, dst := range map[uint16]*uint32{rdmaAttrRQPN: &qp.RemoteQPN, rdmaAttrPID: &qp.PID, rdmaAttrPortIndex: &qp.Port} {
		if value, ok := a[attr]; ok {
			if len(value) != 4 {
				return QPResource{}, fmt.Errorf("invalid RDMA QP attribute %d", attr)
			}
			*dst = binary.NativeEndian.Uint32(value)
		}
	}
	return qp, nil
}
