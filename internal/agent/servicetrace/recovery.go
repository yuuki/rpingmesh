package servicetrace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

// recoverQPs enriches an inventory without guessing uverbs identities. Raw
// failures are nonfatal: partial results accompany the error, and every
// undecodable QP remains in the returned inventory without Recovered set.
func recoverQPs(ctx context.Context, devices map[uint32]string, resources []QPResource, dump, query rdmaDump, driver func(string) string) ([]QPResource, error) {
	out := append([]QPResource(nil), resources...)
	eligible := mlx5Devices(devices, driver)
	if len(eligible) == 0 {
		return out, nil
	}
	msgs, err := dump(ctx, rdmaCmdGet, nil)
	if err != nil {
		return out, err
	}
	indexes, err := rdmaDeviceIndexes(msgs, eligible)
	if err != nil {
		return out, err
	}
	failures := make(map[uint32]error)
	blocked := make(map[uint32]bool)
	for i, qp := range out {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		index, supported := indexes[qp.Dev]
		if !supported || blocked[qp.Dev] || !recoverableQP(qp) {
			continue
		}
		request := rawQPRequest(index, qp)
		msgs, err := query(ctx, rdmaCmdResQPGetRaw, request)
		if err != nil {
			noteRawQueryError(failures, blocked, qp.Dev, err)
			continue
		}
		conn, err := decodeRawQPReply(msgs, qp)
		if err != nil {
			failures[qp.Dev] = err
			continue
		}
		if qpUnchanged(ctx, query, request, qp) {
			out[i].Recovered = &conn
		}
	}
	return out, recoveryError(eligible, failures)
}

// mlx5Devices selects the devices whose driver answers raw QP queries.
func mlx5Devices(devices map[uint32]string, driver func(string) string) map[uint32]string {
	eligible := make(map[uint32]string)
	for dev, name := range devices {
		if driver(name) == "mlx5_core" {
			eligible[dev] = name
		}
	}
	return eligible
}

// rdmaDeviceIndexes maps eligible devices to their RDMA netlink index, from
// an RDMA_NLDEV_CMD_GET dump. A device missing from it gets no index.
func rdmaDeviceIndexes(msgs [][]byte, eligible map[uint32]string) (map[uint32]uint32, error) {
	indexes := make(map[uint32]uint32)
	for _, msg := range msgs {
		a, err := rdmaAttrs(msg)
		if err != nil {
			return nil, err
		}
		for dev, name := range eligible {
			if string(a[rdmaAttrDevName]) == name+"\x00" && len(a[rdmaAttrDevIndex]) == 4 {
				indexes[dev] = binary.NativeEndian.Uint32(a[rdmaAttrDevIndex])
			}
		}
	}
	return indexes, nil
}

// recoverableQP reports whether qp is a user QP whose raw dump can carry a
// connected address vector: a connected type, on a port, in RTR or RTS.
func recoverableQP(qp QPResource) bool {
	return !qp.Kernel && IsConnectedType(qp.QPType) && qp.Port != 0 && (qp.QPState == QPStateRTR || qp.QPState == QPStateRTS)
}

// rawQPRequest identifies qp to the raw and the generic QP queries.
func rawQPRequest(index uint32, qp QPResource) []byte {
	request := appendQPAttr(nil, rdmaAttrDevIndex, index)
	request = appendQPAttr(request, rdmaAttrPortIndex, qp.Port)
	return appendQPAttr(request, rdmaAttrLQPN, qp.LocalQPN)
}

// noteRawQueryError records a failed raw query. A QP that no longer exists
// is not a failure; a device that denies raw queries is not queried again.
func noteRawQueryError(failures map[uint32]error, blocked map[uint32]bool, dev uint32, err error) {
	if !errors.Is(err, syscall.ENOENT) {
		failures[dev] = err
	}
	blocked[dev] = errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EOPNOTSUPP)
}

// decodeRawQPReply decodes the single raw dump that answers qp's query.
func decodeRawQPReply(msgs [][]byte, qp QPResource) (Connection, error) {
	if len(msgs) != 1 {
		return Connection{}, fmt.Errorf("unexpected raw QP response count")
	}
	a, err := rdmaAttrs(msgs[0])
	if err != nil {
		return Connection{}, err
	}
	return decodeMlx5QP(a[rdmaAttrRaw], qp)
}

// qpUnchanged rechecks ownership/state before exporting a recovered address:
// a QPN may have been reused between inventory and raw queries. A failed
// recheck counts as a change.
func qpUnchanged(ctx context.Context, query rdmaDump, request []byte, qp QPResource) bool {
	current, err := query(ctx, rdmaCmdResQPGet, request)
	if err != nil || len(current) != 1 {
		return false
	}
	attrs, err := rdmaAttrs(current[0])
	if err != nil {
		return false
	}
	verified, err := decodeQPResource(attrs, qp.Dev)
	verified.OwnerTGID = qp.OwnerTGID
	return err == nil && verified == qp
}

// recoveryError joins the last failure of each device.
func recoveryError(eligible map[uint32]string, failures map[uint32]error) error {
	var all []error
	for dev, err := range failures {
		all = append(all, fmt.Errorf("recover QPs on %s (raw queries need CAP_NET_ADMIN and supported mlx5 firmware): %w", eligible[dev], err))
	}
	return errors.Join(all...)
}

func appendQPAttr(dst []byte, kind uint16, value uint32) []byte {
	attr := make([]byte, 8)
	binary.NativeEndian.PutUint16(attr, 8)
	binary.NativeEndian.PutUint16(attr[2:], kind)
	binary.NativeEndian.PutUint32(attr[4:], value)
	return append(dst, attr...)
}
