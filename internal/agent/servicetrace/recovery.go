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
	eligible := make(map[uint32]string)
	for dev, name := range devices {
		if driver(name) == "mlx5_core" {
			eligible[dev] = name
		}
	}
	if len(eligible) == 0 {
		return out, nil
	}
	msgs, err := dump(ctx, rdmaCmdGet, nil)
	if err != nil {
		return out, err
	}
	indexes := make(map[uint32]uint32)
	for _, msg := range msgs {
		a, err := rdmaAttrs(msg)
		if err != nil {
			return out, err
		}
		for dev, name := range eligible {
			if string(a[rdmaAttrDevName]) == name+"\x00" && len(a[rdmaAttrDevIndex]) == 4 {
				indexes[dev] = binary.NativeEndian.Uint32(a[rdmaAttrDevIndex])
			}
		}
	}
	failures := make(map[uint32]error)
	blocked := make(map[uint32]bool)
	for i, qp := range out {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		_, supported := indexes[qp.Dev]
		if !supported || blocked[qp.Dev] || qp.Kernel || !IsConnectedType(qp.QPType) || qp.Port == 0 || (qp.QPState != QPStateRTR && qp.QPState != QPStateRTS) {
			continue
		}
		request := appendQPAttr(nil, rdmaAttrDevIndex, indexes[qp.Dev])
		request = appendQPAttr(request, rdmaAttrPortIndex, qp.Port)
		request = appendQPAttr(request, rdmaAttrLQPN, qp.LocalQPN)
		msgs, err := query(ctx, rdmaCmdResQPGetRaw, request)
		if err != nil {
			if !errors.Is(err, syscall.ENOENT) {
				failures[qp.Dev] = err
			}
			blocked[qp.Dev] = errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EOPNOTSUPP)
			continue
		}
		if len(msgs) != 1 {
			failures[qp.Dev] = fmt.Errorf("unexpected raw QP response count")
			continue
		}
		a, err := rdmaAttrs(msgs[0])
		if err != nil {
			failures[qp.Dev] = err
			continue
		}
		conn, err := decodeMlx5QP(a[rdmaAttrRaw], qp)
		if err != nil {
			failures[qp.Dev] = err
			continue
		}
		// A QPN may have been reused between inventory and raw queries.
		// Recheck ownership/state before exporting the recovered address.
		current, err := query(ctx, rdmaCmdResQPGet, request)
		if err != nil || len(current) != 1 {
			continue
		}
		attrs, err := rdmaAttrs(current[0])
		if err != nil {
			continue
		}
		verified, err := decodeQPResource(attrs, qp.Dev)
		verified.OwnerTGID = qp.OwnerTGID
		if err != nil || verified != qp {
			continue
		}
		out[i].Recovered = &conn
	}
	var all []error
	for dev, err := range failures {
		all = append(all, fmt.Errorf("recover QPs on %s (raw queries need CAP_NET_ADMIN and supported mlx5 firmware): %w", eligible[dev], err))
	}
	return out, errors.Join(all...)
}

func appendQPAttr(dst []byte, kind uint16, value uint32) []byte {
	attr := make([]byte, 8)
	binary.NativeEndian.PutUint16(attr, 8)
	binary.NativeEndian.PutUint16(attr[2:], kind)
	binary.NativeEndian.PutUint32(attr[4:], value)
	return append(dst, attr...)
}
