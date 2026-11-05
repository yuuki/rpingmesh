package servicetrace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func qpIdentityAttrs(qp QPResource) []byte {
	attrs := nlJoin(nlAttr(21, nlU32(qp.LocalQPN)), nlAttr(22, nlU32(qp.RemoteQPN)), nlAttr(26, []byte{byte(qp.QPType)}), nlAttr(27, []byte{qp.QPState}), nlAttr(3, nlU32(qp.Port)))
	if qp.PID != 0 {
		attrs = append(attrs, nlAttr(28, nlU32(qp.PID))...)
	}
	return attrs
}

func TestRecoverQPsDriverOwnershipAndFallback(t *testing.T) {
	qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 42}
	for _, mode := range []string{"mlx5", "creator_exited", "kernel", "other_driver", "permission", "reused_qpn", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			qp := qp
			if mode == "creator_exited" {
				qp.PID = 0
			}
			qp.Kernel = mode == "kernel"
			calls := 0
			got, err := recoverQPs(context.Background(), map[uint32]string{devA: "mlx5_0"}, []QPResource{qp},
				func(_ context.Context, cmd uint16, _ []byte) ([][]byte, error) {
					if cmd != 5121 {
						t.Fatalf("dump command = %d", cmd)
					}
					return [][]byte{nlJoin(nlAttr(1, nlU32(5)), nlAttr(2, []byte("mlx5_0\x00")))}, nil
				},
				func(_ context.Context, cmd uint16, request []byte) ([][]byte, error) {
					calls++
					a, err := rdmaAttrs(request)
					if err != nil || string(a[1]) != string(nlU32(5)) || string(a[3]) != string(nlU32(1)) || string(a[21]) != string(nlU32(qp.LocalQPN)) {
						t.Fatalf("request = %x, %v", request, err)
					}
					if calls == 1 {
						if cmd != 5139 {
							t.Fatalf("raw command = %d", cmd)
						}
						if mode == "permission" {
							return nil, syscall.EPERM
						}
						if mode == "malformed" {
							return [][]byte{nlAttr(85, []byte{1, 2, 3})}, nil
						}
						return [][]byte{nlAttr(85, mlx5QPFixture(qp, 0))}, nil
					}
					if cmd != 5130 {
						t.Fatalf("verification command = %d", cmd)
					}
					current := qp
					if mode == "reused_qpn" {
						current.PID++
					}
					return [][]byte{qpIdentityAttrs(current)}, nil
				}, func(string) string {
					if mode == "other_driver" {
						return "other"
					}
					return "mlx5_core"
				})
			if len(got) != 1 || (got[0].Recovered != nil) != (mode == "mlx5" || mode == "creator_exited") {
				t.Fatalf("recovery = %+v, %v", got, err)
			}
			if mode == "permission" && !errors.Is(err, syscall.EPERM) {
				t.Fatalf("permission error = %v", err)
			}
			if (mode == "other_driver" || mode == "kernel") && calls != 0 {
				t.Fatal("queried an unsupported driver or kernel resource")
			}
		})
	}
}

// mlx5FixtureFor is mlx5QPFixture with the MLX5_QP_ST_* transport that
// firmware reports for qp's type (values from mlx5_ifc.h, independent of the
// decoder).
func mlx5FixtureFor(qp QPResource, flowLabel uint32) []byte {
	raw := mlx5QPFixture(qp, flowLabel)
	raw[77] = map[uint32]byte{QPTypeRC: 0, QPTypeUC: 1, QPTypeXRCInitiator: 3, QPTypeXRCTarget: 3}[qp.QPType]
	return raw
}

// mlx5FixtureConnection is the connection mlx5QPFixture describes.
func mlx5FixtureConnection(qp QPResource, flowLabel uint32) Connection {
	c := Connection{
		FromSnapshot: true, Dev: qp.Dev, LocalQPN: qp.LocalQPN, RemoteQPN: qp.RemoteQPN, QPType: qp.QPType,
		PID: qp.OwnerTGID, FlowLabel: flowLabel, TrafficClass: 0xa5, SGIDIndex: 3, HopLimit: 64, SL: 5, Port: uint8(qp.Port),
	}
	c.RemoteGID[10], c.RemoteGID[11], c.RemoteGID[15] = 0xff, 0xff, 7
	return c
}

type recoveryReply struct {
	msgs [][]byte
	err  error
}

// recoveryKernel answers recoverQPs' netlink requests per local QPN and
// records every request in order.
type recoveryKernel struct {
	t       *testing.T
	devices [][]byte
	dumpErr error
	raw     map[uint32]recoveryReply
	verify  map[uint32]recoveryReply
	onQuery func()
	log     []string
}

func (k *recoveryKernel) dump(_ context.Context, cmd uint16, attrs []byte) ([][]byte, error) {
	if cmd != 5121 || attrs != nil {
		k.t.Fatalf("dump request = %d %x", cmd, attrs)
	}
	k.log = append(k.log, "get")
	return k.devices, k.dumpErr
}

func (k *recoveryKernel) query(_ context.Context, cmd uint16, request []byte) ([][]byte, error) {
	a, err := rdmaAttrs(request)
	if err != nil || len(a) != 3 || len(a[1]) != 4 || len(a[3]) != 4 || len(a[21]) != 4 {
		k.t.Fatalf("query request = %x, %v", request, err)
	}
	index, port, qpn := binary.NativeEndian.Uint32(a[1]), binary.NativeEndian.Uint32(a[3]), binary.NativeEndian.Uint32(a[21])
	if want := nlJoin(nlAttr(1, nlU32(index)), nlAttr(3, nlU32(port)), nlAttr(21, nlU32(qpn))); !reflect.DeepEqual(request, want) {
		k.t.Fatalf("query request = %x, want %x", request, want)
	}
	replies := map[uint16]map[uint32]recoveryReply{5139: k.raw, 5130: k.verify}[cmd]
	if replies == nil {
		k.t.Fatalf("query command = %d", cmd)
	}
	k.log = append(k.log, fmt.Sprintf("%s index=%d port=%d qpn=%#x", map[uint16]string{5139: "raw", 5130: "verify"}[cmd], index, port, qpn))
	if k.onQuery != nil {
		k.onQuery()
	}
	r, ok := replies[qpn]
	if !ok {
		k.t.Fatalf("unexpected query for QPN %#x", qpn)
	}
	return r.msgs, r.err
}

func rdmaDevice(index uint32, name string) []byte {
	return nlJoin(nlAttr(1, nlU32(index)), nlAttr(2, []byte(name)))
}

func rawReply(qp QPResource, flowLabel uint32) recoveryReply {
	return recoveryReply{msgs: [][]byte{nlAttr(85, mlx5FixtureFor(qp, flowLabel))}}
}

func verifyReply(qp QPResource) recoveryReply {
	return recoveryReply{msgs: [][]byte{qpIdentityAttrs(qp)}}
}

func mlx5Drivers(name string) string {
	if strings.HasPrefix(name, "mlx5_") {
		return "mlx5_core"
	}
	return "rdma_rxe"
}

const recoveryHint = " (raw queries need CAP_NET_ADMIN and supported mlx5 firmware): "

func TestRecoverQPsCharacterization(t *testing.T) {
	devC := uint32(0xe7000c2)
	base := QPResource{Dev: devA, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 42, OwnerTGID: 42}
	qp := func(qpn uint32, change func(*QPResource)) QPResource {
		q := base
		q.LocalQPN = qpn
		if change != nil {
			change(&q)
		}
		return q
	}
	onDevB := func(q *QPResource) { q.Dev, q.Port = devB, 2 }
	uc := qp(0x102, func(q *QPResource) { q.QPType, q.QPState = QPTypeUC, QPStateRTR })
	xrcIni := qp(0x103, func(q *QPResource) { q.QPType = QPTypeXRCInitiator })
	xrcTgt := qp(0x104, func(q *QPResource) { q.QPType = QPTypeXRCTarget })
	onB := qp(0x200, onDevB)
	stale := &Connection{LocalQPN: 1}
	wrapped := func(err error) error { return fmt.Errorf("fake netlink: %w", err) }
	errIO := wrapped(syscall.EIO)
	devices := [][]byte{rdmaDevice(5, "mlx5_0\x00"), rdmaDevice(9, "mlx5_1\x00"), rdmaDevice(3, "rxe0\x00")}
	all := map[uint32]string{devA: "mlx5_0", devB: "mlx5_1", devC: "rxe0"}

	type recovered map[int]Connection
	for _, tt := range []struct {
		name      string
		devices   map[uint32]string
		resources []QPResource
		kernel    recoveryKernel
		cancel    bool // cancel the context during the first query
		want      recovered
		wantNil   bool
		wantLog   []string
		wantErr   []string // error lines, one per failing device, in any order
		wantIs    []error
	}{
		{name: "no devices", resources: []QPResource{qp(0x100, nil)}},
		{name: "no mlx5 device", devices: map[uint32]string{devC: "rxe0"}, resources: []QPResource{qp(0x100, func(q *QPResource) { q.Dev = devC })}},
		{
			name: "device list error is returned as is", devices: all, resources: []QPResource{qp(0x100, nil)},
			kernel: recoveryKernel{dumpErr: errIO}, wantLog: []string{"get"}, wantErr: []string{errIO.Error()}, wantIs: []error{errIO},
		},
		{
			name: "malformed device list", devices: all, resources: []QPResource{qp(0x100, nil)},
			kernel: recoveryKernel{devices: [][]byte{{1, 2, 3}}}, wantLog: []string{"get"}, wantErr: []string{"truncated RDMA netlink attribute header"},
		},
		{
			name: "device names need their NUL and a 4-byte index", devices: all, resources: []QPResource{qp(0x100, nil), onB},
			kernel:  recoveryKernel{devices: [][]byte{rdmaDevice(5, "mlx5_0"), nlJoin(nlAttr(1, []byte{9, 0}), nlAttr(2, []byte("mlx5_1\x00")))}},
			wantLog: []string{"get"},
		},
		{
			name: "no resources", devices: all, kernel: recoveryKernel{devices: devices}, wantLog: []string{"get"},
		},
		{
			name: "recovers eligible connected QPs in order", devices: all,
			resources: []QPResource{
				qp(0x100, func(q *QPResource) { q.OwnerTGID = 77 }), // the verification does not know the owner
				onB,
				qp(0x300, func(q *QPResource) { q.Dev = devC }),
				qp(0x101, func(q *QPResource) { q.QPType = QPTypeUD }),
				qp(0x105, func(q *QPResource) { q.QPType = QPTypeDriver }),
				qp(0x106, func(q *QPResource) { q.Kernel = true }),
				qp(0x107, func(q *QPResource) { q.Port = 0 }),
				qp(0x108, func(q *QPResource) { q.QPState = QPStateInit }),
				qp(0x109, func(q *QPResource) { q.QPState = 4 }), // SQD
				qp(0x10a, func(q *QPResource) { q.QPState = QPStateErr }),
				uc, xrcIni, xrcTgt,
				qp(0x10b, func(q *QPResource) { q.Dev = 0xdead }), // not in the device map
			},
			kernel: recoveryKernel{
				devices: append([][]byte{rdmaDevice(4, "mlx5_0\x00")}, devices...), // the last index wins
				raw: map[uint32]recoveryReply{
					0x100: rawReply(qp(0x100, func(q *QPResource) { q.OwnerTGID = 77 }), 0xabcde), 0x200: rawReply(onB, 0),
					0x102: rawReply(uc, 1), 0x103: rawReply(xrcIni, 2), 0x104: rawReply(xrcTgt, 3),
				},
				verify: map[uint32]recoveryReply{
					0x100: verifyReply(qp(0x100, nil)), 0x200: verifyReply(onB), 0x102: verifyReply(uc), 0x103: verifyReply(xrcIni), 0x104: verifyReply(xrcTgt),
				},
			},
			want: recovered{
				0:  mlx5FixtureConnection(qp(0x100, func(q *QPResource) { q.OwnerTGID = 77 }), 0xabcde),
				1:  mlx5FixtureConnection(onB, 0),
				10: mlx5FixtureConnection(uc, 1), 11: mlx5FixtureConnection(xrcIni, 2), 12: mlx5FixtureConnection(xrcTgt, 3),
			},
			wantLog: []string{
				"get", "raw index=5 port=1 qpn=0x100", "verify index=5 port=1 qpn=0x100", "raw index=9 port=2 qpn=0x200", "verify index=9 port=2 qpn=0x200",
				"raw index=5 port=1 qpn=0x102", "verify index=5 port=1 qpn=0x102", "raw index=5 port=1 qpn=0x103", "verify index=5 port=1 qpn=0x103",
				"raw index=5 port=1 qpn=0x104", "verify index=5 port=1 qpn=0x104",
			},
		},
		{
			name: "missing QP is skipped without failure", devices: all, resources: []QPResource{qp(0x100, nil), qp(0x101, nil)},
			kernel: recoveryKernel{devices: devices,
				raw:    map[uint32]recoveryReply{0x100: {err: wrapped(syscall.ENOENT)}, 0x101: rawReply(qp(0x101, nil), 0)},
				verify: map[uint32]recoveryReply{0x101: verifyReply(qp(0x101, nil))}},
			want:    recovered{1: mlx5FixtureConnection(qp(0x101, nil), 0)},
			wantLog: []string{"get", "raw index=5 port=1 qpn=0x100", "raw index=5 port=1 qpn=0x101", "verify index=5 port=1 qpn=0x101"},
		},
		{
			name: "other errors fail the device without blocking it", devices: all, resources: []QPResource{qp(0x100, nil), qp(0x101, nil)},
			kernel: recoveryKernel{devices: devices,
				raw:    map[uint32]recoveryReply{0x100: {err: errIO}, 0x101: rawReply(qp(0x101, nil), 0)},
				verify: map[uint32]recoveryReply{0x101: verifyReply(qp(0x101, nil))}},
			want:    recovered{1: mlx5FixtureConnection(qp(0x101, nil), 0)},
			wantLog: []string{"get", "raw index=5 port=1 qpn=0x100", "raw index=5 port=1 qpn=0x101", "verify index=5 port=1 qpn=0x101"},
			wantErr: []string{"recover QPs on mlx5_0" + recoveryHint + errIO.Error()}, wantIs: []error{syscall.EIO},
		},
		{
			name: "last failure of a device wins", devices: all, resources: []QPResource{qp(0x100, nil), qp(0x101, nil), qp(0x102, nil), qp(0x103, nil), qp(0x104, nil)},
			kernel: recoveryKernel{devices: devices, raw: map[uint32]recoveryReply{
				0x100: {err: errIO},
				0x101: {msgs: [][]byte{}},
				0x102: {msgs: [][]byte{nlAttr(85, nil), nlAttr(85, nil)}},
				0x103: {msgs: [][]byte{{1, 2, 3}}},
				0x104: {msgs: [][]byte{nlAttr(1, nlU32(5))}},
			}},
			wantLog: []string{"get", "raw index=5 port=1 qpn=0x100", "raw index=5 port=1 qpn=0x101", "raw index=5 port=1 qpn=0x102", "raw index=5 port=1 qpn=0x103", "raw index=5 port=1 qpn=0x104"},
			wantErr: []string{"recover QPs on mlx5_0" + recoveryHint + "unsupported mlx5 QP dump: missing successful query output"},
		},
		{
			name: "response count and framing failures", devices: all, resources: []QPResource{qp(0x100, nil), onB},
			kernel:  recoveryKernel{devices: devices, raw: map[uint32]recoveryReply{0x100: {msgs: [][]byte{nlAttr(85, nil), nlAttr(85, nil)}}, 0x200: {msgs: [][]byte{{1, 2, 3}}}}},
			wantLog: []string{"get", "raw index=5 port=1 qpn=0x100", "raw index=9 port=2 qpn=0x200"},
			wantErr: []string{"recover QPs on mlx5_0" + recoveryHint + "unexpected raw QP response count", "recover QPs on mlx5_1" + recoveryHint + "truncated RDMA netlink attribute header"},
		},
		{
			name: "a failure is kept after a later success", devices: all, resources: []QPResource{qp(0x100, nil), qp(0x101, nil)},
			kernel: recoveryKernel{devices: devices,
				raw:    map[uint32]recoveryReply{0x100: {err: errIO}, 0x101: rawReply(qp(0x101, nil), 0)},
				verify: map[uint32]recoveryReply{0x101: verifyReply(qp(0x101, nil))}},
			want:    recovered{1: mlx5FixtureConnection(qp(0x101, nil), 0)},
			wantLog: []string{"get", "raw index=5 port=1 qpn=0x100", "raw index=5 port=1 qpn=0x101", "verify index=5 port=1 qpn=0x101"},
			wantErr: []string{"recover QPs on mlx5_0" + recoveryHint + errIO.Error()},
		},
		{
			name: "verification failures skip silently", devices: all,
			resources: []QPResource{qp(0x100, nil), qp(0x101, nil), qp(0x102, nil), qp(0x103, nil), qp(0x104, nil), qp(0x105, nil), qp(0x106, nil), qp(0x107, nil), qp(0x108, nil), qp(0x109, func(q *QPResource) { q.Recovered = stale })},
			kernel: recoveryKernel{devices: devices,
				raw: map[uint32]recoveryReply{
					0x100: rawReply(qp(0x100, nil), 0), 0x101: rawReply(qp(0x101, nil), 0), 0x102: rawReply(qp(0x102, nil), 0), 0x103: rawReply(qp(0x103, nil), 0),
					0x104: rawReply(qp(0x104, nil), 0), 0x105: rawReply(qp(0x105, nil), 0), 0x106: rawReply(qp(0x106, nil), 0), 0x107: rawReply(qp(0x107, nil), 0),
					0x108: rawReply(qp(0x108, nil), 0), 0x109: rawReply(qp(0x109, nil), 0),
				},
				verify: map[uint32]recoveryReply{
					0x100: {err: errIO},
					0x101: {msgs: [][]byte{}},
					0x102: {msgs: [][]byte{qpIdentityAttrs(qp(0x102, nil)), qpIdentityAttrs(qp(0x102, nil))}},
					0x103: {msgs: [][]byte{{1, 2, 3}}},
					0x104: {msgs: [][]byte{nlAttr(21, nlU32(0x104))}},
					0x105: verifyReply(qp(0x105, func(q *QPResource) { q.PID = 43 })),
					0x106: verifyReply(qp(0x106, func(q *QPResource) { q.QPState = QPStateRTR })),
					0x107: verifyReply(qp(0x107, func(q *QPResource) { q.RemoteQPN = 0x201 })),
					0x108: {msgs: [][]byte{append(qpIdentityAttrs(qp(0x108, nil)), nlAttr(29, []byte("kernel\x00"))...)}},
					0x109: verifyReply(qp(0x109, nil)), // a previous recovery makes the inventory differ
				}},
			want: recovered{},
			wantLog: []string{"get",
				"raw index=5 port=1 qpn=0x100", "verify index=5 port=1 qpn=0x100", "raw index=5 port=1 qpn=0x101", "verify index=5 port=1 qpn=0x101",
				"raw index=5 port=1 qpn=0x102", "verify index=5 port=1 qpn=0x102", "raw index=5 port=1 qpn=0x103", "verify index=5 port=1 qpn=0x103",
				"raw index=5 port=1 qpn=0x104", "verify index=5 port=1 qpn=0x104", "raw index=5 port=1 qpn=0x105", "verify index=5 port=1 qpn=0x105",
				"raw index=5 port=1 qpn=0x106", "verify index=5 port=1 qpn=0x106", "raw index=5 port=1 qpn=0x107", "verify index=5 port=1 qpn=0x107",
				"raw index=5 port=1 qpn=0x108", "verify index=5 port=1 qpn=0x108", "raw index=5 port=1 qpn=0x109", "verify index=5 port=1 qpn=0x109",
			},
		},
		{
			name: "cancellation between QPs discards the inventory", devices: all, resources: []QPResource{qp(0x100, nil), qp(0x101, nil)}, cancel: true,
			kernel: recoveryKernel{devices: devices,
				raw:    map[uint32]recoveryReply{0x100: rawReply(qp(0x100, nil), 0)},
				verify: map[uint32]recoveryReply{0x100: verifyReply(qp(0x100, nil))}},
			wantNil: true, wantLog: []string{"get", "raw index=5 port=1 qpn=0x100", "verify index=5 port=1 qpn=0x100"},
			wantErr: []string{context.Canceled.Error()}, wantIs: []error{context.Canceled},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			k := tt.kernel
			k.t = t
			if tt.cancel {
				k.onQuery = cancel
			}
			input := slices.Clone(tt.resources)
			got, err := recoverQPs(ctx, tt.devices, tt.resources, k.dump, k.query, mlx5Drivers)
			if !reflect.DeepEqual(tt.resources, input) {
				t.Fatalf("recoverQPs modified its input: %+v", tt.resources)
			}
			if !slices.Equal(k.log, tt.wantLog) {
				t.Fatalf("requests = %q, want %q", k.log, tt.wantLog)
			}
			var want []QPResource
			if !tt.wantNil {
				want = slices.Clone(tt.resources)
				for i, c := range tt.want {
					want[i].Recovered = &c
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("recovered = %+v, want %+v", got, want)
			}
			var lines []string
			if err != nil {
				lines = strings.Split(err.Error(), "\n")
				slices.Sort(lines)
			}
			wantLines := slices.Sorted(slices.Values(tt.wantErr))
			if !slices.Equal(lines, wantLines) {
				t.Fatalf("error = %q, want %q", lines, wantLines)
			}
			for _, target := range tt.wantIs {
				if !errors.Is(err, target) {
					t.Fatalf("error %v does not wrap %v", err, target)
				}
			}
		})
	}
}

func TestRecoverQPsAccessErrorsBlockTheDevice(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES, syscall.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			denied := fmt.Errorf("fake netlink: %w", errno)
			qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 42}
			next, onB := qp, qp
			next.LocalQPN = 0x101
			onB.Dev, onB.LocalQPN = devB, 0x200
			k := recoveryKernel{t: t, devices: [][]byte{rdmaDevice(5, "mlx5_0\x00"), rdmaDevice(9, "mlx5_1\x00")},
				raw:    map[uint32]recoveryReply{0x100: {err: denied}, 0x200: rawReply(onB, 0)},
				verify: map[uint32]recoveryReply{0x200: verifyReply(onB)}}
			got, err := recoverQPs(context.Background(), map[uint32]string{devA: "mlx5_0", devB: "mlx5_1"}, []QPResource{qp, next, onB}, k.dump, k.query, mlx5Drivers)
			wantLog := []string{"get", "raw index=5 port=1 qpn=0x100", "raw index=9 port=1 qpn=0x200", "verify index=9 port=1 qpn=0x200"}
			if !slices.Equal(k.log, wantLog) {
				t.Fatalf("requests = %q, want %q", k.log, wantLog)
			}
			if len(got) != 3 || got[0].Recovered != nil || got[1].Recovered != nil || got[2].Recovered == nil || *got[2].Recovered != mlx5FixtureConnection(onB, 0) {
				t.Fatalf("recovered = %+v", got)
			}
			if !errors.Is(err, errno) || err.Error() != "recover QPs on mlx5_0"+recoveryHint+denied.Error() {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// Each failure site replaces an earlier failure of the same device.
func TestRecoverQPsReportsTheLastFailure(t *testing.T) {
	qp := QPResource{Dev: devA, LocalQPN: 0x100, RemoteQPN: 0x200, QPType: QPTypeRC, QPState: QPStateRTS, Port: 1, PID: 42}
	next := qp
	next.LocalQPN = 0x101
	errIO := fmt.Errorf("fake netlink: %w", syscall.EIO)
	earlier := map[uint32]recoveryReply{0x100: {msgs: [][]byte{nlAttr(1, nlU32(5))}}}
	for _, tt := range []struct {
		name  string
		first map[uint32]recoveryReply
		last  recoveryReply
		want  string
	}{
		{"query error", earlier, recoveryReply{err: errIO}, errIO.Error()},
		{"response count", nil, recoveryReply{msgs: [][]byte{}}, "unexpected raw QP response count"},
		{"framing", nil, recoveryReply{msgs: [][]byte{{1, 2, 3}}}, "truncated RDMA netlink attribute header"},
		{"dump", nil, recoveryReply{msgs: [][]byte{nlAttr(85, []byte{0, 1})}}, "unsupported mlx5 QP dump: truncated or trailing segment"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := map[uint32]recoveryReply{0x100: {err: errIO}, 0x101: tt.last}
			for qpn, r := range tt.first {
				raw[qpn] = r
			}
			k := recoveryKernel{t: t, devices: [][]byte{rdmaDevice(5, "mlx5_0\x00")}, raw: raw}
			_, err := recoverQPs(context.Background(), map[uint32]string{devA: "mlx5_0"}, []QPResource{qp, next}, k.dump, k.query, mlx5Drivers)
			if err == nil || err.Error() != "recover QPs on mlx5_0"+recoveryHint+tt.want {
				t.Fatalf("error = %v, want the failure of QPN 0x101: %s", err, tt.want)
			}
		})
	}
}
