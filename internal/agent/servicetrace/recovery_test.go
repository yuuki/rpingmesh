package servicetrace

import (
	"context"
	"errors"
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
