//go:build linux

package servicetrace

import (
	"context"
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRDMADumpStatus(t *testing.T) {
	for _, tt := range []struct {
		name string
		msg  syscall.NetlinkMessage
		done bool
		err  bool
	}{
		{"data", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: rdmaCmdResQPGet}}, false, false},
		{"done", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}}, true, false},
		{"done_status", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}, Data: nlU32(0)}, true, false},
		{"ack", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_ERROR}, Data: nlU32(0)}, false, false},
		{"permission", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_ERROR}, Data: nlU32(0xffffffff)}, false, true},
		{"failed_done", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}, Data: nlU32(0xffffffea)}, false, true},
		{"short_done", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}, Data: []byte{0}}, false, true},
		{"short_error", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_ERROR}}, false, true},
		{"interrupted", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE, Flags: unix.NLM_F_DUMP_INTR}}, false, true},
		{"overrun", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_OVERRUN}}, false, true},
		{"wrong_command", syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: rdmaCmdGet}}, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			done, err := checkRDMAMessage(tt.msg, rdmaCmdResQPGet)
			if done != tt.done || (err != nil) != tt.err {
				t.Fatalf("done=%v err=%v", done, err)
			}
		})
	}
}

func TestRDMADumpCancelledBeforeSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dumpRDMA(ctx, -1, 1, rdmaCmdGet, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled dump = %v", err)
	}
}
