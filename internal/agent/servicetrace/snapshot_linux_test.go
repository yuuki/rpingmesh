//go:build linux

package servicetrace

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"syscall"
	"testing"
	"time"

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

// The generic netlink controller (nlctrl) answers with its own message type
// and the request's sequence number, like RDMA netlink, and exists in every
// Linux network namespace. It lets these tests drive requestRDMA against a
// real kernel responder without RDMA hardware.

func openGenlSocket(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_GENERIC)
	if err != nil {
		t.Skipf("generic netlink unavailable: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	return fd
}

func genlCtrl(cmd uint8, attrs ...[]byte) []byte {
	return nlJoin(append([][]byte{{cmd, 1, 0, 0}}, attrs...)...)
}

func genlFamilyQuery(name string) []byte {
	return genlCtrl(unix.CTRL_CMD_GETFAMILY, nlAttr(unix.CTRL_ATTR_FAMILY_NAME, []byte(name+"\x00")))
}

// sendNetlink queues a request whose reply requestRDMA reads before its own.
func sendNetlink(t *testing.T, fd int, typ, flags uint16, seq uint32, payload []byte) {
	t.Helper()
	msg := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(msg, uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], typ)
	binary.NativeEndian.PutUint16(msg[6:], flags)
	binary.NativeEndian.PutUint32(msg[8:], seq)
	copy(msg[unix.NLMSG_HDRLEN:], payload)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
}

// genlFamilies decodes CTRL_CMD_NEWFAMILY replies into family names in order.
func genlFamilies(t *testing.T, msgs [][]byte) []string {
	t.Helper()
	var names []string
	for _, msg := range msgs {
		if len(msg) < 4 || msg[0] != unix.CTRL_CMD_NEWFAMILY {
			t.Fatalf("reply is not a family: %x", msg)
		}
		a, err := rdmaAttrs(msg[4:])
		if err != nil {
			t.Fatal(err)
		}
		name := a[unix.CTRL_ATTR_FAMILY_NAME]
		if len(name) < 2 || name[len(name)-1] != 0 || len(a[unix.CTRL_ATTR_FAMILY_ID]) != 2 {
			t.Fatalf("malformed family: %x", msg)
		}
		names = append(names, string(name[:len(name)-1]))
	}
	return names
}

func TestRequestRDMAQueryReturnsSingleReply(t *testing.T) {
	fd := openGenlSocket(t)
	msgs, err := requestRDMA(context.Background(), fd, 7, unix.GENL_ID_CTRL, genlFamilyQuery("nlctrl"), false)
	if err != nil {
		t.Fatal(err)
	}
	if names := genlFamilies(t, msgs); len(names) != 1 || names[0] != "nlctrl" {
		t.Fatalf("query replies = %q", names)
	}
}

func TestRequestRDMADumpCollectsUntilDone(t *testing.T) {
	fd := openGenlSocket(t)
	msgs, err := requestRDMA(context.Background(), fd, 7, unix.GENL_ID_CTRL, genlCtrl(unix.CTRL_CMD_GETFAMILY), true)
	if err != nil {
		t.Fatal(err)
	}
	// A family query without a name is invalid, so only a dump answers it.
	names := genlFamilies(t, msgs)
	if len(names) == 0 || names[0] != "nlctrl" {
		t.Fatalf("dump replies = %q", names)
	}
	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			t.Fatalf("dump repeats family %q: %q", name, names)
		}
		seen[name] = true
	}
}

// Replies of one request can arrive in several datagrams; each message must
// survive the next receive into the shared buffer, in arrival order.
func TestRequestRDMADumpAcrossDatagrams(t *testing.T) {
	fd := openGenlSocket(t)
	all, err := requestRDMA(context.Background(), fd, 1, unix.GENL_ID_CTRL, genlCtrl(unix.CTRL_CMD_GETFAMILY), true)
	if err != nil {
		t.Fatal(err)
	}
	families := genlFamilies(t, all)
	if len(families) < 2 {
		t.Skip("only the controller family is registered")
	}
	last := families[len(families)-1]
	sendNetlink(t, fd, unix.GENL_ID_CTRL, unix.NLM_F_REQUEST, 2, genlFamilyQuery(last))
	msgs, err := requestRDMA(context.Background(), fd, 2, unix.GENL_ID_CTRL, genlCtrl(unix.CTRL_CMD_GETFAMILY), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := genlFamilies(t, msgs); !reflect.DeepEqual(got, append([]string{last}, families...)) {
		t.Fatalf("replies = %q, want %q then %q", got, last, families)
	}
}

func TestRequestRDMAKernelErrorIsErrno(t *testing.T) {
	fd := openGenlSocket(t)
	_, err := requestRDMA(context.Background(), fd, 7, unix.GENL_ID_CTRL, genlFamilyQuery("rpm-no-family"), false)
	if err != syscall.ENOENT {
		t.Fatalf("unknown family = %#v, want the kernel's ENOENT", err)
	}
	// Without NLM_F_DUMP the controller rejects a family query with no name.
	if _, err := requestRDMA(context.Background(), fd, 8, unix.GENL_ID_CTRL, genlCtrl(unix.CTRL_CMD_GETFAMILY), false); err != syscall.EINVAL {
		t.Fatalf("nameless query = %#v, want EINVAL", err)
	}
}

func TestRequestRDMASkipsAcknowledgement(t *testing.T) {
	fd := openGenlSocket(t)
	// A successful status (an ACK) neither ends nor fails a request.
	sendNetlink(t, fd, unix.NLMSG_NOOP, unix.NLM_F_REQUEST|unix.NLM_F_ACK, 7, nil)
	msgs, err := requestRDMA(context.Background(), fd, 7, unix.GENL_ID_CTRL, genlFamilyQuery("nlctrl"), false)
	if err != nil {
		t.Fatal(err)
	}
	if names := genlFamilies(t, msgs); len(names) != 1 || names[0] != "nlctrl" {
		t.Fatalf("replies after an ACK = %q", names)
	}
}

func TestRequestRDMARejectsStaleSequence(t *testing.T) {
	fd := openGenlSocket(t)
	sendNetlink(t, fd, unix.GENL_ID_CTRL, unix.NLM_F_REQUEST, 6, genlFamilyQuery("nlctrl"))
	_, err := requestRDMA(context.Background(), fd, 7, unix.GENL_ID_CTRL, genlFamilyQuery("nlctrl"), false)
	if err == nil || err.Error() != "RDMA netlink response sequence mismatch" {
		t.Fatalf("stale reply = %v", err)
	}
}

func TestRequestRDMAQueryRejectsMultipart(t *testing.T) {
	fd := openGenlSocket(t)
	sendNetlink(t, fd, unix.GENL_ID_CTRL, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, 7, genlCtrl(unix.CTRL_CMD_GETFAMILY))
	_, err := requestRDMA(context.Background(), fd, 7, unix.GENL_ID_CTRL, genlFamilyQuery("nlctrl"), false)
	if err == nil || err.Error() != "unexpected multipart RDMA query response" {
		t.Fatalf("multipart reply to a query = %v", err)
	}
}

func TestRequestRDMACancelledWhileWaiting(t *testing.T) {
	fd := openGenlSocket(t)
	// The kernel answers a NOOP request only when it asks for an ACK.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := requestRDMA(ctx, fd, 7, unix.NLMSG_NOOP, nil, false)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unanswered request = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("requestRDMA ignored its context while waiting for a reply")
	}
}

func TestRequestRDMASendErrorIsReturned(t *testing.T) {
	if _, err := requestRDMA(context.Background(), -1, 1, rdmaCmdGet, nil, false); !errors.Is(err, unix.EBADF) {
		t.Fatalf("send on a closed socket = %v", err)
	}
}

// sendFromPeer delivers a datagram from a user-space netlink socket, which
// needs CAP_NET_ADMIN on generic netlink.
func sendFromPeer(t *testing.T, fd int, payload []byte) {
	t.Helper()
	local, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	peer := openGenlSocket(t)
	if len(payload) > 1<<19 {
		// Make room for the datagram at both ends; the kernel would
		// otherwise drop it and report an overrun to the receiver.
		for _, opt := range []struct{ fd, name int }{{peer, unix.SO_SNDBUFFORCE}, {fd, unix.SO_RCVBUFFORCE}} {
			if err := unix.SetsockoptInt(opt.fd, unix.SOL_SOCKET, opt.name, 2*len(payload)); err != nil {
				t.Skipf("cannot enlarge netlink socket buffers: %v", err)
			}
		}
	}
	err = unix.Sendto(peer, payload, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: local.(*unix.SockaddrNetlink).Pid})
	if errors.Is(err, unix.EPERM) {
		t.Skip("needs CAP_NET_ADMIN to send between netlink sockets")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestRequestRDMARejectsUserSpaceSender(t *testing.T) {
	fd := openGenlSocket(t)
	msg := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(msg, uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:], unix.GENL_ID_CTRL)
	binary.NativeEndian.PutUint32(msg[8:], 7)
	sendFromPeer(t, fd, msg)
	_, err := requestRDMA(context.Background(), fd, 7, unix.GENL_ID_CTRL, genlFamilyQuery("nlctrl"), false)
	if err == nil || err.Error() != "RDMA netlink response is not from the kernel" {
		t.Fatalf("spoofed reply = %v", err)
	}
}

func TestRequestRDMARejectsTruncatedDatagram(t *testing.T) {
	fd := openGenlSocket(t)
	sendFromPeer(t, fd, make([]byte, 1<<20+unix.NLMSG_HDRLEN))
	_, err := requestRDMA(context.Background(), fd, 7, unix.GENL_ID_CTRL, genlFamilyQuery("nlctrl"), false)
	if err == nil || err.Error() != "truncated RDMA netlink datagram" {
		t.Fatalf("oversized datagram = %v", err)
	}
}
