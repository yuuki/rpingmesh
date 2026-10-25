//go:build linux

package servicetrace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// SnapshotQPs inventories QPs on the given uverbs device numbers/names. It
// needs NETLINK_RDMA in the agent's network namespace, without an additional
// capability. The whole operation is bounded, including all device dumps.
func SnapshotQPs(ctx context.Context, devices map[uint32]string) ([]QPResource, error) {
	if len(devices) == 0 {
		return nil, nil
	}
	return boundedQPSnapshot(ctx, devices, collectQPResources)
}

// The worker exclusively owns the socket, including close. A netlink
// send/receive can synchronously run a driver query even on a nonblocking
// socket, so the caller's deadline must not depend on that syscall returning.
func collectQPResources(ctx context.Context, devices map[uint32]string) ([]QPResource, error) {
	fd, err := openRDMASocket()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var seq uint32
	return snapshotQPs(ctx, devices, func(ctx context.Context, cmd uint16, attrs []byte) ([][]byte, error) {
		seq++
		return dumpRDMA(ctx, fd, seq, cmd, attrs)
	})
}

func openRDMASocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_RDMA)
	if err != nil {
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func dumpRDMA(ctx context.Context, fd int, seq uint32, cmd uint16, attrs []byte) ([][]byte, error) {
	return requestRDMA(ctx, fd, seq, cmd, attrs, true)
}

func requestRDMA(ctx context.Context, fd int, seq uint32, cmd uint16, attrs []byte, dump bool) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req := make([]byte, unix.NLMSG_HDRLEN+len(attrs))
	binary.NativeEndian.PutUint32(req, uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], cmd)
	flags := uint16(unix.NLM_F_REQUEST)
	if dump {
		flags |= unix.NLM_F_DUMP
	}
	binary.NativeEndian.PutUint16(req[6:], flags)
	binary.NativeEndian.PutUint32(req[8:], seq)
	copy(req[unix.NLMSG_HDRLEN:], attrs)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, 1<<20)
	var out [][]byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		// A short poll bounds cancellation latency without a goroutine
		// closing a descriptor that the OS may already have reused.
		if _, err := unix.Poll(poll, 50); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if poll[0].Revents == 0 {
			continue
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if flags&unix.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("truncated RDMA netlink datagram")
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return nil, fmt.Errorf("RDMA netlink response is not from the kernel")
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, msg := range msgs {
			if msg.Header.Seq != seq {
				return nil, fmt.Errorf("RDMA netlink response sequence mismatch")
			}
			done, err := checkRDMAMessage(msg, cmd)
			if err != nil {
				return nil, err
			}
			if done {
				return out, nil
			}
			if msg.Header.Type == cmd {
				out = append(out, append([]byte(nil), msg.Data...))
				if !dump {
					if msg.Header.Flags&unix.NLM_F_MULTI != 0 {
						return nil, fmt.Errorf("unexpected multipart RDMA query response")
					}
					return out, nil
				}
			}
		}
	}
}

func checkRDMAMessage(msg syscall.NetlinkMessage, cmd uint16) (bool, error) {
	if msg.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
		return false, fmt.Errorf("RDMA netlink dump interrupted")
	}
	switch msg.Header.Type {
	case unix.NLMSG_DONE, unix.NLMSG_ERROR:
		if len(msg.Data) < 4 && (msg.Header.Type == unix.NLMSG_ERROR || len(msg.Data) != 0) {
			return false, fmt.Errorf("truncated RDMA netlink status")
		}
		if len(msg.Data) >= 4 {
			if status := int32(binary.NativeEndian.Uint32(msg.Data)); status != 0 {
				if status > 0 {
					return false, fmt.Errorf("invalid RDMA netlink status %d", status)
				}
				return false, syscall.Errno(-int64(status))
			}
		}
		return msg.Header.Type == unix.NLMSG_DONE, nil
	case unix.NLMSG_NOOP:
		return false, nil
	case cmd:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected RDMA netlink message type %d", msg.Header.Type)
	}
}
