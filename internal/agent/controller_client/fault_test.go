package controller_client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Fault injection: the client against controllers that misbehave at the TCP
// level, through the public constructor (a real TCP dial, no bufconn). Every
// RPC must fail within the caller's deadline instead of hanging the agent's
// startup or its pinglist refresh, and Close must release the connection
// (the package's TestMain fails on leaked goroutines).

// faultListener accepts TCP connections on loopback and hands each one to
// handle. Connections still open when the test ends are closed then.
func faultListener(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			handle(c)
		}
	}()
	t.Cleanup(func() {
		_ = lis.Close()
		<-accepted
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return lis.Addr().String()
}

// blackholeController accepts connections and never answers: the host is up
// but the controller process is hung, or a middlebox swallows the traffic.
func blackholeController(t *testing.T) string {
	return faultListener(t, func(net.Conn) {})
}

// resettingController accepts connections and resets them at once (RST via
// SO_LINGER 0): the controller crashed or a load balancer rejects the flow.
func resettingController(t *testing.T) string {
	return faultListener(t, func(c net.Conn) {
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = c.Close()
	})
}

// faultRPCs calls every RPC of the client once.
var faultRPCs = map[string]func(context.Context, *GRPCControllerClient) error{
	"RegisterAgent": func(ctx context.Context, c *GRPCControllerClient) error {
		_, err := c.RegisterAgent(ctx, &controller_agent.AgentRegistrationRequest{AgentId: "agent-1"})
		return err
	},
	"GetPinglist": func(ctx context.Context, c *GRPCControllerClient) error {
		_, err := c.GetPinglist(ctx, "agent-1", "tor-1", "fe80::1", "", controller_agent.PinglistType_TOR_MESH)
		return err
	},
	"GetTargetRnicInfo": func(ctx context.Context, c *GRPCControllerClient) error {
		_, err := c.GetTargetRnicInfo(ctx, "agent-1", "fe80::1", []string{"fe80::2"})
		return err
	},
	"ReportProbeAnalysis": func(ctx context.Context, c *GRPCControllerClient) error {
		_, err := c.ReportProbeAnalysis(ctx, &controller_agent.ProbeAnalysisReport{AgentId: "agent-1"})
		return err
	},
}

func newFaultClient(t *testing.T, addr string) *GRPCControllerClient {
	t.Helper()
	c, err := NewGRPCControllerClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCControllerClient: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c
}

// TestRPCs_UnresponsiveControllerHonourDeadline: with the HTTP/2 handshake
// never completing, each RPC must give up at the caller's deadline.
func TestRPCs_UnresponsiveControllerHonourDeadline(t *testing.T) {
	c := newFaultClient(t, blackholeController(t))
	for name, call := range faultRPCs {
		t.Run(name, func(t *testing.T) {
			const deadline = 200 * time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()

			start := time.Now()
			err := call(ctx, c)
			elapsed := time.Since(start)

			if status.Code(err) != codes.DeadlineExceeded {
				t.Fatalf("error = %v, want DeadlineExceeded", err)
			}
			// Generous slack for a loaded CI machine; without the deadline
			// the call would wait for rpcTimeout (10s).
			if elapsed > deadline+3*time.Second {
				t.Fatalf("returned after %v, deadline was %v", elapsed, deadline)
			}
		})
	}
}

// TestRPCs_ResettingControllerFailFast: a controller that resets every
// connection makes each RPC fail with Unavailable instead of waiting for the
// deadline, so callers can retry or skip the cycle.
func TestRPCs_ResettingControllerFailFast(t *testing.T) {
	c := newFaultClient(t, resettingController(t))
	for name, call := range faultRPCs {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := call(ctx, c)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("error = %v, want Unavailable (fail fast, not the deadline)", err)
			}
		})
	}
}
