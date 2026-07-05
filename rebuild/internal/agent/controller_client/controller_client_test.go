package controller_client

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// fakeControllerServer is a minimal, scriptable implementation of
// controller_agent.ControllerServiceServer used to exercise
// GRPCControllerClient's RPC-wrapping logic (timeouts, error propagation,
// success/failure branches) without a real controller process.
type fakeControllerServer struct {
	controller_agent.UnimplementedControllerServiceServer

	mu sync.Mutex

	// registerFunc, if set, is called on every RegisterAgent invocation
	// with a 0-based call index so tests can script per-attempt behavior
	// (e.g. fail twice, then succeed).
	registerFunc  func(callIndex int, req *controller_agent.AgentRegistrationRequest) (*controller_agent.AgentRegistrationResponse, error)
	registerCalls int

	// pinglistDelay, if non-zero, makes GetPinglist block until either the
	// delay elapses or the request context is done, whichever comes first
	// -- this is what lets a test observe rpcTimeout without waiting out a
	// real 10-second timeout.
	pinglistDelay time.Duration
	pinglistResp  *controller_agent.PinglistResponse
	pinglistErr   error

	// reportFunc, if set, handles ReportProbeAnalysis; otherwise a default
	// accepted=true ack is returned. reportCalls counts invocations and
	// lastReport captures the most recent request for assertions.
	reportFunc  func(req *controller_agent.ProbeAnalysisReport) (*controller_agent.ProbeAnalysisAck, error)
	reportCalls int
	lastReport  *controller_agent.ProbeAnalysisReport
}

func (s *fakeControllerServer) RegisterAgent(
	_ context.Context, req *controller_agent.AgentRegistrationRequest,
) (*controller_agent.AgentRegistrationResponse, error) {
	s.mu.Lock()
	idx := s.registerCalls
	s.registerCalls++
	s.mu.Unlock()

	if s.registerFunc != nil {
		return s.registerFunc(idx, req)
	}
	return &controller_agent.AgentRegistrationResponse{Success: true, Message: "ok"}, nil
}

func (s *fakeControllerServer) GetPinglist(
	ctx context.Context, _ *controller_agent.PinglistRequest,
) (*controller_agent.PinglistResponse, error) {
	if s.pinglistDelay > 0 {
		select {
		case <-time.After(s.pinglistDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.pinglistErr != nil {
		return nil, s.pinglistErr
	}
	if s.pinglistResp != nil {
		return s.pinglistResp, nil
	}
	return &controller_agent.PinglistResponse{}, nil
}

func (s *fakeControllerServer) ReportProbeAnalysis(
	_ context.Context, req *controller_agent.ProbeAnalysisReport,
) (*controller_agent.ProbeAnalysisAck, error) {
	s.mu.Lock()
	s.reportCalls++
	s.lastReport = req
	s.mu.Unlock()

	if s.reportFunc != nil {
		return s.reportFunc(req)
	}
	return &controller_agent.ProbeAnalysisAck{Accepted: true}, nil
}

// newTestClient starts srv on an in-process bufconn listener and returns a
// GRPCControllerClient wired to dial it. Constructed via struct literal
// (rather than NewGRPCControllerClient) because the public constructor only
// accepts a "host:port" string, with no hook for a bufconn dialer; building
// the struct directly is legitimate white-box testing since this file lives
// in the same package.
func newTestClient(t *testing.T, srv *fakeControllerServer) *GRPCControllerClient {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	controller_agent.RegisterControllerServiceServer(grpcServer, srv)
	go grpcServer.Serve(lis)
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &GRPCControllerClient{
		conn:   conn,
		client: controller_agent.NewControllerServiceClient(conn),
		logger: zerolog.Nop(),
	}
}

// TestNewGRPCControllerClient_Construct verifies that the public constructor
// succeeds and Close() releases the connection without error. grpc.NewClient
// dials lazily (no I/O happens until the first RPC), so this needs no
// network access.
func TestNewGRPCControllerClient_Construct(t *testing.T) {
	c, err := NewGRPCControllerClient("127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("NewGRPCControllerClient: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestNewGRPCControllerClient_ExplicitDisabled verifies that an explicit
// &config.TLSClientConfig{Mode: config.TLSModeDisabled} behaves identically
// to a nil tlsCfg: insecure credentials, no certificate files required.
func TestNewGRPCControllerClient_ExplicitDisabled(t *testing.T) {
	c, err := NewGRPCControllerClient("127.0.0.1:1", &config.TLSClientConfig{Mode: config.TLSModeDisabled})
	if err != nil {
		t.Fatalf("NewGRPCControllerClient: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestNewGRPCControllerClient_TLSConfigError verifies that a tlsCfg
// requesting mtls with a nonexistent certificate file fails fast at
// construction time (building the *tls.Config), rather than at the first
// RPC's handshake.
func TestNewGRPCControllerClient_TLSConfigError(t *testing.T) {
	tlsCfg := &config.TLSClientConfig{
		Mode:     config.TLSModeMTLS,
		CertFile: filepath.Join(t.TempDir(), "missing-cert.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "missing-key.pem"),
		CAFile:   filepath.Join(t.TempDir(), "missing-ca.pem"),
	}
	if _, err := NewGRPCControllerClient("127.0.0.1:1", tlsCfg); err == nil {
		t.Fatal("expected an error for missing mtls certificate files, got nil")
	}
}

// TestRegisterAgent_Success verifies the happy path: the controller accepts
// the registration and RegisterAgent returns the response with no error.
func TestRegisterAgent_Success(t *testing.T) {
	srv := &fakeControllerServer{}
	c := newTestClient(t, srv)

	resp, err := c.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{
		AgentId: "agent-1",
		TorId:   "tor-1",
	})
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if !resp.GetSuccess() {
		t.Errorf("resp.Success = false, want true")
	}
}

// TestRegisterAgent_RejectedByController verifies that a Success=false
// response (the controller's way of rejecting a registration without a
// transport-level error) is surfaced as an error, while still returning the
// response so the caller can inspect resp.Message.
func TestRegisterAgent_RejectedByController(t *testing.T) {
	srv := &fakeControllerServer{
		registerFunc: func(_ int, _ *controller_agent.AgentRegistrationRequest) (*controller_agent.AgentRegistrationResponse, error) {
			return &controller_agent.AgentRegistrationResponse{Success: false, Message: "duplicate agent_id"}, nil
		},
	}
	c := newTestClient(t, srv)

	resp, err := c.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{AgentId: "agent-1"})
	if err == nil {
		t.Fatal("RegisterAgent: want error for rejected registration, got nil")
	}
	if resp == nil || resp.GetSuccess() {
		t.Errorf("resp = %+v, want non-nil response with Success=false", resp)
	}
}

// TestRegisterAgent_RPCError verifies that a transport-level gRPC error
// (e.g. the controller is unreachable or returns Internal) is wrapped and
// returned with a nil response.
func TestRegisterAgent_RPCError(t *testing.T) {
	srv := &fakeControllerServer{
		registerFunc: func(_ int, _ *controller_agent.AgentRegistrationRequest) (*controller_agent.AgentRegistrationResponse, error) {
			return nil, status.Error(codes.Internal, "database unavailable")
		},
	}
	c := newTestClient(t, srv)

	resp, err := c.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{AgentId: "agent-1"})
	if err == nil {
		t.Fatal("RegisterAgent: want error, got nil")
	}
	if resp != nil {
		t.Errorf("resp = %+v, want nil on RPC error", resp)
	}
}

// TestRegisterAgent_RetryThenSucceed simulates what a caller-side retry loop
// (internal/agent.Agent.registerWithController's exponential backoff)
// experiences against a flaky controller: the first two attempts fail, and
// the third succeeds. GRPCControllerClient itself is stateless per call, so
// this exercises that repeated calls against the same connection behave
// correctly across a fail/fail/succeed sequence. The backoff/attempt-count
// loop itself lives in internal/agent.Agent.registerWithController, a CGO
// package that requires linking librdmabridge.a and so cannot be built or
// unit-tested on this macOS host; that loop is out of scope for this
// package's tests.
func TestRegisterAgent_RetryThenSucceed(t *testing.T) {
	srv := &fakeControllerServer{
		registerFunc: func(callIndex int, _ *controller_agent.AgentRegistrationRequest) (*controller_agent.AgentRegistrationResponse, error) {
			if callIndex < 2 {
				return nil, status.Error(codes.Unavailable, "controller starting up")
			}
			return &controller_agent.AgentRegistrationResponse{Success: true, Message: "ok"}, nil
		},
	}
	c := newTestClient(t, srv)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := c.RegisterAgent(context.Background(), &controller_agent.AgentRegistrationRequest{AgentId: "agent-1"})
		lastErr = err
		if err == nil {
			if !resp.GetSuccess() {
				t.Fatalf("attempt %d: resp.Success = false, want true on final success", attempt)
			}
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("RegisterAgent never succeeded across retries, last error: %v", lastErr)
	}
	if srv.registerCalls != 3 {
		t.Errorf("server saw %d RegisterAgent calls, want 3 (2 failures + 1 success)", srv.registerCalls)
	}
}

// TestGetPinglist_Success verifies the happy path: targets returned by the
// controller are passed through unchanged.
func TestGetPinglist_Success(t *testing.T) {
	srv := &fakeControllerServer{
		pinglistResp: &controller_agent.PinglistResponse{
			Targets: []*controller_agent.PingTarget{
				{TargetGid: "fe80::2"},
				{TargetGid: "fe80::3"},
			},
		},
	}
	c := newTestClient(t, srv)

	targets, err := c.GetPinglist(context.Background(), "agent-1", "tor-1", "fe80::1", controller_agent.PinglistType_TOR_MESH)
	if err != nil {
		t.Fatalf("GetPinglist: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
}

// TestReportProbeAnalysis_Success verifies the happy path: the report is
// delivered unchanged and the analyzer's ack (accepted + violation count) is
// returned to the caller.
func TestReportProbeAnalysis_Success(t *testing.T) {
	srv := &fakeControllerServer{
		reportFunc: func(_ *controller_agent.ProbeAnalysisReport) (*controller_agent.ProbeAnalysisAck, error) {
			return &controller_agent.ProbeAnalysisAck{Accepted: true, SlaViolations: 2}, nil
		},
	}
	c := newTestClient(t, srv)

	report := &controller_agent.ProbeAnalysisReport{
		AgentId: "agent-1",
		Summaries: []*controller_agent.PathSummary{
			{SourceGid: "fe80::1", TargetGid: "fe80::2", ProbeTotal: 100, ProbeFailed: 50},
		},
	}
	ack, err := c.ReportProbeAnalysis(context.Background(), report)
	if err != nil {
		t.Fatalf("ReportProbeAnalysis: %v", err)
	}
	if !ack.GetAccepted() {
		t.Errorf("ack.Accepted = false, want true")
	}
	if ack.GetSlaViolations() != 2 {
		t.Errorf("ack.SlaViolations = %d, want 2", ack.GetSlaViolations())
	}
	if srv.reportCalls != 1 {
		t.Errorf("server saw %d ReportProbeAnalysis calls, want 1", srv.reportCalls)
	}
	if got := len(srv.lastReport.GetSummaries()); got != 1 {
		t.Errorf("server received %d summaries, want 1", got)
	}
}

// TestReportProbeAnalysis_RPCError verifies that a transport-level error is
// wrapped and returned with a nil ack, so the reporter can drop the batch.
func TestReportProbeAnalysis_RPCError(t *testing.T) {
	srv := &fakeControllerServer{
		reportFunc: func(_ *controller_agent.ProbeAnalysisReport) (*controller_agent.ProbeAnalysisAck, error) {
			return nil, status.Error(codes.Unavailable, "controller busy")
		},
	}
	c := newTestClient(t, srv)

	ack, err := c.ReportProbeAnalysis(context.Background(), &controller_agent.ProbeAnalysisReport{AgentId: "agent-1"})
	if err == nil {
		t.Fatal("ReportProbeAnalysis: want error, got nil")
	}
	if ack != nil {
		t.Errorf("ack = %+v, want nil on RPC error", ack)
	}
}

// TestGetPinglist_Timeout verifies that GetPinglist bounds the RPC to the
// caller's context deadline: rpcTimeout (10s) is the outer bound, but
// context.WithTimeout takes the earlier of the two deadlines, so passing a
// short-deadline context here lets the test observe timeout behavior without
// waiting out the full 10 seconds. The fake server deliberately blocks
// longer than that deadline so the RPC must fail with a deadline/context
// error rather than a real 10s wait.
func TestGetPinglist_Timeout(t *testing.T) {
	srv := &fakeControllerServer{
		pinglistDelay: 500 * time.Millisecond,
	}
	c := newTestClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	targets, err := c.GetPinglist(ctx, "agent-1", "tor-1", "fe80::1", controller_agent.PinglistType_INTER_TOR)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("GetPinglist: want timeout error, got nil")
	}
	if targets != nil {
		t.Errorf("targets = %v, want nil on timeout", targets)
	}
	if elapsed >= srv.pinglistDelay {
		t.Errorf("GetPinglist took %v, want well under the server's %v delay (short ctx deadline should win)", elapsed, srv.pinglistDelay)
	}
	if !errors.Is(err, context.DeadlineExceeded) && status.Code(err) != codes.DeadlineExceeded {
		t.Errorf("GetPinglist error = %v, want a DeadlineExceeded error", err)
	}
}
