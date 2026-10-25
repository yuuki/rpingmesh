// Service tracing end-to-end tests. They run in the privileged soft-RoCE
// container of `make test-e2e` (root, kernel BTF, ib_uverbs loaded) and skip
// elsewhere.
package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/agent"
	"github.com/yuuki/rpingmesh/internal/agent/servicetrace"
	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// responderIP is rxe1's address in scripts/run-e2e.sh.
const responderIP = "10.200.0.1"

// TestServiceTracingTracesRCApplication runs an RC application
// (ibv_rc_pingpong, server on rxe1 and client on rxe0) under the eBPF tracer
// and checks the trace: each side creates an RC QP, moves it to RTR with the
// peer's GID and QPN in the address vector, and both QPs vanish when the
// processes exit. Replayed into the connection table, the events yield two
// connections that share one effective flow label.
func TestServiceTracingTracesRCApplication(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs")
	}
	pingpong, err := exec.LookPath("ibv_rc_pingpong")
	if err != nil {
		t.Skip("ibv_rc_pingpong (ibverbs-utils) is not installed")
	}

	tracer, err := servicetrace.Open()
	if errors.Is(err, servicetrace.ErrNoUverbs) {
		t.Skipf("ib_uverbs is not loaded: %v", err)
	}
	if err != nil {
		t.Fatalf("servicetrace.Open: %v", err)
	}
	defer tracer.Close()

	var mu sync.Mutex
	var events []servicetrace.Event
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tracer.Start(ctx, func(ev servicetrace.Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	devNumbers, err := servicetrace.UverbsDevices("")
	if err != nil {
		t.Fatalf("UverbsDevices: %v", err)
	}
	devOf := func(name string) uint32 {
		for dev, n := range devNumbers {
			if n == name {
				return dev
			}
		}
		t.Fatalf("no uverbs node for %s in %v", name, devNumbers)
		return 0
	}
	clientDev, serverDev := devOf(proberDeviceName), devOf(responderDeviceName)
	clientGID, err := servicetrace.PortGID("", proberDeviceName, 1, gidIndex)
	if err != nil {
		t.Fatalf("PortGID(%s): %v", proberDeviceName, err)
	}
	serverGID, err := servicetrace.PortGID("", responderDeviceName, 1, gidIndex)
	if err != nil {
		t.Fatalf("PortGID(%s): %v", responderDeviceName, err)
	}

	// --- Run the application ---
	const iters = "50"
	gid := strconv.Itoa(gidIndex)
	var serverOut bytes.Buffer
	server := exec.CommandContext(ctx, pingpong, "-d", responderDeviceName, "-g", gid, "-n", iters, "-s", "64")
	server.Stdout, server.Stderr = &serverOut, &serverOut
	if err := server.Start(); err != nil {
		t.Fatalf("start pingpong server: %v", err)
	}
	time.Sleep(time.Second) // let the server listen on its TCP port

	client := exec.CommandContext(ctx, pingpong, "-d", proberDeviceName, "-g", gid, "-n", iters, "-s", "64", responderIP)
	clientOut, err := client.CombinedOutput()
	t.Logf("pingpong client:\n%s", clientOut)
	if err != nil {
		server.Process.Kill()
		server.Wait()
		t.Fatalf("pingpong client failed: %v\nserver output:\n%s", err, serverOut.String())
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("pingpong server failed: %v\n%s", err, serverOut.String())
	}
	t.Logf("pingpong server:\n%s", serverOut.String())

	// --- Wait for both contexts to close ---
	snapshot := func() []servicetrace.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]servicetrace.Event(nil), events...)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		closes := 0
		for _, ev := range snapshot() {
			if ev.Kind == servicetrace.KindContextClose && (ev.Dev == clientDev || ev.Dev == serverDev) {
				closes++
			}
		}
		if closes >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	evs := snapshot()
	for _, ev := range evs {
		t.Logf("event: kind=%s src=%d dev=%#x ctx=%#x handle=%d qpn=%#x type=%d state=%d mask=%#x dest_qpn=%#x fl=%#x sgid=%d comm=%q",
			ev.Kind, ev.Source, ev.Dev, ev.Context, ev.QPHandle, ev.QPNum, ev.QPType, ev.QPState, ev.AttrMask, ev.DestQPNum, ev.FlowLabel, ev.SGIDIndex, ev.Comm)
	}
	if s := tracer.Stats(); s.RingBufferDropped != 0 || s.ParseErrors != 0 || s.DecodeErrors != 0 {
		t.Errorf("tracer lost events: %+v", s)
	} else {
		t.Logf("tracer stats: %+v", s)
	}

	// --- Per-side analysis ---
	type side struct {
		dev     uint32
		created map[uint32]uint32 // handle -> QPN of the RC QPs
		connect *servicetrace.Event
		closed  bool
	}
	sides := make(map[uint64]*side)
	for i := range evs {
		ev := evs[i]
		s := sides[ev.Context]
		if s == nil {
			s = &side{dev: ev.Dev, created: make(map[uint32]uint32)}
			sides[ev.Context] = s
		}
		switch {
		case ev.Kind == servicetrace.KindQPCreate && ev.QPType == servicetrace.QPTypeRC:
			s.created[ev.QPHandle] = ev.QPNum
		case ev.IsConnect():
			s.connect = &ev
		case ev.Kind == servicetrace.KindContextClose:
			s.closed = true
		}
	}
	var clientSide, serverSide *side
	for _, s := range sides {
		if s.connect == nil {
			continue
		}
		switch s.dev {
		case clientDev:
			clientSide = s
		case serverDev:
			serverSide = s
		}
	}
	if clientSide == nil || serverSide == nil {
		t.Fatalf("missing a connected side: client=%v server=%v (events above)", clientSide != nil, serverSide != nil)
	}
	for name, s := range map[string]*side{"client": clientSide, "server": serverSide} {
		if _, ok := s.created[s.connect.QPHandle]; !ok {
			t.Errorf("%s: RTR handle %d was never seen created (created: %v)", name, s.connect.QPHandle, s.created)
		}
		// The address vector names the port; the command's port_num only
		// travels with the INIT transition.
		if s.connect.SGIDIndex != gidIndex || s.connect.DestPortNum != 1 || s.connect.IsGlobal == 0 {
			t.Errorf("%s: address vector sgid_index=%d port=%d is_global=%d, want %d/1/1",
				name, s.connect.SGIDIndex, s.connect.DestPortNum, s.connect.IsGlobal, gidIndex)
		}
		if !s.closed {
			t.Errorf("%s: context close was not traced", name)
		}
	}
	if clientSide.connect.DGID != serverGID {
		t.Errorf("client RTR dgid = %s, want the server GID %s", probe.FormatGID(clientSide.connect.DGID), probe.FormatGID(serverGID))
	}
	if serverSide.connect.DGID != clientGID {
		t.Errorf("server RTR dgid = %s, want the client GID %s", probe.FormatGID(serverSide.connect.DGID), probe.FormatGID(clientGID))
	}
	clientQPN := clientSide.created[clientSide.connect.QPHandle]
	serverQPN := serverSide.created[serverSide.connect.QPHandle]
	if clientSide.connect.DestQPNum != serverQPN || serverSide.connect.DestQPNum != clientQPN {
		t.Errorf("dest QPNs do not cross-match: client->%#x (server QPN %#x), server->%#x (client QPN %#x)",
			clientSide.connect.DestQPNum, serverQPN, serverSide.connect.DestQPNum, clientQPN)
	}

	// --- Replay into the connection table ---
	table := servicetrace.NewTable()
	var peak []servicetrace.Connection
	for _, ev := range evs {
		table.Apply(ev)
		if conns := table.Connections(); len(conns) > len(peak) {
			peak = conns
		}
	}
	if len(peak) != 2 {
		t.Fatalf("the table saw at most %d connections, want 2: %+v", len(peak), peak)
	}
	for _, c := range peak {
		if c.Port != 1 || c.SGIDIndex != gidIndex || c.QPType != servicetrace.QPTypeRC {
			t.Errorf("connection port/sgid/type = %d/%d/%d, want 1/%d/RC: %+v", c.Port, c.SGIDIndex, c.QPType, gidIndex, c)
		}
	}
	if peak[0].EffectiveFlowLabel() != peak[1].EffectiveFlowLabel() {
		t.Errorf("the two sides derive different effective flow labels: %#x vs %#x",
			peak[0].EffectiveFlowLabel(), peak[1].EffectiveFlowLabel())
	}
	if n := len(table.Connections()); n != 0 {
		t.Errorf("%d connections remain after the processes exited", n)
	}
	t.Logf("traced connections at peak: %+v", peak)
}

// TestServiceTracingProbePath verifies the prober's service-tracing pass on
// soft-RoCE: a SERVICE_TRACING target carrying an explicit flow label is
// probed through the agent's UD queue and completes the 6-timestamp
// exchange, with the result flagged for the service instruments and
// carrying that label.
func TestServiceTracingProbePath(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via 'make test-e2e' or set RDMA_E2E_ENABLED=1")
	}
	const (
		serviceFlowLabel = uint32(0x4242)
		probeIntervalMS  = uint32(200)
		resultTimeout    = 15 * time.Second
	)

	rdmaCtx, err := rdmabridge.Init()
	if err != nil {
		t.Fatalf("rdmabridge.Init: %v", err)
	}
	defer rdmaCtx.Destroy()

	proberDev, err := rdmaCtx.OpenDeviceByName(proberDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open prober device %q: %v", proberDeviceName, err)
	}
	defer proberDev.Close()
	responderDev, err := rdmaCtx.OpenDeviceByName(responderDeviceName, gidIndex, testServiceLevel, testTrafficClass)
	if err != nil {
		t.Fatalf("open responder device %q: %v", responderDeviceName, err)
	}
	defer responderDev.Close()

	proberRing, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		t.Fatalf("create prober ring: %v", err)
	}
	defer proberRing.Destroy()
	responderRing, err := rdmabridge.NewEventRing(eventRingCapacity)
	if err != nil {
		t.Fatalf("create responder ring: %v", err)
	}
	defer responderRing.Destroy()

	prober, err := agent.NewProber(proberDev, proberRing, probeIntervalMS)
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	responder, err := agent.NewResponder(responderDev, responderRing)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	prober.SetServiceTracingRate(100, 10)
	prober.UpdateServiceTargets([]*controller_agent.PingTarget{{
		TargetGid:        responderDev.Info.GID,
		TargetQpn:        responder.GetQueueInfo().QPN,
		TargetIp:         responderDev.Info.IPAddr,
		TargetHostname:   "e2e-responder",
		TargetTorId:      "tor-e2e-target",
		TargetDeviceName: responderDev.Info.DeviceName,
		FlowLabel:        serviceFlowLabel,
		FlowLabelCount:   1,
		PinglistType:     controller_agent.PinglistType_SERVICE_TRACING,
	}}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := responder.Start(ctx); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}
	if err := prober.Start(ctx); err != nil {
		t.Fatalf("prober.Start: %v", err)
	}

	var got *probe.ProbeResult
	deadline := time.After(resultTimeout)
wait:
	for {
		select {
		case r, ok := <-prober.Results():
			if !ok {
				break wait
			}
			if r.IsServiceTracing() && r.Success {
				got = r
				break wait
			}
			t.Logf("result: service=%v success=%v reason=%q", r.IsServiceTracing(), r.Success, r.FailureReason)
		case <-deadline:
			break wait
		}
	}

	prober.Destroy()
	responder.Destroy()

	if got == nil {
		t.Fatal("no successful service-tracing probe result within the timeout")
	}
	if got.FlowLabel != serviceFlowLabel {
		t.Errorf("result flow label = %#x, want %#x", got.FlowLabel, serviceFlowLabel)
	}
	if got.TargetQPN != responder.GetQueueInfo().QPN && got.TargetQPN == 0 {
		t.Errorf("result target QPN = %d", got.TargetQPN)
	}
	rtt := probe.CalculateRTT(got)
	t.Logf("service probe: seq=%d flow_label=%#x T1..T6=%d,%d,%d,%d,%d,%d rtt_valid=%v network_rtt=%dns",
		got.SequenceNum, got.FlowLabel, got.T1, got.T2, got.T3, got.T4, got.T5, got.T6, rtt.Valid, rtt.NetworkRTT)
}

// TestServiceTracingSnapshotsExistingQP creates a QP before the connection
// table exists, as happens when an agent starts during a long-running job.
// Generic netlink must inventory it without fabricating a probeable flow.
func TestServiceTracingSnapshotsExistingQP(t *testing.T) {
	if os.Getenv("RDMA_E2E_ENABLED") != "1" {
		t.Skip("RDMA_E2E_ENABLED not set; run via make test-e2e")
	}
	pingpong, err := exec.LookPath("ibv_rc_pingpong")
	if err != nil {
		t.Fatal(err)
	}
	devices, err := servicetrace.UverbsDevices("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, pingpong, "-d", responderDeviceName, "-g", strconv.Itoa(gidIndex), "-p", "18516", "-n", "1")
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if server.ProcessState == nil {
			server.Process.Kill()
			server.Wait()
		}
	}()
	var resource servicetrace.QPResource
	for resource.PID == 0 {
		qps, err := servicetrace.SnapshotQPs(ctx, devices)
		if err != nil {
			t.Fatal(err)
		}
		for _, qp := range qps {
			if qp.PID == uint32(server.Process.Pid) && qp.QPType == servicetrace.QPTypeRC {
				resource = qp
			}
		}
		if ctx.Err() != nil {
			t.Fatal("pre-existing QP did not appear in RDMA netlink")
		}
		time.Sleep(10 * time.Millisecond)
	}
	table := servicetrace.NewTable()
	table.ReconcileQPs([]servicetrace.QPResource{resource})
	if table.QPCount() != 1 || len(table.UnboundQPs()) != 1 || len(table.Connections()) != 0 {
		t.Fatal("existing QP was lost or became a connection without an address vector")
	}
	if err := server.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	server.Wait()
	for {
		qps, err := servicetrace.SnapshotQPs(ctx, devices)
		if err != nil {
			t.Fatal(err)
		}
		table.ReconcileQPs(qps)
		found := false
		for _, qp := range table.UnboundQPs() {
			found = found || (qp.Dev == resource.Dev && qp.LocalQPN == resource.LocalQPN && qp.PID == resource.PID)
		}
		if !found {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("exited process's QP remains in the snapshot")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Opt-in physical mlx5 check: starts an RC job before inventory/recovery.
// It needs two routable mlx5 ports and CAP_NET_ADMIN. The ordinary soft-RoCE
// suite skips this test because rxe does not expose mlx5 resource dumps.
func TestServiceTracingRecoversMlx5Connections(t *testing.T) {
	device, peer := os.Getenv("RPINGMESH_MLX5_E2E_DEVICE"), os.Getenv("RPINGMESH_MLX5_E2E_PEER_DEVICE")
	peerIP := os.Getenv("RPINGMESH_MLX5_E2E_PEER_IP")
	if device == "" || peer == "" || peerIP == "" {
		t.Skip("set RPINGMESH_MLX5_E2E_DEVICE, RPINGMESH_MLX5_E2E_PEER_DEVICE and RPINGMESH_MLX5_E2E_PEER_IP for physical mlx5 validation")
	}
	index := 3
	if value := os.Getenv("RPINGMESH_MLX5_E2E_GID_INDEX"); value != "" {
		var err error
		index, err = strconv.Atoi(value)
		if err != nil || index < 0 || index > 255 {
			t.Fatal("invalid mlx5 GID index")
		}
	}
	pingpong, err := exec.LookPath("ibv_rc_pingpong")
	if err != nil {
		t.Fatal(err)
	}
	all, err := servicetrace.UverbsDevices("")
	if err != nil {
		t.Fatal(err)
	}
	devices := make(map[uint32]string)
	for dev, name := range all {
		if name == device || name == peer {
			devices[dev] = name
		}
	}
	if len(devices) != 2 {
		t.Fatal("two distinct mlx5 RDMA devices are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	start := func(name string, remote ...string) *exec.Cmd {
		args := []string{"-d", name, "-g", strconv.Itoa(index), "-p", "18517", "-n", "1000000000", "-s", "64"}
		cmd := exec.CommandContext(ctx, pingpong, append(args, remote...)...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		return cmd
	}
	server := start(peer)
	// Wait for the server's INIT QP instead of assuming a startup delay.
	for {
		qps, err := servicetrace.SnapshotQPs(ctx, devices)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, qp := range qps {
			found = found || qp.PID == uint32(server.Process.Pid)
		}
		if found {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	client := start(device, peerIP)
	var connected []servicetrace.QPResource
	for len(connected) != 2 {
		qps, err := servicetrace.SnapshotQPs(ctx, devices)
		if err != nil {
			t.Fatal(err)
		}
		connected = nil
		for _, qp := range qps {
			if (qp.PID == uint32(server.Process.Pid) || qp.PID == uint32(client.Process.Pid)) && qp.QPState == servicetrace.QPStateRTS {
				connected = append(connected, qp)
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	recovered, err := servicetrace.RecoverQPs(ctx, devices, connected)
	if err != nil {
		t.Fatal(err)
	}
	table := servicetrace.NewTable()
	table.ReconcileQPs(recovered)
	conns := table.Connections()
	if len(conns) != 2 || len(table.UnboundQPs()) != 0 {
		t.Fatalf("mlx5 connections were not recovered: %+v", recovered)
	}
	for _, c := range conns {
		if c.RemoteGID == ([16]byte{}) || c.LocalQPN == 0 || c.RemoteQPN == 0 || !c.FromSnapshot {
			t.Fatalf("incomplete recovered mlx5 connection: %+v", c)
		}
	}
	if conns[0].LocalQPN != conns[1].RemoteQPN || conns[1].LocalQPN != conns[0].RemoteQPN || conns[0].EffectiveFlowLabel() != conns[1].EffectiveFlowLabel() {
		t.Fatalf("recovered peer identities disagree: %+v", conns)
	}
}
