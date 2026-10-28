//go:build linux

package servicetrace

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUCXDCHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_DC_HARDWARE_TEST") != "1" {
		t.Skip("opt-in UCX DC hardware test")
	}
	testUCXDCHardware(t, false, false, false)
}

func TestUCXDCUprobeHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_DC_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged UCX DC hardware test")
	}
	testUCXDCHardware(t, true, false, false)
}

func TestUCXDevXDCHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_DEVX_HARDWARE_TEST") != "1" {
		t.Skip("opt-in UCX DevX hardware test")
	}
	testUCXDCHardware(t, false, true, false)
}

func TestUCXDevXDCUprobeHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_DEVX_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged UCX DevX hardware test")
	}
	testUCXDCHardware(t, true, true, false)
}

func TestUCXStreamDCHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_STREAM_HARDWARE_TEST") != "1" {
		t.Skip("opt-in UCX DCI stream hardware test")
	}
	testUCXDCHardware(t, false, true, true)
}

func TestUCXStreamDCUprobeHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_STREAM_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged UCX DCI stream hardware test")
	}
	testUCXDCHardware(t, true, true, true)
}

func TestUCXAMHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_AM_HARDWARE_TEST") != "1" {
		t.Skip("opt-in UCX AM hardware test")
	}
	testUCXAMHardware(t, false)
}

func TestUCXAMUprobeHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_AM_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged UCX AM hardware test")
	}
	testUCXAMHardware(t, true)
}

func testUCXAMHardware(t *testing.T, attach bool) {
	for _, backend := range []string{"verbs", "devx", "streams"} {
		for _, operation := range []string{"short-iov", "bcopy", "zcopy"} {
			t.Run(backend+"/"+operation, func(t *testing.T) { testUCXDCHardware(t, attach, backend != "verbs", backend == "streams", operation) })
		}
	}
}

func TestUCXRMAHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_RMA_HARDWARE_TEST") != "1" {
		t.Skip("opt-in UCX RMA hardware test")
	}
	testUCXRMAHardware(t, false)
}
func TestUCXRMAUprobeHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_RMA_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged UCX RMA hardware test")
	}
	testUCXRMAHardware(t, true)
}
func testUCXRMAHardware(t *testing.T, attach bool) {
	for _, backend := range []string{"verbs", "devx", "streams"} {
		for _, operation := range []string{"put-short", "put-bcopy", "put-zcopy", "get-bcopy", "get-zcopy"} {
			t.Run(backend+"/"+operation, func(t *testing.T) { testUCXDCHardware(t, attach, backend != "verbs", backend == "streams", operation) })
		}
	}
}

func testUCXDCHardware(t *testing.T, attach, devx, streams bool, selectedOperation ...string) {
	operation := "short"
	if len(selectedOperation) > 0 {
		operation = selectedOperation[0]
	}
	rma := strings.HasPrefix(operation, "put-") || strings.HasPrefix(operation, "get-")
	am := operation != "short" && !rma
	opcode := byte(0x0a)
	if strings.HasPrefix(operation, "put-") {
		opcode = 0x08
	}
	if strings.HasPrefix(operation, "get-") {
		opcode = 0x10
	}
	wantFlows := 2
	var channels uint32
	if streams {
		wantFlows = 3
		channels = 4
	}
	get := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("set %s", name)
		}
		return value
	}
	device, portText, gid := get("RPINGMESH_DC_TEST_DEVICE"), get("RPINGMESH_DC_TEST_PORT"), get("RPINGMESH_DC_TEST_GID_INDEX")
	port, err := strconv.ParseUint(portText, 10, 8)
	if err != nil || port == 0 {
		t.Fatal("invalid port")
	}
	library, debug := get("RPINGMESH_DC_LIBRARY"), get("RPINGMESH_DC_DEBUG")
	ucx, ucxDebug := get("RPINGMESH_UCX_DC_LIBRARY"), get("RPINGMESH_UCX_DC_DEBUG")
	if err := CheckDCProvider(library, debug); err != nil {
		t.Fatal(err)
	}
	if err := CheckUCXDC(ucx, ucxDebug); err != nil {
		t.Fatal(err)
	}
	if devx {
		if err := CheckUCXDCDevX(library, debug, ucx, ucxDebug); err != nil {
			t.Fatal(err)
		}
	}
	if streams {
		if err := CheckUCXDCStreams(library, debug, ucx, ucxDebug); err != nil {
			t.Fatal(err)
		}
	}
	if am {
		if err := CheckUCXDCAM(ucx, ucxDebug); err != nil {
			t.Fatal(err)
		}
	}
	if rma {
		if err := CheckUCXDCRMA(ucx, ucxDebug); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, get("RPINGMESH_UCX_DC_HELPER"), device, portText, gid)
	if streams {
		child.Args = append(child.Args, "--streams")
	} else if devx {
		child.Args = append(child.Args, "--devx")
	}
	if am || rma {
		if !devx {
			child.Args = append(child.Args, "--verbs")
		}
		child.Args = append(child.Args, operation)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	child.Stderr = &diagnostic
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stdin.Close()
		child.Process.Kill()
		child.Wait()
		for _, line := range strings.Split(diagnostic.String(), "\n") {
			if strings.HasPrefix(line, "RPINGMESH_UCX_TEST_ERROR: ") {
				t.Log(line)
			}
		}
	}()
	r := bufio.NewReader(stdout)
	status := func(want string) {
		t.Helper()
		line, err := r.ReadString('\n')
		if err != nil || line != want+"\n" {
			t.Fatalf("UCX helper did not reach %s", want)
		}
	}
	command := func(op byte) {
		t.Helper()
		if _, err := stdin.Write([]byte{op}); err != nil {
			t.Fatal(err)
		}
	}
	status("ready")
	for _, path := range []string{library, ucx} {
		f := mustOpenDCFile(t, path)
		if err := dcLibraryMapped(child.Process.Pid, f); err != nil {
			t.Fatal(err)
		}
	}
	var c *DCCollector
	if attach {
		c, err = OpenDCCollector(DCOptions{PID: child.Process.Pid, Library: library, DebugFile: debug,
			UCXLibrary: ucx, UCXDebugFile: ucxDebug, UCXDevX: devx, UCXStreams: streams, UCXAM: am, UCXRMA: rma, Device: device, Port: uint8(port)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		defer func() {
			cancel()
			err := <-done
			c.Close()
			if err != nil {
				t.Error(err)
			}
		}()
	}
	command('g')
	var records [3 * 68]byte
	if _, err := io.ReadFull(r, records[:]); err != nil {
		t.Fatal("UCX did not complete three sends")
	}
	status("delivered")
	want := make(map[mlx5DCAddress]bool)
	var qpn uint32
	seenChannels := make(map[uint16]bool)
	destinations := make(map[uint32]bool)
	for i := 0; i < 3; i++ {
		record := records[i*68 : (i+1)*68]
		if !bytes.Equal(record[20:28], make([]byte, 8)) {
			t.Fatal("helper exported an access key")
		}
		if record[7] != opcode {
			t.Fatal("submitted WQE opcode differs from requested operation")
		}
		n := binary.BigEndian.Uint32(record)
		if i > 0 && n != qpn {
			t.Fatal("expected one shared DCI")
		}
		qpn = n
		address, err := decodeMLX5DCStreamAddress(record[4:], qpn, channels)
		if err != nil {
			t.Fatalf("invalid UCX submitted prefix: %v", err)
		}
		if streams {
			if seenChannels[address.StreamChannel] {
				t.Fatal("expected three distinct streams")
			}
			seenChannels[address.StreamChannel] = true
		}
		destinations[address.RemoteDCT] = true
		want[address] = true
	}
	if len(destinations) != 2 {
		t.Fatal("expected two destination DCTs")
	}
	if len(want) != wantFlows {
		t.Fatal("unexpected number of destination/stream flows")
	}
	await := func(active int) DCStats {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			s, err := c.Stats()
			if err != nil {
				t.Fatal(err)
			}
			if s.AcceptedSends == 3 && s.ActiveFlows == active {
				return s
			}
			if time.Now().After(deadline) {
				t.Fatalf("unexpected UCX capture counters: %+v", s)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if attach {
		s := await(wantFlows)
		if s.UCXSubmissions != 3 || s.SubmittedBatches != 3 || s.ReadErrors != 0 || s.MapErrors != 0 ||
			s.RingLost != 0 || s.RejectedRecords != 0 || s.FailedSubmissions != 0 {
			t.Fatalf("unexpected UCX counters: %+v", s)
		}
		if devx && (s.DevXSubmissions != 3 || s.DevXCreated == 0) {
			t.Fatalf("DevX path was not captured: %+v", s)
		}
		if !devx && s.DevXSubmissions != 0 {
			t.Fatal("unexpected DevX capture")
		}
		c.mu.Lock()
		flows := c.table.snapshot(time.Now())
		c.mu.Unlock()
		for _, flow := range flows {
			if !want[flow.Address] || flow.Port != uint8(port) {
				t.Fatal("captured UCX flow differs from delivered WQE")
			}
			delete(want, flow.Address)
		}
		if len(want) != 0 {
			t.Fatal("missing UCX destination flow")
		}
	}
	command('d')
	status("retired")
	if attach {
		await(0)
	}
	command('x')
	if err := child.Wait(); err != nil {
		t.Fatal("UCX helper teardown failed")
	}
	if attach {
		t.Logf("verified 3 UCX direct sends, %d destination/stream flows, and DCI retirement (DevX=%t, streams=%t, operation=%s)", wantFlows, devx, streams, operation)
	} else {
		t.Logf("verified selected libraries and 3 UCX direct sends with data and completion verification (DevX=%t, streams=%t, operation=%s); BPF was not loaded", devx, streams, operation)
	}
}
