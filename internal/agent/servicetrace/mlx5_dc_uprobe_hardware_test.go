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

// TestMLX5DCUprobeHardware compares actual committed WQEs and CQ-verified
// deliveries with the collector's live flows. The user runs this explicitly
// with BPF/perf privileges; library/debug/helper paths are supplied locally.
func TestMLX5DCUprobeHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_DC_UPROBE_HARDWARE_TEST") != "1" {
		t.Skip("user-run privileged mlx5 DC uprobe hardware test")
	}
	get := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("set %s", name)
		}
		return value
	}
	device := get("RPINGMESH_DC_TEST_DEVICE")
	portText := get("RPINGMESH_DC_TEST_PORT")
	gidIndex := get("RPINGMESH_DC_TEST_GID_INDEX")
	port, err := strconv.ParseUint(portText, 10, 8)
	if err != nil || port == 0 {
		t.Fatal("invalid hardware test port")
	}
	library := get("RPINGMESH_DC_LIBRARY")
	debug := get("RPINGMESH_DC_DEBUG")
	helper := get("RPINGMESH_DC_TEST_HELPER")
	if err := CheckDCProvider(library, debug); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, helper, device, portText, gidIndex, "--controlled")
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
		// Provider diagnostics may contain deployment identities. Only the
		// helper's fixed operation names and numeric errno are safe to report.
		for _, line := range strings.Split(diagnostic.String(), "\n") {
			if strings.HasPrefix(line, "RPINGMESH_DC_TEST_ERROR: ") {
				t.Log(strings.TrimPrefix(line, "RPINGMESH_DC_TEST_ERROR: "))
			}
		}
	}()
	reader := bufio.NewReader(stdout)
	status := func(want string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || line != want+"\n" {
			t.Fatalf("hardware helper did not reach %s", want)
		}
	}
	command := func(op byte) {
		t.Helper()
		if _, err := stdin.Write([]byte{op}); err != nil {
			t.Fatal(err)
		}
	}
	status("ready")
	c, err := OpenDCCollector(DCOptions{PID: child.Process.Pid, Library: library, DebugFile: debug, Device: device, Port: uint8(port)})
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
	command('g')
	const recordSize = 104
	var records [3 * recordSize]byte
	if _, err := io.ReadFull(reader, records[:]); err != nil {
		t.Fatal("hardware helper did not complete three DC sends")
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
				t.Fatalf("unexpected hardware capture counters: %+v", s)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	stats := await(3)
	c.mu.Lock()
	flows := c.table.snapshot(time.Now())
	c.mu.Unlock()
	for i := 0; i < 3; i++ {
		record := records[i*recordSize : (i+1)*recordSize]
		qpn := binary.BigEndian.Uint32(record)
		address, err := decodeMLX5DCAddress(record[40:], qpn)
		if err != nil {
			t.Fatal("invalid committed hardware prefix")
		}
		matched := 0
		for _, flow := range flows {
			if flow.Address == address && flow.Port == uint8(port) {
				matched++
			}
		}
		if matched != 1 {
			t.Fatal("captured flow differs from CQ-verified submitted WQE")
		}
	}
	if stats.Created != 1 || stats.SubmittedBatches != 3 || stats.FailedSubmissions != 0 ||
		stats.ReadErrors != 0 || stats.MapErrors != 0 || stats.RingLost != 0 || stats.RejectedRecords != 0 {
		t.Fatalf("unexpected hardware capture counters: %+v", stats)
	}
	command('d')
	status("retired")
	await(0)
	command('x')
	if err := child.Wait(); err != nil {
		t.Fatal("hardware helper teardown failed")
	}
	t.Logf("verified %d submitted sends, %d distinct flows, and DCI retirement", stats.AcceptedSends, stats.ActiveFlows)
}
