//go:build linux

package servicetrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMLX5DCHardware validates actual provider-generated WQEs against our
// decoder after successful send and receive completions. It uses local DCTs,
// does not capture wire packets, and does not validate a production adapter or
// ECMP equivalence. Hardware addresses stay in memory and are never logged.
func TestMLX5DCHardware(t *testing.T) {
	if os.Getenv("RPINGMESH_DC_HARDWARE_TEST") != "1" {
		t.Skip("opt-in mlx5 DC hardware test")
	}
	args := []string{
		os.Getenv("RPINGMESH_DC_TEST_DEVICE"),
		os.Getenv("RPINGMESH_DC_TEST_PORT"),
		os.Getenv("RPINGMESH_DC_TEST_GID_INDEX"),
	}
	for _, v := range args {
		if v == "" {
			t.Fatal("set RPINGMESH_DC_TEST_DEVICE, RPINGMESH_DC_TEST_PORT and RPINGMESH_DC_TEST_GID_INDEX")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	helper := filepath.Join(t.TempDir(), "mlx5-dc-send")
	build := exec.CommandContext(ctx, "cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
		"testdata/mlx5_dc_send.c", "-o", helper, "-libverbs", "-lmlx5")
	if err := build.Run(); err != nil {
		t.Fatalf("build hardware helper (requires C compiler and RDMA development headers): %v", err)
	}
	run := exec.CommandContext(ctx, helper, args...)
	// stdout contains live address data. Keep it separate from diagnostic text
	// and never dump either buffer into a public test report or saved fixture.
	var records, diagnostic bytes.Buffer
	run.Stdout, run.Stderr = &records, &diagnostic
	if err := run.Run(); err != nil {
		// The helper emits only fixed operation names and numeric errno with
		// this prefix. Suppress any provider diagnostics containing live IDs.
		for _, line := range strings.Split(diagnostic.String(), "\n") {
			if strings.HasPrefix(line, "RPINGMESH_DC_TEST_ERROR: ") {
				t.Log(strings.TrimPrefix(line, "RPINGMESH_DC_TEST_ERROR: "))
			}
		}
		t.Fatalf("DC hardware helper failed: %v", err)
	}
	const recordSize = 104
	if records.Len() != 3*recordSize {
		t.Fatal("unexpected hardware record count")
	}
	table, _ := newDCFlowTable(8, time.Minute)
	be := binary.BigEndian
	var qpn, firstDCT uint32
	now := time.Now()
	for i := 0; i < 3; i++ {
		record := records.Next(recordSize)
		expectedQPN, expectedDCT := be.Uint32(record), be.Uint32(record[4:])
		prefix := record[40:]
		if !bytes.Equal(prefix[16:24], make([]byte, 8)) {
			t.Fatal("capture helper did not redact the test access key")
		}
		a, err := decodeMLX5DCAddress(prefix, expectedQPN)
		if err != nil {
			t.Fatalf("decode committed WQE: %v", err)
		}
		if a.RemoteDCT != expectedDCT || a.FlowLabel != be.Uint32(record[8:]) ||
			a.SGIDIndex != record[12] || a.TrafficClass != record[14] ||
			a.SL != record[15] || a.HopLimit != record[16] ||
			!bytes.Equal(a.RemoteGID[:], record[24:40]) {
			t.Fatal("decoded WQE does not match the submitted address vector")
		}
		if a.FlowLabel != 0 && a.AVUDPSourcePort != UDPSourcePort(a.FlowLabel) {
			t.Fatal("provider AV UDP port differs from explicit flow label mapping")
		}
		if i == 0 {
			qpn, firstDCT = expectedQPN, expectedDCT
		} else if expectedQPN != qpn || (i == 1 && expectedDCT == firstDCT) || (i == 2 && expectedDCT != firstDCT) {
			t.Fatal("helper did not send from one DCI to two DCTs")
		}
		if err := table.observeCommitted(1, record[13], qpn, prefix, now); err != nil {
			t.Fatalf("record committed DC flow: %v", err)
		}
	}
	if len(table.snapshot(now)) != 3 {
		t.Fatal("DC flow table merged distinct submitted address vectors")
	}
	table.forgetDCI(1)
	if len(table.snapshot(now)) != 0 {
		t.Fatal("DCI teardown retained flows")
	}
}
