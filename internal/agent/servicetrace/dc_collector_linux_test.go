//go:build linux

package servicetrace

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func buildDCFixture(t *testing.T, extra ...string) string {
	t.Helper()
	if _, err := exec.LookPath("cc"); err != nil {
		t.Fatal("DC fixture requires a C compiler")
	}
	file := filepath.Join(t.TempDir(), "dc-provider")
	cmd := exec.Command("cc", "-std=c11", "-pthread", "-g", "-O0", "-fno-inline", "-fPIE", "-pie", "-Wl,--build-id", "-Wall", "-Wextra", "-Werror", "testdata/dc_provider_fixture.c", "-o", file)
	cmd.Args = append(cmd.Args, extra...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile synthetic provider: %v\n%s", err, out)
	}
	return file
}

func TestUCXDCRejectsUnsupportedLayout(t *testing.T) {
	file := buildDCFixture(t, "-DTEST_UCX_BAD_DCI")
	if _, err := inspectUCXDC(file, file); err == nil {
		t.Fatal("accepted an unsupported DCI index width")
	}
}

func TestUCXDevXRejectsUnsupportedLayout(t *testing.T) {
	file := buildDCFixture(t, "-DTEST_DEVX_BAD_QPN")
	if err := CheckUCXDCDevX(file, file, file, file); err == nil {
		t.Fatal("accepted an unsupported opaque DevX object ID width")
	}
}

func TestDCProviderELF(t *testing.T) {
	file := buildDCFixture(t)
	p, err := inspectDCProvider(file, file)
	if err != nil {
		t.Fatal(err)
	}
	if p.layout.QPBase != 24 || p.layout.QPNum != 8 || p.layout.ContextFD != 8 {
		t.Fatal("incorrect synthetic provider layout")
	}
	if err := dcLibraryMapped(os.Getpid(), mustOpenDCFile(t, file)); err == nil {
		t.Fatal("accepted an unmapped provider")
	}
	if _, err := inspectDCProvider(file, "/dev/null"); err == nil {
		t.Fatal("accepted invalid debug ELF")
	}
	// Same structure layout with a distinct build ID must not be accepted.
	copy, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ef, err := elf.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	note := ef.Section(".note.gnu.build-id")
	if note == nil || note.Size < 20 {
		t.Fatal("missing synthetic build ID")
	}
	offset := note.Offset + 16 // note header followed by the GNU name
	ef.Close()
	copy[offset] ^= 1
	mismatch := filepath.Join(t.TempDir(), "mismatch")
	if err := os.WriteFile(mismatch, copy, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectDCProvider(file, mismatch); err == nil {
		t.Fatal("accepted mismatching debug build ID")
	}
	if _, err := inspectUCXDC(file, file); err != nil {
		t.Fatal(err)
	}
	if err := CheckUCXDCAM(file, file); err != nil {
		t.Fatal(err)
	}
	if err := CheckUCXDCDevX(file, file, file, file); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectUCXDC(file, mismatch); err == nil {
		t.Fatal("accepted mismatching UCX debug build ID")
	}
	copy[offset] ^= 1
	// objcopy removes DWARF without changing the build ID: matching symbols
	// and an ID alone must still be insufficient.
	stripped := filepath.Join(t.TempDir(), "stripped")
	if err := os.WriteFile(stripped, copy, 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("objcopy", "--strip-debug", stripped).CombinedOutput(); err != nil {
		t.Fatalf("strip synthetic DWARF: %v %s", err, out)
	}
	if _, err := inspectDCProvider(file, stripped); err == nil {
		t.Fatal("accepted ELF without full DWARF")
	}
	if _, err := inspectUCXDC(file, stripped); err == nil {
		t.Fatal("accepted UCX ELF without full DWARF")
	}
}

func mustOpenDCFile(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestDCBPFSpec(t *testing.T) {
	spec, err := loadDc()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Maps[dcMapDcSettings].ValueSize != uint32(4+binary.Size(dcLayout{})) ||
		spec.Maps[dcMapDcDevxQueues].ValueSize != uint32(binary.Size(dcDcDevxQueue{})) ||
		spec.Maps[dcMapDcUcxLayout].ValueSize != uint32(binary.Size(ucxDCLayout{})) ||
		spec.Maps[dcMapDcPending].ValueSize != uint32(binary.Size(dcDcBatch{})) ||
		binary.Size(dcDcBatch{}) != 1064 {
		t.Fatal("DC BPF/Go ABI mismatch")
	}
}

// The user explicitly enables this test under BPF/perf privileges. It needs
// no RDMA hardware and must never silently skip after explicit enablement.
func TestDCUprobeIntegration(t *testing.T) {
	if os.Getenv("RPINGMESH_DC_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged DC uprobe test")
	}
	t.Run("leader-exit", func(t *testing.T) { testDCUprobeIntegration(t, false, false) })
	t.Run("worker-exec", func(t *testing.T) { testDCUprobeIntegration(t, true, false) })
}

func TestUCXDevXUprobeIntegration(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_DEVX_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged UCX DevX lifecycle test")
	}
	testDCUprobeIntegration(t, false, true)
}

func TestUCXStreamUprobeIntegration(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_STREAM_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged UCX stream lifecycle test")
	}
	testDCUprobeIntegration(t, false, true, true)
}

func TestUCXAMUprobeIntegration(t *testing.T) {
	if os.Getenv("RPINGMESH_UCX_AM_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged UCX AM submission test")
	}
	testDCUprobeIntegration(t, false, true, true, true)
}

func testDCUprobeIntegration(t *testing.T, workerExec, devx bool, adapterOptions ...bool) {
	streams := len(adapterOptions) > 0 && adapterOptions[0]
	am := len(adapterOptions) > 1 && adapterOptions[1]
	file := buildDCFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, file)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); child.Process.Kill(); child.Wait() }()
	scan := bufio.NewScanner(stdout)
	if !scan.Scan() || scan.Text() != "ready" {
		t.Fatal("fixture not ready")
	}
	root := t.TempDir()
	for path, value := range map[string]string{
		"class/infiniband_verbs/uverbs-test/dev":                 "1:3", // synthetic /dev/null identity
		"class/infiniband_verbs/uverbs-test/ibdev":               "test-device",
		"class/infiniband/test-device/ports/1/gid_attrs/types/0": "RoCE v2",
		"class/infiniband/test-device/ports/1/gids/0":            "0000:0000:0000:0000:0000:ffff:c000:0201",
	} {
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := OpenDCCollector(DCOptions{PID: child.Process.Pid, Library: file, DebugFile: file,
		UCXLibrary: file, UCXDebugFile: file, UCXDevX: devx, UCXStreams: streams, UCXAM: am, Device: "test-device", Port: 1, sysfsRoot: root})
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
	command := func(op byte) {
		t.Helper()
		if _, err := fmt.Fprintf(stdin, "%c\n", op); err != nil {
			t.Fatal(err)
		}
		if !scan.Scan() || (scan.Text() != "done" && scan.Text() != "ready") {
			t.Fatal("fixture command failed")
		}
	}
	await := func(predicate func(DCStats) bool) DCStats {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			s, err := c.Stats()
			if err != nil {
				t.Fatal(err)
			}
			if predicate(s) {
				return s
			}
			if time.Now().After(deadline) {
				t.Fatalf("unexpected collector counters: %+v", s)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	command('c')
	command('s')
	await(func(s DCStats) bool { return s.AcceptedSends == 2 && s.ActiveFlows == 2 })
	command('f')
	await(func(s DCStats) bool { return s.FailedSubmissions == 1 && s.AcceptedSends == 2 })
	command('a')
	command('b')
	await(func(s DCStats) bool { return s.UnsupportedBatches >= 1 && s.AcceptedSends == 2 })
	command('v')
	await(func(s DCStats) bool { return s.RejectedRecords == 1 && s.AcceptedSends == 2 })
	command('d')
	await(func(s DCStats) bool { return s.ActiveFlows == 0 })
	command('c')
	command('s') // same pointer and QPN, fresh lifetime
	await(func(s DCStats) bool { return s.AcceptedSends == 4 && s.ActiveFlows == 2 })
	command('r')
	await(func(s DCStats) bool { return s.ActiveFlows == 0 })
	for _, retire := range []byte{'u', 'z'} {
		command('c')
		command('s')
		await(func(s DCStats) bool { return s.ActiveFlows == 2 })
		command(retire)
		await(func(s DCStats) bool { return s.ActiveFlows == 0 })
	}
	command('t')
	command('s') // stream-enabled QP, even channel zero
	await(func(s DCStats) bool { return s.UnsupportedBatches >= 2 && s.ActiveFlows == 0 })
	command('d')
	command('c')
	command('s')
	await(func(s DCStats) bool { return s.ActiveFlows == 2 })
	// Fill all remaining registry slots with synthetic entries. exec must
	// reclaim them before the new image can create another DCI.
	for i := uint64(1); i < 4096; i++ {
		if err := c.objs.DcQps.Update(i, dcDcIdentity{Token: i}, ebpf.UpdateNoExist); err != nil {
			t.Fatal(err)
		}
	}
	command('e')
	iter := c.objs.DcQps.Iterate()
	var oldQP uint64
	var oldID dcDcIdentity
	if iter.Next(&oldQP, &oldID) {
		t.Fatal("exec retained old QP registry entries")
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	await(func(s DCStats) bool { return s.ActiveFlows == 0 })
	command('c')
	command('s')
	final := await(func(s DCStats) bool { return s.ActiveFlows == 2 })
	command('w') // newly created worker thread shares the tracked DCI
	await(func(s DCStats) bool { return s.AcceptedSends == final.AcceptedSends+2 && s.ActiveFlows == 2 })
	command('y') // worker-thread destruction must retire its flows
	await(func(s DCStats) bool { return s.ActiveFlows == 0 })
	command('c')
	before, err := c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	command('A')
	await(func(s DCStats) bool {
		return s.UCXSubmissions == 1 && s.AcceptedSends == before.AcceptedSends+1 && s.ActiveFlows == 1
	})
	command('F')
	await(func(s DCStats) bool {
		return s.FailedSubmissions == before.FailedSubmissions+1 && s.UCXSubmissions == 1
	})
	for i, op := range []byte{'D', 'B', 'I', 'Q'} {
		command(op) // DevX, stale doorbell, mismatching WQE index, mismatching QPN
		await(func(s DCStats) bool {
			return s.UnsupportedBatches == before.UnsupportedBatches+uint64(i)+1 && s.UCXSubmissions == 1
		})
	}
	command('W') // Both ring and 16-bit producer wrap.
	await(func(s DCStats) bool {
		return s.UCXSubmissions == 2 && s.AcceptedSends == before.AcceptedSends+2 && s.ActiveFlows == 1
	})
	command('d')
	await(func(s DCStats) bool { return s.ActiveFlows == 0 })
	command('A') // A retired DCI must not be revived by the UCX adapter.
	await(func(s DCStats) bool {
		return s.UnsupportedBatches == before.UnsupportedBatches+5 && s.UCXSubmissions == 2 && s.ActiveFlows == 0
	})
	if devx && !streams {
		baseline, err := c.Stats()
		if err != nil {
			t.Fatal(err)
		}
		accepted := func(n uint64, active int) {
			t.Helper()
			await(func(s DCStats) bool {
				return s.DevXSubmissions == n && s.AcceptedSends == baseline.AcceptedSends+n && s.ActiveFlows == active
			})
		}
		command('C')
		command('A') // Created but not connected.
		await(func(s DCStats) bool {
			return s.DevXCreated == 1 && s.UnsupportedBatches > baseline.UnsupportedBatches && s.DevXSubmissions == 0
		})
		command('N')
		command('A')
		accepted(1, 1)
		command('F') // A failed call must not repeat the previous WQE.
		await(func(s DCStats) bool {
			return s.FailedSubmissions == baseline.FailedSubmissions+1 && s.DevXSubmissions == 1
		})
		command('B') // Doorbell mismatch.
		accepted(1, 1)
		command('W') // Ring and 16-bit producer wrap.
		accepted(2, 1)
		command('M') // Even a failed post-connect modification retires.
		accepted(2, 0)
		command('N')
		command('A')
		accepted(2, 0)
		command('C') // Reused pointer and QPN, fresh lifetime.
		command('N')
		command('A')
		accepted(3, 1)
		command('X')
		accepted(3, 0)
		command('C')
		command('J') // Failed connection.
		command('A')
		accepted(3, 0)
		command('X')
		command('S') // Multiple channels, even stream zero.
		command('N')
		command('A')
		accepted(3, 0)
		command('X')
		command('K') // Failed creation.
		command('A')
		accepted(3, 0)
		command('C')
		command('M') // Modification outside initial connect also retires RESET.
		command('N')
		command('A')
		accepted(3, 0)
		command('C')
		command('N')
		command('A')
		accepted(4, 1)
		command('e')
		accepted(4, 0)
		it := c.objs.DcDevxQueues.Iterate()
		var key uint64
		var queue dcDcDevxQueue
		if it.Next(&key, &queue) || it.Err() != nil {
			t.Fatal("exec retained DevX queue metadata")
		}
		command('C')
		command('N')
		command('A')
		accepted(5, 1)
		command('X')
		accepted(5, 0)
	}
	if streams {
		baseline, err := c.Stats()
		if err != nil {
			t.Fatal(err)
		}
		accepted := func(n uint64, active int) {
			t.Helper()
			await(func(s DCStats) bool { return s.AcceptedSends == baseline.AcceptedSends+n && s.ActiveFlows == active })
		}
		command('S')
		command('A') // Not connected yet.
		accepted(0, 0)
		command('N')
		command('A') // Stream zero is a stream flow.
		accepted(1, 1)
		command('1')
		command('A') // Same address and QPN, different channel.
		accepted(2, 2)
		c.mu.Lock()
		flows := c.table.snapshot(time.Now())
		c.mu.Unlock()
		seen := map[uint16]bool{}
		for _, flow := range flows {
			if flow.Address.StreamChannels != 2 {
				t.Fatal("lost stream creation metadata")
			}
			seen[flow.Address.StreamChannel] = true
		}
		if !seen[0] || !seen[1] {
			t.Fatal("stream flows were merged")
		}
		command('W') // Producer and ring wrap retain the stream.
		accepted(3, 2)
		for _, op := range []byte{'F', 'H', 'L', 'B'} {
			command(op)
		}
		command('2')
		command('A') // Out of the creation-time range.
		accepted(3, 2)
		command('M')
		accepted(3, 0) // Failed modification still retires.
		command('0')
		command('N')
		command('A')
		accepted(3, 0)
		command('S')
		command('J')
		command('A')
		accepted(3, 0)
		command('X')
		for _, op := range []byte{'O', 'T', 'K'} {
			command(op)
			command('N')
			command('A')
			accepted(3, 0)
			command('X')
		}
		command('S')
		command('N')
		command('1')
		command('A')
		accepted(4, 1)
		command('e')
		accepted(4, 0)
		command('S')
		command('N')
		command('A')
		accepted(5, 1)
		command('X')
		accepted(5, 0)
		command('C')
		command('N')
		command('1')
		command('A') // Non-stream DCI rejects nonzero channel.
		accepted(5, 0)
		command('0')
		command('A')
		accepted(6, 1)
		command('X')
		accepted(6, 0)
	}
	if am {
		baseline, err := c.Stats()
		if err != nil {
			t.Fatal(err)
		}
		accepted := func(n uint64, active int) {
			t.Helper()
			await(func(s DCStats) bool {
				return s.AcceptedSends == baseline.AcceptedSends+n && s.UCXSubmissions == baseline.UCXSubmissions+n && s.ActiveFlows == active
			})
		}
		command('c')
		for i, op := range []byte{'i', 'p', 'o', 'Z'} {
			command(op) // Includes bcopy length zero and asynchronous zcopy.
			accepted(uint64(i+1), 1)
		}
		for _, op := range []byte{'j', 'l', 'V', 'Y'} {
			command(op)
		}
		await(func(s DCStats) bool { return s.FailedSubmissions == baseline.FailedSubmissions+4 })
		accepted(4, 1)
		command('n') // Reentrant pack callback: reject both inner and outer.
		await(func(s DCStats) bool { return s.UnsupportedBatches == baseline.UnsupportedBatches+1 })
		accepted(4, 1)
		command('A')
		accepted(5, 1) // Pending state must recover after nesting.
		command('d')
		accepted(5, 0)
		command('S')
		command('N')
		command('1')
		for i, op := range []byte{'i', 'p', 'Z'} {
			command(op)
			accepted(uint64(i+6), 1)
		}
		command('X')
		accepted(8, 0)
	}
	final, err = c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if final.ReadErrors != 0 || final.MapErrors != 0 || final.RingLost != 0 {
		t.Fatalf("capture errors: %+v", final)
	}
	if workerExec {
		command('c')
		command('s')
		await(func(s DCStats) bool { return s.ActiveFlows == 2 })
		command('q')
	} else if _, err := fmt.Fprintln(stdin, "x"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		config, err := c.objs.DcSettings.LookupBytes(uint32(0))
		if err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint32(config) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("process exit did not disable TGID filter")
		}
		time.Sleep(10 * time.Millisecond)
	}
	await(func(s DCStats) bool { return s.ActiveFlows == 0 })

}

func TestUCXStreamsRejectUnsupportedLayout(t *testing.T) {
	file := buildDCFixture(t, "-DTEST_UCX_BAD_CHANNEL")
	if err := CheckUCXDCStreams(file, file, file, file); err == nil {
		t.Fatal("accepted incorrect endpoint channel width")
	}
}
