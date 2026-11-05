//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/agent/servicetrace"
)

// runDCTrace runs run with a fresh flag set and the given arguments and
// returns what it printed to stdout.
func runDCTrace(t *testing.T, args ...string) (string, error) {
	t.Helper()
	oldArgs, oldFlags, oldStdout := os.Args, flag.CommandLine, os.Stdout
	defer func() { os.Args, flag.CommandLine, os.Stdout = oldArgs, oldFlags, oldStdout }()
	os.Args = append([]string{"dc-trace"}, args...)
	flag.CommandLine = flag.NewFlagSet("dc-trace", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	os.Stdout = w
	output := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		output <- string(b)
	}()
	runErr := run()
	w.Close()
	return <-output, runErr
}

// buildFixture compiles the synthetic libmlx5/UCX provider of the
// servicetrace tests.
func buildFixture(t *testing.T, extra ...string) string {
	t.Helper()
	if _, err := exec.LookPath("cc"); err != nil {
		t.Fatal("DC fixture requires a C compiler")
	}
	file := filepath.Join(t.TempDir(), "dc-provider")
	cmd := exec.Command("cc", "-std=c11", "-pthread", "-g", "-O0", "-fno-inline", "-fPIE", "-pie", "-Wl,--build-id", "-Wall", "-Wextra", "-Werror", "../../internal/agent/servicetrace/testdata/dc_provider_fixture.c", "-o", file)
	cmd.Args = append(cmd.Args, extra...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile synthetic provider: %v\n%s", err, out)
	}
	return file
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	const bounds = "port must be 1..255; duration, capacity and idle-timeout must be positive"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"extra"}, "unexpected positional arguments"},
		{[]string{"-ucx-streams"}, "-ucx-streams requires -ucx-devx"},
		{[]string{"-check", "-ucx-streams"}, "-ucx-streams requires -ucx-devx"},
		{[]string{"-check"}, "open provider ELF: open : no such file or directory"},
		{nil, bounds},
		{[]string{"-port", "256"}, bounds},
		{[]string{"-port", "1", "-duration", "0"}, bounds},
		{[]string{"-port", "1", "-capacity", "0"}, bounds},
		{[]string{"-port", "1", "-idle-timeout", "0"}, bounds},
		{[]string{"-port", "1"}, "DC collector requires a PID, provider/debug ELF, device and port"},
	} {
		out, err := runDCTrace(t, tc.args...)
		if err == nil || err.Error() != tc.want || out != "" {
			t.Fatalf("%q: got %v and output %q, want %q", tc.args, err, out, tc.want)
		}
	}
}

func TestRunCheck(t *testing.T) {
	good := buildFixture(t)
	badDCI := buildFixture(t, "-DTEST_UCX_BAD_DCI")
	badQPN := buildFixture(t, "-DTEST_DEVX_BAD_QPN")
	badChannel := buildFixture(t, "-DTEST_UCX_BAD_CHANNEL")
	// One missing function per operation check identifies which checks ran.
	missing := buildFixture(t, "-Duct_dc_mlx5_ep_am_bcopy=renamed_am", "-Duct_dc_mlx5_ep_put_bcopy=renamed_rma",
		"-Duct_dc_mlx5_ep_atomic32_post=renamed_atomic", "-Duct_dc_mlx5_ep_tag_eager_bcopy=renamed_tag")
	provider := []string{"-check", "-library", good, "-debug", good}
	ucx := func(file string, flags ...string) []string {
		return append(append(append([]string(nil), provider...), "-ucx-library", file, "-ucx-debug", file), flags...)
	}
	const validated = "Provider layout validated; BPF was not loaded.\n"
	for _, args := range [][]string{
		provider,
		ucx(good),
		ucx(good, "-ucx-devx", "-ucx-streams", "-ucx-am", "-ucx-rma", "-ucx-atomic", "-ucx-tag"),
		ucx(badQPN, "-ucx-am"), // the bad DevX object layout matters only with -ucx-devx
		ucx(badChannel, "-ucx-devx"),
		ucx(missing, "-ucx-devx", "-ucx-streams"),
	} {
		if out, err := runDCTrace(t, args...); err != nil || out != validated {
			t.Fatalf("%q: got %v and output %q", args, err, out)
		}
	}
	const ucxMissing = "open : no such file or directory"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-check", "-library", good, "-debug", badDCI}, "provider and debug build IDs differ"},
		{append(provider, "-ucx-library", good), ucxMissing},
		{append(provider, "-ucx-debug", good), "open : no such file or directory"},
		{append(provider, "-ucx-devx"), ucxMissing},
		{append(provider, "-ucx-am"), ucxMissing},
		{ucx(badDCI, "-ucx-devx"), "UCX uct_dc_mlx5_ep.dci: field size does not match supported ABI"},
		{[]string{"-check", "-library", badQPN, "-debug", badQPN, "-ucx-library", good, "-ucx-debug", good, "-ucx-devx", "-ucx-am"},
			"mlx5dv_devx_obj.object_id: field size does not match supported ABI"},
		{ucx(badChannel, "-ucx-devx", "-ucx-streams"), "UCX uct_dc_mlx5_ep.dci_channel_index: field size does not match supported ABI"},
		{ucx(missing, "-ucx-am"), "required UCX function uct_dc_mlx5_ep_am_bcopy is unavailable"},
		{ucx(missing, "-ucx-rma"), "required UCX function uct_dc_mlx5_ep_put_bcopy is unavailable"},
		{ucx(missing, "-ucx-atomic"), "required UCX function uct_dc_mlx5_ep_atomic32_post is unavailable"},
		{ucx(missing, "-ucx-tag"), "required UCX function uct_dc_mlx5_ep_tag_eager_bcopy is unavailable"},
		{ucx(missing, "-ucx-tag", "-ucx-atomic", "-ucx-rma", "-ucx-am"), "required UCX function uct_dc_mlx5_ep_am_bcopy is unavailable"},
		{ucx(missing, "-ucx-tag", "-ucx-atomic", "-ucx-rma"), "required UCX function uct_dc_mlx5_ep_put_bcopy is unavailable"},
		{ucx(missing, "-ucx-tag", "-ucx-atomic"), "required UCX function uct_dc_mlx5_ep_atomic32_post is unavailable"},
	} {
		out, err := runDCTrace(t, tc.args...)
		if err == nil || err.Error() != tc.want || out != "" {
			t.Fatalf("%q: got %v and output %q, want %q", tc.args, err, out, tc.want)
		}
	}
}

// The user explicitly enables this test under BPF/perf privileges, like the
// servicetrace DC uprobe tests. It needs no RDMA hardware.
func TestRunObserve(t *testing.T) {
	if os.Getenv("RPINGMESH_DC_UPROBE_TEST") != "1" {
		t.Skip("user-run privileged DC uprobe test")
	}
	file := buildFixture(t)
	child := exec.Command(file)
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
	if scan := bufio.NewScanner(stdout); !scan.Scan() || scan.Text() != "ready" {
		t.Fatal("fixture not ready")
	}
	start := time.Now()
	out, err := runDCTrace(t, "-pid", strconv.Itoa(child.Process.Pid), "-library", file, "-debug", file,
		"-device", "test-device", "-port", "1", "-duration", "1500ms")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatalf("returned after %v, before the observation duration", elapsed)
	}
	// One line per second, plus the final statistics after the timeout.
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected periodic and final statistics, got %q", out)
	}
	for _, line := range lines {
		var stats servicetrace.DCStats
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&stats); err != nil || stats != (servicetrace.DCStats{}) {
			t.Fatalf("unexpected statistics line %q: %v", line, err)
		}
	}
}
