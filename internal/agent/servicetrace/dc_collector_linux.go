//go:build linux

package servicetrace

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// DCOptions selects one process and one RDMA port. Attach before it creates
// DCIs. Library and DebugFile must describe the same ELF build, with complete
// provider DWARF. UCXLibrary/UCXDebugFile optionally enable the experimental
// dc_mlx5 AM-short adapter in addition to the libmlx5 extended WR API.
type DCOptions struct {
	PID                        int
	Library, DebugFile, Device string
	UCXLibrary, UCXDebugFile   string
	UCXDevX                    bool
	UCXStreams                 bool
	UCXAM                      bool
	UCXRMA                     bool
	Port                       uint8
	Capacity                   int
	IdleTimeout                time.Duration
	sysfsRoot                  string // tests only; production always uses the host's sysfs
}

// DCStats intentionally contains no process, device, address or binary IDs.
type DCStats struct {
	SubmittedBatches   uint64 `json:"submitted_batches"`
	FailedSubmissions  uint64 `json:"failed_submissions"`
	UnsupportedBatches uint64 `json:"unsupported_batches"`
	ReadErrors         uint64 `json:"read_errors"`
	MapErrors          uint64 `json:"map_errors"`
	RingLost           uint64 `json:"ring_lost"`
	Retired            uint64 `json:"retired"`
	Created            uint64 `json:"created"`
	UCXSubmissions     uint64 `json:"ucx_submissions"`
	DevXSubmissions    uint64 `json:"devx_submissions"`
	DevXCreated        uint64 `json:"devx_created"`
	AcceptedSends      uint64 `json:"accepted_sends"`
	RejectedRecords    uint64 `json:"rejected_records"`
	ActiveFlows        int    `json:"active_flows"`
}

// DCCollector is an experimental observer, not a service-probe source. It
// retains AV UDP-port candidates without claiming wire/ECMP equivalence.
type DCCollector struct {
	options            DCOptions
	objs               dcObjects
	links              []link.Link
	reader             *ringbuf.Reader
	library            *os.File
	ucxLibrary         *os.File
	pidfd              int
	table              *dcFlowTable
	accepted, rejected atomic.Uint64
	closeOnce          sync.Once
	mu                 sync.Mutex // serialize consumers and table-clock updates
	lastLoss           uint64
}

// CheckDCProvider performs only ELF/DWARF checks and needs no BPF privileges.
func CheckDCProvider(library, debugFile string) error {
	_, err := inspectDCProvider(library, debugFile)
	return err
}

func OpenDCCollector(options DCOptions) (_ *DCCollector, err error) {
	if options.PID <= 0 || options.Port == 0 || options.Library == "" || options.DebugFile == "" ||
		options.Device == "" || filepath.Base(options.Device) != options.Device || options.Device == "." || options.Device == ".." {
		return nil, fmt.Errorf("DC collector requires a PID, provider/debug ELF, device and port")
	}
	if options.UCXStreams && !options.UCXDevX {
		return nil, fmt.Errorf("UCX streams require UCX DevX")
	}
	if options.Capacity == 0 {
		options.Capacity = 4096
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = time.Minute
	}
	table, err := newDCFlowTable(options.Capacity, options.IdleTimeout)
	if err != nil {
		return nil, err
	}
	c := &DCCollector{options: options, table: table, pidfd: -1}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	c.pidfd, err = unix.PidfdOpen(options.PID, 0)
	if err != nil {
		return nil, fmt.Errorf("open target pidfd: %w", err)
	}
	c.library, err = os.Open(options.Library)
	if err != nil {
		return nil, err
	}
	// Pin the actual inode throughout inspection and attachment, including
	// when the library pathname is replaced during a package upgrade.
	pinned := fmt.Sprintf("/proc/self/fd/%d", c.library.Fd())
	profile, err := inspectDCProviderMode(pinned, options.DebugFile, options.UCXDevX)
	if err != nil {
		return nil, err
	}
	if (runtime.GOARCH == "amd64" && profile.machine != elf.EM_X86_64) ||
		(runtime.GOARCH == "arm64" && profile.machine != elf.EM_AARCH64) ||
		(runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return nil, fmt.Errorf("provider architecture does not match collector")
	}
	if err = dcLibraryMapped(options.PID, c.library); err != nil {
		return nil, err
	}
	var ucx *ucxDCProvider
	var ucxPinned string
	if options.UCXLibrary != "" || options.UCXDebugFile != "" || options.UCXDevX || options.UCXAM || options.UCXRMA {
		if options.UCXLibrary == "" || options.UCXDebugFile == "" {
			return nil, fmt.Errorf("UCX library and matching debug ELF must both be supplied")
		}
		c.ucxLibrary, err = os.Open(options.UCXLibrary)
		if err != nil {
			return nil, err
		}
		ucxPinned = fmt.Sprintf("/proc/self/fd/%d", c.ucxLibrary.Fd())
		ucx, err = inspectUCXDCOperations(ucxPinned, options.UCXDebugFile, options.UCXDevX, options.UCXStreams, options.UCXAM, options.UCXRMA)
		if err != nil {
			return nil, err
		}
		if ucx.machine != profile.machine {
			return nil, fmt.Errorf("UCX/provider architectures differ")
		}
		if err = dcLibraryMapped(options.PID, c.ucxLibrary); err != nil {
			return nil, err
		}
	}
	if !c.alive() {
		return nil, fmt.Errorf("target process exited")
	}
	_ = rlimit.RemoveMemlock()
	if err = loadDcObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load DC BPF (requires BPF/perf privileges): %w", err)
	}
	var config bytes.Buffer
	_ = binary.Write(&config, binary.LittleEndian, uint32(options.PID))
	_ = binary.Write(&config, binary.LittleEndian, profile.layout)
	if err = c.objs.DcSettings.Put(uint32(0), config.Bytes()); err != nil {
		return nil, err
	}
	if ucx != nil {
		if options.UCXDevX {
			ucx.layout.DevXEnabled = 1
			ucx.layout.DevXContext, ucx.layout.DevXQPN = profile.devxContext, profile.devxQPN
		}
		if err = c.objs.DcUcxLayout.Put(uint32(0), ucx.layout); err != nil {
			return nil, err
		}
	}
	if c.reader, err = ringbuf.NewReader(c.objs.DcEvents); err != nil {
		return nil, err
	}
	exe, err := link.OpenExecutable(pinned)
	if err != nil {
		return nil, err
	}
	// Install retirement/return probes before enabling creation. This excludes
	// partially observed QPs during attachment and prevents stale registration.
	probes := []struct {
		name string
		prog *ebpf.Program
		ret  bool
	}{
		{"mlx5_destroy_qp", c.objs.DcRetire, false},
		{"mlx5dv_modify_qp_udp_sport", c.objs.DcRetire, false},
		{"mlx5_modify_qp", c.objs.DcModifyExit, true},
		{"mlx5_modify_qp", c.objs.DcModifyEnter, false},
		{"mlx5_send_wr_complete", c.objs.DcCompleteExit, true},
		{"mlx5_send_wr_complete", c.objs.DcCompleteEnter, false},
	}
	if profile.symbols["mlx5dv_devx_qp_modify"] != 0 {
		probes = append(probes, struct {
			name string
			prog *ebpf.Program
			ret  bool
		}{"mlx5dv_devx_qp_modify", c.objs.DcRetire, false})
	}
	exitLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exit", Program: c.objs.DcExit})
	if err != nil {
		return nil, fmt.Errorf("attach process-exit invalidation: %w", err)
	}
	c.links = append(c.links, exitLink)
	// If exit happened before the hook was installed, do not enable uprobes.
	// Otherwise the hook disables the TGID filter before PID reuse is possible.
	if !c.alive() {
		return nil, fmt.Errorf("target process exited before attachment")
	}
	execLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exec", Program: c.objs.DcExec})
	if err != nil {
		return nil, fmt.Errorf("attach process-exec invalidation: %w", err)
	}
	c.links = append(c.links, execLink)
	if options.UCXDevX {
		probes = append(probes, struct {
			name string
			prog *ebpf.Program
			ret  bool
		}{"mlx5dv_devx_obj_destroy", c.objs.DcRetire, false},
			struct {
				name string
				prog *ebpf.Program
				ret  bool
			}{"mlx5dv_devx_obj_modify", c.objs.DcDevxModify, false})
	}
	probes = append(probes,
		struct {
			name string
			prog *ebpf.Program
			ret  bool
		}{"mlx5dv_create_qp", c.objs.DcCreateExit, true},
		struct {
			name string
			prog *ebpf.Program
			ret  bool
		}{"mlx5dv_create_qp", c.objs.DcCreateEnter, false})
	for _, p := range probes {
		// PID-scoped perf events do not inherit to worker threads. Attach
		// across tasks and filter the target TGID in BPF before any reads.
		opts := &link.UprobeOptions{Address: profile.symbols[p.name]}
		var hook link.Link
		if p.ret {
			hook, err = exe.Uretprobe("", p.prog, opts)
		} else {
			hook, err = exe.Uprobe("", p.prog, opts)
		}
		if err != nil {
			return nil, fmt.Errorf("attach DC %s: %w", p.name, err)
		}
		c.links = append(c.links, hook)
	}
	if ucx != nil {
		ucxExe, err := link.OpenExecutable(ucxPinned)
		if err != nil {
			return nil, err
		}
		type ucxProbe struct {
			offset uint64
			prog   *ebpf.Program
			ret    bool
		}
		hooks := []ucxProbe{{ucx.symbol, c.objs.DcUcxExit, true}, {ucx.symbol, c.objs.DcUcxEnter, false}}
		if options.UCXAM {
			for i, enter := range []*ebpf.Program{c.objs.DcUcxEnter, c.objs.DcUcxBcopyEnter, c.objs.DcUcxZcopyEnter} {
				hooks = append(hooks, ucxProbe{ucx.amSymbols[i], c.objs.DcUcxExit, true}, ucxProbe{ucx.amSymbols[i], enter, false})
			}
		}
		if options.UCXRMA {
			for i, enter := range []*ebpf.Program{c.objs.DcUcxPutShortEnter, c.objs.DcUcxPutBcopyEnter, c.objs.DcUcxPutZcopyEnter, c.objs.DcUcxGetEnter, c.objs.DcUcxGetEnter} {
				hooks = append(hooks, ucxProbe{ucx.rmaSymbols[i], c.objs.DcUcxExit, true}, ucxProbe{ucx.rmaSymbols[i], enter, false})
			}
		}
		if options.UCXDevX {
			hooks = append(hooks, ucxProbe{ucx.connectSymbol, c.objs.DcDevxConnectExit, true},
				ucxProbe{ucx.connectSymbol, c.objs.DcDevxConnectEnter, false},
				ucxProbe{ucx.createSymbol, c.objs.DcDevxCreateExit, true},
				ucxProbe{ucx.createSymbol, c.objs.DcDevxCreateEnter, false})
		}
		// Provider retirement hooks are active before UCX creation is enabled.
		for _, h := range hooks {
			var hook link.Link
			opts := &link.UprobeOptions{Address: h.offset}
			if h.ret {
				hook, err = ucxExe.Uretprobe("", h.prog, opts)
			} else {
				hook, err = ucxExe.Uprobe("", h.prog, opts)
			}
			if err != nil {
				return nil, fmt.Errorf("attach UCX DC probe: %w", err)
			}
			c.links = append(c.links, hook)
		}
	}
	if !c.alive() {
		return nil, fmt.Errorf("target process exited during attachment")
	}
	return c, nil
}

func dcLibraryMapped(pid int, library *os.File) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(library.Fd()), &st); err != nil {
		return err
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || !strings.Contains(fields[1], "x") {
			continue
		}
		var major, minor uint32
		if _, err := fmt.Sscanf(fields[3], "%x:%x", &major, &minor); err != nil {
			continue
		}
		ino, err := strconv.ParseUint(fields[4], 10, 64)
		if err == nil && ino == st.Ino && unix.Mkdev(major, minor) == uint64(st.Dev) {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("selected provider inode is not executable in the target process")
}

func (c *DCCollector) alive() bool {
	if c.pidfd < 0 {
		return false
	}
	fds := []unix.PollFd{{Fd: int32(c.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	return err == nil && n == 0
}

// Run reads until cancellation or process exit. The caller must join Run
// before Close; a collector is single-use and does not support a second Run.
func (c *DCCollector) Run(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { c.reader.Close() })
	defer stop()
	defer c.table.reset()
	var record ringbuf.Record
	for {
		if !c.alive() {
			return nil
		}
		c.reader.SetDeadline(time.Now().Add(250 * time.Millisecond))
		err := c.reader.ReadInto(&record)
		if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
			return nil
		}
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}
		if !c.alive() {
			return nil
		}
		enabled, configErr := c.enabled()
		if configErr != nil {
			return configErr
		}
		if !enabled {
			return nil
		}
		c.mu.Lock()
		if err == nil {
			c.consume(record.RawSample, time.Now())
		}
		pruneErr := c.prune(time.Now())
		c.mu.Unlock()
		if pruneErr != nil {
			return pruneErr
		}
	}
}

func (c *DCCollector) consume(raw []byte, now time.Time) {
	var b dcDcBatch
	if len(raw) != binary.Size(b) || binary.Read(bytes.NewReader(raw), binary.LittleEndian, &b) != nil ||
		b.Count == 0 || b.Count > 16 || b.Identity.Port != uint32(c.options.Port) {
		c.rejected.Add(1)
		return
	}
	var id dcDcIdentity
	var epoch uint64
	if c.objs.DcEpoch.Lookup(uint32(0), &epoch) != nil || c.objs.DcQps.Lookup(b.Qp, &id) != nil ||
		id != b.Identity || id.Token <= epoch || id.State != 3 || !c.validDeviceFD(id.Fd) {
		c.rejected.Add(1)
		return
	}
	// Stream metadata must still belong to this live DevX DCI.
	if b.StreamChannels != 0 {
		var queue dcDcDevxQueue
		if !c.options.UCXStreams || b.Count != 1 ||
			c.objs.DcDevxQueues.Lookup(b.Qp, &queue) != nil || queue.Token != id.Token || queue.Channels != b.StreamChannels {
			c.rejected.Add(1)
			return
		}
	}
	// Validate the entire batch before admitting any of it.
	for i := uint32(0); i < b.Count; i++ {
		if b.Prefix[i][16]|b.Prefix[i][17]|b.Prefix[i][18]|b.Prefix[i][19]|
			b.Prefix[i][20]|b.Prefix[i][21]|b.Prefix[i][22]|b.Prefix[i][23] != 0 {
			c.rejected.Add(1)
			return
		}
		a, err := decodeMLX5DCStreamAddress(b.Prefix[i][:], id.Qpn, b.StreamChannels)
		if err != nil || !c.roceV2(a.SGIDIndex) {
			c.rejected.Add(1)
			return
		}
	}
	for i := uint32(0); i < b.Count; i++ {
		if err := c.table.observeStreamCommitted(id.Token, uint8(id.Port), id.Qpn, b.Prefix[i][:], b.StreamChannels, now); err != nil {
			c.table.reset()
			c.rejected.Add(1)
			return
		}
		c.accepted.Add(1)
	}
}

func (c *DCCollector) validDeviceFD(fd int32) bool {
	if fd < 0 {
		return false
	}
	info, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", c.options.PID, fd))
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	devices, err := UverbsDevices(c.options.sysfsRoot)
	return err == nil && devices[MakeDev(unix.Major(uint64(stat.Rdev)), unix.Minor(uint64(stat.Rdev)))] == c.options.Device
}

func (c *DCCollector) roceV2(index uint8) bool {
	root := c.options.sysfsRoot
	if root == "" {
		root = DefaultSysfsRoot
	}
	base := filepath.Join(root, "class/infiniband", c.options.Device, "ports", strconv.Itoa(int(c.options.Port)))
	kind, err := os.ReadFile(filepath.Join(base, "gid_attrs/types", strconv.Itoa(int(index))))
	if err != nil || strings.TrimSpace(string(kind)) != "RoCE v2" {
		return false
	}
	gid, err := PortGID(root, c.options.Device, c.options.Port, index)
	return err == nil && gid != [16]byte{}
}

func (c *DCCollector) enabled() (bool, error) {
	var config dcDcConfig
	if err := c.objs.DcSettings.Lookup(uint32(0), &config); err != nil {
		return false, err
	}
	return config.Pid == uint32(c.options.PID), nil
}

// prune also checks live kernel registration, so a queued old batch or a lost
// retirement event cannot resurrect a reused QP. No retirement event is needed.
func (c *DCCollector) prune(now time.Time) error {
	enabled, err := c.enabled()
	if err != nil {
		return err
	}
	if !enabled {
		c.table.reset()
		return nil
	}
	var epoch, loss uint64
	if err := c.objs.DcEpoch.Lookup(uint32(0), &epoch); err != nil {
		return err
	}
	for _, index := range []uint32{3, 4, 5} {
		var n uint64
		if err := c.objs.DcStats.Lookup(index, &n); err != nil {
			return err
		}
		loss += n
	}
	if loss != c.lastLoss {
		c.table.reset()
		c.lastLoss = loss
	}
	live := make(map[uint64]uint32)
	iter := c.objs.DcQps.Iterate()
	var qp uint64
	var id dcDcIdentity
	for iter.Next(&qp, &id) {
		if id.Token > epoch && id.State == 3 {
			live[id.Token] = id.Port
		}
	}
	if err := iter.Err(); err != nil {
		c.table.reset()
		return err
	}
	for _, flow := range c.table.snapshot(now) {
		if port, ok := live[flow.DCI]; !ok || port != uint32(flow.Port) {
			c.table.forgetDCI(flow.DCI)
		}
	}
	return nil
}

func (c *DCCollector) Stats() (DCStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var values [11]uint64
	for i := range values {
		if err := c.objs.DcStats.Lookup(uint32(i), &values[i]); err != nil {
			return DCStats{}, err
		}
	}
	if err := c.prune(time.Now()); err != nil {
		return DCStats{}, err
	}
	return DCStats{SubmittedBatches: values[0], FailedSubmissions: values[1], UnsupportedBatches: values[2],
		ReadErrors: values[3], MapErrors: values[4], RingLost: values[5], Retired: values[6], Created: values[7], UCXSubmissions: values[8], DevXSubmissions: values[9], DevXCreated: values[10],
		AcceptedSends: c.accepted.Load(), RejectedRecords: c.rejected.Load(), ActiveFlows: len(c.table.snapshot(time.Now()))}, nil
}

func (c *DCCollector) Close() {
	c.closeOnce.Do(func() {
		if c.reader != nil {
			c.reader.Close()
		}
		for i := len(c.links) - 1; i >= 0; i-- {
			c.links[i].Close()
		}
		c.objs.Close()
		if c.library != nil {
			c.library.Close()
		}
		if c.ucxLibrary != nil {
			c.ucxLibrary.Close()
		}
		if c.pidfd >= 0 {
			unix.Close(c.pidfd)
		}
		if c.table != nil {
			c.table.reset()
		}
	})
}
