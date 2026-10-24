//go:build linux

package servicetrace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// vmlinuxBTF is the kernel's BTF, required for the CO-RE relocations.
const vmlinuxBTF = "/sys/kernel/btf/vmlinux"

// Indexes into the BPF stats map; keep in sync with the STAT_* enum.
const (
	statRingbufDropped uint32 = 0
	statParseErrors    uint32 = 1
)

// Tracer owns the loaded eBPF programs, their kprobe links and the ring
// buffer reader. Create one with Open, run it with Start, release it with
// Close.
type Tracer struct {
	objs   uverbsObjects
	links  []link.Link
	reader *ringbuf.Reader
	logger zerolog.Logger

	events       atomic.Uint64
	decodeErrors atomic.Uint64

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// Open loads the eBPF programs and attaches them to the uverbs entry points.
// It returns one of the package's Err* values when the host cannot run the
// tracer, so the caller can log why and continue without it.
func Open() (*Tracer, error) {
	if _, err := os.Stat(vmlinuxBTF); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoBTF, err)
	}
	// The feature probe creates a map, so without CAP_BPF it fails with
	// EPERM before saying anything about the kernel.
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		switch {
		case isPermissionError(err):
			return nil, fmt.Errorf("%w: %v", ErrPermission, err)
		case errors.Is(err, ebpf.ErrNotSupported):
			return nil, fmt.Errorf("service tracing: BPF ring buffers are not supported (Linux 5.8+ required): %w", err)
		}
		return nil, fmt.Errorf("service tracing: probe BPF ring buffer support: %w", err)
	}
	// Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK; the systemd
	// unit already lifts the limit, so a failure here is not fatal.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Debug().Err(err).Msg("Could not lift RLIMIT_MEMLOCK for eBPF maps")
	}

	t := &Tracer{logger: log.With().Str("component", "service_tracer").Logger()}
	if err := loadUverbsObjects(&t.objs, nil); err != nil {
		if isPermissionError(err) {
			return nil, fmt.Errorf("%w: %v", ErrPermission, err)
		}
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// The verifier log is long; keep it out of the error chain.
			t.logger.Debug().Str("verifier_log", ve.Error()).Msg("eBPF verifier rejected the tracer")
			return nil, fmt.Errorf("service tracing: the kernel's eBPF verifier rejected the tracer: %w", ve)
		}
		return nil, fmt.Errorf("service tracing: load eBPF objects: %w", err)
	}

	if err := t.attach(); err != nil {
		t.Close()
		return nil, err
	}

	reader, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("service tracing: open event ring buffer: %w", err)
	}
	t.reader = reader
	return t, nil
}

// isPermissionError reports whether err is the kernel refusing the bpf(2) or
// perf_event_open(2) call for lack of capabilities (EPERM, or EACCES on
// kernels in lockdown mode).
func isPermissionError(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrPermission)
}

// attach places the kprobes. A missing symbol means ib_uverbs is not loaded.
func (t *Tracer) attach() error {
	for _, p := range []struct {
		symbol string
		prog   *ebpf.Program
		ret    bool
	}{
		{"ib_uverbs_ioctl", t.objs.UverbsIoctlEnter, false},
		{"ib_uverbs_ioctl", t.objs.UverbsIoctlExit, true},
		{"ib_uverbs_write", t.objs.UverbsWriteEnter, false},
		{"ib_uverbs_write", t.objs.UverbsWriteExit, true},
		{"ib_uverbs_close", t.objs.UverbsCloseEnter, false},
	} {
		var (
			l   link.Link
			err error
		)
		if p.ret {
			l, err = link.Kretprobe(p.symbol, p.prog, nil)
		} else {
			l, err = link.Kprobe(p.symbol, p.prog, nil)
		}
		if err != nil {
			switch {
			case errors.Is(err, os.ErrNotExist):
				return fmt.Errorf("%w: %s: %v", ErrNoUverbs, p.symbol, err)
			case isPermissionError(err):
				return fmt.Errorf("%w: attach %s: %v", ErrPermission, p.symbol, err)
			}
			return fmt.Errorf("service tracing: attach kprobe to %s: %w", p.symbol, err)
		}
		t.links = append(t.links, l)
	}
	return nil
}

// Start reads events until ctx is cancelled or Close is called, calling
// handle for each one on the reader goroutine. handle must not block for
// long: the ring buffer drops events once it is full.
func (t *Tracer) Start(ctx context.Context, handle func(Event)) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.run(ctx, handle)
	}()
}

func (t *Tracer) run(ctx context.Context, handle func(Event)) {
	// Read blocks until Close; let a cancelled context close the reader too.
	stop := context.AfterFunc(ctx, func() { t.reader.Close() })
	defer stop()

	var rec ringbuf.Record
	for {
		if err := t.reader.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			t.logger.Warn().Err(err).Msg("Reading the service trace ring buffer failed")
			continue
		}
		ev, err := DecodeEvent(rec.RawSample)
		if err != nil {
			t.decodeErrors.Add(1)
			continue
		}
		t.events.Add(1)
		handle(ev)
	}
}

// Stats returns the tracer's counters, including those kept by the BPF
// program.
func (t *Tracer) Stats() Stats {
	s := Stats{
		Events:       t.events.Load(),
		DecodeErrors: t.decodeErrors.Load(),
	}
	if t.objs.Stats != nil {
		s.RingBufferDropped = t.readStat(statRingbufDropped)
		s.ParseErrors = t.readStat(statParseErrors)
	}
	return s
}

func (t *Tracer) readStat(idx uint32) uint64 {
	var v uint64
	if err := t.objs.Stats.Lookup(idx, &v); err != nil {
		return 0
	}
	return v
}

// Close detaches the programs, closes the ring buffer and waits for the
// reader goroutine. It is idempotent.
func (t *Tracer) Close() error {
	var err error
	t.closeOnce.Do(func() {
		if t.reader != nil {
			err = t.reader.Close()
		}
		t.wg.Wait()
		for _, l := range t.links {
			if e := l.Close(); e != nil && err == nil {
				err = e
			}
		}
		t.links = nil
		if e := t.objs.Close(); e != nil && err == nil {
			err = e
		}
	})
	return err
}
