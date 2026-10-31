//go:build !linux

package servicetrace

import "context"

// Tracer is a placeholder on platforms without eBPF; Open never returns one.
type Tracer struct{}

// Open returns ErrUnsupported.
func Open() (*Tracer, error) {
	return nil, ErrUnsupported
}

// EnableKernelULP is unavailable on non-Linux platforms.
func (t *Tracer) EnableKernelULP() error { return ErrUnsupported }

// Start is never reached: Open returns no Tracer on this platform.
func (t *Tracer) Start(ctx context.Context, handle func(Event)) {}

// Stats returns zero counters.
func (t *Tracer) Stats() Stats { return Stats{} }

// Close is a no-op.
func (t *Tracer) Close() error { return nil }
