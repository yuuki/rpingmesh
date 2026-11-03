package agent

import (
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// ackDropLogInterval is the minimum gap between two dropped-ACK summaries.
const ackDropLogInterval = 10 * time.Second

// ackDropLog counts the ACKs the prober discards and reports them as one
// rate-limited Warn summary. Both kinds can be produced at line rate by
// anyone who can reach the prober's QP, so logging each one would let
// spoofed traffic flood the log; summarising keeps them visible without that.
// The zero value is ready to use.
type ackDropLog struct {
	mu   sync.Mutex
	now  func() time.Time // time.Now when nil; injectable in tests
	last time.Time
	// unknown counts ACKs whose sequence number matches no pending probe
	// (late ACKs of timed-out probes, or forged ones).
	unknown uint64
	// foreign counts ACKs that matched a pending probe but came from a GID or
	// QPN other than the probed responder's.
	foreign uint64
}

// record counts one dropped ACK and, at most once per ackDropLogInterval,
// logs the counts accumulated since the previous summary.
func (d *ackDropLog) record(logger zerolog.Logger, foreign bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if foreign {
		d.foreign++
	} else {
		d.unknown++
	}
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	t := now()
	if !d.last.IsZero() && t.Sub(d.last) < ackDropLogInterval {
		return
	}
	d.last = t
	logger.Warn().
		Uint64("unknown_seq", d.unknown).
		Uint64("unexpected_source", d.foreign).
		Msg("Dropped probe ACKs: unknown_seq are late ACKs of timed-out probes or forged ones; " +
			"unexpected_source matched a pending probe but not the probed responder's GID/QPN " +
			"(forged, or the target's GID table changed since it registered; Debug logs name the GIDs)")
	d.unknown, d.foreign = 0, 0
}
