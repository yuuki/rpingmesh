// Package agent implements the R-Pingmesh agent, including the Prober
// that sends probe packets to targets and processes ACK responses to
// compute 6-timestamp RTT measurements.
package agent

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/probe"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
)

// Default constants for the Prober.
const (
	// probeSendTimeoutMS is the timeout in milliseconds for sending a single
	// probe packet and waiting for its send completion.
	probeSendTimeoutMS = 1000

	// resultChanSize is the buffer size for the probe results channel.
	resultChanSize = 1024

	// stalePendingTimeout is the duration after which a pending probe entry
	// is considered stale and eligible for cleanup.
	stalePendingTimeout = 30 * time.Second

	// stalePendingCleanupInterval determines how often the probe loop
	// checks for stale pending probes (every N ticks of the probe loop).
	stalePendingCleanupInterval = 100
)

// pendingProbe holds the in-flight state for a single probe awaiting ACKs.
type pendingProbe struct {
	target    *controller_agent.PingTarget
	t1        uint64 // Prober send time (CLOCK_MONOTONIC via Zig)
	t2        uint64 // NIC HW timestamp of probe send completion (or SW fallback)
	t3        uint64 // Responder recv timestamp (filled on first ACK)
	t4        uint64 // Responder first ACK send completion (filled on second ACK)
	t5        uint64 // Prober first ACK recv timestamp (filled on first ACK)
	createdAt time.Time
}

// Prober sends probe packets to targets on a configurable interval,
// processes first and second ACK responses via its event ring, and
// produces ProbeResult values on a buffered channel.
type Prober struct {
	queue         *rdmabridge.Queue
	ring          *rdmabridge.EventRing
	device        *rdmabridge.Device
	targets       []*controller_agent.PingTarget
	targetsMu     sync.RWMutex
	pending       map[uint64]*pendingProbe // sequence_num -> pending probe info
	pendingMu     sync.Mutex
	seqCounter    atomic.Uint64
	agentEpoch    uint32 // Random epoch prefix for sequence number collision prevention
	resultChan    chan *probe.ProbeResult
	running       atomic.Bool
	wg            sync.WaitGroup
	probeInterval time.Duration
	probeTimeout  uint32 // ms
	logger        zerolog.Logger
}

// NewProber creates a new Prober with a sender-type RDMA queue bound to the
// given device and event ring. The probeIntervalMS parameter controls how
// frequently probe packets are sent to all targets.
//
// A random agentEpoch is generated so that sequence numbers from different
// agent lifetimes do not collide: the high 32 bits of each sequence number
// contain the epoch, and the low 32 bits are a monotonic counter.
func NewProber(device *rdmabridge.Device, ring *rdmabridge.EventRing, probeIntervalMS uint32) (*Prober, error) {
	queue, err := device.CreateQueue(rdmabridge.QueueTypeSender, ring)
	if err != nil {
		return nil, err
	}

	p := &Prober{
		queue:         queue,
		ring:          ring,
		device:        device,
		pending:       make(map[uint64]*pendingProbe),
		agentEpoch:    rand.Uint32(),
		resultChan:    make(chan *probe.ProbeResult, resultChanSize),
		probeInterval: time.Duration(probeIntervalMS) * time.Millisecond,
		probeTimeout:  probeSendTimeoutMS,
		logger:        log.With().Str("component", "prober").Logger(),
	}

	p.logger.Info().
		Uint32("qpn", queue.Info.QPN).
		Uint32("agent_epoch", p.agentEpoch).
		Uint32("probe_interval_ms", probeIntervalMS).
		Msg("Prober created")

	return p, nil
}

// Start begins the prober's two background goroutines:
//   - probeLoop: sends probes to all targets on the configured interval
//   - ackProcessLoop: polls the event ring for ACK completions
//
// Both goroutines run until Stop() is called or the context is cancelled.
func (p *Prober) Start(ctx context.Context) error {
	if !p.running.CompareAndSwap(false, true) {
		return nil // already running
	}

	p.wg.Add(2)
	go p.probeLoop(ctx)
	go p.ackProcessLoop(ctx)

	p.logger.Info().
		Uint32("qpn", p.queue.Info.QPN).
		Msg("Prober started")
	return nil
}

// Stop signals both background goroutines to exit and waits for them
// to finish. It is safe to call Stop multiple times.
func (p *Prober) Stop() {
	if !p.running.CompareAndSwap(true, false) {
		return // not running
	}
	p.wg.Wait()
	p.logger.Info().Msg("Prober stopped")
}

// UpdateTargets replaces the current list of probe targets. This is called
// when the agent receives an updated pinglist from the controller.
func (p *Prober) UpdateTargets(targets []*controller_agent.PingTarget) {
	p.targetsMu.Lock()
	defer p.targetsMu.Unlock()
	p.targets = targets
	p.logger.Info().
		Int("count", len(targets)).
		Msg("Probe targets updated")
}

// Results returns a read-only channel that delivers completed probe results
// for consumption by the telemetry/metrics layer.
func (p *Prober) Results() <-chan *probe.ProbeResult {
	return p.resultChan
}

// probeLoop runs on a ticker at probeInterval, sending one probe packet
// to each target on every tick. It also periodically cleans up stale
// pending probes that never received their ACK responses.
func (p *Prober) probeLoop(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.probeInterval)
	defer ticker.Stop()

	var tickCount uint64

	p.logger.Info().
		Dur("interval", p.probeInterval).
		Msg("Probe loop started")

	for p.running.Load() {
		select {
		case <-ctx.Done():
			p.running.Store(false)
			return
		case <-ticker.C:
			tickCount++
			p.sendProbes()

			// Periodically clean up stale pending probes to prevent memory leaks.
			if tickCount%stalePendingCleanupInterval == 0 {
				p.cleanupStalePending()
			}
		}
	}
}

// sendProbes reads the current target list and sends one probe to each target.
func (p *Prober) sendProbes() {
	p.targetsMu.RLock()
	targets := make([]*controller_agent.PingTarget, len(p.targets))
	copy(targets, p.targets)
	p.targetsMu.RUnlock()

	if len(targets) == 0 {
		return
	}

	for _, target := range targets {
		if target == nil {
			continue
		}

		// Generate a globally-unique sequence number:
		// high 32 bits = random agent epoch, low 32 bits = monotonic counter.
		counter := uint64(p.seqCounter.Add(1))
		seqNum := (uint64(p.agentEpoch) << 32) | (counter & 0xFFFFFFFF)

		// Parse the target GID string into a [16]byte for the RDMA layer.
		targetGID, err := probe.ParseGID(target.GetTargetGid())
		if err != nil {
			p.logger.Error().Err(err).
				Str("target_gid", target.GetTargetGid()).
				Uint64("seq", seqNum).
				Msg("Failed to parse target GID, skipping target")
			continue
		}

		// Send the probe packet. SendProbe is synchronous: it posts the
		// packet and waits for the send completion within the timeout.
		result := p.queue.SendProbe(
			targetGID,
			target.GetTargetQpn(),
			seqNum,
			target.GetFlowLabel(),
			p.probeTimeout,
		)

		if result.Error != nil {
			p.logger.Error().Err(result.Error).
				Str("target_gid", target.GetTargetGid()).
				Uint32("target_qpn", target.GetTargetQpn()).
				Uint64("seq", seqNum).
				Msg("Failed to send probe packet")
			continue
		}

		// Record the pending probe with T1 and T2 from the send result.
		p.pendingMu.Lock()
		p.pending[seqNum] = &pendingProbe{
			target:    target,
			t1:        result.T1NS,
			t2:        result.T2NS,
			createdAt: time.Now(),
		}
		p.pendingMu.Unlock()

		p.logger.Debug().
			Str("target_gid", target.GetTargetGid()).
			Uint32("target_qpn", target.GetTargetQpn()).
			Uint64("seq", seqNum).
			Uint64("t1_ns", result.T1NS).
			Uint64("t2_ns", result.T2NS).
			Msg("Probe sent, awaiting ACKs")
	}
}

// ackProcessLoop continuously polls the event ring for ACK completion
// events and matches them against pending probes. First ACKs provide T3
// and T5; second ACKs provide T3, T4, and T6, completing the 6-timestamp
// measurement and emitting a ProbeResult.
func (p *Prober) ackProcessLoop(ctx context.Context) {
	defer p.wg.Done()

	const (
		maxBatch  = 32
		idleSleep = 100 * time.Microsecond
	)

	p.logger.Info().Msg("ACK process loop started")

	for p.running.Load() {
		select {
		case <-ctx.Done():
			p.running.Store(false)
			return
		default:
		}

		events := p.ring.Poll(maxBatch)
		if len(events) == 0 {
			time.Sleep(idleSleep)
			continue
		}

		for i := range events {
			p.handleACKEvent(&events[i])
		}
	}
}

// handleACKEvent processes a single completion event from the ring buffer.
// Only recv events that are ACKs are relevant to the prober; all other
// event types (send completions, non-ACK receives) are ignored.
func (p *Prober) handleACKEvent(event *rdmabridge.CompletionEvent) {
	// Only process recv completions that are ACKs.
	// Skip send completions and non-ACK receives.
	if event.IsSend || !event.IsAck {
		return
	}

	// Check for completion errors from the hardware.
	if event.Status != 0 {
		p.logger.Warn().
			Int32("status", event.Status).
			Uint64("seq", event.SequenceNum).
			Msg("ACK recv completion with non-zero status, skipping")
		return
	}

	seqNum := event.SequenceNum

	switch event.AckType {
	case rdmabridge.AckTypeFirst:
		p.handleFirstACK(seqNum, event)

	case rdmabridge.AckTypeSecond:
		p.handleSecondACK(seqNum, event)

	default:
		p.logger.Warn().
			Uint8("ack_type", event.AckType).
			Uint64("seq", seqNum).
			Msg("Received ACK with unknown type")
	}
}

// handleFirstACK processes a first ACK event. It extracts T3 (responder
// recv timestamp) and records T5 (prober recv timestamp from the NIC HW
// or SW timestamp on this completion).
func (p *Prober) handleFirstACK(seqNum uint64, event *rdmabridge.CompletionEvent) {
	p.pendingMu.Lock()
	pp, ok := p.pending[seqNum]
	if !ok {
		p.pendingMu.Unlock()
		p.logger.Warn().
			Uint64("seq", seqNum).
			Msg("Received first ACK for unknown sequence number")
		return
	}

	// T3 is the responder's recv timestamp, carried in the ACK event.
	pp.t3 = event.T3

	// T5 is the prober's recv timestamp for the first ACK, taken from
	// the NIC completion event (HW or SW timestamp).
	pp.t5 = event.TimestampNS

	p.pendingMu.Unlock()

	p.logger.Debug().
		Uint64("seq", seqNum).
		Uint64("t3_ns", pp.t3).
		Uint64("t5_ns", pp.t5).
		Msg("First ACK received")
}

// handleSecondACK processes a second ACK event, which carries T3 and T4
// (responder-side timestamps). T6 is captured as the current Go monotonic
// time since the ring buffer completion event does not provide a Go-side
// timestamp for the second ACK arrival. With all 6 timestamps available,
// it builds a ProbeResult, calculates RTT, and sends the result to the
// results channel.
func (p *Prober) handleSecondACK(seqNum uint64, event *rdmabridge.CompletionEvent) {
	// Capture T6 immediately upon processing the second ACK.
	t6 := uint64(time.Now().UnixNano())

	p.pendingMu.Lock()
	pp, ok := p.pending[seqNum]
	if !ok {
		p.pendingMu.Unlock()
		p.logger.Warn().
			Uint64("seq", seqNum).
			Msg("Received second ACK for unknown sequence number")
		return
	}

	// The second ACK carries T3 and T4 in the event payload. If the first
	// ACK has already filled T3, prefer the first ACK's value (it arrived
	// earlier and is more accurate). Otherwise, use the second ACK's T3.
	t3 := pp.t3
	if t3 == 0 {
		t3 = event.T3
	}
	t4 := event.T4

	// Build the target GID from the pending probe's target information.
	var targetGID [16]byte
	parsedGID, err := probe.ParseGID(pp.target.GetTargetGid())
	if err == nil {
		targetGID = parsedGID
	}

	// Construct the complete ProbeResult with all 6 timestamps.
	result := &probe.ProbeResult{
		SequenceNum:    seqNum,
		TargetGID:      targetGID,
		TargetQPN:      pp.target.GetTargetQpn(),
		FlowLabel:      pp.target.GetFlowLabel(),
		T1:             pp.t1,
		T2:             pp.t2,
		T3:             t3,
		T4:             t4,
		T5:             pp.t5,
		T6:             t6,
		Success:        true,
		TargetIP:       pp.target.GetTargetIp(),
		TargetHostname: pp.target.GetTargetHostname(),
		TargetTorID:    pp.target.GetTargetTorId(),
	}

	// Remove from pending map now that the probe is complete.
	delete(p.pending, seqNum)
	p.pendingMu.Unlock()

	// Calculate RTT metrics from the 6 timestamps.
	rtt := probe.CalculateRTT(result)

	p.logger.Debug().
		Uint64("seq", seqNum).
		Str("target_gid", pp.target.GetTargetGid()).
		Uint64("t1", result.T1).
		Uint64("t2", result.T2).
		Uint64("t3", result.T3).
		Uint64("t4", result.T4).
		Uint64("t5", result.T5).
		Uint64("t6", result.T6).
		Bool("rtt_valid", rtt.Valid).
		Int64("network_rtt_ns", rtt.NetworkRTT).
		Int64("responder_delay_ns", rtt.ResponderDelay).
		Int64("prober_delay_ns", rtt.ProberDelay).
		Msg("Probe completed with all 6 timestamps")

	// Send the result to the results channel. Use a non-blocking send
	// to avoid blocking the ACK processing loop if the consumer is slow.
	select {
	case p.resultChan <- result:
	default:
		p.logger.Warn().
			Uint64("seq", seqNum).
			Msg("Result channel full, dropping probe result")
	}
}

// cleanupStalePending removes entries from the pending map that are older
// than stalePendingTimeout. This prevents memory leaks from probes whose
// ACK responses were lost or never arrived.
func (p *Prober) cleanupStalePending() {
	now := time.Now()
	var cleaned int

	p.pendingMu.Lock()
	for seqNum, pp := range p.pending {
		if now.Sub(pp.createdAt) > stalePendingTimeout {
			delete(p.pending, seqNum)
			cleaned++
		}
	}
	p.pendingMu.Unlock()

	if cleaned > 0 {
		p.logger.Info().
			Int("cleaned", cleaned).
			Msg("Cleaned up stale pending probes")
	}
}

// GetQueueInfo returns the queue metadata (QPN, timestamp mode) for this
// prober's sender queue. This can be used for logging and diagnostics.
func (p *Prober) GetQueueInfo() rdmabridge.QueueInfo {
	return p.queue.Info
}

// Destroy stops the prober if it is running and destroys the underlying
// RDMA queue, freeing all associated resources (QP, CQ, MRs).
func (p *Prober) Destroy() {
	p.Stop()
	if p.queue != nil {
		p.queue.Destroy()
		p.queue = nil
	}
	p.logger.Info().Msg("Prober destroyed")
}
