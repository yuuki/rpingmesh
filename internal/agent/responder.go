// Package agent implements the R-Pingmesh agent, including the Responder
// that listens for incoming probe packets and sends back ACK replies.
package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/rdmabridge"
)

const (
	// ackSlotWaitTimeout bounds how long handleEvent waits for a free send
	// slot when every slot holds an in-flight ACK pair. Slots return with
	// send completions, so running out means the NIC has not completed
	// NUM_SEND_SLOTS (32) ACKs; a probe answered later than this would be
	// rejected by the prober anyway (ResponderDelay above
	// probe.MaxSaneDelay).
	ackSlotWaitTimeout = time.Second

	// ackSlotRetryInterval is the pause between attempts to get a send slot.
	ackSlotRetryInterval = 50 * time.Microsecond

	// asyncAckFailureLogInterval is the minimum interval between the Warn
	// logs that report asynchronous ACK failures (see logAsyncAckFailures).
	asyncAckFailureLogInterval = 10 * time.Second
)

// errResponderStopping is returned by sendAckPair when Stop() or context
// cancellation interrupts its wait for a send slot. It is not logged.
var errResponderStopping = errors.New("responder stopping")

// Responder listens for incoming probe packets on a single RDMA UD queue
// and sends back first and second ACK packets to complete the R-Pingmesh
// 6-timestamp protocol.
//
// The responder never waits for a send completion: each probe is answered
// with Queue.SendAckPair, which posts the first ACK and leaves the second to
// the queue's CQ poller (it needs the first ACK's completion timestamp, T4).
// The processing goroutine therefore drains the event ring at the inbound
// probe rate even when completions are slow, so a late completion delays
// only its own probe instead of every probe queued behind it.
type Responder struct {
	queue   *rdmabridge.Queue
	ring    *rdmabridge.EventRing
	device  *rdmabridge.Device
	running atomic.Bool
	stopMu  sync.Mutex    // guards stopCh (re)creation across Start/Stop
	stopCh  chan struct{} // closed by Stop() to wake the process loop immediately
	wg      sync.WaitGroup

	// queueMu guards access to the queue pointer so that GetQueueInfo cannot
	// race with Destroy() setting queue to nil.
	queueMu sync.RWMutex

	logger zerolog.Logger

	// reportedAckFailures and lastAckFailureCheck track the Warn log of
	// asynchronous ACK failures. Owned by the processLoop goroutine.
	reportedAckFailures uint64
	lastAckFailureCheck time.Time
}

// NewResponder creates a new Responder with a responder-type RDMA queue
// bound to the given device and event ring. The queue is created immediately
// so that its QPN can be registered with the controller before Start() is
// called.
func NewResponder(device *rdmabridge.Device, ring *rdmabridge.EventRing) (*Responder, error) {
	queue, err := device.CreateQueue(rdmabridge.QueueTypeResponder, ring)
	if err != nil {
		return nil, err
	}

	r := &Responder{
		queue:  queue,
		ring:   ring,
		device: device,
		logger: log.With().Str("component", "responder").Logger(),
	}
	return r, nil
}

// Start begins the responder event processing loop. The loop runs in a
// background goroutine until Stop() is called or the context is cancelled.
func (r *Responder) Start(ctx context.Context) error {
	if !r.running.CompareAndSwap(false, true) {
		return nil // already running
	}

	// Recreate stopCh so the responder can be restarted after a previous
	// Stop() closed it. Stop() has already waited for the old goroutine to
	// exit (running is false here), so nothing references the old channel.
	r.stopMu.Lock()
	r.stopCh = make(chan struct{})
	r.stopMu.Unlock()

	r.wg.Add(1)
	go r.processLoop(ctx)

	r.logger.Info().
		Str("device", r.device.Info.DeviceName).
		Uint32("qpn", r.queue.Info.QPN).
		Bool("cq_events", r.queue.Info.UsesCQEvents).
		Bool("hw_timestamps", !r.queue.Info.UsesSWTimestamps).
		Msg("Responder started")
	return nil
}

// Stop signals the responder to stop processing and waits for the
// background goroutine to exit. Closing stopCh wakes the loop immediately
// instead of waiting out an idle sleep or a long in-flight ACK batch.
func (r *Responder) Stop() {
	// Always Wait, even when running is already false. ctx.Done in
	// processLoop must not skip the join: Destroy tears down the queue
	// immediately after Stop returns. Only the CAS winner closes stopCh.
	signaled := r.running.CompareAndSwap(true, false)
	if signaled {
		r.stopMu.Lock()
		close(r.stopCh)
		r.stopMu.Unlock()
	}
	r.wg.Wait()
	if signaled {
		r.logger.Info().Msg("Responder stopped")
	}
}

// processLoop is the main event processing loop. It drains the event ring
// for recv completion events (incoming probes) and answers each with an ACK
// pair (see handleEvent). Send completions and ACK recv events are
// ignored since the responder only needs to react to incoming probes. While
// the ring is empty the loop sleeps until the CQ poller signals new events
// (see newRingIdleWait).
func (r *Responder) processLoop(ctx context.Context) {
	defer r.wg.Done()

	const maxBatch = 32

	wait, release := newRingIdleWait(ctx, r.stopCh, r.ring, r.queue.Info.UsesCQEvents, r.logger)
	defer release()

	defer r.logAsyncAckFailures(true)

	for r.running.Load() {
		r.logAsyncAckFailures(false)

		// Check for shutdown or context cancellation on every iteration.
		select {
		case <-ctx.Done():
			// Do not Store(false): Stop() joins remaining work after CAS.
			return
		case <-r.stopCh:
			return
		default:
		}

		events := r.ring.Poll(maxBatch)
		if len(events) == 0 {
			// wait returns false as soon as Stop() or ctx cancellation
			// happens, so Stop() is not delayed by an idle ring.
			if !wait() {
				return
			}
			continue
		}

		for i := range events {
			// handleEvent normally returns as soon as the first ACK is
			// posted, but it can wait up to ackSlotWaitTimeout for a send
			// slot, so check for shutdown before every event to keep Stop()
			// responsive.
			select {
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			default:
			}
			r.handleEvent(ctx, &events[i])
		}
	}
}

// handleEvent processes a single completion event. Only recv events that
// are NOT ACKs (i.e., incoming probe packets) are processed. All other
// event types (send completions, ACK receives) are silently skipped.
func (r *Responder) handleEvent(ctx context.Context, event *rdmabridge.CompletionEvent) {
	// Only process recv completions that are incoming probes.
	// Skip send completions and ACK receives.
	if event.IsSend || event.IsAck {
		return
	}

	// Check for completion errors from the hardware.
	if event.Status != 0 {
		r.logger.Warn().
			Int32("status", event.Status).
			Msg("Recv completion with non-zero status, skipping")
		return
	}

	sourceQPN := event.SourceQPN
	recvTimestamp := event.TimestampNS

	// Reconstruct the received probe packet payload for the ACK functions.
	// The Zig layer needs the original packet bytes to build the ACK.
	recvPayload := buildRecvPacketPayload(event)

	r.logger.Debug().
		Uint32("source_qpn", sourceQPN).
		Uint64("seq", event.SequenceNum).
		Uint32("flow_label", event.FlowLabel).
		Uint64("recv_ts_ns", recvTimestamp).
		Msg("Received probe, sending ACKs")

	// Post the first ACK (echoes T1, carries T3 = recv time). The CQ poller
	// sends the second ACK, carrying T3 and T4 (the first ACK's send
	// completion time), once that completion arrives.
	if err := r.sendAckPair(ctx, event, recvPayload); err != nil {
		if errors.Is(err, errResponderStopping) {
			return
		}
		r.logger.Error().Err(err).
			Uint32("source_qpn", sourceQPN).
			Uint64("seq", event.SequenceNum).
			Msg("Failed to send ACK pair")
		return
	}

	r.logger.Debug().
		Uint32("source_qpn", sourceQPN).
		Uint64("seq", event.SequenceNum).
		Uint64("t3_ns", recvTimestamp).
		Msg("First ACK posted")
}

// sendAckPair posts the ACK pair for event, waiting up to ackSlotWaitTimeout
// for a free send slot when all of them hold in-flight ACKs. It gives up
// early on Stop() or context cancellation.
func (r *Responder) sendAckPair(ctx context.Context, event *rdmabridge.CompletionEvent, recvPayload []byte) error {
	var deadline time.Time
	for {
		err := r.queue.SendAckPair(event.SourceGID, event.SourceQPN, event.FlowLabel, recvPayload, event.TimestampNS)
		if !errors.Is(err, rdmabridge.ErrNoFreeSendSlot) {
			return err
		}
		now := time.Now()
		if deadline.IsZero() {
			deadline = now.Add(ackSlotWaitTimeout)
		} else if now.After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return errResponderStopping
		case <-r.stopCh:
			return errResponderStopping
		case <-time.After(ackSlotRetryInterval):
		}
	}
}

// logAsyncAckFailures logs a Warn when ACK pairs failed after SendAckPair
// returned (see rdmabridge.Queue.AsyncAckFailures). It checks at most once
// per asyncAckFailureLogInterval unless final is set. It runs when the loop
// wakes for events and when the loop exits, so failures of the last pairs
// before an idle period are reported with the next probe or at Stop. The
// prober sees each
// failure as a timeout; this log tells the operator that the responder
// side, not the network, dropped the ACK.
func (r *Responder) logAsyncAckFailures(final bool) {
	now := time.Now()
	if !final && now.Sub(r.lastAckFailureCheck) < asyncAckFailureLogInterval {
		return
	}
	r.lastAckFailureCheck = now
	total := r.queue.AsyncAckFailures()
	if total == r.reportedAckFailures {
		return
	}
	r.logger.Warn().
		Str("device", r.device.Info.DeviceName).
		Uint64("failed", total-r.reportedAckFailures).
		Uint64("failed_total", total).
		Msg("ACK pairs failed after posting (send completion error or second ACK not posted)")
	r.reportedAckFailures = total
}

// GetQueueInfo returns the queue metadata (QPN, timestamp mode) for
// registration with the controller so that remote probers know where
// to send probes. It is safe to call after Destroy(): a zero-valued QueueInfo
// is returned once the queue has been torn down.
func (r *Responder) GetQueueInfo() rdmabridge.QueueInfo {
	r.queueMu.RLock()
	defer r.queueMu.RUnlock()
	if r.queue == nil {
		return rdmabridge.QueueInfo{}
	}
	return r.queue.Info
}

// Destroy stops the responder if it is running and destroys the underlying
// RDMA queue, freeing all associated resources (QP, CQ, MRs).
func (r *Responder) Destroy() {
	r.Stop()
	r.queueMu.Lock()
	if r.queue != nil {
		r.queue.Destroy()
		r.queue = nil
	}
	r.queueMu.Unlock()
	r.logger.Info().Msg("Responder destroyed")
}

// buildRecvPacketPayload reconstructs the wire-format probe packet (40 bytes,
// big-endian) from a CompletionEvent. This is needed because the Zig-side
// ACK functions (SendAckPair, SendFirstAck, SendSecondAck) expect the
// original received packet bytes to extract the sequence number and
// original timestamps.
//
// Wire layout (40 bytes) — must match zig/src/packet.zig serializeProbePacket:
//
//	[0]      Version
//	[1]      MsgType (0 = probe)
//	[2]      AckType (0 = none)
//	[3]      Flags
//	[4:12]   SequenceNum (big-endian uint64)
//	[12:20]  T1 (big-endian uint64)
//	[20:28]  T3 (big-endian uint64)
//	[28:36]  T4 (big-endian uint64)
//	[36:40]  Reserved (zero padding)
func buildRecvPacketPayload(event *rdmabridge.CompletionEvent) []byte {
	buf := make([]byte, rdmabridge.ProbePacketSize)

	// Reuse the single canonical wire-format serializer so the offset layout
	// lives in exactly one place (rdmabridge.SerializeProbePacket) rather than
	// being re-implemented here.
	pkt := &rdmabridge.ProbePacket{
		Version:     rdmabridge.PacketVersion,
		MsgType:     rdmabridge.MsgTypeProbe,
		AckType:     rdmabridge.AckTypeNone,
		Flags:       event.Flags,
		SequenceNum: event.SequenceNum,
		T1:          event.T1,
		T3:          event.T3,
		T4:          event.T4,
	}
	rdmabridge.SerializeProbePacket(pkt, buf)

	return buf
}
