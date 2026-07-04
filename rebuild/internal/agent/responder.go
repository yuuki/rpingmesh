// Package agent implements the R-Pingmesh agent, including the Responder
// that listens for incoming probe packets and sends back ACK replies.
package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/rdmabridge"
)

// ackSendTimeoutMS is the timeout in milliseconds for sending ACK packets
// back to the prober.
const ackSendTimeoutMS = 1000

// Responder listens for incoming probe packets on a single RDMA UD queue
// and sends back first and second ACK packets to complete the R-Pingmesh
// 6-timestamp protocol.
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
		Uint32("qpn", r.queue.Info.QPN).
		Msg("Responder started")
	return nil
}

// Stop signals the responder to stop processing and waits for the
// background goroutine to exit. Closing stopCh wakes the loop immediately
// instead of waiting out an idle sleep or a long in-flight ACK batch.
func (r *Responder) Stop() {
	if !r.running.CompareAndSwap(true, false) {
		return // not running
	}
	r.stopMu.Lock()
	close(r.stopCh)
	r.stopMu.Unlock()
	r.wg.Wait()
	r.logger.Info().Msg("Responder stopped")
}

// processLoop is the main event processing loop. It polls the event ring
// for recv completion events (incoming probes), then sends first and second
// ACK packets back to the prober. Send completions and ACK recv events are
// ignored since the responder only needs to react to incoming probes.
func (r *Responder) processLoop(ctx context.Context) {
	defer r.wg.Done()

	const (
		maxBatch  = 32
		idleSleep = 100 * time.Microsecond
	)

	// idleTimer is reused on each empty-poll iteration to avoid allocating a
	// new timer on every spin.
	idleTimer := time.NewTimer(idleSleep)
	defer idleTimer.Stop()

	for r.running.Load() {
		// Check for shutdown or context cancellation on every iteration.
		select {
		case <-ctx.Done():
			r.running.Store(false)
			return
		case <-r.stopCh:
			return
		default:
		}

		events := r.ring.Poll(maxBatch)
		if len(events) == 0 {
			// No events yet; wait briefly, but wake immediately on shutdown so
			// Stop() is not delayed by the idle sleep.
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idleSleep)
			select {
			case <-ctx.Done():
				r.running.Store(false)
				return
			case <-r.stopCh:
				return
			case <-idleTimer.C:
			}
			continue
		}

		for i := range events {
			// Each handleEvent may block for up to two ACK sends
			// (ackSendTimeoutMS each). Across a full batch that is many
			// seconds, so check for shutdown before every event to keep Stop()
			// responsive.
			select {
			case <-ctx.Done():
				r.running.Store(false)
				return
			case <-r.stopCh:
				return
			default:
			}
			r.handleEvent(&events[i])
		}
	}
}

// handleEvent processes a single completion event. Only recv events that
// are NOT ACKs (i.e., incoming probe packets) are processed. All other
// event types (send completions, ACK receives) are silently skipped.
func (r *Responder) handleEvent(event *rdmabridge.CompletionEvent) {
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

	sourceGID := event.SourceGID
	sourceQPN := event.SourceQPN
	flowLabel := event.FlowLabel
	recvTimestamp := event.TimestampNS

	// Reconstruct the received probe packet payload for the ACK functions.
	// The Zig layer needs the original packet bytes to build the ACK.
	recvPayload := buildRecvPacketPayload(event)

	r.logger.Debug().
		Uint32("source_qpn", sourceQPN).
		Uint64("seq", event.SequenceNum).
		Uint32("flow_label", flowLabel).
		Uint64("recv_ts_ns", recvTimestamp).
		Msg("Received probe, sending ACKs")

	// Send first ACK: echoes T1 and records T3 (recv time). Returns T4
	// (the send completion timestamp of this ACK).
	t4, err := r.queue.SendFirstAck(
		sourceGID,
		sourceQPN,
		flowLabel,
		recvPayload,
		recvTimestamp,
		ackSendTimeoutMS,
	)
	if err != nil {
		r.logger.Error().Err(err).
			Uint32("source_qpn", sourceQPN).
			Uint64("seq", event.SequenceNum).
			Msg("Failed to send first ACK")
		return
	}

	// Send second ACK: carries T3 and T4 so the prober can compute the
	// responder processing delay.
	err = r.queue.SendSecondAck(
		sourceGID,
		sourceQPN,
		flowLabel,
		recvPayload,
		recvTimestamp,
		t4,
		ackSendTimeoutMS,
	)
	if err != nil {
		r.logger.Error().Err(err).
			Uint32("source_qpn", sourceQPN).
			Uint64("seq", event.SequenceNum).
			Msg("Failed to send second ACK")
		return
	}

	r.logger.Debug().
		Uint32("source_qpn", sourceQPN).
		Uint64("seq", event.SequenceNum).
		Uint64("t3_ns", recvTimestamp).
		Uint64("t4_ns", t4).
		Msg("ACK pair sent successfully")
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
// SendFirstAck and SendSecondAck functions expect the original received
// packet bytes to extract the sequence number and original timestamps.
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
