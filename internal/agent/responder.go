package agent

import (
	"context"
	"errors"
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

// Responder listens for incoming probes on a responder-type UD queue and
// answers each with the ACK pair of the 6-timestamp protocol.
//
// It never waits for a send completion: Queue.SendAckPair posts the first
// ACK and leaves the second to the queue's CQ poller (which needs the first
// ACK's completion timestamp, T4). The processing goroutine therefore drains
// the event ring at the inbound probe rate even when completions are slow.
type Responder struct {
	lifecycle
	queueHandle
	ring   *rdmabridge.EventRing
	device *rdmabridge.Device
	logger zerolog.Logger

	// reportedAckFailures and lastAckFailureCheck track the Warn log of
	// asynchronous ACK failures. Owned by the processLoop goroutine.
	reportedAckFailures uint64
	lastAckFailureCheck time.Time
}

// NewResponder creates a Responder with a responder-type RDMA queue bound to
// device and ring. The queue is created immediately so its QPN can be
// registered with the controller before Start.
func NewResponder(device *rdmabridge.Device, ring *rdmabridge.EventRing) (*Responder, error) {
	queue, err := device.CreateQueue(rdmabridge.QueueTypeResponder, ring)
	if err != nil {
		return nil, err
	}
	r := &Responder{
		ring:   ring,
		device: device,
		logger: log.With().Str("component", "responder").Logger(),
	}
	r.queue = queue
	return r, nil
}

// Start launches the event processing loop; it runs until Stop is called or
// ctx is cancelled.
func (r *Responder) Start(ctx context.Context) error {
	if !r.lifecycle.start() {
		return nil
	}
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

// Stop signals the loop to exit and waits for it. Safe to call more than once.
func (r *Responder) Stop() {
	if r.lifecycle.stop() {
		r.logger.Info().Msg("Responder stopped")
	}
}

// processLoop answers every incoming probe read from the event ring with an
// ACK pair. Send completions and ACK recv events are ignored.
func (r *Responder) processLoop(ctx context.Context) {
	defer r.wg.Done()
	defer r.logAsyncAckFailures(true)
	runRingLoop(ctx, &r.lifecycle, r.ring, r.queue.Info.UsesCQEvents, r.logger, func(ev *rdmabridge.CompletionEvent) {
		r.logAsyncAckFailures(false)
		r.handleEvent(ctx, ev)
	})
}

// handleEvent answers one incoming probe; other events are skipped.
func (r *Responder) handleEvent(ctx context.Context, event *rdmabridge.CompletionEvent) {
	if event.IsSend || event.IsAck {
		return
	}
	if event.Status != 0 {
		r.logger.Warn().
			Int32("status", event.Status).
			Msg("Recv completion with non-zero status, skipping")
		return
	}

	r.logger.Debug().
		Uint32("source_qpn", event.SourceQPN).
		Uint64("seq", event.SequenceNum).
		Uint32("flow_label", event.FlowLabel).
		Uint64("recv_ts_ns", event.TimestampNS).
		Msg("Received probe, sending ACKs")

	// The first ACK echoes T1 and carries T3 (the recv timestamp); the CQ
	// poller sends the second ACK with T3 and T4 once the first ACK's send
	// completion arrives.
	if err := r.sendAckPair(ctx, event, buildRecvPacketPayload(event)); err != nil {
		if errors.Is(err, errResponderStopping) {
			return
		}
		r.logger.Error().Err(err).
			Uint32("source_qpn", event.SourceQPN).
			Uint64("seq", event.SequenceNum).
			Msg("Failed to send ACK pair")
		return
	}

	r.logger.Debug().
		Uint32("source_qpn", event.SourceQPN).
		Uint64("seq", event.SequenceNum).
		Uint64("t3_ns", event.TimestampNS).
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
// per asyncAckFailureLogInterval unless final is set, so failures of the
// last pairs before an idle period are reported with the next probe or at
// Stop. The prober sees each failure as a timeout; this log tells the
// operator that the responder side, not the network, dropped the ACK.
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

// Destroy stops the responder and destroys its RDMA queue.
func (r *Responder) Destroy() {
	r.Stop()
	r.destroyQueue()
	r.logger.Info().Msg("Responder destroyed")
}

// buildRecvPacketPayload rebuilds the 40-byte wire-format probe the event
// describes, which the Zig ACK path needs to build the ACKs. The layout lives
// in rdmabridge.SerializeProbePacket (and zig/src/packet.zig).
func buildRecvPacketPayload(event *rdmabridge.CompletionEvent) []byte {
	buf := make([]byte, rdmabridge.ProbePacketSize)
	rdmabridge.SerializeProbePacket(&rdmabridge.ProbePacket{
		Version:     rdmabridge.PacketVersion,
		MsgType:     rdmabridge.MsgTypeProbe,
		AckType:     rdmabridge.AckTypeNone,
		Flags:       event.Flags,
		SequenceNum: event.SequenceNum,
		T1:          event.T1,
		T3:          event.T3,
		T4:          event.T4,
	}, buf)
	return buf
}
