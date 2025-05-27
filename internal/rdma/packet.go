package rdma

// #cgo LDFLAGS: -libverbs
// #include <stdlib.h>
// #include <infiniband/verbs.h>
//
// // Helper function to post receive WR without Go pointers with WRID support
// int post_recv_with_wrid(struct ibv_qp *qp, uint64_t addr, uint32_t length, uint32_t lkey, uint64_t wr_id) {
//     struct ibv_sge sge = {
//         .addr = addr,
//         .length = length,
//         .lkey = lkey,
//     };
//     struct ibv_recv_wr wr = {
//         .wr_id = wr_id,
//         .sg_list = &sge,
//         .num_sge = 1,
//     };
//     struct ibv_recv_wr *bad_wr = NULL;
//
//     return ibv_post_recv(qp, &wr, &bad_wr);
// }
//
// // Helper function to post send WR without Go pointers with WRID support
// int post_send_with_wrid(struct ibv_qp *qp, uint64_t addr, uint32_t length, uint32_t lkey,
//              struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey, uint64_t wr_id) {
//     struct ibv_sge sge = {
//         .addr = addr,
//         .length = length,
//         .lkey = lkey,
//     };
//     struct ibv_send_wr wr = {
//         .wr_id = wr_id,
//         .sg_list = &sge,
//         .num_sge = 1,
//         .opcode = IBV_WR_SEND,
//         .send_flags = IBV_SEND_SIGNALED,
//         .wr.ud.ah = ah,
//         .wr.ud.remote_qpn = remote_qpn,
//         .wr.ud.remote_qkey = remote_qkey,
//     };
//     struct ibv_send_wr *bad_wr = NULL;
//
//     return ibv_post_send(qp, &wr, &bad_wr);
// }
//
// // Legacy helper functions for backward compatibility
// int post_recv(struct ibv_qp *qp, uint64_t addr, uint32_t length, uint32_t lkey) {
//     return post_recv_with_wrid(qp, addr, length, lkey, 0);
// }
//
// int post_send(struct ibv_qp *qp, uint64_t addr, uint32_t length, uint32_t lkey,
//              struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey) {
//     return post_send_with_wrid(qp, addr, length, lkey, ah, remote_qpn, remote_qkey, 0);
// }
//
import "C"
import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// GRHSize is the size of the GRH
	GRHSize = 40
	// IPv4HeaderOffset is the offset to the supposed IPv4 header within the GRH region
	IPv4HeaderOffset = 20
	// IPv4HeaderMinLength is the minimum length of an IPv4 header
	IPv4HeaderMinLength = 20
	// DefaultQKey is the standard QKey for UD operations
	DefaultQKey uint32 = 0x11111111
	// AckSendTimeout is the timeout for waiting for ACK send completion
	AckSendTimeout = 10 * time.Millisecond
)

// ProbePacket represents the format of a probe packet
type ProbePacket struct {
	SequenceNum uint64
	T1          uint64 // Timestamp 1 (post send time in ns)
	T3          uint64 // Timestamp 3 (receive time in ns)
	T4          uint64 // Timestamp 4 (responder ACK time in ns)
	IsAck       uint8  // 0 for probe, 1 for ACK
	AckType     uint8  // 1 for first ACK, 2 for second ACK with processing delay
	Flags       uint8  // Reserved for future use
	Padding     [1]byte
}

// GRHHeaderInfo was defined here. It will be removed as its fields are integrated into ProcessedWorkCompletion.

// IncomingAckInfo holds information about a received ACK packet to be passed to the handler.
// It now directly includes ProcessedWorkCompletion for detailed info.
type IncomingAckInfo struct {
	Packet      *ProbePacket             // The deserialized ProbePacket
	ReceivedAt  time.Time                // Timestamp when the ACK was processed by the CQ poller
	ProcessedWC *ProcessedWorkCompletion // Processed work completion including GRH details
	AckStatusOK bool                     // True if the RDMA work completion for this ACK was successful (based on ProcessedWC.Status).
}

// AckHandlerFunc is a callback function type for processing incoming ACK packets.
// It's called by the CQ poller when an ACK is received on a sender queue.
type AckHandlerFunc func(ackInfo *IncomingAckInfo)

// PostRecvSlot posts a receive work request to a specific slot
func (u *UDQueue) PostRecvSlot(slot int) error {
	if slot < 0 || slot >= u.NumRecvSlots {
		return fmt.Errorf("invalid slot index %d, must be between 0 and %d", slot, u.NumRecvSlots-1)
	}

	slotAddr := u.RecvSlots[slot]
	wrid := uint64(slot) // Use slot index as WRID

	// Use the C helper function with WRID support
	ret := C.post_recv_with_wrid(
		u.QP,
		C.uint64_t(slotAddr),
		C.uint32_t(MRSize+GRHSize),
		u.RecvMR.lkey,
		C.uint64_t(wrid),
	)
	if ret != 0 {
		return fmt.Errorf("ibv_post_recv failed for slot %d: %d", slot, ret)
	}
	return nil
}

// PostRecv posts a receive work request using the next available slot
func (u *UDQueue) PostRecv() error {
	u.RecvSlotMutex.Lock()
	defer u.RecvSlotMutex.Unlock()

	slot := u.NextRecvSlot % u.NumRecvSlots
	u.NextRecvSlot++

	return u.PostRecvSlot(slot)
}

// GetNextSendSlot returns the next available send slot and its address
func (u *UDQueue) GetNextSendSlot() (int, unsafe.Pointer) {
	u.SendSlotMutex.Lock()
	defer u.SendSlotMutex.Unlock()

	slot := u.NextSendSlot % u.NumSendSlots
	u.NextSendSlot++

	return slot, unsafe.Pointer(u.SendSlots[slot])
}

// SendProbePacket sends a probe packet to the target
func (u *UDQueue) SendProbePacket(
	ctx context.Context,
	targetGID string,
	targetQPN uint32,
	sequenceNum uint64,
	sourcePort uint32,
	flowLabel uint32,
) (time.Time, time.Time, error) {
	log.Trace().
		Str("target_dest_rnic_gid", targetGID).
		Uint32("target_dest_rnic_qpn", targetQPN).
		Uint32("source_port", sourcePort).
		Uint32("flow_label", flowLabel).
		Uint64("sequence_num", sequenceNum).
		Str("local_device", u.RNIC.DeviceName).
		Str("local_gid", u.RNIC.GID).
		Uint32("local_qpn", u.QPN).
		Msg("sendProbe: Details of target for SendProbePacket")

	ah, err := u.CreateAddressHandle(targetGID, flowLabel)
	if err != nil {
		log.Error().Err(err).
			Str("target_dest_rnic_gid", targetGID).
			Uint32("flow_label", flowLabel).
			Str("local_device", u.RNIC.DeviceName).
			Str("local_gid", u.RNIC.GID).
			Msg("Failed to create Address Handle for probe packet")
		return time.Time{}, time.Time{}, err
	}
	defer C.ibv_destroy_ah(ah)

	log.Trace().
		Str("target_dest_rnic_gid", targetGID).
		Uint32("flow_label", flowLabel).
		Uint64("sequence_num", sequenceNum).
		Msg("Address Handle created successfully")

	// Get next available send slot
	sendSlot, sendBuf := u.GetNextSendSlot()
	sendWRID := uint64(sendSlot + u.NumRecvSlots) // Offset send WRIDs to avoid collision with recv WRIDs

	// Prepare the packet
	packet := (*ProbePacket)(sendBuf)
	C.memset(sendBuf, 0, C.size_t(unsafe.Sizeof(ProbePacket{})))
	packet.SequenceNum = sequenceNum
	t1 := time.Now()
	packet.T1 = uint64(t1.UnixNano())
	packet.IsAck = 0 // Not an ACK

	log.Trace().
		Str("target_dest_rnic_gid", targetGID).
		Uint32("target_dest_rnic_qpn", targetQPN).
		Uint32("flow_label", flowLabel).
		Uint64("sequence_num", sequenceNum).
		Uint64("packet_t1", packet.T1).
		Uint8("packet_isack", packet.IsAck).
		Int("send_slot", sendSlot).
		Uint64("send_wrid", sendWRID).
		Msg("Probe packet prepared, posting send")

	if ret := C.post_send_with_wrid(
		u.QP,
		C.uint64_t(uintptr(sendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(DefaultQKey),
		C.uint64_t(sendWRID),
	); ret != 0 {
		log.Error().
			Int("post_send_ret", int(ret)).
			Str("target_dest_rnic_gid", targetGID).
			Uint32("target_dest_rnic_qpn", targetQPN).
			Uint32("flow_label", flowLabel).
			Uint64("sequence_num", sequenceNum).
			Str("local_device", u.RNIC.DeviceName).
			Str("local_gid", u.RNIC.GID).
			Uint32("local_qpn", u.QPN).
			Int("send_slot", sendSlot).
			Msg("post_send failed for probe packet")
		return time.Time{}, time.Time{}, fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	log.Trace().
		Str("target_dest_rnic_gid", targetGID).
		Uint32("target_dest_rnic_qpn", targetQPN).
		Uint32("source_port", sourcePort).
		Uint32("flow_label", flowLabel).
		Uint64("sequence_num", sequenceNum).
		Int("send_slot", sendSlot).
		Msg("post_send successful")

	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.sendCompChan:
		// Received send completion event
		if wc.Status != C.IBV_WC_SUCCESS {
			log.Error().
				Int("wc_status", wc.Status).
				Str("target_dest_rnic_gid", targetGID).
				Uint32("target_dest_rnic_qpn", targetQPN).
				Uint32("flow_label", flowLabel).
				Uint64("sequence_num", sequenceNum).
				Int("send_slot", sendSlot).
				Msg("Send completion failed for probe packet")
			return time.Time{}, time.Time{}, fmt.Errorf("send completion failed: %d", wc.Status)
		}
		t2 := time.Unix(0, int64(wc.CompletionWallclockNS))
		log.Trace().
			Str("target_dest_rnic_gid", targetGID).
			Uint32("flow_label", flowLabel).
			Uint64("sequence_num", sequenceNum).
			Uint64("hw_timestamp_ns", wc.CompletionWallclockNS).
			Time("t2", t2).
			Int("send_slot", sendSlot).
			Msg("Send completion successful for probe packet")
		return t1, t2, nil
	case err := <-u.errChan:
		// Error occurred
		log.Error().Err(err).
			Str("target_dest_rnic_gid", targetGID).
			Uint32("flow_label", flowLabel).
			Uint64("sequence_num", sequenceNum).
			Int("send_slot", sendSlot).
			Msg("Error during probe packet send")
		return time.Time{}, time.Time{}, fmt.Errorf("error during send: %w", err)
	case <-ctx.Done(): // Context cancelled or timed out
		log.Warn().
			Str("target_dest_rnic_gid", targetGID).
			Uint32("flow_label", flowLabel).
			Uint64("sequence_num", sequenceNum).
			Int("send_slot", sendSlot).
			Err(ctx.Err()).
			Msg("Send probe packet timed out")
		return time.Time{}, time.Time{}, fmt.Errorf("send probe to (%s, %d, %d) timed out: %w", targetGID, targetQPN, sequenceNum, ctx.Err())
	}
}

// parseGRH parses the GRH if present and returns extracted GID/FlowLabel information.
// It uses the provided buffer as the buffer containing the received data including potential GRH.
// Returns: sgid, dgid, flowLabel, pointer to actual payload, actual payload length, error
func (u *UDQueue) parseGRH(
	goWC *GoWorkCompletion, recvBuffer unsafe.Pointer) (sgid string, dgid string, flowLabel uint32, payloadDataPtr unsafe.Pointer, actualPayloadLength uint32, err error) {
	grhPresent := (goWC.WCFlags & C.IBV_WC_GRH) == C.IBV_WC_GRH

	if !grhPresent { // GRH not present
		log.Debug().Msg("IBV_WC_GRH is NOT set. Assuming payload starts at the beginning of the buffer.")
		actualPayloadLength = uint32(goWC.ByteLen)
		payloadDataPtr = recvBuffer
		return "", "", 0, payloadDataPtr, actualPayloadLength, nil
	}

	log.Trace().Msg("IBV_WC_GRH is set. Parsing GRH.")

	if uint32(goWC.ByteLen) < GRHSize { // GRHSize is 40
		log.Error().Uint32("wc_byte_len", uint32(goWC.ByteLen)).Msg("IBV_WC_GRH is set, but wc.byte_len is less than GRHSize (40 bytes).")
		return "", "", 0, nil, 0, fmt.Errorf("IBV_WC_GRH set but wc.byte_len (%d) < GRHSize (%d)", goWC.ByteLen, GRHSize)
	}

	// GRH is at the beginning of the provided buffer
	grhBytes := unsafe.Slice((*byte)(recvBuffer), GRHSize)
	ipVersion := (grhBytes[0] >> 4) & 0x0F

	if ipVersion == 4 {
		sgid, dgid, err = u.parseIPv4GRH(grhBytes)
		// FlowLabel is not typically extracted from IPv4-mapped IPv6 GRH in this manner
		// It might be part of the IPv6 header if one were constructed, but current parsing focuses on GIDs.
	} else if ipVersion == 6 {
		sgid, dgid, flowLabel, err = u.parseIPv6GRH(grhBytes)
	} else {
		log.Error().Uint8("ip_version", ipVersion).Msg("GRH has an unknown or unsupported IP Version in its first byte.")
		err = fmt.Errorf("GRH has unknown IP version: %d", ipVersion)
	}

	if err != nil {
		return "", "", 0, nil, 0, err
	}

	// Payload is after GRH
	payloadDataPtr = unsafe.Pointer(uintptr(recvBuffer) + uintptr(GRHSize))
	actualPayloadLength = uint32(goWC.ByteLen) - GRHSize
	return sgid, dgid, flowLabel, payloadDataPtr, actualPayloadLength, nil
}

// parseIPv4GRH handles parsing for IPv4-like GRH data.
// Returns sgid, dgid, error
func (u *UDQueue) parseIPv4GRH(grhBytes []byte) (string, string, error) {
	log.Trace().Msg("GRH IP Version field is 4. Applying custom IPv4 header parsing logic (from GRH offset 20).")

	const ipv4HeaderOffsetInGRH = 20 // Current code's assumption
	const ipv4HeaderMinLength = 20   // Standard IPv4 header length

	if GRHSize < ipv4HeaderOffsetInGRH+ipv4HeaderMinLength {
		log.Error().Int("GRHSize", GRHSize).Int("ipv4HeaderOffsetInGRH", ipv4HeaderOffsetInGRH).Int("ipv4HeaderMinLength", ipv4HeaderMinLength).Msg("GRH is too small to contain an IPv4 header at the specified offset.")
		return "", "", fmt.Errorf("GRH too small for IPv4 header at offset %d", ipv4HeaderOffsetInGRH)
	}

	// Check if we have enough bytes for the IPv4 header
	if len(grhBytes) < ipv4HeaderOffsetInGRH+ipv4HeaderMinLength {
		log.Error().Int("grhBytes_length", len(grhBytes)).Int("ipv4HeaderOffsetInGRH", ipv4HeaderOffsetInGRH).Int("ipv4HeaderMinLength", ipv4HeaderMinLength).Msg("GRH bytes are too few to contain a complete IPv4 header at the specified offset.")
		return "", "", fmt.Errorf("not enough bytes for IPv4 header at offset %d", ipv4HeaderOffsetInGRH)
	}

	ipv4HeaderBytes := grhBytes[ipv4HeaderOffsetInGRH : ipv4HeaderOffsetInGRH+ipv4HeaderMinLength]
	parsedIPv4Header, parseErr := ipv4.ParseHeader(ipv4HeaderBytes)
	if parseErr != nil {
		log.Warn().Err(parseErr).Bytes("data", ipv4HeaderBytes).Msg("Failed to parse bytes from GRH offset 20 as IPv4 header.")
		return "", "", fmt.Errorf("failed to parse GRH region's IPv4 header part (offset 20): %w", parseErr)
	}

	if parsedIPv4Header.Src == nil || parsedIPv4Header.Dst == nil {
		log.Error().Msg("Parsed IPv4 header from GRH offset 20, but Src or Dst IP is nil.")
		return "", "", fmt.Errorf("parsed IPv4 header from GRH (offset 20), but Src/Dst IP is nil")
	}
	log.Trace().Str("parsed_ipv4_header", parsedIPv4Header.String()).Msg("Successfully parsed IPv4 Header from GRH offset 20")

	srcIPv4 := parsedIPv4Header.Src.To4()
	dstIPv4 := parsedIPv4Header.Dst.To4()

	if srcIPv4 == nil || dstIPv4 == nil {
		log.Error().Str("ipv4.Src", parsedIPv4Header.Src.String()).Str("ipv4.Dst", parsedIPv4Header.Dst.String()).Msg("Could not convert parsed Src/Dst IP (from GRH offset 20) to IPv4.")
		return "", "", fmt.Errorf("could not convert GRH region's IPv4 Src/Dst (offset 20) to 4-byte format")
	}

	srcMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, srcIPv4[0], srcIPv4[1], srcIPv4[2], srcIPv4[3]}
	dstMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, dstIPv4[0], dstIPv4[1], dstIPv4[2], dstIPv4[3]}
	return formatGIDString(srcMappedIPv6Bytes), formatGIDString(dstMappedIPv6Bytes), nil
}

// parseIPv6GRH handles parsing for standard IPv6 GRH data.
// Returns sgid, dgid, flowlabel, error
func (u *UDQueue) parseIPv6GRH(grhBytes []byte) (string, string, uint32, error) {
	log.Trace().Msg("GRH IP Version field is 6. Parsing SGID/DGID from standard GRH fields.")
	// Standard RoCEv2 GRH (IPv6 Format)
	// Source GID: GRH bytes 8-23
	// Destination GID: GRH bytes 24-39
	if len(grhBytes) < 40 { // Defensive check, though already checked by caller
		return "", "", 0, fmt.Errorf("grhBytes too short for IPv6 GID extraction (len: %d)", len(grhBytes))
	}
	sgidSlice := grhBytes[8:24]
	dgidSlice := grhBytes[24:40]

	sgidStr := formatGIDString(sgidSlice)
	dgidStr := formatGIDString(dgidSlice)
	var flowLabelVal uint32

	ipv6Header, parseErr := ipv6.ParseHeader(grhBytes) // Parse the whole GRH as an IPv6 header
	if parseErr == nil && ipv6Header != nil {
		flowLabelVal = uint32(ipv6Header.FlowLabel)
		log.Trace().Str("sgid", sgidStr).Str("dgid", dgidStr).Uint32("flow_label", flowLabelVal).Msg("Parsed IPv6 GRH")
	} else {
		log.Warn().Err(parseErr).Msg("Failed to parse GRH as IPv6 header to get FlowLabel, but SGID/DGID extracted directly.")
		// SGID/DGID are extracted, so this might not be a fatal error for them, but FlowLabel will be missing (remains 0).
	}
	return sgidStr, dgidStr, flowLabelVal, nil
}

// deserializeProbePacket deserializes the given payload into a ProbePacket struct.
// It also checks if the payload length is sufficient.
func (u *UDQueue) deserializeProbePacket(payloadDataPtr unsafe.Pointer, actualPayloadLength uint32) (*ProbePacket, error) {
	expectedMinimumPayloadSize := uint32(unsafe.Sizeof(ProbePacket{}))

	if actualPayloadLength < expectedMinimumPayloadSize {
		return nil, fmt.Errorf("actual received payload too small (len: %d), expected at least %d", actualPayloadLength, expectedMinimumPayloadSize)
	}

	packet := (*ProbePacket)(payloadDataPtr)
	packetCopy := *packet // Make a copy to avoid returning pointer to receive buffer that will be reused
	return &packetCopy, nil
}

// ReceivePacket waits for and processes a received packet using completion channel
func (u *UDQueue) ReceivePacket(ctx context.Context) (*ProbePacket, time.Time, *ProcessedWorkCompletion, error) {
	// Wait for completion notification from CQ poller
	select {
	case err := <-u.errChan:
		return nil, time.Time{}, nil, fmt.Errorf("error during receive: %w", err)

	case <-ctx.Done(): // Context cancelled or timed out
		return nil, time.Time{}, nil, ctx.Err()

	case goWC := <-u.recvCompChan:
		receiveTime := time.Unix(0, int64(goWC.CompletionWallclockNS)) // use HW timestamp

		// Extract slot index from WRID to get the correct buffer
		slot := int(goWC.WRID)
		var recvBuffer unsafe.Pointer
		if slot >= 0 && slot < u.NumRecvSlots {
			recvBuffer = unsafe.Pointer(u.RecvSlots[slot])
		} else {
			// Fallback to the base RecvBuf if slot is invalid
			log.Warn().Int("slot", slot).Int("num_recv_slots", u.NumRecvSlots).Msg("Invalid slot from WRID, using base RecvBuf")
			recvBuffer = u.RecvBuf
		}

		// Parse GRH (if present) and determine payload location and length
		sgid, dgid, flowLabel, payloadDataPtr, actualPayloadLength, grhParseErr := u.parseGRH(goWC, recvBuffer)

		processedWC := &ProcessedWorkCompletion{
			GoWorkCompletion: *goWC, // Embed the original GoWorkCompletion
			SGID:             sgid,
			DGID:             dgid,
			FlowLabel:        flowLabel,
		}

		if grhParseErr != nil {
			// This error comes from GRH parsing issues (e.g., bad length, unknown IP version).
			log.Warn().Err(grhParseErr).Msg("Failed to parse GRH or determine payload details")
			return nil, receiveTime, processedWC, grhParseErr // Return ProcessedWC even on GRH error, it contains the base goWC info
		}

		// Deserialize the payload into a ProbePacket
		packet, deserializeErr := u.deserializeProbePacket(payloadDataPtr, actualPayloadLength)
		if deserializeErr != nil {
			// This error is typically "actual received payload too small".
			grhPresentForLog := (goWC.WCFlags & C.IBV_WC_GRH) == C.IBV_WC_GRH
			log.Warn().
				Err(deserializeErr). // err already contains "actual received payload too small..."
				Uint32("actualPayloadLength", actualPayloadLength).
				Uint32("wc_byte_len", uint32(goWC.ByteLen)).
				Bool("grh_present", grhPresentForLog).
				Int("slot", slot).
				Msg("Failed to deserialize probe packet. Ignoring packet.")
			if slot >= 0 && slot < u.NumRecvSlots {
				if errPost := u.PostRecvSlot(slot); errPost != nil {
					log.Warn().Err(errPost).Str("device", u.RNIC.DeviceName).Uint32("qpn", u.QPN).Int("slot", slot).Msg("Failed to post replacement receive buffer after small/bad packet")
				}
			} else {
				if errPost := u.PostRecv(); errPost != nil {
					log.Warn().Err(errPost).Str("device", u.RNIC.DeviceName).Uint32("qpn", u.QPN).Msg("Failed to post replacement receive buffer after small/bad packet")
				}
			}
			return nil, receiveTime, processedWC, deserializeErr // Return ProcessedWC even on deserialize error
		}

		// Packet successfully deserialized (packet is already a copy)
		log.Trace().
			Uint64("seqNum", packet.SequenceNum).
			Uint8("isAck", packet.IsAck).
			Uint8("ackType", packet.AckType).
			Uint64("t1", packet.T1).
			Uint64("t3", packet.T3).
			Uint64("t4", packet.T4).
			Str("workComp_SGID", processedWC.SGID).
			Str("workComp_DGID", processedWC.DGID).
			Uint32("workComp_FlowLabel", processedWC.FlowLabel).
			Uint32("srcQP", processedWC.SrcQP).
			Int("slot", slot).
			Msg("Received packet data (ProbePacket content)")

		if packet.IsAck == 0 && (processedWC.SGID == "" || processedWC.SGID == "::") {
			log.Warn().Msg("Received a probe, but SGID could not be determined (e.g. no GRH or GRH parsing issue). Sending ACK might fail if SGID is required for AH creation.")
		}

		if slot >= 0 && slot < u.NumRecvSlots {
			if errPost := u.PostRecvSlot(slot); errPost != nil {
				log.Warn().Err(errPost).
					Str("device", u.RNIC.DeviceName).
					Uint32("qpn", u.QPN).
					Int("slot", slot).
					Msg("Failed to post replacement receive buffer after processing packet")
			}
		} else {
			if errPost := u.PostRecv(); errPost != nil {
				log.Warn().Err(errPost).
					Str("device", u.RNIC.DeviceName).
					Uint32("qpn", u.QPN).
					Msg("Failed to post replacement receive buffer after processing packet")
			}
		}

		return packet, receiveTime, processedWC, nil
	}
}

// SendFirstAckPacket sends the first ACK packet in response to a probe
// This corresponds to step 2 in the paper's Figure 4
func (u *UDQueue) SendFirstAckPacket(
	targetGID string,
	targetQPN uint32,
	flowLabel uint32,
	originalPacket *ProbePacket,
	receiveTime time.Time,
) (time.Time, error) {
	// Use consistent QKey across all UD operations (0x11111111 as in ud_pingpong.c)
	const qkey uint32 = DefaultQKey

	ah, err := u.CreateAddressHandle(targetGID, flowLabel)
	if err != nil {
		return time.Time{}, err
	}
	defer C.ibv_destroy_ah(ah)

	// Get next available send slot
	sendSlot, sendBuf := u.GetNextSendSlot()
	sendWRID := uint64(sendSlot + u.NumRecvSlots) // Offset send WRIDs to avoid collision with recv WRIDs

	// Clear the send buffer completely to avoid junk data
	clearSize := unsafe.Sizeof(ProbePacket{})
	C.memset(sendBuf, 0, C.size_t(clearSize))

	// Prepare the first ACK packet
	packet := (*ProbePacket)(sendBuf)
	packet.SequenceNum = originalPacket.SequenceNum
	packet.T1 = originalPacket.T1
	packet.T3 = uint64(receiveTime.UnixNano()) // Record T3 timestamp
	packet.T4 = 0                              // T4 is not known yet
	packet.IsAck = 1
	packet.AckType = 1 // First ACK
	packet.Flags = 0

	// Use the C helper function to post a send WR from C-allocated memory with WRID
	if ret := C.post_send_with_wrid(
		u.QP,
		C.uint64_t(uintptr(sendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(qkey),
		C.uint64_t(sendWRID),
	); ret != 0 {
		return time.Time{}, fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.sendCompChan:
		// Received send completion event
		if wc.Status != C.IBV_WC_SUCCESS {
			return time.Time{}, fmt.Errorf("First ACK send completion failed: %d", wc.Status)
		}
		sendCompletionTime := time.Unix(0, int64(wc.CompletionWallclockNS)) // use HW timestamp
		return sendCompletionTime, nil
	case err := <-u.errChan:
		return time.Time{}, fmt.Errorf("error during First ACK send: %w", err)
	case <-time.After(AckSendTimeout): // Timeout
		return time.Time{}, fmt.Errorf("timeout waiting for First ACK send completion")
	}
}

// SendSecondAckPacket sends the second ACK packet with processing delay information
// This corresponds to step 3 in the paper's Figure 4
func (u *UDQueue) SendSecondAckPacket(
	targetGID string,
	targetQPN uint32,
	flowLabel uint32,
	originalPacket *ProbePacket,
	receiveTime time.Time,
	sendCompletionTime time.Time,
) error {
	// Use consistent QKey across all UD operations (0x11111111 as in ud_pingpong.c)
	const qkey uint32 = DefaultQKey

	ah, err := u.CreateAddressHandle(targetGID, flowLabel)
	if err != nil {
		return err
	}
	defer C.ibv_destroy_ah(ah)

	// Get next available send slot
	sendSlot, sendBuf := u.GetNextSendSlot()
	sendWRID := uint64(sendSlot + u.NumRecvSlots) // Offset send WRIDs to avoid collision with recv WRIDs

	// Clear the send buffer completely to avoid junk data
	clearSize := unsafe.Sizeof(ProbePacket{})
	C.memset(sendBuf, 0, C.size_t(clearSize))

	// Calculate processing delay (T4-T3)
	t3 := receiveTime.UnixNano()
	t4 := sendCompletionTime.UnixNano()

	// Prepare the second ACK packet with processing delay information
	packet := (*ProbePacket)(sendBuf)
	packet.SequenceNum = originalPacket.SequenceNum
	packet.T1 = originalPacket.T1
	packet.T3 = uint64(t3)
	packet.T4 = uint64(t4)
	packet.IsAck = 1
	packet.AckType = 2 // Second ACK with processing delay
	packet.Flags = 0

	// Use the C helper function to post a send WR from C-allocated memory with WRID
	if ret := C.post_send_with_wrid(
		u.QP,
		C.uint64_t(uintptr(sendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(qkey),
		C.uint64_t(sendWRID),
	); ret != 0 {
		return fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.sendCompChan:
		// Received send completion event
		if wc.Status != C.IBV_WC_SUCCESS {
			return fmt.Errorf("Second ACK send completion failed: %d", wc.Status)
		}
		return nil
	case err := <-u.errChan:
		// Error occurred
		return fmt.Errorf("error during Second ACK send: %w", err)
	case <-time.After(AckSendTimeout): // Timeout
		return fmt.Errorf("timeout waiting for Second ACK send completion")
	}
}
