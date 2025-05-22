package rdma

// #cgo LDFLAGS: -libverbs
// #include <stdlib.h>
// #include <infiniband/verbs.h>
//
// // Helper function to post receive WR without Go pointers
// int post_recv(struct ibv_qp *qp, uint64_t addr, uint32_t length, uint32_t lkey) {
//     struct ibv_sge sge;
//     struct ibv_recv_wr wr;
//     struct ibv_recv_wr *bad_wr = NULL;
//
//     memset(&sge, 0, sizeof(sge));
//     sge.addr = addr;
//     sge.length = length;
//     sge.lkey = lkey;
//
//     memset(&wr, 0, sizeof(wr));
//     wr.sg_list = &sge;
//     wr.num_sge = 1;
//
//     return ibv_post_recv(qp, &wr, &bad_wr);
// }
//
// // Helper function to post send WR without Go pointers
// int post_send(struct ibv_qp *qp, uint64_t addr, uint32_t length, uint32_t lkey,
//              struct ibv_ah *ah, uint32_t remote_qpn, uint32_t remote_qkey) {
//     struct ibv_sge sge;
//     struct ibv_send_wr wr;
//     struct ibv_send_wr *bad_wr = NULL;
//
//     memset(&sge, 0, sizeof(sge));
//     sge.addr = addr;
//     sge.length = length;
//     sge.lkey = lkey;
//
//     memset(&wr, 0, sizeof(wr));
//     wr.sg_list = &sge;
//     wr.num_sge = 1;
//     wr.opcode = IBV_WR_SEND;
//     wr.send_flags = IBV_SEND_SIGNALED;
//     wr.wr.ud.ah = ah;
//     wr.wr.ud.remote_qpn = remote_qpn;
//     wr.wr.ud.remote_qkey = remote_qkey;
//
//     return ibv_post_send(qp, &wr, &bad_wr);
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

// GRHHeaderInfo holds extracted information from the GRH.
type GRHHeaderInfo struct {
	SourceGID string
	DestGID   string
	FlowLabel uint32
	// Add other relevant GRH fields if needed by the handler
}

// IncomingAckInfo holds information about a received ACK packet to be passed to the handler.
type IncomingAckInfo struct {
	Packet      *ProbePacket      // The deserialized ProbePacket
	ReceivedAt  time.Time         // Timestamp when the ACK was processed by the CQ poller
	GRHInfo     *GRHHeaderInfo    // Information from GRH, if present
	SourceQP    uint32            // Source QP from the work completion (remote QPN)
	RawWC       *GoWorkCompletion // Raw work completion for any other details. Use with caution.
	AckStatusOK bool              // True if the RDMA work completion for this ACK was successful.
}

// AckHandlerFunc is a callback function type for processing incoming ACK packets.
// It's called by the CQ poller when an ACK is received on a sender queue.
type AckHandlerFunc func(ackInfo *IncomingAckInfo)

// PostRecv posts a receive work request
func (u *UDQueue) PostRecv() error {
	// Use the C helper function that manages work request memory on C side
	// This avoids the "cgo argument has Go pointers to unpinned Go pointers" error
	ret := C.post_recv(
		u.QP,
		C.uint64_t(uintptr(u.RecvBuf)),
		C.uint32_t(MRSize+GRHSize),
		u.RecvMR.lkey,
	)
	if ret != 0 {
		return fmt.Errorf("ibv_post_recv failed: %d", ret)
	}
	return nil
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
		Msg("sendProbe: Details of target for SendProbePacket")

	ah, err := u.CreateAddressHandle(targetGID, flowLabel)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	defer C.ibv_destroy_ah(ah)

	// Prepare the packet
	packet := (*ProbePacket)(u.SendBuf)
	C.memset(u.SendBuf, 0, C.size_t(unsafe.Sizeof(ProbePacket{})))
	packet.SequenceNum = sequenceNum
	t1 := time.Now()
	packet.T1 = uint64(t1.UnixNano())
	packet.IsAck = 0 // Not an ACK

	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(DefaultQKey),
	); ret != 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("ibv_post_send failed: %d", ret)
	}

	log.Trace().
		Str("target_dest_rnic_gid", targetGID).
		Uint32("target_dest_rnic_qpn", targetQPN).
		Uint32("source_port", sourcePort).
		Uint32("flow_label", flowLabel).
		Uint64("sequence_num", sequenceNum).
		Msg("post_send successful")

	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.sendCompChan:
		// Received send completion event
		if wc.Status != C.IBV_WC_SUCCESS {
			return time.Time{}, time.Time{}, fmt.Errorf("send completion failed: %d", wc.Status)
		}
		t2 := time.Unix(0, int64(wc.CompletionWallclockNS))
		return t1, t2, nil
	case err := <-u.errChan:
		// Error occurred
		return time.Time{}, time.Time{}, fmt.Errorf("error during send: %w", err)
	case <-ctx.Done(): // Context cancelled or timed out
		return time.Time{}, time.Time{}, fmt.Errorf("send probe to (%s, %d, %d) timed out: %w", targetGID, targetQPN, sequenceNum, ctx.Err())
	}
}

// ReceivePacket waits for and processes a received packet using completion channel
func (u *UDQueue) ReceivePacket(ctx context.Context) (*ProbePacket, time.Time, *WorkCompletion, error) {
	// Wait for completion notification from CQ poller
	select {
	case wc := <-u.recvCompChan:
		receiveTime := time.Unix(0, int64(wc.CompletionWallclockNS)) // use HW timestamp
		workComp := &WorkCompletion{
			Status:    uint32(wc.Status),
			SrcQP:     uint32(wc.SrcQP),
			VendorErr: uint32(wc.VendorErr),
		}

		var packetDataPtr unsafe.Pointer
		var actualPayloadLength uint32
		expectedMinimumPayloadSize := uint32(unsafe.Sizeof(ProbePacket{}))
		grhPresent := (wc.WCFlags & C.IBV_WC_GRH) == C.IBV_WC_GRH

		if grhPresent {
			log.Trace().Msg("IBV_WC_GRH is set. Parsing GRH.")

			if uint32(wc.ByteLen) < GRHSize { // GRHSize is 40
				log.Error().Uint32("wc_byte_len", uint32(wc.ByteLen)).Msg("IBV_WC_GRH is set, but wc.byte_len is less than GRHSize (40 bytes).")
				return nil, receiveTime, workComp, fmt.Errorf("IBV_WC_GRH set but wc.byte_len (%d) < GRHSize (%d)", wc.ByteLen, GRHSize)
			}

			// GRH is at the beginning of u.RecvBuf
			grhBytes := unsafe.Slice((*byte)(u.RecvBuf), GRHSize)
			ipVersion := (grhBytes[0] >> 4) & 0x0F

			if ipVersion == 4 {
				// User's "current IPv4 processing" - assumes IPv4 header info is at offset 20 within GRH
				// This interpretation of GRH for IPv4 is unusual. Standard RoCEv2 GRH is IPv6-formatted.
				log.Trace().Msg("GRH IP Version field is 4. Applying custom IPv4 header parsing logic (from GRH offset 20).")

				const ipv4HeaderOffsetInGRH = 20 // Current code's assumption
				const ipv4HeaderMinLength = 20   // Standard IPv4 header length

				if GRHSize < ipv4HeaderOffsetInGRH+ipv4HeaderMinLength {
					log.Error().Int("GRHSize", GRHSize).Int("ipv4HeaderOffsetInGRH", ipv4HeaderOffsetInGRH).Int("ipv4HeaderMinLength", ipv4HeaderMinLength).Msg("GRH is too small to contain an IPv4 header at the specified offset.")
					return nil, receiveTime, workComp, fmt.Errorf("GRH too small for IPv4 header at offset %d", ipv4HeaderOffsetInGRH)
				}

				ipv4HeaderBytes := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(u.RecvBuf)+uintptr(ipv4HeaderOffsetInGRH))), ipv4HeaderMinLength)
				parsedIPv4Header, err := ipv4.ParseHeader(ipv4HeaderBytes)
				if err != nil {
					log.Warn().Err(err).Bytes("data", ipv4HeaderBytes).Msg("Failed to parse bytes from GRH offset 20 as IPv4 header.")
					return nil, receiveTime, workComp, fmt.Errorf("failed to parse GRH region's IPv4 header part (offset 20): %w", err)
				}

				if parsedIPv4Header.Src == nil || parsedIPv4Header.Dst == nil {
					log.Error().Msg("Parsed IPv4 header from GRH offset 20, but Src or Dst IP is nil.")
					return nil, receiveTime, workComp, fmt.Errorf("parsed IPv4 header from GRH (offset 20), but Src/Dst IP is nil")
				}
				log.Trace().Str("parsed_ipv4_header", parsedIPv4Header.String()).Msg("Successfully parsed IPv4 Header from GRH offset 20")

				srcIPv4 := parsedIPv4Header.Src.To4()
				dstIPv4 := parsedIPv4Header.Dst.To4()

				if srcIPv4 == nil || dstIPv4 == nil {
					log.Error().Str("ipv4.Src", parsedIPv4Header.Src.String()).Str("ipv4.Dst", parsedIPv4Header.Dst.String()).Msg("Could not convert parsed Src/Dst IP (from GRH offset 20) to IPv4.")
					return nil, receiveTime, workComp, fmt.Errorf("could not convert GRH region's IPv4 Src/Dst (offset 20) to 4-byte format")
				}

				// Convert to IPv4-mapped IPv6 GID strings for workComp
				srcMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, srcIPv4[0], srcIPv4[1], srcIPv4[2], srcIPv4[3]}
				dstMappedIPv6Bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, dstIPv4[0], dstIPv4[1], dstIPv4[2], dstIPv4[3]}
				workComp.SGID = formatGIDString(srcMappedIPv6Bytes)
				workComp.DGID = formatGIDString(dstMappedIPv6Bytes)

			} else if ipVersion == 6 {
				log.Trace().Msg("GRH IP Version field is 6. Parsing SGID/DGID from standard GRH fields.")
				// Standard RoCEv2 GRH (IPv6 Format)
				// Source GID: GRH bytes 8-23
				sgidSlice := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(u.RecvBuf)+8)), 16)
				// Destination GID: GRH bytes 24-39
				dgidSlice := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(u.RecvBuf)+24)), 16)

				workComp.SGID = formatGIDString(sgidSlice)
				workComp.DGID = formatGIDString(dgidSlice)

				// Optionally parse IPv6 header fields for flow label, etc.
				ipv6Header, err := ipv6.ParseHeader(grhBytes) // Parse the whole GRH as an IPv6 header
				if err == nil && ipv6Header != nil {
					workComp.FlowLabel = uint32(ipv6Header.FlowLabel)
					log.Trace().Str("sgid", workComp.SGID).Str("dgid", workComp.DGID).Uint32("flow_label", workComp.FlowLabel).Msg("Parsed IPv6 GRH")
				} else {
					log.Warn().Err(err).Msg("Failed to parse GRH as IPv6 header to get FlowLabel, but SGID/DGID extracted directly.")
				}

			} else {
				log.Error().Uint8("ip_version", ipVersion).Msg("GRH has an unknown or unsupported IP Version in its first byte.")
				return nil, receiveTime, workComp, fmt.Errorf("GRH has unknown IP version: %d", ipVersion)
			}
			// Payload is after GRH
			actualPayloadLength = uint32(wc.ByteLen) - GRHSize
			packetDataPtr = unsafe.Pointer(uintptr(u.RecvBuf) + uintptr(GRHSize))

		} else { // GRH not present
			log.Debug().Msg("IBV_WC_GRH is NOT set. Assuming payload starts at the beginning of the buffer.")
			actualPayloadLength = uint32(wc.ByteLen)
			packetDataPtr = u.RecvBuf
		}

		// Now check the actualPayloadLength against the expected size for ProbePacket
		if actualPayloadLength < expectedMinimumPayloadSize {
			log.Warn().
				Uint32("actualPayloadLength", actualPayloadLength).
				Uint32("expectedMinimumPayloadSize", expectedMinimumPayloadSize).
				Uint32("wc_byte_len", uint32(wc.ByteLen)).
				Bool("grh_present", grhPresent).
				Msg("Actual received payload is smaller than ProbePacket size. Ignoring packet.")
			if errPost := u.PostRecv(); errPost != nil {
				log.Warn().Err(errPost).Str("device", u.RNIC.DeviceName).Uint32("qpn", u.QPN).Msg("Failed to post replacement receive buffer after small/bad packet")
			}
			return nil, receiveTime, workComp, fmt.Errorf("actual received payload too small (len: %d), expected at least %d", actualPayloadLength, expectedMinimumPayloadSize)
		}

		// Access the packet data
		packet := (*ProbePacket)(packetDataPtr)
		packetCopy := *packet // Make a copy

		log.Trace().
			Uint64("seqNum", packet.SequenceNum).
			Uint8("isAck", packet.IsAck).
			Uint8("ackType", packet.AckType).
			Uint64("t1", packet.T1).
			Uint64("t3", packet.T3).
			Uint64("t4", packet.T4).
			Str("workComp_SGID", workComp.SGID).
			Str("workComp_DGID", workComp.DGID).
			Uint32("workComp_FlowLabel", workComp.FlowLabel).
			Uint32("srcQP", workComp.SrcQP).
			Msg("Received packet data (ProbePacket content)")

		if packet.IsAck == 0 && (workComp.SGID == "" || workComp.SGID == "::") {
			log.Warn().Msg("Received a probe, but SGID could not be determined (e.g. no GRH or GRH parsing issue). Sending ACK might fail if SGID is required for AH creation.")
		}

		if errPost := u.PostRecv(); errPost != nil {
			log.Warn().Err(errPost).
				Str("device", u.RNIC.DeviceName).
				Uint32("qpn", u.QPN).
				Msg("Failed to post replacement receive buffer after processing packet")
		}

		return &packetCopy, receiveTime, workComp, nil

	case err := <-u.errChan:
		return nil, time.Time{}, nil, fmt.Errorf("error during receive: %w", err)
	case <-ctx.Done(): // Context cancelled or timed out
		return nil, time.Time{}, nil, ctx.Err()
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

	// Clear the send buffer completely to avoid junk data
	clearSize := unsafe.Sizeof(ProbePacket{})
	C.memset(u.SendBuf, 0, C.size_t(clearSize))

	// Prepare the first ACK packet
	packet := (*ProbePacket)(u.SendBuf)
	packet.SequenceNum = originalPacket.SequenceNum
	packet.T1 = originalPacket.T1
	packet.T3 = uint64(receiveTime.UnixNano()) // Record T3 timestamp
	packet.T4 = 0                              // T4 is not known yet
	packet.IsAck = 1
	packet.AckType = 1 // First ACK
	packet.Flags = 0

	// Use the C helper function to post a send WR from C-allocated memory
	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(qkey),
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

	// Clear the send buffer completely to avoid junk data
	clearSize := unsafe.Sizeof(ProbePacket{})
	C.memset(u.SendBuf, 0, C.size_t(clearSize))

	// Calculate processing delay (T4-T3)
	t3 := receiveTime.UnixNano()
	t4 := sendCompletionTime.UnixNano()

	// Prepare the second ACK packet with processing delay information
	packet := (*ProbePacket)(u.SendBuf)
	packet.SequenceNum = originalPacket.SequenceNum
	packet.T1 = originalPacket.T1
	packet.T3 = uint64(t3)
	packet.T4 = uint64(t4)
	packet.IsAck = 1
	packet.AckType = 2 // Second ACK with processing delay
	packet.Flags = 0

	// Use the C helper function to post a send WR from C-allocated memory
	if ret := C.post_send(
		u.QP,
		C.uint64_t(uintptr(u.SendBuf)),
		C.uint32_t(unsafe.Sizeof(ProbePacket{})),
		u.SendMR.lkey,
		ah,
		C.uint32_t(targetQPN),
		C.uint32_t(qkey),
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
