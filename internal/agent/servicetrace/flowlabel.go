package servicetrace

// FlowLabelMask is the width of the GRH flow label (IB_GRH_FLOWLABEL_MASK).
const FlowLabelMask = 0xFFFFF

// udpEncapPortMin is IB_ROCE_UDP_ENCAP_VALID_PORT_MIN: RoCEv2 UDP source
// ports live in 0xC000-0xFFFF.
const udpEncapPortMin = 0xC000

// CalcFlowLabel is the kernel's rdma_calc_flow_label(): the symmetric flow
// label a RoCEv2 driver derives from the local and remote QPNs of a
// connected QP whose application left the flow label at zero. Both ends of
// the connection compute the same value, since the product commutes.
func CalcFlowLabel(localQPN, remoteQPN uint32) uint32 {
	v := uint64(localQPN) * uint64(remoteQPN)
	v ^= v >> 20
	v ^= v >> 40
	return uint32(v & FlowLabelMask)
}

// EffectiveFlowLabel is the flow label that decides a connected QP's UDP
// source port, following the kernel's rdma_get_udp_sport(): the label the
// application set, or CalcFlowLabel when it set none. A probe sent with
// this label through the agent's UD queue gets the same UDP source port as
// the service flow, hence the same ECMP path.
func EffectiveFlowLabel(flowLabel, localQPN, remoteQPN uint32) uint32 {
	if fl := flowLabel & FlowLabelMask; fl != 0 {
		return fl
	}
	return CalcFlowLabel(localQPN, remoteQPN)
}

// UDPSourcePort is the kernel's rdma_flow_label_to_udp_sport(): the RoCEv2
// UDP source port a driver derives from a 20-bit flow label. It folds the
// label into 14 bits above udpEncapPortMin. Used for logs and diagnostics
// only: the agent never sets the port itself, it sets the flow label.
func UDPSourcePort(flowLabel uint32) uint16 {
	low := flowLabel & 0x03FFF
	high := flowLabel & 0xFC000
	low ^= high >> 14
	return uint16(low | udpEncapPortMin)
}
