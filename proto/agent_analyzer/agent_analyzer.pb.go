// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v3.12.4
// source: proto/agent_analyzer/agent_analyzer.proto

package agent_analyzer

import (
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ProbeResult_ProbeStatus int32

const (
	ProbeResult_OK      ProbeResult_ProbeStatus = 0
	ProbeResult_TIMEOUT ProbeResult_ProbeStatus = 1
	ProbeResult_ERROR   ProbeResult_ProbeStatus = 2
	ProbeResult_UNKNOWN ProbeResult_ProbeStatus = 3
)

// Enum value maps for ProbeResult_ProbeStatus.
var (
	ProbeResult_ProbeStatus_name = map[int32]string{
		0: "OK",
		1: "TIMEOUT",
		2: "ERROR",
		3: "UNKNOWN",
	}
	ProbeResult_ProbeStatus_value = map[string]int32{
		"OK":      0,
		"TIMEOUT": 1,
		"ERROR":   2,
		"UNKNOWN": 3,
	}
)

func (x ProbeResult_ProbeStatus) Enum() *ProbeResult_ProbeStatus {
	p := new(ProbeResult_ProbeStatus)
	*p = x
	return p
}

func (x ProbeResult_ProbeStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProbeResult_ProbeStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_agent_analyzer_agent_analyzer_proto_enumTypes[0].Descriptor()
}

func (ProbeResult_ProbeStatus) Type() protoreflect.EnumType {
	return &file_proto_agent_analyzer_agent_analyzer_proto_enumTypes[0]
}

func (x ProbeResult_ProbeStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProbeResult_ProbeStatus.Descriptor instead.
func (ProbeResult_ProbeStatus) EnumDescriptor() ([]byte, []int) {
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP(), []int{2, 0}
}

// Basic RNIC information
type RnicIdentifier struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Gid           string                 `protobuf:"bytes,1,opt,name=gid,proto3" json:"gid,omitempty"`
	Qpn           uint32                 `protobuf:"varint,2,opt,name=qpn,proto3" json:"qpn,omitempty"`
	IpAddress     string                 `protobuf:"bytes,3,opt,name=ip_address,json=ipAddress,proto3" json:"ip_address,omitempty"`
	HostName      string                 `protobuf:"bytes,4,opt,name=host_name,json=hostName,proto3" json:"host_name,omitempty"`
	TorId         string                 `protobuf:"bytes,5,opt,name=tor_id,json=torId,proto3" json:"tor_id,omitempty"`
	DeviceName    string                 `protobuf:"bytes,6,opt,name=device_name,json=deviceName,proto3" json:"device_name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RnicIdentifier) Reset() {
	*x = RnicIdentifier{}
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RnicIdentifier) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RnicIdentifier) ProtoMessage() {}

func (x *RnicIdentifier) ProtoReflect() protoreflect.Message {
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RnicIdentifier.ProtoReflect.Descriptor instead.
func (*RnicIdentifier) Descriptor() ([]byte, []int) {
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP(), []int{0}
}

func (x *RnicIdentifier) GetGid() string {
	if x != nil {
		return x.Gid
	}
	return ""
}

func (x *RnicIdentifier) GetQpn() uint32 {
	if x != nil {
		return x.Qpn
	}
	return 0
}

func (x *RnicIdentifier) GetIpAddress() string {
	if x != nil {
		return x.IpAddress
	}
	return ""
}

func (x *RnicIdentifier) GetHostName() string {
	if x != nil {
		return x.HostName
	}
	return ""
}

func (x *RnicIdentifier) GetTorId() string {
	if x != nil {
		return x.TorId
	}
	return ""
}

func (x *RnicIdentifier) GetDeviceName() string {
	if x != nil {
		return x.DeviceName
	}
	return ""
}

// Probe 5-tuple details
type ProbeFiveTuple struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	SrcGid        string                 `protobuf:"bytes,1,opt,name=src_gid,json=srcGid,proto3" json:"src_gid,omitempty"`
	SrcQpn        uint32                 `protobuf:"varint,2,opt,name=src_qpn,json=srcQpn,proto3" json:"src_qpn,omitempty"`
	DstGid        string                 `protobuf:"bytes,3,opt,name=dst_gid,json=dstGid,proto3" json:"dst_gid,omitempty"`
	DstQpn        uint32                 `protobuf:"varint,4,opt,name=dst_qpn,json=dstQpn,proto3" json:"dst_qpn,omitempty"`
	FlowLabel     uint32                 `protobuf:"varint,5,opt,name=flow_label,json=flowLabel,proto3" json:"flow_label,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ProbeFiveTuple) Reset() {
	*x = ProbeFiveTuple{}
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ProbeFiveTuple) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProbeFiveTuple) ProtoMessage() {}

func (x *ProbeFiveTuple) ProtoReflect() protoreflect.Message {
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProbeFiveTuple.ProtoReflect.Descriptor instead.
func (*ProbeFiveTuple) Descriptor() ([]byte, []int) {
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP(), []int{1}
}

func (x *ProbeFiveTuple) GetSrcGid() string {
	if x != nil {
		return x.SrcGid
	}
	return ""
}

func (x *ProbeFiveTuple) GetSrcQpn() uint32 {
	if x != nil {
		return x.SrcQpn
	}
	return 0
}

func (x *ProbeFiveTuple) GetDstGid() string {
	if x != nil {
		return x.DstGid
	}
	return ""
}

func (x *ProbeFiveTuple) GetDstQpn() uint32 {
	if x != nil {
		return x.DstQpn
	}
	return 0
}

func (x *ProbeFiveTuple) GetFlowLabel() uint32 {
	if x != nil {
		return x.FlowLabel
	}
	return 0
}

// Probe result data
type ProbeResult struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	SourceRnic      *RnicIdentifier        `protobuf:"bytes,1,opt,name=source_rnic,json=sourceRnic,proto3" json:"source_rnic,omitempty"`
	DestinationRnic *RnicIdentifier        `protobuf:"bytes,2,opt,name=destination_rnic,json=destinationRnic,proto3" json:"destination_rnic,omitempty"`
	// Timestamps (nanoseconds since Unix epoch)
	T1 *timestamp.Timestamp `protobuf:"bytes,3,opt,name=t1,proto3" json:"t1,omitempty"` // Probe post time
	T2 *timestamp.Timestamp `protobuf:"bytes,4,opt,name=t2,proto3" json:"t2,omitempty"` // Prober CQE time
	T3 *timestamp.Timestamp `protobuf:"bytes,5,opt,name=t3,proto3" json:"t3,omitempty"` // Responder receive time
	T4 *timestamp.Timestamp `protobuf:"bytes,6,opt,name=t4,proto3" json:"t4,omitempty"` // Responder ACK post time
	T5 *timestamp.Timestamp `protobuf:"bytes,7,opt,name=t5,proto3" json:"t5,omitempty"` // Prober ACK receive time
	T6 *timestamp.Timestamp `protobuf:"bytes,8,opt,name=t6,proto3" json:"t6,omitempty"` // Prober poll complete time
	// Calculated metrics (nanoseconds)
	NetworkRtt     int64                   `protobuf:"varint,9,opt,name=network_rtt,json=networkRtt,proto3" json:"network_rtt,omitempty"`              // (T5-T2)-(T4-T3)
	ProberDelay    int64                   `protobuf:"varint,10,opt,name=prober_delay,json=proberDelay,proto3" json:"prober_delay,omitempty"`          // (T6-T1)-(T5-T2)
	ResponderDelay int64                   `protobuf:"varint,11,opt,name=responder_delay,json=responderDelay,proto3" json:"responder_delay,omitempty"` // (T4-T3)
	Status         ProbeResult_ProbeStatus `protobuf:"varint,12,opt,name=status,proto3,enum=agent_analyzer.ProbeResult_ProbeStatus" json:"status,omitempty"`
	FiveTuple      *ProbeFiveTuple         `protobuf:"bytes,13,opt,name=five_tuple,json=fiveTuple,proto3" json:"five_tuple,omitempty"`
	ProbeType      string                  `protobuf:"bytes,14,opt,name=probe_type,json=probeType,proto3" json:"probe_type,omitempty"` // "TOR_MESH", "INTER_TOR", "SERVICE"
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *ProbeResult) Reset() {
	*x = ProbeResult{}
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ProbeResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProbeResult) ProtoMessage() {}

func (x *ProbeResult) ProtoReflect() protoreflect.Message {
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProbeResult.ProtoReflect.Descriptor instead.
func (*ProbeResult) Descriptor() ([]byte, []int) {
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP(), []int{2}
}

func (x *ProbeResult) GetSourceRnic() *RnicIdentifier {
	if x != nil {
		return x.SourceRnic
	}
	return nil
}

func (x *ProbeResult) GetDestinationRnic() *RnicIdentifier {
	if x != nil {
		return x.DestinationRnic
	}
	return nil
}

func (x *ProbeResult) GetT1() *timestamp.Timestamp {
	if x != nil {
		return x.T1
	}
	return nil
}

func (x *ProbeResult) GetT2() *timestamp.Timestamp {
	if x != nil {
		return x.T2
	}
	return nil
}

func (x *ProbeResult) GetT3() *timestamp.Timestamp {
	if x != nil {
		return x.T3
	}
	return nil
}

func (x *ProbeResult) GetT4() *timestamp.Timestamp {
	if x != nil {
		return x.T4
	}
	return nil
}

func (x *ProbeResult) GetT5() *timestamp.Timestamp {
	if x != nil {
		return x.T5
	}
	return nil
}

func (x *ProbeResult) GetT6() *timestamp.Timestamp {
	if x != nil {
		return x.T6
	}
	return nil
}

func (x *ProbeResult) GetNetworkRtt() int64 {
	if x != nil {
		return x.NetworkRtt
	}
	return 0
}

func (x *ProbeResult) GetProberDelay() int64 {
	if x != nil {
		return x.ProberDelay
	}
	return 0
}

func (x *ProbeResult) GetResponderDelay() int64 {
	if x != nil {
		return x.ResponderDelay
	}
	return 0
}

func (x *ProbeResult) GetStatus() ProbeResult_ProbeStatus {
	if x != nil {
		return x.Status
	}
	return ProbeResult_OK
}

func (x *ProbeResult) GetFiveTuple() *ProbeFiveTuple {
	if x != nil {
		return x.FiveTuple
	}
	return nil
}

func (x *ProbeResult) GetProbeType() string {
	if x != nil {
		return x.ProbeType
	}
	return ""
}

// Path information
type PathInfo struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	FiveTuple     *ProbeFiveTuple        `protobuf:"bytes,1,opt,name=five_tuple,json=fiveTuple,proto3" json:"five_tuple,omitempty"`
	Hops          []*PathInfo_Hop        `protobuf:"bytes,2,rep,name=hops,proto3" json:"hops,omitempty"`
	Timestamp     *timestamp.Timestamp   `protobuf:"bytes,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PathInfo) Reset() {
	*x = PathInfo{}
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PathInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PathInfo) ProtoMessage() {}

func (x *PathInfo) ProtoReflect() protoreflect.Message {
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PathInfo.ProtoReflect.Descriptor instead.
func (*PathInfo) Descriptor() ([]byte, []int) {
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP(), []int{3}
}

func (x *PathInfo) GetFiveTuple() *ProbeFiveTuple {
	if x != nil {
		return x.FiveTuple
	}
	return nil
}

func (x *PathInfo) GetHops() []*PathInfo_Hop {
	if x != nil {
		return x.Hops
	}
	return nil
}

func (x *PathInfo) GetTimestamp() *timestamp.Timestamp {
	if x != nil {
		return x.Timestamp
	}
	return nil
}

// Data upload request
type UploadDataRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	AgentId       string                 `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
	ProbeResults  []*ProbeResult         `protobuf:"bytes,2,rep,name=probe_results,json=probeResults,proto3" json:"probe_results,omitempty"`
	PathInfos     []*PathInfo            `protobuf:"bytes,3,rep,name=path_infos,json=pathInfos,proto3" json:"path_infos,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *UploadDataRequest) Reset() {
	*x = UploadDataRequest{}
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UploadDataRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UploadDataRequest) ProtoMessage() {}

func (x *UploadDataRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UploadDataRequest.ProtoReflect.Descriptor instead.
func (*UploadDataRequest) Descriptor() ([]byte, []int) {
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP(), []int{4}
}

func (x *UploadDataRequest) GetAgentId() string {
	if x != nil {
		return x.AgentId
	}
	return ""
}

func (x *UploadDataRequest) GetProbeResults() []*ProbeResult {
	if x != nil {
		return x.ProbeResults
	}
	return nil
}

func (x *UploadDataRequest) GetPathInfos() []*PathInfo {
	if x != nil {
		return x.PathInfos
	}
	return nil
}

// Data upload response
type UploadDataResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Success       bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	Message       string                 `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *UploadDataResponse) Reset() {
	*x = UploadDataResponse{}
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UploadDataResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UploadDataResponse) ProtoMessage() {}

func (x *UploadDataResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UploadDataResponse.ProtoReflect.Descriptor instead.
func (*UploadDataResponse) Descriptor() ([]byte, []int) {
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP(), []int{5}
}

func (x *UploadDataResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *UploadDataResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

type PathInfo_Hop struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	IpAddress     string                 `protobuf:"bytes,1,opt,name=ip_address,json=ipAddress,proto3" json:"ip_address,omitempty"`
	RttNs         int64                  `protobuf:"varint,2,opt,name=rtt_ns,json=rttNs,proto3" json:"rtt_ns,omitempty"` // RTT in nanoseconds
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PathInfo_Hop) Reset() {
	*x = PathInfo_Hop{}
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PathInfo_Hop) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PathInfo_Hop) ProtoMessage() {}

func (x *PathInfo_Hop) ProtoReflect() protoreflect.Message {
	mi := &file_proto_agent_analyzer_agent_analyzer_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PathInfo_Hop.ProtoReflect.Descriptor instead.
func (*PathInfo_Hop) Descriptor() ([]byte, []int) {
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP(), []int{3, 0}
}

func (x *PathInfo_Hop) GetIpAddress() string {
	if x != nil {
		return x.IpAddress
	}
	return ""
}

func (x *PathInfo_Hop) GetRttNs() int64 {
	if x != nil {
		return x.RttNs
	}
	return 0
}

var File_proto_agent_analyzer_agent_analyzer_proto protoreflect.FileDescriptor

const file_proto_agent_analyzer_agent_analyzer_proto_rawDesc = "" +
	"\n" +
	")proto/agent_analyzer/agent_analyzer.proto\x12\x0eagent_analyzer\x1a\x1fgoogle/protobuf/timestamp.proto\"\xa8\x01\n" +
	"\x0eRnicIdentifier\x12\x10\n" +
	"\x03gid\x18\x01 \x01(\tR\x03gid\x12\x10\n" +
	"\x03qpn\x18\x02 \x01(\rR\x03qpn\x12\x1d\n" +
	"\n" +
	"ip_address\x18\x03 \x01(\tR\tipAddress\x12\x1b\n" +
	"\thost_name\x18\x04 \x01(\tR\bhostName\x12\x15\n" +
	"\x06tor_id\x18\x05 \x01(\tR\x05torId\x12\x1f\n" +
	"\vdevice_name\x18\x06 \x01(\tR\n" +
	"deviceName\"\x93\x01\n" +
	"\x0eProbeFiveTuple\x12\x17\n" +
	"\asrc_gid\x18\x01 \x01(\tR\x06srcGid\x12\x17\n" +
	"\asrc_qpn\x18\x02 \x01(\rR\x06srcQpn\x12\x17\n" +
	"\adst_gid\x18\x03 \x01(\tR\x06dstGid\x12\x17\n" +
	"\adst_qpn\x18\x04 \x01(\rR\x06dstQpn\x12\x1d\n" +
	"\n" +
	"flow_label\x18\x05 \x01(\rR\tflowLabel\"\xe9\x05\n" +
	"\vProbeResult\x12?\n" +
	"\vsource_rnic\x18\x01 \x01(\v2\x1e.agent_analyzer.RnicIdentifierR\n" +
	"sourceRnic\x12I\n" +
	"\x10destination_rnic\x18\x02 \x01(\v2\x1e.agent_analyzer.RnicIdentifierR\x0fdestinationRnic\x12*\n" +
	"\x02t1\x18\x03 \x01(\v2\x1a.google.protobuf.TimestampR\x02t1\x12*\n" +
	"\x02t2\x18\x04 \x01(\v2\x1a.google.protobuf.TimestampR\x02t2\x12*\n" +
	"\x02t3\x18\x05 \x01(\v2\x1a.google.protobuf.TimestampR\x02t3\x12*\n" +
	"\x02t4\x18\x06 \x01(\v2\x1a.google.protobuf.TimestampR\x02t4\x12*\n" +
	"\x02t5\x18\a \x01(\v2\x1a.google.protobuf.TimestampR\x02t5\x12*\n" +
	"\x02t6\x18\b \x01(\v2\x1a.google.protobuf.TimestampR\x02t6\x12\x1f\n" +
	"\vnetwork_rtt\x18\t \x01(\x03R\n" +
	"networkRtt\x12!\n" +
	"\fprober_delay\x18\n" +
	" \x01(\x03R\vproberDelay\x12'\n" +
	"\x0fresponder_delay\x18\v \x01(\x03R\x0eresponderDelay\x12?\n" +
	"\x06status\x18\f \x01(\x0e2'.agent_analyzer.ProbeResult.ProbeStatusR\x06status\x12=\n" +
	"\n" +
	"five_tuple\x18\r \x01(\v2\x1e.agent_analyzer.ProbeFiveTupleR\tfiveTuple\x12\x1d\n" +
	"\n" +
	"probe_type\x18\x0e \x01(\tR\tprobeType\":\n" +
	"\vProbeStatus\x12\x06\n" +
	"\x02OK\x10\x00\x12\v\n" +
	"\aTIMEOUT\x10\x01\x12\t\n" +
	"\x05ERROR\x10\x02\x12\v\n" +
	"\aUNKNOWN\x10\x03\"\xf2\x01\n" +
	"\bPathInfo\x12=\n" +
	"\n" +
	"five_tuple\x18\x01 \x01(\v2\x1e.agent_analyzer.ProbeFiveTupleR\tfiveTuple\x120\n" +
	"\x04hops\x18\x02 \x03(\v2\x1c.agent_analyzer.PathInfo.HopR\x04hops\x128\n" +
	"\ttimestamp\x18\x03 \x01(\v2\x1a.google.protobuf.TimestampR\ttimestamp\x1a;\n" +
	"\x03Hop\x12\x1d\n" +
	"\n" +
	"ip_address\x18\x01 \x01(\tR\tipAddress\x12\x15\n" +
	"\x06rtt_ns\x18\x02 \x01(\x03R\x05rttNs\"\xa9\x01\n" +
	"\x11UploadDataRequest\x12\x19\n" +
	"\bagent_id\x18\x01 \x01(\tR\aagentId\x12@\n" +
	"\rprobe_results\x18\x02 \x03(\v2\x1b.agent_analyzer.ProbeResultR\fprobeResults\x127\n" +
	"\n" +
	"path_infos\x18\x03 \x03(\v2\x18.agent_analyzer.PathInfoR\tpathInfos\"H\n" +
	"\x12UploadDataResponse\x12\x18\n" +
	"\asuccess\x18\x01 \x01(\bR\asuccess\x12\x18\n" +
	"\amessage\x18\x02 \x01(\tR\amessage2f\n" +
	"\x0fAnalyzerService\x12S\n" +
	"\n" +
	"UploadData\x12!.agent_analyzer.UploadDataRequest\x1a\".agent_analyzer.UploadDataResponseB1Z/github.com/yuuki/rpingmesh/proto/agent_analyzerb\x06proto3"

var (
	file_proto_agent_analyzer_agent_analyzer_proto_rawDescOnce sync.Once
	file_proto_agent_analyzer_agent_analyzer_proto_rawDescData []byte
)

func file_proto_agent_analyzer_agent_analyzer_proto_rawDescGZIP() []byte {
	file_proto_agent_analyzer_agent_analyzer_proto_rawDescOnce.Do(func() {
		file_proto_agent_analyzer_agent_analyzer_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_proto_agent_analyzer_agent_analyzer_proto_rawDesc), len(file_proto_agent_analyzer_agent_analyzer_proto_rawDesc)))
	})
	return file_proto_agent_analyzer_agent_analyzer_proto_rawDescData
}

var file_proto_agent_analyzer_agent_analyzer_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_proto_agent_analyzer_agent_analyzer_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_proto_agent_analyzer_agent_analyzer_proto_goTypes = []any{
	(ProbeResult_ProbeStatus)(0), // 0: agent_analyzer.ProbeResult.ProbeStatus
	(*RnicIdentifier)(nil),       // 1: agent_analyzer.RnicIdentifier
	(*ProbeFiveTuple)(nil),       // 2: agent_analyzer.ProbeFiveTuple
	(*ProbeResult)(nil),          // 3: agent_analyzer.ProbeResult
	(*PathInfo)(nil),             // 4: agent_analyzer.PathInfo
	(*UploadDataRequest)(nil),    // 5: agent_analyzer.UploadDataRequest
	(*UploadDataResponse)(nil),   // 6: agent_analyzer.UploadDataResponse
	(*PathInfo_Hop)(nil),         // 7: agent_analyzer.PathInfo.Hop
	(*timestamp.Timestamp)(nil),  // 8: google.protobuf.Timestamp
}
var file_proto_agent_analyzer_agent_analyzer_proto_depIdxs = []int32{
	1,  // 0: agent_analyzer.ProbeResult.source_rnic:type_name -> agent_analyzer.RnicIdentifier
	1,  // 1: agent_analyzer.ProbeResult.destination_rnic:type_name -> agent_analyzer.RnicIdentifier
	8,  // 2: agent_analyzer.ProbeResult.t1:type_name -> google.protobuf.Timestamp
	8,  // 3: agent_analyzer.ProbeResult.t2:type_name -> google.protobuf.Timestamp
	8,  // 4: agent_analyzer.ProbeResult.t3:type_name -> google.protobuf.Timestamp
	8,  // 5: agent_analyzer.ProbeResult.t4:type_name -> google.protobuf.Timestamp
	8,  // 6: agent_analyzer.ProbeResult.t5:type_name -> google.protobuf.Timestamp
	8,  // 7: agent_analyzer.ProbeResult.t6:type_name -> google.protobuf.Timestamp
	0,  // 8: agent_analyzer.ProbeResult.status:type_name -> agent_analyzer.ProbeResult.ProbeStatus
	2,  // 9: agent_analyzer.ProbeResult.five_tuple:type_name -> agent_analyzer.ProbeFiveTuple
	2,  // 10: agent_analyzer.PathInfo.five_tuple:type_name -> agent_analyzer.ProbeFiveTuple
	7,  // 11: agent_analyzer.PathInfo.hops:type_name -> agent_analyzer.PathInfo.Hop
	8,  // 12: agent_analyzer.PathInfo.timestamp:type_name -> google.protobuf.Timestamp
	3,  // 13: agent_analyzer.UploadDataRequest.probe_results:type_name -> agent_analyzer.ProbeResult
	4,  // 14: agent_analyzer.UploadDataRequest.path_infos:type_name -> agent_analyzer.PathInfo
	5,  // 15: agent_analyzer.AnalyzerService.UploadData:input_type -> agent_analyzer.UploadDataRequest
	6,  // 16: agent_analyzer.AnalyzerService.UploadData:output_type -> agent_analyzer.UploadDataResponse
	16, // [16:17] is the sub-list for method output_type
	15, // [15:16] is the sub-list for method input_type
	15, // [15:15] is the sub-list for extension type_name
	15, // [15:15] is the sub-list for extension extendee
	0,  // [0:15] is the sub-list for field type_name
}

func init() { file_proto_agent_analyzer_agent_analyzer_proto_init() }
func file_proto_agent_analyzer_agent_analyzer_proto_init() {
	if File_proto_agent_analyzer_agent_analyzer_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_proto_agent_analyzer_agent_analyzer_proto_rawDesc), len(file_proto_agent_analyzer_agent_analyzer_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_agent_analyzer_agent_analyzer_proto_goTypes,
		DependencyIndexes: file_proto_agent_analyzer_agent_analyzer_proto_depIdxs,
		EnumInfos:         file_proto_agent_analyzer_agent_analyzer_proto_enumTypes,
		MessageInfos:      file_proto_agent_analyzer_agent_analyzer_proto_msgTypes,
	}.Build()
	File_proto_agent_analyzer_agent_analyzer_proto = out.File
	file_proto_agent_analyzer_agent_analyzer_proto_goTypes = nil
	file_proto_agent_analyzer_agent_analyzer_proto_depIdxs = nil
}
