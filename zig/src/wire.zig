// wire.zig - The 40-byte BigEndian probe/ACK wire format.
//
// Leaf module (imports only std) so the send path (packet.zig) and the CQ
// poller (cq.zig) share one codec without an import cycle. The Go side
// implements the same layout independently (SerializeProbePacket /
// DeserializeProbePacket in internal/rdmabridge/bridge.go) and
// internal/agent/responder.go interprets the decoded fields; keep all three
// in sync. Explicit BigEndian serialization (no packed struct casting) keeps
// the format portable.
//
// Wire format (PACKET_SIZE = 40 bytes):
//   Offset  Size  Field           Encoding
//   0       1     version         uint8 (currently PACKET_VERSION)
//   1       1     msg_type        uint8 (MSG_TYPE_*)
//   2       1     ack_type        uint8 (ACK_TYPE_*)
//   3       1     flags           uint8 (reserved)
//   4       8     sequence_num    uint64 BigEndian
//   12      8     t1              uint64 BigEndian (nanoseconds)
//   20      8     t3              uint64 BigEndian (nanoseconds)
//   28      8     t4              uint64 BigEndian (nanoseconds)
//   36      4     reserved        zero padding
//
// The version byte at offset 0 enables future format changes.

const std = @import("std");

/// Size of a serialized probe or ACK packet in bytes.
pub const PACKET_SIZE: usize = 40;

/// Current version of the wire format.
pub const PACKET_VERSION: u8 = 1;

/// Message type: probe packet (initiator sends to responder).
pub const MSG_TYPE_PROBE: u8 = 0;
/// Message type: acknowledgement packet (responder sends back).
pub const MSG_TYPE_ACK: u8 = 1;

/// ACK type: not applicable (used in probe packets).
pub const ACK_TYPE_NONE: u8 = 0;
/// ACK type: first ACK, carrying T3 (responder receive timestamp).
pub const ACK_TYPE_FIRST: u8 = 1;
/// ACK type: second ACK, carrying both T3 and T4 (processing delay).
pub const ACK_TYPE_SECOND: u8 = 2;

/// Field offsets within a packet.
pub const OFFSET_VERSION: usize = 0;
pub const OFFSET_MSG_TYPE: usize = 1;
pub const OFFSET_ACK_TYPE: usize = 2;
pub const OFFSET_FLAGS: usize = 3;
pub const OFFSET_SEQUENCE_NUM: usize = 4;
pub const OFFSET_T1: usize = 12;
pub const OFFSET_T3: usize = 20;
pub const OFFSET_T4: usize = 28;
pub const OFFSET_RESERVED: usize = 36;

/// A serialized packet.
pub const Bytes = [PACKET_SIZE]u8;

/// A probe or ACK packet in Zig-native layout. Not the wire layout: use
/// serializeProbePacket() / deserializeProbePacket() for conversion.
pub const ProbePacket = struct {
    version: u8,
    msg_type: u8,
    ack_type: u8,
    flags: u8,
    /// Probe sequence number for correlating probes with their ACKs.
    sequence_num: u64,
    /// T1: time the prober posted the send (nanoseconds).
    t1: u64,
    /// T3: time the responder received the probe (nanoseconds).
    t3: u64,
    /// T4: time the responder's first ACK send completed (nanoseconds).
    t4: u64,
};

/// Serialize a ProbePacket into its wire format. The reserved bytes are
/// zeroed regardless of the buffer's previous contents.
pub fn serializeProbePacket(pkt: *const ProbePacket, buf: *Bytes) void {
    buf[OFFSET_VERSION] = pkt.version;
    buf[OFFSET_MSG_TYPE] = pkt.msg_type;
    buf[OFFSET_ACK_TYPE] = pkt.ack_type;
    buf[OFFSET_FLAGS] = pkt.flags;
    std.mem.writeInt(u64, buf[OFFSET_SEQUENCE_NUM..][0..8], pkt.sequence_num, .big);
    std.mem.writeInt(u64, buf[OFFSET_T1..][0..8], pkt.t1, .big);
    std.mem.writeInt(u64, buf[OFFSET_T3..][0..8], pkt.t3, .big);
    std.mem.writeInt(u64, buf[OFFSET_T4..][0..8], pkt.t4, .big);
    @memset(buf[OFFSET_RESERVED..], 0);
}

/// Deserialize a wire-format packet. Returns null when the version byte is
/// not PACKET_VERSION, so callers drop the packet instead of interpreting
/// leftover buffer bytes as a probe.
pub fn deserializeProbePacket(buf: *const Bytes) ?ProbePacket {
    if (buf[OFFSET_VERSION] != PACKET_VERSION) return null;
    return ProbePacket{
        .version = buf[OFFSET_VERSION],
        .msg_type = buf[OFFSET_MSG_TYPE],
        .ack_type = buf[OFFSET_ACK_TYPE],
        .flags = buf[OFFSET_FLAGS],
        .sequence_num = std.mem.readInt(u64, buf[OFFSET_SEQUENCE_NUM..][0..8], .big),
        .t1 = std.mem.readInt(u64, buf[OFFSET_T1..][0..8], .big),
        .t3 = std.mem.readInt(u64, buf[OFFSET_T3..][0..8], .big),
        .t4 = std.mem.readInt(u64, buf[OFFSET_T4..][0..8], .big),
    };
}

/// Overwrite only the T4 field of an already serialized packet. The CQ
/// poller uses it to stamp the first ACK's completion timestamp into the
/// staged second ACK of an asynchronous ACK pair.
pub fn writeT4(buf: *Bytes, t4: u64) void {
    std.mem.writeInt(u64, buf[OFFSET_T4..][0..8], t4, .big);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "field offsets tile the packet" {
    try std.testing.expectEqual(OFFSET_VERSION + 1, OFFSET_MSG_TYPE);
    try std.testing.expectEqual(OFFSET_MSG_TYPE + 1, OFFSET_ACK_TYPE);
    try std.testing.expectEqual(OFFSET_ACK_TYPE + 1, OFFSET_FLAGS);
    try std.testing.expectEqual(OFFSET_FLAGS + 1, OFFSET_SEQUENCE_NUM);
    try std.testing.expectEqual(OFFSET_SEQUENCE_NUM + 8, OFFSET_T1);
    try std.testing.expectEqual(OFFSET_T1 + 8, OFFSET_T3);
    try std.testing.expectEqual(OFFSET_T3 + 8, OFFSET_T4);
    try std.testing.expectEqual(OFFSET_T4 + 8, OFFSET_RESERVED);
    try std.testing.expectEqual(OFFSET_RESERVED + 4, PACKET_SIZE);
}

test "protocol constants have the wire values" {
    try std.testing.expectEqual(@as(u8, 1), PACKET_VERSION);
    try std.testing.expectEqual(@as(u8, 0), MSG_TYPE_PROBE);
    try std.testing.expectEqual(@as(u8, 1), MSG_TYPE_ACK);
    try std.testing.expectEqual(@as(u8, 0), ACK_TYPE_NONE);
    try std.testing.expectEqual(@as(u8, 1), ACK_TYPE_FIRST);
    try std.testing.expectEqual(@as(u8, 2), ACK_TYPE_SECOND);
}

test "serializeProbePacket writes the documented byte layout" {
    const pkt = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_ACK,
        .ack_type = ACK_TYPE_FIRST,
        .flags = 0x42,
        .sequence_num = 0x0102030405060708,
        .t1 = 1000,
        .t3 = 2000,
        .t4 = 3000,
    };
    var buf: Bytes = @splat(0xFF);
    serializeProbePacket(&pkt, &buf);

    const expected = [_]u8{
        1,    1,    1,    0x42,
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0,    0,    0,    0,
        0,    0,    0x03, 0xE8,
        0,    0,    0,    0,
        0,    0,    0x07, 0xD0,
        0,    0,    0,    0,
        0,    0,    0x0B, 0xB8,
        0,    0,    0,    0,
    };
    try std.testing.expectEqualSlices(u8, &expected, &buf);
}

test "deserializeProbePacket round-trips every field" {
    const original = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_ACK,
        .ack_type = ACK_TYPE_SECOND,
        .flags = 7,
        .sequence_num = 12345678,
        .t1 = 1_000_000_000,
        .t3 = 2_000_000_000,
        .t4 = 3_000_000_000,
    };
    var buf: Bytes = undefined;
    serializeProbePacket(&original, &buf);
    const back = deserializeProbePacket(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(original, back);
}

test "deserializeProbePacket round-trips max u64 values" {
    const original = ProbePacket{
        .version = PACKET_VERSION,
        .msg_type = MSG_TYPE_PROBE,
        .ack_type = ACK_TYPE_NONE,
        .flags = 0,
        .sequence_num = std.math.maxInt(u64),
        .t1 = std.math.maxInt(u64),
        .t3 = std.math.maxInt(u64),
        .t4 = std.math.maxInt(u64),
    };
    var buf: Bytes = undefined;
    serializeProbePacket(&original, &buf);
    const back = deserializeProbePacket(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(original, back);
}

test "deserializeProbePacket rejects an unexpected version" {
    var buf: Bytes = @splat(0);
    buf[OFFSET_MSG_TYPE] = MSG_TYPE_ACK;
    try std.testing.expect(deserializeProbePacket(&buf) == null);
    buf[OFFSET_VERSION] = PACKET_VERSION + 1;
    try std.testing.expect(deserializeProbePacket(&buf) == null);
    buf[OFFSET_VERSION] = PACKET_VERSION;
    try std.testing.expect(deserializeProbePacket(&buf) != null);
}

test "deserializeProbePacket reads a hand-built packet" {
    var buf: Bytes = @splat(0);
    buf[OFFSET_VERSION] = PACKET_VERSION;
    buf[OFFSET_MSG_TYPE] = MSG_TYPE_ACK;
    buf[OFFSET_ACK_TYPE] = ACK_TYPE_SECOND;
    buf[OFFSET_SEQUENCE_NUM + 7] = 0x01; // sequence_num = 1
    buf[OFFSET_T1 + 6] = 0x03; // t1 = 0x03E8 = 1000
    buf[OFFSET_T1 + 7] = 0xE8;
    buf[OFFSET_T3 + 6] = 0x07; // t3 = 0x07D0 = 2000
    buf[OFFSET_T3 + 7] = 0xD0;
    buf[OFFSET_T4 + 6] = 0x0B; // t4 = 0x0BB8 = 3000
    buf[OFFSET_T4 + 7] = 0xB8;

    const pkt = deserializeProbePacket(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 1), pkt.sequence_num);
    try std.testing.expectEqual(@as(u64, 1000), pkt.t1);
    try std.testing.expectEqual(@as(u64, 2000), pkt.t3);
    try std.testing.expectEqual(@as(u64, 3000), pkt.t4);
    try std.testing.expectEqual(MSG_TYPE_ACK, pkt.msg_type);
    try std.testing.expectEqual(ACK_TYPE_SECOND, pkt.ack_type);
}

test "writeT4 touches only the T4 field" {
    var buf: Bytes = @splat(0xAA);
    writeT4(&buf, 0x0102030405060708);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), std.mem.readInt(u64, buf[OFFSET_T4..][0..8], .big));
    for (buf[0..OFFSET_T4]) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
    for (buf[OFFSET_RESERVED..]) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
}
