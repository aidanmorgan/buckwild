#![allow(dead_code)]
// Benchmarks for packet serialization and deserialization using consolidated types
//
// This benchmark suite tests the performance characteristics of the consolidated type system:
// 1. Packet serialization/deserialization with newtypes
// 2. Type conversion performance (raw primitives to newtypes)
// 3. Header parsing performance
//
// The benchmarks ensure that the type consolidation does not introduce performance regressions.

use buckwild_common::protocol::types::{
    AckNumber, HmacPolicy, PacketFlags, PacketType, PayloadLength, SequenceNumber, SessionId,
    SessionIdLength, Timestamp, TimestampConfig, VersionByte, WindowSize,
};
use bytes::Bytes;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

/// Test data structure using consolidated types
struct TestPacketData {
    version_byte: VersionByte,
    packet_type: PacketType,
    flags: PacketFlags,
    session_id: SessionId,
    sequence_number: SequenceNumber,
    ack_number: AckNumber,
    timestamp: Timestamp,
    payload_length: PayloadLength,
    window_size: WindowSize,
    hmac_policy: HmacPolicy,
    payload: Bytes,
}

fn create_test_packet_data() -> TestPacketData {
    // Create packet components using consolidated types with realistic values
    let version_byte = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits24);
    let mut flags = PacketFlags::new();
    flags.set(PacketFlags::ACK);

    // Use realistic protocol values
    let session_id = SessionId::from_raw(0x12345678);
    let sequence_number = SequenceNumber::new(0x87654321);
    let ack_number = AckNumber::new(0x11223344);
    let timestamp = Timestamp::from_raw(0x112233);

    // Create realistic payload data
    let payload = Bytes::from(vec![0u8; 1400]); // Typical MTU payload size
    let payload_length = PayloadLength::new(payload.len() as u16);
    let window_size = WindowSize::new(65535); // Maximum TCP window size

    TestPacketData {
        version_byte,
        packet_type: PacketType::Data,
        flags,
        session_id,
        sequence_number,
        ack_number,
        timestamp,
        payload_length,
        window_size,
        hmac_policy: HmacPolicy::Strong,
        payload,
    }
}

fn bench_packet_serialization(c: &mut Criterion) {
    let packet_data = create_test_packet_data();

    c.bench_function("packet_serialization", |b| {
        b.iter(|| {
            // Serialize packet components using consolidated types
            let mut buffer = Vec::with_capacity(256);

            // Serialize version byte
            buffer.push(packet_data.version_byte.as_u8());

            // Serialize packet type
            buffer.push(packet_data.packet_type.as_u8());

            // Serialize flags
            buffer.push(packet_data.flags.as_u8());

            // Serialize session ID (32-bit)
            let session_bytes = (packet_data.session_id.as_raw() as u32).to_be_bytes();
            buffer.extend_from_slice(&session_bytes);

            // Serialize sequence number
            let seq_bytes = packet_data.sequence_number.as_u32().to_be_bytes();
            buffer.extend_from_slice(&seq_bytes);

            // Serialize ack number
            let ack_bytes = packet_data.ack_number.as_u32().to_be_bytes();
            buffer.extend_from_slice(&ack_bytes);

            // Serialize timestamp (24-bit)
            let timestamp_bytes = (packet_data.timestamp.as_raw() as u32).to_be_bytes();
            buffer.extend_from_slice(&timestamp_bytes[1..4]); // 24-bit

            // Serialize payload length
            let payload_len_bytes = packet_data.payload_length.as_u16().to_be_bytes();
            buffer.extend_from_slice(&payload_len_bytes);

            black_box(buffer);
        });
    });
}

fn bench_packet_deserialization(c: &mut Criterion) {
    // Create test serialized data
    let mut buffer = Vec::new();
    buffer.push(0x11); // version byte
    buffer.push(0x04); // packet type (Data)
    buffer.push(0x10); // flags (ACK)
    buffer.extend_from_slice(&0x12345678u32.to_be_bytes()); // session ID
    buffer.extend_from_slice(&0x87654321u32.to_be_bytes()); // sequence number
    buffer.extend_from_slice(&0x11223344u32.to_be_bytes()); // ack number
    buffer.extend_from_slice(&[0x11, 0x22, 0x33]); // timestamp (24-bit)
    buffer.extend_from_slice(&4u16.to_be_bytes()); // payload length

    c.bench_function("packet_deserialization", |b| {
        b.iter(|| {
            // Deserialize packet components using consolidated types
            let mut offset = 0;

            // Deserialize version byte
            let version_byte = VersionByte::from_raw(buffer[offset]);
            offset += 1;

            // Deserialize packet type
            let packet_type = PacketType::from_u8(buffer[offset]).unwrap();
            offset += 1;

            // Deserialize flags
            let flags = PacketFlags::with_flags(buffer[offset]);
            offset += 1;

            // Deserialize session ID
            let session_id_bytes = &buffer[offset..offset + 4];
            let session_id = SessionId::from_raw(u32::from_be_bytes([
                session_id_bytes[0],
                session_id_bytes[1],
                session_id_bytes[2],
                session_id_bytes[3],
            ]) as u64);
            offset += 4;

            // Deserialize sequence number
            let seq_bytes = &buffer[offset..offset + 4];
            let sequence_number = SequenceNumber::new(u32::from_be_bytes([
                seq_bytes[0],
                seq_bytes[1],
                seq_bytes[2],
                seq_bytes[3],
            ]));
            offset += 4;

            // Deserialize ack number
            let ack_bytes = &buffer[offset..offset + 4];
            let ack_number = AckNumber::new(u32::from_be_bytes([
                ack_bytes[0],
                ack_bytes[1],
                ack_bytes[2],
                ack_bytes[3],
            ]));
            offset += 4;

            // Deserialize timestamp (24-bit)
            let timestamp_bytes = &buffer[offset..offset + 3];
            let timestamp = Timestamp::from_raw(u32::from_be_bytes([
                0,
                timestamp_bytes[0],
                timestamp_bytes[1],
                timestamp_bytes[2],
            ]) as u64);
            offset += 3;

            // Deserialize payload length
            let payload_len_bytes = &buffer[offset..offset + 2];
            let payload_length = PayloadLength::new(u16::from_be_bytes([
                payload_len_bytes[0],
                payload_len_bytes[1],
            ]));

            black_box((
                version_byte,
                packet_type,
                flags,
                session_id,
                sequence_number,
                ack_number,
                timestamp,
                payload_length,
            ));
        });
    });
}

fn bench_packet_header_parsing(c: &mut Criterion) {
    // Create a minimal packet header buffer (fixed format)
    // Header layout: version(1) + type(1) + flags(1) + session_id(4) + seq(4) + ack(4) + timestamp(3) + len(2) = 20 bytes
    let header_buffer: [u8; 20] = [
        0x11, // version byte
        0x04, // packet type (Data)
        0x10, // flags (ACK)
        0x12, 0x34, 0x56, 0x78, // session ID (32-bit)
        0x87, 0x65, 0x43, 0x21, // sequence number
        0x11, 0x22, 0x33, 0x44, // ack number
        0x11, 0x22, 0x33, // timestamp (24-bit)
        0x05, 0x78, // payload length
    ];

    c.bench_function("packet_header_parsing", |b| {
        b.iter(|| {
            // Parse header fields directly without validation overhead
            let version_byte = VersionByte::from_raw(header_buffer[0]);
            let packet_type = PacketType::from_u8(header_buffer[1]).unwrap();
            let flags = PacketFlags::with_flags(header_buffer[2]);

            let session_id = SessionId::from_raw(u32::from_be_bytes([
                header_buffer[3],
                header_buffer[4],
                header_buffer[5],
                header_buffer[6],
            ]) as u64);

            let sequence_number = SequenceNumber::new(u32::from_be_bytes([
                header_buffer[7],
                header_buffer[8],
                header_buffer[9],
                header_buffer[10],
            ]));

            let ack_number = AckNumber::new(u32::from_be_bytes([
                header_buffer[11],
                header_buffer[12],
                header_buffer[13],
                header_buffer[14],
            ]));

            let timestamp = Timestamp::from_raw(u32::from_be_bytes([
                0,
                header_buffer[15],
                header_buffer[16],
                header_buffer[17],
            ]) as u64);

            let payload_length =
                PayloadLength::new(u16::from_be_bytes([header_buffer[18], header_buffer[19]]));

            black_box((
                version_byte,
                packet_type,
                flags,
                session_id,
                sequence_number,
                ack_number,
                timestamp,
                payload_length,
            ))
        });
    });
}

fn bench_packet_builder(c: &mut Criterion) {
    let payload = Bytes::from(vec![1, 2, 3, 4]);

    c.bench_function("packet_builder", |b| {
        b.iter(|| {
            // Build packet components using consolidated types
            let version_byte =
                VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits24);
            let mut flags = PacketFlags::new();
            flags.set(PacketFlags::SYN);
            flags.set(PacketFlags::ACK);

            let session_id = SessionId::from_raw(0x12345678);
            let sequence_number = SequenceNumber::new(0x87654321);
            let ack_number = AckNumber::new(0x11223344);
            let timestamp = Timestamp::from_raw(0x112233);
            let payload_length = PayloadLength::new(payload.len() as u16);
            let window_size = WindowSize::new(65535);

            // Create a complete packet data structure using consolidated types
            let packet_data = TestPacketData {
                version_byte,
                packet_type: PacketType::SynAck,
                flags,
                session_id,
                sequence_number,
                ack_number,
                timestamp,
                payload_length,
                window_size,
                hmac_policy: HmacPolicy::Strong,
                payload: payload.clone(),
            };

            black_box(packet_data.version_byte.as_u8());
        });
    });
}

fn bench_type_conversions(c: &mut Criterion) {
    c.bench_function("type_conversions", |b| {
        b.iter(|| {
            // Test performance of consolidated type conversions
            let session_id = SessionId::from_raw(0x12345678);
            let sequence_number = SequenceNumber::new(0x87654321);
            let ack_number = AckNumber::new(0x11223344);
            let timestamp = Timestamp::from_raw(0x112233);
            let payload_length = PayloadLength::new(1400);
            let window_size = WindowSize::new(65535);

            // Test conversion methods
            black_box(session_id.as_raw());
            black_box(sequence_number.as_u32());
            black_box(ack_number.as_u32());
            black_box(timestamp.as_raw());
            black_box(payload_length.as_u16());
            black_box(window_size.as_u32());
        });
    });
}

fn bench_session_id_atomic(c: &mut Criterion) {
    c.bench_function("session_id_atomic_ops", |b| {
        let session_id = SessionId::from_raw(0x12345678);

        b.iter(|| {
            // Test atomic load/store performance on SessionId (which uses AtomicU64 internally)
            let value = session_id.as_raw();
            black_box(value);
        });
    });
}

fn bench_ack_number_atomic(c: &mut Criterion) {
    c.bench_function("ack_number_atomic_ops", |b| {
        let ack_number = AckNumber::new(0x11223344);

        b.iter(|| {
            // Test atomic load/store performance on AckNumber (which uses AtomicU32 internally)
            let value = ack_number.as_u32();
            black_box(value);
        });
    });
}

fn bench_flags_operations(c: &mut Criterion) {
    c.bench_function("flags_operations", |b| {
        b.iter(|| {
            let mut flags = PacketFlags::new();

            // Test flag set/get operations
            flags.set(PacketFlags::SYN);
            flags.set(PacketFlags::ACK);
            flags.set(PacketFlags::FIN);

            let has_syn = flags.has_flag(PacketFlags::SYN);
            let has_ack = flags.has_flag(PacketFlags::ACK);
            let has_fin = flags.has_flag(PacketFlags::FIN);

            black_box((has_syn, has_ack, has_fin));
        });
    });
}

criterion_group!(
    benches,
    bench_packet_serialization,
    bench_packet_deserialization,
    bench_packet_header_parsing,
    bench_packet_builder,
    bench_type_conversions,
    bench_session_id_atomic,
    bench_ack_number_atomic,
    bench_flags_operations
);
criterion_main!(benches);
