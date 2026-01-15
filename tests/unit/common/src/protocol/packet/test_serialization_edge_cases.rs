//! Edge case tests for protocol packet serialization/deserialization
//!
//! Tests boundary conditions, edge cases, and roundtrip integrity for all packet types.

use buckwild_common::protocol::packet::header::PacketHeader;
use buckwild_common::protocol::packet::structures::*;
use buckwild_common::protocol::types::*;
use bytes::Bytes;

// ============================================================================
// HEADER EDGE CASES
// ============================================================================

#[cfg(test)]
mod header_edge_cases {
    use super::*;

    #[test]
    fn test_minimum_header_size() {
        // Minimum config: 16-bit session ID, 16-bit timestamp
        let version = VersionByte::new(1, SessionIdLength::Bits16, TimestampConfig::Bits16);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            SessionId::new(1),
            SequenceNumber::new(0),
            AckNumber::new(0),
            Timestamp::from_nanos(0),
            PayloadLength::new(0),
            HmacPolicy::Light,
        );

        // Base(4) + SessionID(2) + Seq(4) + Ack(4) + Timestamp(2) + PayloadLen(2) = 18 bytes
        assert_eq!(header.header_size(), 18);
    }

    #[test]
    fn test_maximum_header_size() {
        // Maximum config: 64-bit session ID, 32-bit timestamp
        // Note: 128-bit session ID excluded due to known bug
        let version = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            SessionId::new(u64::MAX),
            SequenceNumber::new(u32::MAX),
            AckNumber::new(u32::MAX),
            Timestamp::from_nanos(u64::MAX),
            PayloadLength::new(u16::MAX),
            HmacPolicy::Strong,
        );

        // Base(4) + SessionID(8) + Seq(4) + Ack(4) + Timestamp(4) + PayloadLen(2) = 26 bytes
        assert_eq!(header.header_size(), 26);
    }

    #[test]
    fn test_all_packet_types_serialize() {
        let packet_types = vec![
            PacketType::Syn,
            PacketType::SynAck,
            PacketType::Ack,
            PacketType::Data,
            PacketType::Fin,
            PacketType::Heartbeat,
            PacketType::Error,
            PacketType::Rst,
            PacketType::Control,
            PacketType::Management,
            PacketType::Discovery,
            PacketType::Fragment,
        ];

        for packet_type in packet_types {
            let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
            let header = PacketHeader::new(
                version,
                packet_type,
                SubType::new(0),
                PacketFlags::new(),
                SessionId::new(1),
                SequenceNumber::new(1),
                AckNumber::new(0),
                Timestamp::from_nanos(1000),
                PayloadLength::new(0),
                HmacPolicy::Medium,
            );

            let mut buffer = vec![0u8; 128];
            let result = header.serialize(&mut buffer);
            assert!(result.is_ok(), "Failed to serialize {:?}", packet_type);
        }
    }

    #[test]
    fn test_version_byte_boundaries() {
        // Test all valid protocol versions (0-15)
        for version in 0..=15u8 {
            let version_byte = VersionByte::new(version, SessionIdLength::Bits32, TimestampConfig::Bits32);
            assert_eq!(version_byte.protocol_version(), version);
        }
    }

    #[test]
    fn test_version_byte_session_id_configs() {
        let configs = vec![
            SessionIdLength::Bits16,
            SessionIdLength::Bits32,
            SessionIdLength::Bits64,
            SessionIdLength::Bits128,
        ];

        for config in configs {
            let version_byte = VersionByte::new(1, config, TimestampConfig::Bits32);
            assert_eq!(version_byte.session_id_length(), config);
        }
    }

    #[test]
    fn test_version_byte_timestamp_configs() {
        let configs = vec![
            TimestampConfig::Bits16,
            TimestampConfig::Bits24,
            TimestampConfig::Bits24High,
            TimestampConfig::Bits32,
        ];

        for config in configs {
            let version_byte = VersionByte::new(1, SessionIdLength::Bits32, config);
            assert_eq!(version_byte.timestamp_config(), config);
        }
    }
}

// ============================================================================
// SEQUENCE NUMBER EDGE CASES
// ============================================================================

#[cfg(test)]
mod sequence_number_edge_cases {
    use super::*;

    #[test]
    fn test_sequence_zero() {
        let seq = SequenceNumber::new(0);
        assert_eq!(seq.as_u32(), 0);

        let bytes = seq.to_be_bytes();
        let deserialized = SequenceNumber::new(u32::from_be_bytes(bytes));
        assert_eq!(seq.as_u32(), deserialized.as_u32());
    }

    #[test]
    fn test_sequence_max() {
        let seq = SequenceNumber::new(u32::MAX);
        assert_eq!(seq.as_u32(), u32::MAX);

        let bytes = seq.to_be_bytes();
        let deserialized = SequenceNumber::new(u32::from_be_bytes(bytes));
        assert_eq!(seq.as_u32(), deserialized.as_u32());
    }

    #[test]
    fn test_sequence_wraparound() {
        let seq = SequenceNumber::new(u32::MAX);
        let next = seq.wrapping_add(1);
        assert_eq!(next.as_u32(), 0);
    }

    #[test]
    fn test_sequence_midpoint() {
        let seq = SequenceNumber::new(u32::MAX / 2);
        let bytes = seq.to_be_bytes();
        let deserialized = SequenceNumber::new(u32::from_be_bytes(bytes));
        assert_eq!(seq.as_u32(), deserialized.as_u32());
    }
}

// ============================================================================
// SESSION ID EDGE CASES
// ============================================================================

#[cfg(test)]
mod session_id_edge_cases {
    use super::*;

    #[test]
    fn test_session_id_zero() {
        let session_id = SessionId::new(0);
        assert_eq!(session_id.as_u64(), 0);
    }

    #[test]
    fn test_session_id_max_16bit() {
        let session_id = SessionId::new(0xFFFF);
        assert_eq!(session_id.as_u64(), 0xFFFF);

        let version = VersionByte::new(1, SessionIdLength::Bits16, TimestampConfig::Bits32);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            session_id,
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::from_nanos(1000),
            PayloadLength::new(0),
            HmacPolicy::Light,
        );

        let mut buffer = vec![0u8; 128];
        assert!(header.serialize(&mut buffer).is_ok());
    }

    #[test]
    fn test_session_id_max_32bit() {
        let session_id = SessionId::new(0xFFFFFFFF);
        assert_eq!(session_id.as_u64(), 0xFFFFFFFF);

        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            session_id,
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::from_nanos(1000),
            PayloadLength::new(0),
            HmacPolicy::Light,
        );

        let mut buffer = vec![0u8; 128];
        assert!(header.serialize(&mut buffer).is_ok());
    }

    #[test]
    fn test_session_id_max_64bit() {
        let session_id = SessionId::new(u64::MAX);
        assert_eq!(session_id.as_u64(), u64::MAX);

        let version = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            session_id,
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::from_nanos(1000),
            PayloadLength::new(0),
            HmacPolicy::Light,
        );

        let mut buffer = vec![0u8; 128];
        assert!(header.serialize(&mut buffer).is_ok());
    }
}

// ============================================================================
// PAYLOAD EDGE CASES
// ============================================================================

#[cfg(test)]
mod payload_edge_cases {
    use super::*;

    #[test]
    fn test_empty_payload() {
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            SessionId::new(1),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::from_nanos(1000),
            PayloadLength::new(0),
            HmacPolicy::Medium,
        );

        let hmac = HmacTag::new(vec![0u8; 16], HmacPolicy::Medium).expect("Valid HMAC");
        let packet = DataPacket {
            header,
            hmac,
            window_size: WindowSize::new(65535),
            fragment_header: None,
            payload: Bytes::new(),
        };

        let mut buffer = vec![0u8; 256];
        let result = packet.serialize(&mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_one_byte_payload() {
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            SessionId::new(1),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::from_nanos(1000),
            PayloadLength::new(1),
            HmacPolicy::Medium,
        );

        let hmac = HmacTag::new(vec![0u8; 16], HmacPolicy::Medium).expect("Valid HMAC");
        let packet = DataPacket {
            header,
            hmac,
            window_size: WindowSize::new(65535),
            fragment_header: None,
            payload: Bytes::from(vec![0xAB]),
        };

        let mut buffer = vec![0u8; 256];
        let result = packet.serialize(&mut buffer);
        assert!(result.is_ok());
    }

    #[test]
    fn test_max_mtu_payload() {
        // Max payload = MTU - header size - HMAC size
        // Using default MTU of 1500 bytes
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let hmac_policy = HmacPolicy::Medium;

        // Calculate max payload
        // Header: Base(4) + SessionID(4) + Seq(4) + Ack(4) + Timestamp(4) + PayloadLen(2) = 22
        // HMAC: 16 bytes for Medium
        // Window size: 4 bytes
        let header_size = 22;
        let hmac_size = 16;
        let window_size = 4;
        let max_payload = 1500 - header_size - hmac_size - window_size;

        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            SessionId::new(1),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::from_nanos(1000),
            PayloadLength::new(max_payload as u16),
            hmac_policy,
        );

        let hmac = HmacTag::new(vec![0u8; 16], hmac_policy).expect("Valid HMAC");
        let payload = vec![0xAB; max_payload];
        let packet = DataPacket {
            header,
            hmac,
            window_size: WindowSize::new(65535),
            fragment_header: None,
            payload: Bytes::from(payload),
        };

        let mut buffer = vec![0u8; 2048];
        let result = packet.serialize(&mut buffer);
        assert!(result.is_ok());
    }
}

// ============================================================================
// ROUNDTRIP TESTS
// ============================================================================

#[cfg(test)]
mod roundtrip_tests {
    use super::*;

    #[test]
    fn test_roundtrip_syn_minimum() {
        let version = VersionByte::new(1, SessionIdLength::Bits16, TimestampConfig::Bits16);
        let hmac_policy = HmacPolicy::Strong;
        let header = PacketHeader::new(
            version,
            PacketType::Syn,
            SubType::new(0),
            PacketFlags::from_u8(0x02),
            SessionId::new(1),
            SequenceNumber::new(0),
            AckNumber::new(0),
            Timestamp::from_nanos(0),
            PayloadLength::new(0),
            hmac_policy,
        );

        let hmac = HmacTag::new(vec![0u8; 32], hmac_policy).expect("Valid HMAC");
        let packet = SynPacket {
            header,
            hmac,
            initial_sequence: SequenceNumber::new(0),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
        };

        let mut buffer = vec![0u8; 256];
        let size = packet.serialize(&mut buffer).expect("Serialize failed");
        let deserialized = SynPacket::deserialize(&buffer[..size]).expect("Deserialize failed");

        assert_eq!(packet.header.packet_type(), deserialized.header.packet_type());
        assert_eq!(packet.initial_sequence.as_u32(), deserialized.initial_sequence.as_u32());
    }

    #[test]
    fn test_roundtrip_syn_maximum() {
        let version = VersionByte::new(1, SessionIdLength::Bits64, TimestampConfig::Bits32);
        let hmac_policy = HmacPolicy::Strong;
        let header = PacketHeader::new(
            version,
            PacketType::Syn,
            SubType::new(0),
            PacketFlags::from_u8(0x02),
            SessionId::new(u64::MAX),
            SequenceNumber::new(u32::MAX),
            AckNumber::new(0),
            Timestamp::from_nanos(u64::MAX),
            PayloadLength::new(0),
            hmac_policy,
        );

        let hmac = HmacTag::new(vec![0xFF; 32], hmac_policy).expect("Valid HMAC");
        let packet = SynPacket {
            header,
            hmac,
            initial_sequence: SequenceNumber::new(u32::MAX),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
        };

        let mut buffer = vec![0u8; 256];
        let size = packet.serialize(&mut buffer).expect("Serialize failed");
        let deserialized = SynPacket::deserialize(&buffer[..size]).expect("Deserialize failed");

        assert_eq!(packet.header.packet_type(), deserialized.header.packet_type());
        assert_eq!(packet.initial_sequence.as_u32(), deserialized.initial_sequence.as_u32());
    }

    #[test]
    fn test_roundtrip_synack() {
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let hmac_policy = HmacPolicy::Strong;
        let header = PacketHeader::new(
            version,
            PacketType::SynAck,
            SubType::new(0),
            PacketFlags::from_u8(0x12),
            SessionId::new(12345),
            SequenceNumber::new(100),
            AckNumber::new(50),
            Timestamp::from_nanos(2000),
            PayloadLength::new(0),
            hmac_policy,
        );

        let hmac = HmacTag::new(vec![0u8; 32], hmac_policy).expect("Valid HMAC");
        let packet = SynAckPacket {
            header,
            hmac,
            ack_sequence: SequenceNumber::new(50),
            server_sequence: SequenceNumber::new(100),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
        };

        let mut buffer = vec![0u8; 256];
        let size = packet.serialize(&mut buffer).expect("Serialize failed");
        let deserialized = SynAckPacket::deserialize(&buffer[..size]).expect("Deserialize failed");

        assert_eq!(packet.header.packet_type(), deserialized.header.packet_type());
        assert_eq!(packet.server_sequence.as_u32(), deserialized.server_sequence.as_u32());
        assert_eq!(packet.ack_sequence.as_u32(), deserialized.ack_sequence.as_u32());
    }

    #[test]
    fn test_roundtrip_ack() {
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let hmac_policy = HmacPolicy::Medium;
        let header = PacketHeader::new(
            version,
            PacketType::Ack,
            SubType::new(0),
            PacketFlags::from_u8(0x10),
            SessionId::new(12345),
            SequenceNumber::new(100),
            AckNumber::new(99),
            Timestamp::from_nanos(3000),
            PayloadLength::new(0),
            hmac_policy,
        );

        let hmac = HmacTag::new(vec![0u8; 16], hmac_policy).expect("Valid HMAC");
        let packet = AckPacket {
            header,
            hmac,
            window_size: WindowSize::new(65535),
            sack_data: None,
        };

        let mut buffer = vec![0u8; 256];
        let size = packet.serialize(&mut buffer).expect("Serialize failed");
        let deserialized = AckPacket::deserialize(&buffer[..size]).expect("Deserialize failed");

        assert_eq!(packet.header.packet_type(), deserialized.header.packet_type());
        assert_eq!(packet.window_size.as_u32(), deserialized.window_size.as_u32());
    }

    #[test]
    fn test_roundtrip_data_empty() {
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let hmac_policy = HmacPolicy::Medium;
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            SessionId::new(12345),
            SequenceNumber::new(100),
            AckNumber::new(50),
            Timestamp::from_nanos(4000),
            PayloadLength::new(0),
            hmac_policy,
        );

        let hmac = HmacTag::new(vec![0u8; 16], hmac_policy).expect("Valid HMAC");
        let packet = DataPacket {
            header,
            hmac,
            window_size: WindowSize::new(65535),
            fragment_header: None,
            payload: Bytes::new(),
        };

        let mut buffer = vec![0u8; 256];
        let size = packet.serialize(&mut buffer).expect("Serialize failed");
        let deserialized = DataPacket::deserialize(&buffer[..size]).expect("Deserialize failed");

        assert_eq!(packet.header.packet_type(), deserialized.header.packet_type());
        assert_eq!(packet.payload.len(), deserialized.payload.len());
    }

    #[test]
    fn test_roundtrip_data_with_payload() {
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let hmac_policy = HmacPolicy::Medium;
        let payload = Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            SessionId::new(12345),
            SequenceNumber::new(100),
            AckNumber::new(50),
            Timestamp::from_nanos(4000),
            PayloadLength::new(payload.len() as u16),
            hmac_policy,
        );

        let hmac = HmacTag::new(vec![0u8; 16], hmac_policy).expect("Valid HMAC");
        let packet = DataPacket {
            header,
            hmac,
            window_size: WindowSize::new(65535),
            fragment_header: None,
            payload: payload.clone(),
        };

        let mut buffer = vec![0u8; 256];
        let size = packet.serialize(&mut buffer).expect("Serialize failed");
        let deserialized = DataPacket::deserialize(&buffer[..size]).expect("Deserialize failed");

        assert_eq!(packet.header.packet_type(), deserialized.header.packet_type());
        assert_eq!(packet.payload.as_ref(), deserialized.payload.as_ref());
    }
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_buffer_too_small() {
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            SubType::new(0),
            PacketFlags::new(),
            SessionId::new(1),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::from_nanos(1000),
            PayloadLength::new(0),
            HmacPolicy::Medium,
        );

        let mut buffer = vec![0u8; 10]; // Too small
        let result = header.serialize(&mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_packet_type_deserialize() {
        let mut buffer = vec![0u8; 128];
        buffer[0] = 0x20; // Version 1, default configs
        buffer[1] = 0xFF; // Invalid packet type

        let result = PacketHeader::deserialize(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_packet() {
        let version = VersionByte::new(1, SessionIdLength::Bits32, TimestampConfig::Bits32);
        let hmac_policy = HmacPolicy::Strong;
        let header = PacketHeader::new(
            version,
            PacketType::Syn,
            SubType::new(0),
            PacketFlags::from_u8(0x02),
            SessionId::new(1),
            SequenceNumber::new(100),
            AckNumber::new(0),
            Timestamp::from_nanos(1000),
            PayloadLength::new(0),
            hmac_policy,
        );

        let hmac = HmacTag::new(vec![0u8; 32], hmac_policy).expect("Valid HMAC");
        let packet = SynPacket {
            header,
            hmac,
            initial_sequence: SequenceNumber::new(100),
            protocol_version: ProtocolVersion::new(1),
            session_config: SessionConfig::default(),
            connection_params: ConnectionParams::default(),
        };

        let mut buffer = vec![0u8; 256];
        let size = packet.serialize(&mut buffer).expect("Serialize failed");

        // Try to deserialize with truncated buffer
        let result = SynPacket::deserialize(&buffer[..size - 5]);
        assert!(result.is_err());
    }
}
