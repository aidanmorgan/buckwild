use buckwild_common::protocol::header::*;
use buckwild_common::protocol::types::{
    SequenceNumber, AckNumber, PayloadLength
};
#[test]
    fn test_session_id() {
        let id16 = SessionId::Bits16(0x1234);
        let id32 = SessionId::Bits32(0x12345678);
        let id64 = SessionId::Bits64(0x1234567890ABCDEF);
        
        assert_eq!(id16.len(), 2);
        assert_eq!(id32.len(), 4);
        assert_eq!(id64.len(), 8);
        
        assert_eq!(id16.as_u64(), 0x1234);
        assert_eq!(id32.as_u64(), 0x12345678);
        assert_eq!(id64.as_u64(), 0x1234567890ABCDEF);
        
        let mut buffer = [0u8; 8];
        
        assert_eq!(id16.write_to_be_bytes(&mut buffer), 2);
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
        
        assert_eq!(id32.write_to_be_bytes(&mut buffer), 4);
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
        assert_eq!(buffer[2], 0x56);
        assert_eq!(buffer[3], 0x78);
        
        assert_eq!(id64.write_to_be_bytes(&mut buffer), 8);
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
        assert_eq!(buffer[2], 0x56);
        assert_eq!(buffer[3], 0x78);
        assert_eq!(buffer[4], 0x90);
        assert_eq!(buffer[5], 0xAB);
        assert_eq!(buffer[6], 0xCD);
        assert_eq!(buffer[7], 0xEF);
        
        let read_id16 = SessionId::read_from_be_bytes(&buffer[..2], SessionIdLength::Bits16);
        let read_id32 = SessionId::read_from_be_bytes(&buffer[..4], SessionIdLength::Bits32);
        let read_id64 = SessionId::read_from_be_bytes(&buffer, SessionIdLength::Bits64);
        
        assert_eq!(read_id16.as_u64(), 0x1234);
        assert_eq!(read_id32.as_u64(), 0x12345678);
        assert_eq!(read_id64.as_u64(), 0x1234567890ABCDEF);
    }
    
    #[test]
    fn test_timestamp() {
        let ts16 = Timestamp::Bits16(0x1234);
        let ts24 = Timestamp::Bits24(0x123456);
        let ts32 = Timestamp::Bits32(0x12345678);
        
        assert_eq!(ts16.len(), 2);
        assert_eq!(ts24.len(), 3);
        assert_eq!(ts32.len(), 4);
        
        assert_eq!(ts16.as_u32(), 0x1234);
        assert_eq!(ts24.as_u32(), 0x123456);
        assert_eq!(ts32.as_u32(), 0x12345678);
        
        let mut buffer = [0u8; 4];
        
        assert_eq!(ts16.write_to_be_bytes(&mut buffer), 2);
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
        
        assert_eq!(ts24.write_to_be_bytes(&mut buffer), 3);
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
        assert_eq!(buffer[2], 0x56);
        
        assert_eq!(ts32.write_to_be_bytes(&mut buffer), 4);
        assert_eq!(buffer[0], 0x12);
        assert_eq!(buffer[1], 0x34);
        assert_eq!(buffer[2], 0x56);
        assert_eq!(buffer[3], 0x78);
        
        let read_ts16 = Timestamp::read_from_be_bytes(&buffer[..2], TimestampConfig::Bits16);
        let read_ts24 = Timestamp::read_from_be_bytes(&buffer[..3], TimestampConfig::Bits24);
        let read_ts32 = Timestamp::read_from_be_bytes(&buffer, TimestampConfig::Bits32);
        
        assert_eq!(read_ts16.as_u32(), 0x1234);
        assert_eq!(read_ts24.as_u32(), 0x123456);
        assert_eq!(read_ts32.as_u32(), 0x12345678);
    }
    
    #[test]
    fn test_packet_header_size() {
        let version = VersionByte::new(SessionIdLength::Bits16, TimestampConfig::Bits16);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            0,
            PacketFlags::new(),
            SessionId::Bits16(1),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::Bits16(1),
            PayloadLength::new(0),
            HmacPolicy::Light,
        );
        
        // 4 (base) + 2 (session ID) + 4 (seq) + 4 (ack) + 2 (timestamp) + 2 (payload len)
        assert_eq!(header.header_size(), 18);
        // Header + 8 bytes HMAC (Light)
        assert_eq!(header.total_size(), 26);
        
        let version = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            0,
            PacketFlags::new(),
            SessionId::Bits32(1),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::Bits24(1),
            PayloadLength::new(0),
            HmacPolicy::Light,
        );
        
        // 4 (base) + 4 (session ID) + 4 (seq) + 4 (ack) + 3 (timestamp) + 2 (payload len)
        assert_eq!(header.header_size(), 21);
        // Header + 8 bytes HMAC (Light)
        assert_eq!(header.total_size(), 29);
        
        let version = VersionByte::new(SessionIdLength::Bits64, TimestampConfig::Bits32);
        let header = PacketHeader::new(
            version,
            PacketType::Syn,
            0,
            PacketFlags::new(),
            SessionId::Bits64(1),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::Bits32(1),
            PayloadLength::new(0),
            HmacPolicy::Strong,
        );
        
        // 4 (base) + 8 (session ID) + 4 (seq) + 4 (ack) + 4 (timestamp) + 2 (payload len)
        assert_eq!(header.header_size(), 26);
        // Header + 32 bytes HMAC (Strong)
        assert_eq!(header.total_size(), 58);
    }
    
    #[test]
    fn test_packet_header_serialization() {
        let version = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
        let mut flags = PacketFlags::new();
        flags.set(PacketFlags::SYN);
        flags.set(PacketFlags::ACK);
        
        let header = PacketHeader::new(
            version,
            PacketType::SynAck,
            0,
            flags,
            SessionId::Bits32(0x12345678),
            SequenceNumber::new(0x87654321),
            AckNumber::new(0x11223344),
            Timestamp::Bits24(0x112233),
            PayloadLength::new(1024),
            HmacPolicy::Strong,
        );
        
        let mut buffer = [0u8; 64];
        let written = header.serialize(&mut buffer);
        
        // 4 (base) + 4 (session ID) + 4 (seq) + 4 (ack) + 3 (timestamp) + 2 (payload len)
        assert_eq!(written, 21);
        
        // Check serialized values
        assert_eq!(buffer[0], version.as_u8());
        assert_eq!(buffer[1], PacketType::SynAck as u8);
        assert_eq!(buffer[2], 0);
        assert_eq!(buffer[3], flags.as_u8());
        
        // Session ID (32-bit)
        assert_eq!(buffer[4], 0x12);
        assert_eq!(buffer[5], 0x34);
        assert_eq!(buffer[6], 0x56);
        assert_eq!(buffer[7], 0x78);
        
        // Sequence number
        assert_eq!(buffer[8], 0x87);
        assert_eq!(buffer[9], 0x65);
        assert_eq!(buffer[10], 0x43);
        assert_eq!(buffer[11], 0x21);
        
        // Ack number
        assert_eq!(buffer[12], 0x11);
        assert_eq!(buffer[13], 0x22);
        assert_eq!(buffer[14], 0x33);
        assert_eq!(buffer[15], 0x44);
        
        // Timestamp (24-bit)
        assert_eq!(buffer[16], 0x11);
        assert_eq!(buffer[17], 0x22);
        assert_eq!(buffer[18], 0x33);
        
        // Payload length
        assert_eq!(buffer[19], 0x04);
        assert_eq!(buffer[20], 0x00);
        
        // Deserialize and verify
        let deserialized = PacketHeader::deserialize(&buffer[..written]).unwrap();
        assert_eq!(deserialized.version_byte().as_u8(), version.as_u8());
        assert_eq!(deserialized.packet_type().unwrap() as u8, PacketType::SynAck as u8);
        assert_eq!(deserialized.sub_type(), 0);
        assert_eq!(deserialized.flags().as_u8(), flags.as_u8());
        assert_eq!(deserialized.session_id().as_u64(), 0x12345678);
        assert_eq!(deserialized.sequence_number(), SequenceNumber::new(0x87654321));
        assert_eq!(deserialized.ack_number(), AckNumber::new(0x11223344));
        assert_eq!(deserialized.timestamp().as_u32(), 0x112233);
        assert_eq!(deserialized.payload_length(), PayloadLength::new(1024));
    }
    
    #[test]
    fn test_packet_header_atomic_operations() {
        let version = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            0,
            PacketFlags::new(),
            SessionId::Bits32(1),
            SequenceNumber::new(1),
            AckNumber::new(0),
            Timestamp::Bits24(1),
            PayloadLength::new(0),
            HmacPolicy::Light,
        );
        
        // Test atomic operations
        header.set_sequence_number(SequenceNumber::new(0x12345678));
        assert_eq!(header.sequence_number(), SequenceNumber::new(0x12345678));
        
        header.set_ack_number(AckNumber::new(0x87654321));
        assert_eq!(header.ack_number(), AckNumber::new(0x87654321));
        
        header.set_payload_length(PayloadLength::new(2048));
        assert_eq!(header.payload_length(), PayloadLength::new(2048));
        
        let mut flags = PacketFlags::new();
        flags.set(PacketFlags::ACK);
        header.set_flags(flags);
        assert_eq!(header.flags().as_u8(), flags.as_u8());
        
        header.set_session_id(SessionId::Bits32(0xAABBCCDD));
        assert_eq!(header.session_id().as_u64(), 0xAABBCCDD);
        
        header.set_timestamp(Timestamp::Bits24(0x112233));
        assert_eq!(header.timestamp().as_u32(), 0x112233);
    }
