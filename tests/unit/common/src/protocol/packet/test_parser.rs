use buckwild_common::protocol:packet::parser::*;
use crate::protocol::packet::header::SessionId;

    #[test]
    fn test_parser_creation() {
        let parser = PacketParserEngine::new();
        let stats = parser.get_stats();
        assert_eq!(stats.max_packet_size, 65536);
        assert!(stats.strict_validation);

        let parser = PacketParserEngine::with_config(32768, false);
        let stats = parser.get_stats();
        assert_eq!(stats.max_packet_size, 32768);
        assert!(!stats.strict_validation);
    }

    #[test]
    fn test_packet_validation() {
        let parser = PacketParserEngine::new();

        // Test empty packet
        assert!(parser.validate_packet_integrity(&[]).is_err());

        // Test packet too small
        assert!(parser.validate_packet_integrity(&[1, 2, 3]).is_err());

        // Test invalid version
        let mut packet = vec![0; 20];
        packet[0] = 0xE0; // Version 7 (invalid)
        assert!(parser.validate_packet_integrity(&packet).is_err());

        // Test invalid packet type
        packet[0] = 0x20; // Version 1
        packet[1] = 0xFF; // Invalid packet type
        assert!(parser.validate_packet_integrity(&packet).is_err());

        // Test valid basic packet
        packet[1] = PacketType::Data as u8;
        assert!(parser.validate_packet_integrity(&packet).is_ok());
    }

    #[test]
    fn test_parse_simple_packet() {
        let parser = PacketParserEngine::new();
        
        // Create a minimal valid packet
        let version = VersionByte::new(SessionIdLength::Bits16, TimestampConfig::Bits16);
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            0,
            PacketFlags::new(),
            SessionId::Bits16(0x1234),
            1,
            0,
            Timestamp::Bits16(100),
            4,
            HmacPolicy::Light,
        );

        let mut buffer = vec![0u8; 64];
        let header_size = header.serialize(&mut buffer);
        
        // Add HMAC (8 bytes for Light policy)
        for i in 0..8 {
            buffer[header_size + i] = i as u8;
        }
        
        // Add payload (4 bytes)
        for i in 0..4 {
            buffer[header_size + 8 + i] = (i + 10) as u8;
        }

        let total_size = header_size + 8 + 4;
        let result = parser.parse_packet(&buffer[..total_size]);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.packet_type(), Some(PacketType::Data));
        assert_eq!(parsed.session_id().as_u64(), 0x1234);
        assert_eq!(parsed.sequence_number(), 1);
        assert_eq!(parsed.payload.len(), 4);
        assert_eq!(parsed.total_size, total_size);
    }

    #[test]
    fn test_parse_fragmented_packet() {
        let parser = PacketParserEngine::new();
        
        // Create a fragmented packet
        let version = VersionByte::new(SessionIdLength::Bits16, TimestampConfig::Bits16);
        let mut flags = PacketFlags::new();
        flags.set(PacketFlags::FRAG);
        
        let header = PacketHeader::new(
            version,
            PacketType::Data,
            0,
            flags,
            SessionId::Bits16(0x1234),
            1,
            0,
            Timestamp::Bits16(100),
            12, // 8 bytes fragment header + 4 bytes payload
            HmacPolicy::Light,
        );

        let mut buffer = vec![0u8; 64];
        let header_size = header.serialize(&mut buffer);
        
        // Add HMAC (8 bytes)
        for i in 0..8 {
            buffer[header_size + i] = i as u8;
        }
        
        // Add fragment header (8 bytes)
        let payload_offset = header_size + 8;
        buffer[payload_offset..payload_offset + 2].copy_from_slice(&0x5678u16.to_be_bytes()); // fragment_id
        buffer[payload_offset + 2..payload_offset + 4].copy_from_slice(&0u16.to_be_bytes()); // fragment_index
        buffer[payload_offset + 4..payload_offset + 6].copy_from_slice(&3u16.to_be_bytes()); // total_fragments
        buffer[payload_offset + 6..payload_offset + 8].copy_from_slice(&0u16.to_be_bytes()); // reserved
        
        // Add application payload (4 bytes)
        for i in 0..4 {
            buffer[payload_offset + 8 + i] = (i + 20) as u8;
        }

        let total_size = header_size + 8 + 12;
        let result = parser.parse_packet(&buffer[..total_size]);
        
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(parsed.is_fragmented());
        
        let frag_info = parsed.fragment_info().unwrap();
        assert_eq!(frag_info.fragment_id, 0x5678);
        assert_eq!(frag_info.fragment_index, 0);
        assert_eq!(frag_info.total_fragments, 3);
        assert_eq!(frag_info.payload_size, 4);
        
        let app_payload = parsed.application_payload();
        assert_eq!(app_payload.len(), 4);
        assert_eq!(app_payload[0], 20);
    }

    #[test]
    fn test_strict_validation() {
        let parser = PacketParserEngine::with_config(65536, true);
        
        // Create a SYN packet without SYN flag (should fail strict validation)
        let version = VersionByte::new(SessionIdLength::Bits16, TimestampConfig::Bits16);
        let header = PacketHeader::new(
            version,
            PacketType::Syn,
            0,
            PacketFlags::new(), // No SYN flag set
            SessionId::Bits16(0x1234),
            1,
            0,
            Timestamp::Bits16(100),
            0,
            HmacPolicy::Light,
        );

        let mut buffer = vec![0u8; 32];
        let header_size = header.serialize(&mut buffer);
        
        // Add HMAC
        for i in 0..8 {
            buffer[header_size + i] = i as u8;
        }

        let total_size = header_size + 8;
        let result = parser.parse_packet(&buffer[..total_size]);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("SYN flag"));
    }

    #[test]
    fn test_non_strict_validation() {
        let parser = PacketParserEngine::with_config(65536, false);
        
        // Same packet as above but with non-strict validation
        let version = VersionByte::new(SessionIdLength::Bits16, TimestampConfig::Bits16);
        let header = PacketHeader::new(
            version,
            PacketType::Syn,
            0,
            PacketFlags::new(),
            SessionId::Bits16(0x1234),
            1,
            0,
            Timestamp::Bits16(100),
            0,
            HmacPolicy::Light,
        );

        let mut buffer = vec![0u8; 32];
        let header_size = header.serialize(&mut buffer);
        
        // Add HMAC
        for i in 0..8 {
            buffer[header_size + i] = i as u8;
        }

        let total_size = header_size + 8;
        let result = parser.parse_packet(&buffer[..total_size]);
        
        // Should succeed with non-strict validation
        assert!(result.is_ok());
    }
