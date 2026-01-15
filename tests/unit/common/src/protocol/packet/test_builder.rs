use buckwild_common::protocol:packet::builder::*;
#[test]
    fn test_builder_engine() {
        let engine = PacketBuilderEngine::new();
        
        let builder = engine.syn();
        assert_eq!(builder.packet_type, PacketType::Syn);
        assert!(builder.flags.is_syn());
        
        let builder = engine.data();
        assert_eq!(builder.packet_type, PacketType::Data);
        assert!(builder.flags.is_psh());
    }

    #[test]
    fn test_packet_builder() {
        let engine = PacketBuilderEngine::new();
        
        let packet = engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .ack_number(50)
            .payload_string("Hello, World!")
            .build()
            .unwrap();
        
        assert_eq!(packet.packet_type(), Some(PacketType::Data));
        assert_eq!(packet.session_id().as_u64(), 0x12345678);
        assert_eq!(packet.sequence_number(), 100);
        assert_eq!(packet.ack_number(), 50);
        assert_eq!(packet.payload().len(), 13);
    }

    #[test]
    fn test_packet_with_flow_control() {
        let engine = PacketBuilderEngine::new();
        
        let packet = engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .window_size(8192)
            .payload_string("Data")
            .build()
            .unwrap();
        
        // Payload should include 4-byte flow control header + data
        assert_eq!(packet.payload().len(), 8); // 4 bytes header + 4 bytes "Data"
        
        // Check flow control header
        let payload = packet.payload();
        let window_size = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(window_size, 8192);
    }

    #[test]
    fn test_packet_with_fragmentation() {
        let engine = PacketBuilderEngine::new();
        
        let packet = engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .fragmentation(0x5678, 0, 3)
            .payload_string("Fragment data")
            .build()
            .unwrap();
        
        assert!(packet.flags().is_frag());
        
        // Payload should include 8-byte fragmentation header + data
        assert_eq!(packet.payload().len(), 21); // 8 bytes header + 13 bytes "Fragment data"
        
        // Check fragmentation header
        let payload = packet.payload();
        let fragment_id = u16::from_be_bytes([payload[0], payload[1]]);
        let fragment_index = u16::from_be_bytes([payload[2], payload[3]]);
        let total_fragments = u16::from_be_bytes([payload[4], payload[5]]);
        
        assert_eq!(fragment_id, 0x5678);
        assert_eq!(fragment_index, 0);
        assert_eq!(total_fragments, 3);
    }

    #[test]
    fn test_packet_with_sack() {
        let engine = PacketBuilderEngine::new();
        
        let ranges = vec![(100, 200), (300, 400)];
        let packet = engine.ack()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .window_size(8192)
            .sack_header(0x12345678, ranges)
            .build()
            .unwrap();
        
        assert!(packet.flags().is_sack());
        
        // Payload should include flow control header + SACK header
        // 4 bytes flow control + 5 bytes SACK base + 16 bytes (2 ranges * 8 bytes each)
        assert_eq!(packet.payload().len(), 25);
    }

    #[test]
    fn test_packet_serialization() {
        let engine = PacketBuilderEngine::new();
        
        let packet = engine.data()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .payload_string("Test")
            .build()
            .unwrap();
        
        let serialized = packet.serialize();
        assert!(serialized.len() > 0);
        
        // Should be able to parse it back
        let parser = super::parser::PacketParserEngine::new();
        let parsed = parser.parse_packet(&serialized).unwrap();
        
        assert_eq!(parsed.packet_type(), Some(PacketType::Data));
        assert_eq!(parsed.session_id().as_u64(), 0x12345678);
        assert_eq!(parsed.sequence_number(), 100);
    }

    #[test]
    fn test_configuration_presets() {
        let engine = PacketBuilderEngine::new();
        
        // Test IoT config
        let packet = engine.data()
            .iot_config()
            .session_id(SessionId::Bits16(0x1234))
            .sequence_number(100)
            .build()
            .unwrap();
        
        assert_eq!(packet.header().hmac_policy(), HmacPolicy::Light);
        assert_eq!(packet.session_id(), SessionId::Bits16(0x1234));
        
        // Test secure config
        let packet = engine.data()
            .secure_config()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(100)
            .build()
            .unwrap();
        
        assert_eq!(packet.header().hmac_policy(), HmacPolicy::Strong);
    }

    #[test]
    fn test_sub_types() {
        let engine = PacketBuilderEngine::new();
        
        let packet = engine.control()
            .control_sub_type(ControlSubType::FlowControl)
            .session_id(SessionId::Bits32(0x12345678))
            .build()
            .unwrap();
        
        assert_eq!(packet.header().sub_type(), ControlSubType::FlowControl as u8);
        
        let packet = engine.management()
            .management_sub_type(ManagementSubType::StatusRequest)
            .session_id(SessionId::Bits32(0x12345678))
            .build()
            .unwrap();
        
        assert_eq!(packet.header().sub_type(), ManagementSubType::StatusRequest as u8);
        
        let packet = engine.discovery()
            .discovery_sub_type(DiscoverySubType::Request)
            .session_id(SessionId::Bits32(0x12345678))
            .build()
            .unwrap();
        
        assert_eq!(packet.header().sub_type(), DiscoverySubType::Request as u8);
    }
