use buckwild_common::protocol::packet::*;
#[test]
    fn test_packet_creation() {
        let version_byte = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
        let mut flags = PacketFlags::new();
        flags.set(PacketFlags::SYN);
        flags.set(PacketFlags::ACK);
        
        let payload = Bytes::from(vec![1, 2, 3, 4]);
        
        let packet = Packet::new(
            version_byte,
            PacketType::SynAck,
            0,
            flags,
            SessionId::Bits32(0x12345678),
            0x87654321,
            0x11223344,
            Timestamp::Bits24(0x112233),
            HmacPolicy::Strong,
            payload.clone(),
        );
        
        assert_eq!(packet.packet_type().unwrap(), PacketType::SynAck);
        assert_eq!(packet.flags().as_u8(), flags.as_u8());
        assert_eq!(packet.session_id().as_u64(), 0x12345678);
        assert_eq!(packet.sequence_number(), 0x87654321);
        assert_eq!(packet.ack_number(), 0x11223344);
        assert_eq!(packet.timestamp().as_u32(), 0x112233);
        assert_eq!(packet.payload_length(), 4);
        assert_eq!(packet.payload().len(), 4);
        assert_eq!(&packet.payload()[..], &[1, 2, 3, 4]);
    }
    
    #[test]
    fn test_packet_serialization() {
        let version_byte = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
        let mut flags = PacketFlags::new();
        flags.set(PacketFlags::SYN);
        flags.set(PacketFlags::ACK);
        
        let payload = Bytes::from(vec![1, 2, 3, 4]);
        
        let mut packet = Packet::new(
            version_byte,
            PacketType::SynAck,
            0,
            flags,
            SessionId::Bits32(0x12345678),
            0x87654321,
            0x11223344,
            Timestamp::Bits24(0x112233),
            HmacPolicy::Strong,
            payload.clone(),
        );
        
        // Set HMAC (normally calculated based on packet content)
        let hmac = Bytes::from(vec![0xAA; 32]);
        packet.set_hmac(hmac.clone());
        
        // Serialize the packet
        let serialized = packet.serialize();
        
        // Expected size: 21 (header) + 32 (HMAC) + 4 (payload) = 57
        assert_eq!(serialized.len(), 57);
        
        // Check header fields
        assert_eq!(serialized[0], version_byte.as_u8());
        assert_eq!(serialized[1], PacketType::SynAck as u8);
        assert_eq!(serialized[2], 0);
        assert_eq!(serialized[3], flags.as_u8());
        
        // Check HMAC
        for i in 0..32 {
            assert_eq!(serialized[21 + i], 0xAA);
        }
        
        // Check payload
        assert_eq!(serialized[53], 1);
        assert_eq!(serialized[54], 2);
        assert_eq!(serialized[55], 3);
        assert_eq!(serialized[56], 4);
        
        // Deserialize and verify
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.packet_type().unwrap(), PacketType::SynAck);
        assert_eq!(deserialized.flags().as_u8(), flags.as_u8());
        assert_eq!(deserialized.session_id().as_u64(), 0x12345678);
        assert_eq!(deserialized.sequence_number(), 0x87654321);
        assert_eq!(deserialized.ack_number(), 0x11223344);
        assert_eq!(deserialized.timestamp().as_u32(), 0x112233);
        assert_eq!(deserialized.payload_length(), 4);
        assert_eq!(&deserialized.payload()[..], &[1, 2, 3, 4]);
        assert_eq!(&deserialized.hmac()[..], &hmac[..]);
    }
    
    #[test]
    fn test_packet_builder() {
        let payload = Bytes::from(vec![1, 2, 3, 4]);
        
        let packet = Packet::builder(PacketType::SynAck)
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(0x87654321)
            .ack_number(0x11223344)
            .timestamp(Timestamp::Bits24(0x112233))
            .payload(payload.clone())
            .build()
            .unwrap();
        
        assert_eq!(packet.packet_type().unwrap(), PacketType::SynAck);
        assert!(packet.flags().is_syn());
        assert!(packet.flags().is_ack());
        assert_eq!(packet.session_id().as_u64(), 0x12345678);
        assert_eq!(packet.sequence_number(), 0x87654321);
        assert_eq!(packet.ack_number(), 0x11223344);
        assert_eq!(packet.timestamp().as_u32(), 0x112233);
        assert_eq!(packet.payload_length(), 4);
        assert_eq!(&packet.payload()[..], &[1, 2, 3, 4]);
    }
    
    #[test]
    fn test_packet_configurations() {
        // IoT configuration
        let packet = Packet::builder(PacketType::Data)
            .iot_config()
            .session_id(SessionId::Bits16(0x1234))
            .sequence_number(1)
            .ack_number(0)
            .timestamp(Timestamp::Bits16(0x1234))
            .payload_slice(&[1, 2, 3, 4])
            .build()
            .unwrap();
        
        assert_eq!(packet.header().header_size(), 18);
        assert_eq!(packet.header().total_size(), 26);
        assert_eq!(packet.total_size(), 30);
        
        // Standard configuration
        let packet = Packet::builder(PacketType::Data)
            .standard_config()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(1)
            .ack_number(0)
            .timestamp(Timestamp::Bits24(0x123456))
            .payload_slice(&[1, 2, 3, 4])
            .build()
            .unwrap();
        
        assert_eq!(packet.header().header_size(), 21);
        assert_eq!(packet.header().total_size(), 29);
        assert_eq!(packet.total_size(), 33);
        
        // Secure configuration
        let packet = Packet::builder(PacketType::Data)
            .secure_config()
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(1)
            .ack_number(0)
            .timestamp(Timestamp::Bits24(0x123456))
            .payload_slice(&[1, 2, 3, 4])
            .build()
            .unwrap();
        
        assert_eq!(packet.header().header_size(), 21);
        assert_eq!(packet.header().total_size(), 53);
        assert_eq!(packet.total_size(), 57);
        
        // Infrastructure configuration
        let packet = Packet::builder(PacketType::Data)
            .infrastructure_config()
            .session_id(SessionId::Bits64(0x1234567890ABCDEF))
            .sequence_number(1)
            .ack_number(0)
            .timestamp(Timestamp::Bits32(0x12345678))
            .payload_slice(&[1, 2, 3, 4])
            .build()
            .unwrap();
        
        assert_eq!(packet.header().header_size(), 26);
        assert_eq!(packet.header().total_size(), 42);
        assert_eq!(packet.total_size(), 46);
    }
    
    #[test]
    fn test_zero_copy_operations() {
        let payload = Bytes::from(vec![1, 2, 3, 4]);
        
        let packet = Packet::builder(PacketType::Data)
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(1)
            .ack_number(0)
            .timestamp(Timestamp::Bits24(0x123456))
            .payload(payload.clone())
            .build()
            .unwrap();
        
        // Get a zero-copy view of the packet
        let bytes = packet.as_bytes();
        
        // Create a new packet from the bytes
        let new_packet = Packet::from_bytes(bytes).unwrap();
        
        // Verify the new packet
        assert_eq!(new_packet.packet_type().unwrap(), PacketType::Data);
        assert_eq!(new_packet.session_id().as_u64(), 0x12345678);
        assert_eq!(new_packet.sequence_number(), 1);
        assert_eq!(new_packet.ack_number(), 0);
        assert_eq!(new_packet.timestamp().as_u32(), 0x123456);
        assert_eq!(new_packet.payload_length(), 4);
        assert_eq!(&new_packet.payload()[..], &[1, 2, 3, 4]);
    }
    
    #[test]
    fn test_ebpf_serialization() {
        let payload = Bytes::from(vec![1, 2, 3, 4]);
        
        let mut packet = Packet::builder(PacketType::Data)
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(0x87654321)
            .ack_number(0x11223344)
            .timestamp(Timestamp::Bits24(0x123456))
            .payload(payload.clone())
            .build()
            .unwrap();
        
        // Set HMAC
        let hmac = Bytes::from(vec![0xAA; 8]);
        packet.set_hmac(hmac);
        
        // Serialize for eBPF
        let ebpf_bytes = packet.serialize_for_ebpf().unwrap();
        
        // Should be at least 32 bytes (metadata) + packet size, aligned to 8 bytes
        assert!(ebpf_bytes.len() >= 32 + packet.total_size());
        assert_eq!(ebpf_bytes.len() % 8, 0);
        
        // Deserialize from eBPF format
        let (deserialized_packet, metadata) = Packet::deserialize_from_ebpf(&ebpf_bytes).unwrap();
        
        // Verify metadata (copy fields to avoid packed struct issues)
        let packet_size = metadata.packet_size;
        let session_id = metadata.session_id;
        let sequence_number = metadata.sequence_number;
        let timestamp = metadata.timestamp;
        let packet_type = metadata.packet_type;
        
        assert_eq!(packet_size, packet.total_size() as u32);
        assert_eq!(session_id, 0x12345678);
        assert_eq!(sequence_number, 0x87654321);
        assert_eq!(timestamp, 0x123456);
        assert_eq!(packet_type, PacketType::Data as u8);
        
        // Verify deserialized packet
        assert_eq!(deserialized_packet.packet_type().unwrap(), PacketType::Data);
        assert_eq!(deserialized_packet.session_id().as_u64(), 0x12345678);
        assert_eq!(deserialized_packet.sequence_number(), 0x87654321);
        assert_eq!(deserialized_packet.ack_number(), 0x11223344);
        assert_eq!(deserialized_packet.timestamp().as_u32(), 0x123456);
        assert_eq!(deserialized_packet.payload_length(), 4);
        assert_eq!(&deserialized_packet.payload()[..], &[1, 2, 3, 4]);
    }
    
    #[test]
    fn test_security_metadata_generation() {
        let payload = Bytes::from(vec![1, 2, 3, 4]);
        
        let packet = Packet::builder(PacketType::Data)
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(1)
            .ack_number(0)
            .timestamp(Timestamp::Bits24(0x123456))
            .payload(payload)
            .build()
            .unwrap();
        
        let source_ip = 0x7F000001; // 127.0.0.1
        let security_metadata = packet.get_security_metadata(source_ip);
        
        assert_eq!(security_metadata.source_ip, source_ip);
        assert_eq!(security_metadata.security_class, crate::protocol::SecurityClass::Data);
        assert!(security_metadata.fragment_info.is_none());
        assert!(security_metadata.replay_validation.timestamp_window.is_valid);
        assert!(security_metadata.replay_validation.sequence_validation.is_valid);
    }
    
    #[test]
    fn test_adaptive_header_sizes() {
        // Test all combinations of session ID and timestamp configurations
        let test_cases = [
            (SessionIdLength::Bits16, TimestampConfig::Bits16, 26), // Ultra-compact
            (SessionIdLength::Bits16, TimestampConfig::Bits24, 29), // Compact
            (SessionIdLength::Bits32, TimestampConfig::Bits24, 33), // Standard
            (SessionIdLength::Bits32, TimestampConfig::Bits32, 36), // Extended
            (SessionIdLength::Bits64, TimestampConfig::Bits32, 46), // Infrastructure
        ];
        
        for (session_id_len, timestamp_config, expected_size) in test_cases {
            let version_byte = VersionByte::new(session_id_len, timestamp_config);
            let session_id = match session_id_len {
                SessionIdLength::Bits16 => SessionId::Bits16(0x1234),
                SessionIdLength::Bits32 => SessionId::Bits32(0x12345678),
                SessionIdLength::Bits64 => SessionId::Bits64(0x1234567890ABCDEF),
            };
            let timestamp = match timestamp_config {
                TimestampConfig::Bits16 => Timestamp::Bits16(0x1234),
                TimestampConfig::Bits24 | TimestampConfig::Bits24High => Timestamp::Bits24(0x123456),
                TimestampConfig::Bits32 => Timestamp::Bits32(0x12345678),
            };
            
            let packet = Packet::new(
                version_byte,
                PacketType::Data,
                0,
                PacketFlags::new(),
                session_id,
                1,
                0,
                timestamp,
                HmacPolicy::Light,
                Bytes::from(vec![1, 2, 3, 4]),
            );
            
            // Header size + HMAC size + payload size
            let actual_size = packet.total_size();
            assert_eq!(actual_size, expected_size + 4, 
                "Size mismatch for {:?}/{:?}: expected {}, got {}", 
                session_id_len, timestamp_config, expected_size + 4, actual_size);
        }
    }
    
    #[test]
    fn test_hmac_policy_adaptation() {
        // Test HMAC policy selection based on packet type
        let test_cases = [
            (PacketType::Syn, HmacPolicy::Strong, 32),
            (PacketType::SynAck, HmacPolicy::Strong, 32),
            (PacketType::Fin, HmacPolicy::Strong, 32),
            (PacketType::Discovery, HmacPolicy::Strong, 32),
            (PacketType::Error, HmacPolicy::Medium, 16),
            (PacketType::Rst, HmacPolicy::Medium, 16),
            (PacketType::Heartbeat, HmacPolicy::Medium, 16),
            (PacketType::Control, HmacPolicy::Medium, 16),
            (PacketType::Management, HmacPolicy::Medium, 16),
            (PacketType::Ack, HmacPolicy::Light, 8),
            (PacketType::Data, HmacPolicy::Light, 8),
        ];
        
        for (packet_type, expected_policy, expected_hmac_size) in test_cases {
            let actual_policy = HmacPolicy::for_packet_class(packet_type.packet_class());
            assert_eq!(actual_policy, expected_policy, 
                "HMAC policy mismatch for {:?}: expected {:?}, got {:?}", 
                packet_type, expected_policy, actual_policy);
            assert_eq!(actual_policy.len(), expected_hmac_size,
                "HMAC size mismatch for {:?}: expected {}, got {}", 
                packet_type, expected_hmac_size, actual_policy.len());
        }
    }
    
    #[test]
    fn test_concurrent_packet_access() {
        use std::sync::Arc;
        use std::thread;
        
        let packet = Arc::new(Packet::builder(PacketType::Data)
            .session_id(SessionId::Bits32(0x12345678))
            .sequence_number(1)
            .ack_number(0)
            .timestamp(Timestamp::Bits24(0x123456))
            .payload_slice(&[1, 2, 3, 4])
            .build()
            .unwrap());
        
        let mut handles = vec![];
        
        // Spawn multiple threads to access packet concurrently
        for i in 0..10 {
            let packet_clone = Arc::clone(&packet);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    // Test concurrent read access
                    assert_eq!(packet_clone.session_id().as_u64(), 0x12345678);
                    assert_eq!(packet_clone.sequence_number(), 1);
                    assert_eq!(packet_clone.timestamp().as_u32(), 0x123456);
                    assert_eq!(packet_clone.payload().len(), 4);
                    
                    // Test serialization under concurrent access
                    let _serialized = packet_clone.serialize();
                }
                i
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }
