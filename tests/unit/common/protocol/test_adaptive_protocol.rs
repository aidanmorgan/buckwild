// Comprehensive unit tests for adaptive protocol data structures with enhanced security features
//
// This file tests all adaptive configurations, security features, and concurrent access
// patterns for the protocol implementation.

use std::sync::Arc;
use std::thread;
use std::time::Duration;
use bytes::Bytes;

use buckwild_common::protocol::{
    packet::{Packet, EbpfPacketMetadata},
    header::{PacketHeader, SessionId, Timestamp},
    types::{
        PacketType, PacketFlags, VersionByte, SessionIdLength, TimestampConfig, 
        HmacPolicy, PacketClass, config
    },
    security::{SecurityValidator, SecurityMetadata, SecurityClass, EpochType},
    validation::PacketValidator,
};

#[test]
fn test_adaptive_header_configurations() {
    // Test all combinations of session ID and timestamp configurations
    let test_cases = [
        // (SessionIdLength, TimestampConfig, Expected header size, Expected total size with LIGHT HMAC)
        (SessionIdLength::Bits16, TimestampConfig::Bits16, 18, 26), // Ultra-compact
        (SessionIdLength::Bits16, TimestampConfig::Bits24, 19, 27), // Compact
        (SessionIdLength::Bits32, TimestampConfig::Bits16, 20, 28), // Standard-compact
        (SessionIdLength::Bits32, TimestampConfig::Bits24, 21, 29), // Standard
        (SessionIdLength::Bits32, TimestampConfig::Bits32, 22, 30), // Standard-extended
        (SessionIdLength::Bits64, TimestampConfig::Bits16, 24, 32), // Enterprise-compact
        (SessionIdLength::Bits64, TimestampConfig::Bits24, 25, 33), // Enterprise
        (SessionIdLength::Bits64, TimestampConfig::Bits32, 26, 34), // Infrastructure
    ];
    
    for (session_id_len, timestamp_config, expected_header_size, expected_total_size) in test_cases {
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
        
        let header = PacketHeader::new(
            version_byte,
            PacketType::Data,
            0,
            PacketFlags::new(),
            session_id,
            1,
            0,
            timestamp,
            0,
            HmacPolicy::Light,
        );
        
        assert_eq!(
            header.header_size(),
            expected_header_size,
            "Header size mismatch for {:?}/{:?}",
            session_id_len,
            timestamp_config
        );
        
        assert_eq!(
            header.total_size(),
            expected_total_size,
            "Total size mismatch for {:?}/{:?}",
            session_id_len,
            timestamp_config
        );
    }
}

#[test]
fn test_three_tier_hmac_policies() {
    let test_cases = [
        (PacketType::Syn, PacketClass::Critical, HmacPolicy::Strong, 32),
        (PacketType::SynAck, PacketClass::Critical, HmacPolicy::Strong, 32),
        (PacketType::Fin, PacketClass::Critical, HmacPolicy::Strong, 32),
        (PacketType::Discovery, PacketClass::Critical, HmacPolicy::Strong, 32),
        (PacketType::Error, PacketClass::Control, HmacPolicy::Medium, 16),
        (PacketType::Rst, PacketClass::Control, HmacPolicy::Medium, 16),
        (PacketType::Heartbeat, PacketClass::Control, HmacPolicy::Medium, 16),
        (PacketType::Control, PacketClass::Control, HmacPolicy::Medium, 16),
        (PacketType::Management, PacketClass::Control, HmacPolicy::Medium, 16),
        (PacketType::Ack, PacketClass::Data, HmacPolicy::Light, 8),
        (PacketType::Data, PacketClass::Data, HmacPolicy::Light, 8),
    ];
    
    for (packet_type, expected_class, expected_policy, expected_hmac_len) in test_cases {
        // Test packet class determination
        assert_eq!(
            packet_type.packet_class(),
            expected_class,
            "Packet class mismatch for {:?}",
            packet_type
        );
        
        // Test HMAC policy for packet class
        assert_eq!(
            HmacPolicy::for_packet_class(expected_class),
            expected_policy,
            "HMAC policy mismatch for {:?}",
            expected_class
        );
        
        // Test HMAC length
        assert_eq!(
            expected_policy.len(),
            expected_hmac_len,
            "HMAC length mismatch for {:?}",
            expected_policy
        );
        
        // Test adaptive HMAC policy in header
        let header = PacketHeader::new(
            VersionByte::default(),
            packet_type,
            0,
            PacketFlags::new(),
            SessionId::Bits32(1),
            1,
            0,
            Timestamp::Bits24(1),
            0,
            HmacPolicy::Light, // Base policy
        );
        
        assert_eq!(
            header.adaptive_hmac_policy(),
            expected_policy,
            "Adaptive HMAC policy mismatch for {:?}",
            packet_type
        );
    }
}

#[test]
fn test_version_byte_encoding() {
    let test_cases = [
        // (SessionIdLength, TimestampConfig, Expected encoding)
        (SessionIdLength::Bits16, TimestampConfig::Bits16, 0x01), // v1 + 16-bit ID + 16-bit TS
        (SessionIdLength::Bits32, TimestampConfig::Bits16, 0x11), // v1 + 32-bit ID + 16-bit TS
        (SessionIdLength::Bits64, TimestampConfig::Bits16, 0x21), // v1 + 64-bit ID + 16-bit TS
        (SessionIdLength::Bits32, TimestampConfig::Bits24, 0x51), // v1 + 32-bit ID + 24-bit TS
        (SessionIdLength::Bits32, TimestampConfig::Bits32, 0x91), // v1 + 32-bit ID + 32-bit TS
    ];
    
    for (session_id_len, timestamp_config, expected_encoding) in test_cases {
        let version_byte = VersionByte::new(session_id_len, timestamp_config);
        
        assert_eq!(
            version_byte.as_u8(),
            expected_encoding,
            "Version byte encoding mismatch for {:?}/{:?}",
            session_id_len,
            timestamp_config
        );
        
        // Test round-trip encoding/decoding
        let decoded = VersionByte::from_u8(expected_encoding);
        assert_eq!(decoded.session_id_length(), session_id_len);
        assert_eq!(decoded.timestamp_config(), timestamp_config);
        assert!(decoded.is_supported_version());
    }
}

#[test]
fn test_deployment_configurations() {
    // Test IoT configuration (ultra-compact)
    let (iot_version, iot_hmac) = config::iot_config();
    assert_eq!(iot_version.session_id_length(), SessionIdLength::Bits16);
    assert_eq!(iot_version.timestamp_config(), TimestampConfig::Bits16);
    assert_eq!(iot_hmac, HmacPolicy::Light);
    
    let iot_packet = Packet::builder(PacketType::Data)
        .iot_config()
        .session_id(SessionId::Bits16(0x1234))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits16(0x1234))
        .payload_slice(&[1, 2, 3, 4])
        .build()
        .unwrap();
    
    assert_eq!(iot_packet.header().header_size(), 18);
    assert_eq!(iot_packet.header().total_size(), 26);
    assert_eq!(iot_packet.total_size(), 30);
    
    // Test standard configuration
    let (std_version, std_hmac) = config::standard_config();
    assert_eq!(std_version.session_id_length(), SessionIdLength::Bits32);
    assert_eq!(std_version.timestamp_config(), TimestampConfig::Bits24);
    assert_eq!(std_hmac, HmacPolicy::Light);
    
    let std_packet = Packet::builder(PacketType::Data)
        .standard_config()
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload_slice(&[1, 2, 3, 4])
        .build()
        .unwrap();
    
    assert_eq!(std_packet.header().header_size(), 21);
    assert_eq!(std_packet.header().total_size(), 29);
    assert_eq!(std_packet.total_size(), 33);
    
    // Test secure configuration
    let (sec_version, sec_hmac) = config::secure_config();
    assert_eq!(sec_version.session_id_length(), SessionIdLength::Bits32);
    assert_eq!(sec_version.timestamp_config(), TimestampConfig::Bits24);
    assert_eq!(sec_hmac, HmacPolicy::Strong);
    
    let sec_packet = Packet::builder(PacketType::Data)
        .secure_config()
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload_slice(&[1, 2, 3, 4])
        .build()
        .unwrap();
    
    assert_eq!(sec_packet.header().header_size(), 21);
    assert_eq!(sec_packet.header().total_size(), 53);
    assert_eq!(sec_packet.total_size(), 57);
    
    // Test infrastructure configuration
    let (infra_version, infra_hmac) = config::infrastructure_config();
    assert_eq!(infra_version.session_id_length(), SessionIdLength::Bits64);
    assert_eq!(infra_version.timestamp_config(), TimestampConfig::Bits32);
    assert_eq!(infra_hmac, HmacPolicy::Medium);
    
    let infra_packet = Packet::builder(PacketType::Data)
        .infrastructure_config()
        .session_id(SessionId::Bits64(0x1234567890ABCDEF))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits32(0x12345678))
        .payload_slice(&[1, 2, 3, 4])
        .build()
        .unwrap();
    
    assert_eq!(infra_packet.header().header_size(), 26);
    assert_eq!(infra_packet.header().total_size(), 42);
    assert_eq!(infra_packet.total_size(), 46);
}

#[test]
fn test_dual_epoch_timestamp_handling() {
    // Test daily epoch for connection establishment packets
    let syn_packet = Packet::builder(PacketType::Syn)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload_slice(&[])
        .build()
        .unwrap();
    
    assert_eq!(syn_packet.header().epoch_type(), EpochType::Daily);
    
    let syn_ack_packet = Packet::builder(PacketType::SynAck)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(2)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload_slice(&[])
        .build()
        .unwrap();
    
    assert_eq!(syn_ack_packet.header().epoch_type(), EpochType::Daily);
    
    // Test monthly epoch for session packets
    let data_packet = Packet::builder(PacketType::Data)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload_slice(&[1, 2, 3, 4])
        .build()
        .unwrap();
    
    assert_eq!(data_packet.header().epoch_type(), EpochType::Monthly);
    
    let ack_packet = Packet::builder(PacketType::Ack)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(2)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload_slice(&[])
        .build()
        .unwrap();
    
    assert_eq!(ack_packet.header().epoch_type(), EpochType::Monthly);
}

#[test]
fn test_security_hardening_features() {
    let validator = SecurityValidator::new();
    
    // Test fragment bomb prevention
    let fragment_packet = Packet::builder(PacketType::Data)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits24(0x123456))
        .flag(PacketFlags::FRAG)
        .payload_slice(&[
            0x00, 0x01, // Fragment ID
            0x00, 0x00, // Fragment index
            0x00, 0x02, // Total fragments
            0x00, 0x00, // Reserved
            1, 2, 3, 4, // Actual payload
        ])
        .build()
        .unwrap();
    
    let source_ip = 0x7F000001; // 127.0.0.1
    let security_metadata = fragment_packet.get_security_metadata(source_ip);
    
    assert_eq!(security_metadata.security_class, SecurityClass::Data);
    assert!(security_metadata.fragment_info.is_some());
    
    let fragment_info = security_metadata.fragment_info.unwrap();
    assert_eq!(fragment_info.fragment_id, 1);
    assert_eq!(fragment_info.fragment_index, 0);
    assert_eq!(fragment_info.total_fragments, 2);
    assert_eq!(fragment_info.payload_size, 4); // Payload minus fragment header
    assert_eq!(fragment_info.session_binding.as_u64(), 0x12345678);
    
    // Test security validation
    assert!(validator.validate_security(&security_metadata).is_ok());
}

#[test]
fn test_lock_free_packet_validation() {
    let validator = Arc::new(PacketValidator::new());
    let mut handles = vec![];
    
    // Test concurrent validation with different configurations
    for thread_id in 0..8 {
        let validator_clone = Arc::clone(&validator);
        let handle = thread::spawn(move || {
            let configs = [
                config::iot_config(),
                config::standard_config(),
                config::secure_config(),
                config::infrastructure_config(),
            ];
            
            for (i, (version_byte, hmac_policy)) in configs.iter().enumerate() {
                for j in 0..25 {
                    let session_id = match version_byte.session_id_length() {
                        SessionIdLength::Bits16 => SessionId::Bits16((thread_id * 1000 + i * 100 + j) as u16),
                        SessionIdLength::Bits32 => SessionId::Bits32((thread_id * 1000 + i * 100 + j) as u32),
                        SessionIdLength::Bits64 => SessionId::Bits64((thread_id * 1000 + i * 100 + j) as u64),
                    };
                    
                    let timestamp = match version_byte.timestamp_config() {
                        TimestampConfig::Bits16 => Timestamp::Bits16((j * 1000) as u16),
                        TimestampConfig::Bits24 | TimestampConfig::Bits24High => Timestamp::Bits24((j * 1000) as u32),
                        TimestampConfig::Bits32 => Timestamp::Bits32((j * 1000) as u32),
                    };
                    
                    let packet = Packet::new(
                        *version_byte,
                        PacketType::Data,
                        0,
                        PacketFlags::new(),
                        session_id,
                        j as u32,
                        0,
                        timestamp,
                        *hmac_policy,
                        Bytes::from(vec![1, 2, 3, 4]),
                    );
                    
                    // Validate the packet
                    assert!(validator_clone.validate(&packet).is_ok());
                }
            }
            thread_id
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Check that all packets were processed (8 threads * 4 configs * 25 packets)
    assert_eq!(validator.packets_processed(), 800);
    assert_eq!(validator.validation_errors(), 0);
}

#[test]
fn test_memory_mapped_ebpf_serialization() {
    let packet = Packet::builder(PacketType::Data)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(0x87654321)
        .ack_number(0x11223344)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload_slice(&[1, 2, 3, 4])
        .build()
        .unwrap();
    
    let source_ip = 0x7F000001; // 127.0.0.1
    
    // Test eBPF serialization with source IP
    let ebpf_bytes = packet.serialize_for_ebpf_with_source(source_ip).unwrap();
    
    // Should be at least 32 bytes (metadata) + packet size, aligned to 8 bytes
    assert!(ebpf_bytes.len() >= 32 + packet.total_size());
    assert_eq!(ebpf_bytes.len() % 8, 0);
    
    // Deserialize and verify
    let (deserialized_packet, metadata) = Packet::deserialize_from_ebpf(&ebpf_bytes).unwrap();
    
    // Verify metadata
    assert_eq!(metadata.packet_size, packet.total_size() as u32);
    assert_eq!(metadata.session_id, 0x12345678);
    assert_eq!(metadata.sequence_number, 0x87654321);
    assert_eq!(metadata.timestamp, 0x123456);
    assert_eq!(metadata.packet_type, PacketType::Data as u8);
    assert_eq!(metadata.source_ip, source_ip);
    assert_eq!(metadata.epoch_type, EpochType::Monthly as u8);
    
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
fn test_atomic_bounds_checking() {
    let validator = PacketValidator::new();
    
    // Test with various invalid packets
    let invalid_cases = [
        // Invalid version
        (0xF2, PacketType::Data as u8, 0x00, 0x00),
        // Invalid packet type
        (0x01, 0xFF, 0x00, 0x00),
        // Valid header
        (0x01, PacketType::Data as u8, 0x00, 0x00),
    ];
    
    for (version, packet_type, sub_type, flags) in invalid_cases {
        let buffer = [version, packet_type, sub_type, flags, 0, 0, 0, 0];
        
        let result = validator.validate_buffer(&buffer);
        
        if version != 0x01 {
            assert!(result.is_err(), "Should fail for invalid version");
        } else if packet_type == 0xFF {
            assert!(result.is_err(), "Should fail for invalid packet type");
        } else {
            assert!(result.is_ok(), "Should pass for valid header");
        }
    }
}

#[test]
fn test_concurrent_security_validation() {
    let validator = Arc::new(PacketValidator::new());
    let mut handles = vec![];
    
    // Test concurrent security validation
    for thread_id in 0..4 {
        let validator_clone = Arc::clone(&validator);
        let handle = thread::spawn(move || {
            for i in 0..50 {
                let packet = Packet::builder(PacketType::Data)
                    .session_id(SessionId::Bits32((thread_id * 1000 + i) as u32))
                    .sequence_number(i as u32)
                    .ack_number(0)
                    .timestamp(Timestamp::Bits24(0x123456))
                    .payload_slice(&[1, 2, 3, 4])
                    .build()
                    .unwrap();
                
                let source_ip = 0x7F000001 + thread_id as u32;
                
                // First validation should pass
                assert!(validator_clone.validate_with_security(&packet, source_ip).is_ok());
                
                // Second validation with same packet should fail (duplicate detection)
                let result = validator_clone.validate_with_security(&packet, source_ip);
                assert!(result.is_err(), "Duplicate packet should be rejected");
            }
            thread_id
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Check security statistics
    let security_stats = validator.security_validator().get_security_stats();
    assert_eq!(security_stats.replay_attacks, 200); // 4 threads * 50 duplicates
}

#[test]
fn test_adaptive_hmac_escalation() {
    let header = PacketHeader::new(
        VersionByte::default(),
        PacketType::Data,
        0,
        PacketFlags::new(),
        SessionId::Bits32(1),
        1,
        0,
        Timestamp::Bits24(1),
        0,
        HmacPolicy::Light,
    );
    
    // Initially should use light HMAC for data packets
    assert_eq!(header.adaptive_hmac_policy(), HmacPolicy::Light);
    assert!(!header.requires_strong_hmac());
    
    // Escalate to strong HMAC
    header.set_requires_strong_hmac(true);
    assert_eq!(header.adaptive_hmac_policy(), HmacPolicy::Strong);
    assert!(header.requires_strong_hmac());
    
    // De-escalate
    header.set_requires_strong_hmac(false);
    assert_eq!(header.adaptive_hmac_policy(), HmacPolicy::Light);
    assert!(!header.requires_strong_hmac());
}

#[test]
fn test_cache_line_alignment() {
    let header = PacketHeader::new(
        VersionByte::default(),
        PacketType::Data,
        0,
        PacketFlags::new(),
        SessionId::Bits32(1),
        1,
        0,
        Timestamp::Bits24(1),
        0,
        HmacPolicy::Light,
    );
    
    // Verify cache line alignment (64 bytes)
    assert_eq!(std::mem::align_of_val(&header), 64);
    assert_eq!(std::mem::size_of_val(&header), 128); // Two cache lines
}

#[test]
fn test_zero_copy_operations() {
    let original_payload = Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    
    let packet = Packet::builder(PacketType::Data)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload(original_payload.clone())
        .build()
        .unwrap();
    
    // Verify zero-copy payload handling
    assert_eq!(packet.payload().len(), original_payload.len());
    
    // Get zero-copy view
    let packet_bytes = packet.as_bytes();
    
    // Create new packet from bytes (should be zero-copy)
    let new_packet = Packet::from_bytes(packet_bytes).unwrap();
    
    // Verify the new packet
    assert_eq!(new_packet.packet_type().unwrap(), PacketType::Data);
    assert_eq!(new_packet.session_id().as_u64(), 0x12345678);
    assert_eq!(new_packet.sequence_number(), 1);
    assert_eq!(new_packet.payload().len(), original_payload.len());
    assert_eq!(&new_packet.payload()[..], &original_payload[..]);
}

#[test]
fn test_security_metadata_generation() {
    let packet = Packet::builder(PacketType::Syn)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(1)
        .ack_number(0)
        .timestamp(Timestamp::Bits24(0x123456))
        .payload_slice(&[])
        .build()
        .unwrap();
    
    let source_ip = 0x7F000001;
    let metadata = packet.get_security_metadata(source_ip);
    
    // Verify security classification
    assert_eq!(metadata.security_class, SecurityClass::Critical);
    assert_eq!(metadata.source_ip, source_ip);
    
    // Verify HMAC policy override for critical packets
    assert_eq!(metadata.hmac_policy_override, Some(HmacPolicy::Strong));
    
    // Verify dual-epoch timestamp validation
    assert_eq!(metadata.replay_validation.timestamp_window.epoch_type, EpochType::Daily);
    
    // Verify composite key generation
    assert_ne!(metadata.replay_validation.composite_key, 0);
}

#[test]
fn test_packet_builder_fluent_api() {
    // Test fluent API with all configurations
    let packet = Packet::builder(PacketType::Data)
        .sub_type(0x01)
        .flag(PacketFlags::PSH)
        .flag(PacketFlags::ACK)
        .session_id(SessionId::Bits32(0x12345678))
        .sequence_number(0x87654321)
        .ack_number(0x11223344)
        .timestamp(Timestamp::Bits24(0x123456))
        .hmac_policy(HmacPolicy::Medium)
        .payload_slice(&[1, 2, 3, 4, 5, 6, 7, 8])
        .build()
        .unwrap();
    
    assert_eq!(packet.packet_type().unwrap(), PacketType::Data);
    assert_eq!(packet.header().sub_type(), 0x01);
    assert!(packet.flags().is_psh());
    assert!(packet.flags().is_ack());
    assert_eq!(packet.session_id().as_u64(), 0x12345678);
    assert_eq!(packet.sequence_number(), 0x87654321);
    assert_eq!(packet.ack_number(), 0x11223344);
    assert_eq!(packet.timestamp().as_u32(), 0x123456);
    assert_eq!(packet.payload().len(), 8);
    assert_eq!(&packet.payload()[..], &[1, 2, 3, 4, 5, 6, 7, 8]);
}