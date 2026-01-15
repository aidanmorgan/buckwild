//! Property tests for fragmentation round-trips
//!
//! Uses proptest to verify that arbitrary payloads fragment and reassemble correctly.

use super::*;
use crate::protocol::packet::*;
use bytes::Bytes;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn roundtrip_fragmentation(
        payload_size in 0usize..102400,  // 0-100KB
        session_id in 1u64..1000000u64,
        seq_num in 0u32..1000000u32,
        mtu in 500usize..2000usize,
    ) {
        // Generate test payload with pattern that can detect corruption
        let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();
        let payload_bytes = Bytes::from(payload.clone());

        // Create test packet
        let packet = create_test_packet(session_id, seq_num, payload_bytes.clone());

        // Create fragmentation engine with rate limiting disabled for property tests
        let config = FragmentationConfig { enable_rate_limiting: false, ..Default::default() };
        let engine = FragmentationEngine::with_config(config);

        // Fragment the packet
        let frag_request = FragmentationRequest {
            session_id: SessionId::new_with_length(session_id, SessionIdLength::Bits32),
            packet,
            max_fragment_size: Some(mtu),
            source_ip: 0x7f000001,
        };

        let frag_result = engine.fragment_packet(frag_request);
        prop_assert!(frag_result.is_ok(), "Fragmentation should succeed for valid payload");

        let fragments = frag_result.unwrap();

        // Verify fragment count is reasonable
        if payload_size > 0 {
            prop_assert!(!fragments.fragments.is_empty(), "Should create at least one fragment");
        }

        // Reassemble the fragments
        let mut last_result = None;
        for (i, fragment) in fragments.fragments.iter().enumerate() {
            let reassembly_request = ReassemblyRequest {
                fragment: fragment.clone(),
                source_ip: 0x7f000001,
            };

            let result = engine.process_fragment(reassembly_request);
            prop_assert!(result.is_ok(), "Reassembly should succeed for fragment {}", i);

            last_result = Some(result.unwrap());
        }

        // Verify final result is complete
        match last_result {
            Some(ReassemblyResult::Complete { packet: reassembled, .. }) => {
                // Verify payload matches
                prop_assert_eq!(
                    reassembled.payload.as_ref(),
                    payload.as_slice(),
                    "Reassembled payload should match original"
                );

                // Verify session ID matches
                prop_assert_eq!(
                    reassembled.header.session_id().as_u64(),
                    session_id,
                    "Reassembled session ID should match original"
                );

                // Verify sequence number matches
                prop_assert_eq!(
                    reassembled.header.sequence_number().as_u32(),
                    seq_num,
                    "Reassembled sequence number should match original"
                );
            }
            Some(ReassemblyResult::InProgress { .. }) => {
                prop_assert!(false, "Reassembly should be complete after all fragments");
            }
            Some(ReassemblyResult::Rejected { reason }) => {
                prop_assert!(false, "Reassembly should not be rejected: {}", reason);
            }
            None => {
                prop_assert!(false, "Should have reassembly result");
            }
        }
    }

    #[test]
    fn roundtrip_fragmentation_out_of_order(
        payload_size in 1000usize..10240usize,  // 1-10KB to ensure multiple fragments
        session_id in 1u64..1000000u64,
        seq_num in 0u32..1000000u32,
        mtu in 500usize..1000usize,  // Smaller MTU to ensure fragmentation
    ) {
        // Generate test payload
        let payload: Vec<u8> = (0..payload_size).map(|i| ((i * 7) % 256) as u8).collect();
        let payload_bytes = Bytes::from(payload.clone());

        // Create test packet
        let packet = create_test_packet(session_id, seq_num, payload_bytes.clone());

        // Create fragmentation engine with rate limiting disabled for property tests
        let config = FragmentationConfig { enable_rate_limiting: false, ..Default::default() };
        let engine = FragmentationEngine::with_config(config);

        // Fragment the packet
        let frag_request = FragmentationRequest {
            session_id: SessionId::new_with_length(session_id, SessionIdLength::Bits32),
            packet,
            max_fragment_size: Some(mtu),
            source_ip: 0x7f000001,
        };

        let frag_result = engine.fragment_packet(frag_request);
        prop_assert!(frag_result.is_ok(), "Fragmentation should succeed");

        let mut fragments = frag_result.unwrap().fragments;

        // Only test out-of-order if we have multiple fragments
        prop_assume!(fragments.len() >= 2);

        // Reverse fragment order
        fragments.reverse();

        // Reassemble in reverse order
        let mut last_result = None;
        for (i, fragment) in fragments.iter().enumerate() {
            let reassembly_request = ReassemblyRequest {
                fragment: fragment.clone(),
                source_ip: 0x7f000001,
            };

            let result = engine.process_fragment(reassembly_request);
            prop_assert!(result.is_ok(), "Reassembly should succeed for fragment {}", i);

            last_result = Some(result.unwrap());
        }

        // Verify reassembly completed successfully
        match last_result {
            Some(ReassemblyResult::Complete { packet: reassembled, .. }) => {
                prop_assert_eq!(
                    reassembled.payload.as_ref(),
                    payload.as_slice(),
                    "Out-of-order reassembly should produce correct payload"
                );
            }
            Some(ReassemblyResult::InProgress { .. }) => {
                prop_assert!(false, "Reassembly should be complete after all fragments");
            }
            Some(ReassemblyResult::Rejected { reason }) => {
                prop_assert!(false, "Reassembly should not be rejected: {}", reason);
            }
            None => {
                prop_assert!(false, "Should have reassembly result");
            }
        }
    }
}

/// Helper function to create a test data packet
fn create_test_packet(session_id: u64, seq: u32, payload: Bytes) -> DataPacket {
    let header = PacketHeader::new(
        VersionByte::new(0x01, SessionIdLength::Bits32, TimestampConfig::Bits24),
        PacketType::Data,
        SubType::new(0),
        PacketFlags::new(),
        SessionId::new_with_length(session_id, SessionIdLength::Bits32),
        SequenceNumber::new(seq),
        AckNumber::new(0),
        Timestamp::now(),
        PayloadLength::new(payload.len() as u16),
        HmacPolicy::Medium,
    );

    DataPacket {
        header,
        hmac: HmacTag::default(),
        window_size: WindowSize::new(65536),
        fragment_header: None,
        payload,
    }
}
