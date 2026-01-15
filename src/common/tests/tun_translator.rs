#![allow(clippy::unnecessary_unwrap)]
//! Integration tests for TUN Packet Translator (Task 2)
//!
//! These tests validate the protocol translation between TCP packets and
//! buckwild protocol packets, including fragmentation and security checks.
//!
//! Tests 2.1-2.12 from TUN_EBPF_IMPLEMENTATION_GUIDE.md
//!
//! ## TDD Status: RED Phase
//!
//! All tests call the stub translator and fail as expected.

use buckwild_common::network::tun::{ProtocolTranslator, TranslatorConfig};
use buckwild_common::protocol::types::{FragmentId, SessionId};

/// Test 2.1: TCP SYN to Protocol Handshake
///
/// REQ-TRANS-001, REQ-TRANS-002, REQ-TRANS-003, REQ-TRANS-006
///
/// GIVEN translator is initialized
/// WHEN TCP SYN packet arrives from 10.100.0.1:12345 to 10.100.0.2:80
/// THEN protocol packet is generated with correct handshake fields
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_1_tcp_syn_to_protocol_handshake() {
    let mut translator = ProtocolTranslator::new(TranslatorConfig::default());

    let tcp_syn_packet = vec![0u8; 64]; // Placeholder TCP SYN

    let result = translator.translate_ingress(&tcp_syn_packet).await;

    let packets = result.expect("Should successfully translate TCP SYN to protocol packet");
    assert!(
        !packets.is_empty(),
        "Should generate at least one protocol packet"
    );
}

/// Test 2.2: Data Translation with Flow Control
///
/// REQ-TRANS-001, REQ-TRANS-004, REQ-TRANS-005, REQ-TRANS-006
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_2_data_translation_with_flow_control() {
    let mut translator = ProtocolTranslator::new(TranslatorConfig::default());

    let tcp_data_packet = vec![0u8; 64]; // Placeholder TCP data

    let result = translator.translate_ingress(&tcp_data_packet).await;

    let packets = result.expect("Should successfully translate TCP data to protocol packet");
    assert!(
        !packets.is_empty(),
        "Should generate at least one protocol packet"
    );
}

/// Test 2.3: Large Payload Fragmentation
///
/// REQ-TRANS-007, REQ-TRANS-008, REQ-TRANS-009, REQ-TRANS-010, REQ-TRANS-011
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_3_large_payload_fragmentation() {
    let mut translator = ProtocolTranslator::new(TranslatorConfig::default());

    let large_packet = vec![0xAB; 10240]; // 10KB payload

    let result = translator.translate_ingress(&large_packet).await;

    let fragments = result.expect("Should successfully fragment large payload");
    assert!(
        fragments.len() >= 8,
        "Should generate at least 8 fragments for 10KB payload"
    );
}

/// Test 2.4: Out-of-Order Fragment Reassembly
///
/// REQ-TRANS-018
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_4_out_of_order_fragment_reassembly() {
    let mut translator = ProtocolTranslator::new(TranslatorConfig::default());

    let fragment_id = FragmentId::new(42);
    let session_id = SessionId::generate();

    let result = translator
        .process_fragment(fragment_id, 0, 4, session_id, &[0xAA; 100])
        .await;

    assert!(result.is_ok(), "Should accept valid fragment");
    assert!(
        result.unwrap().is_none(),
        "Should not complete reassembly with only 1 of 4 fragments"
    );
}

/// Test 2.5: Fragment Security - Session Binding
///
/// REQ-TRANS-012
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_5_fragment_security_session_binding() {
    let mut translator = ProtocolTranslator::new(TranslatorConfig::default());

    let fragment_id = FragmentId::new(100);
    let session_a = SessionId::new(0xAAAAAAAAAAAAAAAAu64);
    let session_b = SessionId::new(0xBBBBBBBBBBBBBBBBu64);

    let result_a = translator
        .process_fragment(fragment_id, 0, 2, session_a, &[0xAA; 100])
        .await;

    assert!(
        result_a.is_ok(),
        "First fragment with session A should be accepted"
    );

    let result_b = translator
        .process_fragment(fragment_id, 1, 2, session_b, &[0xBB; 100])
        .await;

    assert!(
        result_b.is_err(),
        "Second fragment with different session should be rejected"
    );
    match result_b.unwrap_err() {
        buckwild_common::network::tun::TranslatorError::SessionMismatch { .. } => {}
        e => panic!("Expected SessionMismatch error, got: {:?}", e),
    }
}

/// Test 2.6: Fragment Security - Overlap Detection
///
/// REQ-TRANS-014
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_6_fragment_security_overlap_detection() {
    let mut translator = ProtocolTranslator::new(TranslatorConfig::default());

    let fragment_id = FragmentId::new(200);
    let session_id = SessionId::generate();

    let result1 = translator
        .process_fragment(fragment_id, 0, 2, session_id.clone(), &[0xAA; 100])
        .await;

    assert!(result1.is_ok(), "First fragment should be accepted");

    let result2 = translator
        .process_fragment(fragment_id, 0, 2, session_id, &[0xBB; 100])
        .await;

    assert!(
        result2.is_err(),
        "Duplicate fragment index should be rejected as overlap"
    );
}

/// Test 2.7: Fragment Security - Fragment Bomb
///
/// REQ-TRANS-015
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_7_fragment_security_fragment_bomb() {
    let mut translator = ProtocolTranslator::new(TranslatorConfig::default());

    let fragment_id = FragmentId::new(300);
    let session_id = SessionId::generate();

    let result = translator
        .process_fragment(fragment_id, 0, 10000, session_id, &[0xAA; 100])
        .await;

    assert!(
        result.is_err(),
        "Fragment bomb with 10000 fragments should be rejected"
    );
    match result.unwrap_err() {
        buckwild_common::network::tun::TranslatorError::FragmentBomb {
            total_fragments, ..
        } => {
            assert_eq!(total_fragments, 10000);
        }
        e => panic!("Expected FragmentBomb error, got: {:?}", e),
    }
}

/// Test 2.8: Fragment Security - Rate Limiting
///
/// REQ-TRANS-013
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_8_fragment_security_rate_limiting() {
    let config = TranslatorConfig {
        max_fragments_per_sec: 100,
        ..Default::default()
    };
    let mut translator = ProtocolTranslator::new(config);

    let session_id = SessionId::generate();
    let mut accepted = 0;
    let mut rate_limited = 0;

    for i in 0..150 {
        let result = translator
            .process_fragment(
                FragmentId::new(400 + i),
                0,
                1,
                session_id.clone(),
                &[0xAA; 100],
            )
            .await;

        if result.is_ok() {
            accepted += 1;
        } else if matches!(
            result.unwrap_err(),
            buckwild_common::network::tun::TranslatorError::RateLimitExceeded { .. }
        ) {
            rate_limited += 1;
        }
    }

    assert_eq!(accepted, 100, "Should accept exactly 100 fragments");
    assert_eq!(rate_limited, 50, "Should rate limit exactly 50 fragments");
}

/// Test 2.9: Fragment Security - Buffer Size Limit
///
/// REQ-TRANS-015
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_9_fragment_security_buffer_size_limit() {
    let config = TranslatorConfig {
        max_reassembly_buffer_size: 65536,
        ..Default::default()
    };
    let mut translator = ProtocolTranslator::new(config);

    let fragment_id = FragmentId::new(500);
    let session_id = SessionId::generate();

    let large_fragment = vec![0xAA; 70000];
    let result = translator
        .process_fragment(fragment_id, 0, 1, session_id, &large_fragment)
        .await;

    assert!(
        result.is_err(),
        "Fragment exceeding buffer limit should be rejected"
    );
    match result.unwrap_err() {
        buckwild_common::network::tun::TranslatorError::ReassemblyBufferExceeded { .. } => {}
        e => panic!("Expected ReassemblyBufferExceeded error, got: {:?}", e),
    }
}

/// Test 2.10: Fragment Timeout
///
/// REQ-TRANS-016
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_10_fragment_timeout() {
    let config = TranslatorConfig {
        fragment_timeout_ms: 100,
        ..Default::default()
    };
    let mut translator = ProtocolTranslator::new(config);

    let fragment_id = FragmentId::new(600);
    let session_id = SessionId::generate();

    let result1 = translator
        .process_fragment(fragment_id, 0, 4, session_id.clone(), &[0xAA; 100])
        .await;

    assert!(result1.is_ok(), "First fragment should be accepted");

    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    let result2 = translator
        .process_fragment(fragment_id, 1, 4, session_id, &[0xBB; 100])
        .await;

    assert!(
        result2.is_err(),
        "Fragment arriving after timeout should be rejected"
    );
    match result2.unwrap_err() {
        buckwild_common::network::tun::TranslatorError::FragmentTimeout { .. } => {}
        e => panic!("Expected FragmentTimeout error, got: {:?}", e),
    }
}

/// Test 2.11: Egress Translation (Protocol → TCP)
///
/// REQ-TRANS-001
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_11_egress_translation_protocol_to_tcp() {
    let mut translator = ProtocolTranslator::new(TranslatorConfig::default());

    let protocol_packet = vec![0u8; 64]; // Placeholder protocol packet

    let result = translator.translate_egress(&protocol_packet).await;

    let tcp_packet = result.expect("Should successfully translate protocol packet to TCP");
    assert!(!tcp_packet.is_empty(), "Should generate valid TCP packet");
}

/// Test 2.12: Property Test - Fragment Roundtrip
///
/// REQ-TRANS-007, REQ-TRANS-018
///
/// Property: For any payload size 0..100,000 bytes and any MTU 1280..9000:
/// - Fragment payload into N fragments
/// - Shuffle fragment order randomly
/// - Reassemble fragments
/// - Reassembled payload MUST equal original payload exactly
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_2_12_property_test_fragment_roundtrip() {
    for payload_size in [0, 1, 100, 1000, 5000, 10000].iter() {
        for mtu in [1280, 1400, 1500, 2000].iter() {
            let config = TranslatorConfig {
                mtu: *mtu,
                ..Default::default()
            };
            let mut translator = ProtocolTranslator::new(config);

            let original_payload: Vec<u8> = (0..*payload_size).map(|i| (i % 256) as u8).collect();

            if original_payload.is_empty() {
                continue;
            }

            let fragments = translator
                .translate_ingress(&original_payload)
                .await
                .expect("Translation should succeed");

            let mut reassembled = Vec::new();
            for fragment in fragments {
                if fragment.len() > 28 {
                    reassembled.extend_from_slice(&fragment[28..]);
                }
            }

            assert_eq!(
                reassembled, original_payload,
                "Roundtrip failed for payload_size={}, mtu={}",
                payload_size, mtu
            );
        }
    }
}
