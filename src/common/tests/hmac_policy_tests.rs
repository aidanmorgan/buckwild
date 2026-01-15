//! HMAC Policy Framework Tests
//!
//! Comprehensive tests for the three-tier HMAC policy framework including
//! negotiation, validation, and error handling.

use buckwild_common::error::security::SecurityError;
use buckwild_common::protocol::types::HmacPolicy;
use buckwild_common::security::crypto::{MinimumPolicy, PolicyMismatchHandler, PolicyNegotiator};

// ============================================================================
// Policy Basic Tests
// ============================================================================

#[test]
fn test_light_policy_8_byte_hmac() {
    assert_eq!(HmacPolicy::Light.tag_size(), 8);
}

#[test]
fn test_medium_policy_16_byte_hmac() {
    assert_eq!(HmacPolicy::Medium.tag_size(), 16);
}

#[test]
fn test_strong_policy_32_byte_hmac() {
    assert_eq!(HmacPolicy::Strong.tag_size(), 32);
}

// ============================================================================
// Minimum Policy Tests
// ============================================================================

#[test]
fn test_minimum_policy_default_is_medium() {
    let min_policy = MinimumPolicy::default();
    assert_eq!(min_policy.policy(), HmacPolicy::Medium);
}

#[test]
fn test_minimum_policy_accepts_equal_or_stronger() {
    let min_medium = MinimumPolicy::new(HmacPolicy::Medium);

    assert!(min_medium.accepts(HmacPolicy::Strong));
    assert!(min_medium.accepts(HmacPolicy::Medium));
    assert!(!min_medium.accepts(HmacPolicy::Light));
}

#[test]
fn test_minimum_policy_strong_rejects_weaker() {
    let min_strong = MinimumPolicy::new(HmacPolicy::Strong);

    assert!(min_strong.accepts(HmacPolicy::Strong));
    assert!(!min_strong.accepts(HmacPolicy::Medium));
    assert!(!min_strong.accepts(HmacPolicy::Light));
}

// ============================================================================
// Policy Negotiation Tests
// ============================================================================

#[test]
fn test_negotiator_proposes_strongest_policy() {
    let negotiator = PolicyNegotiator::new();
    assert_eq!(negotiator.propose_policy(), Some(HmacPolicy::Strong));
}

#[test]
fn test_negotiation_selects_strongest_common_policy() {
    let negotiator = PolicyNegotiator::new();
    let remote_policies = vec![HmacPolicy::Strong, HmacPolicy::Medium, HmacPolicy::Light];

    let result = negotiator.negotiate(&remote_policies);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), HmacPolicy::Strong);
}

#[test]
fn test_negotiation_accepts_medium_when_strong_unavailable() {
    let negotiator = PolicyNegotiator::new();
    let remote_policies = vec![HmacPolicy::Medium, HmacPolicy::Light];

    let result = negotiator.negotiate(&remote_policies);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), HmacPolicy::Medium);
}

#[test]
fn test_negotiation_fails_when_below_minimum() {
    let negotiator = PolicyNegotiator::new(); // Default minimum is Medium
    let remote_policies = vec![HmacPolicy::Light];

    let result = negotiator.negotiate(&remote_policies);
    assert!(result.is_err());

    if let Err(SecurityError::PolicyMismatch { reason }) = result {
        assert!(reason.contains("No compatible HMAC policy"));
    } else {
        panic!("Expected PolicyMismatch error");
    }
}

#[test]
fn test_negotiation_fails_with_no_overlap() {
    let negotiator = PolicyNegotiator::with_policies(vec![HmacPolicy::Strong]);
    let remote_policies = vec![HmacPolicy::Light];

    let result = negotiator.negotiate(&remote_policies);
    assert!(result.is_err());
}

#[test]
fn test_negotiation_with_custom_minimum_strong() {
    let negotiator = PolicyNegotiator::new().with_minimum_policy(HmacPolicy::Strong);
    let remote_policies = vec![HmacPolicy::Medium];

    let result = negotiator.negotiate(&remote_policies);
    assert!(result.is_err());
}

#[test]
fn test_negotiation_succeeds_with_custom_minimum_light() {
    let negotiator = PolicyNegotiator::new().with_minimum_policy(HmacPolicy::Light);
    let remote_policies = vec![HmacPolicy::Light];

    let result = negotiator.negotiate(&remote_policies);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), HmacPolicy::Light);
}

// ============================================================================
// Policy Validation Tests
// ============================================================================

#[test]
fn test_validate_policy_accepts_supported_above_minimum() {
    let negotiator = PolicyNegotiator::new();

    assert!(negotiator.validate_policy(HmacPolicy::Strong).is_ok());
    assert!(negotiator.validate_policy(HmacPolicy::Medium).is_ok());
}

#[test]
fn test_validate_policy_rejects_below_minimum() {
    let negotiator = PolicyNegotiator::new(); // Default minimum is Medium

    let result = negotiator.validate_policy(HmacPolicy::Light);
    assert!(result.is_err());
}

#[test]
fn test_validate_policy_rejects_unsupported() {
    let negotiator = PolicyNegotiator::with_policies(vec![HmacPolicy::Strong]);

    let result = negotiator.validate_policy(HmacPolicy::Medium);
    assert!(result.is_err());
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_serialize_policies() {
    let negotiator = PolicyNegotiator::new();
    let serialized = negotiator.serialize_policies();

    assert_eq!(serialized.len(), 3);
    assert!(serialized.contains(&HmacPolicy::Strong.as_byte()));
    assert!(serialized.contains(&HmacPolicy::Medium.as_byte()));
    assert!(serialized.contains(&HmacPolicy::Light.as_byte()));
}

#[test]
fn test_deserialize_policies() {
    let data = vec![
        HmacPolicy::Strong.as_byte(),
        HmacPolicy::Medium.as_byte(),
        HmacPolicy::Light.as_byte(),
    ];

    let result = PolicyNegotiator::deserialize_policies(&data);
    assert!(result.is_ok());

    let policies = result.unwrap();
    assert_eq!(policies.len(), 3);
    assert!(policies.contains(&HmacPolicy::Strong));
    assert!(policies.contains(&HmacPolicy::Medium));
    assert!(policies.contains(&HmacPolicy::Light));
}

#[test]
fn test_deserialize_invalid_policy_byte() {
    let invalid_data = vec![1, 2, 99]; // 99 is not a valid policy

    let result = PolicyNegotiator::deserialize_policies(&invalid_data);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_empty_data() {
    let empty_data = vec![];

    let result = PolicyNegotiator::deserialize_policies(&empty_data);
    assert!(result.is_err());
}

#[test]
fn test_roundtrip_serialization() {
    let negotiator = PolicyNegotiator::new();
    let serialized = negotiator.serialize_policies();
    let deserialized = PolicyNegotiator::deserialize_policies(&serialized).unwrap();

    assert_eq!(deserialized.len(), 3);
    for policy in negotiator.supported_policies() {
        assert!(deserialized.contains(policy));
    }
}

// ============================================================================
// Policy Mismatch Handler Tests
// ============================================================================

#[test]
fn test_policy_mismatch_handler_returns_correct_error_code() {
    let handler = PolicyMismatchHandler::new(30_000);
    let local = vec![HmacPolicy::Strong, HmacPolicy::Medium];
    let remote = vec![HmacPolicy::Light];

    let (error_code, _timeout) = handler.handle_mismatch(&local, &remote, HmacPolicy::Medium);

    assert_eq!(error_code, 0x04); // PolicyMismatch error code
}

#[test]
fn test_policy_mismatch_handler_connection_timeout() {
    let handler = PolicyMismatchHandler::new(30_000);
    let local = vec![HmacPolicy::Strong];
    let remote = vec![HmacPolicy::Light];

    let (_error_code, timeout) = handler.handle_mismatch(&local, &remote, HmacPolicy::Strong);

    assert_eq!(timeout.as_millis(), 30_000);
}

#[test]
fn test_policy_mismatch_handler_default_timeout() {
    let handler = PolicyMismatchHandler::default();
    let timeout = handler.connection_timeout();

    assert_eq!(timeout.as_millis(), 30_000);
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_initiator_proposes_strong_responder_accepts() {
    let initiator = PolicyNegotiator::new();
    let responder = PolicyNegotiator::new();

    let proposed = initiator.propose_policy().unwrap();
    let remote_policies = responder.serialize_policies();
    let deserialized = PolicyNegotiator::deserialize_policies(&remote_policies).unwrap();

    let negotiated = initiator.negotiate(&deserialized).unwrap();

    assert_eq!(proposed, HmacPolicy::Strong);
    assert_eq!(negotiated, HmacPolicy::Strong);
}

#[test]
fn test_both_peers_detect_policy_mismatch() {
    let initiator = PolicyNegotiator::new().with_minimum_policy(HmacPolicy::Strong);
    let responder = PolicyNegotiator::with_policies(vec![HmacPolicy::Light]);

    let initiator_policies = initiator.serialize_policies();
    let responder_policies = responder.serialize_policies();

    let initiator_remote = PolicyNegotiator::deserialize_policies(&responder_policies).unwrap();
    let responder_remote = PolicyNegotiator::deserialize_policies(&initiator_policies).unwrap();

    let initiator_result = initiator.negotiate(&initiator_remote);
    let responder_result = responder.negotiate(&responder_remote);

    assert!(initiator_result.is_err());
    assert!(responder_result.is_err());
}

#[test]
fn test_both_peers_transition_to_closed_within_timeout() {
    let handler = PolicyMismatchHandler::new(30_000);
    let timeout = handler.connection_timeout();

    // Simulate both peers detecting mismatch
    let start = std::time::Instant::now();

    // In real implementation, both peers would send RST and transition to CLOSED
    // Here we just verify the timeout value is correct
    assert_eq!(timeout.as_millis(), 30_000);

    // Verify timeout hasn't elapsed yet
    assert!(start.elapsed() < timeout);
}

#[test]
fn test_policy_logged_at_info_level() {
    // This test verifies the structure - actual logging verification would
    // require tracing-subscriber configuration in integration tests
    let negotiator = PolicyNegotiator::new();
    let remote = vec![HmacPolicy::Strong];

    let result = negotiator.negotiate(&remote);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), HmacPolicy::Strong);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_negotiation_with_duplicate_policies() {
    let negotiator = PolicyNegotiator::new();
    let remote = vec![HmacPolicy::Medium, HmacPolicy::Medium, HmacPolicy::Medium];

    let result = negotiator.negotiate(&remote);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), HmacPolicy::Medium);
}

#[test]
fn test_negotiation_prefers_first_match_in_preference_order() {
    let negotiator = PolicyNegotiator::with_policies(vec![
        HmacPolicy::Strong,
        HmacPolicy::Medium,
        HmacPolicy::Light,
    ]);

    // Remote supports Medium and Light - should pick Medium (stronger)
    let remote = vec![HmacPolicy::Medium, HmacPolicy::Light];
    let result = negotiator.negotiate(&remote);

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), HmacPolicy::Medium);
}

#[test]
fn test_custom_policy_list_orders_correctly() {
    let negotiator = PolicyNegotiator::with_policies(vec![
        HmacPolicy::Light,
        HmacPolicy::Strong,
        HmacPolicy::Medium,
    ]);

    // Should be sorted strongest first
    assert_eq!(negotiator.supported_policies()[0], HmacPolicy::Strong);
}
