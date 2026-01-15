#![forbid(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for error propagation through the error hierarchy
//!
//! This test suite demonstrates how errors propagate from lower layers
//! (SecurityError, ProtocolError, EngineError) through the ConnectionError
//! layer and up to BuckwildError, preserving context at each level.

use buckwild_common::error::{
    BuckwildError, ConnectionError, EngineError, ProtocolError, SecurityError,
};
use buckwild_common::protocol::types::{SequenceNumber, SessionId};

#[test]
fn test_security_error_propagation_through_connection() {
    let session = SessionId::new(1);
    let sequence = SequenceNumber::new(42);

    // Create a SecurityError at the lowest layer
    let security_err = SecurityError::duplicate_packet(session.clone(), sequence);
    assert!(!security_err.is_recoverable());
    assert!(security_err.is_potential_attack());

    // Wrap it in a ConnectionError
    let connection_err = ConnectionError::security_integration(session.clone(), security_err);
    assert!(!connection_err.is_recoverable());
    assert_eq!(connection_err.session_id(), Some(session.clone()));

    // Wrap it in BuckwildError
    let buckwild_err: BuckwildError = connection_err.into();
    assert!(!buckwild_err.is_recoverable());
    assert_eq!(buckwild_err.error_layer(), "connection");

    // Verify error message contains context
    let error_msg = buckwild_err.to_string();
    assert!(error_msg.contains("Security integration error"));
    assert!(error_msg.contains("Duplicate packet detected"));
}

#[test]
fn test_protocol_error_propagation_through_connection() {
    let session = SessionId::new(1);
    let sequence = SequenceNumber::new(100);

    // Create a ProtocolError
    let protocol_err = ProtocolError::invalid_format("malformed header");
    assert!(!protocol_err.is_recoverable());

    // Wrap it in ConnectionError
    let connection_err =
        ConnectionError::protocol_integration(session.clone(), sequence, protocol_err);
    assert!(!connection_err.is_recoverable());
    assert_eq!(connection_err.session_id(), Some(session));

    // Verify recovery hint propagates
    assert!(connection_err.recovery_hint().is_none());
}

#[test]
fn test_engine_error_propagation_through_connection() {
    let session = SessionId::new(1);

    // Create an EngineError that is recoverable
    let engine_err = EngineError::port_hopping_error("port calculation failed");
    assert!(engine_err.is_recoverable());
    assert_eq!(engine_err.engine_type(), "port_hopping");

    // Wrap it in ConnectionError
    let connection_err = ConnectionError::engine_integration(session.clone(), engine_err);
    assert!(connection_err.is_recoverable());
    assert_eq!(connection_err.session_id(), Some(session));

    // Verify recovery hint propagates from engine layer
    assert_eq!(
        connection_err.recovery_hint(),
        Some("Reinitialize port hopping sequence")
    );

    // Wrap in BuckwildError
    let buckwild_err: BuckwildError = connection_err.into();
    assert!(buckwild_err.is_recoverable());
    assert_eq!(
        buckwild_err.recovery_hint(),
        Some("Reinitialize port hopping sequence")
    );
}

#[test]
fn test_connection_error_direct_creation() {
    let session = SessionId::new(1);

    // Create ConnectionError directly
    let err = ConnectionError::invalid_state_transition("Idle", "Active", session, "send_data");

    assert!(!err.is_recoverable());
    assert!(err.recovery_hint().is_none());

    // Convert to BuckwildError
    let buckwild_err: BuckwildError = err.into();
    assert!(!buckwild_err.is_recoverable());
    assert_eq!(buckwild_err.error_layer(), "connection");

    // Verify error message
    let error_msg = buckwild_err.to_string();
    assert!(error_msg.contains("Invalid state transition"));
    assert!(error_msg.contains("Idle -> Active"));
    assert!(error_msg.contains("send_data"));
}

#[test]
fn test_recoverable_connection_error() {
    let session = SessionId::new(1);

    // Create a recoverable ConnectionError
    let err = ConnectionError::establishment_failed(session, "handshake timeout");

    assert!(err.is_recoverable());
    assert_eq!(err.recovery_hint(), Some("Retry connection establishment"));

    // Convert to BuckwildError and verify recoverability is preserved
    let buckwild_err: BuckwildError = err.into();
    assert!(buckwild_err.is_recoverable());
    assert_eq!(
        buckwild_err.recovery_hint(),
        Some("Retry connection establishment")
    );
}

#[test]
fn test_error_context_extraction() {
    let session = SessionId::new(1);
    let security_err = SecurityError::hmac_verification_failed();
    let connection_err = ConnectionError::security_integration(session, security_err);
    let buckwild_err: BuckwildError = connection_err.into();

    // Extract error context
    let context = buckwild_err.error_context();
    assert_eq!(context.layer, "connection");
    assert!(!context.recoverable);
    assert!(!context.potential_attack); // Connection layer itself isn't the attack vector
    assert!(context.security_severity.is_none());
}

#[test]
fn test_max_connections_error() {
    let err = ConnectionError::max_connections_reached(100, 100);

    assert!(err.is_recoverable());
    assert_eq!(err.recovery_hint(), Some("Wait for connections to close"));
    assert!(err.session_id().is_none());

    // Verify error message
    let error_msg = err.to_string();
    assert!(error_msg.contains("Maximum connections reached"));
    assert!(error_msg.contains("100/100"));
}

#[test]
fn test_error_chain_preserves_source() {
    let session = SessionId::new(1);
    let sequence = SequenceNumber::new(1);

    // Create error chain: SecurityError -> ConnectionError -> BuckwildError
    let security_err = SecurityError::replay_attack(session.clone(), sequence);
    let connection_err = ConnectionError::security_integration(session, security_err);
    let buckwild_err: BuckwildError = connection_err.into();

    // Verify the error chain via Display
    let error_msg = buckwild_err.to_string();
    assert!(error_msg.contains("Connection error"));
    assert!(error_msg.contains("Security integration error"));
    assert!(error_msg.contains("Replay attack detected"));
}

#[test]
fn test_async_compatibility() {
    // Verify that errors can be used in async context (Send + Sync)
    fn is_send_sync<T: Send + Sync>() {}

    is_send_sync::<SecurityError>();
    is_send_sync::<ProtocolError>();
    is_send_sync::<EngineError>();
    is_send_sync::<ConnectionError>();
    is_send_sync::<BuckwildError>();
}
