// Basic tests for ECDH connection establishment engine
//
// This file tests the basic functionality without depending on problematic modules.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use buckwild_common::crypto::SecureBytes;
use buckwild_common::session::SessionManager;
use buckwild_common::protocol::{
    ConnectionParams, VersionByte, SessionIdLength, TimestampConfig, HmacPolicy
};
use buckwild_common::protocol::types::{
    SequenceNumber, Port, AttemptCount
};

fn create_test_addresses() -> (SocketAddr, SocketAddr) {
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), Port::new(8000).as_u16());
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), Port::new(9000).as_u16());
    (local_addr, remote_addr)
}

fn create_test_params() -> ConnectionParams {
    ConnectionParams {
        version_byte: VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24),
        hmac_policy: HmacPolicy::Medium,
        timeout: Duration::from_secs(5),
        max_retries: AttemptCount::new(3),
        psk: Some(SecureBytes::from_slice(b"test_psk_key_32_bytes_long_12345").unwrap()),
    }
}

#[test]
fn test_connection_params_creation() {
    let params = create_test_params();
    
    // Verify parameters are set correctly
    assert_eq!(params.version_byte.session_id_length(), SessionIdLength::Bits32);
    assert_eq!(params.version_byte.timestamp_config(), TimestampConfig::Bits24);
    assert_eq!(params.hmac_policy, HmacPolicy::Medium);
    assert_eq!(params.timeout, Duration::from_secs(5));
    assert_eq!(params.max_retries, AttemptCount::new(3));
    assert!(params.psk.is_some());
    
    let psk = params.psk.unwrap();
    assert_eq!(psk.len(), 32);
}

#[test]
fn test_connection_params_default() {
    let params = ConnectionParams::default();
    
    // Verify default parameters
    assert_eq!(params.version_byte.session_id_length(), SessionIdLength::Bits32);
    assert_eq!(params.version_byte.timestamp_config(), TimestampConfig::Bits24);
    assert_eq!(params.hmac_policy, HmacPolicy::Light); // Default from standard config
    assert!(params.timeout > Duration::from_secs(0));
    assert!(params.max_retries > AttemptCount::new(0));
    assert!(params.psk.is_none()); // Default has no PSK
}

#[test]
fn test_version_byte_configurations() {
    // Test different deployment configurations
    let iot_version = VersionByte::new(SessionIdLength::Bits16, TimestampConfig::Bits16);
    let standard_version = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
    let secure_version = VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24);
    let infra_version = VersionByte::new(SessionIdLength::Bits64, TimestampConfig::Bits32);
    
    // Verify configurations are different
    assert_ne!(iot_version.as_u8(), standard_version.as_u8());
    assert_ne!(standard_version.as_u8(), infra_version.as_u8());
    
    // Verify session ID lengths
    assert_eq!(iot_version.session_id_length(), SessionIdLength::Bits16);
    assert_eq!(standard_version.session_id_length(), SessionIdLength::Bits32);
    assert_eq!(infra_version.session_id_length(), SessionIdLength::Bits64);
    
    // Verify timestamp configurations
    assert_eq!(iot_version.timestamp_config(), TimestampConfig::Bits16);
    assert_eq!(standard_version.timestamp_config(), TimestampConfig::Bits24);
    assert_eq!(infra_version.timestamp_config(), TimestampConfig::Bits32);
}

#[test]
fn test_hmac_policy_values() {
    // Test HMAC policy values
    let policies = vec![HmacPolicy::Light, HmacPolicy::Medium, HmacPolicy::Strong];
    
    for policy in &policies {
        match policy {
            HmacPolicy::Light => {
                // Light policy should be for data packets
            },
            HmacPolicy::Medium => {
                // Medium policy should be for control packets
            },
            HmacPolicy::Strong => {
                // Strong policy should be for critical packets
            },
        }
    }
    
    // Verify all policies are distinct
    for (i, policy1) in policies.iter().enumerate() {
        for (j, policy2) in policies.iter().enumerate() {
            if i != j {
                assert_ne!(policy1, policy2);
            } else {
                assert_eq!(policy1, policy2);
            }
        }
    }
}

#[test]
fn test_session_manager_creation() {
    let session_manager = Arc::new(SessionManager::default());
    
    // Verify session manager is created
    assert_eq!(session_manager.session_count(), 0);
    
    // Test session creation
    let (session_id, session_state) = session_manager.create_session();
    assert_eq!(session_manager.session_count(), 1);
    
    // Verify session can be retrieved
    let retrieved = session_manager.get_session(&session_id);
    assert!(retrieved.is_some());
    
    // Verify session state is initialized
    assert_eq!(session_state.local_seq(), SequenceNumber::new(0)); // Initial value
    assert_eq!(session_state.remote_seq(), SequenceNumber::new(0)); // Initial value
}

#[test]
fn test_session_with_ecdh_parameters() {
    let session_manager = Arc::new(SessionManager::default());
    
    // Test creating a session with ECDH-derived parameters
    let shared_secret = [1u8; 32];
    let salt = b"test_salt_for_session_creation";
    
    let result = session_manager.create_session_with_ecdh(&shared_secret, salt);
    assert!(result.is_ok());
    
    let (session_id, session_state) = result.unwrap();
    
    // Verify session was created
    let retrieved = session_manager.get_session(&session_id);
    assert!(retrieved.is_some());
    
    // Verify session parameters were initialized from ECDH
    // These should be non-zero because they're derived from the shared secret
    assert_ne!(session_state.local_seq(), SequenceNumber::new(0));
    assert_ne!(session_state.remote_seq(), SequenceNumber::new(0));
    
    // Test that derivation is deterministic
    let result2 = session_manager.create_session_with_ecdh(&shared_secret, salt);
    assert!(result2.is_ok());
    
    let (session_id2, session_state2) = result2.unwrap();
    
    // Different session IDs but same derived parameters
    assert_ne!(session_id, session_id2);
    assert_eq!(session_state.local_seq(), session_state2.local_seq());
    assert_eq!(session_state.remote_seq(), session_state2.remote_seq());
}

#[test]
fn test_pbkdf2_parameter_derivation() {
    let session_manager = Arc::new(SessionManager::default());
    
    // Test PBKDF2 parameter derivation
    let shared_secret = [0x42u8; 32];
    let salt = b"test_salt_for_derivation_testing";
    
    let params_result = session_manager.derive_session_parameters(&shared_secret, salt);
    assert!(params_result.is_ok());
    
    let params = params_result.unwrap();
    assert_eq!(params.len(), 128); // 64 × 16-bit chunks
    
    // Test that derivation is deterministic
    let params2 = session_manager.derive_session_parameters(&shared_secret, salt).unwrap();
    assert_eq!(params.as_slice(), params2.as_slice());
    
    // Test that different inputs produce different outputs
    let different_secret = [0x43u8; 32];
    let params3 = session_manager.derive_session_parameters(&different_secret, salt).unwrap();
    assert_ne!(params.as_slice(), params3.as_slice());
    
    // Test with different salt
    let different_salt = b"different_salt_for_testing";
    let params4 = session_manager.derive_session_parameters(&shared_secret, different_salt).unwrap();
    assert_ne!(params.as_slice(), params4.as_slice());
}

#[test]
fn test_secure_bytes_handling() {
    // Test SecureBytes creation and usage
    let data = b"test_data_for_secure_bytes_testing";
    let secure_bytes = SecureBytes::from_slice(data).unwrap();
    
    assert_eq!(secure_bytes.len(), data.len());
    assert_eq!(secure_bytes.as_slice(), data);
    
    // Test cloning
    let cloned = secure_bytes.clone();
    assert_eq!(cloned.as_slice(), secure_bytes.as_slice());
    
    // Test with different sizes
    let small_data = b"small";
    let small_secure = SecureBytes::from_slice(small_data).unwrap();
    assert_eq!(small_secure.len(), 5);
    
    let large_data = [0x42u8; 1024];
    let large_secure = SecureBytes::from_slice(&large_data).unwrap();
    assert_eq!(large_secure.len(), 1024);
}

#[test]
fn test_connection_addresses() {
    let (local_addr, remote_addr) = create_test_addresses();
    
    // Verify addresses are different
    assert_ne!(local_addr, remote_addr);
    
    // Verify address components
    assert_eq!(local_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(remote_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(local_addr.port(), Port::new(8000).as_u16());
    assert_eq!(remote_addr.port(), Port::new(9000).as_u16());
    
    // Test address formatting
    assert_eq!(local_addr.to_string(), "127.0.0.1:8000");
    assert_eq!(remote_addr.to_string(), "127.0.0.1:9000");
}

#[test]
fn test_timeout_and_retry_parameters() {
    let params = create_test_params();
    
    // Verify timeout and retry parameters
    assert_eq!(params.timeout, Duration::from_secs(5));
    assert_eq!(params.max_retries, 3);
    
    // Test with different values
    let custom_params = ConnectionParams {
        timeout: Duration::from_millis(500),
        max_retries: AttemptCount::new(10),
        ..Default::default()
    };
    
    assert_eq!(custom_params.timeout, Duration::from_millis(500));
    assert_eq!(custom_params.max_retries, AttemptCount::new(10));
    
    // Test edge cases
    let minimal_params = ConnectionParams {
        timeout: Duration::from_millis(1),
        max_retries: AttemptCount::new(0),
        ..Default::default()
    };
    
    assert_eq!(minimal_params.timeout, Duration::from_millis(1));
    assert_eq!(minimal_params.max_retries, AttemptCount::new(0));
}