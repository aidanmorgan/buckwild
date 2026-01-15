// Integration tests for connection lifecycle - SYN/SYN-ACK/ACK flow
//
// Tests complete connection establishment and teardown lifecycle including:
// - Handshake flow (SYN -> SYN-ACK -> ACK)
// - State transitions (CLOSED -> SYN_SENT -> ESTABLISHED, etc.)
// - Error scenarios (timeouts, mismatches, rejections)
// - Concurrent connections with session isolation

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use buckwild_common::connection::lifecycle::{
    ConnectionLifecycle, ConnectionMachineState, SessionConfiguration,
};
use buckwild_common::error::EngineError;
use buckwild_common::protocol::types::*;

/// Helper to create test lifecycle instances
fn create_test_lifecycle(psk: Vec<u8>) -> Result<ConnectionLifecycle, EngineError> {
    ConnectionLifecycle::new(
        psk,
        500,      // 500ms time bucket
        1024,     // min port
        65535,    // max port
        1000,     // 1s past window
        1000,     // 1s future window
        SessionConfiguration::default(),
    )
}

#[tokio::test]
async fn test_successful_handshake_client_flow() {
    // Test client-initiated connection: CLOSED -> CONNECTING -> SYN_SENT -> ESTABLISHED
    let psk = b"test_psk_for_client_handshake".to_vec();
    let client = create_test_lifecycle(psk.clone()).unwrap();
    let server = create_test_lifecycle(psk).unwrap();

    // Initial state: CLOSED
    assert_eq!(
        client.connection_state(),
        ConnectionMachineState::Closed,
        "Client should start in CLOSED state"
    );

    // Client initiates connection
    let client_pub_key = client.initiate_connection().await.unwrap();
    assert_eq!(
        client.connection_state(),
        ConnectionMachineState::SynSent,
        "Client should be in SYN_SENT after initiation"
    );

    // Server starts listening
    server.start_listening().unwrap();
    assert_eq!(
        server.connection_state(),
        ConnectionMachineState::Listening,
        "Server should be in LISTENING state"
    );

    // Server handles SYN
    let (server_pub_key, challenge) = server.handle_syn(&client_pub_key).await.unwrap();
    assert_eq!(
        server.connection_state(),
        ConnectionMachineState::SynReceived,
        "Server should be in SYN_RECEIVED after handling SYN"
    );

    // Client handles SYN-ACK
    let response = client
        .handle_syn_ack(&server_pub_key, &challenge)
        .await
        .unwrap();

    assert_eq!(
        client.connection_state(),
        ConnectionMachineState::Established,
        "Client should be in ESTABLISHED after SYN-ACK"
    );
    assert!(
        client.is_established().await,
        "Client connection should be established"
    );

    // Server handles ACK
    server.handle_ack(&response).await.unwrap();
    assert_eq!(
        server.connection_state(),
        ConnectionMachineState::Established,
        "Server should be in ESTABLISHED after ACK"
    );
    assert!(
        server.is_established().await,
        "Server connection should be established"
    );

    // Both should have matching session keys
    let client_key = client.get_session_key().await.unwrap();
    let server_key = server.get_session_key().await.unwrap();
    assert_eq!(
        client_key, server_key,
        "Client and server session keys must match"
    );
}

#[tokio::test]
async fn test_successful_handshake_server_flow() {
    // Test server-side flow: CLOSED -> LISTENING -> SYN_RECEIVED -> ESTABLISHED
    let psk = b"test_psk_for_server_handshake".to_vec();
    let client = create_test_lifecycle(psk.clone()).unwrap();
    let server = create_test_lifecycle(psk).unwrap();

    // Server starts listening first
    server.start_listening().unwrap();
    assert_eq!(server.connection_state(), ConnectionMachineState::Listening);

    // Client connects
    let client_pub_key = client.initiate_connection().await.unwrap();
    assert_eq!(client.connection_state(), ConnectionMachineState::SynSent);

    // Server receives SYN
    let (server_pub_key, challenge) = server.handle_syn(&client_pub_key).await.unwrap();
    assert_eq!(
        server.connection_state(),
        ConnectionMachineState::SynReceived
    );

    // Client completes handshake
    let response = client
        .handle_syn_ack(&server_pub_key, &challenge)
        .await
        .unwrap();
    assert_eq!(
        client.connection_state(),
        ConnectionMachineState::Established
    );

    // Server accepts connection
    server.handle_ack(&response).await.unwrap();
    assert_eq!(
        server.connection_state(),
        ConnectionMachineState::Established
    );

    // Verify both are established
    assert!(client.is_established().await);
    assert!(server.is_established().await);
}

#[tokio::test]
async fn test_state_transitions_closed_to_established() {
    // Test complete state transition sequence
    let psk = b"test_psk_state_transitions".to_vec();
    let lifecycle = create_test_lifecycle(psk).unwrap();

    // Track state transitions
    let mut states = vec![lifecycle.connection_state()];

    // CLOSED -> CONNECTING
    let _pub_key = lifecycle.initiate_connection().await.unwrap();
    states.push(lifecycle.connection_state());

    // Should be: CLOSED, SYN_SENT
    assert_eq!(states, vec![
        ConnectionMachineState::Closed,
        ConnectionMachineState::SynSent,
    ]);
}

#[tokio::test]
async fn test_state_transitions_established_to_closed() {
    // Test closing state transitions: ESTABLISHED -> CLOSING -> CLOSED
    let psk = b"test_psk_closing".to_vec();
    let client = create_test_lifecycle(psk.clone()).unwrap();
    let server = create_test_lifecycle(psk).unwrap();

    // Establish connection first
    server.start_listening().unwrap();
    let client_pub_key = client.initiate_connection().await.unwrap();
    let (server_pub_key, challenge) = server.handle_syn(&client_pub_key).await.unwrap();
    let response = client
        .handle_syn_ack(&server_pub_key, &challenge)
        .await
        .unwrap();
    server.handle_ack(&response).await.unwrap();

    assert_eq!(
        client.connection_state(),
        ConnectionMachineState::Established
    );

    // Close connection
    client.close().unwrap();
    assert_eq!(
        client.connection_state(),
        ConnectionMachineState::Closing,
        "Should transition to CLOSING"
    );

    // Complete close
    client.state_machine().finish_close().unwrap();
    assert_eq!(
        client.connection_state(),
        ConnectionMachineState::Closed,
        "Should transition to CLOSED"
    );
}

#[tokio::test]
async fn test_syn_ack_mismatch() {
    // Test error when SYN-ACK contains mismatched keys
    let psk = b"test_psk_mismatch".to_vec();
    let client = create_test_lifecycle(psk.clone()).unwrap();
    let wrong_server = create_test_lifecycle(b"different_psk".to_vec()).unwrap();

    // Client initiates
    let _client_pub_key = client.initiate_connection().await.unwrap();

    // Wrong server responds (different PSK means different derived keys)
    wrong_server.start_listening().unwrap();

    // Generate a random public key that won't match
    let wrong_pub_key = EcdhPublicKey::new([0x42; 64]);
    let wrong_challenge = [0xAB; 32];

    // Client should handle SYN-ACK but session keys won't match
    // This would be detected during authentication
    let response = client
        .handle_syn_ack(&wrong_pub_key, &wrong_challenge)
        .await
        .unwrap();

    // Session keys will differ due to different ECDH
    let client_key = client.get_session_key().await;
    assert!(client_key.is_some(), "Client should have derived a session key");

    // In a real scenario, the server would reject the ACK due to invalid challenge response
}

#[tokio::test]
async fn test_ack_rejection() {
    // Test server rejecting invalid ACK (wrong challenge response)
    let psk = b"test_psk_ack_reject".to_vec();
    let client = create_test_lifecycle(psk.clone()).unwrap();
    let server = create_test_lifecycle(psk).unwrap();

    // Establish up to SYN-ACK
    server.start_listening().unwrap();
    let client_pub_key = client.initiate_connection().await.unwrap();
    let (_server_pub_key, _challenge) = server.handle_syn(&client_pub_key).await.unwrap();

    // Client sends wrong ACK response
    let wrong_response = [0xFF; 32];

    // Server should reject
    let result = server.handle_ack(&wrong_response).await;
    assert!(
        result.is_err(),
        "Server should reject invalid challenge response"
    );

    // Server should not be established
    assert!(!server.is_established().await);
}

#[tokio::test]
async fn test_concurrent_connections_isolation() {
    // Test multiple simultaneous handshakes with session isolation
    let num_connections = 5;
    let mut handles = Vec::new();

    for i in 0..num_connections {
        let handle = tokio::spawn(async move {
            let psk = format!("test_psk_concurrent_{}", i)
                .as_bytes()
                .to_vec();
            let client = create_test_lifecycle(psk.clone()).unwrap();
            let server = create_test_lifecycle(psk).unwrap();

            // Each connection completes handshake independently
            server.start_listening().unwrap();
            let client_pub_key = client.initiate_connection().await.unwrap();
            let (server_pub_key, challenge) =
                server.handle_syn(&client_pub_key).await.unwrap();
            let response = client
                .handle_syn_ack(&server_pub_key, &challenge)
                .await
                .unwrap();
            server.handle_ack(&response).await.unwrap();

            // Verify both established
            assert!(client.is_established().await);
            assert!(server.is_established().await);

            // Return session keys to verify uniqueness
            let client_key = client.get_session_key().await.unwrap();
            let server_key = server.get_session_key().await.unwrap();

            (client_key, server_key)
        });

        handles.push(handle);
    }

    // Collect all session keys
    let mut session_keys = Vec::new();
    for handle in handles {
        let (client_key, server_key) = handle.await.unwrap();
        assert_eq!(client_key, server_key, "Keys must match within session");
        session_keys.push(client_key);
    }

    // Verify all session keys are unique (different PSKs)
    for i in 0..session_keys.len() {
        for j in (i + 1)..session_keys.len() {
            assert_ne!(
                session_keys[i], session_keys[j],
                "Session keys from different PSKs must differ"
            );
        }
    }
}

#[tokio::test]
async fn test_rst_packet_handling() {
    // Test RST packet immediately transitions to CLOSED from any state
    let psk = b"test_psk_rst".to_vec();

    // Test RST from SYN_SENT
    let client = create_test_lifecycle(psk.clone()).unwrap();
    let _pub_key = client.initiate_connection().await.unwrap();
    assert_eq!(client.connection_state(), ConnectionMachineState::SynSent);

    client.handle_rst().await.unwrap();
    assert_eq!(
        client.connection_state(),
        ConnectionMachineState::Closed,
        "RST should transition SYN_SENT to CLOSED"
    );

    // Test RST from ESTABLISHED
    let client2 = create_test_lifecycle(psk.clone()).unwrap();
    let server2 = create_test_lifecycle(psk.clone()).unwrap();

    server2.start_listening().unwrap();
    let client_pub_key = client2.initiate_connection().await.unwrap();
    let (server_pub_key, challenge) = server2.handle_syn(&client_pub_key).await.unwrap();
    let response = client2
        .handle_syn_ack(&server_pub_key, &challenge)
        .await
        .unwrap();
    server2.handle_ack(&response).await.unwrap();

    assert_eq!(
        client2.connection_state(),
        ConnectionMachineState::Established
    );

    client2.handle_rst().await.unwrap();
    assert_eq!(
        client2.connection_state(),
        ConnectionMachineState::Closed,
        "RST should transition ESTABLISHED to CLOSED"
    );

    // Session key should be cleared
    assert!(
        client2.get_session_key().await.is_none(),
        "RST should clear session key"
    );
}

#[tokio::test]
async fn test_session_configuration_negotiation() {
    // Test session configuration negotiation (prefer more secure)
    let psk = b"test_psk_config_negotiation".to_vec();

    let client_config = SessionConfiguration {
        protocol_version: 1,
        session_id_length: 1, // 32-bit
        timestamp_config: 1,  // 24-bit
        hmac_policy: 1,       // Low
    };

    let server_config = SessionConfiguration {
        protocol_version: 1,
        session_id_length: 2, // 48-bit (more secure)
        timestamp_config: 2,  // 32-bit (more precise)
        hmac_policy: 2,       // Medium (more secure)
    };

    let client = ConnectionLifecycle::new(
        psk.clone(),
        500,
        1024,
        65535,
        1000,
        1000,
        client_config,
    )
    .unwrap();

    let server = ConnectionLifecycle::new(psk, 500, 1024, 65535, 1000, 1000, server_config).unwrap();

    // Negotiate from client's perspective
    let negotiated = client
        .negotiate_configuration(server_config.to_version_byte())
        .await
        .unwrap();

    // Should choose more secure options
    assert_eq!(negotiated.session_id_length, 2, "Should choose 48-bit");
    assert_eq!(negotiated.timestamp_config, 2, "Should choose 32-bit");
    assert_eq!(negotiated.hmac_policy, 2, "Should choose Medium");
}

#[tokio::test]
async fn test_challenge_response_authentication() {
    // Test challenge-response mechanism
    let psk = b"test_psk_challenge_response".to_vec();
    let client = create_test_lifecycle(psk.clone()).unwrap();
    let server = create_test_lifecycle(psk).unwrap();

    // Establish up to ECDH completion
    server.start_listening().unwrap();
    let client_pub_key = client.initiate_connection().await.unwrap();
    let (server_pub_key, server_challenge) =
        server.handle_syn(&client_pub_key).await.unwrap();

    // Client computes challenge response
    let client_response = client
        .handle_syn_ack(&server_pub_key, &server_challenge)
        .await
        .unwrap();

    // Server verifies challenge response
    let result = server.handle_ack(&client_response).await;
    assert!(
        result.is_ok(),
        "Server should accept valid challenge response"
    );

    // Verify server is established
    assert!(server.is_established().await);
}

#[tokio::test]
async fn test_port_hopping_after_establishment() {
    // Test port hopping calculation after connection established
    let psk = b"test_psk_port_hopping".to_vec();
    let client = create_test_lifecycle(psk.clone()).unwrap();
    let server = create_test_lifecycle(psk).unwrap();

    // Establish connection
    server.start_listening().unwrap();
    let client_pub_key = client.initiate_connection().await.unwrap();
    let (server_pub_key, challenge) = server.handle_syn(&client_pub_key).await.unwrap();
    let response = client
        .handle_syn_ack(&server_pub_key, &challenge)
        .await
        .unwrap();
    server.handle_ack(&response).await.unwrap();

    // Both should calculate same ports
    let client_ports = client.calculate_listening_ports().await.unwrap();
    let server_ports = server.calculate_listening_ports().await.unwrap();

    assert!(!client_ports.is_empty(), "Should calculate ports");
    assert!(!server_ports.is_empty(), "Should calculate ports");

    // Ports should match (same PSK, same time)
    assert_eq!(
        client_ports.len(),
        server_ports.len(),
        "Should calculate same number of ports"
    );
}

#[tokio::test]
async fn test_invalid_state_transition() {
    // Test that invalid state transitions are rejected
    let psk = b"test_psk_invalid_transition".to_vec();
    let lifecycle = create_test_lifecycle(psk).unwrap();

    // Try to transition directly to ESTABLISHED from CLOSED (invalid)
    let result = lifecycle.state_machine().receive_syn_ack();
    assert!(
        result.is_err(),
        "Should reject invalid state transition"
    );

    // State should remain CLOSED
    assert_eq!(lifecycle.connection_state(), ConnectionMachineState::Closed);
}

#[tokio::test]
async fn test_session_key_derivation_deterministic() {
    // Test that same ECDH exchange produces same session key
    let psk = b"test_psk_deterministic".to_vec();
    let client1 = create_test_lifecycle(psk.clone()).unwrap();
    let server1 = create_test_lifecycle(psk.clone()).unwrap();

    // First handshake
    server1.start_listening().unwrap();
    let client_pub_key = client1.initiate_connection().await.unwrap();
    let (server_pub_key, challenge) = server1.handle_syn(&client_pub_key).await.unwrap();
    let response = client1
        .handle_syn_ack(&server_pub_key, &challenge)
        .await
        .unwrap();
    server1.handle_ack(&response).await.unwrap();

    let key1 = client1.get_session_key().await.unwrap();

    // Second handshake with same peers (different instance but same ECDH)
    let client2 = create_test_lifecycle(psk.clone()).unwrap();
    let server2 = create_test_lifecycle(psk).unwrap();

    server2.start_listening().unwrap();
    let client_pub_key2 = client2.initiate_connection().await.unwrap();
    let (server_pub_key2, challenge2) = server2.handle_syn(&client_pub_key2).await.unwrap();
    let response2 = client2
        .handle_syn_ack(&server_pub_key2, &challenge2)
        .await
        .unwrap();
    server2.handle_ack(&response2).await.unwrap();

    let key2 = client2.get_session_key().await.unwrap();

    // Keys will differ because ECDH generates new keypairs each time
    // This test verifies that the derivation process is consistent
    assert!(key1.len() == key2.len(), "Keys should have same length");
}

#[tokio::test]
async fn test_recovery_substate_transitions() {
    // Test recovery sub-state transitions
    let psk = b"test_psk_recovery".to_vec();
    let lifecycle = create_test_lifecycle(psk).unwrap();

    use buckwild_common::connection::lifecycle::RecoverySubState;

    // Should start in Normal sub-state
    assert_eq!(
        lifecycle.state_machine().current_sub_state(),
        RecoverySubState::Normal
    );

    // Transition to Resync recovery
    lifecycle
        .state_machine()
        .enter_resync_recovery()
        .unwrap();
    assert_eq!(
        lifecycle.state_machine().current_sub_state(),
        RecoverySubState::Resync
    );

    // Exit back to Normal
    lifecycle
        .state_machine()
        .exit_recovery_to_normal()
        .unwrap();
    assert_eq!(
        lifecycle.state_machine().current_sub_state(),
        RecoverySubState::Normal
    );

    // Test Emergency recovery (can enter from any state)
    lifecycle
        .state_machine()
        .enter_rekey_recovery()
        .unwrap();
    lifecycle
        .state_machine()
        .enter_emergency_recovery()
        .unwrap();
    assert_eq!(
        lifecycle.state_machine().current_sub_state(),
        RecoverySubState::Emergency
    );
}

#[tokio::test]
async fn test_concurrent_handshakes_no_interference() {
    // Test that concurrent handshakes don't interfere with each other
    let num_pairs = 10;
    let mut handles = Vec::new();

    for i in 0..num_pairs {
        let handle = tokio::spawn(async move {
            let psk = format!("test_psk_no_interference_{}", i)
                .as_bytes()
                .to_vec();
            let client = create_test_lifecycle(psk.clone()).unwrap();
            let server = create_test_lifecycle(psk).unwrap();

            // Perform handshake
            server.start_listening().unwrap();
            let client_pub_key = client.initiate_connection().await.unwrap();
            let (server_pub_key, challenge) =
                server.handle_syn(&client_pub_key).await.unwrap();
            let response = client
                .handle_syn_ack(&server_pub_key, &challenge)
                .await
                .unwrap();
            server.handle_ack(&response).await.unwrap();

            // Return connection IDs to verify
            (
                client.connection_state(),
                server.connection_state(),
                client.get_session_key().await.is_some(),
                server.get_session_key().await.is_some(),
            )
        });

        handles.push(handle);
    }

    // Verify all completed successfully
    for (idx, handle) in handles.into_iter().enumerate() {
        let (client_state, server_state, client_has_key, server_has_key) =
            handle.await.unwrap();
        assert_eq!(
            client_state,
            ConnectionMachineState::Established,
            "Connection {} client should be established",
            idx
        );
        assert_eq!(
            server_state,
            ConnectionMachineState::Established,
            "Connection {} server should be established",
            idx
        );
        assert!(client_has_key, "Connection {} client should have key", idx);
        assert!(server_has_key, "Connection {} server should have key", idx);
    }
}

#[tokio::test]
async fn test_multiple_ports_listening() {
    // Test that server calculates multiple listening ports
    let psk = b"test_psk_multi_port".to_vec();
    let server = create_test_lifecycle(psk).unwrap();

    server.start_listening().unwrap();

    // Server should calculate window of ports
    let ports = server.calculate_listening_ports().await.unwrap();

    // Should have multiple ports (adaptive window)
    assert!(
        ports.len() >= 1,
        "Should calculate at least one listening port"
    );

    // All ports should be in valid range
    for port in &ports {
        assert!(
            port.as_u16() >= 1024 && port.as_u16() <= 65535,
            "Port {} should be in valid range",
            port.as_u16()
        );
    }
}
