use std::sync::Arc;
use std::collections::HashSet;
use std::time::Duration;
use parking_lot::Mutex;
use tokio::time;

use buckwild::protocol::{PortHoppingEngine, PortHoppingParams};
use buckwild::time_sync::engine::TimeSyncEngine;
use buckwild::time_sync::epoch::{TimeEpoch, EpochType};

#[tokio::test]
async fn test_port_hopping_engine() {
    // Create time sync engine
    let time_sync = Arc::new(TimeSyncEngine::new());
    
    // Create port hopping engine
    let mut engine = PortHoppingEngine::new(time_sync.clone());
    
    // Set up mock callbacks
    let bound_ports = Arc::new(Mutex::new(HashSet::new()));
    let bound_ports_clone = bound_ports.clone();
    
    engine.set_bind_port_callback(move |port| {
        println!("Binding to port {}", port);
        bound_ports_clone.lock().insert(port);
        true
    });
    
    let bound_ports_clone = bound_ports.clone();
    engine.set_unbind_port_callback(move |port| {
        println!("Unbinding from port {}", port);
        bound_ports_clone.lock().remove(&port);
        true
    });
    
    // Start the engine
    engine.start().await.expect("Failed to start port hopping engine");
    
    // Create test PSK and derive daily key
    let psk = b"test_psk_for_port_hopping";
    let daily_key = engine.derive_daily_key(psk, "2023-01-01");
    
    // Calculate base port
    let base_port = engine.get_current_base_port(&daily_key);
    println!("Current base port: {}", base_port);
    
    // Create test port hopping parameters
    let params = PortHoppingParams {
        port_seed: 0x12345678,
        hop_sequence_seed: 0x87654321,
        time_variance: 50,
        hop_pattern_seed: 0xABCD,
        session_id: 0x1234567890ABCDEF,
    };
    
    // Get current session port
    let current_port = engine.get_current_session_port(&params);
    println!("Current session port: {}", current_port);
    
    // Get next session port
    let next_port = engine.get_next_session_port(&params);
    println!("Next session port: {}", next_port);
    
    // Get ports for delay window
    let delay_ports = engine.get_ports_for_delay_window(&params);
    println!("Delay window ports: {:?}", delay_ports);
    
    // Test port binding
    engine.bind_to_port(current_port).expect("Failed to bind to current port");
    assert!(bound_ports.lock().contains(&current_port));
    
    // Schedule port transition
    engine.schedule_port_transition(&params).await.expect("Failed to schedule port transition");
    
    // Wait a bit to allow transition to occur
    time::sleep(Duration::from_millis(100)).await;
    
    // Verify next port is bound
    assert!(bound_ports.lock().contains(&next_port));
    
    // Update adaptive delay window
    engine.update_adaptive_delay_window(150.0, 75.0);
    
    // Get updated delay window ports
    let updated_delay_ports = engine.get_ports_for_delay_window(&params);
    println!("Updated delay window ports: {:?}", updated_delay_ports);
    
    // Verify delay window size increased
    assert!(updated_delay_ports.len() > delay_ports.len());
}

#[test]
fn test_port_derivation() {
    // Test ECDH shared secret
    let shared_secret = b"test_shared_secret_for_port_derivation";
    let client_pubkey = b"client_public_key_test";
    let server_pubkey = b"server_public_key_test";
    let session_id = 0x1234567890ABCDEF;
    
    // Derive port hopping parameters
    let params = PortHoppingEngine::derive_port_hopping_params(
        shared_secret,
        client_pubkey,
        server_pubkey,
        session_id,
    );
    
    // Verify parameters
    println!("Port seed: {:08x}", params.port_seed);
    println!("Hop sequence seed: {:08x}", params.hop_sequence_seed);
    println!("Time variance: {}", params.time_variance);
    println!("Hop pattern seed: {:04x}", params.hop_pattern_seed);
    
    // Verify deterministic derivation
    let params2 = PortHoppingEngine::derive_port_hopping_params(
        shared_secret,
        client_pubkey,
        server_pubkey,
        session_id,
    );
    
    assert_eq!(params.port_seed, params2.port_seed);
    assert_eq!(params.hop_sequence_seed, params2.hop_sequence_seed);
    assert_eq!(params.time_variance, params2.time_variance);
    assert_eq!(params.hop_pattern_seed, params2.hop_pattern_seed);
    
    // Verify different inputs produce different outputs
    let params3 = PortHoppingEngine::derive_port_hopping_params(
        shared_secret,
        client_pubkey,
        server_pubkey,
        0x9876543210FEDCBA, // Different session ID
    );
    
    assert_ne!(params.port_seed, params3.port_seed);
}

#[tokio::test]
async fn test_port_calculation_determinism() {
    // Create time sync engine
    let time_sync = Arc::new(TimeSyncEngine::new());
    
    // Create port hopping engine
    let engine = PortHoppingEngine::new(time_sync.clone());
    
    // Create test PSK and derive daily key
    let psk = b"test_psk_for_port_calculation_determinism";
    let daily_key = engine.derive_daily_key(psk, "2023-01-01");
    
    // Test base port calculation determinism
    let mut base_ports = HashSet::new();
    for i in 0..100 {
        let port = engine.calculate_base_port(&daily_key, i);
        base_ports.insert(port);
    }
    
    // Verify we get a good distribution of ports
    println!("Unique base ports in 100 time windows: {}", base_ports.len());
    assert!(base_ports.len() > 90); // Should have high uniqueness
    
    // Test session port calculation determinism
    let params = PortHoppingParams {
        port_seed: 0x12345678,
        hop_sequence_seed: 0x87654321,
        time_variance: 50,
        hop_pattern_seed: 0xABCD,
        session_id: 0x1234567890ABCDEF,
    };
    
    let mut session_ports = HashSet::new();
    for i in 0..100 {
        let port = engine.calculate_session_port(&params, i);
        session_ports.insert(port);
    }
    
    // Verify we get a good distribution of ports
    println!("Unique session ports in 100 time windows: {}", session_ports.len());
    assert!(session_ports.len() > 90); // Should have high uniqueness
    
    // Verify port calculation is consistent
    for i in 0..10 {
        let port1 = engine.calculate_session_port(&params, i);
        let port2 = engine.calculate_session_port(&params, i);
        assert_eq!(port1, port2);
    }
}

#[tokio::test]
async fn test_port_transition_coordination() {
    // Create time sync engine
    let time_sync = Arc::new(TimeSyncEngine::new());
    
    // Create port hopping engine
    let mut engine = PortHoppingEngine::new(time_sync.clone());
    
    // Set up mock callbacks
    let bound_ports = Arc::new(Mutex::new(HashSet::new()));
    let bound_ports_clone = bound_ports.clone();
    let port_transitions = Arc::new(Mutex::new(Vec::new()));
    let port_transitions_clone = port_transitions.clone();
    
    engine.set_bind_port_callback(move |port| {
        println!("Binding to port {}", port);
        bound_ports_clone.lock().insert(port);
        port_transitions_clone.lock().push((true, port));
        true
    });
    
    let bound_ports_clone = bound_ports.clone();
    let port_transitions_clone = port_transitions.clone();
    engine.set_unbind_port_callback(move |port| {
        println!("Unbinding from port {}", port);
        bound_ports_clone.lock().remove(&port);
        port_transitions_clone.lock().push((false, port));
        true
    });
    
    // Start the engine
    engine.start().await.expect("Failed to start port hopping engine");
    
    // Create test port hopping parameters
    let params = PortHoppingParams {
        port_seed: 0x12345678,
        hop_sequence_seed: 0x87654321,
        time_variance: 50,
        hop_pattern_seed: 0xABCD,
        session_id: 0x1234567890ABCDEF,
    };
    
    // Get current and next ports
    let current_port = engine.get_current_session_port(&params);
    let next_port = engine.get_next_session_port(&params);
    
    println!("Current port: {}", current_port);
    println!("Next port: {}", next_port);
    
    // Schedule port transition
    engine.schedule_port_transition(&params).await.expect("Failed to schedule port transition");
    
    // Verify both ports are bound initially
    assert!(bound_ports.lock().contains(&current_port));
    assert!(bound_ports.lock().contains(&next_port));
    
    // Wait for port transition delay plus cleanup
    time::sleep(Duration::from_millis(1500)).await;
    
    // Verify transition occurred
    let transitions = port_transitions.lock();
    
    // Find bind and unbind events
    let mut found_bind_next = false;
    let mut found_unbind_current = false;
    
    for (is_bind, port) in transitions.iter() {
        if *is_bind && *port == next_port {
            found_bind_next = true;
        } else if !*is_bind && *port == current_port {
            found_unbind_current = true;
        }
    }
    
    assert!(found_bind_next, "Should have bound to next port");
    assert!(found_unbind_current, "Should have unbound from current port");
}