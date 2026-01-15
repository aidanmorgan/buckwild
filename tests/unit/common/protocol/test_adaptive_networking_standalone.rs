// Standalone tests for adaptive networking functionality
//
// These tests focus specifically on the adaptive networking module
// without dependencies on other protocol components.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use buckwild_common::protocol::adaptive_networking::{
    AdaptiveNetworkingEngine, DelayMeasurement, NetworkConditions, DelayNegotiationPayload,
    ADAPTIVE_DELAY_WINDOW_MIN, ADAPTIVE_DELAY_WINDOW_MAX, DELAY_MEASUREMENT_SAMPLES,
    DELAY_PERCENTILE_TARGET, HOP_INTERVAL_MS,
};

#[test]
fn test_adaptive_networking_initialization() {
    let engine = AdaptiveNetworkingEngine::new();
    assert!(engine.initialize().is_ok());
    
    let stats = engine.get_network_statistics();
    assert_eq!(stats.effective_delay_window, ADAPTIVE_DELAY_WINDOW_MIN);
    assert!(stats.is_adaptation_enabled);
    assert_eq!(stats.measurement_count, 0);
    assert!(stats.asymmetric_adaptation_enabled);
    assert_eq!(stats.packet_loss_rate, 0.0);
    assert_eq!(stats.network_jitter, 0);
}

#[test]
fn test_delay_measurement_recording() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Record delay measurements with various patterns
    let test_cases = [
        (1000, 1, 1400), // Normal packet
        (1100, 1, 1400), // Another packet
        (1200, 2, 800),  // Control packet
        (1300, 1, 1400), // Another normal packet
        (1400, 1, 1400), // Another packet
    ];

    for (timestamp, packet_type, packet_size) in test_cases {
        let result = engine.measure_packet_delay(timestamp, packet_type, packet_size);
        assert!(result.is_ok(), "Failed to record delay measurement");
    }

    let stats = engine.get_network_statistics();
    assert_eq!(stats.measurement_count, test_cases.len());
}

#[test]
fn test_95th_percentile_delay_calculation() {
    let engine = AdaptiveNetworkingEngine::new();
    
    // Test with known data set
    let delays = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    let p95 = engine.calculate_percentile(&delays, 95);
    assert_eq!(p95, 100, "95th percentile should be 100 for this dataset");

    let p50 = engine.calculate_percentile(&delays, 50);
    assert_eq!(p50, 50, "50th percentile should be 50 for this dataset");

    let p90 = engine.calculate_percentile(&delays, 90);
    assert_eq!(p90, 90, "90th percentile should be 90 for this dataset");

    // Test with empty array
    let empty: Vec<u32> = vec![];
    let p95_empty = engine.calculate_percentile(&empty, 95);
    assert_eq!(p95_empty, 0, "95th percentile of empty array should be 0");

    // Test with single value
    let single = vec![42];
    let p95_single = engine.calculate_percentile(&single, 95);
    assert_eq!(p95_single, 42, "95th percentile of single value should be that value");
}

#[test]
fn test_network_jitter_calculation() {
    let engine = AdaptiveNetworkingEngine::new();
    
    // Test with consistent delays (low jitter)
    let consistent_delays = vec![100, 101, 99, 100, 102];
    let low_jitter = engine.calculate_jitter(&consistent_delays);
    assert!(low_jitter < 5, "Consistent delays should have low jitter, got {}", low_jitter);

    // Test with variable delays (high jitter)
    let variable_delays = vec![50, 150, 75, 125, 100];
    let high_jitter = engine.calculate_jitter(&variable_delays);
    assert!(high_jitter > 20, "Variable delays should have high jitter, got {}", high_jitter);

    // Test with insufficient data
    let insufficient = vec![100];
    let no_jitter = engine.calculate_jitter(&insufficient);
    assert_eq!(no_jitter, 0, "Single value should have zero jitter");

    let empty: Vec<u32> = vec![];
    let empty_jitter = engine.calculate_jitter(&empty);
    assert_eq!(empty_jitter, 0, "Empty array should have zero jitter");
}

#[test]
fn test_adaptive_window_sizing() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Test with low latency, low jitter conditions
    let good_conditions = NetworkConditions {
        timestamp: 1000,
        packet_loss_rate: 0.001, // 0.1% loss
        average_rtt: 50,         // 50ms RTT
        rtt_variance: 5,
        network_jitter: 10,      // 10ms jitter
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    let good_window = engine.calculate_adaptive_port_window(&good_conditions);
    assert!(good_window >= ADAPTIVE_DELAY_WINDOW_MIN);
    assert!(good_window <= ADAPTIVE_DELAY_WINDOW_MAX);

    // Test with poor network conditions
    let poor_conditions = NetworkConditions {
        timestamp: 1000,
        packet_loss_rate: 0.05,  // 5% loss
        average_rtt: 300,        // 300ms RTT
        rtt_variance: 100,
        network_jitter: 200,     // 200ms jitter
        high_latency: true,
        high_jitter: true,
        high_loss: true,
        unstable_network: true,
        congested_network: true,
    };

    let poor_window = engine.calculate_adaptive_port_window(&poor_conditions);
    assert!(poor_window > good_window, "Poor conditions should require larger window");
    assert!(poor_window <= ADAPTIVE_DELAY_WINDOW_MAX);
}

#[test]
fn test_heartbeat_delay_negotiation() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Set some network state
    engine.state.network_jitter.store(50, std::sync::atomic::Ordering::Relaxed);
    engine.state.set_packet_loss_rate(0.02); // 2% loss
    engine.state.current_delay_window.store(5, std::sync::atomic::Ordering::Relaxed);

    // Create enhanced HEARTBEAT payload
    let payload = engine.create_enhanced_heartbeat_payload().unwrap();
    assert!(!payload.is_empty(), "HEARTBEAT payload should not be empty");

    // Process the payload (simulating peer processing)
    let result = engine.process_enhanced_heartbeat_payload(&payload);
    assert!(result.is_ok(), "Failed to process HEARTBEAT payload");

    // Verify negotiation occurred
    let stats = engine.get_network_statistics();
    assert_eq!(stats.negotiated_delay_window, 5, "Negotiated window should match current window");
}

#[test]
fn test_port_listening_strategy_update() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Update port listening strategy
    let ports = engine.update_port_listening_strategy().unwrap();
    
    assert!(!ports.is_empty(), "Should return at least one port");
    assert!(ports.len() <= ADAPTIVE_DELAY_WINDOW_MAX as usize, 
            "Should not exceed maximum window size");
    
    // Verify ports are in reasonable range
    for &port in &ports {
        assert!(port >= 1024, "Ports should be >= 1024");
        assert!(port < 65535, "Ports should be < 65535");
    }
    
    // Verify ports are unique
    let mut sorted_ports = ports.clone();
    sorted_ports.sort_unstable();
    sorted_ports.dedup();
    assert_eq!(sorted_ports.len(), ports.len(), "All ports should be unique");
}

#[test]
fn test_concurrent_delay_measurement() {
    let engine = Arc::new(AdaptiveNetworkingEngine::new());
    engine.initialize().unwrap();

    let mut handles = vec![];

    // Spawn multiple threads recording measurements concurrently
    for thread_id in 0..4 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            for i in 0..25 {
                let timestamp = 1000 + (thread_id * 1000 + i) as u64;
                let result = engine_clone.measure_packet_delay(timestamp, 1, 1400);
                assert!(result.is_ok(), "Concurrent measurement should succeed");
                
                // Small delay to simulate realistic timing
                thread::sleep(Duration::from_millis(1));
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    let stats = engine.get_network_statistics();
    assert_eq!(stats.measurement_count, 100, "Should record all measurements from all threads");
}

#[test]
fn test_adaptation_enable_disable() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Test enabling/disabling adaptation
    assert!(engine.get_network_statistics().is_adaptation_enabled);

    engine.set_adaptation_enabled(false);
    assert!(!engine.get_network_statistics().is_adaptation_enabled);
    assert_eq!(engine.state.get_effective_delay_window(), ADAPTIVE_DELAY_WINDOW_MIN);

    engine.set_adaptation_enabled(true);
    assert!(engine.get_network_statistics().is_adaptation_enabled);

    // Test asymmetric adaptation toggle
    assert!(engine.get_network_statistics().asymmetric_adaptation_enabled);

    engine.set_asymmetric_adaptation_enabled(false);
    assert!(!engine.get_network_statistics().asymmetric_adaptation_enabled);

    engine.set_asymmetric_adaptation_enabled(true);
    assert!(engine.get_network_statistics().asymmetric_adaptation_enabled);
}

#[test]
fn test_delay_negotiation_payload_serialization() {
    let payload = DelayNegotiationPayload {
        current_delay_window: 5,
        network_jitter: 50,
        packet_loss_rate: 20, // 2% as per-mille
        measurement_count: 10,
        is_adaptation_enabled: true,
        negotiation_sequence: 42,
    };

    // Test serialization
    let serialized = bincode::serialize(&payload).unwrap();
    assert!(!serialized.is_empty(), "Serialized payload should not be empty");

    // Test deserialization
    let deserialized: DelayNegotiationPayload = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.current_delay_window, payload.current_delay_window);
    assert_eq!(deserialized.network_jitter, payload.network_jitter);
    assert_eq!(deserialized.packet_loss_rate, payload.packet_loss_rate);
    assert_eq!(deserialized.measurement_count, payload.measurement_count);
    assert_eq!(deserialized.is_adaptation_enabled, payload.is_adaptation_enabled);
    assert_eq!(deserialized.negotiation_sequence, payload.negotiation_sequence);
}

#[test]
fn test_network_statistics_completeness() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Add some measurements and update state
    for i in 0..5 {
        engine.measure_packet_delay(1000 + i * 100, 1, 1400).unwrap();
    }

    engine.state.network_jitter.store(75, std::sync::atomic::Ordering::Relaxed);
    engine.state.set_packet_loss_rate(0.015); // 1.5%
    engine.state.negotiated_delay_window.store(6, std::sync::atomic::Ordering::Relaxed);
    engine.state.peer_delay_window.store(4, std::sync::atomic::Ordering::Relaxed);

    let stats = engine.get_network_statistics();

    // Verify all statistics are populated
    assert!(stats.effective_delay_window >= ADAPTIVE_DELAY_WINDOW_MIN);
    assert!(stats.effective_delay_window <= ADAPTIVE_DELAY_WINDOW_MAX);
    assert_eq!(stats.past_window_size + 1 + stats.future_window_size, stats.effective_delay_window);
    assert_eq!(stats.negotiated_delay_window, 6);
    assert_eq!(stats.peer_delay_window, 4);
    assert_eq!(stats.network_jitter, 75);
    assert!((stats.packet_loss_rate - 0.015).abs() < 0.001);
    assert_eq!(stats.measurement_count, 5);
    assert!(stats.is_adaptation_enabled);
    assert!(stats.asymmetric_adaptation_enabled);
    assert!(stats.early_packet_ratio >= 0.0 && stats.early_packet_ratio <= 1.0);
    assert!(stats.late_packet_ratio >= 0.0 && stats.late_packet_ratio <= 1.0);
    assert!(stats.network_conditions.timestamp > 0);
}

#[test]
fn test_boundary_conditions() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Test with maximum delay window
    engine.state.current_delay_window.store(ADAPTIVE_DELAY_WINDOW_MAX, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(engine.state.get_effective_delay_window(), ADAPTIVE_DELAY_WINDOW_MAX);

    // Test with minimum delay window
    engine.state.current_delay_window.store(ADAPTIVE_DELAY_WINDOW_MIN, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(engine.state.get_effective_delay_window(), ADAPTIVE_DELAY_WINDOW_MIN);

    // Test with extreme network conditions
    let extreme_conditions = NetworkConditions {
        timestamp: 1000,
        packet_loss_rate: 1.0,  // 100% loss (theoretical maximum)
        average_rtt: u32::MAX,  // Maximum RTT
        rtt_variance: u32::MAX,
        network_jitter: u32::MAX,
        high_latency: true,
        high_jitter: true,
        high_loss: true,
        unstable_network: true,
        congested_network: true,
    };

    let extreme_window = engine.calculate_adaptive_port_window(&extreme_conditions);
    assert_eq!(extreme_window, ADAPTIVE_DELAY_WINDOW_MAX, 
               "Extreme conditions should result in maximum window");

    // Test with perfect network conditions
    let perfect_conditions = NetworkConditions {
        timestamp: 1000,
        packet_loss_rate: 0.0,
        average_rtt: 1,
        rtt_variance: 0,
        network_jitter: 0,
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    let perfect_window = engine.calculate_adaptive_port_window(&perfect_conditions);
    assert!(perfect_window >= ADAPTIVE_DELAY_WINDOW_MIN, 
            "Perfect conditions should still meet minimum window requirement");
}