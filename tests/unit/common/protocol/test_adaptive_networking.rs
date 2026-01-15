// Comprehensive unit tests for adaptive networking and dynamic delay tuning
//
// This file tests the adaptive delay measurement and tuning mechanisms that optimize
// port hopping timing based on real-time network conditions.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use buckwild_common::protocol::{
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
        (1000, 1, 1400, false), // Normal packet
        (1100, 1, 1400, true),  // Early packet
        (1200, 2, 800, false),  // Control packet
        (1300, 1, 1400, false), // Another normal packet
        (1400, 1, 1400, true),  // Another early packet
    ];

    for (timestamp, packet_type, packet_size, _expected_early) in test_cases {
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
fn test_packet_loss_rate_calculation() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Add measurements with sequence gaps to simulate packet loss
    let measurements = vec![
        DelayMeasurement {
            delay_ms: 50,
            timestamp: 1000,
            sequence: 1,
            packet_type: 1,
            packet_size: 1400,
            rtt_estimate: 100,
            is_early: false,
        },
        DelayMeasurement {
            delay_ms: 60,
            timestamp: 1100,
            sequence: 2,
            packet_type: 1,
            packet_size: 1400,
            rtt_estimate: 100,
            is_early: false,
        },
        // Missing sequence 3 (simulated packet loss)
        DelayMeasurement {
            delay_ms: 55,
            timestamp: 1300,
            sequence: 4,
            packet_type: 1,
            packet_size: 1400,
            rtt_estimate: 100,
            is_early: false,
        },
        DelayMeasurement {
            delay_ms: 65,
            timestamp: 1400,
            sequence: 5,
            packet_type: 1,
            packet_size: 1400,
            rtt_estimate: 100,
            is_early: false,
        },
    ];

    // Add measurements to engine
    {
        let mut delay_measurements = engine.state.delay_measurements.write();
        for measurement in measurements {
            delay_measurements.push_back(measurement);
        }
    }

    // Calculate packet loss rate
    let loss_rate = engine.calculate_packet_loss_rate().unwrap();
    
    // Expected: 4 received out of 5 expected (sequences 1-5) = 20% loss
    assert!(loss_rate > 0.15 && loss_rate < 0.25, 
            "Expected ~20% loss rate, got {:.3}%", loss_rate * 100.0);
}

#[test]
fn test_asymmetric_window_adaptation() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();
    
    // Enable asymmetric adaptation
    engine.set_asymmetric_adaptation_enabled(true);

    // Add measurements with bias toward early packets (75% early)
    let mut measurements = Vec::new();
    for i in 0..DELAY_MEASUREMENT_SAMPLES {
        let is_early = i < (DELAY_MEASUREMENT_SAMPLES * 3) / 4;
        let delay = if is_early { 30 } else { 120 }; // Early packets have less delay
        
        measurements.push(DelayMeasurement {
            delay_ms: delay,
            timestamp: 1000 + i as u64 * 100,
            sequence: i as u64,
            packet_type: 1,
            packet_size: 1400,
            rtt_estimate: 100,
            is_early,
        });
    }

    // Add measurements to engine
    {
        let mut delay_measurements = engine.state.delay_measurements.write();
        for measurement in measurements {
            delay_measurements.push_back(measurement);
        }
    }

    // Trigger window update
    engine.update_adaptive_delay_window().unwrap();

    let (past, _current, future) = engine.state.get_asymmetric_windows();
    let stats = engine.get_network_statistics();
    
    // Verify asymmetric adaptation occurred
    assert!(stats.early_packet_ratio > 0.7, "Should detect high early packet ratio");
    assert!(past + future >= ADAPTIVE_DELAY_WINDOW_MIN - 1, "Total window should meet minimum");
    
    // With more early packets, the algorithm should adapt the window accordingly
    assert!(past + 1 + future <= ADAPTIVE_DELAY_WINDOW_MAX, "Total window should not exceed maximum");
}

#[test]
fn test_network_condition_assessment() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Add sufficient measurements for assessment
    for i in 0..DELAY_MEASUREMENT_SAMPLES {
        let delay = 50 + (i % 3) * 10; // Some variation in delays
        let measurement = DelayMeasurement {
            delay_ms: delay as u32,
            timestamp: 1000 + i as u64 * 100,
            sequence: i as u64,
            packet_type: 1,
            packet_size: 1400,
            rtt_estimate: 100 + (i % 5) as u32 * 10, // Some RTT variation
            is_early: i % 4 == 0, // 25% early packets
        };

        engine.state.delay_measurements.write().push_back(measurement);
    }

    // Assess network conditions
    let conditions = engine.assess_network_conditions().unwrap();
    
    assert!(conditions.timestamp > 0, "Timestamp should be set");
    assert!(conditions.packet_loss_rate >= 0.0, "Loss rate should be non-negative");
    assert!(conditions.average_rtt > 0, "Average RTT should be positive");
    assert!(conditions.network_jitter >= 0, "Jitter should be non-negative");
    
    // Verify condition flags are set appropriately
    assert_eq!(conditions.high_latency, conditions.average_rtt > 200);
    assert_eq!(conditions.high_jitter, conditions.network_jitter > 100);
    assert_eq!(conditions.high_loss, conditions.packet_loss_rate > 0.02);
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
fn test_window_optimization() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();
    
    // Set initial window sizes
    engine.state.past_window_size.store(4, std::sync::atomic::Ordering::Relaxed);
    engine.state.future_window_size.store(4, std::sync::atomic::Ordering::Relaxed);
    engine.state.current_delay_window.store(9, std::sync::atomic::Ordering::Relaxed);
    
    // Set low packet loss to enable optimization
    engine.state.set_packet_loss_rate(0.001); // 0.1% loss
    
    // Trigger optimization
    engine.periodic_window_optimization().unwrap();
    
    // Check if optimization test was started
    let test_state = engine.state.window_optimization_test.read();
    if test_state.is_some() {
        let test = test_state.as_ref().unwrap();
        assert!(test.test_past < test.original_past || test.test_future < test.original_future,
                "Optimization should attempt smaller windows");
        assert!(test.packet_loss_baseline >= 0.0, "Baseline loss rate should be recorded");
    }
}

#[test]
fn test_rtt_statistics_calculation() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Add measurements with known RTT values
    let rtt_values = vec![80, 100, 120, 90, 110];
    for (i, &rtt) in rtt_values.iter().enumerate() {
        let measurement = DelayMeasurement {
            delay_ms: 50,
            timestamp: 1000 + i as u64 * 100,
            sequence: i as u64,
            packet_type: 1,
            packet_size: 1400,
            rtt_estimate: rtt,
            is_early: false,
        };
        engine.state.delay_measurements.write().push_back(measurement);
    }

    let rtt_stats = engine.calculate_rtt_statistics();
    
    // Expected average: (80 + 100 + 120 + 90 + 110) / 5 = 100
    assert_eq!(rtt_stats.average, 100, "Average RTT should be 100ms");
    assert_eq!(rtt_stats.minimum, 80, "Minimum RTT should be 80ms");
    assert_eq!(rtt_stats.maximum, 120, "Maximum RTT should be 120ms");
    assert!(rtt_stats.variance > 0, "RTT variance should be positive");
}

#[test]
fn test_congestion_detection() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Create conditions indicating congestion
    let rtt_stats = buckwild_common::protocol::RttStatistics {
        average: 250,    // High RTT
        variance: 150,   // High variance
        minimum: 100,
        maximum: 400,
    };

    // Set high packet loss
    engine.state.set_packet_loss_rate(0.03); // 3% loss
    engine.state.network_jitter.store(200, std::sync::atomic::Ordering::Relaxed); // High jitter

    let is_congested = engine.detect_congestion_indicators(&rtt_stats);
    assert!(is_congested, "Should detect congestion with high loss, jitter, and RTT variance");

    // Test with good conditions
    let good_rtt_stats = buckwild_common::protocol::RttStatistics {
        average: 50,     // Low RTT
        variance: 10,    // Low variance
        minimum: 40,
        maximum: 60,
    };

    engine.state.set_packet_loss_rate(0.001); // 0.1% loss
    engine.state.network_jitter.store(20, std::sync::atomic::Ordering::Relaxed); // Low jitter

    let is_not_congested = engine.detect_congestion_indicators(&good_rtt_stats);
    assert!(!is_not_congested, "Should not detect congestion with good conditions");
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
    assert_eq!(engine.get_effective_delay_window(), ADAPTIVE_DELAY_WINDOW_MIN);

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
    assert_eq!(engine.get_effective_delay_window(), ADAPTIVE_DELAY_WINDOW_MAX);

    // Test with minimum delay window
    engine.state.current_delay_window.store(ADAPTIVE_DELAY_WINDOW_MIN, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(engine.get_effective_delay_window(), ADAPTIVE_DELAY_WINDOW_MIN);

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