// Integration tests for adaptive networking and dynamic delay tuning
//
// This file tests the integration of adaptive delay measurement and tuning with
// the broader protocol system, including HEARTBEAT negotiation and port hopping.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

use buckwild_common::protocol::{
    AdaptiveNetworkingEngine, NetworkConditions, DelayNegotiationPayload,
    ADAPTIVE_DELAY_WINDOW_MIN, ADAPTIVE_DELAY_WINDOW_MAX, DELAY_MEASUREMENT_SAMPLES,
    HOP_INTERVAL_MS,
};

/// Simulate network conditions for testing
#[derive(Debug, Clone)]
struct NetworkSimulator {
    base_latency: u32,
    jitter_range: u32,
    packet_loss_rate: f64,
    congestion_factor: f64,
}

impl NetworkSimulator {
    fn new(base_latency: u32, jitter_range: u32, packet_loss_rate: f64) -> Self {
        Self {
            base_latency,
            jitter_range,
            packet_loss_rate,
            congestion_factor: 1.0,
        }
    }

    fn with_congestion(mut self, factor: f64) -> Self {
        self.congestion_factor = factor;
        self
    }

    /// Simulate packet transmission with network conditions
    fn simulate_packet_transmission(&self, sequence: u64) -> Option<(u64, u32)> {
        // Simulate packet loss
        if rand::random::<f64>() < self.packet_loss_rate {
            return None; // Packet lost
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Add base latency with jitter
        let jitter = if self.jitter_range > 0 {
            rand::random::<u32>() % self.jitter_range
        } else {
            0
        };

        let total_latency = (self.base_latency as f64 * self.congestion_factor) as u32 + jitter;
        let arrival_time = current_time + total_latency as u64;

        Some((arrival_time, total_latency))
    }
}

#[test]
fn test_adaptive_networking_with_good_network_conditions() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    let simulator = NetworkSimulator::new(50, 10, 0.001); // Good conditions: 50ms ±10ms, 0.1% loss

    // Simulate packet arrivals over time
    for i in 0..DELAY_MEASUREMENT_SAMPLES * 2 {
        if let Some((arrival_time, latency)) = simulator.simulate_packet_transmission(i as u64) {
            // Simulate measuring the delay when packet arrives
            engine.measure_packet_delay(arrival_time, 1, 1400).unwrap();
            
            // Small delay to simulate realistic packet intervals
            thread::sleep(Duration::from_millis(10));
        }
    }

    // Assess network conditions
    let conditions = engine.assess_network_conditions().unwrap();
    
    // Verify good conditions are detected
    assert!(!conditions.high_latency, "Should not detect high latency with good conditions");
    assert!(!conditions.high_jitter, "Should not detect high jitter with good conditions");
    assert!(!conditions.high_loss, "Should not detect high loss with good conditions");
    assert!(!conditions.congested_network, "Should not detect congestion with good conditions");

    // Verify adaptive window is reasonable for good conditions
    let window = engine.calculate_adaptive_port_window(&conditions);
    assert!(window <= ADAPTIVE_DELAY_WINDOW_MIN + 2, 
            "Good conditions should result in small window, got {}", window);
}

#[test]
fn test_adaptive_networking_with_poor_network_conditions() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    let simulator = NetworkSimulator::new(200, 100, 0.05) // Poor conditions: 200ms ±100ms, 5% loss
        .with_congestion(1.5); // 50% congestion increase

    // Simulate packet arrivals with poor conditions
    let mut successful_measurements = 0;
    for i in 0..DELAY_MEASUREMENT_SAMPLES * 3 {
        if let Some((arrival_time, latency)) = simulator.simulate_packet_transmission(i as u64) {
            engine.measure_packet_delay(arrival_time, 1, 1400).unwrap();
            successful_measurements += 1;
            thread::sleep(Duration::from_millis(20));
        }
    }

    // Ensure we got enough measurements despite packet loss
    assert!(successful_measurements >= DELAY_MEASUREMENT_SAMPLES, 
            "Should have enough measurements despite packet loss");

    // Assess network conditions
    let conditions = engine.assess_network_conditions().unwrap();
    
    // Verify poor conditions are detected
    assert!(conditions.high_latency, "Should detect high latency with poor conditions");
    assert!(conditions.high_jitter, "Should detect high jitter with poor conditions");
    assert!(conditions.high_loss, "Should detect high loss with poor conditions");
    assert!(conditions.packet_loss_rate > 0.03, "Should measure significant packet loss");

    // Verify adaptive window increases for poor conditions
    let window = engine.calculate_adaptive_port_window(&conditions);
    assert!(window > ADAPTIVE_DELAY_WINDOW_MIN + 2, 
            "Poor conditions should result in larger window, got {}", window);
    assert!(window <= ADAPTIVE_DELAY_WINDOW_MAX, "Window should not exceed maximum");
}

#[test]
fn test_heartbeat_negotiation_between_peers() {
    let peer1 = AdaptiveNetworkingEngine::new();
    let peer2 = AdaptiveNetworkingEngine::new();
    
    peer1.initialize().unwrap();
    peer2.initialize().unwrap();

    // Set different network conditions for each peer
    peer1.state.current_delay_window.store(3, std::sync::atomic::Ordering::Relaxed);
    peer1.state.network_jitter.store(30, std::sync::atomic::Ordering::Relaxed);
    peer1.state.set_packet_loss_rate(0.01); // 1%

    peer2.state.current_delay_window.store(5, std::sync::atomic::Ordering::Relaxed);
    peer2.state.network_jitter.store(80, std::sync::atomic::Ordering::Relaxed);
    peer2.state.set_packet_loss_rate(0.03); // 3%

    // Peer1 creates HEARTBEAT payload
    let peer1_payload = peer1.create_enhanced_heartbeat_payload().unwrap();
    
    // Peer2 processes peer1's HEARTBEAT
    peer2.process_enhanced_heartbeat_payload(&peer1_payload).unwrap();
    
    // Peer2 creates response HEARTBEAT payload
    let peer2_payload = peer2.create_enhanced_heartbeat_payload().unwrap();
    
    // Peer1 processes peer2's HEARTBEAT
    peer1.process_enhanced_heartbeat_payload(&peer2_payload).unwrap();

    // Verify negotiation results
    let peer1_stats = peer1.get_network_statistics();
    let peer2_stats = peer2.get_network_statistics();

    // Both peers should negotiate to use the larger window (5)
    assert_eq!(peer1_stats.negotiated_delay_window, 5, 
               "Peer1 should negotiate to larger window");
    assert_eq!(peer2_stats.negotiated_delay_window, 5, 
               "Peer2 should negotiate to larger window");

    // Verify peer information is stored
    assert_eq!(peer1_stats.peer_delay_window, 5, "Peer1 should know peer2's window");
    assert_eq!(peer2_stats.peer_delay_window, 3, "Peer2 should know peer1's window");
}

#[test]
fn test_port_listening_strategy_adaptation() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Test with minimal window
    engine.state.current_delay_window.store(ADAPTIVE_DELAY_WINDOW_MIN, std::sync::atomic::Ordering::Relaxed);
    let min_ports = engine.update_port_listening_strategy().unwrap();
    assert_eq!(min_ports.len(), ADAPTIVE_DELAY_WINDOW_MIN as usize, 
               "Minimum window should result in minimum ports");

    // Test with larger window
    engine.state.current_delay_window.store(8, std::sync::atomic::Ordering::Relaxed);
    let more_ports = engine.update_port_listening_strategy().unwrap();
    assert_eq!(more_ports.len(), 8, "Larger window should result in more ports");
    assert!(more_ports.len() > min_ports.len(), "More ports should be required for larger window");

    // Test with maximum window
    engine.state.current_delay_window.store(ADAPTIVE_DELAY_WINDOW_MAX, std::sync::atomic::Ordering::Relaxed);
    let max_ports = engine.update_port_listening_strategy().unwrap();
    assert_eq!(max_ports.len(), ADAPTIVE_DELAY_WINDOW_MAX as usize, 
               "Maximum window should result in maximum ports");

    // Verify all ports are unique and in valid range
    for &port in &max_ports {
        assert!(port >= 1024, "Port should be >= 1024");
        assert!(port < 65535, "Port should be < 65535");
    }

    let mut sorted_ports = max_ports.clone();
    sorted_ports.sort_unstable();
    sorted_ports.dedup();
    assert_eq!(sorted_ports.len(), max_ports.len(), "All ports should be unique");
}

#[test]
fn test_asymmetric_window_adaptation_with_timing_patterns() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();
    engine.set_asymmetric_adaptation_enabled(true);

    // Simulate network with consistent early packet bias
    let simulator = NetworkSimulator::new(30, 20, 0.001); // Low latency, some jitter

    let mut early_count = 0;
    let mut late_count = 0;

    for i in 0..DELAY_MEASUREMENT_SAMPLES * 2 {
        if let Some((arrival_time, _latency)) = simulator.simulate_packet_transmission(i as u64) {
            // Simulate timing measurement
            let expected_time = 1000 + i as u64 * HOP_INTERVAL_MS as u64;
            let is_early = arrival_time < expected_time;
            
            if is_early {
                early_count += 1;
            } else {
                late_count += 1;
            }

            engine.measure_packet_delay(arrival_time, 1, 1400).unwrap();
            thread::sleep(Duration::from_millis(5));
        }
    }

    // Assess the adaptation
    let stats = engine.get_network_statistics();
    let (past_window, _current, future_window) = engine.state.get_asymmetric_windows();

    // Verify asymmetric adaptation occurred
    assert!(stats.measurement_count >= DELAY_MEASUREMENT_SAMPLES, 
            "Should have sufficient measurements");
    
    // The exact window sizes depend on the algorithm, but total should be reasonable
    assert!(past_window + 1 + future_window >= ADAPTIVE_DELAY_WINDOW_MIN, 
            "Total window should meet minimum requirement");
    assert!(past_window + 1 + future_window <= ADAPTIVE_DELAY_WINDOW_MAX, 
            "Total window should not exceed maximum");

    println!("Timing pattern: {} early, {} late packets", early_count, late_count);
    println!("Asymmetric windows: past={}, future={}", past_window, future_window);
}

#[test]
fn test_window_optimization_under_improving_conditions() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Start with poor conditions requiring large window
    engine.state.current_delay_window.store(10, std::sync::atomic::Ordering::Relaxed);
    engine.state.past_window_size.store(4, std::sync::atomic::Ordering::Relaxed);
    engine.state.future_window_size.store(5, std::sync::atomic::Ordering::Relaxed);
    engine.state.set_packet_loss_rate(0.001); // Very low loss to enable optimization

    // Add measurements indicating good conditions
    for i in 0..DELAY_MEASUREMENT_SAMPLES {
        engine.measure_packet_delay(1000 + i as u64 * 100, 1, 1400).unwrap();
    }

    // Trigger optimization attempt
    engine.periodic_window_optimization().unwrap();

    // Check if optimization test was initiated
    let test_state = engine.state.window_optimization_test.read();
    if let Some(test) = test_state.as_ref() {
        assert!(test.test_past <= test.original_past, 
                "Optimization should attempt smaller past window");
        assert!(test.test_future <= test.original_future, 
                "Optimization should attempt smaller future window");
        assert!(test.packet_loss_baseline < 0.01, 
                "Baseline loss should be low to enable optimization");
    }

    // Simulate successful optimization (low packet loss continues)
    engine.state.set_packet_loss_rate(0.0005); // Even lower loss
    
    // Evaluate optimization after sufficient time
    thread::sleep(Duration::from_millis(10)); // Simulate time passage
    engine.evaluate_window_optimization_test().unwrap();
}

#[test]
fn test_concurrent_adaptive_networking_operations() {
    let engine = Arc::new(AdaptiveNetworkingEngine::new());
    engine.initialize().unwrap();

    let mut handles = vec![];

    // Thread 1: Continuous delay measurements
    let engine1 = Arc::clone(&engine);
    let handle1 = thread::spawn(move || {
        let simulator = NetworkSimulator::new(75, 25, 0.02);
        for i in 0..50 {
            if let Some((arrival_time, _)) = simulator.simulate_packet_transmission(i) {
                engine1.measure_packet_delay(arrival_time, 1, 1400).unwrap();
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    handles.push(handle1);

    // Thread 2: Periodic network assessment
    let engine2 = Arc::clone(&engine);
    let handle2 = thread::spawn(move || {
        for _ in 0..10 {
            thread::sleep(Duration::from_millis(100));
            let _conditions = engine2.assess_network_conditions().unwrap();
        }
    });
    handles.push(handle2);

    // Thread 3: HEARTBEAT negotiation simulation
    let engine3 = Arc::clone(&engine);
    let handle3 = thread::spawn(move || {
        for _ in 0..5 {
            thread::sleep(Duration::from_millis(200));
            let payload = engine3.create_enhanced_heartbeat_payload().unwrap();
            engine3.process_enhanced_heartbeat_payload(&payload).unwrap();
        }
    });
    handles.push(handle3);

    // Thread 4: Port strategy updates
    let engine4 = Arc::clone(&engine);
    let handle4 = thread::spawn(move || {
        for _ in 0..8 {
            thread::sleep(Duration::from_millis(125));
            let _ports = engine4.update_port_listening_strategy().unwrap();
        }
    });
    handles.push(handle4);

    // Wait for all operations to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify system state is consistent after concurrent operations
    let stats = engine.get_network_statistics();
    assert!(stats.measurement_count > 0, "Should have recorded measurements");
    assert!(stats.effective_delay_window >= ADAPTIVE_DELAY_WINDOW_MIN, 
            "Window should be within valid range");
    assert!(stats.effective_delay_window <= ADAPTIVE_DELAY_WINDOW_MAX, 
            "Window should be within valid range");
}

#[test]
fn test_network_condition_history_tracking() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Add measurements to enable condition assessment
    for i in 0..DELAY_MEASUREMENT_SAMPLES {
        engine.measure_packet_delay(1000 + i as u64 * 100, 1, 1400).unwrap();
    }

    // Perform multiple assessments to build history
    let mut conditions_history = Vec::new();
    for i in 0..10 {
        // Simulate changing network conditions
        let loss_rate = (i as f64) * 0.005; // Gradually increasing loss
        engine.state.set_packet_loss_rate(loss_rate);
        
        let conditions = engine.assess_network_conditions().unwrap();
        conditions_history.push(conditions.clone());
        
        thread::sleep(Duration::from_millis(10));
    }

    // Verify history is maintained
    let history = engine.state.performance_history.read();
    assert_eq!(history.len(), 10, "Should maintain history of all assessments");

    // Verify history shows progression
    let first_condition = &history[0];
    let last_condition = &history[history.len() - 1];
    assert!(last_condition.packet_loss_rate > first_condition.packet_loss_rate, 
            "History should show increasing packet loss");
    assert!(last_condition.timestamp > first_condition.timestamp, 
            "History should be chronologically ordered");
}

#[test]
fn test_adaptive_networking_with_mixed_packet_types() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    let simulator = NetworkSimulator::new(100, 30, 0.015);

    // Simulate different packet types with different characteristics
    let packet_types = [
        (1, 1400), // Data packets
        (2, 64),   // Control packets
        (3, 32),   // Heartbeat packets
        (4, 1400), // Fragment packets
    ];

    for i in 0..DELAY_MEASUREMENT_SAMPLES * 2 {
        let (packet_type, packet_size) = packet_types[i % packet_types.len()];
        
        if let Some((arrival_time, _)) = simulator.simulate_packet_transmission(i as u64) {
            engine.measure_packet_delay(arrival_time, packet_type, packet_size).unwrap();
            thread::sleep(Duration::from_millis(15));
        }
    }

    // Assess conditions with mixed packet types
    let conditions = engine.assess_network_conditions().unwrap();
    let stats = engine.get_network_statistics();

    // Verify system handles mixed packet types correctly
    assert!(stats.measurement_count > DELAY_MEASUREMENT_SAMPLES, 
            "Should record measurements for all packet types");
    assert!(conditions.average_rtt > 0, "Should calculate RTT from mixed packets");
    assert!(conditions.network_jitter >= 0, "Should calculate jitter from mixed packets");

    // Verify adaptive window calculation works with mixed types
    let window = engine.calculate_adaptive_port_window(&conditions);
    assert!(window >= ADAPTIVE_DELAY_WINDOW_MIN && window <= ADAPTIVE_DELAY_WINDOW_MAX, 
            "Window should be valid for mixed packet types");
}

#[test]
fn test_extreme_network_condition_handling() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Test with extremely poor conditions
    let extreme_simulator = NetworkSimulator::new(1000, 500, 0.3) // 1s ±500ms, 30% loss
        .with_congestion(3.0); // 3x congestion

    let mut successful_measurements = 0;
    for i in 0..DELAY_MEASUREMENT_SAMPLES * 5 {
        if let Some((arrival_time, _)) = extreme_simulator.simulate_packet_transmission(i as u64) {
            engine.measure_packet_delay(arrival_time, 1, 1400).unwrap();
            successful_measurements += 1;
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Even with extreme conditions, system should remain stable
    assert!(successful_measurements > 0, "Should record some measurements even in extreme conditions");

    let conditions = engine.assess_network_conditions().unwrap();
    assert!(conditions.high_latency, "Should detect high latency");
    assert!(conditions.high_jitter, "Should detect high jitter");
    assert!(conditions.high_loss, "Should detect high loss");
    assert!(conditions.congested_network, "Should detect congestion");

    // System should adapt to maximum window for extreme conditions
    let window = engine.calculate_adaptive_port_window(&conditions);
    assert_eq!(window, ADAPTIVE_DELAY_WINDOW_MAX, 
               "Extreme conditions should result in maximum window");

    // Verify system remains functional
    let stats = engine.get_network_statistics();
    assert!(stats.effective_delay_window <= ADAPTIVE_DELAY_WINDOW_MAX, 
            "System should remain within bounds even in extreme conditions");
}

// Helper function to create realistic network conditions for testing
fn create_network_conditions(latency: u32, jitter: u32, loss: f64) -> NetworkConditions {
    NetworkConditions {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        packet_loss_rate: loss,
        average_rtt: latency,
        rtt_variance: jitter / 2, // Approximate variance from jitter
        network_jitter: jitter,
        high_latency: latency > 200,
        high_jitter: jitter > 100,
        high_loss: loss > 0.02,
        unstable_network: jitter > 50,
        congested_network: loss > 0.01 && latency > 150,
    }
}

#[test]
fn test_realistic_network_scenarios() {
    let scenarios = [
        ("WiFi Good", 25, 10, 0.001),
        ("WiFi Poor", 150, 75, 0.02),
        ("Mobile 4G", 80, 40, 0.005),
        ("Mobile 3G", 200, 100, 0.015),
        ("Satellite", 600, 200, 0.01),
        ("Congested", 300, 150, 0.05),
    ];

    for (name, latency, jitter, loss) in scenarios {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();

        let conditions = create_network_conditions(latency, jitter, loss);
        let window = engine.calculate_adaptive_port_window(&conditions);

        println!("Scenario {}: latency={}ms, jitter={}ms, loss={:.1}% -> window={}",
                 name, latency, jitter, loss * 100.0, window);

        // Verify window is appropriate for conditions
        assert!(window >= ADAPTIVE_DELAY_WINDOW_MIN, 
                "Window should meet minimum for scenario {}", name);
        assert!(window <= ADAPTIVE_DELAY_WINDOW_MAX, 
                "Window should not exceed maximum for scenario {}", name);

        // Poor conditions should generally result in larger windows
        if loss > 0.02 || latency > 200 || jitter > 100 {
            assert!(window > ADAPTIVE_DELAY_WINDOW_MIN, 
                    "Poor conditions should increase window for scenario {}", name);
        }
    }
}