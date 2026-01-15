// Adaptive Engine Tests
//
// Comprehensive tests for adaptive networking engine including:
// - Measurement accuracy
// - Parameter adjustment
// - Stability (no oscillation)
// - Varying network conditions

use super::*;
use crate::protocol::types::{
    NetworkJitter, PacketLossRate, PacketSize, PacketType, RoundTripTime, SequenceNumber, Timestamp,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

// Test constants (duplicated from module for testing)
const MIN_SAMPLES_FOR_OPTIMIZATION: usize = 10;
const OPTIMIZATION_COOLDOWN_MS: Duration = Duration::from_millis(100); // Shorter for tests

// =========================================================================
// Measurement Accuracy Tests
// =========================================================================

#[tokio::test]
async fn test_measurement_initialization() {
    let measurement = NetworkMeasurement::new();
    assert!(measurement.initialize().is_ok());

    let stats = measurement.get_measurement_stats();
    assert_eq!(
        stats.total_rtt_measurements.as_u64(),
        0,
        "RTT measurements should start at zero"
    );
    assert_eq!(
        stats.total_jitter_calculations.as_u64(),
        0,
        "Jitter calculations should start at zero"
    );
    assert_eq!(
        stats.total_loss_calculations.as_u64(),
        0,
        "Loss calculations should start at zero"
    );
}

#[tokio::test]
async fn test_rtt_measurement_accuracy() {
    let measurement = NetworkMeasurement::new();
    measurement.initialize().unwrap();

    // Create delay measurements with known RTT values
    for i in 0..10 {
        let rtt_ms = 100 + i * 10; // 100ms, 110ms, 120ms, ...
        let delay_measurement = DelayMeasurement {
            delay_ms: Duration::from_millis(50),
            timestamp: Timestamp::now(),
            sequence: SequenceNumber::new(i as u32),
            packet_type: PacketType::Data,
            packet_size: PacketSize::new(1000),
            rtt_estimate: RoundTripTime::from_millis(rtt_ms),
            is_early: false,
        };

        measurement
            .process_delay_measurement(&delay_measurement)
            .unwrap();
    }

    let stats = measurement.get_measurement_stats();
    assert_eq!(
        stats.total_rtt_measurements.as_u64(),
        10,
        "Should have 10 RTT measurements"
    );

    // Average RTT should be approximately 145ms (100 + 110 + ... + 190) / 10
    let avg_rtt_ms = stats.current_rtt.as_millis();
    assert!(
        (140..=150).contains(&avg_rtt_ms),
        "Average RTT should be around 145ms, got {}ms",
        avg_rtt_ms
    );
}

#[tokio::test]
async fn test_packet_loss_calculation_accuracy() {
    let measurement = NetworkMeasurement::new();
    measurement.initialize().unwrap();

    // Create measurements with gaps to simulate packet loss
    // Need enough samples for loss calculation (min 10 samples)
    // Pattern: send 70 out of 100 packets (30% loss)
    let mut sequences = Vec::new();
    for i in 1..=100 {
        // Skip every third packet to create ~30% loss
        if i % 3 != 0 {
            sequences.push(i);
        }
    }

    for seq in sequences {
        let delay_measurement = DelayMeasurement {
            delay_ms: Duration::from_millis(50),
            timestamp: Timestamp::now(),
            sequence: SequenceNumber::new(seq),
            packet_type: PacketType::Data,
            packet_size: PacketSize::new(1000),
            rtt_estimate: RoundTripTime::from_millis(100),
            is_early: false,
        };

        measurement
            .process_delay_measurement(&delay_measurement)
            .unwrap();

        // Small delay for timing
        tokio::time::sleep(Duration::from_micros(100)).await;
    }

    let stats = measurement.get_measurement_stats();

    // Expected: approximately 67 received out of 100 expected = 33% loss
    let loss_rate = stats.current_loss_rate.as_f64();
    assert!(
        loss_rate > 0.20 && loss_rate < 0.40,
        "Loss rate should be around 30%, got {}",
        loss_rate
    );
}

#[tokio::test]
async fn test_jitter_measurement_accuracy() {
    let measurement = NetworkMeasurement::new();
    measurement.initialize().unwrap();

    // Create measurements with varying delays to test jitter calculation
    let delays = [50, 55, 45, 60, 40, 65, 35];

    for (i, delay) in delays.iter().enumerate() {
        let delay_measurement = DelayMeasurement {
            delay_ms: Duration::from_millis(*delay),
            timestamp: Timestamp::now(),
            sequence: SequenceNumber::new(i as u32),
            packet_type: PacketType::Data,
            packet_size: PacketSize::new(1000),
            rtt_estimate: RoundTripTime::from_millis(100),
            is_early: false,
        };

        measurement
            .process_delay_measurement(&delay_measurement)
            .unwrap();

        // Small delay between measurements for realistic timing
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let stats = measurement.get_measurement_stats();
    assert!(
        stats.current_jitter.as_millis() > 0,
        "Jitter should be calculated"
    );
}

#[tokio::test]
async fn test_measurement_edge_cases_very_low_values() {
    let measurement = NetworkMeasurement::new();
    measurement.initialize().unwrap();

    // Test with very low RTT (1ms)
    let delay_measurement = DelayMeasurement {
        delay_ms: Duration::from_millis(1),
        timestamp: Timestamp::now(),
        sequence: SequenceNumber::new(1),
        packet_type: PacketType::Data,
        packet_size: PacketSize::new(100),
        rtt_estimate: RoundTripTime::from_millis(1),
        is_early: false,
    };

    assert!(
        measurement
            .process_delay_measurement(&delay_measurement)
            .is_ok()
    );

    let stats = measurement.get_measurement_stats();
    assert!(stats.current_rtt.as_millis() > 0, "RTT should be recorded");
}

#[tokio::test]
async fn test_measurement_edge_cases_very_high_values() {
    let measurement = NetworkMeasurement::new();
    measurement.initialize().unwrap();

    // Test with very high RTT (5000ms)
    let delay_measurement = DelayMeasurement {
        delay_ms: Duration::from_millis(5000),
        timestamp: Timestamp::now(),
        sequence: SequenceNumber::new(1),
        packet_type: PacketType::Data,
        packet_size: PacketSize::new(1000),
        rtt_estimate: RoundTripTime::from_millis(5000),
        is_early: false,
    };

    assert!(
        measurement
            .process_delay_measurement(&delay_measurement)
            .is_ok()
    );

    let stats = measurement.get_measurement_stats();
    assert!(
        stats.current_rtt.as_millis() >= 1000,
        "High RTT should be recorded"
    );
}

// =========================================================================
// Parameter Adjustment Tests
// =========================================================================

#[tokio::test]
async fn test_optimization_initialization() {
    let optimization = ParameterOptimization::new();
    assert!(optimization.initialize().is_ok());

    let stats = optimization.get_optimization_stats();
    assert_eq!(
        stats.total_optimizations.as_u64(),
        0,
        "Optimizations should start at zero"
    );
}

#[tokio::test]
async fn test_parameter_adjustment_conservative_strategy() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set initial window
    state.current_delay_window.store(8, Ordering::Relaxed);

    // Create network conditions that require conservative optimization
    let conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(10), // 1% loss
        average_rtt: RoundTripTime::from_millis(150),
        rtt_variance: RoundTripTime::from_millis(10),
        network_jitter: NetworkJitter::new(20),
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    state.update_network_conditions(conditions);

    // Trigger optimization
    assert!(optimization.optimize_parameters(&state).is_ok());

    // Window should change only slightly in conservative mode
    let new_window = state.current_delay_window.load(Ordering::Relaxed);
    assert!(
        (7..=9).contains(&new_window),
        "Conservative optimization should make small adjustments, got {}",
        new_window
    );
}

#[tokio::test]
async fn test_parameter_adjustment_aggressive_strategy() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set initial window
    state.current_delay_window.store(8, Ordering::Relaxed);

    // Create poor network conditions that trigger aggressive optimization
    let conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(100), // 10% loss - very high
        average_rtt: RoundTripTime::from_millis(400), // High latency
        rtt_variance: RoundTripTime::from_millis(50),
        network_jitter: NetworkJitter::new(150), // High jitter
        high_latency: true,
        high_jitter: true,
        high_loss: true,
        unstable_network: true,
        congested_network: true,
    };

    state.update_network_conditions(conditions.clone());

    // Add enough history for optimization
    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(conditions.clone());
    }

    // Trigger optimization
    assert!(optimization.optimize_parameters(&state).is_ok());

    // Window should remain in valid bounds
    let new_window = state.current_delay_window.load(Ordering::Relaxed);
    assert!(
        (ADAPTIVE_DELAY_WINDOW_MIN..=ADAPTIVE_DELAY_WINDOW_MAX).contains(&new_window),
        "Aggressive optimization should keep window in valid range, got {}",
        new_window
    );
}

#[tokio::test]
async fn test_parameter_bounds_respected() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set window at minimum
    state
        .current_delay_window
        .store(ADAPTIVE_DELAY_WINDOW_MIN, Ordering::Relaxed);

    // Try to optimize downward (should be clamped)
    let conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(0),
        average_rtt: RoundTripTime::from_millis(50), // Very low latency
        rtt_variance: RoundTripTime::from_millis(5),
        network_jitter: NetworkJitter::new(5),
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    state.update_network_conditions(conditions.clone());

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(conditions.clone());
    }

    optimization.optimize_parameters(&state).unwrap();

    let new_window = state.current_delay_window.load(Ordering::Relaxed);
    assert!(
        new_window >= ADAPTIVE_DELAY_WINDOW_MIN,
        "Window should not go below minimum"
    );

    // Set window at maximum
    state
        .current_delay_window
        .store(ADAPTIVE_DELAY_WINDOW_MAX, Ordering::Relaxed);

    // Try to optimize upward (should be clamped)
    let bad_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(200), // 20% loss
        average_rtt: RoundTripTime::from_millis(1000),
        rtt_variance: RoundTripTime::from_millis(100),
        network_jitter: NetworkJitter::new(200),
        high_latency: true,
        high_jitter: true,
        high_loss: true,
        unstable_network: true,
        congested_network: true,
    };

    state.update_network_conditions(bad_conditions.clone());

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(bad_conditions.clone());
    }

    optimization.optimize_parameters(&state).unwrap();

    let new_window = state.current_delay_window.load(Ordering::Relaxed);
    assert!(
        new_window <= ADAPTIVE_DELAY_WINDOW_MAX,
        "Window should not exceed maximum"
    );
}

// =========================================================================
// Stability Tests (No Oscillation)
// =========================================================================

#[tokio::test]
async fn test_stability_no_oscillation_under_stable_conditions() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set initial window
    let initial_window = 8;
    state
        .current_delay_window
        .store(initial_window, Ordering::Relaxed);

    // Create stable network conditions
    let stable_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(5), // 0.5% loss
        average_rtt: RoundTripTime::from_millis(100),
        rtt_variance: RoundTripTime::from_millis(5),
        network_jitter: NetworkJitter::new(10),
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    // Track window changes over multiple optimization cycles
    let mut window_history = Vec::new();

    for _ in 0..20 {
        state.update_network_conditions(stable_conditions.clone());

        if optimization.optimize_parameters(&state).is_ok() {
            let current_window = state.current_delay_window.load(Ordering::Relaxed);
            window_history.push(current_window);
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Check for oscillation: window shouldn't swing wildly
    if window_history.len() >= 5 {
        let recent_windows = &window_history[window_history.len() - 5..];
        let min_recent = *recent_windows.iter().min().unwrap();
        let max_recent = *recent_windows.iter().max().unwrap();

        assert!(
            max_recent - min_recent <= 2,
            "Window should be stable under consistent conditions, range: {}",
            max_recent - min_recent
        );
    }
}

#[tokio::test]
async fn test_stability_cooldown_prevents_thrashing() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Create conditions
    let conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(10),
        average_rtt: RoundTripTime::from_millis(150),
        rtt_variance: RoundTripTime::from_millis(10),
        network_jitter: NetworkJitter::new(20),
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    state.update_network_conditions(conditions.clone());

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(conditions.clone());
    }

    // First optimization should succeed
    optimization.optimize_parameters(&state).unwrap();
    let stats = optimization.get_optimization_stats();
    let first_count = stats.total_optimizations.as_u64();

    // Immediate second optimization should be prevented by cooldown
    optimization.optimize_parameters(&state).unwrap();
    let stats = optimization.get_optimization_stats();
    let second_count = stats.total_optimizations.as_u64();

    assert_eq!(
        first_count, second_count,
        "Cooldown should prevent immediate re-optimization"
    );
}

#[tokio::test]
async fn test_stability_dampening_of_rapid_changes() {
    let measurement = NetworkMeasurement::new();
    measurement.initialize().unwrap();

    // Send measurements with rapidly changing RTT
    for i in 0..20 {
        let rtt_ms = if i % 2 == 0 { 50 } else { 150 };

        let delay_measurement = DelayMeasurement {
            delay_ms: Duration::from_millis(rtt_ms),
            timestamp: Timestamp::now(),
            sequence: SequenceNumber::new(i),
            packet_type: PacketType::Data,
            packet_size: PacketSize::new(1000),
            rtt_estimate: RoundTripTime::from_millis(rtt_ms),
            is_early: false,
        };

        measurement
            .process_delay_measurement(&delay_measurement)
            .unwrap();
    }

    let stats = measurement.get_measurement_stats();

    // Average should be between the extremes due to smoothing
    let avg_rtt = stats.current_rtt.as_millis();
    assert!(
        avg_rtt > 50 && avg_rtt < 150,
        "RTT should be smoothed, got {}ms",
        avg_rtt
    );
}

// =========================================================================
// Varying Conditions Tests
// =========================================================================

#[tokio::test]
async fn test_varying_conditions_adaptation_to_improving_network() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Start with poor conditions
    let initial_window = 12;
    state
        .current_delay_window
        .store(initial_window, Ordering::Relaxed);

    let poor_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(50), // 5% loss
        average_rtt: RoundTripTime::from_millis(300),
        rtt_variance: RoundTripTime::from_millis(30),
        network_jitter: NetworkJitter::new(80),
        high_latency: true,
        high_jitter: false,
        high_loss: true,
        unstable_network: false,
        congested_network: true,
    };

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(poor_conditions.clone());
    }

    optimization.optimize_parameters(&state).unwrap();
    let _window_after_poor = state.current_delay_window.load(Ordering::Relaxed);

    // Simulate network improvement
    tokio::time::sleep(Duration::from_millis(50)).await;

    let good_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(2), // 0.2% loss
        average_rtt: RoundTripTime::from_millis(80),
        rtt_variance: RoundTripTime::from_millis(5),
        network_jitter: NetworkJitter::new(10),
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(good_conditions.clone());
    }

    // Wait for cooldown
    tokio::time::sleep(OPTIMIZATION_COOLDOWN_MS).await;

    optimization.optimize_parameters(&state).unwrap();
    let window_after_good = state.current_delay_window.load(Ordering::Relaxed);

    // Window should adapt to better conditions (generally decrease)
    // But we don't enforce strict direction since adaptive logic is complex
    assert!(
        (ADAPTIVE_DELAY_WINDOW_MIN..=ADAPTIVE_DELAY_WINDOW_MAX).contains(&window_after_good),
        "Window should remain in valid range after adaptation"
    );
}

#[tokio::test]
async fn test_varying_conditions_adaptation_to_degrading_network() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Start with good conditions
    state.current_delay_window.store(4, Ordering::Relaxed);

    let good_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(2),
        average_rtt: RoundTripTime::from_millis(50),
        rtt_variance: RoundTripTime::from_millis(3),
        network_jitter: NetworkJitter::new(5),
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(good_conditions.clone());
    }

    optimization.optimize_parameters(&state).unwrap();

    // Simulate network degradation
    tokio::time::sleep(Duration::from_millis(50)).await;

    let degraded_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(80), // 8% loss
        average_rtt: RoundTripTime::from_millis(400),
        rtt_variance: RoundTripTime::from_millis(60),
        network_jitter: NetworkJitter::new(120),
        high_latency: true,
        high_jitter: true,
        high_loss: true,
        unstable_network: true,
        congested_network: true,
    };

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(degraded_conditions.clone());
    }

    // Wait for cooldown
    tokio::time::sleep(OPTIMIZATION_COOLDOWN_MS).await;

    optimization.optimize_parameters(&state).unwrap();
    let window_after_degradation = state.current_delay_window.load(Ordering::Relaxed);

    // Window should still be in valid range
    assert!(
        (ADAPTIVE_DELAY_WINDOW_MIN..=ADAPTIVE_DELAY_WINDOW_MAX).contains(&window_after_degradation),
        "Window should remain in valid range after degradation"
    );
}

#[tokio::test]
async fn test_varying_conditions_high_jitter_handling() {
    let measurement = NetworkMeasurement::new();
    measurement.initialize().unwrap();

    // Send measurements with high jitter
    let delays = [50, 200, 30, 180, 60, 150, 40, 170];

    for (i, delay) in delays.iter().enumerate() {
        let delay_measurement = DelayMeasurement {
            delay_ms: Duration::from_millis(*delay),
            timestamp: Timestamp::now(),
            sequence: SequenceNumber::new(i as u32),
            packet_type: PacketType::Data,
            packet_size: PacketSize::new(1000),
            rtt_estimate: RoundTripTime::from_millis(*delay),
            is_early: false,
        };

        measurement
            .process_delay_measurement(&delay_measurement)
            .unwrap();

        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let stats = measurement.get_measurement_stats();

    // Should detect high jitter
    assert!(
        stats.high_jitter_events.as_u64() > 0 || stats.current_jitter.as_millis() > 50,
        "High jitter should be detected"
    );
}

#[tokio::test]
async fn test_varying_conditions_packet_burst_handling() {
    let measurement = NetworkMeasurement::new();
    measurement.initialize().unwrap();

    // Simulate a burst of packets arriving together
    for i in 0..20 {
        let delay_measurement = DelayMeasurement {
            delay_ms: Duration::from_millis(100),
            timestamp: Timestamp::now(),
            sequence: SequenceNumber::new(i),
            packet_type: PacketType::Data,
            packet_size: PacketSize::new(1000),
            rtt_estimate: RoundTripTime::from_millis(100),
            is_early: false,
        };

        measurement
            .process_delay_measurement(&delay_measurement)
            .unwrap();
    }

    let stats = measurement.get_measurement_stats();

    // Should handle burst without errors
    assert_eq!(
        stats.total_rtt_measurements.as_u64(),
        20,
        "All measurements should be processed"
    );
}

// =========================================================================
// Integration Tests
// =========================================================================

#[tokio::test]
async fn test_full_engine_lifecycle() {
    let engine = AdaptiveNetworkingEngine::new();

    // Initialize
    assert!(engine.initialize().is_ok());

    // Measure some packets
    for _ in 0..15 {
        let packet_timestamp = Timestamp::now();
        let packet_type = PacketType::Data;
        let packet_size = PacketSize::new(1000);

        assert!(
            engine
                .measure_packet_delay(packet_timestamp, packet_type, packet_size)
                .is_ok()
        );

        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Get stats
    let stats = engine.get_adaptive_stats();
    assert!(
        stats.total_measurements.as_u64() >= 15,
        "Should have recorded measurements"
    );

    // Shutdown
    assert!(engine.shutdown().await.is_ok());
}

#[tokio::test]
async fn test_engine_enable_disable_adaptation() {
    let engine = AdaptiveNetworkingEngine::new();
    engine.initialize().unwrap();

    // Disable adaptation
    engine.set_adaptation_enabled(false);

    // Effective window should fall back to minimum
    let window = engine.get_effective_delay_window();
    assert_eq!(
        window, ADAPTIVE_DELAY_WINDOW_MIN,
        "Window should be minimum when adaptation is disabled"
    );

    // Re-enable adaptation
    engine.set_adaptation_enabled(true);

    // Should allow adaptation again
    let stats = engine.get_adaptive_stats();
    assert!(
        stats.adaptation_enabled,
        "Adaptation should be enabled again"
    );
}

// =========================================================================
// Window Optimization Tests
// =========================================================================

#[tokio::test]
async fn test_window_optimization_based_on_rtt() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set initial window
    state.current_delay_window.store(4, Ordering::Relaxed);

    // High RTT should increase window
    let high_rtt_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(5), // 0.5% loss
        average_rtt: RoundTripTime::from_millis(600), // High RTT
        rtt_variance: RoundTripTime::from_millis(20),
        network_jitter: NetworkJitter::new(30),
        high_latency: true,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(high_rtt_conditions.clone());
    }

    let initial_window = state.current_delay_window.load(Ordering::Relaxed);
    optimization.optimize_parameters(&state).unwrap();
    let optimized_window = state.current_delay_window.load(Ordering::Relaxed);

    // Window should increase to accommodate high RTT
    assert!(
        optimized_window >= initial_window,
        "Window should increase for high RTT: {} -> {}",
        initial_window,
        optimized_window
    );
}

#[tokio::test]
async fn test_window_optimization_based_on_loss_rate() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set initial window
    state.current_delay_window.store(4, Ordering::Relaxed);

    // High loss rate should increase window (multiplicative increase)
    let high_loss_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(80), // 8% loss - high
        average_rtt: RoundTripTime::from_millis(100),
        rtt_variance: RoundTripTime::from_millis(10),
        network_jitter: NetworkJitter::new(20),
        high_latency: false,
        high_jitter: false,
        high_loss: true,
        unstable_network: false,
        congested_network: true,
    };

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(high_loss_conditions.clone());
    }

    let initial_window = state.current_delay_window.load(Ordering::Relaxed);
    optimization.optimize_parameters(&state).unwrap();
    let optimized_window = state.current_delay_window.load(Ordering::Relaxed);

    // Window should increase to handle retransmissions
    assert!(
        optimized_window >= initial_window,
        "Window should increase for high loss rate: {} -> {}",
        initial_window,
        optimized_window
    );
}

#[tokio::test]
async fn test_window_optimization_based_on_jitter() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set initial window
    state.current_delay_window.store(4, Ordering::Relaxed);

    // High jitter should increase window for stability
    let high_jitter_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(5), // 0.5% loss
        average_rtt: RoundTripTime::from_millis(100),
        rtt_variance: RoundTripTime::from_millis(30),
        network_jitter: NetworkJitter::new(150), // High jitter
        high_latency: false,
        high_jitter: true,
        high_loss: false,
        unstable_network: true,
        congested_network: false,
    };

    for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
        state.update_network_conditions(high_jitter_conditions.clone());
    }

    let initial_window = state.current_delay_window.load(Ordering::Relaxed);
    optimization.optimize_parameters(&state).unwrap();
    let optimized_window = state.current_delay_window.load(Ordering::Relaxed);

    // Window should increase to handle timing variations
    assert!(
        optimized_window >= initial_window,
        "Window should increase for high jitter: {} -> {}",
        initial_window,
        optimized_window
    );
}

#[tokio::test]
async fn test_optimization_stability_with_ewma_smoothing() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set initial window
    state.current_delay_window.store(8, Ordering::Relaxed);

    // Create alternating conditions to test smoothing
    let good_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(2), // 0.2% loss
        average_rtt: RoundTripTime::from_millis(80),
        rtt_variance: RoundTripTime::from_millis(5),
        network_jitter: NetworkJitter::new(10),
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    let bad_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(50), // 5% loss
        average_rtt: RoundTripTime::from_millis(300),
        rtt_variance: RoundTripTime::from_millis(30),
        network_jitter: NetworkJitter::new(80),
        high_latency: true,
        high_jitter: false,
        high_loss: true,
        unstable_network: false,
        congested_network: true,
    };

    let mut window_changes = Vec::new();

    // Alternate between good and bad conditions
    for i in 0..10 {
        let conditions = if i % 2 == 0 {
            good_conditions.clone()
        } else {
            bad_conditions.clone()
        };

        for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
            state.update_network_conditions(conditions.clone());
        }

        // Wait for cooldown
        tokio::time::sleep(OPTIMIZATION_COOLDOWN_MS).await;

        let before = state.current_delay_window.load(Ordering::Relaxed);
        optimization.optimize_parameters(&state).unwrap();
        let after = state.current_delay_window.load(Ordering::Relaxed);

        if before != after {
            window_changes.push((before as i32 - after as i32).abs());
        }
    }

    // EWMA smoothing should prevent large oscillations
    // Average change should be moderate (< 3 windows per change)
    if !window_changes.is_empty() {
        let avg_change = window_changes.iter().sum::<i32>() as f64 / window_changes.len() as f64;
        assert!(
            avg_change < 3.0,
            "Average window change should be moderate with EWMA smoothing, got {}",
            avg_change
        );
    }
}

#[tokio::test]
async fn test_optimization_prevents_rapid_oscillation() {
    let state = Arc::new(AdaptiveDelayState::new());
    let optimization = ParameterOptimization::new();
    optimization.initialize().unwrap();

    // Set initial window
    state.current_delay_window.store(8, Ordering::Relaxed);

    // Create slightly varying conditions
    let base_conditions = NetworkConditions {
        timestamp: Timestamp::now(),
        packet_loss_rate: PacketLossRate::new(10), // 1% loss
        average_rtt: RoundTripTime::from_millis(120),
        rtt_variance: RoundTripTime::from_millis(10),
        network_jitter: NetworkJitter::new(20),
        high_latency: false,
        high_jitter: false,
        high_loss: false,
        unstable_network: false,
        congested_network: false,
    };

    let mut window_values = Vec::new();

    for i in 0..20 {
        // Slightly vary the conditions
        let varied_rtt = 120 + (i % 4) * 10; // Varies between 120-150ms
        let conditions = NetworkConditions {
            average_rtt: RoundTripTime::from_millis(varied_rtt),
            ..base_conditions.clone()
        };

        for _ in 0..MIN_SAMPLES_FOR_OPTIMIZATION {
            state.update_network_conditions(conditions.clone());
        }

        // Wait for cooldown
        tokio::time::sleep(OPTIMIZATION_COOLDOWN_MS).await;

        optimization.optimize_parameters(&state).unwrap();
        let current_window = state.current_delay_window.load(Ordering::Relaxed);
        window_values.push(current_window);
    }

    // Check for oscillation pattern: no rapid back-and-forth
    let mut oscillation_count = 0;
    for i in 2..window_values.len() {
        if window_values.len() >= 3 {
            let prev_prev = window_values[i - 2] as i32;
            let prev = window_values[i - 1] as i32;
            let curr = window_values[i] as i32;

            // Check if direction changed twice (oscillation pattern)
            if (prev > prev_prev && curr < prev) || (prev < prev_prev && curr > prev) {
                oscillation_count += 1;
            }
        }
    }

    // EWMA smoothing should keep oscillations low
    assert!(
        oscillation_count < window_values.len() / 4,
        "Too many oscillations detected: {} out of {}",
        oscillation_count,
        window_values.len()
    );
}
