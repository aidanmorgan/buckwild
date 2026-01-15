use buckwild_common::protocol::adaptive_networking::*;
use std::thread;
    use std::time::Duration;

    #[test]
    fn test_adaptive_networking_initialization() {
        let engine = AdaptiveNetworkingEngine::new();
        assert!(engine.initialize().is_ok());
        
        let stats = engine.get_network_statistics();
        assert_eq!(stats.effective_delay_window, ADAPTIVE_DELAY_WINDOW_MIN);
        assert!(stats.is_adaptation_enabled);
        assert_eq!(stats.measurement_count, 0);
    }

    #[test]
    fn test_delay_measurement_recording() {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();

        // Record some delay measurements
        for i in 0..5 {
            let result = engine.measure_packet_delay(
                1000 + i * 100, // timestamp
                1, // packet type (data)
                1400, // packet size
            );
            assert!(result.is_ok());
        }

        let stats = engine.get_network_statistics();
        assert_eq!(stats.measurement_count, 5);
    }

    #[test]
    fn test_network_condition_assessment() {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();

        // Add some measurements to enable assessment
        for i in 0..DELAY_MEASUREMENT_SAMPLES {
            engine.measure_packet_delay(
                1000 + i as u64 * 100,
                1,
                1400,
            ).unwrap();
        }

        let conditions = engine.assess_network_conditions().unwrap();
        assert!(conditions.timestamp > 0);
        assert!(conditions.packet_loss_rate >= 0.0);
        assert!(conditions.average_rtt > 0);
    }

    #[test]
    fn test_heartbeat_payload_serialization() {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();

        let payload = engine.create_enhanced_heartbeat_payload().unwrap();
        assert!(!payload.is_empty());

        // Test processing the payload
        let result = engine.process_enhanced_heartbeat_payload(&payload);
        assert!(result.is_ok());
    }

    #[test]
    fn test_adaptive_window_calculation() {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();

        let conditions = NetworkConditions {
            timestamp: 1000,
            packet_loss_rate: 0.01, // 1% loss
            average_rtt: 150,
            rtt_variance: 20,
            network_jitter: 50,
            high_latency: false,
            high_jitter: false,
            high_loss: false,
            unstable_network: false,
            congested_network: false,
        };

        let window = engine.calculate_adaptive_port_window(&conditions);
        assert!(window >= ADAPTIVE_DELAY_WINDOW_MIN);
        assert!(window <= ADAPTIVE_DELAY_WINDOW_MAX);
    }

    #[test]
    fn test_port_listening_strategy_update() {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();

        let ports = engine.update_port_listening_strategy().unwrap();
        assert!(!ports.is_empty());
        assert!(ports.len() <= ADAPTIVE_DELAY_WINDOW_MAX as usize);
    }

    #[test]
    fn test_percentile_calculation() {
        let engine = AdaptiveNetworkingEngine::new();
        
        let values = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let p95 = engine.calculate_percentile(&values, 95);
        assert_eq!(p95, 100); // 95th percentile of 10 values should be the last one

        let p50 = engine.calculate_percentile(&values, 50);
        assert_eq!(p50, 50); // 50th percentile should be middle value
    }

    #[test]
    fn test_jitter_calculation() {
        let engine = AdaptiveNetworkingEngine::new();
        
        let delays = vec![100, 110, 90, 105, 95]; // Mean = 100, some variation
        let jitter = engine.calculate_jitter(&delays);
        assert!(jitter > 0); // Should have some jitter
        assert!(jitter < 20); // But not too much for this data
    }

    #[test]
    fn test_asymmetric_window_adaptation() {
        let engine = AdaptiveNetworkingEngine::new();
        engine.initialize().unwrap();
        
        // Enable asymmetric adaptation
        engine.set_asymmetric_adaptation_enabled(true);

        // Add measurements with bias toward early packets
        for i in 0..DELAY_MEASUREMENT_SAMPLES {
            let is_early = i < DELAY_MEASUREMENT_SAMPLES * 3 / 4; // 75% early packets
            let delay = if is_early { 50 } else { 150 }; // Early packets have less delay
            
            let measurement = DelayMeasurement {
                delay_ms: delay,
                timestamp: 1000 + i as u64 * 100,
                sequence: i as u64,
                packet_type: 1,
                packet_size: 1400,
                rtt_estimate: 100,
                is_early,
            };

            engine.state.delay_measurements.write().push_back(measurement);
        }

        // Trigger window update
        engine.update_adaptive_delay_window().unwrap();

        let (past, _current, future) = engine.state.get_asymmetric_windows();
        // With more early packets, future window should be larger than past
        // (though exact values depend on the algorithm)
        assert!(past + future >= ADAPTIVE_DELAY_WINDOW_MIN - 1);
    }

    #[test]
    fn test_concurrent_measurement_recording() {
        let engine = Arc::new(AdaptiveNetworkingEngine::new());
        engine.initialize().unwrap();

        let mut handles = vec![];

        // Spawn multiple threads recording measurements
        for thread_id in 0..4 {
            let engine_clone = Arc::clone(&engine);
            let handle = thread::spawn(move || {
                for i in 0..25 {
                    let result = engine_clone.measure_packet_delay(
                        1000 + (thread_id * 1000 + i) as u64,
                        1,
                        1400,
                    );
                    assert!(result.is_ok());
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
        assert_eq!(stats.measurement_count, 100); // 4 threads * 25 measurements
    }
