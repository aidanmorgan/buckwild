use buckwild_common::engines:adaptive::measurement::*;
#[tokio::test]
    async fn test_network_measurement_creation() {
        let measurement = NetworkMeasurement::new();
        let stats = measurement.get_measurement_stats();
        
        assert_eq!(stats.current_rtt_ms, 100);
        assert_eq!(stats.current_jitter_ms, 0);
        assert_eq!(stats.current_loss_rate, 0.0);
    }
    
    #[tokio::test]
    async fn test_rtt_measurement() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();
        
        // Add RTT measurements
        measurement.update_rtt_measurement(150, 1000).unwrap();
        measurement.update_rtt_measurement(200, 2000).unwrap();
        measurement.update_rtt_measurement(100, 3000).unwrap();
        
        let stats = measurement.get_measurement_stats();
        assert_eq!(stats.current_rtt_ms, 150); // Average of 150, 200, 100
        assert!(stats.rtt_variance > 0);
        assert_eq!(stats.total_rtt_measurements, 3);
    }
    
    #[tokio::test]
    async fn test_packet_loss_calculation() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();
        
        // Track packets with gaps (simulating loss)
        for seq in [1, 2, 4, 5, 7, 8, 9, 10] { // Missing 3 and 6
            measurement.track_packet(seq, seq * 1000).unwrap();
        }
        
        let stats = measurement.get_measurement_stats();
        assert!(stats.current_loss_rate > 0.0); // Should detect packet loss
        assert!(stats.current_loss_rate < 1.0); // But not 100% loss
    }
    
    #[tokio::test]
    async fn test_network_conditions() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();
        
        // Add high RTT measurement
        measurement.update_rtt_measurement(300, 1000).unwrap();
        
        let conditions = measurement.get_current_network_conditions();
        assert!(conditions.high_latency);
        assert_eq!(conditions.average_rtt, 300);
    }
    
    #[tokio::test]
    async fn test_jitter_calculation() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();
        
        let delay_measurement = DelayMeasurement {
            delay_ms: 100,
            timestamp: 2000,
            sequence: 1,
            packet_type: 1,
            packet_size: 1000,
            rtt_estimate: 150,
            is_early: false,
        };
        
        // Set initial measurement time
        measurement.last_measurement_time.store(1000, Ordering::Relaxed);
        
        measurement.calculate_jitter(&delay_measurement).unwrap();
        
        let stats = measurement.get_measurement_stats();
        assert!(stats.current_jitter_ms >= 0); // Jitter should be calculated
    }
    
    #[tokio::test]
    async fn test_reset_measurements() {
        let measurement = NetworkMeasurement::new();
        measurement.initialize().unwrap();
        
        // Add some measurements
        measurement.update_rtt_measurement(200, 1000).unwrap();
        measurement.track_packet(1, 1000).unwrap();
        
        // Reset
        measurement.reset_measurements().unwrap();
        
        let stats = measurement.get_measurement_stats();
        assert_eq!(stats.current_rtt_ms, 100); // Back to default
        assert_eq!(stats.current_loss_rate, 0.0);
    }
