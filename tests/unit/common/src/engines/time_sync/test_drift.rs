use buckwild_common::engines:time_sync::drift::*;
use crate::time_sync::state::create_shared_time_sync_state;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_linear_regression_slope() {
        let state = create_shared_time_sync_state();
        let compensator = DriftCompensator::new(state);
        
        // Test perfect positive slope
        let x_values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y_values = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let slope = compensator.calculate_linear_regression_slope(&x_values, &y_values);
        assert!((slope - 2.0).abs() < 0.001);
        
        // Test perfect negative slope
        let y_values = vec![10.0, 8.0, 6.0, 4.0, 2.0];
        let slope = compensator.calculate_linear_regression_slope(&x_values, &y_values);
        assert!((slope - (-2.0)).abs() < 0.001);
        
        // Test zero slope
        let y_values = vec![5.0, 5.0, 5.0, 5.0, 5.0];
        let slope = compensator.calculate_linear_regression_slope(&x_values, &y_values);
        assert!(slope.abs() < 0.001);
    }
    
    #[test]
    fn test_drift_detection_insufficient_samples() {
        let state = create_shared_time_sync_state();
        let compensator = DriftCompensator::new(state);
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // No samples - should return 0.0
        let drift = compensator.detect_drift_for_host(host);
        assert_eq!(drift, 0.0);
    }
    
    #[test]
    fn test_drift_compensation_threshold() {
        let state = create_shared_time_sync_state();
        let compensator = DriftCompensator::new(state.clone());
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Set a small drift rate
        state.set_drift_rate_for_host(host, 0.5); // 0.5 ppm
        state.set_last_sync_time_for_host(host, TimeEpoch::current_time_ms() - 1000); // 1 second ago
        
        // Should not compensate (drift too small)
        let compensated = compensator.compensate_drift_for_host(host);
        assert!(!compensated);
        
        // Set a larger drift rate
        state.set_drift_rate_for_host(host, 50.0); // 50 ppm
        state.set_last_sync_time_for_host(host, TimeEpoch::current_time_ms() - 60000); // 1 minute ago
        
        // Should compensate
        let compensated = compensator.compensate_drift_for_host(host);
        assert!(compensated);
    }
    
    #[test]
    fn test_drift_stats() {
        let state = create_shared_time_sync_state();
        let compensator = DriftCompensator::new(state.clone());
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Set up drift data
        state.set_drift_rate_for_host(host, 25.0);
        state.set_last_sync_time_for_host(host, TimeEpoch::current_time_ms() - 30000);
        
        let stats = compensator.get_drift_stats_for_host(host);
        
        assert_eq!(stats.drift_rate_ppm, 25.0);
        assert!(!stats.is_excessive); // 25 ppm is below 100 ppm threshold
        assert!(stats.accumulated_drift_ms.abs() > 0.0);
    }
    
    #[test]
    fn test_drift_config() {
        let state = create_shared_time_sync_state();
        let mut compensator = DriftCompensator::new(state);
        
        // Test initial configuration
        let config = compensator.get_drift_config();
        assert_eq!(config.drift_calculation_window, 300000);
        assert_eq!(config.max_acceptable_drift_ppm, 100.0);
        assert_eq!(config.min_samples_for_drift, 3);
        assert_eq!(config.compensation_threshold_ms, 1.0);
        
        // Update configuration
        compensator.set_drift_calculation_window(600000);
        compensator.set_max_acceptable_drift_ppm(200.0);
        compensator.set_min_samples_for_drift(5);
        compensator.set_compensation_threshold(2.0);
        
        let config = compensator.get_drift_config();
        assert_eq!(config.drift_calculation_window, 600000);
        assert_eq!(config.max_acceptable_drift_ppm, 200.0);
        assert_eq!(config.min_samples_for_drift, 5);
        assert_eq!(config.compensation_threshold_ms, 2.0);
    }
    
    #[test]
    fn test_drift_reset() {
        let state = create_shared_time_sync_state();
        let compensator = DriftCompensator::new(state.clone());
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Set up drift data
        state.set_drift_rate_for_host(host, 50.0);
        
        // Verify drift is set
        let stats = compensator.get_drift_stats_for_host(host);
        assert_eq!(stats.drift_rate_ppm, 50.0);
        
        // Reset drift
        let result = compensator.reset_drift_for_host(host);
        assert!(result.is_ok());
        
        // Verify drift is reset
        let stats = compensator.get_drift_stats_for_host(host);
        assert_eq!(stats.drift_rate_ppm, 0.0);
    }
    
    #[test]
    fn test_all_hosts_operations() {
        let state = create_shared_time_sync_state();
        let compensator = DriftCompensator::new(state.clone());
        
        let host1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        
        // Set up drift for multiple hosts
        state.set_drift_rate_for_host(host1, 25.0);
        state.set_drift_rate_for_host(host2, 75.0);
        state.set_last_sync_time_for_host(host1, TimeEpoch::current_time_ms() - 60000);
        state.set_last_sync_time_for_host(host2, TimeEpoch::current_time_ms() - 30000);
        
        // Test drift detection for all hosts
        let drift_results = compensator.detect_drift_for_all_hosts();
        assert!(drift_results.is_empty()); // No samples, so no drift detected
        
        // Test drift compensation for all hosts
        let compensated = compensator.compensate_drift_for_all_hosts();
        assert!(compensated); // Should compensate for both hosts
        
        // Test drift stats for all hosts
        let all_stats = compensator.get_drift_stats_for_all_hosts();
        assert_eq!(all_stats.len(), 2);
    }
