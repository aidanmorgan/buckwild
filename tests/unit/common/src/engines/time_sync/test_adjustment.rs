use buckwild_common::engines:time_sync::adjustment::*;
use crate::time_sync::state::create_shared_time_sync_state;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_adjustment_steps_calculation() {
        let state = create_shared_time_sync_state();
        let adjuster = TimeAdjuster::new(state);
        
        // Test small offset (should be 1 step)
        let steps = adjuster.calculate_adjustment_steps(10.0);
        assert_eq!(steps, 1);
        
        // Test medium offset
        let steps = adjuster.calculate_adjustment_steps(100.0);
        assert!(steps > 1 && steps <= 10);
        
        // Test large offset (should be capped)
        let steps = adjuster.calculate_adjustment_steps(10000.0);
        assert!(steps <= 60);
    }
    
    #[test]
    fn test_small_adjustment_immediate_application() {
        let state = create_shared_time_sync_state();
        let adjuster = TimeAdjuster::new(state.clone());
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Apply small adjustment
        let result = adjuster.apply_gradual_adjustment_for_host(host, 0.5, 90);
        assert!(result);
        
        // Should be applied immediately
        let status = adjuster.get_adjustment_status_for_host(host);
        assert!(!status.is_adjusting);
        assert_eq!(status.total_steps, 0);
    }
    
    #[test]
    fn test_large_adjustment_gradual_application() {
        let state = create_shared_time_sync_state();
        let adjuster = TimeAdjuster::new(state.clone());
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Apply large adjustment
        let result = adjuster.apply_gradual_adjustment_for_host(host, 100.0, 80);
        assert!(result);
        
        // Should be scheduled for gradual application
        let status = adjuster.get_adjustment_status_for_host(host);
        assert!(status.is_adjusting);
        assert!(status.total_steps > 1);
        assert_eq!(status.completed_steps, 0);
        assert!(status.remaining_offset > 0.0);
    }
    
    #[test]
    fn test_emergency_adjustment() {
        let state = create_shared_time_sync_state();
        let adjuster = TimeAdjuster::new(state.clone());
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Apply emergency adjustment
        let result = adjuster.apply_emergency_adjustment_for_host(host, 5000.0);
        assert!(result);
        
        // Should be applied immediately
        let status = adjuster.get_adjustment_status_for_host(host);
        assert!(!status.is_adjusting);
        
        // Status should be synchronized
        assert_eq!(state.status_for_host(host), TimeSyncStatus::Synchronized);
    }
    
    #[test]
    fn test_adjustment_pause_resume() {
        let state = create_shared_time_sync_state();
        let adjuster = TimeAdjuster::new(state.clone());
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Apply large adjustment
        adjuster.apply_gradual_adjustment_for_host(host, 100.0, 80);
        
        // Pause adjustments
        let result = adjuster.pause_adjustments_for_host(host);
        assert!(result.is_ok());
        
        let status = adjuster.get_adjustment_status_for_host(host);
        assert!(status.is_paused);
        
        // Resume adjustments
        let result = adjuster.resume_adjustments_for_host(host);
        assert!(result.is_ok());
        
        let status = adjuster.get_adjustment_status_for_host(host);
        assert!(!status.is_paused);
    }
    
    #[test]
    fn test_adjustment_cancellation() {
        let state = create_shared_time_sync_state();
        let adjuster = TimeAdjuster::new(state.clone());
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Apply large adjustment
        adjuster.apply_gradual_adjustment_for_host(host, 100.0, 80);
        
        let status = adjuster.get_adjustment_status_for_host(host);
        assert!(status.is_adjusting);
        
        // Cancel adjustments
        let result = adjuster.cancel_adjustments_for_host(host);
        assert!(result.is_ok());
        
        let status = adjuster.get_adjustment_status_for_host(host);
        assert!(!status.is_adjusting);
        assert_eq!(status.total_steps, 0);
    }
    
    #[test]
    fn test_adjustment_configuration() {
        let state = create_shared_time_sync_state();
        let mut adjuster = TimeAdjuster::new(state);
        
        // Test initial configuration
        let config = adjuster.get_adjustment_config();
        assert_eq!(config.max_adjustment_per_hop, 25.0);
        assert_eq!(config.adjustment_rate, 0.1);
        
        // Update configuration
        adjuster.set_max_adjustment_per_hop(50.0);
        adjuster.set_adjustment_rate(0.2);
        
        let config = adjuster.get_adjustment_config();
        assert_eq!(config.max_adjustment_per_hop, 50.0);
        assert_eq!(config.adjustment_rate, 0.2);
        
        // Test rate bounds
        adjuster.set_adjustment_rate(1.5); // Should be capped at 1.0
        let config = adjuster.get_adjustment_config();
        assert_eq!(config.adjustment_rate, 1.0);
        
        adjuster.set_adjustment_rate(-0.1); // Should be set to minimum 0.01
        let config = adjuster.get_adjustment_config();
        assert_eq!(config.adjustment_rate, 0.01);
    }
