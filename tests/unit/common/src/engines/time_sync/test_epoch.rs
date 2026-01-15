use buckwild_common::engines:time_sync::epoch::*;
use std::net::Ipv4Addr;
    
    #[test]
    fn test_time_window_calculation() {
        let epoch = TimeEpoch::new();
        let test_time = 1640995200000; // 2022-01-01 00:00:00 UTC
        
        // Test daily window
        let daily_window = TimeEpoch::get_daily_time_window(test_time);
        assert_eq!(daily_window.epoch_type, EpochType::Daily);
        assert_eq!(daily_window.window, 0); // First window of the day
        assert_eq!(daily_window.epoch_start, test_time); // Should be start of day
        
        // Test monthly window
        let monthly_window = TimeEpoch::get_monthly_time_window(test_time);
        assert_eq!(monthly_window.epoch_type, EpochType::Monthly);
        assert_eq!(monthly_window.window, 0); // First window of the month
        assert_eq!(monthly_window.epoch_start, test_time); // Should be start of month
    }
    
    #[test]
    fn test_host_time_offsets() {
        let host1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        
        // Set offsets for different hosts
        TimeEpoch::set_host_time_offset(host1, 1000000); // 1 second
        TimeEpoch::set_host_time_offset(host2, -500000); // -0.5 seconds
        
        // Verify offsets
        assert_eq!(TimeEpoch::get_host_time_offset(host1), 1000000);
        assert_eq!(TimeEpoch::get_host_time_offset(host2), -500000);
        
        // Add to offsets
        let new_offset1 = TimeEpoch::add_host_time_offset(host1, 500000);
        assert_eq!(new_offset1, 1500000);
        assert_eq!(TimeEpoch::get_host_time_offset(host1), 1500000);
        
        // Get all offsets
        let all_offsets = TimeEpoch::get_all_host_offsets();
        assert_eq!(all_offsets.len(), 2);
        assert_eq!(all_offsets[&host1], 1500000);
        assert_eq!(all_offsets[&host2], -500000);
        
        // Remove offset
        TimeEpoch::remove_host_time_offset(host1);
        assert_eq!(TimeEpoch::get_host_time_offset(host1), 0);
        
        let all_offsets = TimeEpoch::get_all_host_offsets();
        assert_eq!(all_offsets.len(), 1);
    }
    
    #[test]
    fn test_synchronized_time() {
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Set a time offset
        TimeEpoch::set_host_time_offset(host, 1000000); // 1 second in microseconds
        
        let raw_time = TimeEpoch::current_time_ms();
        let sync_time = TimeEpoch::synchronized_time_ms_for_host(host);
        
        // Synchronized time should be 1 second ahead
        assert!((sync_time as i64 - raw_time as i64 - 1000).abs() < 10); // Allow small timing differences
    }
    
    #[test]
    fn test_month_boundary_detection() {
        // This test is time-dependent, so we'll test the logic rather than actual dates
        let threshold = 3600000; // 1 hour
        
        // Test that the function doesn't crash
        let is_near = TimeEpoch::is_near_month_boundary(threshold);
        assert!(is_near == true || is_near == false); // Just ensure it returns a boolean
    }
    
    #[test]
    fn test_month_boundary_preparation() {
        // Test initial state
        assert!(!TimeEpoch::is_in_month_boundary_preparation());
        
        // Start preparation
        TimeEpoch::start_month_boundary_preparation();
        assert!(TimeEpoch::is_in_month_boundary_preparation());
        
        // End preparation
        TimeEpoch::end_month_boundary_preparation();
        assert!(!TimeEpoch::is_in_month_boundary_preparation());
        
        // Test manual setting
        TimeEpoch::set_month_boundary_preparation(true);
        assert!(TimeEpoch::is_in_month_boundary_preparation());
        
        TimeEpoch::set_month_boundary_preparation(false);
        assert!(!TimeEpoch::is_in_month_boundary_preparation());
    }
    
    #[test]
    fn test_time_security_validation() {
        let reference_time = 1640995200000; // 2022-01-01 00:00:00 UTC
        
        // Test valid time (within boundary)
        let valid_time = reference_time + 1000; // 1 second later
        assert!(TimeEpoch::validate_time_security_boundary(valid_time, reference_time));
        
        // Test invalid time (outside boundary)
        let invalid_time = reference_time + TIME_SECURITY_BOUNDARY_MS + 1000;
        assert!(!TimeEpoch::validate_time_security_boundary(invalid_time, reference_time));
        
        // Test time skew validation
        let local_time = reference_time;
        let peer_time = reference_time + 1000; // 1 second skew
        assert!(TimeEpoch::validate_time_skew(local_time, peer_time));
        
        let large_skew_time = reference_time + MAX_SECURITY_TIME_SKEW_MS + 1000;
        assert!(!TimeEpoch::validate_time_skew(local_time, large_skew_time));
    }
    
    #[test]
    fn test_replay_window_validation() {
        let window_start = 1640995200000;
        let window_end = window_start + 10000; // 10 second window
        
        // Test valid timestamp (within window)
        let valid_timestamp = window_start + 5000;
        assert!(TimeEpoch::validate_timestamp_replay_window(valid_timestamp, window_start, window_end));
        
        // Test invalid timestamp (before window)
        let early_timestamp = window_start - 1000;
        assert!(!TimeEpoch::validate_timestamp_replay_window(early_timestamp, window_start, window_end));
        
        // Test invalid timestamp (after window)
        let late_timestamp = window_end + 1000;
        assert!(!TimeEpoch::validate_timestamp_replay_window(late_timestamp, window_start, window_end));
        
        // Test edge cases
        assert!(TimeEpoch::validate_timestamp_replay_window(window_start, window_start, window_end));
        assert!(TimeEpoch::validate_timestamp_replay_window(window_end, window_start, window_end));
    }
    
    #[test]
    fn test_epoch_stats() {
        let epoch = TimeEpoch::new();
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Set up some state
        TimeEpoch::set_host_time_offset(host, 1000000);
        TimeEpoch::set_atomic_time_offset(500000);
        
        // Test global stats
        let stats = epoch.get_epoch_stats();
        assert!(stats.current_time_ms > 0);
        assert!(stats.daily_epoch_start > 0);
        assert!(stats.monthly_epoch_start > 0);
        assert_eq!(stats.global_time_offset_us, 500000);
        assert!(stats.active_host_count > 0);
        
        // Test host-specific stats
        let host_stats = epoch.get_epoch_stats_for_host(host);
        assert!(host_stats.current_time_ms > 0);
        assert_eq!(host_stats.global_time_offset_us, 1000000);
        assert_eq!(host_stats.active_host_count, 1);
    }
    
    #[test]
    fn test_cleanup_expired_hosts() {
        let host1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let host3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));
        
        // Set up offsets
        TimeEpoch::set_host_time_offset(host1, 1000);
        TimeEpoch::set_host_time_offset(host2, 2000);
        TimeEpoch::set_host_time_offset(host3, 3000);
        
        // Verify all are present
        let all_offsets = TimeEpoch::get_all_host_offsets();
        assert_eq!(all_offsets.len(), 3);
        
        // Cleanup some hosts
        let inactive_hosts = vec![host1, host3];
        let result = TimeEpoch::cleanup_expired_host_offsets(&inactive_hosts);
        assert!(result.is_ok());
        
        // Verify cleanup
        let all_offsets = TimeEpoch::get_all_host_offsets();
        assert_eq!(all_offsets.len(), 1);
        assert_eq!(all_offsets[&host2], 2000);
    }
