use buckwild_common::engines:flow_control::windowing::*;
#[tokio::test]
    async fn test_window_management_creation() {
        let wm = WindowManagement::new(65536);
        assert_eq!(wm.get_receive_window(), 65536);
        assert_eq!(wm.get_advertised_window(), 65536);
    }
    
    #[tokio::test]
    async fn test_buffer_usage_update() {
        let wm = WindowManagement::new(65536);
        
        // Add data to buffer
        let result = wm.add_to_receive_buffer(1000).await.unwrap();
        assert!(result);
        
        // Consume data from buffer
        wm.update_buffer_usage(500).await.unwrap();
        
        let stats = wm.get_window_stats().await;
        assert!(stats.buffer_utilization > 0.0);
    }
    
    #[tokio::test]
    async fn test_window_update_threshold() {
        let wm = WindowManagement::new(65536);
        
        // Small change should not trigger update
        assert!(!wm.should_send_window_update(65536, 65000));
        
        // Large change should trigger update
        assert!(wm.should_send_window_update(65536, 40000));
        
        // Zero window changes should always trigger update
        assert!(wm.should_send_window_update(65536, 0));
        assert!(wm.should_send_window_update(0, 65536));
    }
    
    #[tokio::test]
    async fn test_zero_window_handling() {
        let wm = WindowManagement::new(1000);
        
        // Fill buffer to trigger zero window
        let result = wm.add_to_receive_buffer(1000).await.unwrap();
        assert!(result);
        
        // Try to add more data (should fail)
        let result = wm.add_to_receive_buffer(100).await.unwrap();
        assert!(!result);
        
        let stats = wm.get_window_stats().await;
        assert_eq!(stats.zero_window_events, 1);
    }
    
    #[tokio::test]
    async fn test_window_update_handling() {
        let wm = WindowManagement::new(65536);
        
        // Handle window update
        wm.handle_window_update(32768).await.unwrap();
        assert_eq!(wm.get_receive_window(), 32768);
        
        let stats = wm.get_window_stats().await;
        assert_eq!(stats.window_updates_received, 1);
    }
    
    #[test]
    fn test_zero_window_probe_state() {
        let mut probe_state = ZeroWindowProbeState::new();
        
        // Should probe initially
        assert!(probe_state.should_probe());
        
        // Update after probe
        probe_state.update_after_probe();
        assert!(!probe_state.should_probe()); // Too soon
        assert_eq!(probe_state.probe_count, 1);
        assert_eq!(probe_state.interval_ms, 2000); // Doubled
        
        // Reset state
        probe_state.reset();
        assert_eq!(probe_state.probe_count, 0);
        assert_eq!(probe_state.interval_ms, ZERO_WINDOW_PROBE_INTERVAL_MS);
    }
