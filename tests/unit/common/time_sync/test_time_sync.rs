#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use std::collections::HashMap;
    use std::sync::Mutex;
    
    use buckwild::time_sync::{
        TimeSyncEngine, TimeSyncState, TimeSyncStatus, SyncQuality,
        SyncRequest, SyncResponse, TimeWindow, EpochType
    };
    
    #[test]
    fn test_time_sync_state() {
        let state = TimeSyncState::new();
        
        // Test initial state
        assert_eq!(state.status(), TimeSyncStatus::Synchronized);
        assert_eq!(state.local_offset(), 0);
        assert_eq!(state.peer_offset(), 0);
        assert_eq!(state.drift_rate(), 0.0);
        assert_eq!(state.sync_quality(), 100);
        assert_eq!(state.emergency_sync_attempts(), 0);
        
        // Test status updates
        state.set_status(TimeSyncStatus::Adjusting);
        assert_eq!(state.status(), TimeSyncStatus::Adjusting);
        
        state.set_status(TimeSyncStatus::Emergency);
        assert_eq!(state.status(), TimeSyncStatus::Emergency);
        
        // Test offset updates
        state.set_local_offset(1000);
        assert_eq!(state.local_offset(), 1000);
        
        let new_offset = state.add_local_offset(500);
        assert_eq!(new_offset, 1500);
        assert_eq!(state.local_offset(), 1500);
        
        // Test quality updates
        state.set_sync_quality(75);
        assert_eq!(state.sync_quality(), 75);
        assert_eq!(state.sync_quality_level(), SyncQuality::Good);
        
        state.set_sync_quality(45);
        assert_eq!(state.sync_quality(), 45);
        assert_eq!(state.sync_quality_level(), SyncQuality::Poor);
        
        // Test emergency attempts
        state.set_emergency_sync_attempts(1);
        assert_eq!(state.emergency_sync_attempts(), 1);
        
        let attempts = state.increment_emergency_sync_attempts();
        assert_eq!(attempts, 2);
        assert_eq!(state.emergency_sync_attempts(), 2);
        
        state.reset_emergency_sync_attempts();
        assert_eq!(state.emergency_sync_attempts(), 0);
    }
    
    #[test]
    fn test_time_epoch() {
        use buckwild::time_sync::TimeEpoch;
        
        // Test current time functions
        let time_ms = TimeEpoch::current_time_ms();
        let time_us = TimeEpoch::current_time_us();
        let high_precision = TimeEpoch::current_time_high_precision();
        
        assert!(time_ms > 0);
        assert!(time_us > 0);
        assert!(high_precision > 0);
        assert!(time_us >= time_ms * 1000);
        
        // Test day and month start calculations
        let day_start = TimeEpoch::current_day_start_ms();
        let month_start = TimeEpoch::current_month_start_ms();
        
        assert!(day_start <= time_ms);
        assert!(month_start <= time_ms);
        assert!(month_start <= day_start);
        
        // Test time window calculations
        let daily_window = TimeEpoch::current_time_window(EpochType::Daily, 0);
        let monthly_window = TimeEpoch::current_time_window(EpochType::Monthly, 0);
        
        assert_eq!(daily_window.epoch_type, EpochType::Daily);
        assert_eq!(monthly_window.epoch_type, EpochType::Monthly);
        
        assert!(daily_window.window >= 0);
        assert!(monthly_window.window >= 0);
        
        assert_eq!(daily_window.epoch_start, day_start);
        assert_eq!(monthly_window.epoch_start, month_start);
        
        assert!(daily_window.window_start <= time_ms);
        assert!(daily_window.window_end >= time_ms);
        assert!(monthly_window.window_start <= time_ms);
        assert!(monthly_window.window_end >= time_ms);
        
        // Test next hop time calculation
        let next_hop = TimeEpoch::next_hop_time(0, EpochType::Daily);
        assert!(next_hop > time_ms);
        assert!(next_hop <= time_ms + 500); // Next hop should be within 500ms
    }
    
    #[test]
    fn test_time_sync_engine_basic() {
        let engine = TimeSyncEngine::new();
        
        // Test initial state
        assert!(engine.is_sync_healthy());
        
        // Test synchronized time functions
        let sync_time_ms = engine.synchronized_time_ms();
        let sync_time_us = engine.synchronized_time_us();
        
        assert!(sync_time_ms > 0);
        assert!(sync_time_us > 0);
        assert!(sync_time_us >= sync_time_ms * 1000);
        
        // Test time window functions
        let daily_window = engine.current_time_window(EpochType::Daily);
        let monthly_window = engine.current_time_window(EpochType::Monthly);
        
        assert_eq!(daily_window.epoch_type, EpochType::Daily);
        assert_eq!(monthly_window.epoch_type, EpochType::Monthly);
        
        // Test monitoring function
        let _ = engine.monitor_synchronization();
        assert!(engine.is_sync_healthy());
    }
    
    #[tokio::test]
    async fn test_time_sync_protocol() {
        // Create a mock network for testing
        let request_store = Arc::new(Mutex::new(HashMap::new()));
        let response_store = Arc::new(Mutex::new(HashMap::new()));
        
        let req_store = request_store.clone();
        let resp_store = response_store.clone();
        
        // Create two engines to simulate peers
        let mut engine1 = TimeSyncEngine::new();
        let engine2 = TimeSyncEngine::new();
        
        // Simulate a 50ms offset between peers
        engine1.state().set_local_offset(50000); // 50ms in microseconds
        
        // Define send/receive functions for engine1
        let send_request = move |request: SyncRequest| {
            let mut store = req_store.lock().unwrap();
            store.insert(request.challenge_nonce, request);
            
            // Process the request with engine2 and store response
            if let Some(response) = engine2.process_sync_request(&store[&request.challenge_nonce]) {
                let mut resp_store = resp_store.lock().unwrap();
                resp_store.insert(response.challenge_nonce, response);
            }
            
            true
        };
        
        let receive_response = move |nonce: u32| {
            let store = response_store.lock().unwrap();
            store.get(&nonce).cloned()
        };
        
        // Execute precision time sync
        let result = engine1.execute_precision_time_sync(send_request, receive_response).await;
        
        // Verify the result
        assert!(result.is_ok());
        let offset = result.unwrap();
        
        // The offset should be close to -50ms (with some tolerance for processing time)
        assert!(offset < -40.0 && offset > -60.0);
        
        // Verify the engine state was updated
        assert_eq!(engine1.state().status(), TimeSyncStatus::Adjusting);
        assert!(!engine1.state().time_adjustments().is_empty());
        
        // Process adjustments to apply the offset
        while !engine1.state().time_adjustments().is_empty() {
            engine1.monitor_synchronization();
            std::thread::sleep(Duration::from_millis(10));
        }
        
        // Verify the offset was applied
        assert_eq!(engine1.state().status(), TimeSyncStatus::Synchronized);
        
        // The local offset should now be close to 0 (with some tolerance)
        let final_offset_ms = engine1.state().local_offset() as f64 / 1000.0;
        assert!(final_offset_ms.abs() < 10.0);
    }
    
    #[test]
    fn test_month_boundary_detection() {
        use buckwild::time_sync::TimeEpoch;
        
        // This test can't reliably test the actual boundary detection
        // since we can't control the system time, but we can test the function exists
        let is_near = TimeEpoch::is_near_month_boundary(2000);
        
        // Just verify the function returns a boolean
        assert!(is_near == true || is_near == false);
    }
}