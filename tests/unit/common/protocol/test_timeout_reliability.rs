// Comprehensive tests for timeout and reliability system
//
// Tests RFC 6298 RTO calculation, connection timeouts, fragment timeouts,
// and timeout monitoring under various network conditions.

use std::time::{Duration, Instant};
use tokio::time::sleep;

use buckwild_common::protocol::{
    TimeoutManager, RtoState, TimeoutEventType, TimeoutOutcome, TimeoutAction,
    TimeoutErrorContext, RecoveryType, rfc6298_constants, timeout_constants,
};
use buckwild_common::protocol::types::{
    ConnectionId, PacketId, FragmentId, SequenceNumber,
    MicrosecondTimestampValue, TimeoutMs,
};
use buckwild_common::errors::BuckwildError;

#[tokio::test]
async fn test_rfc6298_rto_calculation() {
    let rto_state = RtoState::new();
    
    // Verify initial state
    let initial_stats = rto_state.get_statistics();
    assert_eq!(initial_stats.srtt_ms, rfc6298_constants::RTT_INITIAL_MS);
    assert_eq!(initial_stats.rttvar_ms, rfc6298_constants::RTT_INITIAL_MS / 2);
    assert_eq!(initial_stats.rto_ms, rfc6298_constants::RTT_INITIAL_MS);
    assert_eq!(initial_stats.measurement_count, 0);
    
    // First RTT measurement (100ms)
    let send_time1 = MicrosecondTimestampValue::now();
    sleep(Duration::from_millis(100)).await;
    let ack_time1 = MicrosecondTimestampValue::now();
    
    let rtt1 = rto_state.measure_rtt(send_time1, ack_time1);
    let rto1 = rto_state.update_rto_with_measurement(rtt1);
    
    assert!(rtt1.as_millis() >= 100);
    assert!(rtt1.as_millis() <= 110); // Allow some variance
    
    let stats1 = rto_state.get_statistics();
    assert_eq!(stats1.srtt_ms, rtt1.as_millis());
    assert_eq!(stats1.rttvar_ms, rtt1.as_millis() / 2);
    assert_eq!(stats1.measurement_count, 1);
    
    // Second RTT measurement (50ms) - should smooth the values
    let send_time2 = MicrosecondTimestampValue::now();
    sleep(Duration::from_millis(50)).await;
    let ack_time2 = MicrosecondTimestampValue::now();
    
    let rtt2 = rto_state.measure_rtt(send_time2, ack_time2);
    let rto2 = rto_state.update_rto_with_measurement(rtt2);
    
    assert!(rtt2.as_millis() >= 50);
    assert!(rtt2.as_millis() <= 60);
    
    let stats2 = rto_state.get_statistics();
    assert_eq!(stats2.measurement_count, 2);
    
    // SRTT should be smoothed (closer to first measurement due to alpha=1/8)
    assert!(stats2.srtt_ms > rtt2.as_millis());
    assert!(stats2.srtt_ms < stats1.srtt_ms);
    
    // Third measurement with higher RTT (200ms)
    let send_time3 = MicrosecondTimestampValue::now();
    sleep(Duration::from_millis(200)).await;
    let ack_time3 = MicrosecondTimestampValue::now();
    
    let rtt3 = rto_state.measure_rtt(send_time3, ack_time3);
    let rto3 = rto_state.update_rto_with_measurement(rtt3);
    
    let stats3 = rto_state.get_statistics();
    assert_eq!(stats3.measurement_count, 3);
    
    // RTTVAR should increase due to higher variation
    assert!(stats3.rttvar_ms > stats2.rttvar_ms);
    
    // RTO should be SRTT + max(G, K * RTTVAR)
    let expected_rto = stats3.srtt_ms + 
        (rfc6298_constants::RTT_G.max((rfc6298_constants::RTT_K * stats3.rttvar_ms as f64) as u32));
    assert_eq!(stats3.rto_ms, expected_rto.max(rfc6298_constants::MIN_RETRANSMISSION_TIMEOUT_MS));
}

#[tokio::test]
async fn test_rto_exponential_backoff() {
    let rto_state = RtoState::new();
    
    // Set initial RTO
    let initial_rto = rto_state.get_current_rto();
    assert_eq!(initial_rto.as_ms(), rfc6298_constants::RTT_INITIAL_MS as u64);
    
    // First timeout - should double
    let rto1 = rto_state.handle_retransmission_timeout();
    assert_eq!(rto1.as_ms(), (rfc6298_constants::RTT_INITIAL_MS * 2) as u64);
    
    // Second timeout - should double again
    let rto2 = rto_state.handle_retransmission_timeout();
    assert_eq!(rto2.as_ms(), (rfc6298_constants::RTT_INITIAL_MS * 4) as u64);
    
    // Continue until max
    let mut current_rto = rto2;
    while current_rto.as_ms() < rfc6298_constants::MAX_RETRANSMISSION_TIMEOUT_MS as u64 {
        current_rto = rto_state.handle_retransmission_timeout();
    }
    
    // Should cap at maximum
    assert_eq!(current_rto.as_ms(), rfc6298_constants::MAX_RETRANSMISSION_TIMEOUT_MS as u64);
    
    // Further timeouts should stay at maximum
    let final_rto = rto_state.handle_retransmission_timeout();
    assert_eq!(final_rto.as_ms(), rfc6298_constants::MAX_RETRANSMISSION_TIMEOUT_MS as u64);
}

#[tokio::test]
async fn test_rto_bounds_enforcement() {
    let rto_state = RtoState::new();
    
    // Test minimum RTT enforcement
    let send_time = MicrosecondTimestampValue::now();
    // Simulate very small RTT (less than 1ms)
    let ack_time = MicrosecondTimestampValue::from_micros(send_time.as_micros() + 500); // 0.5ms
    
    let rtt = rto_state.measure_rtt(send_time, ack_time);
    assert_eq!(rtt.as_millis(), rfc6298_constants::RTT_MIN_MS);
    
    // Test maximum RTT enforcement
    let send_time2 = MicrosecondTimestampValue::now();
    let ack_time2 = MicrosecondTimestampValue::from_micros(
        send_time2.as_micros() + (rfc6298_constants::RTT_MAX_MS as u64 + 1000) * 1000
    );
    
    let rtt2 = rto_state.measure_rtt(send_time2, ack_time2);
    assert_eq!(rtt2.as_millis(), rfc6298_constants::RTT_MAX_MS);
}

#[tokio::test]
async fn test_timeout_manager_packet_tracking() {
    let manager = TimeoutManager::new();
    
    let packet_id = PacketId::new(1);
    let sequence = SequenceNumber::new(100);
    
    // Send packet with timing
    manager.send_packet_with_timing(packet_id, sequence).await.unwrap();
    
    // Verify packet is tracked
    {
        let pending = manager.pending_packets.read().await;
        assert!(pending.contains_key(&packet_id));
        let timing = &pending[&packet_id];
        assert_eq!(timing.packet_id, packet_id);
        assert_eq!(timing.sequence_number, sequence);
        assert!(!timing.retransmitted);
        assert_eq!(timing.retry_count, 0);
    }
    
    // Simulate ACK
    manager.handle_ack_packet(sequence).await.unwrap();
    
    // Verify packet was removed
    {
        let pending = manager.pending_packets.read().await;
        assert!(!pending.contains_key(&packet_id));
    }
    
    // Verify retransmission timer was cancelled
    {
        let timers = manager.retransmission_timers.read().await;
        assert!(!timers.contains_key(&packet_id));
    }
}

#[tokio::test]
async fn test_retransmission_timeout_handling() {
    let manager = TimeoutManager::new();
    
    let packet_id = PacketId::new(1);
    let sequence = SequenceNumber::new(100);
    
    // Send packet
    manager.send_packet_with_timing(packet_id, sequence).await.unwrap();
    
    // Simulate retransmission timeout
    let should_retransmit = manager.handle_retransmission_timer_expiry(packet_id).await.unwrap();
    assert!(should_retransmit);
    
    // Verify packet is marked as retransmitted
    {
        let pending = manager.pending_packets.read().await;
        assert!(pending.contains_key(&packet_id));
        let timing = &pending[&packet_id];
        assert!(timing.retransmitted);
        assert_eq!(timing.retry_count, 1);
    }
    
    // Simulate multiple retransmission timeouts
    for i in 2..=rfc6298_constants::MAX_RETRANSMISSION_ATTEMPTS {
        let should_retransmit = manager.handle_retransmission_timer_expiry(packet_id).await.unwrap();
        assert!(should_retransmit);
        
        let pending = manager.pending_packets.read().await;
        let timing = &pending[&packet_id];
        assert_eq!(timing.retry_count, i);
    }
    
    // Next timeout should exceed maximum retries
    let should_retransmit = manager.handle_retransmission_timer_expiry(packet_id).await.unwrap();
    assert!(!should_retransmit);
    
    // Packet should be removed
    {
        let pending = manager.pending_packets.read().await;
        assert!(!pending.contains_key(&packet_id));
    }
}

#[tokio::test]
async fn test_connection_timeout_management() {
    let manager = TimeoutManager::new();
    let connection_id = ConnectionId::new(1);
    
    // Test connection establishment timeout
    let connection_start = Some(Instant::now() - Duration::from_millis(timeout_constants::CONNECTION_TIMEOUT_MS + 1000));
    
    let actions = manager.manage_connection_timeouts(
        connection_id,
        "CONNECTING",
        connection_start,
        None,
        None,
        0,
    ).await.unwrap();
    
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TimeoutAction::ConnectionEstablishmentTimeout(conn_id) => {
            assert_eq!(*conn_id, connection_id);
        }
        _ => panic!("Expected ConnectionEstablishmentTimeout"),
    }
    
    // Test heartbeat timeout
    let last_heartbeat = Some(Instant::now() - Duration::from_millis(timeout_constants::HEARTBEAT_TIMEOUT_MS + 1000));
    
    let actions = manager.manage_connection_timeouts(
        connection_id,
        "ESTABLISHED",
        None,
        last_heartbeat,
        None,
        0,
    ).await.unwrap();
    
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TimeoutAction::HeartbeatTimeout(conn_id) => {
            assert_eq!(*conn_id, connection_id);
        }
        _ => panic!("Expected HeartbeatTimeout"),
    }
    
    // Test heartbeat failure after max attempts
    let actions = manager.manage_connection_timeouts(
        connection_id,
        "ESTABLISHED",
        None,
        last_heartbeat,
        None,
        timeout_constants::MAX_HEARTBEAT_FAILURES,
    ).await.unwrap();
    
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TimeoutAction::ConnectionFailure(conn_id, reason) => {
            assert_eq!(*conn_id, connection_id);
            assert_eq!(reason, "Heartbeat timeout");
        }
        _ => panic!("Expected ConnectionFailure"),
    }
    
    // Test session idle timeout
    let last_packet = Some(Instant::now() - Duration::from_millis(timeout_constants::SESSION_IDLE_TIMEOUT_MS + 1000));
    
    let actions = manager.manage_connection_timeouts(
        connection_id,
        "ESTABLISHED",
        None,
        None,
        last_packet,
        0,
    ).await.unwrap();
    
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TimeoutAction::SessionIdleTimeout(conn_id) => {
            assert_eq!(*conn_id, connection_id);
        }
        _ => panic!("Expected SessionIdleTimeout"),
    }
}

#[tokio::test]
async fn test_fragment_timeout_management() {
    let manager = TimeoutManager::new();
    let fragment_id = FragmentId::new(1);
    
    // Set fragment timeout
    manager.set_fragment_reassembly_timeout(fragment_id).await;
    
    // Verify timeout was set
    {
        let timeouts = manager.fragment_timeouts.read().await;
        assert!(timeouts.contains_key(&fragment_id));
    }
    
    // Simulate timeout expiry by manually setting past time
    {
        let mut timeouts = manager.fragment_timeouts.write().await;
        timeouts.insert(fragment_id, Instant::now() - Duration::from_secs(1));
    }
    
    // Check for expired fragments
    let expired = manager.manage_fragment_timeouts().await.unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0], fragment_id);
    
    // Verify fragment was removed
    {
        let timeouts = manager.fragment_timeouts.read().await;
        assert!(!timeouts.contains_key(&fragment_id));
    }
}

#[tokio::test]
async fn test_exponential_backoff_calculation() {
    let manager = TimeoutManager::new();
    
    // Test exponential growth
    let backoff0 = manager.calculate_exponential_backoff(0, 1000, 60000);
    let backoff1 = manager.calculate_exponential_backoff(1, 1000, 60000);
    let backoff2 = manager.calculate_exponential_backoff(2, 1000, 60000);
    let backoff3 = manager.calculate_exponential_backoff(3, 1000, 60000);
    
    // Should roughly double each time (with jitter)
    assert!(backoff0.as_ms() >= 1000);
    assert!(backoff0.as_ms() <= 1100); // 10% jitter
    
    assert!(backoff1.as_ms() >= 2000);
    assert!(backoff1.as_ms() <= 2200);
    
    assert!(backoff2.as_ms() >= 4000);
    assert!(backoff2.as_ms() <= 4400);
    
    assert!(backoff3.as_ms() >= 8000);
    assert!(backoff3.as_ms() <= 8800);
    
    // Test maximum capping
    let backoff_large = manager.calculate_exponential_backoff(10, 1000, 60000);
    assert_eq!(backoff_large.as_ms(), 60000);
}

#[tokio::test]
async fn test_timeout_error_context_backoff() {
    let manager = TimeoutManager::new();
    
    let mut context = TimeoutErrorContext::new(
        TimeoutEventType::Connection,
        "test_connection".to_string(),
        Some(ConnectionId::new(1)),
        "Connection failed".to_string(),
    );
    
    // Test successful backoff calculation
    let backoff = manager.handle_timeout_error_with_backoff(context.clone()).await.unwrap();
    assert!(backoff.is_some());
    
    // Test maximum retries exceeded
    context.retry_count = timeout_constants::MAX_RETRY_ATTEMPTS;
    let backoff = manager.handle_timeout_error_with_backoff(context).await.unwrap();
    assert!(backoff.is_none());
}

#[test]
fn test_timestamp_validation() {
    let manager = TimeoutManager::new();
    
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    // Valid timestamp (recent)
    let valid_timestamp = current_time - 1000; // 1 second ago
    assert!(manager.validate_packet_timestamp_timeout(valid_timestamp).is_ok());
    
    // Invalid timestamp (too old)
    let old_timestamp = current_time - (timeout_constants::TIMESTAMP_WINDOW_MS + 1000);
    let result = manager.validate_packet_timestamp_timeout(old_timestamp);
    assert!(result.is_err());
    match result.unwrap_err() {
        BuckwildError::SecurityError(msg) => {
            assert!(msg.contains("Timestamp replay detected"));
        }
        _ => panic!("Expected SecurityError"),
    }
    
    // Invalid timestamp (future)
    let future_timestamp = current_time + (timeout_constants::TIME_SYNC_TOLERANCE_MS + 1000);
    let result = manager.validate_packet_timestamp_timeout(future_timestamp);
    assert!(result.is_err());
    match result.unwrap_err() {
        BuckwildError::SecurityError(msg) => {
            assert!(msg.contains("Future timestamp detected"));
        }
        _ => panic!("Expected SecurityError"),
    }
}

#[tokio::test]
async fn test_timeout_statistics_tracking() {
    let manager = TimeoutManager::new();
    
    // Initially no statistics
    let stats = manager.get_timeout_statistics().await;
    assert!(stats.is_empty());
    
    // Trigger some timeout events
    let connection_id = ConnectionId::new(1);
    let _ = manager.manage_connection_timeouts(
        connection_id,
        "CONNECTING",
        Some(Instant::now() - Duration::from_millis(timeout_constants::CONNECTION_TIMEOUT_MS + 1000)),
        None,
        None,
        0,
    ).await;
    
    // Check statistics were recorded
    let stats = manager.get_timeout_statistics().await;
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].event_type, TimeoutEventType::Connection);
    assert_eq!(stats[0].outcome, TimeoutOutcome::Timeout);
    assert_eq!(stats[0].connection_id, Some(connection_id));
}

#[tokio::test]
async fn test_rto_statistics() {
    let manager = TimeoutManager::new();
    
    let initial_stats = manager.get_rto_statistics();
    assert_eq!(initial_stats.srtt_ms, rfc6298_constants::RTT_INITIAL_MS);
    assert_eq!(initial_stats.measurement_count, 0);
    
    // Reset RTO estimates
    manager.reset_rto_estimates();
    
    let reset_stats = manager.get_rto_statistics();
    assert_eq!(reset_stats.srtt_ms, rfc6298_constants::RTT_INITIAL_MS);
    assert_eq!(reset_stats.measurement_count, 0);
}

#[tokio::test]
async fn test_recovery_type_timeouts() {
    // Test timeout limits for different recovery types
    assert_eq!(
        RecoveryType::TimeResync.get_timeout_limit().as_ms(),
        timeout_constants::TIME_RESYNC_TIMEOUT_MS
    );
    
    assert_eq!(
        RecoveryType::Rekey.get_timeout_limit().as_ms(),
        timeout_constants::REKEY_TIMEOUT_MS
    );
    
    assert_eq!(
        RecoveryType::SequenceRepair.get_timeout_limit().as_ms(),
        timeout_constants::SEQUENCE_REPAIR_TIMEOUT_MS
    );
    
    assert_eq!(
        RecoveryType::Emergency.get_timeout_limit().as_ms(),
        timeout_constants::EMERGENCY_RECOVERY_TIMEOUT_MS
    );
}

#[tokio::test]
async fn test_timeout_manager_cleanup() {
    let manager = TimeoutManager::new();
    
    // Add some test data
    let packet_id = PacketId::new(1);
    let sequence = SequenceNumber::new(100);
    manager.send_packet_with_timing(packet_id, sequence).await.unwrap();
    
    let fragment_id = FragmentId::new(1);
    manager.set_fragment_reassembly_timeout(fragment_id).await;
    
    // Verify data exists
    {
        let pending = manager.pending_packets.read().await;
        assert!(pending.contains_key(&packet_id));
    }
    
    {
        let timeouts = manager.fragment_timeouts.read().await;
        assert!(timeouts.contains_key(&fragment_id));
    }
    
    // Run cleanup
    manager.cleanup_expired_data().await;
    
    // Data should still exist (not expired yet)
    {
        let pending = manager.pending_packets.read().await;
        assert!(pending.contains_key(&packet_id));
    }
    
    {
        let timeouts = manager.fragment_timeouts.read().await;
        assert!(timeouts.contains_key(&fragment_id));
    }
}

#[tokio::test]
async fn test_timeout_under_network_conditions() {
    let manager = TimeoutManager::new();
    
    // Simulate high latency network
    let rto_state = &manager.rto_state;
    
    // Multiple high RTT measurements
    for _ in 0..5 {
        let send_time = MicrosecondTimestampValue::now();
        sleep(Duration::from_millis(500)).await; // 500ms RTT
        let ack_time = MicrosecondTimestampValue::now();
        
        let rtt = rto_state.measure_rtt(send_time, ack_time);
        rto_state.update_rto_with_measurement(rtt);
    }
    
    let stats = rto_state.get_statistics();
    assert!(stats.srtt_ms >= 400); // Should adapt to high RTT
    assert!(stats.rto_ms >= 500); // RTO should be higher
    
    // Simulate network improvement
    for _ in 0..5 {
        let send_time = MicrosecondTimestampValue::now();
        sleep(Duration::from_millis(50)).await; // 50ms RTT
        let ack_time = MicrosecondTimestampValue::now();
        
        let rtt = rto_state.measure_rtt(send_time, ack_time);
        rto_state.update_rto_with_measurement(rtt);
    }
    
    let improved_stats = rto_state.get_statistics();
    assert!(improved_stats.srtt_ms < stats.srtt_ms); // Should adapt down
    assert!(improved_stats.rto_ms < stats.rto_ms);
}

#[tokio::test]
async fn test_timeout_accuracy_under_load() {
    let manager = TimeoutManager::new();
    
    // Send multiple packets simultaneously
    let mut packet_ids = Vec::new();
    for i in 0..100 {
        let packet_id = PacketId::new(i);
        let sequence = SequenceNumber::new(i as u32);
        manager.send_packet_with_timing(packet_id, sequence).await.unwrap();
        packet_ids.push(packet_id);
    }
    
    // Verify all packets are tracked
    {
        let pending = manager.pending_packets.read().await;
        assert_eq!(pending.len(), 100);
    }
    
    // Acknowledge half the packets
    for i in 0..50 {
        let sequence = SequenceNumber::new(i as u32);
        manager.handle_ack_packet(sequence).await.unwrap();
    }
    
    // Verify correct packets were removed
    {
        let pending = manager.pending_packets.read().await;
        assert_eq!(pending.len(), 50);
        
        for i in 50..100 {
            let packet_id = PacketId::new(i);
            assert!(pending.contains_key(&packet_id));
        }
    }
    
    // Check for expired timers
    let expired = manager.check_retransmission_timers().await;
    // Should be empty since timers haven't expired yet
    assert!(expired.is_empty());
}