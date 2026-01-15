// Integration tests for timeout and reliability system
//
// Tests timeout system integration with other protocol components
// and end-to-end timeout behavior under realistic conditions.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};

use buckwild_common::protocol::{
    TimeoutManager, TimeoutEventType, TimeoutOutcome, TimeoutAction,
    timeout_constants, rfc6298_constants,
};
use buckwild_common::protocol::types::{
    ConnectionId, PacketId, FragmentId, SequenceNumber,
    MicrosecondTimestampValue,
};
use buckwild_common::errors::BuckwildError;

/// Mock connection state for testing
#[derive(Debug, Clone)]
struct MockConnectionState {
    connection_id: ConnectionId,
    state: String,
    connection_start_time: Option<Instant>,
    last_heartbeat_time: Option<Instant>,
    last_packet_time: Option<Instant>,
    consecutive_heartbeat_failures: u32,
}

impl MockConnectionState {
    fn new(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            state: "CONNECTING".to_string(),
            connection_start_time: Some(Instant::now()),
            last_heartbeat_time: None,
            last_packet_time: Some(Instant::now()),
            consecutive_heartbeat_failures: 0,
        }
    }
    
    fn establish(&mut self) {
        self.state = "ESTABLISHED".to_string();
        self.last_heartbeat_time = Some(Instant::now());
    }
    
    fn update_heartbeat(&mut self) {
        self.last_heartbeat_time = Some(Instant::now());
        self.consecutive_heartbeat_failures = 0;
    }
    
    fn heartbeat_failed(&mut self) {
        self.consecutive_heartbeat_failures += 1;
    }
    
    fn update_activity(&mut self) {
        self.last_packet_time = Some(Instant::now());
    }
}

/// Mock protocol engine for testing timeout integration
struct MockProtocolEngine {
    timeout_manager: TimeoutManager,
    connections: Arc<RwLock<std::collections::HashMap<ConnectionId, MockConnectionState>>>,
    next_packet_id: Arc<std::sync::atomic::AtomicU64>,
    next_sequence: Arc<std::sync::atomic::AtomicU32>,
}

impl MockProtocolEngine {
    fn new() -> Self {
        Self {
            timeout_manager: TimeoutManager::new(),
            connections: Arc::new(RwLock::new(std::collections::HashMap::new())),
            next_packet_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            next_sequence: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        }
    }
    
    async fn create_connection(&self, connection_id: ConnectionId) {
        let mut connections = self.connections.write().await;
        connections.insert(connection_id, MockConnectionState::new(connection_id));
    }
    
    async fn establish_connection(&self, connection_id: ConnectionId) -> Result<(), BuckwildError> {
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.get_mut(&connection_id) {
            conn.establish();
            Ok(())
        } else {
            Err(BuckwildError::SessionError("Connection not found".to_string()))
        }
    }
    
    async fn send_packet(&self, connection_id: ConnectionId) -> Result<PacketId, BuckwildError> {
        let packet_id = PacketId::new(
            self.next_packet_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let sequence = SequenceNumber::new(
            self.next_sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        
        // Update connection activity
        {
            let mut connections = self.connections.write().await;
            if let Some(conn) = connections.get_mut(&connection_id) {
                conn.update_activity();
            }
        }
        
        // Track packet with timeout manager
        self.timeout_manager.send_packet_with_timing(packet_id, sequence).await?;
        
        Ok(packet_id)
    }
    
    async fn receive_ack(&self, sequence: SequenceNumber) -> Result<(), BuckwildError> {
        self.timeout_manager.handle_ack_packet(sequence).await
    }
    
    async fn send_heartbeat(&self, connection_id: ConnectionId) -> Result<(), BuckwildError> {
        {
            let mut connections = self.connections.write().await;
            if let Some(conn) = connections.get_mut(&connection_id) {
                conn.update_heartbeat();
            }
        }
        
        // Send heartbeat packet
        self.send_packet(connection_id).await?;
        Ok(())
    }
    
    async fn process_timeout_events(&self) -> Result<Vec<TimeoutAction>, BuckwildError> {
        let mut all_actions = Vec::new();
        
        // Check connection timeouts
        let connections = self.connections.read().await;
        for (_, conn) in connections.iter() {
            let actions = self.timeout_manager.manage_connection_timeouts(
                conn.connection_id,
                &conn.state,
                conn.connection_start_time,
                conn.last_heartbeat_time,
                conn.last_packet_time,
                conn.consecutive_heartbeat_failures,
            ).await?;
            all_actions.extend(actions);
        }
        
        // Check retransmission timeouts
        let expired_packets = self.timeout_manager.check_retransmission_timers().await;
        for packet_id in expired_packets {
            if self.timeout_manager.handle_retransmission_timer_expiry(packet_id).await? {
                all_actions.push(TimeoutAction::RetransmitPacket(packet_id));
            }
        }
        
        // Check fragment timeouts
        let expired_fragments = self.timeout_manager.manage_fragment_timeouts().await?;
        for fragment_id in expired_fragments {
            all_actions.push(TimeoutAction::RequestFragmentRetransmission(fragment_id));
        }
        
        Ok(all_actions)
    }
    
    async fn handle_timeout_action(&self, action: TimeoutAction) -> Result<(), BuckwildError> {
        match action {
            TimeoutAction::ConnectionEstablishmentTimeout(connection_id) => {
                let mut connections = self.connections.write().await;
                connections.remove(&connection_id);
                println!("Connection {} establishment timeout", connection_id);
            }
            TimeoutAction::HeartbeatTimeout(connection_id) => {
                {
                    let mut connections = self.connections.write().await;
                    if let Some(conn) = connections.get_mut(&connection_id) {
                        conn.heartbeat_failed();
                    }
                }
                // Attempt to send heartbeat
                self.send_heartbeat(connection_id).await?;
            }
            TimeoutAction::SessionIdleTimeout(connection_id) => {
                let mut connections = self.connections.write().await;
                connections.remove(&connection_id);
                println!("Connection {} idle timeout", connection_id);
            }
            TimeoutAction::ConnectionFailure(connection_id, reason) => {
                let mut connections = self.connections.write().await;
                connections.remove(&connection_id);
                println!("Connection {} failed: {}", connection_id, reason);
            }
            TimeoutAction::RetransmitPacket(packet_id) => {
                println!("Retransmitting packet {}", packet_id);
                // In real implementation, would retransmit the actual packet
            }
            TimeoutAction::RequestFragmentRetransmission(fragment_id) => {
                println!("Requesting retransmission of fragment {}", fragment_id);
                // In real implementation, would send retransmission request
            }
            _ => {
                println!("Unhandled timeout action: {:?}", action);
            }
        }
        Ok(())
    }
    
    async fn run_timeout_processing(&self) -> Result<(), BuckwildError> {
        let actions = self.process_timeout_events().await?;
        for action in actions {
            self.handle_timeout_action(action).await?;
        }
        Ok(())
    }
}

#[tokio::test]
async fn test_end_to_end_connection_establishment_timeout() {
    let engine = MockProtocolEngine::new();
    let connection_id = ConnectionId::new(1);
    
    // Create connection but don't establish it
    engine.create_connection(connection_id).await;
    
    // Wait for connection timeout
    sleep(Duration::from_millis(timeout_constants::CONNECTION_TIMEOUT_MS + 100)).await;
    
    // Process timeout events
    let actions = engine.process_timeout_events().await.unwrap();
    
    // Should have connection establishment timeout
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        TimeoutAction::ConnectionEstablishmentTimeout(conn_id) => {
            assert_eq!(*conn_id, connection_id);
        }
        _ => panic!("Expected ConnectionEstablishmentTimeout"),
    }
    
    // Handle the timeout action
    engine.handle_timeout_action(actions[0].clone()).await.unwrap();
    
    // Connection should be removed
    let connections = engine.connections.read().await;
    assert!(!connections.contains_key(&connection_id));
}

#[tokio::test]
async fn test_end_to_end_heartbeat_timeout_recovery() {
    let engine = MockProtocolEngine::new();
    let connection_id = ConnectionId::new(1);
    
    // Create and establish connection
    engine.create_connection(connection_id).await;
    engine.establish_connection(connection_id).await.unwrap();
    
    // Send initial heartbeat
    engine.send_heartbeat(connection_id).await.unwrap();
    
    // Wait for heartbeat timeout
    sleep(Duration::from_millis(timeout_constants::HEARTBEAT_TIMEOUT_MS + 100)).await;
    
    // Process timeout events - should trigger heartbeat timeout
    let actions = engine.process_timeout_events().await.unwrap();
    assert_eq!(actions.len(), 1);
    
    match &actions[0] {
        TimeoutAction::HeartbeatTimeout(conn_id) => {
            assert_eq!(*conn_id, connection_id);
        }
        _ => panic!("Expected HeartbeatTimeout"),
    }
    
    // Handle heartbeat timeout (sends new heartbeat)
    engine.handle_timeout_action(actions[0].clone()).await.unwrap();
    
    // Connection should still exist
    let connections = engine.connections.read().await;
    assert!(connections.contains_key(&connection_id));
    
    // Simulate multiple heartbeat failures
    for i in 1..timeout_constants::MAX_HEARTBEAT_FAILURES {
        sleep(Duration::from_millis(timeout_constants::HEARTBEAT_TIMEOUT_MS + 100)).await;
        
        let actions = engine.process_timeout_events().await.unwrap();
        assert_eq!(actions.len(), 1);
        
        engine.handle_timeout_action(actions[0].clone()).await.unwrap();
        
        let connections = engine.connections.read().await;
        let conn = &connections[&connection_id];
        assert_eq!(conn.consecutive_heartbeat_failures, i);
    }
    
    // Next heartbeat timeout should cause connection failure
    sleep(Duration::from_millis(timeout_constants::HEARTBEAT_TIMEOUT_MS + 100)).await;
    
    let actions = engine.process_timeout_events().await.unwrap();
    assert_eq!(actions.len(), 1);
    
    match &actions[0] {
        TimeoutAction::ConnectionFailure(conn_id, reason) => {
            assert_eq!(*conn_id, connection_id);
            assert_eq!(reason, "Heartbeat timeout");
        }
        _ => panic!("Expected ConnectionFailure"),
    }
    
    // Handle connection failure
    engine.handle_timeout_action(actions[0].clone()).await.unwrap();
    
    // Connection should be removed
    let connections = engine.connections.read().await;
    assert!(!connections.contains_key(&connection_id));
}

#[tokio::test]
async fn test_end_to_end_packet_retransmission() {
    let engine = MockProtocolEngine::new();
    let connection_id = ConnectionId::new(1);
    
    // Create and establish connection
    engine.create_connection(connection_id).await;
    engine.establish_connection(connection_id).await.unwrap();
    
    // Send packet
    let packet_id = engine.send_packet(connection_id).await.unwrap();
    
    // Wait for retransmission timeout
    let initial_rto = engine.timeout_manager.rto_state.get_current_rto();
    sleep(initial_rto.as_duration() + Duration::from_millis(100)).await;
    
    // Process timeout events - should trigger retransmission
    let actions = engine.process_timeout_events().await.unwrap();
    assert_eq!(actions.len(), 1);
    
    match &actions[0] {
        TimeoutAction::RetransmitPacket(pkt_id) => {
            assert_eq!(*pkt_id, packet_id);
        }
        _ => panic!("Expected RetransmitPacket"),
    }
    
    // Handle retransmission
    engine.handle_timeout_action(actions[0].clone()).await.unwrap();
    
    // RTO should have doubled
    let new_rto = engine.timeout_manager.rto_state.get_current_rto();
    assert!(new_rto.as_ms() >= initial_rto.as_ms() * 2);
    
    // Simulate ACK arrival
    let sequence = SequenceNumber::new(1);
    engine.receive_ack(sequence).await.unwrap();
    
    // Packet should be removed from pending
    let pending = engine.timeout_manager.pending_packets.read().await;
    assert!(!pending.contains_key(&packet_id));
}

#[tokio::test]
async fn test_end_to_end_fragment_timeout() {
    let engine = MockProtocolEngine::new();
    let fragment_id = FragmentId::new(1);
    
    // Set fragment timeout
    engine.timeout_manager.set_fragment_reassembly_timeout(fragment_id).await;
    
    // Wait for fragment timeout
    sleep(Duration::from_millis(timeout_constants::FRAGMENT_TIMEOUT_MS + 100)).await;
    
    // Process timeout events
    let actions = engine.process_timeout_events().await.unwrap();
    assert_eq!(actions.len(), 1);
    
    match &actions[0] {
        TimeoutAction::RequestFragmentRetransmission(frag_id) => {
            assert_eq!(*frag_id, fragment_id);
        }
        _ => panic!("Expected RequestFragmentRetransmission"),
    }
    
    // Handle fragment timeout
    engine.handle_timeout_action(actions[0].clone()).await.unwrap();
}

#[tokio::test]
async fn test_rto_adaptation_under_varying_conditions() {
    let engine = MockProtocolEngine::new();
    let connection_id = ConnectionId::new(1);
    
    engine.create_connection(connection_id).await;
    engine.establish_connection(connection_id).await.unwrap();
    
    // Simulate stable network conditions
    for i in 0..10 {
        let packet_id = engine.send_packet(connection_id).await.unwrap();
        
        // Simulate consistent 100ms RTT
        sleep(Duration::from_millis(100)).await;
        
        let sequence = SequenceNumber::new(i + 1);
        engine.receive_ack(sequence).await.unwrap();
    }
    
    let stable_stats = engine.timeout_manager.get_rto_statistics();
    assert!(stable_stats.srtt_ms >= 90 && stable_stats.srtt_ms <= 110);
    assert!(stable_stats.rttvar_ms <= 20); // Low variation
    
    // Simulate network degradation
    for i in 10..15 {
        let packet_id = engine.send_packet(connection_id).await.unwrap();
        
        // Simulate increasing RTT (200-600ms)
        let rtt_ms = 200 + (i - 10) * 100;
        sleep(Duration::from_millis(rtt_ms as u64)).await;
        
        let sequence = SequenceNumber::new(i + 1);
        engine.receive_ack(sequence).await.unwrap();
    }
    
    let degraded_stats = engine.timeout_manager.get_rto_statistics();
    assert!(degraded_stats.srtt_ms > stable_stats.srtt_ms);
    assert!(degraded_stats.rttvar_ms > stable_stats.rttvar_ms);
    assert!(degraded_stats.rto_ms > stable_stats.rto_ms);
    
    // Simulate network recovery
    for i in 15..20 {
        let packet_id = engine.send_packet(connection_id).await.unwrap();
        
        // Back to 100ms RTT
        sleep(Duration::from_millis(100)).await;
        
        let sequence = SequenceNumber::new(i + 1);
        engine.receive_ack(sequence).await.unwrap();
    }
    
    let recovered_stats = engine.timeout_manager.get_rto_statistics();
    assert!(recovered_stats.srtt_ms < degraded_stats.srtt_ms);
    assert!(recovered_stats.rto_ms < degraded_stats.rto_ms);
}

#[tokio::test]
async fn test_concurrent_timeout_processing() {
    let engine = Arc::new(MockProtocolEngine::new());
    
    // Create multiple connections
    let mut connection_ids = Vec::new();
    for i in 0..10 {
        let connection_id = ConnectionId::new(i);
        engine.create_connection(connection_id).await;
        engine.establish_connection(connection_id).await.unwrap();
        connection_ids.push(connection_id);
    }
    
    // Send packets from all connections concurrently
    let mut handles = Vec::new();
    for connection_id in connection_ids.clone() {
        let engine_clone = engine.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..5 {
                let _ = engine_clone.send_packet(connection_id).await;
                sleep(Duration::from_millis(10)).await;
            }
        });
        handles.push(handle);
    }
    
    // Wait for all packets to be sent
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Process timeout events concurrently
    let mut timeout_handles = Vec::new();
    for _ in 0..5 {
        let engine_clone = engine.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..10 {
                let _ = engine_clone.run_timeout_processing().await;
                sleep(Duration::from_millis(50)).await;
            }
        });
        timeout_handles.push(handle);
    }
    
    // Let timeout processing run
    sleep(Duration::from_millis(500)).await;
    
    // Cancel timeout processing
    for handle in timeout_handles {
        handle.abort();
    }
    
    // Verify system is still functional
    let stats = engine.timeout_manager.get_timeout_statistics().await;
    println!("Processed {} timeout events", stats.len());
    
    // All connections should still exist (no timeouts yet)
    let connections = engine.connections.read().await;
    assert_eq!(connections.len(), 10);
}

#[tokio::test]
async fn test_timeout_system_under_load() {
    let engine = MockProtocolEngine::new();
    let connection_id = ConnectionId::new(1);
    
    engine.create_connection(connection_id).await;
    engine.establish_connection(connection_id).await.unwrap();
    
    // Send many packets rapidly
    let mut packet_ids = Vec::new();
    for _ in 0..1000 {
        let packet_id = engine.send_packet(connection_id).await.unwrap();
        packet_ids.push(packet_id);
    }
    
    // Verify all packets are tracked
    {
        let pending = engine.timeout_manager.pending_packets.read().await;
        assert_eq!(pending.len(), 1000);
    }
    
    // Acknowledge packets in batches with realistic timing
    for chunk in packet_ids.chunks(100) {
        sleep(Duration::from_millis(50)).await; // Simulate network delay
        
        for (i, _) in chunk.iter().enumerate() {
            let sequence = SequenceNumber::new((chunk.as_ptr() as usize / std::mem::size_of::<PacketId>() * 100 + i + 1) as u32);
            engine.receive_ack(sequence).await.unwrap();
        }
    }
    
    // All packets should be acknowledged
    {
        let pending = engine.timeout_manager.pending_packets.read().await;
        assert!(pending.is_empty());
    }
    
    // RTO should have adapted to the measured RTT
    let stats = engine.timeout_manager.get_rto_statistics();
    assert!(stats.measurement_count > 0);
    assert!(stats.srtt_ms >= 40 && stats.srtt_ms <= 70); // Around 50ms
}

#[tokio::test]
async fn test_timeout_recovery_escalation() {
    let engine = MockProtocolEngine::new();
    let connection_id = ConnectionId::new(1);
    
    engine.create_connection(connection_id).await;
    engine.establish_connection(connection_id).await.unwrap();
    
    // Send packet that will timeout multiple times
    let packet_id = engine.send_packet(connection_id).await.unwrap();
    
    // Simulate multiple retransmission timeouts
    for attempt in 1..=rfc6298_constants::MAX_RETRANSMISSION_ATTEMPTS {
        let current_rto = engine.timeout_manager.rto_state.get_current_rto();
        sleep(current_rto.as_duration() + Duration::from_millis(100)).await;
        
        let should_retransmit = engine.timeout_manager
            .handle_retransmission_timer_expiry(packet_id)
            .await
            .unwrap();
        
        if attempt < rfc6298_constants::MAX_RETRANSMISSION_ATTEMPTS {
            assert!(should_retransmit);
            
            // RTO should have doubled
            let new_rto = engine.timeout_manager.rto_state.get_current_rto();
            assert!(new_rto.as_ms() >= current_rto.as_ms() * 2);
        } else {
            // Final attempt should fail
            assert!(!should_retransmit);
        }
    }
    
    // Packet should be removed after max retries
    {
        let pending = engine.timeout_manager.pending_packets.read().await;
        assert!(!pending.contains_key(&packet_id));
    }
}

#[tokio::test]
async fn test_session_idle_timeout_integration() {
    let engine = MockProtocolEngine::new();
    let connection_id = ConnectionId::new(1);
    
    engine.create_connection(connection_id).await;
    engine.establish_connection(connection_id).await.unwrap();
    
    // Send some initial activity
    engine.send_packet(connection_id).await.unwrap();
    
    // Wait for session idle timeout
    sleep(Duration::from_millis(timeout_constants::SESSION_IDLE_TIMEOUT_MS + 100)).await;
    
    // Process timeout events
    let actions = engine.process_timeout_events().await.unwrap();
    assert_eq!(actions.len(), 1);
    
    match &actions[0] {
        TimeoutAction::SessionIdleTimeout(conn_id) => {
            assert_eq!(*conn_id, connection_id);
        }
        _ => panic!("Expected SessionIdleTimeout"),
    }
    
    // Handle idle timeout
    engine.handle_timeout_action(actions[0].clone()).await.unwrap();
    
    // Connection should be removed
    let connections = engine.connections.read().await;
    assert!(!connections.contains_key(&connection_id));
}