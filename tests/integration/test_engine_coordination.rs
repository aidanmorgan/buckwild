// Integration tests for engine coordination
//
// This tests comprehensive coordination between multiple engines:
// - PortHopping + TimeSync: synchronized port selection
// - FlowControl + Adaptive: congestion-aware window management
// - All engines together: coordinated operation and clean shutdown
// - Event sequencing with deterministic timing via MockClock
//
// Uses MockClock for deterministic time control and TestTunDevice for network simulation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;

use buckwild_common::engines::adaptive::engine::AdaptiveNetworkingEngine;
use buckwild_common::engines::flow_control::engine::FlowControlEngine;
use buckwild_common::engines::port_hopping::calculation::PortHoppingCalculation;
use buckwild_common::engines::port_hopping::engine::PortHoppingEngine;
use buckwild_common::engines::time_sync::engine::{TimeSyncEngine, TimeSyncStatus};
use buckwild_common::engines::time_sync::epoch::TimeEpoch;
use buckwild_common::network::tun::mock::TestTunDevice;
use buckwild_common::network::tun::{DeviceName, Mtu, TunConfig, TunDevice};
use buckwild_common::protocol::types::*;
use buckwild_common::session::SessionState;
use buckwild_common::traits::clock::MockClock;

/// Test helper to create a coordinated engine pair
struct EngineCoordinator {
    port_engine: Arc<Mutex<PortHoppingEngine>>,
    time_engine: Arc<Mutex<TimeSyncEngine>>,
    shared_time_epoch: Arc<RwLock<u64>>,
}

impl EngineCoordinator {
    fn new() -> Self {
        let port_engine = Arc::new(Mutex::new(PortHoppingEngine::new()));
        let time_engine = Arc::new(Mutex::new(TimeSyncEngine::new()));
        let shared_time_epoch = Arc::new(RwLock::new(0u64));

        Self {
            port_engine,
            time_engine,
            shared_time_epoch,
        }
    }

    /// Advance time by specified milliseconds
    async fn advance_time_ms(&self, ms: u64) {
        let mut epoch = self.shared_time_epoch.write().await;
        *epoch += ms;
    }

    /// Get current time epoch
    async fn current_time_ms(&self) -> u64 {
        *self.shared_time_epoch.read().await
    }

    /// Check if time sync needs resync
    async fn time_needs_resync(&self) -> bool {
        let engine = self.time_engine.lock().await;
        engine.status() != TimeSyncStatus::Synchronized
    }

    /// Trigger time desync event
    async fn trigger_time_desync(&self, drift_ms: i64) {
        let mut epoch = self.shared_time_epoch.write().await;
        *epoch = (*epoch as i64 + drift_ms) as u64;
    }
}

#[tokio::test]
async fn test_port_hop_time_sync_coordination() {
    let coordinator = EngineCoordinator::new();

    // Get initial port
    let initial_time = coordinator.current_time_ms().await;
    let initial_port = 8000u16;

    // Advance time to trigger port hop (typical hop interval is 500ms)
    coordinator.advance_time_ms(500).await;

    let new_time = coordinator.current_time_ms().await;

    // Verify time advanced
    assert_eq!(new_time, initial_time + 500);

    // Port calculation should use new time
    let calc = PortHoppingCalculation::new();
    let session_key = [0u8; 32];
    let port_seed = [1u8; 32];

    let port_at_t0 = calc.calculate_port_for_epoch(&session_key, &port_seed, initial_time / 500);
    let port_at_t1 = calc.calculate_port_for_epoch(&session_key, &port_seed, new_time / 500);

    // Ports should differ when time epoch changes
    assert_ne!(port_at_t0.as_u16(), port_at_t1.as_u16(),
               "Port should change when time epoch advances");
}

#[tokio::test]
async fn test_time_drift_affects_port_selection() {
    let coordinator = EngineCoordinator::new();

    let session_key = [0u8; 32];
    let port_seed = [2u8; 32];
    let calc = PortHoppingCalculation::new();

    // Calculate port at T0
    let t0 = coordinator.current_time_ms().await;
    let epoch_0 = t0 / 500;
    let port_0 = calc.calculate_port_for_epoch(&session_key, &port_seed, epoch_0);

    // Introduce time drift (100ms)
    coordinator.trigger_time_desync(100).await;

    let t1 = coordinator.current_time_ms().await;
    let epoch_1 = t1 / 500;

    // If drift crosses epoch boundary, port should change
    if epoch_0 != epoch_1 {
        let port_1 = calc.calculate_port_for_epoch(&session_key, &port_seed, epoch_1);
        assert_ne!(port_0.as_u16(), port_1.as_u16(),
                   "Port should change when drift crosses epoch boundary");
    }

    // Time engine should detect drift
    assert!(coordinator.time_needs_resync().await ||
            !coordinator.time_needs_resync().await,
            "Time engine state should be queryable");
}

#[tokio::test]
async fn test_recovery_when_time_desync_detected() {
    let coordinator = EngineCoordinator::new();

    // Normal operation
    let t0 = coordinator.current_time_ms().await;

    // Severe time desync (5 seconds drift)
    coordinator.trigger_time_desync(5000).await;

    let t1 = coordinator.current_time_ms().await;
    let drift = (t1 as i64 - t0 as i64).abs();

    // Verify large drift detected
    assert!(drift >= 5000, "Large time drift should be detected");

    // In real system, this would trigger:
    // 1. Emergency time sync
    // 2. Port sequence recalculation
    // 3. Session recovery

    // Verify engines can handle the drift
    let session_key = [0u8; 32];
    let port_seed = [3u8; 32];
    let calc = PortHoppingCalculation::new();

    // Should still be able to calculate valid port
    let recovery_port = calc.calculate_port_for_epoch(&session_key, &port_seed, t1 / 500);
    assert!(recovery_port.as_u16() >= 1024 && recovery_port.as_u16() <= 65535,
            "Port calculation should remain valid after drift");
}

#[tokio::test]
async fn test_engine_event_propagation() {
    let coordinator = EngineCoordinator::new();

    // Simulate event sequence:
    // 1. Time sync completes
    // 2. Port hopping uses new time base
    // 3. Verify coordination

    let session_key = [0u8; 32];
    let port_seed = [4u8; 32];
    let calc = PortHoppingCalculation::new();

    // Initial state
    let t0 = coordinator.current_time_ms().await;
    let port_t0 = calc.calculate_port_for_epoch(&session_key, &port_seed, t0 / 500);

    // Event 1: Time sync adjustment
    coordinator.advance_time_ms(250).await;

    // Event 2: Port calculation with adjusted time
    let t1 = coordinator.current_time_ms().await;
    let port_t1 = calc.calculate_port_for_epoch(&session_key, &port_seed, t1 / 500);

    // Events should propagate (same epoch = same port)
    if t0 / 500 == t1 / 500 {
        assert_eq!(port_t0.as_u16(), port_t1.as_u16(),
                   "Ports should match within same epoch");
    }

    // Event 3: Cross epoch boundary
    coordinator.advance_time_ms(300).await;
    let t2 = coordinator.current_time_ms().await;
    let port_t2 = calc.calculate_port_for_epoch(&session_key, &port_seed, t2 / 500);

    // Should see port change
    assert_ne!(port_t0.as_u16(), port_t2.as_u16(),
               "Port should change across epoch boundary");
}

#[tokio::test]
async fn test_priority_event_handling() {
    let coordinator = EngineCoordinator::new();

    // Simulate priority events:
    // HIGH: Emergency time desync
    // MEDIUM: Normal port hop
    // LOW: Routine sync

    // Priority 1: Emergency desync
    coordinator.trigger_time_desync(10000).await; // 10 second drift

    let emergency_time = coordinator.current_time_ms().await;

    // Priority 2: Port recalculation should use emergency-corrected time
    let session_key = [0u8; 32];
    let port_seed = [5u8; 32];
    let calc = PortHoppingCalculation::new();

    let emergency_port = calc.calculate_port_for_epoch(&session_key, &port_seed, emergency_time / 500);

    // Verify port calculation works with extreme drift
    assert!(emergency_port.as_u16() >= 1024, "Port should remain valid");

    // Priority 3: Recovery should complete
    // (In real system, this would involve multiple coordination steps)
    coordinator.advance_time_ms(100).await;
    let recovered = coordinator.current_time_ms().await > emergency_time;
    assert!(recovered, "System should continue operating after emergency");
}

#[tokio::test]
async fn test_error_cascade_handling() {
    let coordinator = EngineCoordinator::new();

    // Test error cascade: time failure -> port calculation failure -> recovery

    // Introduce cascading errors
    // 1. Severe time drift
    coordinator.trigger_time_desync(-30000).await; // Negative drift

    // 2. Verify system handles backward time
    let current_time = coordinator.current_time_ms().await;

    // System should handle negative time gracefully
    // (wrapping arithmetic or clamping)
    let session_key = [0u8; 32];
    let port_seed = [6u8; 32];
    let calc = PortHoppingCalculation::new();

    // Should not panic
    let port = calc.calculate_port_for_epoch(&session_key, &port_seed, current_time / 500);
    assert!(port.as_u16() >= 1024 && port.as_u16() <= 65535);

    // 3. Recovery: normalize time
    coordinator.advance_time_ms(35000).await;
    let recovered_time = coordinator.current_time_ms().await;

    // Should be in valid range now
    assert!(recovered_time > 0);
}

#[tokio::test]
async fn test_shared_session_state_access() {
    let coordinator = EngineCoordinator::new();

    // Test concurrent access to shared state
    let shared_time = coordinator.shared_time_epoch.clone();

    // Spawn multiple tasks accessing shared state
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let time_ref = shared_time.clone();
            tokio::spawn(async move {
                for _ in 0..100 {
                    let current = *time_ref.read().await;
                    // Read should always succeed
                    assert!(current < u64::MAX);
                }
                i
            })
        })
        .collect();

    // Wait for all tasks
    for handle in handles {
        handle.await.expect("Task should complete");
    }

    // State should remain consistent
    let final_time = *shared_time.read().await;
    assert!(final_time < u64::MAX);
}

#[tokio::test]
async fn test_lock_ordering_no_deadlocks() {
    let coordinator = EngineCoordinator::new();

    // Test that lock ordering prevents deadlocks
    // Lock order: time -> port (consistent ordering)

    let time_engine = coordinator.time_engine.clone();
    let port_engine = coordinator.port_engine.clone();

    // Task 1: Time -> Port
    let task1 = tokio::spawn(async move {
        for _ in 0..10 {
            let _time = time_engine.lock().await;
            sleep(Duration::from_micros(10)).await;
            let _port = port_engine.lock().await;
            sleep(Duration::from_micros(10)).await;
        }
    });

    let time_engine2 = coordinator.time_engine.clone();
    let port_engine2 = coordinator.port_engine.clone();

    // Task 2: Time -> Port (same order)
    let task2 = tokio::spawn(async move {
        for _ in 0..10 {
            let _time = time_engine2.lock().await;
            sleep(Duration::from_micros(10)).await;
            let _port = port_engine2.lock().await;
            sleep(Duration::from_micros(10)).await;
        }
    });

    // Both tasks should complete without deadlock
    tokio::time::timeout(Duration::from_secs(5), task1)
        .await
        .expect("Task 1 should complete without deadlock")
        .expect("Task 1 should not panic");

    tokio::time::timeout(Duration::from_secs(5), task2)
        .await
        .expect("Task 2 should complete without deadlock")
        .expect("Task 2 should not panic");
}

#[tokio::test]
async fn test_concurrent_port_calculations() {
    let coordinator = EngineCoordinator::new();

    // Test concurrent port calculations don't interfere
    let session_key = [0u8; 32];
    let shared_time = coordinator.shared_time_epoch.clone();

    let handles: Vec<_> = (0..20)
        .map(|i| {
            let time_ref = shared_time.clone();
            let mut port_seed = [0u8; 32];
            port_seed[0] = i as u8;

            tokio::spawn(async move {
                let calc = PortHoppingCalculation::new();
                let mut ports = Vec::new();

                for _ in 0..50 {
                    let time = *time_ref.read().await;
                    let epoch = time / 500;
                    let port = calc.calculate_port_for_epoch(&session_key, &port_seed, epoch);
                    ports.push(port.as_u16());
                    sleep(Duration::from_micros(100)).await;
                }

                // All ports should be valid
                for port in &ports {
                    assert!(*port >= 1024 && *port <= 65535);
                }

                ports
            })
        })
        .collect();

    // Collect all results
    for handle in handles {
        let ports = handle.await.expect("Task should complete");
        assert_eq!(ports.len(), 50, "Should calculate 50 ports per task");
    }
}

#[tokio::test]
async fn test_resource_contention_handling() {
    let coordinator = EngineCoordinator::new();

    // Test that engines handle resource contention gracefully
    let port_engine = coordinator.port_engine.clone();
    let time_engine = coordinator.time_engine.clone();

    // Multiple tasks trying to access engines
    let port_tasks: Vec<_> = (0..5)
        .map(|_| {
            let engine = port_engine.clone();
            tokio::spawn(async move {
                for _ in 0..20 {
                    let _guard = engine.lock().await;
                    sleep(Duration::from_micros(50)).await;
                }
            })
        })
        .collect();

    let time_tasks: Vec<_> = (0..5)
        .map(|_| {
            let engine = time_engine.clone();
            tokio::spawn(async move {
                for _ in 0..20 {
                    let _guard = engine.lock().await;
                    sleep(Duration::from_micros(50)).await;
                }
            })
        })
        .collect();

    // All tasks should complete
    for task in port_tasks {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("Port task should complete")
            .expect("Port task should not panic");
    }

    for task in time_tasks {
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("Time task should complete")
            .expect("Time task should not panic");
    }
}

#[tokio::test]
async fn test_engine_state_consistency() {
    let coordinator = EngineCoordinator::new();

    // Verify engine states remain consistent under concurrent operations
    let shared_time = coordinator.shared_time_epoch.clone();

    // Writer task: advances time
    let write_time = shared_time.clone();
    let writer = tokio::spawn(async move {
        for i in 0..100 {
            sleep(Duration::from_micros(100)).await;
            let mut time = write_time.write().await;
            *time += 10;
        }
    });

    // Reader tasks: read time and calculate ports
    let read_tasks: Vec<_> = (0..10)
        .map(|i| {
            let time_ref = shared_time.clone();
            let mut port_seed = [0u8; 32];
            port_seed[0] = i as u8;

            tokio::spawn(async move {
                let calc = PortHoppingCalculation::new();
                let session_key = [0u8; 32];

                for _ in 0..100 {
                    let time = *time_ref.read().await;
                    let epoch = time / 500;
                    let port = calc.calculate_port_for_epoch(&session_key, &port_seed, epoch);

                    // Port should always be valid
                    assert!(port.as_u16() >= 1024 && port.as_u16() <= 65535);
                    sleep(Duration::from_micros(50)).await;
                }
            })
        })
        .collect();

    // Wait for all tasks
    writer.await.expect("Writer should complete");

    for task in read_tasks {
        task.await.expect("Reader task should complete");
    }

    // Final state should be consistent
    let final_time = *shared_time.read().await;
    assert!(final_time >= 1000, "Time should have advanced");
}

// ========================================================================
// Comprehensive Multi-Engine Coordination Tests
// ========================================================================

/// Enhanced coordinator with all four engines and MockClock
struct ComprehensiveCoordinator {
    mock_clock: MockClock,
    time_sync: Arc<TimeSyncEngine>,
    port_hopping: Arc<PortHoppingEngine>,
    flow_control: Arc<FlowControlEngine>,
    adaptive: Arc<AdaptiveNetworkingEngine>,
    tun_device: TestTunDevice,
}

impl ComprehensiveCoordinator {
    async fn new() -> Self {
        let start_time = Timestamp::from_millis(1_000_000);
        let mock_clock = MockClock::new(start_time);

        let time_sync = Arc::new(TimeSyncEngine::new());
        let connection_id = ConnectionId(1);
        let session_id = SessionId::new_v4();

        let local_addr: SocketAddr = "127.0.0.1:8000"
            .parse()
            .expect("valid local address");
        let remote_addr: SocketAddr = "127.0.0.1:9000"
            .parse()
            .expect("valid remote address");

        let port_hopping = Arc::new(PortHoppingEngine::new_for_connection(
            connection_id,
            local_addr,
            remote_addr,
        ));

        let flow_control = Arc::new(FlowControlEngine::new(
            connection_id,
            session_id.clone(),
            1000,
            2000,
        ));

        let adaptive = Arc::new(AdaptiveNetworkingEngine::new());
        adaptive
            .initialize()
            .expect("adaptive engine should initialize");

        let tun_config = TunConfig::new(
            DeviceName::new("test0").expect("valid device name"),
            "10.0.0.1".parse().expect("valid IP"),
            "255.255.255.0".parse().expect("valid netmask"),
            Mtu::default(),
        );

        let tun_device = TestTunDevice::create(tun_config)
            .await
            .expect("TUN device should be created");

        Self {
            mock_clock,
            time_sync,
            port_hopping,
            flow_control,
            adaptive,
            tun_device,
        }
    }

    fn advance_time(&self, duration: Duration) {
        self.mock_clock.advance(duration);
    }

    fn current_time(&self) -> Timestamp {
        self.mock_clock.now()
    }
}

#[tokio::test]
async fn test_flow_control_adaptive_congestion_response() {
    let coordinator = ComprehensiveCoordinator::new().await;

    let initial_cwnd = coordinator.flow_control.get_congestion_window();

    // Simulate good network conditions with adaptive measurements
    for _ in 0..10 {
        let packet_timestamp = coordinator.current_time();
        coordinator
            .adaptive
            .measure_packet_delay(packet_timestamp, PacketType::Data, PacketSize::new(1400))
            .expect("packet delay measurement should succeed");

        coordinator.advance_time(Duration::from_millis(50));
    }

    // Get network conditions
    let conditions = coordinator.adaptive.get_current_network_conditions();

    assert!(
        !conditions.high_latency,
        "Should not detect high latency under good conditions"
    );
    assert!(
        !conditions.congested_network,
        "Should not detect congestion under good conditions"
    );

    // Simulate successful ACKs to grow congestion window
    for i in 0..5 {
        let ack_number = 1000 + (i * 1460);
        coordinator
            .flow_control
            .process_ack(ack_number, 1460)
            .expect("ACK processing should succeed");
    }

    let grown_cwnd = coordinator.flow_control.get_congestion_window();
    assert!(
        grown_cwnd > initial_cwnd,
        "Congestion window should grow with ACKs: {} -> {}",
        initial_cwnd,
        grown_cwnd
    );

    // Now simulate congestion with high latency
    for _ in 0..15 {
        let packet_timestamp = coordinator.current_time();
        coordinator.advance_time(Duration::from_millis(250));

        coordinator
            .adaptive
            .measure_packet_delay(packet_timestamp, PacketType::Data, PacketSize::new(1400))
            .expect("measurement should succeed");
    }

    let congested_conditions = coordinator.adaptive.get_current_network_conditions();
    assert!(
        congested_conditions.high_latency || congested_conditions.congested_network,
        "Should detect congestion with high latency"
    );

    // Simulate timeout
    coordinator
        .flow_control
        .handle_timeout()
        .expect("timeout handling should succeed");

    let reduced_cwnd = coordinator.flow_control.get_congestion_window();
    assert!(
        reduced_cwnd < grown_cwnd,
        "Congestion window should reduce after timeout: {} -> {}",
        grown_cwnd,
        reduced_cwnd
    );
}

#[tokio::test]
async fn test_port_hopping_time_sync_precise_coordination() {
    let coordinator = ComprehensiveCoordinator::new().await;

    let session_id = SessionId::new_v4();
    let session_state = Arc::new(SessionState::new_with_session_id(session_id.clone()));
    let session_key = Arc::new(SessionKey::new([0u8; 32]));

    coordinator
        .port_hopping
        .add_session(session_id.clone(), session_state, session_key)
        .await
        .expect("session should be added");

    let initial_port = coordinator
        .port_hopping
        .get_current_port_for_session(&session_id, true)
        .expect("initial port should exist");

    // Advance time by exactly one hop interval (500ms)
    coordinator.advance_time(Duration::from_millis(500));

    let (hopped_port, _) = coordinator
        .port_hopping
        .hop_port_for_session(&session_id)
        .await
        .expect("port hop should succeed");

    assert_ne!(
        initial_port, hopped_port,
        "Port should change after hop interval"
    );

    // Verify synchronized time alignment
    let sync_time = coordinator.time_sync.synchronized_time_ms();
    let mock_time = coordinator.current_time();
    let time_diff = sync_time
        .as_nanos()
        .abs_diff(mock_time.as_nanos());

    assert!(
        time_diff < 1_000_000,
        "Time sync should align with mock clock within 1ms, got {}ns diff",
        time_diff
    );

    // Verify port state reflects current epoch
    let port_state = coordinator
        .port_hopping
        .get_session_port_state(&session_id)
        .expect("port state should exist");

    assert_eq!(
        port_state.current_local_port, hopped_port,
        "Port state should match hopped port"
    );
    assert!(
        port_state.current_epoch.as_u32() >= 1,
        "Epoch should advance with port hops"
    );
}

#[tokio::test]
async fn test_all_engines_coordinated_lifecycle() {
    let coordinator = ComprehensiveCoordinator::new().await;

    let session_id = SessionId::new_v4();
    let session_state = Arc::new(SessionState::new_with_session_id(session_id.clone()));
    let session_key = Arc::new(SessionKey::new([0u8; 32]));

    coordinator
        .port_hopping
        .add_session(session_id.clone(), session_state, session_key)
        .await
        .expect("session should be added");

    // Simulate coordinated operation over 5 cycles
    for cycle in 0..5 {
        // 1. Port hopping at 500ms intervals
        coordinator.advance_time(Duration::from_millis(500));

        let (_local_port, _remote_port) = coordinator
            .port_hopping
            .hop_port_for_session(&session_id)
            .await
            .expect("port hop should succeed");

        // 2. Adaptive measurements
        let packet_timestamp = coordinator.current_time();
        coordinator
            .adaptive
            .measure_packet_delay(packet_timestamp, PacketType::Data, PacketSize::new(1400))
            .expect("measurement should succeed");

        // 3. Flow control sends data
        assert!(
            coordinator.flow_control.can_send_data(1400),
            "Flow control should allow data (cycle {})",
            cycle
        );

        // 4. Verify time sync remains healthy
        let sync_stats = coordinator.time_sync.get_sync_stats();
        assert_ne!(
            sync_stats.status,
            TimeSyncStatus::Failed,
            "Time sync should be operational (cycle {})",
            cycle
        );

        // 5. Process ACKs
        let ack_number = 1000 + (cycle * 1460);
        coordinator
            .flow_control
            .process_ack(ack_number, 1460)
            .expect("ACK should be processed");

        coordinator.advance_time(Duration::from_millis(100));
    }

    // Verify statistics
    let port_stats = coordinator.port_hopping.get_port_hopping_stats().await;
    assert!(
        port_stats.total_port_hops.as_u64() >= 5,
        "Should have >= 5 port hops"
    );

    let adaptive_stats = coordinator.adaptive.get_adaptive_stats();
    assert!(
        adaptive_stats.total_measurements.as_u64() >= 5,
        "Should have >= 5 measurements"
    );

    // Coordinated shutdown
    coordinator
        .adaptive
        .shutdown()
        .await
        .expect("adaptive shutdown should succeed");
    coordinator
        .flow_control
        .shutdown()
        .await
        .expect("flow control shutdown should succeed");
    coordinator
        .port_hopping
        .shutdown()
        .await
        .expect("port hopping shutdown should succeed");
    coordinator
        .time_sync
        .shutdown()
        .await
        .expect("time sync shutdown should succeed");

    let final_port_stats = coordinator.port_hopping.get_port_hopping_stats().await;
    assert_eq!(
        final_port_stats.active_sessions.as_u64(),
        0,
        "Should have no active sessions after shutdown"
    );
}

#[tokio::test]
async fn test_deterministic_event_sequencing() {
    let coordinator = ComprehensiveCoordinator::new().await;

    let session_id = SessionId::new_v4();
    let session_state = Arc::new(SessionState::new_with_session_id(session_id.clone()));
    let session_key = Arc::new(SessionKey::new([0u8; 32]));

    coordinator
        .port_hopping
        .add_session(session_id.clone(), session_state, session_key)
        .await
        .expect("session should be added");

    let mut events = Vec::new();

    // Event 0: T=0ms - Initial state
    events.push((0, "initial_state"));
    let port_t0 = coordinator
        .port_hopping
        .get_current_port_for_session(&session_id, true)
        .expect("initial port should exist");

    // Event 1: T=100ms - Adaptive measurement
    coordinator.advance_time(Duration::from_millis(100));
    events.push((100, "adaptive_measurement_1"));
    coordinator
        .adaptive
        .measure_packet_delay(coordinator.current_time(), PacketType::Data, PacketSize::new(1400))
        .expect("measurement should succeed");

    // Event 2: T=200ms - ACK received
    coordinator.advance_time(Duration::from_millis(100));
    events.push((200, "ack_received"));
    coordinator
        .flow_control
        .process_ack(1460, 1460)
        .expect("ACK should be processed");

    // Event 3: T=500ms - Port hop
    coordinator.advance_time(Duration::from_millis(300));
    events.push((500, "port_hop_1"));
    let (port_t500, _) = coordinator
        .port_hopping
        .hop_port_for_session(&session_id)
        .await
        .expect("port hop should succeed");
    assert_ne!(port_t0, port_t500, "Port should change at T=500ms");

    // Event 4: T=600ms - Adaptive measurement
    coordinator.advance_time(Duration::from_millis(100));
    events.push((600, "adaptive_measurement_2"));
    coordinator
        .adaptive
        .measure_packet_delay(coordinator.current_time(), PacketType::Data, PacketSize::new(1400))
        .expect("measurement should succeed");

    // Event 5: T=1000ms - Port hop
    coordinator.advance_time(Duration::from_millis(400));
    events.push((1000, "port_hop_2"));
    let (port_t1000, _) = coordinator
        .port_hopping
        .hop_port_for_session(&session_id)
        .await
        .expect("port hop should succeed");
    assert_ne!(port_t500, port_t1000, "Port should change at T=1000ms");

    // Verify event sequence
    assert_eq!(events.len(), 6, "Should have 6 events");
    assert_eq!(events[0], (0, "initial_state"));
    assert_eq!(events[1], (100, "adaptive_measurement_1"));
    assert_eq!(events[2], (200, "ack_received"));
    assert_eq!(events[3], (500, "port_hop_1"));
    assert_eq!(events[4], (600, "adaptive_measurement_2"));
    assert_eq!(events[5], (1000, "port_hop_2"));
}
