// Test suite for resource cleanup functions - TASK-059
//
// Tests verify all cleanup functions properly release resources:
// - Session keys are securely zeroed
// - Port bindings are released
// - Sequence state is cleared
// - Replay caches are purged
// - Timers are cancelled
// - Buffers are freed

use buckwild_common::connection::cleanup::{
    cleanup_buffers, cleanup_port_bindings, cleanup_replay_cache, cleanup_sequence_state,
    cleanup_session_keys, cleanup_timers, CleanupContext, PacketBuffer, PortBinding,
    ReplayCacheEntry, SequenceState, SessionKeyState, TimerHandle,
};
use buckwild_common::protocol::types::{Port, SequenceNumber, SessionId, Timestamp};
use std::collections::HashMap;

#[tokio::test]
async fn test_cleanup_session_keys_zeros_single_key() {
    // Create single session key
    let mut session_keys = HashMap::new();
    let session_id = SessionId::from_raw(1);
    let key = buckwild_common::protocol::types::SessionKey::new([0x42; 32]);
    session_keys.insert(session_id.clone(), SessionKeyState::new(key));

    // Verify initial state
    assert_eq!(session_keys.len(), 1);
    assert!(!session_keys.get(&session_id).unwrap().is_zeroed());

    // Cleanup
    let count = cleanup_session_keys(&mut session_keys).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 1, "Should zero 1 key");
    assert_eq!(session_keys.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_session_keys_zeros_multiple_keys() {
    // Create multiple session keys
    let mut session_keys = HashMap::new();
    for i in 1..=5 {
        let session_id = SessionId::from_raw(i);
        let key = buckwild_common::protocol::types::SessionKey::new([i as u8; 32]);
        session_keys.insert(session_id, SessionKeyState::new(key));
    }

    // Verify initial state
    assert_eq!(session_keys.len(), 5);

    // Cleanup
    let count = cleanup_session_keys(&mut session_keys).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 5, "Should zero 5 keys");
    assert_eq!(session_keys.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_session_keys_empty_map() {
    // Empty map
    let mut session_keys = HashMap::new();

    // Cleanup
    let count = cleanup_session_keys(&mut session_keys).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 0, "Should zero 0 keys");
}

#[tokio::test]
async fn test_cleanup_port_bindings_releases_single_port() {
    // Create single port binding
    let mut port_bindings = HashMap::new();
    let port = Port::from_raw(8080);
    port_bindings.insert(
        port,
        PortBinding {
            port,
            active: true,
            socket_fd: None,
        },
    );

    // Verify initial state
    assert_eq!(port_bindings.len(), 1);
    assert!(port_bindings.get(&port).unwrap().active);

    // Cleanup
    let count = cleanup_port_bindings(&mut port_bindings).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 1, "Should release 1 port");
    assert_eq!(port_bindings.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_port_bindings_releases_multiple_ports() {
    // Create multiple port bindings
    let mut port_bindings = HashMap::new();
    for port_num in 8080..8085 {
        let port = Port::from_raw(port_num);
        port_bindings.insert(
            port,
            PortBinding {
                port,
                active: true,
                socket_fd: None,
            },
        );
    }

    // Verify initial state
    assert_eq!(port_bindings.len(), 5);

    // Cleanup
    let count = cleanup_port_bindings(&mut port_bindings).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 5, "Should release 5 ports");
    assert_eq!(port_bindings.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_port_bindings_skips_inactive_bindings() {
    // Create mix of active and inactive bindings
    let mut port_bindings = HashMap::new();

    let port1 = Port::from_raw(8080);
    port_bindings.insert(
        port1,
        PortBinding {
            port: port1,
            active: true,
            socket_fd: None,
        },
    );

    let port2 = Port::from_raw(8081);
    port_bindings.insert(
        port2,
        PortBinding {
            port: port2,
            active: false,
            socket_fd: None,
        },
    );

    // Cleanup
    let count = cleanup_port_bindings(&mut port_bindings).await.unwrap();

    // Verify cleanup (both removed from map, but only 1 was active)
    assert_eq!(count, 1, "Should release 1 active port");
    assert_eq!(port_bindings.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_sequence_state_clears_single_state() {
    // Create single sequence state
    let mut sequence_states = HashMap::new();
    let session_id = SessionId::from_raw(1);
    sequence_states.insert(
        session_id.clone(),
        SequenceState {
            send_seq: SequenceNumber::new(100),
            recv_seq: SequenceNumber::new(200),
            last_ack: SequenceNumber::new(150),
        },
    );

    // Verify initial state
    assert_eq!(sequence_states.len(), 1);
    let state = sequence_states.get(&session_id).unwrap();
    assert_eq!(state.send_seq.as_u32(), 100);
    assert_eq!(state.recv_seq.as_u32(), 200);
    assert_eq!(state.last_ack.as_u32(), 150);

    // Cleanup
    let count = cleanup_sequence_state(&mut sequence_states).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 1, "Should clear 1 state");
    assert_eq!(sequence_states.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_sequence_state_clears_multiple_states() {
    // Create multiple sequence states
    let mut sequence_states = HashMap::new();
    for i in 1..=5 {
        let session_id = SessionId::from_raw(i);
        sequence_states.insert(
            session_id,
            SequenceState {
                send_seq: SequenceNumber::new(i as u32 * 100),
                recv_seq: SequenceNumber::new(i as u32 * 200),
                last_ack: SequenceNumber::new(i as u32 * 150),
            },
        );
    }

    // Verify initial state
    assert_eq!(sequence_states.len(), 5);

    // Cleanup
    let count = cleanup_sequence_state(&mut sequence_states).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 5, "Should clear 5 states");
    assert_eq!(sequence_states.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_replay_cache_purges_single_session() {
    // Create replay cache with single session
    let mut replay_cache = HashMap::new();
    let session_id = SessionId::from_raw(1);
    replay_cache.insert(
        session_id.clone(),
        vec![
            ReplayCacheEntry {
                timestamp: Timestamp::now(),
                sequence: SequenceNumber::new(1),
                session_id: session_id.clone(),
            },
            ReplayCacheEntry {
                timestamp: Timestamp::now(),
                sequence: SequenceNumber::new(2),
                session_id: session_id.clone(),
            },
        ],
    );

    // Verify initial state
    assert_eq!(replay_cache.len(), 1);
    assert_eq!(replay_cache.get(&session_id).unwrap().len(), 2);

    // Cleanup
    let count = cleanup_replay_cache(&mut replay_cache).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 2, "Should purge 2 entries");
    assert_eq!(replay_cache.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_replay_cache_purges_multiple_sessions() {
    // Create replay cache with multiple sessions
    let mut replay_cache = HashMap::new();
    for i in 1..=3 {
        let session_id = SessionId::from_raw(i);
        replay_cache.insert(
            session_id.clone(),
            vec![
                ReplayCacheEntry {
                    timestamp: Timestamp::now(),
                    sequence: SequenceNumber::new(i as u32 * 10 + 1),
                    session_id: session_id.clone(),
                },
                ReplayCacheEntry {
                    timestamp: Timestamp::now(),
                    sequence: SequenceNumber::new(i as u32 * 10 + 2),
                    session_id: session_id.clone(),
                },
            ],
        );
    }

    // Verify initial state
    assert_eq!(replay_cache.len(), 3);

    // Cleanup
    let count = cleanup_replay_cache(&mut replay_cache).await.unwrap();

    // Verify cleanup (3 sessions × 2 entries = 6 total)
    assert_eq!(count, 6, "Should purge 6 entries");
    assert_eq!(replay_cache.len(), 0, "Map should be empty");
}

#[tokio::test]
async fn test_cleanup_replay_cache_empty_cache() {
    // Empty cache
    let mut replay_cache = HashMap::new();

    // Cleanup
    let count = cleanup_replay_cache(&mut replay_cache).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 0, "Should purge 0 entries");
}

#[tokio::test]
async fn test_cleanup_timers_cancels_single_timer() {
    // Create single timer
    let mut timers = Vec::new();
    let handle = tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    });
    timers.push(TimerHandle::new(handle, "test_timer".to_string()));

    // Verify initial state
    assert_eq!(timers.len(), 1);

    // Cleanup
    let count = cleanup_timers(&mut timers).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 1, "Should cancel 1 timer");
    assert_eq!(timers.len(), 0, "Vector should be empty");
}

#[tokio::test]
async fn test_cleanup_timers_cancels_multiple_timers() {
    // Create multiple timers
    let mut timers = Vec::new();
    for i in 1..=5 {
        let handle = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        });
        timers.push(TimerHandle::new(handle, format!("timer_{}", i)));
    }

    // Verify initial state
    assert_eq!(timers.len(), 5);

    // Cleanup
    let count = cleanup_timers(&mut timers).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 5, "Should cancel 5 timers");
    assert_eq!(timers.len(), 0, "Vector should be empty");
}

#[tokio::test]
async fn test_cleanup_timers_empty_vec() {
    // Empty vector
    let mut timers = Vec::new();

    // Cleanup
    let count = cleanup_timers(&mut timers).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 0, "Should cancel 0 timers");
}

#[tokio::test]
async fn test_cleanup_buffers_frees_single_buffer() {
    // Create single buffer
    let mut buffers = Vec::new();
    let mut buffer = PacketBuffer::new(1500);
    buffer.allocate(100).unwrap();
    buffers.push(buffer);

    // Verify initial state
    assert_eq!(buffers.len(), 1);
    assert!(buffers[0].is_in_use());

    // Cleanup
    let count = cleanup_buffers(&mut buffers).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 1, "Should free 1 buffer");
    assert_eq!(buffers.len(), 0, "Vector should be empty");
}

#[tokio::test]
async fn test_cleanup_buffers_frees_multiple_buffers() {
    // Create multiple buffers
    let mut buffers = Vec::new();
    for i in 1..=5 {
        let mut buffer = PacketBuffer::new(1500);
        buffer.allocate(100 * i).unwrap();
        buffers.push(buffer);
    }

    // Verify initial state
    assert_eq!(buffers.len(), 5);
    for buffer in &buffers {
        assert!(buffer.is_in_use());
    }

    // Cleanup
    let count = cleanup_buffers(&mut buffers).await.unwrap();

    // Verify cleanup
    assert_eq!(count, 5, "Should free 5 buffers");
    assert_eq!(buffers.len(), 0, "Vector should be empty");
}

#[tokio::test]
async fn test_cleanup_buffers_handles_unused_buffers() {
    // Create mix of used and unused buffers
    let mut buffers = Vec::new();

    let mut buffer1 = PacketBuffer::new(1500);
    buffer1.allocate(100).unwrap();
    buffers.push(buffer1);

    let buffer2 = PacketBuffer::new(1500); // Not allocated
    buffers.push(buffer2);

    // Verify initial state
    assert_eq!(buffers.len(), 2);

    // Cleanup
    let count = cleanup_buffers(&mut buffers).await.unwrap();

    // Verify cleanup (both cleared, only 1 was in use)
    assert_eq!(count, 2, "Should clear 2 buffers total");
    assert_eq!(buffers.len(), 0, "Vector should be empty");
}

#[tokio::test]
async fn test_cleanup_context_cleanup_all() {
    // Create cleanup context
    let context = CleanupContext::new();

    // Add test data to each resource type
    let session_id = SessionId::from_raw(1);

    // Add session key
    let key = buckwild_common::protocol::types::SessionKey::new([0x42; 32]);
    context
        .session_keys
        .write()
        .await
        .insert(session_id.clone(), SessionKeyState::new(key));

    // Add port binding
    let port = Port::from_raw(8080);
    context.port_bindings.write().await.insert(
        port,
        PortBinding {
            port,
            active: true,
            socket_fd: None,
        },
    );

    // Add sequence state
    context.sequence_states.write().await.insert(
        session_id.clone(),
        SequenceState {
            send_seq: SequenceNumber::new(100),
            recv_seq: SequenceNumber::new(200),
            last_ack: SequenceNumber::new(150),
        },
    );

    // Add replay cache
    context.replay_cache.write().await.insert(
        session_id.clone(),
        vec![ReplayCacheEntry {
            timestamp: Timestamp::now(),
            sequence: SequenceNumber::new(1),
            session_id: session_id.clone(),
        }],
    );

    // Add timer
    let handle = tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    });
    context
        .timers
        .write()
        .await
        .push(TimerHandle::new(handle, "test_timer".to_string()));

    // Add buffer
    let mut buffer = PacketBuffer::new(1500);
    buffer.allocate(100).unwrap();
    context.buffers.write().await.push(buffer);

    // Perform cleanup
    let stats = context.cleanup_all().await.unwrap();

    // Verify stats
    assert_eq!(stats.keys_zeroed, 1, "Should zero 1 key");
    assert_eq!(stats.ports_released, 1, "Should release 1 port");
    assert_eq!(stats.states_cleared, 1, "Should clear 1 state");
    assert_eq!(stats.cache_entries_purged, 1, "Should purge 1 cache entry");
    assert_eq!(stats.timers_cancelled, 1, "Should cancel 1 timer");
    assert_eq!(stats.buffers_freed, 1, "Should free 1 buffer");

    // Verify all maps/vectors are empty
    assert_eq!(context.session_keys.read().await.len(), 0);
    assert_eq!(context.port_bindings.read().await.len(), 0);
    assert_eq!(context.sequence_states.read().await.len(), 0);
    assert_eq!(context.replay_cache.read().await.len(), 0);
    assert_eq!(context.timers.read().await.len(), 0);
    assert_eq!(context.buffers.read().await.len(), 0);
}

#[tokio::test]
async fn test_cleanup_context_empty_context() {
    // Create empty cleanup context
    let context = CleanupContext::new();

    // Perform cleanup
    let stats = context.cleanup_all().await.unwrap();

    // Verify stats (all zeros)
    assert_eq!(stats.keys_zeroed, 0);
    assert_eq!(stats.ports_released, 0);
    assert_eq!(stats.states_cleared, 0);
    assert_eq!(stats.cache_entries_purged, 0);
    assert_eq!(stats.timers_cancelled, 0);
    assert_eq!(stats.buffers_freed, 0);
}

#[tokio::test]
async fn test_packet_buffer_allocation_and_free() {
    // Create buffer
    let mut buffer = PacketBuffer::new(1500);

    // Verify initial state
    assert!(!buffer.is_in_use());
    assert_eq!(buffer.capacity(), 1500);

    // Allocate
    buffer.allocate(100).unwrap();
    assert!(buffer.is_in_use());

    // Free
    buffer.free();
    assert!(!buffer.is_in_use());
}

#[tokio::test]
async fn test_packet_buffer_prevents_double_allocation() {
    // Create and allocate buffer
    let mut buffer = PacketBuffer::new(1500);
    buffer.allocate(100).unwrap();

    // Attempt second allocation
    let result = buffer.allocate(200);
    assert!(result.is_err(), "Should prevent double allocation");
}

#[tokio::test]
async fn test_packet_buffer_rejects_oversized_allocation() {
    // Create buffer
    let mut buffer = PacketBuffer::new(1500);

    // Attempt oversized allocation
    let result = buffer.allocate(2000);
    assert!(result.is_err(), "Should reject oversized allocation");
}

#[test]
fn test_session_key_state_zeroing_warning() {
    // This test verifies that dropping SessionKeyState without zeroing triggers a warning
    // We can't easily test the warning itself, but we can verify the is_zeroed flag works

    let key = buckwild_common::protocol::types::SessionKey::new([0x42; 32]);
    let key_state = SessionKeyState::new(key);

    assert!(!key_state.is_zeroed(), "New key should not be zeroed");
    assert!(key_state.key().is_some(), "Should be able to access key");

    // Drop will trigger warning (visible in test output)
    drop(key_state);
}

#[tokio::test]
async fn test_sequence_state_reset() {
    // Create sequence state with non-zero values
    let mut state = SequenceState {
        send_seq: SequenceNumber::new(100),
        recv_seq: SequenceNumber::new(200),
        last_ack: SequenceNumber::new(150),
    };

    // Verify initial values
    assert_eq!(state.send_seq.as_u32(), 100);
    assert_eq!(state.recv_seq.as_u32(), 200);
    assert_eq!(state.last_ack.as_u32(), 150);

    // Reset
    state.reset();

    // Verify reset
    assert_eq!(state.send_seq.as_u32(), 0);
    assert_eq!(state.recv_seq.as_u32(), 0);
    assert_eq!(state.last_ack.as_u32(), 0);
}
