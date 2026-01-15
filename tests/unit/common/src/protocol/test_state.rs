use buckwild_common::protocol::state::*;
use crate::protocol::packet::{PacketBuilderEngine, SessionId};

    #[test]
    fn test_state_manager_creation() {
        let manager = ProtocolStateManager::new();
        let stats = manager.get_stats();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.active_sessions, 0);
    }

    #[test]
    fn test_connection_establishment() {
        let manager = ProtocolStateManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let builder_engine = PacketBuilderEngine::new();

        // SYN packet (local)
        let syn_packet = builder_engine.syn()
            .session_id(session_id)
            .sequence_number(100)
            .build()
            .unwrap();

        let request = StateTransitionRequest {
            session_id,
            packet: syn_packet,
            is_local: true,
        };

        let result = manager.process_transition(request).unwrap();
        match result {
            StateTransitionResult::Success { old_state, new_state } => {
                assert_eq!(old_state, ConnectionStateType::Closed);
                assert_eq!(new_state, ConnectionStateType::SynSent);
            }
            _ => panic!("Expected successful transition"),
        }

        // Check connection state
        let conn_state = manager.get_connection_state(session_id).unwrap();
        assert_eq!(conn_state.state, ConnectionStateType::SynSent);
        assert_eq!(conn_state.local_sequence, 100);
    }

    #[test]
    fn test_full_connection_lifecycle() {
        let manager = ProtocolStateManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let builder_engine = PacketBuilderEngine::new();

        // 1. SYN (local -> remote)
        let syn_packet = builder_engine.syn()
            .session_id(session_id)
            .sequence_number(100)
            .build()
            .unwrap();

        let result = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: syn_packet,
            is_local: true,
        }).unwrap();

        assert!(matches!(result, StateTransitionResult::Success { 
            old_state: ConnectionStateType::Closed, 
            new_state: ConnectionStateType::SynSent 
        }));

        // 2. SYN-ACK (remote -> local)
        let syn_ack_packet = builder_engine.syn_ack()
            .session_id(session_id)
            .sequence_number(200)
            .ack_number(101)
            .build()
            .unwrap();

        let result = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: syn_ack_packet,
            is_local: false,
        }).unwrap();

        assert!(matches!(result, StateTransitionResult::Success { 
            old_state: ConnectionStateType::SynSent, 
            new_state: ConnectionStateType::Established 
        }));

        // 3. Data transfer
        let data_packet = builder_engine.data()
            .session_id(session_id)
            .sequence_number(101)
            .payload_string("Hello")
            .build()
            .unwrap();

        let result = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: data_packet,
            is_local: true,
        }).unwrap();

        assert!(matches!(result, StateTransitionResult::Success { 
            old_state: ConnectionStateType::Established, 
            new_state: ConnectionStateType::Established 
        }));

        // 4. FIN (local -> remote)
        let fin_packet = builder_engine.fin()
            .session_id(session_id)
            .sequence_number(106)
            .build()
            .unwrap();

        let result = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: fin_packet,
            is_local: true,
        }).unwrap();

        assert!(matches!(result, StateTransitionResult::Success { 
            old_state: ConnectionStateType::Established, 
            new_state: ConnectionStateType::FinWait1 
        }));

        // Check final connection state
        let conn_state = manager.get_connection_state(session_id).unwrap();
        assert_eq!(conn_state.state, ConnectionStateType::FinWait1);
    }

    #[test]
    fn test_invalid_transition() {
        let manager = ProtocolStateManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let builder_engine = PacketBuilderEngine::new();

        // Try to send data without establishing connection
        let data_packet = builder_engine.data()
            .session_id(session_id)
            .sequence_number(100)
            .payload_string("Invalid")
            .build()
            .unwrap();

        let result = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: data_packet,
            is_local: true,
        }).unwrap();

        match result {
            StateTransitionResult::InvalidTransition { current_state, attempted_packet_type, .. } => {
                assert_eq!(current_state, ConnectionStateType::Closed);
                assert_eq!(attempted_packet_type, PacketType::Data);
            }
            _ => panic!("Expected invalid transition"),
        }

        let stats = manager.get_stats();
        assert_eq!(stats.invalid_transitions, 1);
    }

    #[test]
    fn test_session_metrics_update() {
        let manager = ProtocolStateManager::new();
        let session_id = SessionId::Bits32(0x12345678);

        // Update metrics
        manager.update_session_metrics(session_id, |metrics| {
            metrics.packets_sent += 1;
            metrics.bytes_sent += 100;
        });

        let session_state = manager.get_session_state(session_id).unwrap();
        assert_eq!(session_state.metrics.packets_sent, 1);
        assert_eq!(session_state.metrics.bytes_sent, 100);
    }

    #[test]
    fn test_state_cleanup() {
        let mut config = StateConfig::default();
        config.connection_timeout_sec = 1; // Very short timeout
        
        let manager = ProtocolStateManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let builder_engine = PacketBuilderEngine::new();

        // Create a connection
        let syn_packet = builder_engine.syn()
            .session_id(session_id)
            .sequence_number(100)
            .build()
            .unwrap();

        let _ = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: syn_packet,
            is_local: true,
        }).unwrap();

        let stats_before = manager.get_stats();
        assert_eq!(stats_before.active_connections, 1);

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Cleanup
        manager.cleanup_expired_states();

        let stats_after = manager.get_stats();
        assert_eq!(stats_after.active_connections, 0);
        assert!(stats_after.expired_connections > 0);
    }

    #[test]
    fn test_reset_connection() {
        let manager = ProtocolStateManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let builder_engine = PacketBuilderEngine::new();

        // Establish connection first
        let syn_packet = builder_engine.syn()
            .session_id(session_id)
            .sequence_number(100)
            .build()
            .unwrap();

        let _ = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: syn_packet,
            is_local: true,
        }).unwrap();

        // Send RST packet
        let rst_packet = builder_engine.rst()
            .session_id(session_id)
            .sequence_number(101)
            .build()
            .unwrap();

        let result = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: rst_packet,
            is_local: true,
        }).unwrap();

        assert!(matches!(result, StateTransitionResult::Success { 
            old_state: ConnectionStateType::SynSent, 
            new_state: ConnectionStateType::Closed 
        }));
    }

    #[test]
    fn test_statistics_reset() {
        let manager = ProtocolStateManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let builder_engine = PacketBuilderEngine::new();

        // Generate some statistics
        let syn_packet = builder_engine.syn()
            .session_id(session_id)
            .sequence_number(100)
            .build()
            .unwrap();

        let _ = manager.process_transition(StateTransitionRequest {
            session_id,
            packet: syn_packet,
            is_local: true,
        }).unwrap();

        let stats_before = manager.get_stats();
        assert_eq!(stats_before.total_transitions, 1);
        assert_eq!(stats_before.active_connections, 1);

        // Reset statistics
        manager.reset_stats();

        let stats_after = manager.get_stats();
        assert_eq!(stats_after.total_transitions, 0);
        assert_eq!(stats_after.active_connections, 1); // Should remain
    }
