use buckwild_common::protocol::port_hopping::*;
use crate::time_sync::state::create_shared_time_sync_state;
    
    #[test]
    fn test_derive_port_hopping_params() {
        let shared_secret = b"test_shared_secret_for_port_hopping_params";
        let client_pubkey = b"client_public_key_test";
        let server_pubkey = b"server_public_key_test";
        let session_id = 0x1234567890ABCDEF;
        
        let params = PortHoppingEngine::derive_port_hopping_params(
            shared_secret,
            client_pubkey,
            server_pubkey,
            session_id,
        );
        
        // Verify parameters are derived correctly
        assert_ne!(params.port_seed, 0);
        assert_ne!(params.hop_sequence_seed, 0);
        assert!(params.time_variance <= 100);
    }
    
    #[tokio::test]
    async fn test_port_calculation() {
        let time_sync_state = create_shared_time_sync_state();
        let time_sync = Arc::new(TimeSyncEngine::new());
        let engine = PortHoppingEngine::new(time_sync.clone());
        
        // Create a test daily key
        let psk = b"test_psk_for_port_calculation";
        let daily_key = engine.derive_daily_key(psk, "2023-01-01");
        
        // Calculate base port
        let base_port = engine.calculate_base_port(&daily_key, 100);
        assert!(base_port >= MIN_PORT);
        assert!(base_port <= MAX_PORT);
        
        // Calculate session port
        let params = PortHoppingParams {
            port_seed: 0x12345678,
            hop_sequence_seed: 0x87654321,
            time_variance: 50,
            hop_pattern_seed: 0xABCD,
            session_id: 0x1234567890ABCDEF,
        };
        
        let session_port = engine.calculate_session_port(&params, 200);
        assert!(session_port >= MIN_PORT);
        assert!(session_port <= MAX_PORT);
        
        // Verify port calculation is deterministic
        let base_port2 = engine.calculate_base_port(&daily_key, 100);
        assert_eq!(base_port, base_port2);
        
        let session_port2 = engine.calculate_session_port(&params, 200);
        assert_eq!(session_port, session_port2);
        
        // Verify different time windows produce different ports
        let session_port3 = engine.calculate_session_port(&params, 201);
        assert_ne!(session_port, session_port3);
    }
    
    #[tokio::test]
    async fn test_port_binding() {
        let time_sync = Arc::new(TimeSyncEngine::new());
        let mut engine = PortHoppingEngine::new(time_sync.clone());
        
        // Set up mock callbacks
        let bound_ports = Arc::new(Mutex::new(HashSet::new()));
        let bound_ports_clone = bound_ports.clone();
        
        engine.set_bind_port_callback(move |port| {
            bound_ports_clone.lock().insert(port);
            true
        });
        
        let bound_ports_clone = bound_ports.clone();
        engine.set_unbind_port_callback(move |port| {
            bound_ports_clone.lock().remove(&port);
            true
        });
        
        // Bind to a port
        let result = engine.bind_to_port(8000);
        assert!(result.is_ok());
        assert!(bound_ports.lock().contains(&8000));
        
        // Unbind from a port
        let result = engine.unbind_from_port(8000);
        assert!(result.is_ok());
        assert!(!bound_ports.lock().contains(&8000));
    }
    
    #[tokio::test]
    async fn test_adaptive_delay_window() {
        let time_sync = Arc::new(TimeSyncEngine::new());
        let engine = PortHoppingEngine::new(time_sync.clone());
        
        // Default window size
        assert_eq!(engine.adaptive_delay_window.load(Ordering::SeqCst), 3);
        
        // Update window size based on network conditions
        engine.update_adaptive_delay_window(150.0, 75.0);
        
        // Verify window size was updated
        // Base (3) + Delay (2) + Jitter (3) = 8
        assert_eq!(engine.adaptive_delay_window.load(Ordering::SeqCst), 8);
        
        // Test with extreme conditions (should cap at 10)
        engine.update_adaptive_delay_window(500.0, 200.0);
        assert_eq!(engine.adaptive_delay_window.load(Ordering::SeqCst), 10);
    }
