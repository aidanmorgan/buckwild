use buckwild_common::engines:port_hopping::calculation::*;
use crate::time_sync::state::create_shared_time_sync_state;
    use crate::time_sync::engine::TimeSyncEngine;
    
    #[tokio::test]
    async fn test_derive_port_hopping_params() {
        let shared_secret = b"test_shared_secret_for_port_hopping_params";
        let client_pubkey = b"client_public_key_test";
        let server_pubkey = b"server_public_key_test";
        let session_id = 0x1234567890ABCDEF;
        
        let params = PortHoppingCalculation::derive_port_hopping_params(
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
        let time_sync = Arc::new(TimeSyncEngine::new());
        let time_epoch = Arc::new(TimeEpoch::new());
        let calculation = PortHoppingCalculation::new(time_epoch);
        
        // Create a test daily key
        let psk = b"test_psk_for_port_calculation";
        let daily_key = calculation.derive_daily_key(psk, "2023-01-01").await;
        
        // Calculate base port
        let base_port = calculation.calculate_base_port(&daily_key, 100);
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
        
        let session_port = calculation.calculate_session_port(&params, 200);
        assert!(session_port >= MIN_PORT);
        assert!(session_port <= MAX_PORT);
        
        // Verify port calculation is deterministic
        let base_port2 = calculation.calculate_base_port(&daily_key, 100);
        assert_eq!(base_port, base_port2);
        
        let session_port2 = calculation.calculate_session_port(&params, 200);
        assert_eq!(session_port, session_port2);
        
        // Verify different time windows produce different ports
        let session_port3 = calculation.calculate_session_port(&params, 201);
        assert_ne!(session_port, session_port3);
    }
    
    #[tokio::test]
    async fn test_session_port_calculation() {
        let time_epoch = Arc::new(TimeEpoch::new());
        let calculation = PortHoppingCalculation::new(time_epoch);
        
        let seed = [0x42; 32];
        let epoch = 100;
        
        // Calculate local and remote ports
        let local_port = calculation.calculate_session_port(&seed, epoch, true);
        let remote_port = calculation.calculate_session_port(&seed, epoch, false);
        
        // Verify ports are in valid range
        assert!(local_port >= MIN_PORT);
        assert!(local_port <= MAX_PORT);
        assert!(remote_port >= MIN_PORT);
        assert!(remote_port <= MAX_PORT);
        
        // Verify local and remote ports are different
        assert_ne!(local_port, remote_port);
        
        // Verify deterministic calculation
        let local_port2 = calculation.calculate_session_port(&seed, epoch, true);
        let remote_port2 = calculation.calculate_session_port(&seed, epoch, false);
        assert_eq!(local_port, local_port2);
        assert_eq!(remote_port, remote_port2);
        
        // Verify different epochs produce different ports
        let local_port_next = calculation.calculate_session_port(&seed, epoch + 1, true);
        assert_ne!(local_port, local_port_next);
    }
    
    #[tokio::test]
    async fn test_delay_window_ports() {
        let time_epoch = Arc::new(TimeEpoch::new());
        let calculation = PortHoppingCalculation::new(time_epoch);
        
        let params = PortHoppingParams {
            port_seed: 0x12345678,
            hop_sequence_seed: 0x87654321,
            time_variance: 50,
            hop_pattern_seed: 0xABCD,
            session_id: 0x1234567890ABCDEF,
        };
        
        let delay_window = 5;
        let ports = calculation.get_ports_for_delay_window(&params, delay_window);
        
        // Verify we get the expected number of unique ports
        assert!(!ports.is_empty());
        assert!(ports.len() <= delay_window * 2 + 1);
        
        // Verify all ports are in valid range
        for port in &ports {
            assert!(*port >= MIN_PORT);
            assert!(*port <= MAX_PORT);
        }
        
        // Verify no duplicate ports
        let mut unique_ports = std::collections::HashSet::new();
        for port in &ports {
            assert!(unique_ports.insert(*port), "Duplicate port found: {}", port);
        }
    }
    
    #[tokio::test]
    async fn test_cache_operations() {
        let time_epoch = Arc::new(TimeEpoch::new());
        let calculation = PortHoppingCalculation::new(time_epoch);
        
        // Test cache statistics
        let (cache_size, keys_size) = calculation.get_cache_stats();
        assert_eq!(cache_size, 0);
        assert_eq!(keys_size, 0);
        
        // Add some entries to cache
        let psk = b"test_psk";
        let daily_key = calculation.derive_daily_key(psk, "2023-01-01").await;
        let _base_port = calculation.calculate_base_port(&daily_key, 100);
        
        let (cache_size, keys_size) = calculation.get_cache_stats();
        assert!(cache_size > 0);
        assert!(keys_size > 0);
        
        // Clear cache
        calculation.clear_cache().await;
        let (cache_size, _) = calculation.get_cache_stats();
        assert_eq!(cache_size, 0);
    }
