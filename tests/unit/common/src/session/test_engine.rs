use buckwild_common::session::engine::*;
use std::thread;
    use std::time::Duration;
    
    #[test]
    fn test_session_id_generation() {
        let engine = SessionEngine::default();
        
        // Generate multiple session IDs
        let id1 = engine.generate_session_id();
        let id2 = engine.generate_session_id();
        let id3 = engine.generate_session_id();
        
        // Ensure they're all different
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);
    }
    
    #[test]
    fn test_session_creation() {
        let engine = SessionEngine::default();
        
        // Create a session
        let (id, session) = engine.create_session();
        
        // Check that the session exists
        let retrieved = engine.get_session(&id);
        assert!(retrieved.is_some());
        
        // Check that the session is the same
        assert!(Arc::ptr_eq(&session, &retrieved.unwrap()));
        
        // Check session count
        assert_eq!(engine.session_count(), 1);
    }
    
    #[test]
    fn test_session_removal() {
        let engine = SessionEngine::default();
        
        // Create a session
        let (id, _session) = engine.create_session();
        
        // Release the creation reference
        engine.release_session(&id);
        
        // Remove the session
        assert!(engine.remove_session(&id));
        
        // Check that the session no longer exists
        assert!(engine.get_session(&id).is_none());
        
        // Check session count
        assert_eq!(engine.session_count(), 0);
        
        // Try to remove a non-existent session
        assert!(!engine.remove_session(&id));
    }
    
    #[test]
    fn test_session_cleanup() {
        let mut engine = SessionEngine::new(
            Duration::from_millis(10),  // Cleanup every 10ms
            Duration::from_millis(50),  // Idle timeout after 50ms
        );
        
        // Create a session
        let (id, session) = engine.create_session();
        
        // Update activity
        session.update_activity();
        
        // Release the creation reference
        engine.release_session(&id);
        
        // Wait for the session to become idle
        thread::sleep(Duration::from_millis(100));
        
        // Clean up sessions
        let removed = engine.cleanup_sessions();
        assert_eq!(removed, 1);
        
        // Check that the session no longer exists
        assert!(engine.get_session(&id).is_none());
        
        // Check session count
        assert_eq!(engine.session_count(), 0);
    }
    
    #[test]
    fn test_port_calculation() {
        let engine = SessionEngine::default();
        
        // Create a session
        let (_, session) = engine.create_session();
        
        // Set port hopping parameters
        session.set_port_hop_param(0, 0x1234);
        session.set_port_hop_param(1, 0x5678);
        session.set_port_hop_param(2, 0x9ABC);
        session.set_port_hop_param(3, 0xDEF0);
        
        // Calculate ports for different time buckets
        let port1_local = engine.calculate_port(&session, 1, true);
        let port1_remote = engine.calculate_port(&session, 1, false);
        let port2_local = engine.calculate_port(&session, 2, true);
        let port2_remote = engine.calculate_port(&session, 2, false);
        
        // Check that ports are in the correct range
        assert!(port1_local >= 49152 && port1_local <= 65535);
        assert!(port1_remote >= 49152 && port1_remote <= 65535);
        assert!(port2_local >= 49152 && port2_local <= 65535);
        assert!(port2_remote >= 49152 && port2_remote <= 65535);
        
        // Check that ports are different
        assert_ne!(port1_local, port1_remote);
        assert_ne!(port1_local, port2_local);
        assert_ne!(port1_remote, port2_remote);
        
        // Check that ports are deterministic
        assert_eq!(port1_local, engine.calculate_port(&session, 1, true));
        assert_eq!(port1_remote, engine.calculate_port(&session, 1, false));
    }
    
    #[test]
    fn test_concurrent_access() {
        let engine = Arc::new(SessionEngine::default());
        let engine_clone = engine.clone();
        
        // Create some initial sessions
        let mut session_ids = Vec::new();
        for _ in 0..10 {
            let (id, _) = engine.create_session();
            session_ids.push(id);
        }
        
        // Spawn a thread to create and remove sessions
        let thread = thread::spawn(move || {
            for _ in 0..100 {
                let (id, _) = engine_clone.create_session();
                
                // Randomly remove some sessions
                if rand::random::<bool>() {
                    engine_clone.remove_session(&id);
                }
            }
        });
        
        // Create and remove sessions in the main thread
        for _ in 0..100 {
            let (id, _) = engine.create_session();
            
            // Randomly remove some sessions
            if rand::random::<bool>() {
                engine.remove_session(&id);
            }
        }
        
        // Wait for the thread to finish
        thread.join().unwrap();
        
        // Check that we can still access the initial sessions
        for id in session_ids {
            // This should not panic even if the session was removed
            let _ = engine.get_session(&id);
        }
    }
