use buckwild_common::session::concurrency_tests::*;

    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::session::{SessionState, SessionStatus, SessionManager, SessionId};
    use crate::crypto::kdf::Kdf;

    #[test]
    fn test_atomic_sequence_number_updates() {
        let session = Arc::new(SessionState::new());
        let num_threads = 10;
        let updates_per_thread = 1000;
        
        // Spawn multiple threads to update sequence numbers concurrently
        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let session_clone = session.clone();
                thread::spawn(move || {
                    for i in 0..updates_per_thread {
                        // Increment local sequence
                        session_clone.increment_local_seq();
                        
                        // Try to update remote sequence
                        let remote_seq = (thread_id * updates_per_thread + i) as u32;
                        session_clone.update_remote_seq(remote_seq);
                        
                        // Update activity periodically
                        if i % 100 == 0 {
                            session_clone.update_activity();
                        }
                    }
                })
            })
            .collect();
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify final state
        assert_eq!(session.local_seq(), (num_threads * updates_per_thread) as u32);
        
        // Remote sequence should be the highest value attempted
        let expected_max_remote = ((num_threads - 1) * updates_per_thread + updates_per_thread - 1) as u32;
        assert_eq!(session.remote_seq(), expected_max_remote);
    }

    #[test]
    fn test_concurrent_session_parameter_access() {
        let session = Arc::new(SessionState::new());
        let num_threads = 8;
        let operations_per_thread = 500;
        
        // Initialize session with PBKDF2 parameters
        let kdf = Kdf::default();
        let test_key = b"test_concurrent_key";
        let params = kdf.derive_parameters(test_key).unwrap();
        session.init_from_pbkdf2(&params).unwrap();
        
        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let session_clone = session.clone();
                thread::spawn(move || {
                    for i in 0..operations_per_thread {
                        // Read port hopping parameters
                        for j in 0..4 {
                            let _ = session_clone.port_hop_param(j);
                        }
                        
                        // Read session parameters
                        for j in 0..16 {
                            let _ = session_clone.session_param(j);
                        }
                        
                        // Update some parameters
                        let param_index = i % 16;
                        let new_value = (thread_id * 1000 + i) as u16;
                        session_clone.set_session_param(param_index, new_value);
                        
                        // Update window state
                        let window = session_clone.window_state();
                        window.set_congestion_window(1460 + (i % 1000) as u32);
                        window.update_rtt(100_000 + (i % 50_000) as u32);
                    }
                })
            })
            .collect();
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify that all parameters are accessible and valid
        for i in 0..16 {
            assert!(session.session_param(i).is_some());
        }
        
        for i in 0..4 {
            assert!(session.port_hop_param(i).is_some());
        }
    }

    #[test]
    fn test_session_manager_concurrent_operations() {
        let manager = Arc::new(SessionManager::default());
        let num_threads = 12;
        let operations_per_thread = 200;
        let created_sessions = Arc::new(AtomicUsize::new(0));
        let removed_sessions = Arc::new(AtomicUsize::new(0));
        
        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let manager_clone = manager.clone();
                let created_counter = created_sessions.clone();
                let removed_counter = removed_sessions.clone();
                
                thread::spawn(move || {
                    let mut local_sessions = Vec::new();
                    
                    for i in 0..operations_per_thread {
                        match i % 4 {
                            0 => {
                                // Create session
                                let (session_id, session) = manager_clone.create_session();
                                local_sessions.push(session_id);
                                created_counter.fetch_add(1, Ordering::Relaxed);
                                
                                // Initialize with some data
                                session.set_status(SessionStatus::Established);
                                session.set_local_seq(thread_id as u32 * 1000 + i as u32);
                            }
                            1 => {
                                // Get existing session
                                if !local_sessions.is_empty() {
                                    let session_id = local_sessions[i % local_sessions.len()];
                                    if let Some(session) = manager_clone.get_session(&session_id) {
                                        // Update session
                                        session.increment_local_seq();
                                        session.update_activity();
                                        
                                        // Release reference
                                        manager_clone.release_session(&session_id);
                                    }
                                }
                            }
                            2 => {
                                // Remove session
                                if !local_sessions.is_empty() && local_sessions.len() > 10 {
                                    let session_id = local_sessions.remove(0);
                                    if manager_clone.remove_session(&session_id) {
                                        removed_counter.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            3 => {
                                // Check session count
                                let _ = manager_clone.session_count();
                                
                                // Get all session IDs
                                let _ = manager_clone.get_all_session_ids();
                            }
                            _ => unreachable!(),
                        }
                    }
                    
                    // Clean up remaining sessions
                    for session_id in local_sessions {
                        if manager_clone.remove_session(&session_id) {
                            removed_counter.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        let final_created = created_sessions.load(Ordering::Relaxed);
        let final_removed = removed_sessions.load(Ordering::Relaxed);
        
        println!("Created: {}, Removed: {}, Remaining: {}", 
                 final_created, final_removed, manager.session_count());
        
        // Verify that the manager is in a consistent state
        assert!(manager.session_count() <= final_created);
        assert_eq!(manager.session_count(), final_created - final_removed);
    }

    #[test]
    fn test_reference_counting_safety() {
        let manager = Arc::new(SessionManager::default());
        
        // Create a session
        let (session_id, session) = manager.create_session();
        
        // Get multiple references
        let ref1 = manager.get_session(&session_id).unwrap();
        println!("After ref1: {}", manager.get_reference_count(&session_id));
        let ref2 = manager.get_session(&session_id).unwrap();
        println!("After ref2: {}", manager.get_reference_count(&session_id));
        let ref3 = manager.get_session(&session_id).unwrap();
        println!("After ref3: {}", manager.get_reference_count(&session_id));
        
        // Check reference count
        assert_eq!(manager.get_reference_count(&session_id), 3); // 3 gets
        
        // Try to remove session (should fail due to active references)
        assert!(!manager.remove_session(&session_id));
        // Don't call get_session here as it would increment the reference count
        
        // Release references
        manager.release_session(&session_id);
        println!("After release 1: {}", manager.get_reference_count(&session_id));
        manager.release_session(&session_id);
        println!("After release 2: {}", manager.get_reference_count(&session_id));
        manager.release_session(&session_id);
        println!("After release 3: {}", manager.get_reference_count(&session_id));
        
        // Check reference count
        let ref_count = manager.get_reference_count(&session_id);
        println!("Reference count after releases: {}", ref_count);
        
        // Now removal should succeed
        assert!(manager.remove_session(&session_id));
        assert!(manager.get_session(&session_id).is_none());
        
        // Keep references alive to test Arc behavior
        drop(ref1);
        drop(ref2);
        drop(ref3);
        drop(session);
    }

    #[test]
    fn test_concurrent_reference_counting() {
        let manager = Arc::new(SessionManager::default());
        let num_threads = 8;
        let operations_per_thread = 1000;
        
        // Create initial sessions
        let mut session_ids = Vec::new();
        for _ in 0..10 {
            let (session_id, _) = manager.create_session();
            session_ids.push(session_id);
        }
        
        let session_ids = Arc::new(session_ids);
        
        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let manager_clone = manager.clone();
                let session_ids_clone = session_ids.clone();
                
                thread::spawn(move || {
                    for _ in 0..operations_per_thread {
                        // Randomly select a session
                        let session_id = session_ids_clone[rand::random::<usize>() % session_ids_clone.len()];
                        
                        // Get reference
                        if let Some(_session) = manager_clone.get_session(&session_id) {
                            // Do some work
                            thread::sleep(Duration::from_nanos(100));
                            
                            // Release reference
                            manager_clone.release_session(&session_id);
                        }
                    }
                })
            })
            .collect();
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        // All reference counts should be 0 (no external references)
        for session_id in session_ids.iter() {
            assert_eq!(manager.get_reference_count(session_id), 0);
        }
        
        // Clean up
        for session_id in session_ids.iter() {
            assert!(manager.remove_session(session_id));
        }
    }

    #[test]
    fn test_session_id_collision_detection() {
        let manager = SessionManager::default();
        let mut session_ids = std::collections::HashSet::new();
        
        // Generate many session IDs to test collision detection
        for _ in 0..10000 {
            let session_id = manager.generate_session_id();
            
            // Ensure no collisions
            assert!(!session_ids.contains(&session_id));
            assert_ne!(session_id.0, 0); // Ensure not zero
            
            session_ids.insert(session_id);
        }
    }

    #[test]
    fn test_pbkdf2_parameter_derivation_consistency() {
        let manager = SessionManager::default();
        let shared_secret = b"test_shared_secret_for_ecdh";
        let salt = b"test_salt_16byte";
        
        // Create multiple sessions with the same parameters
        let mut sessions = Vec::new();
        for _ in 0..5 {
            let result = manager.create_session_with_ecdh(shared_secret, salt);
            assert!(result.is_ok());
            let (session_id, session) = result.unwrap();
            sessions.push((session_id, session));
        }
        
        // All sessions should have the same derived parameters
        let first_session: &SessionState = &sessions[0].1;
        for (_, session) in &sessions[1..] {
            assert_eq!(session.local_seq(), first_session.local_seq());
            assert_eq!(session.remote_seq(), first_session.remote_seq());
            assert_eq!(session.local_port(), first_session.local_port());
            assert_eq!(session.remote_port(), first_session.remote_port());
            
            // Check that port hopping parameters are the same
            for i in 0..4 {
                assert_eq!(session.port_hop_param(i), first_session.port_hop_param(i));
            }
            
            // Check that session parameters (HMAC key) are the same
            for i in 0..16 {
                assert_eq!(session.session_param(i), first_session.session_param(i));
            }
        }
        
        // Clean up
        for (session_id, _) in sessions {
            manager.remove_session(&session_id);
        }
    }

    #[test]
    fn test_port_calculation_determinism() {
        let manager = SessionManager::default();
        let (_, session) = manager.create_session();
        
        // Set port hopping parameters
        session.set_port_hop_param(0, 0x1234);
        session.set_port_hop_param(1, 0x5678);
        session.set_port_hop_param(2, 0x9ABC);
        session.set_port_hop_param(3, 0xDEF0);
        
        // Test determinism across multiple calls
        for time_bucket in 0..100 {
            let port1_local = manager.calculate_port(&session, time_bucket, true);
            let port1_remote = manager.calculate_port(&session, time_bucket, false);
            
            // Call again to ensure determinism
            let port2_local = manager.calculate_port(&session, time_bucket, true);
            let port2_remote = manager.calculate_port(&session, time_bucket, false);
            
            assert_eq!(port1_local, port2_local);
            assert_eq!(port1_remote, port2_remote);
            
            // Ensure ports are in valid range
            assert!(port1_local >= 49152);
            assert!(port1_remote >= 49152);
            
            // Local and remote ports should be different
            assert_ne!(port1_local, port1_remote);
        }
    }

    #[test]
    fn test_session_cleanup_with_references() {
        let mut manager = SessionManager::new(
            Duration::from_millis(10),  // Cleanup every 10ms
            Duration::from_millis(50),  // Idle timeout after 50ms
        );
        
        // Create sessions
        let (id1, session1) = manager.create_session();
        let (id2, session2) = manager.create_session();
        let (id3, _session3) = manager.create_session();
        
        // Get additional references for some sessions
        let _ref1 = manager.get_session(&id1).unwrap();
        let _ref2 = manager.get_session(&id2).unwrap();
        
        // Update activity for session1 to keep it fresh
        session1.update_activity();
        
        // Wait for sessions to become idle
        thread::sleep(Duration::from_millis(100));
        
        // Cleanup should only remove session3 (no references and idle)
        let removed = manager.cleanup_sessions();
        assert_eq!(removed, 1);
        
        // Session1 and session2 should still exist (have references)
        assert!(manager.get_session(&id1).is_some());
        assert!(manager.get_session(&id2).is_some());
        assert!(manager.get_session(&id3).is_none());
        
        // Release references
        manager.release_session(&id1);
        manager.release_session(&id1); // Release the get reference
        manager.release_session(&id2);
        manager.release_session(&id2); // Release the get reference
        
        // Wait for sessions to become idle again
        thread::sleep(Duration::from_millis(100));
        
        // Now cleanup should remove the remaining sessions
        let removed = manager.cleanup_sessions();
        println!("Removed in second cleanup: {}, session count: {}", removed, manager.session_count());
        
        // Check reference counts
        println!("Session 1 ref count: {}", manager.get_reference_count(&id1));
        println!("Session 2 ref count: {}", manager.get_reference_count(&id2));
        
        assert_eq!(removed, 2);
        
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_ebpf_synchronization() {
        let manager = SessionManager::default();
        
        // Create sessions
        let (id1, session1) = manager.create_session();
        let (id2, session2) = manager.create_session();
        let (id3, session3) = manager.create_session();
        
        // Update session states
        session1.set_status(SessionStatus::Established);
        session1.set_remote_seq(1000);
        session1.set_remote_port(8080);
        
        session2.set_status(SessionStatus::Established);
        session2.set_remote_seq(2000);
        session2.set_remote_port(8081);
        
        session3.set_status(SessionStatus::Closing);
        session3.set_remote_seq(3000);
        session3.set_remote_port(8082);
        
        // Test individual session sync
        assert!(manager.update_ebpf_session_map(&id1, &session1).is_ok());
        assert!(manager.update_ebpf_session_map(&id2, &session2).is_ok());
        assert!(manager.update_ebpf_session_map(&id3, &session3).is_ok());
        
        // Test bulk sync
        let synced = manager.sync_all_sessions_to_ebpf().unwrap();
        assert_eq!(synced, 3);
        
        // Test session removal from eBPF
        assert!(manager.remove_ebpf_session(&id1).is_ok());
        assert!(manager.remove_ebpf_session(&id2).is_ok());
        assert!(manager.remove_ebpf_session(&id3).is_ok());
        
        // Clean up
        manager.remove_session(&id1);
        manager.remove_session(&id2);
        manager.remove_session(&id3);
    }
