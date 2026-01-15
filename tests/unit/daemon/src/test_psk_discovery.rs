use buckwild_daemon::psk_discovery::*;
use std::time::Duration;
    use tokio::time::sleep;
    
    /// Create a test PSK fingerprint from a string
    fn test_fingerprint(s: &str) -> PskFingerprint {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let result = hasher.finalize();
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&result);
        fingerprint
    }
    
    /// Create a test PSK from a string
    fn test_psk(s: &str) -> Arc<SecureBytes> {
        Arc::new(SecureBytes::new(s.as_bytes()))
    }
    
    #[tokio::test]
    async fn test_psk_discovery_engine_creation() {
        let engine = PskDiscoveryEngine::new();
        let stats = engine.get_statistics().await;
        
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.cached_psks, 0);
        assert_eq!(stats.local_psks, 0);
    }
    
    #[tokio::test]
    async fn test_add_remove_psk() {
        let engine = PskDiscoveryEngine::new();
        let fingerprint = test_fingerprint("test_psk_1");
        let psk = test_psk("test_psk_data_1");
        
        // Add PSK
        engine.add_psk(fingerprint, psk.clone()).await;
        
        let stats = engine.get_statistics().await;
        assert_eq!(stats.local_psks, 1);
        assert_eq!(stats.cached_psks, 1);
        
        let fingerprints = engine.get_local_fingerprints().await;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0], fingerprint);
        
        // Remove PSK
        engine.remove_psk(&fingerprint).await;
        
        let stats = engine.get_statistics().await;
        assert_eq!(stats.local_psks, 0);
        assert_eq!(stats.cached_psks, 0);
        
        let fingerprints = engine.get_local_fingerprints().await;
        assert_eq!(fingerprints.len(), 0);
    }
    
    #[tokio::test]
    async fn test_blinded_fingerprint_generation() {
        let engine = PskDiscoveryEngine::new();
        let fingerprints = vec![
            test_fingerprint("psk1"),
            test_fingerprint("psk2"),
            test_fingerprint("psk3"),
        ];
        
        let discovery_id = 12345u64;
        let session_salt = 67890u32;
        
        let blinded_fps = engine.create_blinded_fingerprint_set(
            &fingerprints,
            discovery_id,
            session_salt,
        );
        
        assert_eq!(blinded_fps.len(), fingerprints.len());
        
        // Blinded fingerprints should be deterministic for same inputs
        let blinded_fps2 = engine.create_blinded_fingerprint_set(
            &fingerprints,
            discovery_id,
            session_salt,
        );
        
        assert_eq!(blinded_fps, blinded_fps2);
        
        // Different session parameters should produce different blinded fingerprints
        let blinded_fps3 = engine.create_blinded_fingerprint_set(
            &fingerprints,
            discovery_id + 1,
            session_salt,
        );
        
        assert_ne!(blinded_fps, blinded_fps3);
    }
    
    #[tokio::test]
    async fn test_bloom_filter_operations() {
        let engine = PskDiscoveryEngine::new();
        let fingerprints = vec![
            test_fingerprint("psk1"),
            test_fingerprint("psk2"),
            test_fingerprint("psk3"),
        ];
        
        let discovery_id = 12345u64;
        let session_salt = 67890u32;
        
        let blinded_fps = engine.create_blinded_fingerprint_set(
            &fingerprints,
            discovery_id,
            session_salt,
        );
        
        let (bloom_filter, filter_size, num_hashes) = engine.create_adaptive_bloom_filter(
            &blinded_fps,
            fingerprints.len(),
        );
        
        assert!(filter_size >= BLOOM_FILTER_SIZE_BITS_DEFAULT);
        assert!(num_hashes >= 1);
        assert_eq!(bloom_filter.len(), filter_size);
        
        // All blinded fingerprints should test positive in the filter
        for blinded_fp in &blinded_fps {
            assert!(engine.bloom_filter_test(&bloom_filter, blinded_fp));
        }
        
        // Random fingerprint should likely test negative (but could be false positive)
        let random_blinded = [0u8; PSI_BLINDED_FINGERPRINT_SIZE];
        // Note: This could be a false positive, so we don't assert false
        let _ = engine.bloom_filter_test(&bloom_filter, &random_blinded);
    }
    
    #[tokio::test]
    async fn test_candidate_verification() {
        let engine = PskDiscoveryEngine::new();
        let fingerprints = vec![
            test_fingerprint("psk1"),
            test_fingerprint("psk2"),
            test_fingerprint("psk3"),
        ];
        
        let discovery_id = 12345u64;
        let session_salt = 67890u32;
        
        let blinded_fps = engine.create_blinded_fingerprint_set(
            &fingerprints,
            discovery_id,
            session_salt,
        );
        
        // Create candidate hashes from blinded fingerprints
        let candidate_hashes: Vec<CandidateHash> = blinded_fps
            .iter()
            .map(|bf| engine.calculate_candidate_hash(bf))
            .collect();
        
        // Verify candidates
        let intersection_results = engine.verify_psi_candidates(
            &candidate_hashes,
            &fingerprints,
            discovery_id,
            session_salt,
        );
        
        assert_eq!(intersection_results.len(), fingerprints.len());
        
        // Check that all original fingerprints are found
        let found_fingerprints: Vec<PskFingerprint> = intersection_results
            .iter()
            .map(|r| r.original_fingerprint)
            .collect();
        
        for fp in &fingerprints {
            assert!(found_fingerprints.contains(fp));
        }
    }
    
    #[tokio::test]
    async fn test_psk_selection() {
        let engine = PskDiscoveryEngine::new();
        let fingerprints = vec![
            test_fingerprint("psk_c"),
            test_fingerprint("psk_a"),
            test_fingerprint("psk_b"),
        ];
        
        let discovery_id = 12345u64;
        let session_salt = 67890u32;
        
        let blinded_fps = engine.create_blinded_fingerprint_set(
            &fingerprints,
            discovery_id,
            session_salt,
        );
        
        let candidate_hashes: Vec<CandidateHash> = blinded_fps
            .iter()
            .map(|bf| engine.calculate_candidate_hash(bf))
            .collect();
        
        let intersection_results = engine.verify_psi_candidates(
            &candidate_hashes,
            &fingerprints,
            discovery_id,
            session_salt,
        );
        
        let selected = engine.select_optimal_psk(&intersection_results);
        
        // Should select lexicographically smallest fingerprint
        let mut sorted_fps = fingerprints.clone();
        sorted_fps.sort();
        assert_eq!(selected, sorted_fps[0]);
    }
    
    #[tokio::test]
    async fn test_psk_confirmation() {
        let engine = PskDiscoveryEngine::new();
        let fingerprint = test_fingerprint("test_psk");
        let discovery_id = 12345u64;
        let session_salt = 67890u32;
        
        // Calculate confirmation hash
        let confirmation_hash = engine.calculate_psk_confirmation_hash(
            &fingerprint,
            discovery_id,
            session_salt,
        );
        
        // Verify confirmation
        let verified = engine.verify_psk_confirmation(
            &confirmation_hash,
            &[fingerprint],
            discovery_id,
            session_salt,
        ).await;
        
        assert_eq!(verified, Some(fingerprint));
        
        // Wrong fingerprint should not verify
        let wrong_fingerprint = test_fingerprint("wrong_psk");
        let verified_wrong = engine.verify_psk_confirmation(
            &confirmation_hash,
            &[wrong_fingerprint],
            discovery_id,
            session_salt,
        ).await;
        
        assert_eq!(verified_wrong, None);
    }
    
    #[tokio::test]
    async fn test_discovery_session_timeout() {
        let engine = PskDiscoveryEngine::new();
        let fingerprint = test_fingerprint("test_psk");
        let psk = test_psk("test_psk_data");
        
        engine.add_psk(fingerprint, psk).await;
        
        // Get initial stats
        let stats = engine.get_statistics().await;
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.local_psks, 1);
        
        // Test cleanup functionality (without actually starting discovery)
        engine.cleanup_expired_sessions().await;
        
        let stats_after_cleanup = engine.get_statistics().await;
        assert_eq!(stats_after_cleanup.active_sessions, 0);
        assert_eq!(stats_after_cleanup.local_psks, 1);
    }
    
    #[tokio::test]
    async fn test_session_cleanup() {
        let engine = PskDiscoveryEngine::new();
        
        // Add some test data
        let fingerprint = test_fingerprint("test_psk");
        let psk = test_psk("test_psk_data");
        engine.add_psk(fingerprint, psk).await;
        
        // Run cleanup (should not crash)
        engine.cleanup_expired_sessions().await;
        
        let stats = engine.get_statistics().await;
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.local_psks, 1);
    }
    
    #[tokio::test]
    async fn test_bloom_filter_parameters() {
        let engine = PskDiscoveryEngine::new();
        
        // Test with different PSK counts
        let test_cases = vec![
            (1, BLOOM_FILTER_FALSE_POSITIVE_RATE),
            (10, BLOOM_FILTER_FALSE_POSITIVE_RATE),
            (100, BLOOM_FILTER_FALSE_POSITIVE_RATE),
            (256, BLOOM_FILTER_FALSE_POSITIVE_RATE),
        ];
        
        for (psk_count, fp_rate) in test_cases {
            let (filter_size, num_hashes) = engine.calculate_optimal_bloom_parameters(
                psk_count,
                fp_rate,
            );
            
            assert!(filter_size >= BLOOM_FILTER_SIZE_BITS_DEFAULT);
            assert!(filter_size <= BLOOM_FILTER_SIZE_BITS_MAX);
            assert!(num_hashes >= 1);
            assert!(num_hashes <= 8);
        }
    }
    
    #[tokio::test]
    async fn test_privacy_preservation() {
        let engine = PskDiscoveryEngine::new();
        
        // Create two different PSK sets
        let alice_psks = vec![
            test_fingerprint("alice_psk_1"),
            test_fingerprint("alice_psk_2"),
            test_fingerprint("shared_psk"),
        ];
        
        let bob_psks = vec![
            test_fingerprint("bob_psk_1"),
            test_fingerprint("bob_psk_2"),
            test_fingerprint("shared_psk"),
        ];
        
        let discovery_id = 12345u64;
        let session_salt = 67890u32;
        
        // Create Alice's blinded fingerprints and Bloom filter
        let alice_blinded = engine.create_blinded_fingerprint_set(
            &alice_psks,
            discovery_id,
            session_salt,
        );
        
        let (alice_bloom, _, _) = engine.create_adaptive_bloom_filter(
            &alice_blinded,
            alice_psks.len(),
        );
        
        // Create Bob's blinded fingerprints
        let bob_blinded = engine.create_blinded_fingerprint_set(
            &bob_psks,
            discovery_id,
            session_salt,
        );
        
        // Test Bob's fingerprints against Alice's Bloom filter
        let mut candidates = Vec::new();
        for blinded_fp in &bob_blinded {
            if engine.bloom_filter_test(&alice_bloom, blinded_fp) {
                candidates.push(engine.calculate_candidate_hash(blinded_fp));
            }
        }
        
        // Should find at least the shared PSK (might have false positives)
        assert!(!candidates.is_empty());
        
        // Verify actual intersections
        let intersections = engine.verify_psi_candidates(
            &candidates,
            &bob_psks,
            discovery_id,
            session_salt,
        );
        
        // Should find exactly the shared PSK
        assert_eq!(intersections.len(), 1);
        assert_eq!(intersections[0].original_fingerprint, test_fingerprint("shared_psk"));
    }
    
    #[tokio::test]
    async fn test_discovery_success_rates() {
        let engine = PskDiscoveryEngine::new();
        
        // Test with various intersection scenarios
        let test_cases = vec![
            (vec!["psk1", "psk2"], vec!["psk1", "psk3"], vec!["psk1"]), // Single intersection
            (vec!["psk1", "psk2"], vec!["psk3", "psk4"], vec![]),        // No intersection
            (vec!["psk1", "psk2", "psk3"], vec!["psk1", "psk2", "psk4"], vec!["psk1", "psk2"]), // Multiple intersections
        ];
        
        for (alice_psk_names, bob_psk_names, expected_intersections) in test_cases {
            let alice_psks: Vec<PskFingerprint> = alice_psk_names
                .iter()
                .map(|name| test_fingerprint(name))
                .collect();
            
            let bob_psks: Vec<PskFingerprint> = bob_psk_names
                .iter()
                .map(|name| test_fingerprint(name))
                .collect();
            
            let expected_fps: Vec<PskFingerprint> = expected_intersections
                .iter()
                .map(|name| test_fingerprint(name))
                .collect();
            
            let discovery_id = 12345u64;
            let session_salt = 67890u32;
            
            // Simulate discovery process
            let alice_blinded = engine.create_blinded_fingerprint_set(
                &alice_psks,
                discovery_id,
                session_salt,
            );
            
            let (alice_bloom, _, _) = engine.create_adaptive_bloom_filter(
                &alice_blinded,
                alice_psks.len(),
            );
            
            let bob_blinded = engine.create_blinded_fingerprint_set(
                &bob_psks,
                discovery_id,
                session_salt,
            );
            
            let mut candidates = Vec::new();
            for blinded_fp in &bob_blinded {
                if engine.bloom_filter_test(&alice_bloom, blinded_fp) {
                    candidates.push(engine.calculate_candidate_hash(blinded_fp));
                }
            }
            
            let intersections = engine.verify_psi_candidates(
                &candidates,
                &bob_psks,
                discovery_id,
                session_salt,
            );
            
            let found_fps: Vec<PskFingerprint> = intersections
                .iter()
                .map(|r| r.original_fingerprint)
                .collect();
            
            // Check that we found all expected intersections
            assert_eq!(found_fps.len(), expected_fps.len());
            for expected_fp in &expected_fps {
                assert!(found_fps.contains(expected_fp));
            }
        }
    }
