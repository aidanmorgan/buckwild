use buckwild_common::crypto::ecdh::*;
#[test]
    fn test_ecdh_key_exchange() {
        // Create ECDH manager
        let manager = EcdhManager::new(10);
        
        // Generate key pairs
        let alice_public = manager.get_key_pair("alice").unwrap();
        let bob_public = manager.get_key_pair("bob").unwrap();
        
        // Compute shared secrets
        let alice_secret = manager.compute_shared_secret("alice", &bob_public).unwrap();
        let bob_secret = manager.compute_shared_secret("bob", &alice_public).unwrap();
        
        // Verify that the shared secrets are the same
        assert_eq!(alice_secret.as_slice(), bob_secret.as_slice());
    }
    
    #[test]
    fn test_key_caching() {
        // Create ECDH manager with short expiration
        let manager = EcdhManager::new(10);
        
        // Generate key pair
        let public1 = manager.get_key_pair("test").unwrap();
        
        // Get the same key pair again (should be cached)
        let public2 = manager.get_key_pair("test").unwrap();
        
        // Verify that the public keys are the same
        assert_eq!(public1, public2);
    }
    
    #[test]
    fn test_shared_secret_caching() {
        // Create ECDH manager
        let manager = EcdhManager::new(10);
        
        // Generate key pairs
        let alice_public = manager.get_key_pair("alice").unwrap();
        let bob_public = manager.get_key_pair("bob").unwrap();
        
        // Compute shared secret
        let secret1 = manager.compute_shared_secret("alice", &bob_public).unwrap();
        
        // Compute the same shared secret again (should be cached)
        let secret2 = manager.compute_shared_secret("alice", &bob_public).unwrap();
        
        // Verify that the shared secrets are the same
        assert_eq!(secret1.as_slice(), secret2.as_slice());
    }
    
    #[test]
    fn test_key_rotation() {
        // Create ECDH manager
        let manager = EcdhManager::new(10);
        
        // Generate key pair
        let public1 = manager.get_key_pair("test").unwrap();
        
        // Rotate keys
        manager.rotate_keys().unwrap();
        
        // Generate key pair again
        let public2 = manager.get_key_pair("test").unwrap();
        
        // Verify that the public keys are different
        assert_ne!(public1, public2);
    }
    
    #[test]
    fn test_thread_safe_manager() {
        // Create thread-safe ECDH manager
        let manager = ThreadSafeEcdhManager::new(10);
        
        // Generate key pairs
        let alice_public = manager.get_key_pair("alice").unwrap();
        let bob_public = manager.get_key_pair("bob").unwrap();
        
        // Compute shared secrets
        let alice_secret = manager.compute_shared_secret("alice", &bob_public).unwrap();
        let bob_secret = manager.compute_shared_secret("bob", &alice_public).unwrap();
        
        // Verify that the shared secrets are the same
        assert_eq!(alice_secret.as_slice(), bob_secret.as_slice());
    }
