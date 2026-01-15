use buckwild_common::crypto::precomputation::*;
#[test]
    fn test_thread_local_hmac_context() {
        // Get HMAC context
        let key = b"test key";
        let context = get_hmac_context(key, HmacPolicy::Medium);
        
        // Sign a message
        let message = b"test message";
        let tag = context.sign(message);
        
        // Verify the tag
        let truncated_tag = &tag.as_ref()[..context.policy().tag_length()];
        assert!(context.verify(message, truncated_tag).is_ok());
        
        // Get the same context again
        let context2 = get_hmac_context(key, HmacPolicy::Medium);
        
        // Verify that it's the same context
        let tag2 = context2.sign(message);
        assert_eq!(tag.as_ref(), tag2.as_ref());
        
        // Clear the cache
        clear_hmac_context_cache();
    }
    
    #[test]
    fn test_precomputation_cache() {
        // Create cache
        let cache = PrecomputationCache::<Vec<u8>>::new();
        
        // Get or insert a value
        let key = b"test key";
        let value = cache.get_or_insert(key, || Ok(vec![1, 2, 3])).unwrap();
        assert_eq!(value, vec![1, 2, 3]);
        
        // Get the same value again
        let value2 = cache.get_or_insert(key, || Ok(vec![4, 5, 6])).unwrap();
        assert_eq!(value2, vec![1, 2, 3]);
        
        // Check cache size
        assert_eq!(cache.len().unwrap(), 1);
        
        // Clear the cache
        cache.clear().unwrap();
        assert!(cache.is_empty().unwrap());
    }
    
    #[test]
    fn test_hmac_key_cache() {
        // Create cache
        let cache = HmacKeyCache::new();
        
        // Get or create a key
        let key_material = b"test key";
        let key = cache.get_key(key_material, &hmac::HMAC_SHA256).unwrap();
        
        // Sign a message
        let message = b"test message";
        let tag1 = hmac::sign(&key, message);
        
        // Get the same key again
        let key2 = cache.get_key(key_material, &hmac::HMAC_SHA256).unwrap();
        
        // Sign the same message
        let tag2 = hmac::sign(&key2, message);
        
        // Verify that the tags are the same
        assert_eq!(tag1.as_ref(), tag2.as_ref());
        
        // Clear the cache
        cache.clear().unwrap();
    }
