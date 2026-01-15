use buckwild_common::crypto::secure_storage::*;
#[test]
    fn test_secure_bytes() {
        let data = b"sensitive data";
        let secure_data = SecureBytes::new(data);
        
        // Check data
        assert_eq!(secure_data.as_bytes(), data);
        assert_eq!(secure_data.len(), data.len());
        assert!(!secure_data.is_empty());
        
        // Check access count
        assert_eq!(secure_data.access_count(), 1);
        let _ = secure_data.as_bytes();
        assert_eq!(secure_data.access_count(), 2);
    }
    
    #[test]
    fn test_secure_key_store() {
        let store = SecureKeyStore::new(100);
        
        // Add keys
        store.add_key("key1", b"data1");
        store.add_key("key2", b"data2");
        
        // Check key count
        assert_eq!(store.key_count(), 2);
        assert!(store.has_key("key1"));
        assert!(store.has_key("key2"));
        assert!(!store.has_key("key3"));
        
        // Get keys
        let key1 = store.get_key("key1", "test").unwrap();
        assert_eq!(key1.as_bytes(), b"data1");
        
        // Remove key
        assert!(store.remove_key("key1"));
        assert!(!store.has_key("key1"));
        assert_eq!(store.key_count(), 1);
        
        // Check access log
        let log = store.get_access_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1, "key1");
        assert_eq!(log[0].2, "test");
    }
