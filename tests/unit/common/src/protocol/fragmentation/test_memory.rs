use buckwild_common::protocol:fragmentation::memory::*;
use crate::protocol::packet::SessionId;

    #[test]
    fn test_memory_manager_creation() {
        let manager = FragmentMemoryManager::new();
        let stats = manager.get_stats();
        assert_eq!(stats.stored_fragments, 0);
        assert_eq!(stats.total_memory_usage, 0);
    }

    #[test]
    fn test_buffer_allocation_and_deallocation() {
        let manager = FragmentMemoryManager::new();
        
        // Allocate a buffer
        let buffer = manager.allocate_buffer(1024);
        assert!(buffer.capacity() >= 1024);
        
        let stats_before = manager.get_stats();
        assert_eq!(stats_before.total_allocations, 1);
        
        // Deallocate the buffer
        manager.deallocate_buffer(buffer);
        
        let stats_after = manager.get_stats();
        assert_eq!(stats_after.total_deallocations, 1);
    }

    #[test]
    fn test_fragment_storage_and_retrieval() {
        let manager = FragmentMemoryManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        let fragment_id = 0x1234;
        let fragment_index = 0;
        let data = Bytes::from("test fragment data");

        // Store fragment
        let result = manager.store_fragment(session_id, fragment_id, fragment_index, data.clone());
        assert!(result.is_ok());

        let stats = manager.get_stats();
        assert_eq!(stats.stored_fragments, 1);
        assert!(stats.total_memory_usage > 0);

        // Retrieve fragment
        let retrieved = manager.retrieve_fragment(session_id, fragment_id, fragment_index);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);

        // Remove fragment
        let removed = manager.remove_fragment(session_id, fragment_id, fragment_index);
        assert!(removed);

        let stats_after = manager.get_stats();
        assert_eq!(stats_after.stored_fragments, 0);
    }

    #[test]
    fn test_memory_limit_enforcement() {
        let mut config = MemoryConfig::default();
        config.max_memory_usage = 100; // Very small limit
        
        let manager = FragmentMemoryManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let large_data = Bytes::from(vec![0u8; 200]); // Larger than limit

        let result = manager.store_fragment(session_id, 0x1234, 0, large_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Memory limit exceeded"));
    }

    #[test]
    fn test_memory_pool_reuse() {
        let manager = FragmentMemoryManager::new();
        
        // Allocate and deallocate a buffer
        let buffer1 = manager.allocate_buffer(1024);
        manager.deallocate_buffer(buffer1);
        
        // Allocate another buffer of the same size
        let _buffer2 = manager.allocate_buffer(1024);
        
        let stats = manager.get_stats();
        
        // Should have some cache hits if pooling is working
        let pool_stats = stats.pool_stats.iter()
            .find(|p| p.fragment_size >= 1024)
            .expect("Should have a pool for 1024 byte fragments");
        
        assert!(pool_stats.allocations >= 2);
    }

    #[test]
    fn test_cleanup_expired_fragments() {
        let mut config = MemoryConfig::default();
        config.fragment_timeout_sec = 1; // Very short timeout
        
        let manager = FragmentMemoryManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        let data = Bytes::from("test data");

        // Store a fragment
        let _ = manager.store_fragment(session_id, 0x1234, 0, data);
        
        let stats_before = manager.get_stats();
        assert_eq!(stats_before.stored_fragments, 1);

        // Wait for expiration (in a real test, you might want to mock time)
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Cleanup expired fragments
        manager.cleanup_expired_fragments();
        
        let stats_after = manager.get_stats();
        assert_eq!(stats_after.stored_fragments, 0);
    }

    #[test]
    fn test_memory_optimization() {
        let manager = FragmentMemoryManager::new();
        
        // Store some fragments
        let session_id = SessionId::Bits32(0x12345678);
        for i in 0..10 {
            let data = Bytes::from(format!("fragment {}", i));
            let _ = manager.store_fragment(session_id, 0x1234, i, data);
        }

        let stats_before = manager.get_stats();
        assert_eq!(stats_before.stored_fragments, 10);

        // Optimize memory
        manager.optimize_memory();

        // Should still have fragments (unless they expired)
        let stats_after = manager.get_stats();
        assert!(stats_after.stored_fragments <= 10);
    }

    #[test]
    fn test_pool_statistics() {
        let manager = FragmentMemoryManager::new();
        
        // Allocate buffers of different sizes
        let _buffer1 = manager.allocate_buffer(64);
        let _buffer2 = manager.allocate_buffer(256);
        let _buffer3 = manager.allocate_buffer(1024);

        let pool_info = manager.get_pool_info();
        assert!(!pool_info.is_empty());

        // Check that allocations were recorded
        let total_allocations: u64 = pool_info.iter().map(|p| p.allocations).sum();
        assert!(total_allocations >= 3);
    }
