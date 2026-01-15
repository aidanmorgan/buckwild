use buckwild_common::protocol::fragment_memory::*;
#[test]
    fn test_fragment_memory_manager_creation() {
        let manager = FragmentMemoryManager::new();
        let stats = manager.get_memory_stats();
        
        assert_eq!(stats.global_memory_usage, 0);
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.active_buffers, 0);
        assert!(!stats.memory_pressure);
    }
    
    #[test]
    fn test_memory_allocation_success() {
        let manager = FragmentMemoryManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        let request = MemoryAllocationRequest {
            session_id,
            fragment_id: 1,
            size: 1024,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        let result = manager.allocate_memory(&request);
        assert_eq!(result, MemoryAllocationResult::Success);
        
        let stats = manager.get_memory_stats();
        assert_eq!(stats.global_memory_usage, 1024);
        assert_eq!(stats.active_sessions, 1);
        assert_eq!(stats.active_buffers, 1);
        assert_eq!(stats.total_allocations, 1);
    }
    
    #[test]
    fn test_per_session_limit_enforcement() {
        let config = FragmentMemoryConfig {
            per_session_limit: 1000,
            global_limit: 10000,
            ..Default::default()
        };
        
        let manager = FragmentMemoryManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        
        // First allocation should succeed
        let request1 = MemoryAllocationRequest {
            session_id,
            fragment_id: 1,
            size: 600,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request1), MemoryAllocationResult::Success);
        
        // Second allocation should exceed per-session limit
        let request2 = MemoryAllocationRequest {
            session_id,
            fragment_id: 2,
            size: 500,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request2), MemoryAllocationResult::SessionLimitExceeded);
        
        let stats = manager.get_memory_stats();
        assert_eq!(stats.global_memory_usage, 600);
        assert_eq!(stats.active_buffers, 1);
    }
    
    #[test]
    fn test_global_limit_enforcement() {
        let config = FragmentMemoryConfig {
            per_session_limit: 10000,
            global_limit: 1000,
            ..Default::default()
        };
        
        let manager = FragmentMemoryManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        
        // First allocation should succeed
        let request1 = MemoryAllocationRequest {
            session_id,
            fragment_id: 1,
            size: 600,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request1), MemoryAllocationResult::Success);
        
        // Second allocation should exceed global limit
        let request2 = MemoryAllocationRequest {
            session_id,
            fragment_id: 2,
            size: 500,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request2), MemoryAllocationResult::GlobalLimitExceeded);
        
        let stats = manager.get_memory_stats();
        assert_eq!(stats.global_memory_usage, 600);
        assert_eq!(stats.memory_exhaustion_events, 1);
    }
    
    #[test]
    fn test_memory_deallocation() {
        let manager = FragmentMemoryManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Allocate memory
        let alloc_request = MemoryAllocationRequest {
            session_id,
            fragment_id: 1,
            size: 1024,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&alloc_request), MemoryAllocationResult::Success);
        
        let stats = manager.get_memory_stats();
        assert_eq!(stats.global_memory_usage, 1024);
        
        // Deallocate memory
        let dealloc_request = MemoryDeallocationRequest {
            session_id,
            fragment_id: 1,
            size: 1024,
        };
        
        assert!(manager.deallocate_memory(&dealloc_request).is_ok());
        
        let stats = manager.get_memory_stats();
        assert_eq!(stats.global_memory_usage, 0);
        assert_eq!(stats.total_deallocations, 1);
    }
    
    #[test]
    fn test_memory_pressure_detection() {
        let config = FragmentMemoryConfig {
            per_session_limit: 10000,
            global_limit: 1000,
            memory_pressure_threshold: 0.8, // 80% = 800 bytes
            ..Default::default()
        };
        
        let manager = FragmentMemoryManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        
        // Allocate memory to trigger pressure
        let request = MemoryAllocationRequest {
            session_id,
            fragment_id: 1,
            size: 850, // Above 80% threshold
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request), MemoryAllocationResult::Success);
        
        let stats = manager.get_memory_stats();
        assert!(stats.memory_pressure);
        assert_eq!(stats.memory_pressure_events, 1);
        
        // Next allocation should be denied due to pressure
        let request2 = MemoryAllocationRequest {
            session_id,
            fragment_id: 2,
            size: 100,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request2), MemoryAllocationResult::MemoryPressure);
    }
    
    #[test]
    fn test_buffer_limit_enforcement() {
        let config = FragmentMemoryConfig {
            per_session_limit: 10000,
            global_limit: 10000,
            max_buffers_per_session: 2,
            ..Default::default()
        };
        
        let manager = FragmentMemoryManager::with_config(config);
        let session_id = SessionId::Bits32(0x12345678);
        
        // First two allocations should succeed
        for i in 1..=2 {
            let request = MemoryAllocationRequest {
                session_id,
                fragment_id: i,
                size: 100,
                expected_fragments: 2,
                fragment_index: 0,
            };
            assert_eq!(manager.allocate_memory(&request), MemoryAllocationResult::Success);
        }
        
        // Third allocation should exceed buffer limit
        let request3 = MemoryAllocationRequest {
            session_id,
            fragment_id: 3,
            size: 100,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request3), MemoryAllocationResult::BufferLimitExceeded);
        
        let stats = manager.get_memory_stats();
        assert_eq!(stats.buffer_limit_violations, 1);
    }
    
    #[test]
    fn test_fragment_count_update() {
        let manager = FragmentMemoryManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Allocate memory for 2-fragment reassembly
        let request = MemoryAllocationRequest {
            session_id,
            fragment_id: 1,
            size: 1024,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request), MemoryAllocationResult::Success);
        
        // First fragment count update (should not complete)
        let result = manager.update_fragment_count(session_id, 1).unwrap();
        assert!(!result); // Not complete yet
        
        // Second fragment count update (should complete)
        let result = manager.update_fragment_count(session_id, 1).unwrap();
        assert!(result); // Should be complete now
    }
    
    #[test]
    fn test_session_cleanup() {
        let manager = FragmentMemoryManager::new();
        let session_id = SessionId::Bits32(0x12345678);
        
        // Allocate memory
        let request = MemoryAllocationRequest {
            session_id,
            fragment_id: 1,
            size: 1024,
            expected_fragments: 2,
            fragment_index: 0,
        };
        
        assert_eq!(manager.allocate_memory(&request), MemoryAllocationResult::Success);
        
        let stats = manager.get_memory_stats();
        assert_eq!(stats.active_sessions, 1);
        assert_eq!(stats.global_memory_usage, 1024);
        
        // Clean up session
        manager.cleanup_session(session_id);
        
        let stats = manager.get_memory_stats();
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.global_memory_usage, 0);
    }
