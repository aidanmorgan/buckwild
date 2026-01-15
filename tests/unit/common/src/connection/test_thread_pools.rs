use buckwild_common::connection::thread_pools::*;
#[tokio::test]
    async fn test_thread_pool_creation() {
        let pools = ConnectionThreadPools::new(4, false);
        let connection_id = ConnectionId(1);
        
        // Assign pools to connection
        pools.assign_connection(connection_id).await.unwrap();
        
        // Verify pools exist
        assert!(pools.get_rx_pool(connection_id).is_some());
        assert!(pools.get_tx_pool(connection_id).is_some());
        
        // Remove pools
        pools.remove_connection(connection_id).await;
        
        // Verify pools are removed
        assert!(pools.get_rx_pool(connection_id).is_none());
        assert!(pools.get_tx_pool(connection_id).is_none());
    }
    
    #[tokio::test]
    async fn test_task_execution() {
        let pools = ConnectionThreadPools::new(4, false);
        let connection_id = ConnectionId(1);
        
        pools.assign_connection(connection_id).await.unwrap();
        
        // Test RX task execution
        let result = pools.execute_rx_task(connection_id, || {
            42
        }).await.unwrap();
        assert_eq!(result, 42);
        
        // Test TX task execution
        let result = pools.execute_tx_task(connection_id, || {
            "hello".to_string()
        }).await.unwrap();
        assert_eq!(result, "hello");
        
        // Test establishment task execution
        let result = pools.execute_establishment_task(|| {
            true
        }).await.unwrap();
        assert_eq!(result, true);
    }
    
    #[tokio::test]
    async fn test_cpu_affinity_manager() {
        let manager = CpuAffinityManager::new(true, Some(vec![0, 1, 2, 3]));
        let connection_id = ConnectionId(1);
        
        let assignment = manager.assign_connection_cores(connection_id, 2, 2).await.unwrap();
        
        assert_eq!(assignment.rx_cores.len(), 2);
        assert_eq!(assignment.tx_cores.len(), 2);
        assert_eq!(assignment.establishment_cores.len(), 1);
        
        // Verify assignment is stored
        let retrieved = manager.get_assignment(connection_id).await.unwrap();
        assert_eq!(retrieved.rx_cores, assignment.rx_cores);
        
        // Remove assignment
        manager.remove_connection_assignment(connection_id).await;
        assert!(manager.get_assignment(connection_id).await.is_none());
    }
