use buckwild_common::engines:recovery::coordination::*;
use std::time::Duration;
    
    #[tokio::test]
    async fn test_recovery_coordination_creation() {
        let coordination = RecoveryCoordination::new();
        let stats = coordination.get_coordination_stats().await;
        
        assert_eq!(stats.total_operations, 0);
        assert_eq!(stats.active_operations, 0);
    }
    
    #[tokio::test]
    async fn test_start_and_complete_operation() {
        let coordination = RecoveryCoordination::new();
        let session_id = SessionId::new(1, crate::types::SessionIdLength::Bits64);
        
        // Start operation
        let mut rx = coordination.start_recovery_operation(
            session_id,
            RecoveryPacketType::TimeSync,
            Duration::from_secs(10),
            3,
        ).await.unwrap();
        
        let stats = coordination.get_coordination_stats().await;
        assert_eq!(stats.active_operations, 1);
        
        // Complete operation
        coordination.complete_recovery_operation(
            session_id,
            RecoveryPacketType::TimeSync,
            RecoveryResult::Success,
        ).await.unwrap();
        
        // Check result
        let result = rx.recv().await.unwrap();
        assert_eq!(result, RecoveryResult::Success);
        
        let stats = coordination.get_coordination_stats().await;
        assert_eq!(stats.active_operations, 0);
        assert_eq!(stats.successful_operations, 1);
    }
    
    #[tokio::test]
    async fn test_cancel_operation() {
        let coordination = RecoveryCoordination::new();
        let session_id = SessionId::new(1, crate::types::SessionIdLength::Bits64);
        
        // Start operation
        let mut rx = coordination.start_recovery_operation(
            session_id,
            RecoveryPacketType::SequenceRepair,
            Duration::from_secs(10),
            3,
        ).await.unwrap();
        
        // Cancel operation
        coordination.cancel_recovery_operation(
            session_id,
            RecoveryPacketType::SequenceRepair,
        ).await.unwrap();
        
        // Check result
        let result = rx.recv().await.unwrap();
        assert_eq!(result, RecoveryResult::Failed);
        
        let stats = coordination.get_coordination_stats().await;
        assert_eq!(stats.active_operations, 0);
        assert_eq!(stats.failed_operations, 1);
    }
    
    #[tokio::test]
    async fn test_packet_handler_registration() {
        let coordination = RecoveryCoordination::new();
        let session_id = SessionId::new(1, crate::types::SessionIdLength::Bits64);
        
        // Register handler
        let mut rx = coordination.register_packet_handler(session_id).await.unwrap();
        
        // Send packet
        let test_data = vec![1, 2, 3, 4];
        coordination.handle_incoming_packet(session_id, test_data.clone()).await.unwrap();
        
        // Receive packet
        let received_data = rx.recv().await.unwrap();
        assert_eq!(received_data, test_data);
        
        // Unregister handler
        coordination.unregister_packet_handler(&session_id).await;
    }
    
    #[tokio::test]
    async fn test_cleanup_expired_operations() {
        let coordination = RecoveryCoordination::new();
        let session_id = SessionId::new(1, crate::types::SessionIdLength::Bits64);
        
        // Start operation with very short timeout
        let _rx = coordination.start_recovery_operation(
            session_id,
            RecoveryPacketType::Emergency,
            Duration::from_millis(1), // Very short timeout
            1,
        ).await.unwrap();
        
        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Cleanup expired operations
        let expired_count = coordination.cleanup_expired_operations().await.unwrap();
        assert_eq!(expired_count, 1);
        
        let stats = coordination.get_coordination_stats().await;
        assert_eq!(stats.active_operations, 0);
        assert_eq!(stats.timeout_operations, 1);
    }
