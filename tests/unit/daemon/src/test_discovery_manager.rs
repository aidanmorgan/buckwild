use buckwild_daemon::discovery_manager::*;
use crate::crypto::SecureBytes;
    use crate::logging::{LoggingManager, LoggingConfig};
    
    #[tokio::test]
    async fn test_discovery_manager_creation() {
        let manager = DiscoveryManager::new();
        let stats = manager.get_statistics().await;
        
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.active_retry_sessions, 0);
        assert_eq!(stats.cached_psks, 0);
        assert_eq!(stats.local_psks, 0);
    }
    
    #[tokio::test]
    async fn test_add_remove_psk() {
        let manager = DiscoveryManager::new();
        let fingerprint = [1u8; 32];
        let psk = Arc::new(SecureBytes::new(b"test_psk"));
        
        manager.add_psk(fingerprint, psk.clone()).await;
        
        let stats = manager.get_statistics().await;
        assert_eq!(stats.local_psks, 1);
        assert_eq!(stats.cached_psks, 1);
        
        manager.remove_psk(&fingerprint).await;
        
        let stats = manager.get_statistics().await;
        assert_eq!(stats.local_psks, 0);
        assert_eq!(stats.cached_psks, 0);
    }
    
    #[tokio::test]
    async fn test_discovery_manager_start() {
        let manager = DiscoveryManager::new();
        
        // Should be able to start
        assert!(manager.start().await.is_ok());
        
        // Should not be able to start again (receiver already taken)
        assert!(manager.start().await.is_err());
    }
    
    #[tokio::test]
    async fn test_logging_integration() {
        let logging_config = LoggingConfig::default();
        let logging_manager = Arc::new(LoggingManager::new(logging_config).unwrap());
        let mut manager = DiscoveryManager::new();
        
        // Set logging manager
        manager.set_logging_manager(logging_manager);
        
        // Test operations with logging
        let fingerprint = [1u8; 32];
        let psk = Arc::new(SecureBytes::new(b"test_psk"));
        
        manager.add_psk(fingerprint, psk).await;
        manager.remove_psk(&fingerprint).await;
        
        let _stats = manager.get_statistics().await;
    }
