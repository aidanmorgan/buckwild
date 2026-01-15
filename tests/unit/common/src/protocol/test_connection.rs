use buckwild_common::protocol::connection::*;
use std::net::{IpAddr, Ipv4Addr};
    use tokio::runtime::Runtime;

    fn create_test_addresses() -> (SocketAddr, SocketAddr) {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000);
        (local_addr, remote_addr)
    }

    #[tokio::test]
    async fn test_connection_engine_creation() {
        let session_manager = Arc::new(SessionManager::default());
        let engine = EcdhConnectionEngine::new(session_manager);
        
        assert_eq!(engine.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_connection_context() {
        let (local_addr, remote_addr) = create_test_addresses();
        let params = ConnectionParams::default();
        
        let mut context = ConnectionContext::new(local_addr, remote_addr, params);
        
        assert_eq!(context.state, ConnectionState::Closed);
        assert_eq!(context.local_addr, local_addr);
        assert_eq!(context.remote_addr, remote_addr);
        assert_eq!(context.retry_count, 0);
        assert!(context.can_retry());
        
        context.increment_retry();
        assert_eq!(context.retry_count, 1);
        
        context.update_activity();
        assert!(!context.is_expired());
    }

    #[tokio::test]
    async fn test_session_salt_creation() {
        let session_manager = Arc::new(SessionManager::default());
        let engine = EcdhConnectionEngine::new(session_manager);
        let (local_addr, remote_addr) = create_test_addresses();
        let params = ConnectionParams::default();
        
        let mut context = ConnectionContext::new(local_addr, remote_addr, params);
        context.key_exchange_id = Some(0x1234);
        context.client_nonce = Some([1u8; 16]);
        context.server_nonce = Some([2u8; 16]);
        
        let session_id = HeaderSessionId::Bits32(0x12345678);
        let salt = engine.create_session_salt(&context, &session_id).unwrap();
        
        assert_eq!(salt.len(), 32); // SHA256 output
        
        // Salt should be deterministic for same inputs
        let salt2 = engine.create_session_salt(&context, &session_id).unwrap();
        assert_eq!(salt, salt2);
        
        // Salt should be different for different session IDs
        let session_id2 = HeaderSessionId::Bits32(0x87654321);
        let salt3 = engine.create_session_salt(&context, &session_id2).unwrap();
        assert_ne!(salt, salt3);
    }

    #[tokio::test]
    async fn test_verification_hash_creation() {
        let session_manager = Arc::new(SessionManager::default());
        let engine = EcdhConnectionEngine::new(session_manager);
        let (local_addr, remote_addr) = create_test_addresses();
        let params = ConnectionParams::default();
        
        let mut context = ConnectionContext::new(local_addr, remote_addr, params);
        context.shared_secret = Some(SecureBytes::from_slice(&[1u8; 32]).unwrap());
        context.key_exchange_id = Some(0x1234);
        context.client_nonce = Some([1u8; 16]);
        context.server_nonce = Some([2u8; 16]);
        context.server_challenge = Some([3u8; 32]);
        
        let hash = engine.create_verification_hash(&context).unwrap();
        
        assert_eq!(hash.len(), 32); // SHA256 output
        
        // Hash should be deterministic for same inputs
        let hash2 = engine.create_verification_hash(&context).unwrap();
        assert_eq!(hash, hash2);
        
        // Hash should be different for different shared secrets
        context.shared_secret = Some(SecureBytes::from_slice(&[2u8; 32]).unwrap());
        let hash3 = engine.create_verification_hash(&context).unwrap();
        assert_ne!(hash, hash3);
    }

    #[tokio::test]
    async fn test_parameter_negotiation() {
        let session_manager = Arc::new(SessionManager::default());
        let engine = EcdhConnectionEngine::new(session_manager);
        
        let local_params = ConnectionParams {
            version_byte: VersionByte::new(SessionIdLength::Bits32, TimestampConfig::Bits24),
            hmac_policy: HmacPolicy::Medium,
            ..Default::default()
        };
        
        let remote_version = VersionByte::new(SessionIdLength::Bits64, TimestampConfig::Bits32);
        let remote_hmac = HmacPolicy::Strong;
        
        let negotiated = engine.negotiate_session_parameters(
            &local_params,
            remote_version,
            remote_hmac,
        ).await.unwrap();
        
        // Should choose the larger session ID length
        assert_eq!(negotiated.version_byte.session_id_length(), SessionIdLength::Bits64);
        // Should choose the stronger HMAC policy
        assert_eq!(negotiated.hmac_policy, HmacPolicy::Strong);
    }

    #[tokio::test]
    async fn test_cleanup_expired_connections() {
        let session_manager = Arc::new(SessionManager::default());
        let engine = EcdhConnectionEngine::new(session_manager);
        let (local_addr, remote_addr) = create_test_addresses();
        
        // Create a connection context with very short timeout
        let params = ConnectionParams {
            timeout: Duration::from_millis(1),
            ..Default::default()
        };
        
        let context = Arc::new(Mutex::new(ConnectionContext::new(local_addr, remote_addr, params)));
        
        // Add to connections
        {
            let mut connections = engine.connections.write().await;
            connections.insert((local_addr, remote_addr), context);
        }
        
        assert_eq!(engine.connection_count().await, 1);
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Clean up
        let removed = engine.cleanup_expired_connections().await;
        assert_eq!(removed, 1);
        assert_eq!(engine.connection_count().await, 0);
    }
