use buckwild_daemon::config:hosts::parser::*;
use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;
    
    #[tokio::test]
    async fn test_hosts_config_parsing() {
        // Create a temporary file
        let mut file = NamedTempFile::new().unwrap();
        
        // Write test configuration
        let config = r#"
            [settings]
            default_psk_fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            tun_device = "tun0"
            update_interval_ms = 500
            ipv6_enabled = true
            max_connections = 1000
            connection_timeout_sec = 30

            [[hosts]]
            ip = "192.168.1.100"
            psk_fingerprint = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            description = "Server 1"
            port_range = "1024-65535"
            hmac_policy = "STRONG"
            priority = 200

            [[hosts]]
            ip = "2001:db8::1"
            psk_fingerprint = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            description = "IPv6 Server"
        "#;
        
        tokio::io::AsyncWriteExt::write_all(&mut file, config.as_bytes()).await.unwrap();
        
        // Parse configuration
        let config = HostsConfig::load(file.path()).await.unwrap();
        
        // Check settings
        assert_eq!(config.settings.tun_device, "tun0");
        assert_eq!(config.settings.update_interval_ms, 500);
        assert_eq!(config.settings.ipv6_enabled, true);
        assert_eq!(config.settings.max_connections, 1000);
        assert_eq!(config.settings.connection_timeout_sec, 30);
        assert_eq!(
            config.settings.default_psk_fingerprint,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        );
        
        // Check hosts
        assert_eq!(config.hosts.len(), 2);
        
        // Check first host
        let host1 = &config.hosts[0];
        assert_eq!(host1.ip, "192.168.1.100");
        assert_eq!(host1.psk_fingerprint, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        assert_eq!(host1.description, Some("Server 1".to_string()));
        assert_eq!(host1.port_range, Some("1024-65535".to_string()));
        assert_eq!(host1.hmac_policy, Some("STRONG".to_string()));
        assert_eq!(host1.priority, 200);
        
        // Check second host
        let host2 = &config.hosts[1];
        assert_eq!(host2.ip, "2001:db8::1");
        assert_eq!(host2.psk_fingerprint, "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
        assert_eq!(host2.description, Some("IPv6 Server".to_string()));
        assert_eq!(host2.port_range, None);
        assert_eq!(host2.hmac_policy, None);
        assert_eq!(host2.priority, 100); // Default value
        
        // Test get_host_by_ip
        let host = config.get_host_by_ip("192.168.1.100").unwrap();
        assert_eq!(host.description, Some("Server 1".to_string()));
        
        // Test host count
        assert_eq!(config.host_count(), 2);
    }
    
    #[tokio::test]
    async fn test_invalid_config() {
        // Test invalid IP
        let config = r#"
            [[hosts]]
            ip = "invalid-ip"
            psk_fingerprint = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        "#;
        
        let mut file = NamedTempFile::new().unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, config.as_bytes()).await.unwrap();
        
        let result = HostsConfig::load(file.path()).await;
        assert!(result.is_err());
        
        // Test invalid fingerprint
        let config = r#"
            [[hosts]]
            ip = "192.168.1.100"
            psk_fingerprint = "invalid"
        "#;
        
        let mut file = NamedTempFile::new().unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, config.as_bytes()).await.unwrap();
        
        let result = HostsConfig::load(file.path()).await;
        assert!(result.is_err());
        
        // Test duplicate hosts
        let config = r#"
            [[hosts]]
            ip = "192.168.1.100"
            psk_fingerprint = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            
            [[hosts]]
            ip = "192.168.1.100"
            psk_fingerprint = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        "#;
        
        let mut file = NamedTempFile::new().unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, config.as_bytes()).await.unwrap();
        
        let result = HostsConfig::load(file.path()).await;
        assert!(result.is_err());
    }
