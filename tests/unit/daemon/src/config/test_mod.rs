use buckwild_daemon::config::mod::*;
use std::fs::{self, File};
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};
    
    #[tokio::test]
    #[ignore] // Requires root privileges for routing
    async fn test_config_manager() {
        // Create temporary directory for PSKs
        let psk_dir = tempdir().unwrap();
        
        // Create PSK file
        let psk_path = psk_dir.path().join("test.psk");
        let mut file = File::create(&psk_path).unwrap();
        file.write_all(b"test psk data").unwrap();
        
        // Create hosts configuration file
        let hosts_file = NamedTempFile::new().unwrap();
        let hosts_path = hosts_file.path().to_path_buf();
        
        let hosts_content = r#"
            [settings]
            tun_device = "tun0"
            update_interval_ms = 500

            [[hosts]]
            ip = "192.168.1.100"
            psk_fingerprint = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            description = "Test Host"
        "#;
        
        fs::write(&hosts_path, hosts_content).unwrap();
        
        // Create configuration manager
        let manager = ConfigManager::new(
            hosts_path,
            psk_dir.path(),
            "tun0"
        ).await;
        
        // Check if creation succeeded
        assert!(manager.is_ok());
        
        if let Ok(manager) = manager {
            // Check hosts configuration
            let hosts_config = manager.get_hosts_config();
            assert_eq!(hosts_config.hosts.len(), 1);
            assert_eq!(hosts_config.hosts[0].ip, "192.168.1.100");
            
            // Check PSK count
            assert_eq!(manager.psk_count(), 1);
            
            // Get fingerprints
            let fingerprints = manager.get_all_fingerprints();
            assert_eq!(fingerprints.len(), 1);
        }
    }
