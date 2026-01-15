use buckwild_common::config::schema::*;
#[test]
    fn test_default_config() {
        let config = DaemonConfig::default();
        
        // Validate default configuration
        assert!(config.validate().is_ok());
        
        // Check default values
        assert_eq!(config.general.daemon_name, "buckwild");
        assert_eq!(config.network.tun_device, "tun0");
        assert_eq!(config.security.default_hmac_policy, "MEDIUM");
        assert_eq!(config.logging.log_level, "info");
        assert_eq!(config.advanced.worker_threads, num_cpus::get());
    }
    
    #[test]
    fn test_invalid_config() {
        // Test invalid port range
        let mut config = DaemonConfig::default();
        config.network.port_range = "invalid".to_string();
        assert!(config.validate().is_err());
        
        // Test invalid HMAC policy
        let mut config = DaemonConfig::default();
        config.security.default_hmac_policy = "INVALID".to_string();
        assert!(config.validate().is_err());
        
        // Test invalid log level
        let mut config = DaemonConfig::default();
        config.logging.log_level = "INVALID".to_string();
        assert!(config.validate().is_err());
        
        // Test invalid MTU
        let mut config = DaemonConfig::default();
        config.network.mtu = 100;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_port_range_validation() {
        // Valid ranges
        assert!(is_valid_port_range("1024-65535"));
        assert!(is_valid_port_range("8080-8090"));
        assert!(is_valid_port_range("1024"));
        
        // Invalid ranges
        assert!(!is_valid_port_range("invalid"));
        assert!(!is_valid_port_range("1023-65535")); // Below minimum
        assert!(!is_valid_port_range("1024-65536")); // Above maximum
        assert!(!is_valid_port_range("5000-4000")); // End before start
        assert!(!is_valid_port_range("1024-5000-6000")); // Too many parts
    }
    
    #[test]
    fn test_hmac_policy_validation() {
        // Valid policies
        assert!(is_valid_hmac_policy("LIGHT"));
        assert!(is_valid_hmac_policy("MEDIUM"));
        assert!(is_valid_hmac_policy("STRONG"));
        assert!(is_valid_hmac_policy("light")); // Case insensitive
        
        // Invalid policies
        assert!(!is_valid_hmac_policy("INVALID"));
        assert!(!is_valid_hmac_policy(""));
    }
    
    #[test]
    fn test_log_level_validation() {
        // Valid levels
        assert!(is_valid_log_level("trace"));
        assert!(is_valid_log_level("debug"));
        assert!(is_valid_log_level("info"));
        assert!(is_valid_log_level("warn"));
        assert!(is_valid_log_level("error"));
        assert!(is_valid_log_level("INFO")); // Case insensitive
        
        // Invalid levels
        assert!(!is_valid_log_level("INVALID"));
        assert!(!is_valid_log_level(""));
    }
