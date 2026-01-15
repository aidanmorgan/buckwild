use buckwild_daemon::logging::sanitizer::*;
use serde_json::json;

    #[test]
    fn test_sanitizer_creation() {
        let sanitizer = LogSanitizer::new();
        // Salt should be different each time
        let sanitizer2 = LogSanitizer::new();
        assert_ne!(sanitizer.hash_salt, sanitizer2.hash_salt);
    }

    #[test]
    fn test_sensitive_field_redaction() {
        let sanitizer = LogSanitizer::new();
        let mut fields = HashMap::new();
        fields.insert("password".to_string(), json!("secret123"));
        fields.insert("api_key".to_string(), json!("key_abc123"));
        fields.insert("normal_field".to_string(), json!("normal_value"));

        let sanitized = sanitizer.sanitize_fields(fields);

        assert_eq!(sanitized.get("password").unwrap(), &json!("[REDACTED]"));
        assert_eq!(sanitized.get("api_key").unwrap(), &json!("[REDACTED]"));
        assert_eq!(sanitized.get("normal_field").unwrap(), &json!("normal_value"));
    }

    #[test]
    fn test_hash_field_processing() {
        let sanitizer = LogSanitizer::new();
        let mut fields = HashMap::new();
        fields.insert("session_id".to_string(), json!("session_12345"));
        fields.insert("user_id".to_string(), json!("user_67890"));

        let sanitized = sanitizer.sanitize_fields(fields);

        let session_value = sanitized.get("session_id").unwrap().as_str().unwrap();
        let user_value = sanitized.get("user_id").unwrap().as_str().unwrap();

        assert!(session_value.starts_with("hash:"));
        assert!(user_value.starts_with("hash:"));
        assert_ne!(session_value, user_value); // Different inputs should produce different hashes
    }

    #[test]
    fn test_ip_address_masking() {
        let sanitizer = LogSanitizer::new();
        let input = "Connection from 192.168.1.100 failed".to_string();
        let sanitized = sanitizer.sanitize_string(input);
        
        assert_eq!(sanitized, "Connection from 192.168.xxx.xxx failed");
    }

    #[test]
    fn test_ipv6_address_masking() {
        let sanitizer = LogSanitizer::new();
        let input = "IPv6 connection from 2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string();
        let sanitized = sanitizer.sanitize_string(input);
        
        assert!(sanitized.contains("2001:0db8:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"));
    }

    #[test]
    fn test_crypto_key_masking() {
        let sanitizer = LogSanitizer::new();
        let input = "Key: abcdef1234567890abcdef1234567890abcdef12".to_string();
        let sanitized = sanitizer.sanitize_string(input);
        
        assert!(sanitized.contains("[KEY_abcdef12]"));
    }

    #[test]
    fn test_nested_object_sanitization() {
        let sanitizer = LogSanitizer::new();
        let mut fields = HashMap::new();
        fields.insert("config".to_string(), json!({
            "password": "secret123",
            "session_id": "sess_456",
            "timeout": 30
        }));

        let sanitized = sanitizer.sanitize_fields(fields);
        let config = sanitized.get("config").unwrap().as_object().unwrap();

        assert_eq!(config.get("password").unwrap(), &json!("[REDACTED]"));
        assert!(config.get("session_id").unwrap().as_str().unwrap().starts_with("hash:"));
        assert_eq!(config.get("timeout").unwrap(), &json!(30));
    }

    #[test]
    fn test_array_sanitization() {
        let sanitizer = LogSanitizer::new();
        let mut fields = HashMap::new();
        fields.insert("connections".to_string(), json!([
            {"ip": "192.168.1.100", "status": "active"},
            {"ip": "10.0.0.5", "status": "inactive"}
        ]));

        let sanitized = sanitizer.sanitize_fields(fields);
        let connections = sanitized.get("connections").unwrap().as_array().unwrap();

        for conn in connections {
            let ip = conn.as_object().unwrap().get("ip").unwrap().as_str().unwrap();
            assert!(ip.contains("xxx.xxx"));
        }
    }

    #[test]
    fn test_sensitive_data_detection() {
        let sanitizer = LogSanitizer::new();
        
        assert!(sanitizer.contains_sensitive_data("IP: 192.168.1.100"));
        assert!(sanitizer.contains_sensitive_data("Key: abcdef1234567890abcdef1234567890"));
        assert!(!sanitizer.contains_sensitive_data("Normal log message"));
    }

    #[test]
    fn test_error_message_sanitization() {
        let sanitizer = LogSanitizer::new();
        let error = "Connection failed to 192.168.1.100 with key abcdef1234567890abcdef1234567890";
        let sanitized = sanitizer.sanitize_error_message(error);
        
        assert!(sanitized.contains("192.168.xxx.xxx"));
        assert!(sanitized.contains("[KEY_abcdef12]"));
    }

    #[test]
    fn test_sanitization_stats() {
        let sanitizer = LogSanitizer::new();
        let mut original = HashMap::new();
        original.insert("password".to_string(), json!("secret"));
        original.insert("session_id".to_string(), json!("sess_123"));
        original.insert("message".to_string(), json!("IP: 192.168.1.100"));
        original.insert("normal".to_string(), json!("value"));

        let sanitized = sanitizer.sanitize_fields(original.clone());
        let stats = sanitizer.get_sanitization_stats(&original, &sanitized);

        assert_eq!(stats.total_fields, 4);
        assert_eq!(stats.redacted_fields, 1); // password
        assert_eq!(stats.hashed_fields, 1);   // session_id
        assert_eq!(stats.masked_values, 1);   // IP in message
    }

    #[test]
    fn test_consistent_hashing() {
        let sanitizer = LogSanitizer::new();
        
        let hash1 = sanitizer.hash_string("test_value");
        let hash2 = sanitizer.hash_string("test_value");
        let hash3 = sanitizer.hash_string("different_value");
        
        assert_eq!(hash1, hash2); // Same input should produce same hash
        assert_ne!(hash1, hash3); // Different input should produce different hash
    }
