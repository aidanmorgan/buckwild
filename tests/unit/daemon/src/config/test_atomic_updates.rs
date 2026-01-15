use buckwild_daemon::config::atomic_updates::*;
#[derive(Clone, Debug, PartialEq)]
    struct TestConfig {
        value: i32,
        name: String,
    }
    
    struct TestValidator;
    
    impl ConfigValidator<TestConfig> for TestValidator {
        fn validate(&self, config: &TestConfig) -> Result<(), String> {
            if config.value < 0 {
                return Err("Value must be non-negative".to_string());
            }
            
            if config.name.is_empty() {
                return Err("Name must not be empty".to_string());
            }
            
            Ok(())
        }
    }
    
    #[test]
    fn test_atomic_config() {
        // Create initial configuration
        let initial_config = TestConfig {
            value: 42,
            name: "test".to_string(),
        };
        
        // Create atomic configuration
        let config = AtomicConfig::new(initial_config.clone());
        
        // Check initial value
        assert_eq!(config.get(), initial_config);
        
        // Update configuration
        let new_config = TestConfig {
            value: 100,
            name: "updated".to_string(),
        };
        
        config.update(new_config.clone()).unwrap();
        
        // Check updated value
        assert_eq!(config.get(), new_config);
        
        // Rollback
        config.rollback().unwrap();
        
        // Check rolled back value
        assert_eq!(config.get(), initial_config);
    }
    
    #[test]
    fn test_atomic_config_with_validator() {
        // Create initial configuration
        let initial_config = TestConfig {
            value: 42,
            name: "test".to_string(),
        };
        
        // Create atomic configuration with validator
        let config = AtomicConfig::with_validator(initial_config.clone(), TestValidator);
        
        // Try to update with invalid configuration
        let invalid_config = TestConfig {
            value: -1,
            name: "invalid".to_string(),
        };
        
        let result = config.update(invalid_config);
        assert!(result.is_err());
        
        // Check that configuration was not updated
        assert_eq!(config.get(), initial_config);
        
        // Update with valid configuration
        let valid_config = TestConfig {
            value: 100,
            name: "valid".to_string(),
        };
        
        config.update(valid_config.clone()).unwrap();
        
        // Check updated value
        assert_eq!(config.get(), valid_config);
    }
    
    #[tokio::test]
    async fn test_atomic_config_notifications() {
        // Create initial configuration
        let initial_config = TestConfig {
            value: 42,
            name: "test".to_string(),
        };
        
        // Create atomic configuration
        let config = Arc::new(AtomicConfig::new(initial_config.clone()));
        
        // Create subscriber
        let mut subscriber = config.subscribe();
        
        // Update in a separate task
        let config_clone = config.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            
            let new_config = TestConfig {
                value: 100,
                name: "updated".to_string(),
            };
            
            config_clone.update(new_config).unwrap();
        });
        
        // Wait for notification
        let result = subscriber.recv().await;
        assert!(result.is_ok());
        
        // Check updated value
        assert_eq!(config.get().value, 100);
    }
