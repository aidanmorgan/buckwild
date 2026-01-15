use std::sync::Arc;

use parking_lot::RwLock;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{debug, info, instrument, warn};

// Import consolidated types from common crate
use buckwild_common::protocol::types::*;

/// Errors that can occur during atomic configuration updates
#[derive(Error, Debug)]
pub enum AtomicUpdateError {
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Update rejected: {0}")]
    UpdateRejected(String),

    #[error("Update notification failed")]
    NotificationFailed,
}

/// Trait for configuration validation
pub trait ConfigValidator<T> {
    /// Validate a configuration
    fn validate(&self, config: &T) -> Result<(), String>;
}

/// Default validator that always succeeds
pub struct NoopValidator;

impl<T> ConfigValidator<T> for NoopValidator {
    fn validate(&self, _config: &T) -> Result<(), String> {
        Ok(())
    }
}

/// Atomic configuration holder with update notifications
pub struct AtomicConfig<T: Clone + Send + Sync + 'static> {
    /// Current configuration
    config: Arc<RwLock<T>>,

    /// Previous configuration for rollback
    previous_config: Arc<RwLock<Option<T>>>,

    /// Update notification channel
    update_sender: broadcast::Sender<()>,

    /// Configuration validator
    validator: Box<dyn ConfigValidator<T> + Send + Sync>,
}

impl<T: Clone + Send + Sync + 'static> AtomicConfig<T> {
    /// Create a new atomic configuration
    pub fn new(initial_config: T) -> Self {
        let (update_sender, _) = broadcast::channel(MaxConnections::from_raw(16).as_raw() as usize);

        Self {
            config: Arc::new(RwLock::new(initial_config)),
            previous_config: Arc::new(RwLock::new(None)),
            update_sender,
            validator: Box::new(NoopValidator),
        }
    }

    /// Create a new atomic configuration with a validator
    pub fn with_validator(
        initial_config: T,
        validator: impl ConfigValidator<T> + Send + Sync + 'static,
    ) -> Self {
        let (update_sender, _) = broadcast::channel(MaxConnections::from_raw(16).as_raw() as usize);

        Self {
            config: Arc::new(RwLock::new(initial_config)),
            previous_config: Arc::new(RwLock::new(None)),
            update_sender,
            validator: Box::new(validator),
        }
    }

    /// Get the current configuration
    pub fn get(&self) -> T {
        self.config.read().clone()
    }

    /// Get a reference to the current configuration
    pub fn get_ref(&self) -> Arc<RwLock<T>> {
        self.config.clone()
    }

    /// Update the configuration
    #[instrument(skip(self, new_config), err)]
    pub fn update(&self, new_config: T) -> Result<(), AtomicUpdateError> {
        // Validate new configuration
        if let Err(e) = self.validator.validate(&new_config) {
            return Err(AtomicUpdateError::ValidationFailed(e));
        }

        // Store previous configuration for rollback
        let current = self.config.read().clone();
        *self.previous_config.write() = Some(current);

        // Update configuration
        *self.config.write() = new_config;

        // Notify listeners
        if self.update_sender.send(()).is_err() {
            warn!("Failed to notify configuration update listeners");
        }

        debug!("Configuration updated successfully");

        Ok(())
    }

    /// Update the configuration with a modifier function
    #[instrument(skip(self, modifier), err)]
    pub fn update_with<F>(&self, modifier: F) -> Result<(), AtomicUpdateError>
    where
        F: FnOnce(&mut T),
    {
        // Get current configuration
        let mut current = self.config.read().clone();

        // Apply modifier
        modifier(&mut current);

        // Update with modified configuration
        self.update(current)
    }

    /// Rollback to the previous configuration
    #[instrument(skip(self), err)]
    pub fn rollback(&self) -> Result<(), AtomicUpdateError> {
        // Get previous configuration
        let previous = self.previous_config.read().clone();

        if let Some(previous_config) = previous {
            // Update configuration
            *self.config.write() = previous_config;

            // Clear previous configuration
            *self.previous_config.write() = None;

            // Notify listeners
            if self.update_sender.send(()).is_err() {
                warn!("Failed to notify configuration rollback listeners");
            }

            info!("Configuration rolled back successfully");

            Ok(())
        } else {
            Err(AtomicUpdateError::UpdateRejected(
                "No previous configuration available for rollback".to_string(),
            ))
        }
    }

    /// Subscribe to configuration updates
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.update_sender.subscribe()
    }
}

/// Atomic configuration reference for sharing
pub struct AtomicConfigRef<T: Clone + Send + Sync + 'static> {
    /// Reference to the atomic configuration
    config: Arc<AtomicConfig<T>>,
}

impl<T: Clone + Send + Sync + 'static> Clone for AtomicConfigRef<T> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> AtomicConfigRef<T> {
    /// Create a new atomic configuration reference
    pub fn new(config: Arc<AtomicConfig<T>>) -> Self {
        Self { config }
    }

    /// Get the current configuration
    pub fn get(&self) -> T {
        self.config.get()
    }

    /// Subscribe to configuration updates
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.config.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct TestConfig {
        value: u32,
        name: String,
    }

    struct TestValidator {
        max_value: u32,
    }

    impl ConfigValidator<TestConfig> for TestValidator {
        fn validate(&self, config: &TestConfig) -> Result<(), String> {
            if config.value > self.max_value {
                return Err(format!(
                    "Value {} exceeds maximum {}",
                    config.value, self.max_value
                ));
            }
            if config.name.is_empty() {
                return Err("Name cannot be empty".to_string());
            }
            Ok(())
        }
    }

    #[test]
    fn test_valid_config_parsing() {
        let config = TestConfig {
            value: 42,
            name: "test".to_string(),
        };

        let validator = TestValidator { max_value: 100 };
        let atomic_config = AtomicConfig::with_validator(config.clone(), validator);

        let retrieved = atomic_config.get();
        assert_eq!(retrieved.value, 42);
        assert_eq!(retrieved.name, "test");
    }

    #[test]
    fn test_invalid_config_rejection() {
        let valid_config = TestConfig {
            value: 50,
            name: "valid".to_string(),
        };

        let validator = TestValidator { max_value: 100 };
        let atomic_config = AtomicConfig::with_validator(valid_config, validator);

        let invalid_config = TestConfig {
            value: 150,
            name: "invalid".to_string(),
        };

        let result = atomic_config.update(invalid_config);
        assert!(result.is_err());

        match result {
            Err(AtomicUpdateError::ValidationFailed(msg)) => {
                assert!(msg.contains("exceeds maximum"));
            }
            _ => panic!("Expected ValidationFailed error"),
        }

        let current = atomic_config.get();
        assert_eq!(current.value, 50);
        assert_eq!(current.name, "valid");
    }
}
