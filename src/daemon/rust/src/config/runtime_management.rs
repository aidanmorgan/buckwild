use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tracing::info;

// Import consolidated types from common crate
use buckwild_common::protocol::types::*;

use crate::logging::{LoggingConfig, LoggingManager, correlation::CorrelationId};
use crate::monitoring::MonitoringConfig;

/// Runtime configuration change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChangeEvent {
    pub timestamp: SystemTime,
    pub component: String,
    pub change_type: ConfigChangeType,
    pub old_value: Option<serde_json::Value>,
    pub new_value: serde_json::Value,
    pub correlation_id: Option<CorrelationId>,
    pub applied: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigChangeType {
    LoggingLevel,
    MonitoringEnabled,
    SnmpCommunity,
    MetricsInterval,
    SecurityPolicy,
    NetworkSettings,
    Custom(String),
}

/// Configuration validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn success() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            valid: false,
            errors: vec![message],
            warnings: Vec::new(),
        }
    }

    pub fn with_warning(mut self, warning: String) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Runtime configuration manager with atomic updates
pub struct RuntimeConfigManager {
    logging_config: Arc<RwLock<LoggingConfig>>,
    monitoring_config: Arc<RwLock<MonitoringConfig>>,
    custom_configs: Arc<DashMap<String, serde_json::Value>>,
    change_history: Arc<Mutex<Vec<ConfigChangeEvent>>>,
    logging_manager: Arc<LoggingManager>,
    validators: Arc<DashMap<String, Box<dyn ConfigValidator + Send + Sync>>>,
    max_history_size: MaxConnections,
}

/// Trait for configuration validators
pub trait ConfigValidator {
    fn validate(
        &self,
        old_value: Option<&serde_json::Value>,
        new_value: &serde_json::Value,
    ) -> ValidationResult;
    fn component_name(&self) -> &str;
}

impl RuntimeConfigManager {
    pub fn new(
        logging_config: LoggingConfig,
        monitoring_config: MonitoringConfig,
        logging_manager: Arc<LoggingManager>,
    ) -> Self {
        let manager = Self {
            logging_config: Arc::new(RwLock::new(logging_config)),
            monitoring_config: Arc::new(RwLock::new(monitoring_config)),
            custom_configs: Arc::new(DashMap::new()),
            change_history: Arc::new(Mutex::new(Vec::new())),
            logging_manager,
            validators: Arc::new(DashMap::new()),
            max_history_size: MaxConnections::from_raw(1000),
        };

        // Register default validators
        manager.register_default_validators();
        manager
    }

    /// Register default configuration validators
    fn register_default_validators(&self) {
        self.register_validator(Box::new(LoggingLevelValidator));
        self.register_validator(Box::new(MonitoringIntervalValidator));
        self.register_validator(Box::new(SnmpPortValidator));
    }

    /// Register a configuration validator
    pub fn register_validator(&self, validator: Box<dyn ConfigValidator + Send + Sync>) {
        let component = validator.component_name().to_string();
        self.validators.insert(component, validator);
    }

    /// Update logging configuration atomically
    pub async fn update_logging_config(
        &self,
        new_config: LoggingConfig,
        correlation_id: Option<CorrelationId>,
    ) -> Result<(), String> {
        let old_config = self.logging_config.read().await.clone();

        // Validate configuration
        let validation = self.validate_config_change(
            "logging",
            Some(&serde_json::to_value(&old_config).unwrap()),
            &serde_json::to_value(&new_config).unwrap(),
        );

        if !validation.valid {
            let error_msg = format!(
                "Logging configuration validation failed: {:?}",
                validation.errors
            );
            self.record_config_change(ConfigChangeEvent {
                timestamp: SystemTime::now(),
                component: "logging".to_string(),
                change_type: ConfigChangeType::LoggingLevel,
                old_value: Some(serde_json::to_value(&old_config).unwrap()),
                new_value: serde_json::to_value(&new_config).unwrap(),
                correlation_id: correlation_id.clone(),
                applied: false,
                error: Some(error_msg.clone()),
            });
            return Err(error_msg);
        }

        // Apply configuration atomically
        {
            let mut config_guard = self.logging_config.write().await;
            *config_guard = new_config.clone();
        }

        // Update logging manager
        self.logging_manager.update_config(new_config.clone());

        // Record successful change
        self.record_config_change(ConfigChangeEvent {
            timestamp: SystemTime::now(),
            component: "logging".to_string(),
            change_type: ConfigChangeType::LoggingLevel,
            old_value: Some(serde_json::to_value(&old_config).unwrap()),
            new_value: serde_json::to_value(&new_config).unwrap(),
            correlation_id,
            applied: true,
            error: None,
        });

        info!("Logging configuration updated successfully");
        Ok(())
    }

    /// Update monitoring configuration atomically
    pub async fn update_monitoring_config(
        &self,
        new_config: MonitoringConfig,
        correlation_id: Option<CorrelationId>,
    ) -> Result<(), String> {
        let old_config = self.monitoring_config.read().await.clone();

        // Validate configuration
        let validation = self.validate_config_change(
            "monitoring",
            Some(&serde_json::to_value(&old_config).unwrap()),
            &serde_json::to_value(&new_config).unwrap(),
        );

        if !validation.valid {
            let error_msg = format!(
                "Monitoring configuration validation failed: {:?}",
                validation.errors
            );
            self.record_config_change(ConfigChangeEvent {
                timestamp: SystemTime::now(),
                component: "monitoring".to_string(),
                change_type: ConfigChangeType::MonitoringEnabled,
                old_value: Some(serde_json::to_value(&old_config).unwrap()),
                new_value: serde_json::to_value(&new_config).unwrap(),
                correlation_id: correlation_id.clone(),
                applied: false,
                error: Some(error_msg.clone()),
            });
            return Err(error_msg);
        }

        // Apply configuration atomically
        {
            let mut config_guard = self.monitoring_config.write().await;
            *config_guard = new_config.clone();
        }

        // Record successful change
        self.record_config_change(ConfigChangeEvent {
            timestamp: SystemTime::now(),
            component: "monitoring".to_string(),
            change_type: ConfigChangeType::MonitoringEnabled,
            old_value: Some(serde_json::to_value(&old_config).unwrap()),
            new_value: serde_json::to_value(&new_config).unwrap(),
            correlation_id,
            applied: true,
            error: None,
        });

        info!("Monitoring configuration updated successfully");
        Ok(())
    }

    /// Update custom configuration value
    pub async fn update_custom_config(
        &self,
        key: String,
        value: serde_json::Value,
        correlation_id: Option<CorrelationId>,
    ) -> Result<(), String> {
        let old_value = self.custom_configs.get(&key).map(|v| v.clone());

        // Validate configuration
        let validation = self.validate_config_change(&key, old_value.as_ref(), &value);

        if !validation.valid {
            let error_msg = format!(
                "Custom configuration validation failed for {}: {:?}",
                key, validation.errors
            );
            self.record_config_change(ConfigChangeEvent {
                timestamp: SystemTime::now(),
                component: key.clone(),
                change_type: ConfigChangeType::Custom(key.clone()),
                old_value,
                new_value: value,
                correlation_id: correlation_id.clone(),
                applied: false,
                error: Some(error_msg.clone()),
            });
            return Err(error_msg);
        }

        // Apply configuration atomically
        self.custom_configs.insert(key.clone(), value.clone());

        // Record successful change
        self.record_config_change(ConfigChangeEvent {
            timestamp: SystemTime::now(),
            component: key.clone(),
            change_type: ConfigChangeType::Custom(key.clone()),
            old_value,
            new_value: value,
            correlation_id,
            applied: true,
            error: None,
        });

        info!("Custom configuration '{}' updated successfully", key);
        Ok(())
    }

    /// Get current logging configuration
    pub async fn get_logging_config(&self) -> LoggingConfig {
        self.logging_config.read().await.clone()
    }

    /// Get current monitoring configuration
    pub async fn get_monitoring_config(&self) -> MonitoringConfig {
        self.monitoring_config.read().await.clone()
    }

    /// Get custom configuration value
    pub fn get_custom_config(&self, key: &str) -> Option<serde_json::Value> {
        self.custom_configs.get(key).map(|v| v.clone())
    }

    /// Get all custom configuration values
    pub fn get_all_custom_configs(&self) -> HashMap<String, serde_json::Value> {
        self.custom_configs
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Validate configuration change
    fn validate_config_change(
        &self,
        component: &str,
        old_value: Option<&serde_json::Value>,
        new_value: &serde_json::Value,
    ) -> ValidationResult {
        if let Some(validator) = self.validators.get(component) {
            validator.validate(old_value, new_value)
        } else {
            // No validator registered, assume valid
            ValidationResult::success()
        }
    }

    /// Record configuration change in history
    fn record_config_change(&self, event: ConfigChangeEvent) {
        let mut history = self.change_history.lock();

        // Maintain history size limit
        if history.len() >= self.max_history_size.as_raw() as usize {
            history.remove(0);
        }

        history.push(event);
    }

    /// Get configuration change history
    pub fn get_change_history(&self) -> Vec<ConfigChangeEvent> {
        self.change_history.lock().clone()
    }

    /// Get recent configuration changes
    pub fn get_recent_changes(&self, since: SystemTime) -> Vec<ConfigChangeEvent> {
        self.change_history
            .lock()
            .iter()
            .filter(|event| event.timestamp >= since)
            .cloned()
            .collect()
    }

    /// Get configuration statistics
    pub fn get_config_statistics(&self) -> ConfigStatistics {
        let history = self.change_history.lock();
        let total_changes = history.len();
        let successful_changes = history.iter().filter(|e| e.applied).count();
        let failed_changes = total_changes - successful_changes;

        let last_change = history.last().map(|e| e.timestamp);

        ConfigStatistics {
            total_changes,
            successful_changes,
            failed_changes,
            last_change,
            custom_configs_count: MaxConnections::from_raw(self.custom_configs.len() as u32),
        }
    }

    /// Rollback to previous configuration (if available)
    pub async fn rollback_config(
        &self,
        component: &str,
        correlation_id: Option<CorrelationId>,
    ) -> Result<(), String> {
        let old_value = {
            let history = self.change_history.lock();

            // Find the last successful change for this component
            let last_change = history
                .iter()
                .rev()
                .find(|event| event.component == component && event.applied);

            match last_change {
                Some(change) => match &change.old_value {
                    Some(val) => Ok(val.clone()),
                    None => Err("No previous value available for rollback".to_string()),
                },
                None => Err(format!(
                    "No previous configuration found for component: {}",
                    component
                )),
            }
        }?;

        // Lock is now dropped, safe to await
        match component {
            "logging" => {
                let old_config: LoggingConfig = serde_json::from_value(old_value)
                    .map_err(|e| format!("Failed to deserialize old logging config: {}", e))?;
                self.update_logging_config(old_config, correlation_id).await
            }
            "monitoring" => {
                let old_config: MonitoringConfig = serde_json::from_value(old_value)
                    .map_err(|e| format!("Failed to deserialize old monitoring config: {}", e))?;
                self.update_monitoring_config(old_config, correlation_id)
                    .await
            }
            _ => {
                // Custom configuration
                self.update_custom_config(component.to_string(), old_value, correlation_id)
                    .await
            }
        }
    }
}

/// Configuration statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigStatistics {
    pub total_changes: usize,
    pub successful_changes: usize,
    pub failed_changes: usize,
    pub last_change: Option<SystemTime>,
    pub custom_configs_count: MaxConnections,
}

/// Default validators
struct LoggingLevelValidator;

impl ConfigValidator for LoggingLevelValidator {
    fn validate(
        &self,
        _old_value: Option<&serde_json::Value>,
        new_value: &serde_json::Value,
    ) -> ValidationResult {
        if let Ok(config) = serde_json::from_value::<LoggingConfig>(new_value.clone()) {
            let valid_levels = ["error", "warn", "info", "debug", "trace"];
            if valid_levels.contains(&config.level.as_str()) {
                ValidationResult::success()
            } else {
                ValidationResult::error(format!(
                    "Invalid logging level: {}. Must be one of: {:?}",
                    config.level, valid_levels
                ))
            }
        } else {
            ValidationResult::error("Invalid logging configuration format".to_string())
        }
    }

    fn component_name(&self) -> &str {
        "logging"
    }
}

struct MonitoringIntervalValidator;

impl ConfigValidator for MonitoringIntervalValidator {
    fn validate(
        &self,
        _old_value: Option<&serde_json::Value>,
        new_value: &serde_json::Value,
    ) -> ValidationResult {
        if let Ok(config) = serde_json::from_value::<MonitoringConfig>(new_value.clone()) {
            if config.metrics_update_interval_seconds
                >= MetricsInterval::from_raw(std::time::Duration::from_secs(1))
                    .as_raw()
                    .as_secs()
                && config.metrics_update_interval_seconds
                    <= MetricsInterval::from_raw(std::time::Duration::from_secs(3600))
                        .as_raw()
                        .as_secs()
            {
                ValidationResult::success()
            } else {
                ValidationResult::error(
                    "Metrics update interval must be between 1 and 3600 seconds".to_string(),
                )
            }
        } else {
            ValidationResult::error("Invalid monitoring configuration format".to_string())
        }
    }

    fn component_name(&self) -> &str {
        "monitoring"
    }
}

struct SnmpPortValidator;

impl ConfigValidator for SnmpPortValidator {
    fn validate(
        &self,
        _old_value: Option<&serde_json::Value>,
        new_value: &serde_json::Value,
    ) -> ValidationResult {
        if let Ok(config) = serde_json::from_value::<MonitoringConfig>(new_value.clone()) {
            if config.snmp_port >= Port::from_well_known(1024)
                && config.snmp_port <= Port::from_well_known(65535)
            {
                ValidationResult::success()
            } else {
                ValidationResult::error("SNMP port must be between 1024 and 65535".to_string())
                    .with_warning(
                        "Using privileged ports (< 1024) requires root privileges".to_string(),
                    )
            }
        } else {
            ValidationResult::error("Invalid monitoring configuration format".to_string())
        }
    }

    fn component_name(&self) -> &str {
        "monitoring"
    }
}
