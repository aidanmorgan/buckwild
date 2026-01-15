use std::fs;
use std::path::Path;
// Network types and serialization available from protocol types
use thiserror::Error;
use toml;

// Import consolidated types
use super::schema::{ConfigError, DaemonConfig};
use crate::protocol::types::{
    CryptoThreadCount, HopInterval, KeyRotationInterval, MaxConnections, MaxPskSize, MtuSize, Port,
    ReplayWindowSize, RingBufferSize, WorkerThreadCount,
};
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parsing error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("Configuration validation error: {0}")]
    Config(#[from] ConfigError),

    #[error("Path validation error: {path} - {message}")]
    PathValidation { path: String, message: String },

    #[error("Network validation error: {0}")]
    NetworkValidation(String),

    #[error("Security validation error: {0}")]
    SecurityValidation(String),
}

/// Configuration validator
#[derive(Clone)]
pub struct ConfigValidator {
    strict_mode: bool,
    check_paths: bool,
    check_network: bool,
}

impl Default for ConfigValidator {
    fn default() -> Self {
        Self {
            strict_mode: false,
            check_paths: true,
            check_network: true,
        }
    }
}

impl ConfigValidator {
    /// Create a new validator with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable strict validation mode
    pub fn strict(mut self) -> Self {
        self.strict_mode = true;
        self
    }

    /// Disable path checking
    pub fn no_path_check(mut self) -> Self {
        self.check_paths = false;
        self
    }

    /// Disable network checking
    pub fn no_network_check(mut self) -> Self {
        self.check_network = false;
        self
    }

    /// Load and validate configuration from a file
    pub fn load_from_file<P: AsRef<Path>>(&self, path: P) -> Result<DaemonConfig, ValidationError> {
        let content = fs::read_to_string(path.as_ref())?;
        let config: DaemonConfig = toml::from_str(&content)?;
        self.validate(&config)?;
        Ok(config)
    }

    /// Load and validate configuration from a string
    pub fn load_from_str(&self, content: &str) -> Result<DaemonConfig, ValidationError> {
        let config: DaemonConfig = toml::from_str(content)?;
        self.validate(&config)?;
        Ok(config)
    }

    /// Validate a configuration object
    pub fn validate(&self, config: &DaemonConfig) -> Result<(), ValidationError> {
        // Basic schema validation
        config.validate()?;

        // Path validation
        if self.check_paths {
            self.validate_paths(config)?;
        }

        // Network validation
        if self.check_network {
            self.validate_network(config)?;
        }

        // Security validation
        self.validate_security(config)?;

        // Advanced validation
        self.validate_advanced(config)?;

        Ok(())
    }

    /// Validate path-related configuration
    fn validate_paths(&self, config: &DaemonConfig) -> Result<(), ValidationError> {
        // Check PSK directory
        let psk_dir = &config.general.psk_directory;
        if self.strict_mode {
            if !psk_dir.exists() {
                return Err(ValidationError::PathValidation {
                    path: psk_dir.display().to_string(),
                    message: "PSK directory does not exist".to_string(),
                });
            }
            if !psk_dir.is_dir() {
                return Err(ValidationError::PathValidation {
                    path: psk_dir.display().to_string(),
                    message: "PSK path is not a directory".to_string(),
                });
            }
        } else if let Some(parent) = psk_dir.parent() {
            // In non-strict mode, just check if parent directory exists
            if !parent.exists() {
                return Err(ValidationError::PathValidation {
                    path: parent.display().to_string(),
                    message: "PSK directory parent does not exist".to_string(),
                });
            }
        }

        // Check state directory
        let state_dir = &config.general.state_directory;
        if self.strict_mode {
            if !state_dir.exists() {
                return Err(ValidationError::PathValidation {
                    path: state_dir.display().to_string(),
                    message: "State directory does not exist".to_string(),
                });
            }
            if !state_dir.is_dir() {
                return Err(ValidationError::PathValidation {
                    path: state_dir.display().to_string(),
                    message: "State path is not a directory".to_string(),
                });
            }
        }

        // Check log file directory if logging to file is enabled
        if config.logging.log_to_file {
            let log_file = &config.logging.log_file;
            if let Some(log_dir) = log_file.parent() {
                if self.strict_mode && !log_dir.exists() {
                    return Err(ValidationError::PathValidation {
                        path: log_dir.display().to_string(),
                        message: "Log directory does not exist".to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate network-related configuration
    fn validate_network(&self, config: &DaemonConfig) -> Result<(), ValidationError> {
        // Validate port range
        let port_range = &config.network.port_range;
        if let Err(e) = parse_port_range(port_range) {
            return Err(ValidationError::NetworkValidation(format!(
                "Invalid port range '{}': {}",
                port_range, e
            )));
        }

        // Validate MTU
        let mtu = config.network.mtu;
        if mtu < MtuSize::from_raw(576) {
            return Err(ValidationError::NetworkValidation(
                "MTU cannot be less than 576 (IPv4 minimum)".to_string(),
            ));
        }
        if mtu > MtuSize::from_raw(9000) {
            return Err(ValidationError::NetworkValidation(
                "MTU cannot be greater than 9000 (jumbo frame limit)".to_string(),
            ));
        }

        // Validate connection limits
        if config.network.max_connections > MaxConnections::from_raw(65535) {
            return Err(ValidationError::NetworkValidation(
                "Maximum connections cannot exceed 65535".to_string(),
            ));
        }

        // Validate timeouts
        if config.network.connection_timeout_sec.as_secs() == 0 {
            return Err(ValidationError::NetworkValidation(
                "Connection timeout must be greater than 0".to_string(),
            ));
        }

        if config.network.port_hop_interval_ms < HopInterval::from_raw(50) {
            return Err(ValidationError::NetworkValidation(
                "Port hop interval must be at least 50ms".to_string(),
            ));
        }

        // Validate TUN device name
        let tun_name = &config.network.tun_device;
        if tun_name.is_empty() {
            return Err(ValidationError::NetworkValidation(
                "TUN device name cannot be empty".to_string(),
            ));
        }
        if tun_name.len() > 15 {
            return Err(ValidationError::NetworkValidation(
                "TUN device name cannot be longer than 15 characters".to_string(),
            ));
        }
        if !tun_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ValidationError::NetworkValidation(
                "TUN device name can only contain alphanumeric characters, underscores, and hyphens".to_string()
            ));
        }

        Ok(())
    }

    /// Validate security-related configuration
    fn validate_security(&self, config: &DaemonConfig) -> Result<(), ValidationError> {
        // Validate HMAC policy
        let hmac_policy = &config.security.default_hmac_policy;
        if !matches!(
            hmac_policy.to_uppercase().as_str(),
            "LIGHT" | "MEDIUM" | "STRONG"
        ) {
            return Err(ValidationError::SecurityValidation(format!(
                "Invalid HMAC policy '{}'. Must be LIGHT, MEDIUM, or STRONG",
                hmac_policy
            )));
        }

        // Validate key rotation interval
        if config.security.key_rotation_minutes == KeyRotationInterval::from_raw(0) {
            return Err(ValidationError::SecurityValidation(
                "Key rotation interval must be greater than 0".to_string(),
            ));
        }
        if config.security.key_rotation_minutes < KeyRotationInterval::from_raw(5) {
            return Err(ValidationError::SecurityValidation(
                "Key rotation interval should be at least 5 minutes for security".to_string(),
            ));
        }

        // Validate PSK size limits
        if config.security.max_psk_size == MaxPskSize::from_raw(0) {
            return Err(ValidationError::SecurityValidation(
                "Maximum PSK size must be greater than 0".to_string(),
            ));
        }
        if config.security.max_psk_size < MaxPskSize::from_raw(32) {
            return Err(ValidationError::SecurityValidation(
                "Maximum PSK size should be at least 32 bytes for security".to_string(),
            ));
        }
        if config.security.max_psk_size > MaxPskSize::from_raw(10 * 1024 * 1024) {
            return Err(ValidationError::SecurityValidation(
                "Maximum PSK size cannot exceed 10MB".to_string(),
            ));
        }

        // Validate replay protection window
        if config.security.replay_protection
            && config.security.replay_window_sec == ReplayWindowSize::from_raw(0)
        {
            return Err(ValidationError::SecurityValidation(
                "Replay protection window must be greater than 0 when replay protection is enabled"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Validate advanced configuration
    fn validate_advanced(&self, config: &DaemonConfig) -> Result<(), ValidationError> {
        // Validate thread counts
        if config.advanced.worker_threads == WorkerThreadCount::from_raw(0) {
            return Err(ValidationError::SecurityValidation(
                "Worker threads must be greater than 0".to_string(),
            ));
        }
        if config.advanced.worker_threads > WorkerThreadCount::from_raw(1024) {
            return Err(ValidationError::SecurityValidation(
                "Worker threads should not exceed 1024".to_string(),
            ));
        }

        if config.advanced.crypto_threads == CryptoThreadCount::from_raw(0) {
            return Err(ValidationError::SecurityValidation(
                "Crypto threads must be greater than 0".to_string(),
            ));
        }
        if config.advanced.crypto_threads > CryptoThreadCount::from_raw(256) {
            return Err(ValidationError::SecurityValidation(
                "Crypto threads should not exceed 256".to_string(),
            ));
        }

        // Validate ring buffer size
        if config.advanced.ring_buffer_kb == RingBufferSize::from_raw(0) {
            return Err(ValidationError::SecurityValidation(
                "Ring buffer size must be greater than 0".to_string(),
            ));
        }
        if config.advanced.ring_buffer_kb > RingBufferSize::from_raw(1024 * 1024) {
            return Err(ValidationError::SecurityValidation(
                "Ring buffer size should not exceed 1GB".to_string(),
            ));
        }

        // Validate metrics interval
        if config.advanced.enable_metrics && config.advanced.metrics_interval_sec.0.as_secs() == 0 {
            return Err(ValidationError::SecurityValidation(
                "Metrics interval must be greater than 0 when metrics are enabled".to_string(),
            ));
        }

        // Validate SNMP port
        if config.advanced.enable_snmp {
            let port = config.advanced.snmp_port;
            if port < Port::from_raw(1024) {
                return Err(ValidationError::SecurityValidation(
                    "SNMP port should be >= 1024 for non-privileged operation".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Save configuration to a file
    pub fn save_to_file<P: AsRef<Path>>(
        &self,
        config: &DaemonConfig,
        path: P,
    ) -> Result<(), ValidationError> {
        self.validate(config)?;
        let content = toml::to_string_pretty(config)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Convert configuration to TOML string
    pub fn to_toml_string(&self, config: &DaemonConfig) -> Result<String, ValidationError> {
        self.validate(config)?;
        Ok(toml::to_string_pretty(config)?)
    }
}

/// Parse a port range string into start and end ports
fn parse_port_range(range: &str) -> Result<(u16, u16), String> {
    if range.contains('-') {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return Err("Port range must be in format 'start-end'".to_string());
        }

        let start = parts[0]
            .parse::<u16>()
            .map_err(|_| "Invalid start port number".to_string())?;
        let end = parts[1]
            .parse::<u16>()
            .map_err(|_| "Invalid end port number".to_string())?;

        if start > end {
            return Err("Start port must be less than or equal to end port".to_string());
        }

        if start < 1024 {
            return Err("Port range must start at 1024 or higher".to_string());
        }

        Ok((start, end))
    } else {
        let port = range
            .parse::<u16>()
            .map_err(|_| "Invalid port number".to_string())?;

        if port < 1024 {
            return Err("Port must be 1024 or higher".to_string());
        }

        Ok((port, port))
    }
}

/// Configuration loader with hot-reloading support
pub struct ConfigLoader {
    validator: ConfigValidator,
    current_config: Option<DaemonConfig>,
    config_path: Option<std::path::PathBuf>,
}

impl ConfigLoader {
    /// Create a new configuration loader
    pub fn new() -> Self {
        Self {
            validator: ConfigValidator::new(),
            current_config: None,
            config_path: None,
        }
    }

    /// Create a configuration loader with custom validator
    pub fn with_validator(validator: ConfigValidator) -> Self {
        Self {
            validator,
            current_config: None,
            config_path: None,
        }
    }

    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<&DaemonConfig, ValidationError> {
        let config = self.validator.load_from_file(&path)?;
        self.config_path = Some(path.as_ref().to_path_buf());
        self.current_config = Some(config);
        // We just set current_config to Some, so this cannot be None
        self.current_config.as_ref().ok_or_else(|| {
            ValidationError::Config(ConfigError::ValidationError(
                "Internal error: config disappeared".to_string(),
            ))
        })
    }

    /// Reload configuration from the same file
    pub fn reload(&mut self) -> Result<&DaemonConfig, ValidationError> {
        if let Some(path) = &self.config_path {
            let config = self.validator.load_from_file(path)?;
            self.current_config = Some(config);
            // We just set current_config to Some, so this cannot be None
            Ok(self.current_config.as_ref().ok_or_else(|| {
                ValidationError::Config(ConfigError::ValidationError(
                    "Internal error: config disappeared".to_string(),
                ))
            })?)
        } else {
            Err(ValidationError::Config(ConfigError::ValidationError(
                "No configuration file path set".to_string(),
            )))
        }
    }

    /// Get the current configuration
    pub fn current(&self) -> Option<&DaemonConfig> {
        self.current_config.as_ref()
    }

    /// Check if configuration file has been modified
    pub fn is_modified(&self) -> Result<bool, ValidationError> {
        if let Some(path) = &self.config_path {
            let _metadata = fs::metadata(path)?;
            // This is a simplified check - in a real implementation,
            // you'd want to store and compare the last modification time
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::KeyRotationInterval;

    #[test]
    fn test_port_range_parsing() {
        assert_eq!(parse_port_range("8080").unwrap(), (8080, 8080));
        assert_eq!(parse_port_range("1024-65535").unwrap(), (1024, 65535));
        assert!(parse_port_range("65536").is_err());
        assert!(parse_port_range("1000-2000").is_err()); // Below 1024
        assert!(parse_port_range("2000-1000").is_err()); // Start > end
    }

    #[test]
    fn test_config_validation() {
        let mut config = DaemonConfig::default();
        let validator = ConfigValidator::new().no_path_check().no_network_check();

        // Valid config should pass
        assert!(validator.validate(&config).is_ok());

        // Invalid port range should fail
        config.network.port_range = "invalid".to_string();
        assert!(validator.validate(&config).is_err());

        // Reset and test other validations
        config.network.port_range = "1024-65535".to_string();
        config.security.key_rotation_minutes = KeyRotationInterval::new(0);
        assert!(validator.validate(&config).is_err());
    }

    #[test]
    fn test_toml_serialization() {
        let config = DaemonConfig::default();
        let validator = ConfigValidator::new().no_path_check().no_network_check();

        let toml_str = validator.to_toml_string(&config).unwrap();
        assert!(toml_str.contains("[general]"));
        assert!(toml_str.contains("[network]"));
        assert!(toml_str.contains("[security]"));
        assert!(toml_str.contains("[logging]"));
        assert!(toml_str.contains("[advanced]"));
    }
}
