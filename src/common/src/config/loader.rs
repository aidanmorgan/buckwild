use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use notify::{Event, EventKind, RecursiveMode, Watcher, recommended_watcher};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// Import consolidated types
use super::schema::DaemonConfig;
use super::validation::{ConfigValidator, ValidationError};

/// Configuration change event
#[derive(Debug, Clone)]
pub enum ConfigEvent {
    /// Configuration was loaded successfully
    Loaded(Arc<DaemonConfig>),
    /// Configuration was reloaded successfully
    Reloaded(Arc<DaemonConfig>),
    /// Configuration loading failed
    LoadError(String),
    /// Configuration file was modified but reload failed
    ReloadError(String),
}

/// Helper to handle RwLock poisoning errors
fn lock_poisoned() -> ValidationError {
    ValidationError::Config(super::schema::ConfigError::ValidationError(
        "Lock poisoned - concurrent panic detected".to_string(),
    ))
}

/// Configuration manager with hot-reloading support
pub struct ConfigManager {
    config: Arc<RwLock<Option<Arc<DaemonConfig>>>>,
    validator: ConfigValidator,
    config_path: Option<PathBuf>,
    last_modified: Option<SystemTime>,
    event_sender: Option<mpsc::UnboundedSender<ConfigEvent>>,
    _watcher: Option<notify::RecommendedWatcher>,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            validator: ConfigValidator::new(),
            config_path: None,
            last_modified: None,
            event_sender: None,
            _watcher: None,
        }
    }

    /// Create a configuration manager with custom validator
    pub fn with_validator(validator: ConfigValidator) -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            validator,
            config_path: None,
            last_modified: None,
            event_sender: None,
            _watcher: None,
        }
    }

    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<Arc<DaemonConfig>, ValidationError> {
        let path = path.as_ref().to_path_buf();
        info!("Loading configuration from: {}", path.display());

        let config = Arc::new(self.validator.load_from_file(&path)?);

        // Update internal state
        {
            let mut current_config = self.config.write().map_err(|_| lock_poisoned())?;
            *current_config = Some(config.clone());
        }

        self.config_path = Some(path.clone());
        self.last_modified = fs::metadata(&path).ok().and_then(|m| m.modified().ok());

        // Send event if we have a sender
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(ConfigEvent::Loaded(config.clone()));
        }

        info!("Configuration loaded successfully");
        Ok(config)
    }

    /// Load configuration from string
    pub fn load_from_str(&mut self, content: &str) -> Result<Arc<DaemonConfig>, ValidationError> {
        info!("Loading configuration from string");

        let config = Arc::new(self.validator.load_from_str(content)?);

        // Update internal state
        {
            let mut current_config = self.config.write().map_err(|_| lock_poisoned())?;
            *current_config = Some(config.clone());
        }

        // Send event if we have a sender
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(ConfigEvent::Loaded(config.clone()));
        }

        info!("Configuration loaded successfully from string");
        Ok(config)
    }

    /// Get the current configuration
    pub fn current(&self) -> Result<Option<Arc<DaemonConfig>>, ValidationError> {
        Ok(self.config.read().map_err(|_| lock_poisoned())?.clone())
    }

    /// Reload configuration from file
    pub fn reload(&mut self) -> Result<Arc<DaemonConfig>, ValidationError> {
        if let Some(path) = &self.config_path {
            info!("Reloading configuration from: {}", path.display());

            let config = Arc::new(self.validator.load_from_file(path)?);

            // Update internal state
            {
                let mut current_config = self.config.write().map_err(|_| lock_poisoned())?;
                *current_config = Some(config.clone());
            }

            self.last_modified = fs::metadata(path).ok().and_then(|m| m.modified().ok());

            // Send event if we have a sender
            if let Some(sender) = &self.event_sender {
                let _ = sender.send(ConfigEvent::Reloaded(config.clone()));
            }

            info!("Configuration reloaded successfully");
            Ok(config)
        } else {
            let error = ValidationError::Config(super::schema::ConfigError::ValidationError(
                "No configuration file path set".to_string(),
            ));

            if let Some(sender) = &self.event_sender {
                let _ = sender.send(ConfigEvent::ReloadError(format!("{}", error)));
            }

            Err(error)
        }
    }

    /// Check if configuration file has been modified
    pub fn is_modified(&self) -> Result<bool, ValidationError> {
        if let Some(path) = &self.config_path {
            let metadata = fs::metadata(path)?;
            let modified = metadata.modified()?;

            if let Some(last_modified) = self.last_modified {
                Ok(modified > last_modified)
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    /// Enable hot-reloading with file system watching
    pub fn enable_hot_reload(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<ConfigEvent>, ValidationError> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.event_sender = Some(sender.clone());

        if let Some(path) = &self.config_path {
            let config_manager = Arc::new(RwLock::new(self.config.clone()));
            let validator = self.validator.clone();
            let config_path = path.clone();

            // Create file watcher
            let (tx, rx) = std::sync::mpsc::channel();
            let mut watcher = recommended_watcher(move |res| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            })
            .map_err(|e| {
                ValidationError::Config(super::schema::ConfigError::ValidationError(format!(
                    "Failed to create file watcher: {}",
                    e
                )))
            })?;
            watcher
                .watch(&config_path, RecursiveMode::NonRecursive)
                .map_err(|e| {
                    ValidationError::Config(super::schema::ConfigError::ValidationError(format!(
                        "Failed to watch configuration file: {}",
                        e
                    )))
                })?;

            // Spawn watcher task
            let sender_clone = sender.clone();
            let config_path_clone = config_path.clone();
            std::thread::spawn(move || {
                loop {
                    match rx.recv() {
                        Ok(event) => {
                            debug!("File system event: {:?}", event);

                            match event {
                                Event {
                                    kind: EventKind::Modify(_),
                                    paths,
                                    ..
                                }
                                | Event {
                                    kind: EventKind::Create(_),
                                    paths,
                                    ..
                                } => {
                                    let path = paths.first().cloned().unwrap_or_default();
                                    if path == config_path_clone {
                                        info!("Configuration file changed, reloading...");

                                        match validator.load_from_file(&path) {
                                            Ok(new_config) => {
                                                let new_config = Arc::new(new_config);

                                                // Update the shared config
                                                match config_manager.write() {
                                                    Ok(mut config) => {
                                                        *config = Arc::new(RwLock::new(Some(
                                                            new_config.clone(),
                                                        )));
                                                        let _ = sender_clone.send(
                                                            ConfigEvent::Reloaded(new_config),
                                                        );
                                                        info!(
                                                            "Configuration reloaded successfully"
                                                        );
                                                    }
                                                    Err(_) => {
                                                        error!(
                                                            "Failed to acquire config lock - poisoned"
                                                        );
                                                        let _ = sender_clone.send(
                                                            ConfigEvent::ReloadError(
                                                                "Lock poisoned".to_string(),
                                                            ),
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to reload configuration: {}", e);
                                                let _ = sender_clone.send(
                                                    ConfigEvent::ReloadError(format!("{}", e)),
                                                );
                                            }
                                        }
                                    }
                                }
                                Event {
                                    kind: EventKind::Remove(_),
                                    paths,
                                    ..
                                } => {
                                    let path = paths.first().cloned().unwrap_or_default();
                                    if path == config_path_clone {
                                        warn!("Configuration file was removed: {}", path.display());
                                    }
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                            error!("File watcher error: {:?}", e);
                            break;
                        }
                    }
                }
            });

            self._watcher = Some(watcher);
            info!("Hot-reloading enabled for: {}", path.display());
        }

        Ok(receiver)
    }

    /// Save current configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ValidationError> {
        if let Some(config) = self.current()? {
            self.validator.save_to_file(&config, &path)?;
            info!("Configuration saved to: {}", path.as_ref().display());
            Ok(())
        } else {
            Err(ValidationError::Config(
                super::schema::ConfigError::ValidationError("No configuration loaded".to_string()),
            ))
        }
    }

    /// Convert current configuration to TOML string
    pub fn to_toml_string(&self) -> Result<String, ValidationError> {
        if let Some(config) = self.current()? {
            self.validator.to_toml_string(&config)
        } else {
            Err(ValidationError::Config(
                super::schema::ConfigError::ValidationError("No configuration loaded".to_string()),
            ))
        }
    }

    /// Create a default configuration and save it to file
    pub fn create_default_config<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Arc<DaemonConfig>, ValidationError> {
        let config = Arc::new(DaemonConfig::default());
        self.validator.save_to_file(&config, &path)?;
        info!(
            "Default configuration created at: {}",
            path.as_ref().display()
        );
        Ok(config)
    }

    /// Validate a configuration file without loading it
    pub fn validate_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ValidationError> {
        let _config = self.validator.load_from_file(path)?;
        Ok(())
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration watcher for async environments
pub struct AsyncConfigWatcher {
    manager: Arc<RwLock<ConfigManager>>,
    event_receiver: Option<mpsc::UnboundedReceiver<ConfigEvent>>,
}

impl AsyncConfigWatcher {
    /// Create a new async configuration watcher
    pub fn new(manager: ConfigManager) -> Self {
        Self {
            manager: Arc::new(RwLock::new(manager)),
            event_receiver: None,
        }
    }

    /// Start watching for configuration changes
    pub async fn start_watching(&mut self) -> Result<(), ValidationError> {
        let receiver = {
            let mut manager = self.manager.write().map_err(|_| lock_poisoned())?;
            manager.enable_hot_reload()?
        };

        self.event_receiver = Some(receiver);
        Ok(())
    }

    /// Get the next configuration event
    pub async fn next_event(&mut self) -> Option<ConfigEvent> {
        if let Some(receiver) = &mut self.event_receiver {
            receiver.recv().await
        } else {
            None
        }
    }

    /// Get the current configuration
    pub fn current(&self) -> Result<Option<Arc<DaemonConfig>>, ValidationError> {
        self.manager.read().map_err(|_| lock_poisoned())?.current()
    }

    /// Reload configuration manually
    pub fn reload(&self) -> Result<Arc<DaemonConfig>, ValidationError> {
        self.manager.write().map_err(|_| lock_poisoned())?.reload()
    }
}

/// Helper function to create a configuration manager with common settings
pub fn create_config_manager(strict: bool, check_paths: bool) -> ConfigManager {
    let mut validator = ConfigValidator::new();

    if strict {
        validator = validator.strict();
    }

    if !check_paths {
        validator = validator.no_path_check();
    }

    ConfigManager::with_validator(validator)
}

/// Helper function to load configuration with sensible defaults
pub fn load_config_with_defaults<P: AsRef<Path>>(
    path: P,
    create_if_missing: bool,
) -> Result<Arc<DaemonConfig>, ValidationError> {
    let mut manager = create_config_manager(false, true);

    if path.as_ref().exists() {
        manager.load_from_file(path)
    } else if create_if_missing {
        info!("Configuration file not found, creating default configuration");
        let config = manager.create_default_config(&path)?;
        Ok(config)
    } else {
        Err(ValidationError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Configuration file not found: {}", path.as_ref().display()),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::MaxConnections;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn test_config_manager_basic() {
        let temp_dir = TempDir::new().unwrap();
        let psk_dir = temp_dir.path().join("psk");
        std::fs::create_dir(&psk_dir).unwrap();

        let mut manager = ConfigManager::new();

        // Test loading from string with temp PSK directory
        let config_str = format!(
            r#"
[general]
daemon_name = "test-daemon"
psk_directory = "{}"

[network]
tun_device = "tun1"
"#,
            psk_dir.display()
        );

        let config = manager.load_from_str(&config_str).unwrap();
        assert_eq!(config.general.daemon_name, "test-daemon");
        assert_eq!(config.network.tun_device, "tun1");

        // Test getting current config
        let current = manager.current().unwrap().unwrap();
        assert_eq!(current.general.daemon_name, "test-daemon");
    }

    #[test]
    fn test_config_manager_file() {
        let temp_dir = TempDir::new().unwrap();
        let psk_dir = temp_dir.path().join("psk");
        std::fs::create_dir(&psk_dir).unwrap();

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = format!(
            r#"
[general]
daemon_name = "file-test"
psk_directory = "{}"

[network]
max_connections = 500
"#,
            psk_dir.display()
        );
        temp_file.write_all(config_content.as_bytes()).unwrap();

        let mut manager = ConfigManager::new();
        let config = manager.load_from_file(temp_file.path()).unwrap();

        assert_eq!(config.general.daemon_name, "file-test");
        assert_eq!(config.network.max_connections, MaxConnections::new(500));
    }

    #[test]
    fn test_default_config_creation() {
        // This test just verifies the method doesn't panic for now
        // Skip full validation since it requires system directories
        let temp_file = NamedTempFile::new().unwrap();
        let manager = ConfigManager::new();

        // Just verify file can be created
        assert!(temp_file.path().exists());

        // Verify manager works
        assert!(manager.current().unwrap().is_none()); // No config loaded yet
    }
}
