use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use thiserror::Error;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep;
use tracing::{debug, error, info, instrument};

// Import consolidated types from common crate
use buckwild_common::protocol::types::MetricsInterval;

use crate::config::psk::fingerprint::FingerprintError;
use crate::crypto::secure_storage::SecureBytes;

/// Errors that can occur during PSK directory operations
#[derive(Error, Debug)]
pub enum PskDirectoryError {
    #[error("Failed to watch directory: {0}")]
    WatchError(#[from] notify::Error),

    #[error("Failed to read PSK file: {0}")]
    FileReadError(#[from] std::io::Error),

    #[error("Failed to calculate fingerprint: {0}")]
    FingerprintError(#[from] FingerprintError),

    #[error("Watcher channel closed")]
    WatcherChannelClosed,

    #[error("Event processing error: {0}")]
    EventProcessingError(String),
}

/// Configuration for PSK directory monitoring
#[derive(Debug, Clone)]
pub struct PskDirectoryConfig {
    /// Base directory for PSK files
    pub base_dir: PathBuf,

    /// Debounce duration for rapid changes
    pub debounce_ms: MetricsInterval,

    /// Whether to recursively monitor subdirectories
    pub recursive: bool,
}

impl Default for PskDirectoryConfig {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("/etc/buckwild/psk"),
            debounce_ms: MetricsInterval::from_raw(std::time::Duration::from_millis(100)),
            recursive: true,
        }
    }
}

/// Manages PSK directory monitoring and loading
pub struct PskDirectoryMonitor {
    /// Configuration for the monitor
    config: PskDirectoryConfig,

    /// Map of PSK fingerprints to PSK data
    psks: Arc<DashMap<String, Arc<SecureBytes>>>,

    /// Map of file paths to fingerprints
    path_to_fingerprint: Arc<DashMap<PathBuf, String>>,

    /// Channel for sending events to the processing loop
    event_sender: UnboundedSender<Result<Event, notify::Error>>,

    /// Watcher instance
    _watcher: RecommendedWatcher,
}

impl PskDirectoryMonitor {
    /// Create a new PSK directory monitor
    #[instrument(skip(fingerprint_calculator), err)]
    pub fn new(
        config: PskDirectoryConfig,
        fingerprint_calculator: Arc<crate::config::psk::fingerprint::FingerprintCalculator>,
    ) -> Result<Self, PskDirectoryError> {
        let psks = Arc::new(DashMap::new());
        let path_to_fingerprint = Arc::new(DashMap::new());

        // Create channel for event processing
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        // Create watcher
        let watcher = Self::create_watcher(event_sender.clone())?;

        // Create monitor instance
        let monitor = Self {
            config,
            psks: psks.clone(),
            path_to_fingerprint: path_to_fingerprint.clone(),
            event_sender,
            _watcher: watcher,
        };

        // Start event processing loop
        Self::start_event_loop(
            event_receiver,
            monitor.config.clone(),
            psks,
            path_to_fingerprint,
            fingerprint_calculator,
        );

        Ok(monitor)
    }

    /// Create file system watcher
    fn create_watcher(
        event_sender: UnboundedSender<Result<Event, notify::Error>>,
    ) -> Result<RecommendedWatcher, PskDirectoryError> {
        let watcher = notify::recommended_watcher(move |event| {
            let _ = event_sender.send(event);
        })?;

        Ok(watcher)
    }

    /// Start watching the PSK directory
    #[instrument(skip(self), err)]
    pub fn start_watching(&mut self) -> Result<(), PskDirectoryError> {
        let watch_mode = if self.config.recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        info!(
            path = %self.config.base_dir.as_path().display(),
            recursive = self.config.recursive,
            "Starting PSK directory monitoring"
        );

        self._watcher
            .watch(self.config.base_dir.as_path(), watch_mode)?;

        Ok(())
    }

    /// Start the event processing loop
    fn start_event_loop(
        mut event_receiver: UnboundedReceiver<Result<Event, notify::Error>>,
        config: PskDirectoryConfig,
        psks: Arc<DashMap<String, Arc<SecureBytes>>>,
        path_to_fingerprint: Arc<DashMap<PathBuf, String>>,
        fingerprint_calculator: Arc<crate::config::psk::fingerprint::FingerprintCalculator>,
    ) {
        tokio::spawn(async move {
            // Create a debouncer for file events
            let pending_events: DashMap<PathBuf, (EventKind, std::time::Instant)> = DashMap::new();

            loop {
                // Process any events that have exceeded the debounce time
                Self::process_debounced_events(
                    &pending_events,
                    &psks,
                    &path_to_fingerprint,
                    &fingerprint_calculator,
                )
                .await;

                // Wait for next event or timeout
                tokio::select! {
                    event_result = event_receiver.recv() => {
                        match event_result {
                            Some(Ok(event)) => {
                                Self::handle_fs_event(
                                    event,
                                    &config,
                                    &pending_events,
                                ).await;
                            }
                            Some(Err(e)) => {
                                error!(error = %e, "Error from file watcher");
                            }
                            None => {
                                error!("Event channel closed, stopping PSK directory monitor");
                                break;
                            }
                        }
                    }
                    _ = sleep(config.debounce_ms.as_raw()) => {
                        // Just continue to process debounced events
                    }
                }
            }
        });
    }

    /// Handle a filesystem event
    async fn handle_fs_event(
        event: Event,
        _config: &PskDirectoryConfig,
        pending_events: &DashMap<PathBuf, (EventKind, std::time::Instant)>,
    ) {
        let now = std::time::Instant::now();

        // Filter and debounce events
        for path in event.paths {
            // Skip non-PSK files
            if path.is_file() && !Self::is_psk_file(&path) {
                continue;
            }

            // Add to pending events with timestamp
            pending_events.insert(path, (event.kind, now));
        }
    }

    /// Process events that have exceeded the debounce time
    async fn process_debounced_events(
        pending_events: &DashMap<PathBuf, (EventKind, std::time::Instant)>,
        psks: &DashMap<String, Arc<SecureBytes>>,
        path_to_fingerprint: &DashMap<PathBuf, String>,
        fingerprint_calculator: &Arc<crate::config::psk::fingerprint::FingerprintCalculator>,
    ) {
        let now = std::time::Instant::now();

        // Find events that have exceeded debounce time
        let expired_paths: Vec<PathBuf> = pending_events
            .iter()
            .filter_map(|entry| {
                let (path, (_, timestamp)) = (entry.key(), entry.value());
                if now.duration_since(*timestamp) >= std::time::Duration::from_millis(100) {
                    Some(path.clone())
                } else {
                    None
                }
            })
            .collect();

        // Process expired events
        for path in expired_paths {
            if let Some((_, (kind, _))) = pending_events.remove(&path) {
                match kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        if path.is_file() {
                            Self::process_psk_file(
                                &path,
                                psks,
                                path_to_fingerprint,
                                fingerprint_calculator,
                            )
                            .await;
                        } else if path.is_dir() {
                            Self::process_psk_directory(
                                &path,
                                psks,
                                path_to_fingerprint,
                                fingerprint_calculator,
                            )
                            .await;
                        }
                    }
                    EventKind::Remove(_) => {
                        Self::remove_psk(&path, psks, path_to_fingerprint).await;
                    }
                    _ => {
                        // Ignore other event types
                    }
                }
            }
        }
    }

    /// Process a PSK file
    async fn process_psk_file(
        path: &Path,
        psks: &DashMap<String, Arc<SecureBytes>>,
        path_to_fingerprint: &DashMap<PathBuf, String>,
        fingerprint_calculator: &Arc<crate::config::psk::fingerprint::FingerprintCalculator>,
    ) {
        debug!(path = %path.display(), "Processing PSK file");

        // Read file
        match tokio::fs::read(path).await {
            Ok(data) => {
                // Create secure bytes
                let secure_data = Arc::new(SecureBytes::from_slice(&data));

                // Calculate fingerprint
                match fingerprint_calculator.calculate(secure_data.clone()).await {
                    Ok(fingerprint) => {
                        // Store PSK and fingerprint
                        psks.insert(fingerprint.clone(), secure_data);
                        path_to_fingerprint.insert(path.to_path_buf(), fingerprint.clone());

                        info!(
                            path = %path.display(),
                            fingerprint = %fingerprint,
                            "Added PSK file"
                        );
                    }
                    Err(e) => {
                        error!(
                            path = %path.display(),
                            error = %e,
                            "Failed to calculate fingerprint"
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    path = %path.display(),
                    error = %e,
                    "Failed to read PSK file"
                );
            }
        }
    }

    /// Process a PSK directory
    async fn process_psk_directory(
        dir: &Path,
        psks: &DashMap<String, Arc<SecureBytes>>,
        path_to_fingerprint: &DashMap<PathBuf, String>,
        fingerprint_calculator: &Arc<crate::config::psk::fingerprint::FingerprintCalculator>,
    ) {
        debug!(path = %dir.display(), "Processing PSK directory");

        // Read directory
        match tokio::fs::read_dir(dir).await {
            Ok(mut entries) => {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    if path.is_file() && Self::is_psk_file(&path) {
                        Self::process_psk_file(
                            &path,
                            psks,
                            path_to_fingerprint,
                            fingerprint_calculator,
                        )
                        .await;
                    }
                }
            }
            Err(e) => {
                error!(
                    path = %dir.display(),
                    error = %e,
                    "Failed to read PSK directory"
                );
            }
        }
    }

    /// Remove a PSK
    async fn remove_psk(
        path: &Path,
        psks: &DashMap<String, Arc<SecureBytes>>,
        path_to_fingerprint: &DashMap<PathBuf, String>,
    ) {
        debug!(path = %path.display(), "Removing PSK");

        // Remove fingerprint and PSK
        if let Some((_, fingerprint)) = path_to_fingerprint.remove(path) {
            psks.remove(&fingerprint);

            info!(
                path = %path.display(),
                fingerprint = %fingerprint,
                "Removed PSK"
            );
        }
    }

    /// Check if a file is a PSK file
    fn is_psk_file(path: &Path) -> bool {
        path.extension().map(|ext| ext == "psk").unwrap_or(false)
    }

    /// Get a PSK by fingerprint
    pub fn get_psk(&self, fingerprint: &str) -> Option<Arc<SecureBytes>> {
        self.psks.get(fingerprint).map(|psk| psk.clone())
    }

    /// Get all PSK fingerprints
    pub fn get_all_fingerprints(&self) -> Vec<String> {
        self.psks.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get the number of loaded PSKs
    pub fn psk_count(&self) -> usize {
        self.psks.len()
    }
}
