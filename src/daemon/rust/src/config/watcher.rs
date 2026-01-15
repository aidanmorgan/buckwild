use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{self, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, instrument, warn};

// Import consolidated types from common crate
use buckwild_common::protocol::types::{MaxConnections, MetricsInterval};

/// Type alias for event filter function
pub type EventFilter = Arc<dyn Fn(&Event) -> bool + Send + Sync>;

/// Errors that can occur during file watching
#[derive(Error, Debug)]
pub enum WatcherError {
    #[error("Failed to watch path: {0}")]
    WatchError(#[from] notify::Error),

    #[error("Failed to send event: {0}")]
    SendError(String),

    #[error("Watcher channel closed")]
    ChannelClosed,

    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// Configuration for file watcher
#[derive(Clone)]
pub struct WatcherConfig {
    /// Path to watch
    pub path: PathBuf,

    /// Whether to watch recursively
    pub recursive: bool,

    /// Debounce duration in milliseconds
    pub debounce_ms: MetricsInterval,

    /// Filter function for events
    pub filter: Option<EventFilter>,

    /// Batch size for event processing
    pub batch_size: MaxConnections,
}

impl std::fmt::Debug for WatcherConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatcherConfig")
            .field("path", &self.path)
            .field("recursive", &self.recursive)
            .field("debounce_ms", &self.debounce_ms)
            .field("filter", &self.filter.as_ref().map(|_| "<closure>"))
            .field("batch_size", &self.batch_size)
            .finish()
    }
}

impl WatcherConfig {
    /// Create a new watcher configuration
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            recursive: false,
            debounce_ms: MetricsInterval::from_raw(std::time::Duration::from_millis(100)),
            filter: None,
            batch_size: MaxConnections::from_raw(10),
        }
    }

    /// Set recursive watching
    pub fn recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Set debounce duration
    pub fn debounce(mut self, debounce_ms: u64) -> Self {
        self.debounce_ms = MetricsInterval::from_raw(std::time::Duration::from_millis(debounce_ms));
        self
    }

    /// Set event filter
    pub fn filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&Event) -> bool + Send + Sync + 'static,
    {
        self.filter = Some(Arc::new(filter));
        self
    }

    /// Set batch size
    pub fn batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = MaxConnections::from_raw(batch_size as u32);
        self
    }
}

/// File watcher for configuration files
pub struct FileWatcher {
    /// Watcher configuration
    config: WatcherConfig,

    /// Underlying watcher
    _watcher: RecommendedWatcher,

    /// Event sender
    event_sender: broadcast::Sender<Vec<Event>>,
}

impl FileWatcher {
    /// Create a new file watcher
    #[instrument(skip(config), err)]
    pub fn new(config: WatcherConfig) -> Result<Self, WatcherError> {
        // Validate path
        if !config.path.exists() {
            return Err(WatcherError::InvalidPath(format!(
                "Path does not exist: {}",
                config.path.display()
            )));
        }

        // Create channels
        let (event_sender, _) = broadcast::channel(MaxConnections::from_raw(100).as_raw() as usize);
        let (raw_sender, raw_receiver) =
            mpsc::channel(MaxConnections::from_raw(100).as_raw() as usize);

        // Create watcher
        let mut watcher = notify::recommended_watcher(move |result| {
            let _ = raw_sender.blocking_send(result);
        })?;

        // Start watching
        let watch_mode = if config.recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        watcher.watch(&config.path, watch_mode)?;

        // Create file watcher
        let file_watcher = Self {
            config: config.clone(),
            _watcher: watcher,
            event_sender: event_sender.clone(),
        };

        // Log configuration before moving
        info!(
            path = %config.path.display(),
            recursive = config.recursive,
            debounce_ms = config.debounce_ms.as_raw().as_millis(),
            "Started file watcher"
        );

        // Start event processing loop
        Self::start_event_loop(raw_receiver, event_sender, config);

        Ok(file_watcher)
    }

    /// Start the event processing loop
    fn start_event_loop(
        mut raw_receiver: mpsc::Receiver<Result<Event, notify::Error>>,
        event_sender: broadcast::Sender<Vec<Event>>,
        config: WatcherConfig,
    ) {
        tokio::spawn(async move {
            // Create debounce map
            let mut pending_events =
                std::collections::HashMap::<PathBuf, (EventKind, std::time::Instant)>::new();

            loop {
                // Process any events that have exceeded the debounce time
                let now = std::time::Instant::now();
                let mut expired_events = Vec::new();

                // Find expired events
                pending_events.retain(|path, (kind, timestamp)| {
                    if now.duration_since(*timestamp) >= config.debounce_ms.as_raw() {
                        expired_events.push(Event {
                            paths: vec![path.clone()],
                            kind: *kind,
                            attrs: notify::event::EventAttributes::new(),
                        });
                        false
                    } else {
                        true
                    }
                });

                // Send expired events if any
                if !expired_events.is_empty() {
                    // Apply filter if configured
                    if let Some(filter) = &config.filter {
                        expired_events.retain(|event| filter(event));
                    }

                    if !expired_events.is_empty() && event_sender.receiver_count() > 0 {
                        if let Err(e) = event_sender.send(expired_events) {
                            warn!(error = %e, "Failed to send file events");
                        }
                    }
                }

                // Wait for next event or timeout
                tokio::select! {
                    event_result = raw_receiver.recv() => {
                        match event_result {
                            Some(Ok(event)) => {
                                // Add to pending events with timestamp
                                for path in &event.paths {
                                    pending_events.insert(path.clone(), (event.kind, now));
                                }
                            }
                            Some(Err(e)) => {
                                error!(error = %e, "Error from file watcher");
                            }
                            None => {
                                error!("Event channel closed, stopping file watcher");
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(config.debounce_ms.as_raw().as_millis() as u64 / 2)) => {
                        // Just continue to process debounced events
                    }
                }
            }
        });
    }

    /// Subscribe to file events
    pub fn subscribe(&self) -> broadcast::Receiver<Vec<Event>> {
        self.event_sender.subscribe()
    }

    /// Get the number of subscribers
    pub fn subscriber_count(&self) -> usize {
        self.event_sender.receiver_count()
    }

    /// Get the watched path
    pub fn watched_path(&self) -> &Path {
        &self.config.path
    }

    /// Check if watching recursively
    pub fn is_recursive(&self) -> bool {
        self.config.recursive
    }
}

/// Manages multiple file watchers
pub struct WatcherManager {
    /// Map of paths to watchers
    watchers: dashmap::DashMap<PathBuf, Arc<FileWatcher>>,
}

impl WatcherManager {
    /// Create a new watcher manager
    pub fn new() -> Self {
        Self {
            watchers: dashmap::DashMap::new(),
        }
    }

    /// Add a watcher
    #[instrument(skip(self, config), err)]
    pub fn add_watcher(&self, config: WatcherConfig) -> Result<Arc<FileWatcher>, WatcherError> {
        // Check if already watching
        if let Some(watcher) = self.watchers.get(&config.path) {
            return Ok(watcher.clone());
        }

        // Create watcher
        let watcher = Arc::new(FileWatcher::new(config.clone())?);

        // Add to map
        self.watchers.insert(config.path.clone(), watcher.clone());

        info!(
            path = %config.path.display(),
            "Added file watcher"
        );

        Ok(watcher)
    }

    /// Remove a watcher
    #[instrument(skip(self), err)]
    pub fn remove_watcher<P: AsRef<Path> + std::fmt::Debug>(
        &self,
        path: P,
    ) -> Result<(), WatcherError> {
        let path = path.as_ref();

        // Remove from map
        if self.watchers.remove(path).is_some() {
            info!(
                path = %path.display(),
                "Removed file watcher"
            );

            Ok(())
        } else {
            Err(WatcherError::InvalidPath(format!(
                "No watcher found for path: {}",
                path.display()
            )))
        }
    }

    /// Get a watcher
    pub fn get_watcher<P: AsRef<Path>>(&self, path: P) -> Option<Arc<FileWatcher>> {
        self.watchers.get(path.as_ref()).map(|w| w.clone())
    }

    /// Get all watchers
    pub fn get_all_watchers(&self) -> Vec<Arc<FileWatcher>> {
        self.watchers.iter().map(|w| w.clone()).collect()
    }

    /// Get the number of watchers
    pub fn watcher_count(&self) -> MaxConnections {
        MaxConnections::from_raw(self.watchers.len() as u32)
    }
}

impl Default for WatcherManager {
    fn default() -> Self {
        Self::new()
    }
}
