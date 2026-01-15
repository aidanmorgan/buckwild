// Window Management - Flow control window management and zero window probing
//
// This module handles receive window management, window updates, zero window
// probing, and flow control coordination.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::cmp::min;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::error::EngineError;
use crate::protocol::types::*;

/// Window management constants
const WINDOW_UPDATE_THRESHOLD: f32 = 0.25; // 25% change triggers update
const ZERO_WINDOW_PROBE_INTERVAL_MS: Interval = Interval(5_000_000_000); // 5 seconds in nanoseconds per spec
const MAX_ZERO_WINDOW_PROBE_INTERVAL_MS: Interval = Interval(60_000_000_000); // 60 seconds in nanoseconds
const MAX_RECEIVE_BUFFER_SIZE: u32 = 1048576; // 1MB
const MAX_RECEIVE_WINDOW: u32 = 65535; // Max window per spec

/// Window update information
#[derive(Debug, Clone)]
pub struct WindowUpdate {
    pub new_window_size: WindowSize,
    pub timestamp: Instant,
    pub sequence_number: SequenceNumber,
}

/// Zero window probe state
#[derive(Debug)]
struct ZeroWindowProbeState {
    /// Current probe interval
    interval_ms: u64,

    /// Last probe time
    last_probe_time: Option<Instant>,

    /// Probe count
    probe_count: u32,

    /// Maximum probe count before giving up
    max_probe_count: u32,
}

impl ZeroWindowProbeState {
    fn new() -> Self {
        Self {
            interval_ms: ZERO_WINDOW_PROBE_INTERVAL_MS.as_u64(),
            last_probe_time: None,
            probe_count: 0,
            max_probe_count: 60, // 60 probes max
        }
    }

    /// Check if it's time to send a probe
    fn should_probe(&self) -> bool {
        match self.last_probe_time {
            Some(last_time) => last_time.elapsed() >= Duration::from_millis(self.interval_ms),
            None => true, // First probe
        }
    }

    /// Update probe state after sending a probe
    fn update_after_probe(&mut self) {
        self.last_probe_time = Some(Instant::now());
        self.probe_count += 1;

        // Exponential backoff with maximum
        self.interval_ms = min(
            self.interval_ms * 2,
            MAX_ZERO_WINDOW_PROBE_INTERVAL_MS.as_u64(),
        );
    }

    /// Reset probe state when window opens
    fn reset(&mut self) {
        self.interval_ms = ZERO_WINDOW_PROBE_INTERVAL_MS.as_u64();
        self.last_probe_time = None;
        self.probe_count = 0;
    }

    /// Check if maximum probes reached
    fn is_exhausted(&self) -> bool {
        self.probe_count >= self.max_probe_count
    }
}

/// Window management statistics
#[derive(Debug, Default, Clone)]
pub struct WindowManagementStats {
    pub window_updates_sent: Counter,
    pub window_updates_received: Counter,
    pub zero_window_probes_sent: Counter,
    pub zero_window_probes_received: Counter,
    pub zero_window_events: Counter,
    pub current_receive_window: WindowSize,
    pub current_advertised_window: WindowSize,
    pub buffer_utilization: f32,
    pub average_window_size: WindowSize,
}

/// Window Management Engine
pub struct WindowManagement {
    /// Current receive window size
    receive_window: AtomicU32,

    /// Advertised window size (what we tell the peer)
    advertised_window: AtomicU32,

    /// Receive buffer size
    receive_buffer_size: AtomicBufferSize,

    /// Receive buffer used space
    receive_buffer_used: AtomicBufferSize,

    /// Zero window probe state
    zero_window_probe: Mutex<ZeroWindowProbeState>,

    /// Window update pending flag
    window_update_pending: AtomicPendingFlag,

    /// Last window update time
    last_window_update: Mutex<Option<Instant>>,

    /// Window management statistics
    stats: Mutex<WindowManagementStats>,

    /// Window update callback
    window_update_callback: Option<Box<dyn Fn(WindowUpdate) + Send + Sync>>,

    /// Zero window probe callback
    zero_window_probe_callback: Option<Box<dyn Fn() -> bool + Send + Sync>>,
}

impl WindowManagement {
    /// Create new window management engine
    pub fn new(initial_window_size: u32) -> Self {
        // Buffer size matches window size for accurate flow control
        // In production, use larger buffer if specified
        let buffer_size = min(initial_window_size, MAX_RECEIVE_BUFFER_SIZE);

        Self {
            receive_window: AtomicU32::new(initial_window_size),
            advertised_window: AtomicU32::new(initial_window_size),
            receive_buffer_size: AtomicBufferSize::new(buffer_size),
            receive_buffer_used: AtomicBufferSize::new(0),
            zero_window_probe: Mutex::new(ZeroWindowProbeState::new()),
            window_update_pending: AtomicPendingFlag::new(false),
            last_window_update: Mutex::new(None),
            stats: Mutex::new(WindowManagementStats::default()),
            window_update_callback: None,
            zero_window_probe_callback: None,
        }
    }

    /// Set window update callback
    pub fn set_window_update_callback<F>(&mut self, callback: F)
    where
        F: Fn(WindowUpdate) + Send + Sync + 'static,
    {
        self.window_update_callback = Some(Box::new(callback));
    }

    /// Set zero window probe callback
    pub fn set_zero_window_probe_callback<F>(&mut self, callback: F)
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        self.zero_window_probe_callback = Some(Box::new(callback));
    }

    /// Get current receive window
    pub fn get_receive_window(&self) -> WindowSize {
        WindowSize::new(self.receive_window.load(Ordering::Relaxed))
    }

    /// Get current advertised window
    pub fn get_advertised_window(&self) -> WindowSize {
        WindowSize::new(self.advertised_window.load(Ordering::Relaxed))
    }

    /// Update receive buffer usage
    pub async fn update_buffer_usage(&self, bytes_consumed: u32) -> Result<(), EngineError> {
        let current_used = self.receive_buffer_used.load(Ordering::Relaxed);
        let new_used = current_used.saturating_sub(bytes_consumed);
        self.receive_buffer_used
            .store(new_used, std::sync::atomic::Ordering::Relaxed);

        // Calculate new available window
        let buffer_size = self.receive_buffer_size.load(Ordering::Relaxed);
        let available_space = buffer_size.saturating_sub(new_used);
        let new_window = min(available_space, MAX_RECEIVE_WINDOW);

        let current_window = self.advertised_window.load(Ordering::Relaxed);

        // Check if window update is needed
        if self.should_send_window_update(current_window, new_window) {
            self.send_window_update(new_window).await?;
        }

        self.advertised_window.store(new_window, Ordering::Relaxed);

        debug!(
            bytes_consumed,
            new_used, available_space, new_window, "Updated buffer usage"
        );

        Ok(())
    }

    /// Add data to receive buffer
    pub async fn add_to_receive_buffer(&self, data_size: u32) -> Result<bool, EngineError> {
        let current_used = self.receive_buffer_used.load(Ordering::Relaxed);
        let buffer_size = self.receive_buffer_size.load(Ordering::Relaxed);

        if current_used + data_size > buffer_size {
            warn!(
                current_used,
                data_size, buffer_size, "Receive buffer would overflow"
            );
            return Ok(false); // Buffer full
        }

        let new_used = current_used + data_size;
        self.receive_buffer_used
            .store(new_used, std::sync::atomic::Ordering::Relaxed);

        // Update advertised window
        let available_space = buffer_size.saturating_sub(new_used);
        let new_window = min(available_space, MAX_RECEIVE_WINDOW);
        let current_window = self.advertised_window.load(Ordering::Relaxed);

        // Check if window became zero
        if new_window == 0 && current_window > 0 {
            self.handle_zero_window().await?;
        }

        // Check if window update is needed
        if self.should_send_window_update(current_window, new_window) {
            self.send_window_update(new_window).await?;
        }

        self.advertised_window.store(new_window, Ordering::Relaxed);

        debug!(
            data_size,
            new_used, available_space, new_window, "Added data to receive buffer"
        );

        Ok(true)
    }

    /// Check if window update should be sent
    fn should_send_window_update(&self, current_window: u32, new_window: u32) -> bool {
        if new_window == 0 || current_window == 0 {
            return new_window != current_window;
        }

        let change_ratio = if current_window > new_window {
            (current_window - new_window) as f32 / current_window as f32
        } else {
            (new_window - current_window) as f32 / current_window as f32
        };

        change_ratio >= WINDOW_UPDATE_THRESHOLD
    }

    /// Send window update
    async fn send_window_update(&self, new_window_size: u32) -> Result<(), EngineError> {
        if self.window_update_pending.is_pending() {
            return Ok(()); // Update already pending
        }

        self.window_update_pending.set_pending();

        let window_update = WindowUpdate {
            new_window_size: WindowSize::new(new_window_size),
            timestamp: Instant::now(),
            sequence_number: SequenceNumber::new(0), // Would be set by protocol layer
        };

        // Call callback if available
        if let Some(ref callback) = self.window_update_callback {
            callback(window_update.clone());
        }

        // Track window update sent
        {
            let mut stats = self.stats.lock().await;
            stats.window_updates_sent.increment_mut();
        }

        tracing::trace!(new_window_size, "Window update sent");

        *self.last_window_update.lock().await = Some(Instant::now());
        self.window_update_pending.clear_pending();

        info!(
            new_window_size = %new_window_size,
            "Sent window update"
        );

        Ok(())
    }

    /// Handle zero window condition
    async fn handle_zero_window(&self) -> Result<(), EngineError> {
        // Track zero window event
        {
            let mut stats = self.stats.lock().await;
            stats.zero_window_events.increment_mut();
        }

        warn!("Receive window became zero");

        // Reset zero window probe state
        {
            let mut probe_state = self.zero_window_probe.lock().await;
            probe_state.reset();
        }

        Ok(())
    }

    /// Process zero window probe
    pub async fn process_zero_window_probe(&self) -> Result<bool, EngineError> {
        let should_probe = {
            let probe_state = self.zero_window_probe.lock().await;
            probe_state.should_probe() && !probe_state.is_exhausted()
        };

        if !should_probe {
            return Ok(false);
        }

        // Send zero window probe
        let probe_sent = if let Some(ref callback) = self.zero_window_probe_callback {
            callback()
        } else {
            false
        };

        if probe_sent {
            // Update probe state
            {
                let mut probe_state = self.zero_window_probe.lock().await;
                probe_state.update_after_probe();
            }

            // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
            debug!("Sent zero window probe");
        }

        Ok(probe_sent)
    }

    /// Handle received window update
    pub async fn handle_window_update(&self, new_window_size: u32) -> Result<(), EngineError> {
        let old_window = self.receive_window.load(Ordering::Relaxed);
        self.receive_window
            .store(new_window_size, Ordering::Relaxed);

        // Track window update received
        {
            let mut stats = self.stats.lock().await;
            stats.window_updates_received.increment_mut();
        }

        // If window opened from zero, reset probe state
        if old_window == 0 && new_window_size > 0 {
            let mut probe_state = self.zero_window_probe.lock().await;
            probe_state.reset();

            info!(
                new_window_size = %new_window_size,
                "Window opened from zero"
            );
        }

        debug!(
            old_window,
            new_window_size = %new_window_size,
            "Processed window update"
        );

        Ok(())
    }

    /// Handle received zero window probe
    pub async fn handle_zero_window_probe(&self) -> Result<(), EngineError> {
        // Track zero window probe received
        {
            let mut stats = self.stats.lock().await;
            stats.zero_window_probes_received.increment_mut();
        }

        tracing::trace!("Zero window probe received");

        // Send window update in response
        let current_window = self.get_advertised_window();
        self.send_window_update(current_window.as_u32()).await?;

        debug!("Handled zero window probe");

        Ok(())
    }

    /// Start zero window probe monitoring
    pub async fn start_zero_window_monitoring(&self) -> Result<(), EngineError> {
        let window_management = self.clone_for_monitoring();

        tokio::spawn(async move {
            let mut interval =
                interval(Duration::from_millis(ZERO_WINDOW_PROBE_INTERVAL_MS.into()));

            loop {
                interval.tick().await;

                // Check if peer window is zero
                let peer_window = window_management.receive_window.load(Ordering::Relaxed);
                if peer_window == 0 {
                    if let Err(e) = window_management.process_zero_window_probe().await {
                        error!(error = ?e, "Failed to process zero window probe");
                    }
                }
            }
        });

        Ok(())
    }

    /// Get window management statistics
    pub async fn get_window_stats(&self) -> WindowManagementStats {
        let mut stats = self.stats.lock().await.clone();

        // Update current values
        stats.current_receive_window = self.get_receive_window();
        stats.current_advertised_window = self.get_advertised_window();

        // Calculate buffer utilization
        let buffer_size = self.receive_buffer_size.load(Ordering::Relaxed);
        let buffer_used = self.receive_buffer_used.load(Ordering::Relaxed);
        stats.buffer_utilization = if buffer_size > 0 {
            buffer_used as f32 / buffer_size as f32
        } else {
            0.0
        };

        stats
    }

    /// Shutdown window management
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        // Reset all state
        self.receive_window.store(0, Ordering::Relaxed);
        self.advertised_window.store(0, Ordering::Relaxed);
        self.receive_buffer_used
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.window_update_pending.clear_pending();

        info!("Window management shut down");
        Ok(())
    }

    // Helper method for monitoring task
    fn clone_for_monitoring(&self) -> WindowManagementMonitor {
        WindowManagementMonitor {
            receive_window: AtomicU32::new(self.receive_window.load(Ordering::Relaxed)),
            zero_window_probe_callback: self
                .zero_window_probe_callback
                .as_ref()
                .map(|_| true)
                .unwrap_or(false),
        }
    }
}

/// Helper struct for monitoring task
struct WindowManagementMonitor {
    receive_window: AtomicU32,
    zero_window_probe_callback: bool,
}

impl WindowManagementMonitor {
    async fn process_zero_window_probe(&self) -> Result<bool, EngineError> {
        // Simplified version for monitoring
        Ok(self.zero_window_probe_callback)
    }
}
