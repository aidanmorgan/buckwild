#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

// Port Hopping Coordination - Port binding and transition coordination
//
// This module handles port binding coordination, transition scheduling,
// and multi-session port management to ensure seamless port hopping.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, error, info, warn};

use crate::engines::port_hopping::{
    PortBinding, PortBindingStatus, PortHoppingParams, PortTransitionEvent,
};
use crate::engines::time_sync::epoch::{EpochType, TimeEpoch};
use crate::error::EngineError;
use crate::protocol::types::*;

/// Port coordination statistics
#[derive(Debug, Default, Clone)]
pub struct PortCoordinationStats {
    pub total_bindings: Counter,
    pub total_unbindings: Counter,
    pub binding_failures: Counter,
    pub unbinding_failures: Counter,
    pub active_ports: Counter,
    pub transition_events: Counter,
    pub cleanup_operations: Counter,
}

/// Port Hopping Coordination Engine
#[derive(Clone)]
pub struct PortHoppingCoordination {
    /// Port bindings
    port_bindings: Arc<DashMap<Port, PortBinding>>,

    /// Port transition history
    port_history: Arc<Mutex<Vec<PortTransitionEvent>>>,

    /// Coordination statistics
    stats: Arc<Mutex<PortCoordinationStats>>,

    /// Port binding callback
    bind_port_callback: Option<Arc<dyn Fn(Port) -> bool + Send + Sync>>,

    /// Port unbinding callback
    unbind_port_callback: Option<Arc<dyn Fn(Port) -> bool + Send + Sync>>,
}

impl PortHoppingCoordination {
    /// Create a new port hopping coordination engine
    pub fn new() -> Self {
        Self {
            port_bindings: Arc::new(DashMap::new()),
            port_history: Arc::new(Mutex::new(Vec::with_capacity(100))),
            stats: Arc::new(Mutex::new(PortCoordinationStats::default())),
            bind_port_callback: None,
            unbind_port_callback: None,
        }
    }

    /// Set port binding callback
    pub fn set_bind_port_callback<F>(&mut self, callback: F)
    where
        F: Fn(Port) -> bool + Send + Sync + 'static,
    {
        self.bind_port_callback = Some(Arc::new(callback));
    }

    /// Set port unbinding callback
    pub fn set_unbind_port_callback<F>(&mut self, callback: F)
    where
        F: Fn(Port) -> bool + Send + Sync + 'static,
    {
        self.unbind_port_callback = Some(Arc::new(callback));
    }

    /// Bind to port
    pub async fn bind_to_port(&self, port: Port) -> Result<(), EngineError> {
        // Check if already bound
        if self.port_bindings.contains_key(&port) {
            // Increment reference count
            if let Some(mut binding) = self.port_bindings.get_mut(&port) {
                binding.ref_count.fetch_add(1, Ordering::SeqCst);
                binding.last_activity = Timestamp::from_millis(TimeEpoch::current_time_ms());
            }
            return Ok(());
        }

        // Bind to port
        if let Some(ref callback) = self.bind_port_callback {
            if callback(port) {
                self.port_bindings.insert(
                    port,
                    PortBinding {
                        port,
                        status: PortBindingStatus::Active,
                        last_activity: Timestamp::from_millis(TimeEpoch::current_time_ms()),
                        ref_count: UsageCount::new(1),
                    },
                );

                // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                debug!(
                    port = %port,
                    active_ports = self.port_bindings.len(),
                    "Bound to port"
                );
                Ok(())
            } else {
                // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                warn!(
                    port = %port,
                    active_ports = self.port_bindings.len(),
                    "Failed to bind to port"
                );
                Err(EngineError::port_coordination_error(format!(
                    "Failed to bind to port {}",
                    port
                )))
            }
        } else {
            Err(EngineError::port_coordination_error(
                "No port binding callback set",
            ))
        }
    }

    /// Unbind from port
    pub async fn unbind_from_port(&self, port: Port) -> Result<(), EngineError> {
        // Check if bound
        if !self.port_bindings.contains_key(&port) {
            return Ok(());
        }

        // Decrement reference count
        let should_unbind = if let Some(binding) = self.port_bindings.get_mut(&port) {
            let new_count = binding
                .ref_count
                .fetch_sub(1, Ordering::SeqCst)
                .saturating_sub(1);
            new_count == 0
        } else {
            false
        };

        // Unbind if reference count is zero
        if should_unbind {
            if let Some(ref callback) = self.unbind_port_callback {
                if callback(port) {
                    self.port_bindings.remove(&port);

                    // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                    debug!(
                        port = %port,
                        active_ports = self.port_bindings.len(),
                        "Unbound from port"
                    );
                    Ok(())
                } else {
                    // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                    warn!(
                        port = %port,
                        active_ports = self.port_bindings.len(),
                        "Failed to unbind from port"
                    );
                    Err(EngineError::port_coordination_error(format!(
                        "Failed to unbind from port {}",
                        port
                    )))
                }
            } else {
                Err(EngineError::port_coordination_error(
                    "No port unbinding callback set",
                ))
            }
        } else {
            Ok(())
        }
    }

    /// Schedule port transition
    pub async fn schedule_port_transition(
        &self,
        params: &PortHoppingParams,
        _time_epoch: &TimeEpoch,
        transition_sender: &mpsc::UnboundedSender<PortTransitionEvent>,
    ) -> Result<(), EngineError> {
        let time_window = TimeEpoch::current_time_window(EpochType::Monthly, 0);
        let current_port =
            self.calculate_session_port_for_transition(params, time_window.window.as_u64());

        // Calculate next hop time
        let next_hop_time = TimeEpoch::next_hop_time(
            0, // Use default offset for now
            EpochType::Monthly,
        );

        let current_time = TimeEpoch::current_time_ms();
        let delay_until_hop = next_hop_time.saturating_sub(current_time);

        // Calculate next port
        let next_port =
            self.calculate_session_port_for_transition(params, time_window.window.as_u64() + 1);

        // Create transition event
        let event = PortTransitionEvent {
            old_port: current_port,
            new_port: next_port,
            time_window: ProtocolDuration::from_millis(time_window.window.as_u64() + 1),
            transition_time: ProtocolDuration::from_millis(next_hop_time),
        };

        // Schedule transition
        let transition_sender = transition_sender.clone();
        let coordination = self.clone();

        tokio::spawn(async move {
            // Wait until next hop time
            if delay_until_hop > 0 {
                time::sleep(Duration::from_millis(delay_until_hop)).await;
            }

            // Send transition event
            if let Err(e) = transition_sender.send(event.clone()) {
                error!(error = ?e, "Failed to send port transition event");
            } else {
                // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                tracing::debug!(
                    old_port = %event.old_port,
                    new_port = %event.new_port,
                    "Port transition event sent"
                );

                // Add to history
                coordination.add_to_history(event).await;
            }
        });

        // Also bind to the next port immediately for seamless transition
        self.bind_to_port(next_port).await?;

        Ok(())
    }

    /// Process port transition event
    pub async fn process_port_transition(
        &self,
        event: PortTransitionEvent,
    ) -> Result<(), EngineError> {
        debug!(
            old_port = %event.old_port,
            new_port = %event.new_port,
            time_window = %event.time_window,
            "Processing port transition"
        );

        // Start listening on new port if not already
        if !self.port_bindings.contains_key(&event.new_port) {
            if let Some(ref callback) = self.bind_port_callback {
                if callback(event.new_port) {
                    self.port_bindings.insert(
                        event.new_port,
                        PortBinding {
                            port: event.new_port,
                            status: PortBindingStatus::Active,
                            last_activity: Timestamp::from_millis(TimeEpoch::current_time_ms()),
                            ref_count: UsageCount::new(1),
                        },
                    );

                    // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                    tracing::trace!(
                        port = %event.new_port,
                        active_ports = self.port_bindings.len(),
                        "Bound to new port during transition"
                    );
                } else {
                    warn!(port = %event.new_port, "Failed to bind to port during transition");
                    self.port_bindings.insert(
                        event.new_port,
                        PortBinding {
                            port: event.new_port,
                            status: PortBindingStatus::Failed,
                            last_activity: Timestamp::from_millis(TimeEpoch::current_time_ms()),
                            ref_count: UsageCount::new(0),
                        },
                    );

                    // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                    tracing::warn!(
                        port = %event.new_port,
                        active_ports = self.port_bindings.len(),
                        "Failed to bind during transition"
                    );
                }
            }
        } else {
            // Increment reference count
            if let Some(mut binding) = self.port_bindings.get_mut(&event.new_port) {
                binding.ref_count.fetch_add(1, Ordering::SeqCst);
                binding.last_activity = Timestamp::from_millis(TimeEpoch::current_time_ms());
            }
        }

        // Add to port history
        self.add_to_history(event.clone()).await;

        // Schedule unbinding of old port after delay
        let coordination = self.clone();
        let old_port = event.old_port;

        tokio::spawn(async move {
            // Wait for port transition delay
            time::sleep(Duration::from_millis(1000)).await;

            // Unbind from old port
            if let Err(e) = coordination.unbind_from_port(old_port).await {
                warn!(port = %old_port, error = ?e, "Failed to unbind from old port after transition");
            }
        });

        Ok(())
    }

    /// Start port cleanup task
    pub async fn start_port_cleanup_task(&self) -> Result<(), EngineError> {
        let coordination = self.clone();

        tokio::spawn(async move {
            loop {
                // Run cleanup every 30 seconds
                time::sleep(Duration::from_secs(30)).await;

                if let Err(e) = coordination.cleanup_inactive_ports().await {
                    warn!(error = ?e, "Port cleanup task failed");
                }
            }
        });

        Ok(())
    }

    /// Cleanup inactive ports
    pub async fn cleanup_inactive_ports(&self) -> Result<(), EngineError> {
        let current_time = TimeEpoch::current_time_ms();
        let mut ports_to_remove = Vec::new();

        // Find inactive ports
        for entry in self.port_bindings.iter() {
            let port = *entry.key();
            let binding = entry.value();

            let last_activity = binding.last_activity.get();
            let ref_count = binding.ref_count.load(Ordering::SeqCst);

            // If port has been inactive for more than 5 minutes and has no references
            if current_time - last_activity > 300000 && ref_count == 0 {
                ports_to_remove.push(port);
            }
        }

        // Remove inactive ports
        for port in ports_to_remove {
            if let Some(ref callback) = self.unbind_port_callback {
                if callback(port) {
                    self.port_bindings.remove(&port);

                    // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                    debug!(
                        port = %port,
                        active_ports = self.port_bindings.len(),
                        "Cleaned up inactive port"
                    );
                } else {
                    // NOTE: Statistics removed - use tokio-tracing events per design/rules.md
                    warn!(
                        port = %port,
                        active_ports = self.port_bindings.len(),
                        "Failed to unbind from inactive port during cleanup"
                    );
                }
            }
        }

        Ok(())
    }

    /// Get currently bound ports
    pub fn get_bound_ports(&self) -> Vec<Port> {
        self.port_bindings
            .iter()
            .filter(|entry| entry.value().status == PortBindingStatus::Active)
            .map(|entry| *entry.key())
            .collect()
    }

    /// Get port binding status
    pub fn get_port_status(&self, port: Port) -> Option<PortBindingStatus> {
        self.port_bindings.get(&port).map(|binding| binding.status)
    }

    /// Get port reference count
    pub fn get_port_ref_count(&self, port: Port) -> Option<usize> {
        self.port_bindings
            .get(&port)
            .map(|binding| binding.ref_count.load(Ordering::SeqCst) as usize)
    }

    /// Get coordination statistics
    pub fn get_coordination_stats(&self) -> PortCoordinationStats {
        let mut stats = self.stats.lock().clone();
        stats.active_ports = Counter::new(self.port_bindings.len() as u64);
        stats
    }

    /// Get port transition history
    pub async fn get_port_history(&self) -> Vec<PortTransitionEvent> {
        self.port_history.lock().clone()
    }

    /// Clear port transition history
    pub async fn clear_port_history(&self) {
        self.port_history.lock().clear();
    }

    /// Update adaptive delay window size based on network conditions
    pub fn update_adaptive_delay_window(&self, network_delay_ms: f64, jitter_ms: f64) -> usize {
        // Calculate optimal window size based on network conditions
        let base_window = 3; // Minimum 3 windows (1.5 seconds)

        // Add windows based on network delay (1 window per 100ms of delay)
        let delay_windows = (network_delay_ms / 100.0).ceil() as usize;

        // Add windows based on jitter (2 windows per 50ms of jitter)
        let jitter_windows = (jitter_ms / 50.0).ceil() as usize * 2;

        // Calculate total window size
        let window_size = base_window + delay_windows + jitter_windows;

        // Cap at reasonable maximum (10 windows = 5 seconds)
        let capped_window = window_size.min(10);

        debug!(
            network_delay_ms = network_delay_ms,
            jitter_ms = jitter_ms,
            window_size = capped_window,
            "Updated adaptive delay window"
        );

        capped_window
    }

    /// Shutdown coordination engine
    pub async fn shutdown(&self) -> Result<(), EngineError> {
        // Unbind from all ports
        let bound_ports: Vec<Port> = self
            .port_bindings
            .iter()
            .map(|entry| *entry.key())
            .collect();

        for port in bound_ports {
            if let Err(e) = self.unbind_from_port(port).await {
                warn!(port = %port, error = ?e, "Failed to unbind from port during shutdown");
            }
        }

        // Clear history
        self.port_history.lock().clear();

        info!("Port hopping coordination engine shut down");
        Ok(())
    }

    // Private helper methods

    /// Add event to port history
    async fn add_to_history(&self, event: PortTransitionEvent) {
        let mut history = self.port_history.lock();
        history.push(event);

        // Trim history if needed
        if history.len() > 100 {
            history.remove(0);
        }
    }

    /// Calculate session port for transition (simplified version)
    fn calculate_session_port_for_transition(
        &self,
        params: &PortHoppingParams,
        time_window: u64,
    ) -> Port {
        use ring::hmac;

        // Convert time window to bytes
        let mut time_window_bytes = [0u8; 8];
        time_window_bytes.copy_from_slice(&time_window.to_be_bytes());

        // Create input for HMAC
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&time_window_bytes);
        input.extend_from_slice(&params.port_seed.to_be_bytes());
        input.extend_from_slice(b"session_port_v2");

        // Create HMAC key from hop sequence seed
        let key_material = params.hop_sequence_seed.to_be_bytes();
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &key_material);

        // Calculate HMAC
        let hmac_result = hmac::sign(&hmac_key, &input);

        // Extract port value from first 4 bytes of HMAC
        let port_value = u32::from_be_bytes([
            hmac_result.as_ref()[0],
            hmac_result.as_ref()[1],
            hmac_result.as_ref()[2],
            hmac_result.as_ref()[3],
        ]);

        // Map to port range
        const MIN_PORT: u16 = Port::MIN_PORT;
        const MAX_PORT: u16 = Port::MAX_PORT;
        const PORT_RANGE: u16 = MAX_PORT - MIN_PORT + 1;

        // port_value % PORT_RANGE ensures result fits within valid port range [MIN_PORT, MAX_PORT]
        Port::from_u16_unchecked(MIN_PORT + (port_value % PORT_RANGE as u32) as u16)
    }
}

impl Default for PortHoppingCoordination {
    fn default() -> Self {
        Self::new()
    }
}
