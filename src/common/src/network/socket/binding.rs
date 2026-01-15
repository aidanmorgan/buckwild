// Port binding functionality and management

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use crate::error::{BuckwildError, BuckwildResult};
use crate::protocol::types::{IpAddress, PacketCount, Port};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, Instant};

/// Port binding manager for managing port allocations and bindings
#[derive(Debug)]
pub struct PortBindingManager {
    /// Map of port to binding information
    bindings: Arc<RwLock<HashMap<Port, PortBinding>>>,
    /// Manager configuration
    config: BindingManagerConfig,
    /// Manager state
    state: Arc<RwLock<BindingManagerState>>,
    /// Port allocation tracking
    allocation_tracker: Arc<Mutex<PortAllocationTracker>>,
}

/// Port binding manager configuration
#[derive(Debug, Clone)]
pub struct BindingManagerConfig {
    /// Enable port reuse
    pub enable_port_reuse: bool,
    /// Maximum binding duration
    pub max_binding_duration: Duration,
    /// Port range for dynamic allocation
    pub dynamic_port_range: (Port, Port),
    /// Reserved ports that cannot be allocated
    pub reserved_ports: Vec<Port>,
    /// Enable binding validation
    pub enable_validation: bool,
}

/// Port binding manager state
#[derive(Debug, Clone, PartialEq)]
pub enum BindingManagerState {
    /// Manager is not initialized
    Uninitialized,
    /// Manager is running
    Running,
    /// Manager is shutting down
    ShuttingDown,
    /// Manager is shut down
    Shutdown,
}

/// Port allocation tracker for dynamic port allocation
#[derive(Debug)]
struct PortAllocationTracker {
    /// Next port to try for allocation
    next_port: Port,
    /// Allocation history for avoiding recent ports
    allocation_history: Vec<(Port, Instant)>,
    /// Maximum history size
    max_history_size: usize,
}

/// Port binding information
#[derive(Debug, Clone)]
pub struct PortBinding {
    /// Bound port
    port: Port,
    /// Bound address (None means all addresses)
    address: Option<IpAddress>,
    /// Protocol type
    protocol: Protocol,
    /// Binding state
    state: BindingState,
    /// Binding metadata
    metadata: BindingMetadata,
}

/// Protocol type for port binding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// UDP protocol
    Udp,
    /// TCP protocol
    Tcp,
}

// Use consolidated BindingState from protocol types
use crate::protocol::types::BindingState;

/// Binding metadata
#[derive(Debug, Clone)]
pub struct BindingMetadata {
    /// When the binding was created
    pub created_at: Instant,
    /// When the binding expires (if applicable)
    pub expires_at: Option<Instant>,
    /// Whether the binding is exclusive
    pub exclusive: bool,
    /// Binding description
    pub description: Option<String>,
    /// Reference count for shared bindings
    pub reference_count: PacketCount,
}

/// Port binding request
#[derive(Debug, Clone)]
pub struct BindingRequest {
    /// Desired port (0 for dynamic allocation)
    pub port: Port,
    /// Specific address to bind to (None for all addresses)
    pub address: Option<IpAddress>,
    /// Protocol type
    pub protocol: Protocol,
    /// Whether the binding should be exclusive
    pub exclusive: bool,
}

/// Binding information for external queries
#[derive(Debug, Clone)]
pub struct BindingInfo {
    /// Bound port
    pub port: Port,
    /// Bound address
    pub address: Option<IpAddress>,
    /// Protocol
    pub protocol: Protocol,
    /// Current state
    pub state: BindingState,
    /// Creation time
    pub created_at: Instant,
    /// Expiration time
    pub expires_at: Option<Instant>,
    /// Whether exclusive
    pub exclusive: bool,
    /// Reference count
    pub reference_count: PacketCount,
}

impl Default for BindingManagerConfig {
    fn default() -> Self {
        Self {
            enable_port_reuse: true,
            max_binding_duration: Duration::from_secs(3600), // 1 hour
            dynamic_port_range: (
                Port(49152), // Start of dynamic/private port range
                Port(65535), // End of port range
            ),
            reserved_ports: vec![
                Port::from_well_known(22),  // SSH
                Port::from_well_known(53),  // DNS
                Port::from_well_known(80),  // HTTP
                Port::from_well_known(443), // HTTPS
            ],
            enable_validation: true,
        }
    }
}

impl PortAllocationTracker {
    fn new(start_port: Port) -> Self {
        Self {
            next_port: start_port,
            allocation_history: Vec::new(),
            max_history_size: 1000,
        }
    }

    fn allocate_next_port(&mut self, reserved_ports: &[Port]) -> Option<Port> {
        let start_port = self.next_port;
        let mut current_port = start_port;

        loop {
            // Check if port is reserved
            if !reserved_ports.contains(&current_port) {
                // Check if port was recently allocated
                let now = Instant::now();
                let recently_used = self.allocation_history.iter().any(|(port, time)| {
                    *port == current_port && now.duration_since(*time) < Duration::from_secs(60)
                });

                if !recently_used {
                    // Record allocation
                    self.allocation_history.push((current_port, now));

                    // Trim history if too large
                    if self.allocation_history.len() > self.max_history_size {
                        self.allocation_history.remove(0);
                    }

                    // Update next port
                    self.next_port = current_port.next();

                    return Some(current_port);
                }
            }

            // Try next port
            current_port = current_port.next();

            // Avoid infinite loop
            if current_port == start_port {
                break;
            }
        }

        None
    }
}

impl PortBinding {
    /// Create a new port binding
    pub fn new(port: Port, address: IpAddress) -> Self {
        Self {
            port,
            address: Some(address),
            protocol: Protocol::Udp,
            state: BindingState::Active,
            metadata: BindingMetadata {
                created_at: Instant::now(),
                expires_at: None,
                exclusive: false,
                description: None,
                reference_count: PacketCount::new(1),
            },
        }
    }

    /// Create a new port binding with full configuration
    pub fn new_with_config(
        port: Port,
        address: Option<IpAddress>,
        protocol: Protocol,
        exclusive: bool,
        expires_at: Option<Instant>,
    ) -> Self {
        Self {
            port,
            address,
            protocol,
            state: BindingState::Active,
            metadata: BindingMetadata {
                created_at: Instant::now(),
                expires_at,
                exclusive,
                description: None,
                reference_count: PacketCount::new(1),
            },
        }
    }

    /// Get the bound port
    pub fn port(&self) -> Port {
        self.port
    }

    /// Get the bound address
    pub fn address(&self) -> Option<IpAddress> {
        self.address
    }

    /// Get the protocol
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Get the binding state
    pub fn state(&self) -> &BindingState {
        &self.state
    }

    /// Check if the binding is active
    pub fn is_active(&self) -> bool {
        matches!(self.state, BindingState::Active)
    }

    /// Check if the binding is exclusive
    pub fn is_exclusive(&self) -> bool {
        self.metadata.exclusive
    }

    /// Check if the binding has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.metadata.expires_at {
            Instant::now() > expires_at
        } else {
            false
        }
    }

    /// Increment reference count
    pub fn add_reference(&mut self) {
        self.metadata
            .reference_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Decrement reference count
    pub fn remove_reference(&mut self) -> usize {
        let current = self
            .metadata
            .reference_count
            .load(std::sync::atomic::Ordering::Relaxed);
        if current > 0 {
            self.metadata
                .reference_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.metadata
            .reference_count
            .load(std::sync::atomic::Ordering::Relaxed) as usize
    }

    /// Get binding information
    pub fn info(&self) -> BindingInfo {
        BindingInfo {
            port: self.port,
            address: self.address,
            protocol: self.protocol,
            state: self.state,
            created_at: self.metadata.created_at,
            expires_at: self.metadata.expires_at,
            exclusive: self.metadata.exclusive,
            reference_count: self.metadata.reference_count.clone(),
        }
    }

    /// Update binding state
    pub fn set_state(&mut self, state: BindingState) {
        self.state = state;
    }

    /// Set description
    pub fn set_description(&mut self, description: String) {
        self.metadata.description = Some(description);
    }
}

impl PortBindingManager {
    /// Create a new port binding manager
    pub fn new(config: BindingManagerConfig) -> Self {
        let allocation_tracker = PortAllocationTracker::new(config.dynamic_port_range.0);

        Self {
            bindings: Arc::new(RwLock::new(HashMap::new())),
            config,
            state: Arc::new(RwLock::new(BindingManagerState::Uninitialized)),
            allocation_tracker: Arc::new(Mutex::new(allocation_tracker)),
        }
    }

    /// Start the port binding manager
    pub async fn start(&self) -> BuckwildResult<()> {
        let mut state = self.state.write().await;
        if *state != BindingManagerState::Uninitialized {
            return Err(BuckwildError::invalid_state("Manager already started"));
        }

        *state = BindingManagerState::Running;
        Ok(())
    }

    /// Bind a port according to the request
    pub async fn bind_port(&self, request: BindingRequest) -> BuckwildResult<PortBinding> {
        let state = self.state.read().await;
        if *state != BindingManagerState::Running {
            return Err(BuckwildError::invalid_state("Manager is not running"));
        }
        drop(state);

        // Determine the port to bind
        let port = if request.port.as_u16() == 0 {
            // Dynamic port allocation
            self.allocate_dynamic_port().await?
        } else {
            // Specific port requested
            if self.config.enable_validation {
                self.validate_port_request(&request).await?;
            }
            request.port
        };

        // Check if port is already bound
        {
            let mut bindings = self.bindings.write().await;

            if let Some(existing_binding) = bindings.get_mut(&port) {
                // Check if we can share the binding
                if !existing_binding.is_exclusive()
                    && !request.exclusive
                    && self.config.enable_port_reuse
                {
                    existing_binding.add_reference();
                    return Ok(existing_binding.clone());
                }
                return Err(BuckwildError::resource_exhausted(format!(
                    "Port {} is already bound exclusively",
                    port
                )));
            }

            // Create new binding
            let expires_at = if self.config.max_binding_duration > Duration::ZERO {
                Some(Instant::now() + self.config.max_binding_duration)
            } else {
                None
            };

            let binding = PortBinding::new_with_config(
                port,
                request.address,
                request.protocol,
                request.exclusive,
                expires_at,
            );

            bindings.insert(port, binding.clone());
            Ok(binding)
        }
    }

    /// Allocate a dynamic port
    async fn allocate_dynamic_port(&self) -> BuckwildResult<Port> {
        let mut tracker = self.allocation_tracker.lock().await;

        tracker
            .allocate_next_port(&self.config.reserved_ports)
            .ok_or_else(|| {
                BuckwildError::resource_exhausted("No available ports for dynamic allocation")
            })
    }

    /// Validate a port binding request
    async fn validate_port_request(&self, request: &BindingRequest) -> BuckwildResult<()> {
        // Check if port is in reserved list
        if self.config.reserved_ports.contains(&request.port) {
            return Err(BuckwildError::invalid_input(format!(
                "Port {} is reserved",
                request.port
            )));
        }

        // Check if port is in valid range
        if !request.port.is_valid() {
            return Err(BuckwildError::invalid_input("Invalid port number"));
        }

        // Check if port is well-known and we're not privileged
        if request.port.is_well_known() {
            return Err(BuckwildError::invalid_input(format!(
                "Port {} is a well-known port",
                request.port
            )));
        }

        Ok(())
    }

    /// Release a port binding
    pub async fn release_port(&self, port: Port) -> BuckwildResult<()> {
        let mut bindings = self.bindings.write().await;

        if let Some(binding) = bindings.get_mut(&port) {
            let remaining_refs = binding.remove_reference();

            if remaining_refs == 0 {
                binding.set_state(BindingState::Releasing);
                bindings.remove(&port);
            }

            Ok(())
        } else {
            Err(BuckwildError::not_found(format!(
                "Port {} is not bound",
                port
            )))
        }
    }

    /// Get binding information for a port
    pub async fn get_binding(&self, port: Port) -> Option<BindingInfo> {
        let bindings = self.bindings.read().await;
        bindings.get(&port).map(|binding| binding.info())
    }

    /// List all active bindings
    pub async fn list_bindings(&self) -> Vec<BindingInfo> {
        let bindings = self.bindings.read().await;
        bindings.values().map(|binding| binding.info()).collect()
    }

    /// Check if a port is available for binding
    pub async fn is_port_available(&self, port: Port, exclusive: bool) -> bool {
        let bindings = self.bindings.read().await;

        match bindings.get(&port) {
            None => true, // Port is not bound
            Some(binding) => {
                // Port is bound, check if we can share it
                !binding.is_exclusive() && !exclusive && self.config.enable_port_reuse
            }
        }
    }

    /// Clean up expired bindings
    pub async fn cleanup_expired_bindings(&self) -> usize {
        let mut bindings = self.bindings.write().await;
        let mut expired_ports = Vec::new();

        for (port, binding) in bindings.iter_mut() {
            if binding.is_expired() {
                binding.set_state(BindingState::Expired);
                expired_ports.push(*port);
            }
        }

        for port in &expired_ports {
            bindings.remove(port);
        }

        expired_ports.len()
    }

    /// Get binding statistics
    pub async fn get_binding_stats(&self) -> BindingStats {
        let bindings = self.bindings.read().await;

        let mut stats = BindingStats {
            total_bindings: PacketCount::new(bindings.len() as u64),
            ..Default::default()
        };

        for binding in bindings.values() {
            match binding.state() {
                BindingState::Unbound => {}
                BindingState::Binding => {}
                BindingState::Bound => {}
                BindingState::Active => stats.active_bindings += 1,
                BindingState::Failed => stats.expired_bindings += 1, // Count failed as expired
                BindingState::Reserved => stats.reserved_bindings += 1,
                BindingState::Releasing => stats.releasing_bindings += 1,
                BindingState::Expired => stats.expired_bindings += 1,
                BindingState::Error => stats.expired_bindings += 1, // Count errors as expired
            }

            if binding.is_exclusive() {
                stats.exclusive_bindings += 1;
            }

            match binding.protocol() {
                Protocol::Udp => stats.udp_bindings += 1,
                Protocol::Tcp => stats.tcp_bindings += 1,
            }
        }

        stats
    }

    /// Get current manager state
    pub async fn state(&self) -> BindingManagerState {
        self.state.read().await.clone()
    }

    /// Check if manager is running
    pub async fn is_running(&self) -> bool {
        matches!(*self.state.read().await, BindingManagerState::Running)
    }

    /// Shutdown the binding manager
    pub async fn shutdown(&self) -> BuckwildResult<()> {
        let mut state = self.state.write().await;
        if *state == BindingManagerState::Shutdown {
            return Ok(());
        }

        *state = BindingManagerState::ShuttingDown;

        // Release all bindings
        {
            let mut bindings = self.bindings.write().await;
            for binding in bindings.values_mut() {
                binding.set_state(BindingState::Releasing);
            }
            bindings.clear();
        }

        *state = BindingManagerState::Shutdown;
        Ok(())
    }
}

/// Binding statistics
#[derive(Debug, Default, Clone)]
pub struct BindingStats {
    /// Total number of bindings
    pub total_bindings: PacketCount,
    /// Active bindings
    pub active_bindings: PacketCount,
    /// Reserved bindings
    pub reserved_bindings: PacketCount,
    /// Bindings being released
    pub releasing_bindings: PacketCount,
    /// Expired bindings
    pub expired_bindings: PacketCount,
    /// Exclusive bindings
    pub exclusive_bindings: PacketCount,
    /// UDP bindings
    pub udp_bindings: PacketCount,
    /// TCP bindings
    pub tcp_bindings: PacketCount,
}

impl Drop for PortBindingManager {
    fn drop(&mut self) {
        // Note: In a real implementation, we'd want to ensure proper cleanup
        // This is a simplified version for the restructuring task
    }
}
