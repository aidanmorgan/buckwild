//! eBPF Manager trait for abstracting eBPF program lifecycle
//!
//! Defines the async interface for eBPF program management including
//! loading, attaching, detaching, and map operations.

use super::error::LoaderResult;
use super::types::AdaptiveStats;
use crate::protocol::types::SessionId;

/// Trait for eBPF program lifecycle management
///
/// This trait defines the async interface for managing eBPF programs
/// (XDP and TC), map operations, and session registration.
///
/// ## Lifecycle
///
/// 1. Load programs with `load_xdp()` and `load_tc()`
/// 2. Attach to interfaces with `attach_xdp()` and `attach_tc()`
/// 3. Manage port hopping with `update_port_table()` and `start_port_updates()`
/// 4. Register/unregister sessions
/// 5. Clean up with `detach_xdp()`, `detach_tc()`, and `stop()`
///
/// ## Platform-Specific Implementations
///
/// - Linux: Uses aya crate for real eBPF program loading
/// - Other platforms: Returns errors or provides mock implementations
#[async_trait::async_trait]
pub trait EbpfManager: Send + Sync {
    /// Load XDP program from file
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Program file not found
    /// - Program fails eBPF verifier
    /// - Platform does not support eBPF
    async fn load_xdp(&mut self) -> LoaderResult<()>;

    /// Load TC egress program from file
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Program file not found
    /// - Program fails eBPF verifier
    /// - Platform does not support eBPF
    async fn load_tc(&mut self) -> LoaderResult<()>;

    /// Attach XDP program to network interface
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface not found
    /// - Already attached to another interface
    /// - Insufficient permissions
    async fn attach_xdp(&mut self, interface: &str) -> LoaderResult<()>;

    /// Attach TC egress program to network interface
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Interface not found
    /// - Already attached to another interface
    /// - Insufficient permissions
    async fn attach_tc(&mut self, interface: &str) -> LoaderResult<()>;

    /// Detach XDP program from network interface
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Not currently attached
    /// - Interface mismatch
    async fn detach_xdp(&mut self, interface: &str) -> LoaderResult<()>;

    /// Detach TC egress program from network interface
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Not currently attached
    /// - Interface mismatch
    async fn detach_tc(&mut self, interface: &str) -> LoaderResult<()>;

    /// Update port validity map with current port hopping schedule
    ///
    /// Calculates valid ports for current time bucket plus adaptive window
    /// and updates the eBPF port validity map.
    async fn update_port_table(&mut self) -> LoaderResult<()>;

    /// Start periodic port table updates
    ///
    /// Spawns a background task that updates the port table at the
    /// configured interval.
    async fn start_port_updates(&mut self) -> LoaderResult<()>;

    /// Register a session in the routing map
    ///
    /// Maps session ID to ring buffer ID for packet routing.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier
    /// * `ring_buffer_id` - Ring buffer ID for this session
    async fn register_session(
        &mut self,
        session_id: SessionId,
        ring_buffer_id: u32,
    ) -> LoaderResult<()>;

    /// Unregister a session from the routing map
    ///
    /// # Errors
    ///
    /// Returns error if session not found
    async fn unregister_session(&mut self, session_id: SessionId) -> LoaderResult<()>;

    /// Configure adaptive delay windows
    ///
    /// Updates the past and future window sizes used for port hopping
    /// tolerance.
    ///
    /// # Arguments
    ///
    /// * `past_ms` - Past window size in milliseconds
    /// * `future_ms` - Future window size in milliseconds
    async fn set_adaptive_window(&mut self, past_ms: u32, future_ms: u32) -> LoaderResult<()>;

    /// Get adaptive delay statistics
    ///
    /// Returns counters for early and late packet arrivals.
    fn get_adaptive_stats(&self) -> AdaptiveStats;

    /// Check if port is currently valid
    ///
    /// Helper method for testing and validation.
    fn is_port_valid(&self, port: u16) -> bool;

    /// Stop the manager and clean up resources
    ///
    /// Detaches programs, stops update tasks, clears maps.
    async fn stop(&mut self) -> LoaderResult<()>;
}
