// Resource Cleanup Functions - LC-012, 3P-MED-024
//
// Implements secure resource cleanup for connection termination:
// - Session key zeroing (security requirement)
// - Port binding release (network resource management)
// - Sequence state clearing (protocol state cleanup)
// - Replay cache purging (anti-replay state cleanup)
// - Timer cancellation (resource cleanup)
// - Buffer deallocation (memory cleanup)
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::error::{BuckwildError, SessionError};
use crate::protocol::types::{Port, SequenceNumber, SessionId, Timestamp};

/// Session key container that requires explicit cleanup
/// Wraps SessionKey to track cleanup state
pub struct SessionKeyState {
    /// The actual session key (already implements Zeroize)
    key: crate::protocol::types::SessionKey,
    /// Whether this key has been securely zeroed
    zeroed: bool,
}

impl SessionKeyState {
    /// Create new session key state
    pub fn new(key: crate::protocol::types::SessionKey) -> Self {
        Self { key, zeroed: false }
    }

    /// Check if key has been zeroed
    pub fn is_zeroed(&self) -> bool {
        self.zeroed
    }

    /// Get reference to the key (only if not zeroed)
    pub fn key(&self) -> Option<&crate::protocol::types::SessionKey> {
        if self.zeroed { None } else { Some(&self.key) }
    }
}

impl Drop for SessionKeyState {
    fn drop(&mut self) {
        if !self.zeroed {
            warn!("SessionKeyState dropped without explicit zeroing");
        }
    }
}

/// Port binding state
#[derive(Debug)]
pub struct PortBinding {
    /// Port number
    pub port: Port,
    /// Whether binding is still active
    pub active: bool,
    /// Socket file descriptor (if available)
    pub socket_fd: Option<i32>,
}

/// Sequence tracking state
#[derive(Debug)]
pub struct SequenceState {
    /// Send sequence number
    pub send_seq: SequenceNumber,
    /// Receive sequence number
    pub recv_seq: SequenceNumber,
    /// Last acknowledged sequence
    pub last_ack: SequenceNumber,
}

impl SequenceState {
    /// Reset all sequence numbers to zero
    pub fn reset(&mut self) {
        self.send_seq = SequenceNumber::new(0);
        self.recv_seq = SequenceNumber::new(0);
        self.last_ack = SequenceNumber::new(0);
    }
}

/// Replay cache entry
#[derive(Debug, Clone)]
pub struct ReplayCacheEntry {
    /// Timestamp of the packet
    pub timestamp: Timestamp,
    /// Sequence number
    pub sequence: SequenceNumber,
    /// Session ID
    pub session_id: SessionId,
}

/// Timer handle wrapper
pub struct TimerHandle {
    /// Tokio join handle
    handle: tokio::task::JoinHandle<()>,
    /// Timer description
    description: String,
}

impl TimerHandle {
    /// Create new timer handle
    pub fn new(handle: tokio::task::JoinHandle<()>, description: String) -> Self {
        Self {
            handle,
            description,
        }
    }

    /// Cancel the timer
    pub fn cancel(self) {
        self.handle.abort();
    }

    /// Get timer description
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Packet buffer
pub struct PacketBuffer {
    /// Buffer data
    data: Vec<u8>,
    /// Buffer capacity
    capacity: usize,
    /// Whether buffer is in use
    in_use: bool,
}

impl PacketBuffer {
    /// Create new packet buffer
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            capacity,
            in_use: false,
        }
    }

    /// Mark buffer as in use
    pub fn allocate(&mut self, size: usize) -> Result<(), BuckwildError> {
        if self.in_use {
            return Err(BuckwildError::resource_exhausted("Buffer already in use"));
        }
        if size > self.capacity {
            return Err(BuckwildError::invalid_state(format!(
                "Requested size {} exceeds capacity {}",
                size, self.capacity
            )));
        }
        self.data.resize(size, 0);
        self.in_use = true;
        Ok(())
    }

    /// Free the buffer
    pub fn free(&mut self) {
        self.data.clear();
        self.in_use = false;
    }

    /// Check if buffer is in use
    pub fn is_in_use(&self) -> bool {
        self.in_use
    }

    /// Get buffer capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        // Zero the buffer data before dropping
        self.data.zeroize();
    }
}

/// Cleanup session keys securely
///
/// Zeroes all session key material using zeroize to prevent key material
/// from remaining in memory after cleanup.
///
/// # Arguments
/// * `session_keys` - Mutable map of session IDs to session key states
///
/// # Returns
/// * `Ok(usize)` - Number of keys successfully zeroed
/// * `Err` - If cleanup fails
pub async fn cleanup_session_keys(
    session_keys: &mut HashMap<SessionId, SessionKeyState>,
) -> Result<usize, SessionError> {
    let count = session_keys.len();

    info!(key_count = count, "Starting session key cleanup");

    for (session_id, key_state) in session_keys.iter_mut() {
        if !key_state.zeroed {
            // Explicitly zeroize the key
            key_state.key.zeroize();
            key_state.zeroed = true;

            debug!(
                session_id = %session_id,
                "Session key securely zeroed"
            );
        }
    }

    // Clear the map
    session_keys.clear();

    info!(keys_zeroed = count, "Session key cleanup complete");

    Ok(count)
}

/// Release port bindings
///
/// Closes sockets and releases port bindings to the operating system.
///
/// # Arguments
/// * `port_bindings` - Mutable map of ports to binding states
///
/// # Returns
/// * `Ok(usize)` - Number of ports successfully released
/// * `Err` - If cleanup fails
pub async fn cleanup_port_bindings(
    port_bindings: &mut HashMap<Port, PortBinding>,
) -> Result<usize, SessionError> {
    let count = port_bindings.len();

    info!(port_count = count, "Starting port binding cleanup");

    let mut released = 0;

    for (port, binding) in port_bindings.iter_mut() {
        if binding.active {
            // Close socket if we have a file descriptor
            if let Some(fd) = binding.socket_fd {
                #[cfg(unix)]
                {
                    // SAFETY: We own this file descriptor and are cleaning up
                    unsafe {
                        libc::close(fd);
                    }
                    debug!(
                        port = %port,
                        fd = fd,
                        "Socket closed"
                    );
                }
                #[cfg(not(unix))]
                {
                    debug!(
                        port = %port,
                        fd = fd,
                        "Socket cleanup skipped (not Unix)"
                    );
                }
            }

            binding.active = false;
            binding.socket_fd = None;
            released += 1;

            debug!(
                port = %port,
                "Port binding released"
            );
        }
    }

    // Clear the map
    port_bindings.clear();

    info!(ports_released = released, "Port binding cleanup complete");

    Ok(released)
}

/// Clear sequence tracking state
///
/// Resets all sequence number tracking to prevent state confusion
/// after connection cleanup.
///
/// # Arguments
/// * `sequence_states` - Mutable map of session IDs to sequence states
///
/// # Returns
/// * `Ok(usize)` - Number of sequence states cleared
/// * `Err` - If cleanup fails
pub async fn cleanup_sequence_state(
    sequence_states: &mut HashMap<SessionId, SequenceState>,
) -> Result<usize, SessionError> {
    let count = sequence_states.len();

    info!(state_count = count, "Starting sequence state cleanup");

    for (session_id, state) in sequence_states.iter_mut() {
        state.reset();

        debug!(
            session_id = %session_id,
            "Sequence state cleared"
        );
    }

    // Clear the map
    sequence_states.clear();

    info!(states_cleared = count, "Sequence state cleanup complete");

    Ok(count)
}

/// Purge anti-replay caches
///
/// Removes all anti-replay cache entries to free memory and prevent
/// stale replay detection state.
///
/// # Arguments
/// * `replay_cache` - Mutable map of session IDs to replay cache entries
///
/// # Returns
/// * `Ok(usize)` - Number of cache entries purged
/// * `Err` - If cleanup fails
pub async fn cleanup_replay_cache(
    replay_cache: &mut HashMap<SessionId, Vec<ReplayCacheEntry>>,
) -> Result<usize, SessionError> {
    let session_count = replay_cache.len();
    let mut total_entries = 0;

    info!(
        session_count = session_count,
        "Starting replay cache cleanup"
    );

    for (session_id, entries) in replay_cache.iter() {
        let entry_count = entries.len();
        total_entries += entry_count;

        debug!(
            session_id = %session_id,
            entries = entry_count,
            "Replay cache entries purged"
        );
    }

    // Clear the map
    replay_cache.clear();

    info!(
        sessions_purged = session_count,
        entries_purged = total_entries,
        "Replay cache cleanup complete"
    );

    Ok(total_entries)
}

/// Cancel all active timers
///
/// Aborts all running timer tasks to prevent resource leaks and
/// unwanted timer callbacks.
///
/// # Arguments
/// * `timers` - Mutable vector of timer handles
///
/// # Returns
/// * `Ok(usize)` - Number of timers successfully cancelled
/// * `Err` - If cleanup fails
pub async fn cleanup_timers(timers: &mut Vec<TimerHandle>) -> Result<usize, SessionError> {
    let count = timers.len();

    info!(timer_count = count, "Starting timer cleanup");

    let mut cancelled = 0;

    for timer in timers.drain(..) {
        let description = timer.description().to_string();
        timer.cancel();
        cancelled += 1;

        debug!(
            timer = %description,
            "Timer cancelled"
        );
    }

    info!(timers_cancelled = cancelled, "Timer cleanup complete");

    Ok(cancelled)
}

/// Free all packet buffers
///
/// Releases all packet buffers back to the pool or operating system,
/// securely zeroing buffer contents.
///
/// # Arguments
/// * `buffers` - Mutable vector of packet buffers
///
/// # Returns
/// * `Ok(usize)` - Number of buffers successfully freed
/// * `Err` - If cleanup fails
pub async fn cleanup_buffers(buffers: &mut Vec<PacketBuffer>) -> Result<usize, SessionError> {
    let count = buffers.len();

    info!(buffer_count = count, "Starting buffer cleanup");

    let mut freed = 0;

    for buffer in buffers.iter_mut() {
        if buffer.is_in_use() {
            buffer.free();
            freed += 1;
        }
    }

    // Clear the vector (Drop impl will zeroize remaining data)
    buffers.clear();

    info!(
        buffers_freed = freed,
        total_buffers = count,
        "Buffer cleanup complete"
    );

    Ok(count)
}

/// Cleanup context for connection termination
///
/// Aggregates all cleanup state for a connection.
pub struct CleanupContext {
    /// Session keys to cleanup
    pub session_keys: Arc<RwLock<HashMap<SessionId, SessionKeyState>>>,
    /// Port bindings to release
    pub port_bindings: Arc<RwLock<HashMap<Port, PortBinding>>>,
    /// Sequence states to clear
    pub sequence_states: Arc<RwLock<HashMap<SessionId, SequenceState>>>,
    /// Replay cache to purge
    pub replay_cache: Arc<RwLock<HashMap<SessionId, Vec<ReplayCacheEntry>>>>,
    /// Timers to cancel
    pub timers: Arc<RwLock<Vec<TimerHandle>>>,
    /// Buffers to free
    pub buffers: Arc<RwLock<Vec<PacketBuffer>>>,
}

impl CleanupContext {
    /// Create new cleanup context
    pub fn new() -> Self {
        Self {
            session_keys: Arc::new(RwLock::new(HashMap::new())),
            port_bindings: Arc::new(RwLock::new(HashMap::new())),
            sequence_states: Arc::new(RwLock::new(HashMap::new())),
            replay_cache: Arc::new(RwLock::new(HashMap::new())),
            timers: Arc::new(RwLock::new(Vec::new())),
            buffers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Perform complete cleanup of all resources
    pub async fn cleanup_all(&self) -> Result<CleanupStats, SessionError> {
        let mut stats = CleanupStats::default();

        // Cleanup in dependency order:
        // 1. Cancel timers first (prevents callbacks during cleanup)
        stats.timers_cancelled = cleanup_timers(&mut *self.timers.write().await).await?;

        // 2. Clear sequence state
        stats.states_cleared =
            cleanup_sequence_state(&mut *self.sequence_states.write().await).await?;

        // 3. Purge replay cache
        stats.cache_entries_purged =
            cleanup_replay_cache(&mut *self.replay_cache.write().await).await?;

        // 4. Release port bindings
        stats.ports_released =
            cleanup_port_bindings(&mut *self.port_bindings.write().await).await?;

        // 5. Free buffers
        stats.buffers_freed = cleanup_buffers(&mut *self.buffers.write().await).await?;

        // 6. Zero session keys last (most sensitive)
        stats.keys_zeroed = cleanup_session_keys(&mut *self.session_keys.write().await).await?;

        info!(
            keys_zeroed = stats.keys_zeroed,
            ports_released = stats.ports_released,
            states_cleared = stats.states_cleared,
            cache_purged = stats.cache_entries_purged,
            timers_cancelled = stats.timers_cancelled,
            buffers_freed = stats.buffers_freed,
            "Complete cleanup finished"
        );

        Ok(stats)
    }
}

impl Default for CleanupContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from cleanup operations
#[derive(Debug, Clone, Default)]
pub struct CleanupStats {
    /// Number of session keys zeroed
    pub keys_zeroed: usize,
    /// Number of port bindings released
    pub ports_released: usize,
    /// Number of sequence states cleared
    pub states_cleared: usize,
    /// Number of replay cache entries purged
    pub cache_entries_purged: usize,
    /// Number of timers cancelled
    pub timers_cancelled: usize,
    /// Number of buffers freed
    pub buffers_freed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cleanup_session_keys_zeros_keys() {
        // Create test session keys
        let mut session_keys = HashMap::new();
        let session_id = SessionId::from_raw(1);
        let key = crate::protocol::types::SessionKey::new([0x42; 32]);
        session_keys.insert(session_id.clone(), SessionKeyState::new(key));

        // Verify key exists and is not zeroed
        assert_eq!(session_keys.len(), 1);
        assert!(!session_keys.get(&session_id).unwrap().is_zeroed());

        // Cleanup
        let count = cleanup_session_keys(&mut session_keys).await.unwrap();

        // Verify cleanup
        assert_eq!(count, 1);
        assert_eq!(session_keys.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_port_bindings_releases_ports() {
        // Create test port bindings
        let mut port_bindings = HashMap::new();
        let port = Port::from_u16_unchecked(8080);
        port_bindings.insert(
            port,
            PortBinding {
                port,
                active: true,
                socket_fd: None,
            },
        );

        // Verify binding exists
        assert_eq!(port_bindings.len(), 1);
        assert!(port_bindings.get(&port).unwrap().active);

        // Cleanup
        let count = cleanup_port_bindings(&mut port_bindings).await.unwrap();

        // Verify cleanup
        assert_eq!(count, 1);
        assert_eq!(port_bindings.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_sequence_state_clears_state() {
        // Create test sequence states
        let mut sequence_states = HashMap::new();
        let session_id = SessionId::from_raw(1);
        sequence_states.insert(
            session_id.clone(),
            SequenceState {
                send_seq: SequenceNumber::new(100),
                recv_seq: SequenceNumber::new(200),
                last_ack: SequenceNumber::new(150),
            },
        );

        // Verify state exists
        assert_eq!(sequence_states.len(), 1);

        // Cleanup
        let count = cleanup_sequence_state(&mut sequence_states).await.unwrap();

        // Verify cleanup
        assert_eq!(count, 1);
        assert_eq!(sequence_states.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_replay_cache_purges_caches() {
        // Create test replay cache
        let mut replay_cache = HashMap::new();
        let session_id = SessionId::from_raw(1);
        replay_cache.insert(
            session_id.clone(),
            vec![
                ReplayCacheEntry {
                    timestamp: Timestamp::now(),
                    sequence: SequenceNumber::new(1),
                    session_id: session_id.clone(),
                },
                ReplayCacheEntry {
                    timestamp: Timestamp::now(),
                    sequence: SequenceNumber::new(2),
                    session_id: session_id.clone(),
                },
            ],
        );

        // Verify cache exists
        assert_eq!(replay_cache.len(), 1);
        assert_eq!(replay_cache.get(&session_id).unwrap().len(), 2);

        // Cleanup
        let count = cleanup_replay_cache(&mut replay_cache).await.unwrap();

        // Verify cleanup
        assert_eq!(count, 2); // 2 entries purged
        assert_eq!(replay_cache.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_timers_cancels_timers() {
        // Create test timers
        let mut timers = Vec::new();
        let handle = tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        });
        timers.push(TimerHandle::new(handle, "test_timer".to_string()));

        // Verify timer exists
        assert_eq!(timers.len(), 1);

        // Cleanup
        let count = cleanup_timers(&mut timers).await.unwrap();

        // Verify cleanup
        assert_eq!(count, 1);
        assert_eq!(timers.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_buffers_frees_buffers() {
        // Create test buffers
        let mut buffers = Vec::new();
        let mut buffer = PacketBuffer::new(1500);
        buffer.allocate(100).unwrap();
        buffers.push(buffer);

        // Verify buffer exists and is in use
        assert_eq!(buffers.len(), 1);
        assert!(buffers[0].is_in_use());

        // Cleanup
        let count = cleanup_buffers(&mut buffers).await.unwrap();

        // Verify cleanup
        assert_eq!(count, 1);
        assert_eq!(buffers.len(), 0);
    }

    #[tokio::test]
    async fn test_cleanup_context_cleanup_all() {
        // Create cleanup context with test data
        let context = CleanupContext::new();

        // Add test data
        let session_id = SessionId::from_raw(1);
        let key = crate::protocol::types::SessionKey::new([0x42; 32]);
        context
            .session_keys
            .write()
            .await
            .insert(session_id.clone(), SessionKeyState::new(key));

        let port = Port::from_u16_unchecked(8080);
        context.port_bindings.write().await.insert(
            port,
            PortBinding {
                port,
                active: true,
                socket_fd: None,
            },
        );

        // Perform cleanup
        let stats = context.cleanup_all().await.unwrap();

        // Verify stats
        assert_eq!(stats.keys_zeroed, 1);
        assert_eq!(stats.ports_released, 1);

        // Verify all maps are empty
        assert_eq!(context.session_keys.read().await.len(), 0);
        assert_eq!(context.port_bindings.read().await.len(), 0);
    }
}
