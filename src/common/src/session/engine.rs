// Session engine implementation
//
// This file implements the SessionEngine using DashMap for O(1) lock-free session lookup.
#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tracing;

use super::state::SessionState;
use crate::error::security::SecurityError;
use crate::memory::secure::SecureBytes;
use crate::protocol::types::{ConnectionId, Epoch, Port, SequenceNumber, SessionId, Timestamp};
use crate::security::crypto::kdf::{Kdf, KdfResult};

/// eBPF session information structure for kernel-userspace synchronization
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EbpfSessionInfo {
    /// Session ID - using raw u64 for eBPF compatibility
    pub session_id: u64, // Raw u64 for eBPF boundary compatibility
    /// Last sequence number seen
    pub last_sequence: crate::protocol::types::SequenceNumber,
    /// Expected port for next packet
    pub expected_port: crate::protocol::types::Port,
    /// Last packet timestamp (seconds since UNIX epoch)
    pub last_packet_time: Timestamp,
    /// Packet count for this session
    pub packet_count: PacketCount,
    /// Session state
    pub session_state: u8, // Keep as u8 for eBPF compatibility
}

impl EbpfSessionInfo {
    /// Convert eBPF session ID to typed SessionId
    pub fn get_session_id(&self) -> SessionId {
        SessionId::from_raw(self.session_id)
    }

    /// Create from typed SessionId
    pub fn with_session_id(session_id: SessionId) -> Self {
        Self {
            session_id: session_id.as_u64(),
            last_sequence: SequenceNumber::from_raw(0),
            expected_port: Port::from_raw(0),
            last_packet_time: Timestamp::from(0),
            packet_count: PacketCount::zero(),
            session_state: 0,
        }
    }
}

/// Session engine for lock-free session lookup with reference counting
/// Now operates as an engine within a connection rather than globally
pub struct SessionEngine {
    /// Session map with reference counting for safe concurrent access
    sessions: DashMap<SessionId, Arc<SessionState>>,

    /// Session cleanup interval
    cleanup_interval: Duration,

    /// Session idle timeout
    idle_timeout: Duration,

    /// Last cleanup time
    last_cleanup: Instant,

    /// Reference count tracking for active sessions
    active_references: DashMap<SessionId, usize>,

    /// Connection established state for M2 recovery enforcement
    /// Per M2 spec, recovery sub-states are only accessible from ESTABLISHED state
    connection_established: AtomicBool,
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionEngineConfig {
    pub cleanup_interval: Duration,
    pub idle_timeout: Duration,
}

impl Default for SessionEngineConfig {
    fn default() -> Self {
        Self {
            cleanup_interval: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

impl SessionEngine {
    /// Create a new session engine
    pub fn new(config: SessionEngineConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            cleanup_interval: config.cleanup_interval,
            idle_timeout: config.idle_timeout,
            last_cleanup: Instant::now(),
            active_references: DashMap::new(),
            connection_established: AtomicBool::new(false),
        }
    }

    /// Set connection established state
    /// Called when connection transitions to/from ESTABLISHED state
    pub fn set_connection_established(&self, established: bool) {
        self.connection_established
            .store(established, Ordering::Release);
    }

    /// Create a new session engine for a specific connection
    pub fn new_for_connection(_connection_id: ConnectionId) -> Self {
        Self::new(SessionEngineConfig::default())
    }

    /// Create a new session engine with default settings
    pub fn new_default() -> Self {
        Self::new(SessionEngineConfig::default())
    }

    /// Generate a cryptographically secure session ID with collision detection
    /// Uses 64-bit session IDs by default for maximum uniqueness
    pub fn generate_session_id(&self) -> Result<SessionId, SecurityError> {
        let mut attempts = 0u32;
        const MAX_ATTEMPTS: u32 = 1000;

        loop {
            // Generate cryptographically secure random session ID
            let mut rng = rand::thread_rng();
            let session_id = SessionId::from_raw(rng.r#gen::<u64>());

            // Ensure session ID is not zero
            if session_id.as_u64() == 0 {
                attempts += 1;
                if attempts >= MAX_ATTEMPTS {
                    return Err(SecurityError::CryptographicError {
                        reason: format!(
                            "Failed to generate valid session ID after {} attempts",
                            MAX_ATTEMPTS
                        ),
                    });
                }
                continue;
            }

            // Check for collisions using atomic operation
            if !self.sessions.contains_key(&session_id) {
                return Ok(session_id);
            }

            attempts += 1;
            if attempts >= MAX_ATTEMPTS {
                return Err(SecurityError::CryptographicError {
                    reason: format!(
                        "Failed to generate unique session ID after {} attempts - session table may be full",
                        MAX_ATTEMPTS
                    ),
                });
            }
        }
    }

    /// Create a new session with reference counting
    pub fn create_session(&self) -> Result<(SessionId, Arc<SessionState>), SecurityError> {
        let session_id = self.generate_session_id()?;
        let session = Arc::new(SessionState::new());

        // Insert session (no reference counting for the returned session)
        self.sessions.insert(session_id.clone(), session.clone());

        // Update eBPF map
        if let Err(e) = self.update_ebpf_session_map(&session_id, &session) {
            tracing::warn!(
                session_id = %session_id,
                error = %e,
                "Failed to update eBPF map for new session"
            );
        }

        Ok((session_id, session))
    }

    /// Get a session by ID with reference counting
    pub fn get_session(&self, session_id: &SessionId) -> Option<Arc<SessionState>> {
        if let Some(session) = self.sessions.get(session_id) {
            // Increment reference count atomically
            self.active_references
                .entry(session_id.clone())
                .and_modify(|count| *count += 1)
                .or_insert(1);

            Some(session.clone())
        } else {
            None
        }
    }

    /// Release a session reference
    pub fn release_session(&self, session_id: &SessionId) {
        if let Some(mut entry) = self.active_references.get_mut(session_id) {
            if *entry > 0 {
                *entry -= 1;
            }

            // If reference count reaches zero, the session can be cleaned up
            if *entry == 0 {
                drop(entry); // Release the lock
                self.active_references.remove(session_id);
            }
        }
    }

    /// Get reference count for a session
    pub fn get_reference_count(&self, session_id: &SessionId) -> usize {
        self.active_references
            .get(session_id)
            .map(|entry| *entry)
            .unwrap_or(0)
    }

    /// Remove a session by ID with reference counting safety
    pub fn remove_session(&self, session_id: &SessionId) -> bool {
        // Check if session has active references
        if self.get_reference_count(session_id) > 0 {
            tracing::warn!(
                session_id = %session_id,
                ref_count = self.get_reference_count(session_id),
                "Attempting to remove session with active references"
            );
            return false;
        }

        // Remove from eBPF map first
        if let Err(e) = self.remove_ebpf_session(session_id) {
            tracing::warn!(
                session_id = %session_id,
                error = e,
                "Failed to remove session from eBPF map"
            );
        }

        // Remove from both maps
        let session_removed = self.sessions.remove(session_id).is_some();
        self.active_references.remove(session_id);

        session_removed
    }

    /// Force remove a session (ignoring reference count)
    pub fn force_remove_session(&self, session_id: &SessionId) -> bool {
        // Remove from eBPF map first
        if let Err(e) = self.remove_ebpf_session(session_id) {
            tracing::warn!(
                session_id = %session_id,
                error = e,
                "Failed to remove session from eBPF map"
            );
        }

        // Remove from both maps
        let session_removed = self.sessions.remove(session_id).is_some();
        self.active_references.remove(session_id);

        if session_removed {
            tracing::info!(
                session_id = %session_id,
                "Force removed session"
            );
        }

        session_removed
    }

    /// Get the number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Clean up idle sessions with reference counting safety
    pub fn cleanup_sessions(&mut self) -> usize {
        // Check if it's time to clean up
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) < self.cleanup_interval {
            return 0;
        }

        self.last_cleanup = now;

        // Find idle sessions that have no active references
        let idle_sessions: Vec<SessionId> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let session_id = entry.key().clone();
                let session = entry.value();

                // Only clean up if session is idle AND has no active references
                if session.is_idle(self.idle_timeout) && self.get_reference_count(&session_id) == 0
                {
                    Some(session_id)
                } else {
                    None
                }
            })
            .collect();

        // Remove idle sessions
        let mut removed_count = 0;
        for session_id in &idle_sessions {
            if self.remove_session(session_id) {
                removed_count += 1;
                tracing::debug!(
                    session_id = %session_id,
                    "Cleaned up idle session"
                );
            }
        }

        // Log cleanup statistics
        if removed_count > 0 {
            tracing::info!(
                removed = removed_count,
                total_sessions = self.session_count(),
                "Session cleanup completed"
            );
        }

        removed_count
    }

    /// Initialize a session from PBKDF2-derived parameters
    pub fn init_session_from_pbkdf2(
        &self,
        session_id: &SessionId,
        params: &[u8],
    ) -> Result<(), &'static str> {
        // Get the session
        let session = self.get_session(session_id).ok_or("Session not found")?;

        // Initialize the session
        session.init_from_pbkdf2(params)?;

        Ok(())
    }

    /// Derive session parameters from ECDH shared secret
    pub fn derive_session_parameters(
        &self,
        shared_secret: &[u8],
        salt: &[u8],
    ) -> KdfResult<SecureBytes> {
        // Create KDF with the provided salt
        let mut kdf = Kdf::new_default();
        kdf.set_salt(SaltBytes::new(salt.to_vec()));

        // Derive parameters
        #[allow(deprecated)]
        let result = kdf.derive_parameters(shared_secret);
        result
    }

    /// Create a session with parameters derived from ECDH shared secret
    pub fn create_session_with_ecdh(
        &self,
        shared_secret: &[u8],
        salt: &[u8],
    ) -> KdfResult<(SessionId, Arc<SessionState>)> {
        // Create a new session
        let (session_id, session) = self.create_session()?;

        // Derive parameters
        let params = self.derive_session_parameters(shared_secret, salt)?;

        // Initialize the session
        if let Err(e) = session.init_from_pbkdf2(&params) {
            return Err(SecurityError::internal_error(format!(
                "Key derivation failed: {}",
                e
            )));
        }

        Ok((session_id, session))
    }

    /// Update eBPF session map with atomic state synchronization
    pub fn update_ebpf_session_map(
        &self,
        session_id: &SessionId,
        session: &SessionState,
    ) -> Result<(), &'static str> {
        // Create eBPF session info structure
        let ebpf_session_info = EbpfSessionInfo {
            session_id: session_id.as_u64(),
            last_sequence: SequenceNumber::from_raw(session.remote_seq().as_u32()),
            expected_port: Port::from_raw(session.remote_port().as_u16()),
            last_packet_time: Timestamp::from_nanos(session.last_activity()),
            packet_count: PacketCount::new(0), // This would be maintained by eBPF
            session_state: session.status() as u8,
        };

        // In a real implementation, this would use eBPF map operations
        // For now, we simulate the operation
        tracing::debug!(
            session_id = %session_id,
            sequence = %ebpf_session_info.last_sequence,
            port = %ebpf_session_info.expected_port,
            "Updated eBPF session map"
        );

        Ok(())
    }

    /// Remove session from eBPF map
    pub fn remove_ebpf_session(&self, session_id: &SessionId) -> Result<(), &'static str> {
        // In a real implementation, this would remove the session from eBPF map
        tracing::debug!(session_id = %session_id, "Removed session from eBPF map");
        Ok(())
    }

    /// Synchronize all sessions with eBPF
    pub fn sync_all_sessions_to_ebpf(&self) -> Result<usize, &'static str> {
        let mut synced_count = 0;

        for entry in self.sessions.iter() {
            let session_id = entry.key();
            let session = entry.value();

            if let Err(e) = self.update_ebpf_session_map(session_id, session) {
                tracing::warn!(
                    session_id = %session_id,
                    error = e,
                    "Failed to sync session to eBPF"
                );
            } else {
                synced_count += 1;
            }
        }

        Ok(synced_count)
    }

    /// Calculate a deterministic port for a given time bucket and session
    pub fn calculate_port(
        &self,
        session: &SessionState,
        time_bucket: Epoch,
        is_local: bool,
    ) -> Port {
        // Get the port hopping parameters
        let seed1 = session.port_hop_param(0).unwrap_or(0);
        let seed2 = session.port_hop_param(1).unwrap_or(0);
        let seed3 = session.port_hop_param(2).unwrap_or(0);
        let seed4 = session.port_hop_param(3).unwrap_or(0);

        // Combine seeds into a 64-bit seed
        let seed = ((seed1 as u64) << 48)
            | ((seed2 as u64) << 32)
            | ((seed3 as u64) << 16)
            | (seed4 as u64);

        // Create a deterministic RNG from the seed and time bucket
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        (time_bucket.as_u64()).hash(&mut hasher);
        if is_local {
            1u8.hash(&mut hasher);
        } else {
            0u8.hash(&mut hasher);
        }
        let rng_seed = hasher.finish();

        // Use ChaCha20 for high-quality deterministic randomness
        let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);

        // Generate a port in the dynamic/private port range (49152-65535)
        let port_range = 65535 - 49152 + 1;
        let port_num = 49152 + (rng.r#gen::<u16>() % port_range as u16);
        // Safety: port_num is guaranteed to be in range [49152, 65535]
        Port(port_num)
    }

    /// Set the cleanup interval
    pub fn set_cleanup_interval(&mut self, interval: Duration) {
        self.cleanup_interval = interval;
    }

    /// Set the idle timeout
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.idle_timeout = timeout;
    }

    /// Get all session IDs
    pub fn get_all_session_ids(&self) -> Vec<SessionId> {
        self.sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get the cleanup interval
    pub fn cleanup_interval(&self) -> Duration {
        self.cleanup_interval
    }

    /// Get the idle timeout
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

impl Default for SessionEngine {
    fn default() -> Self {
        Self::new(SessionEngineConfig::default())
    }
}

// Import the trait from recovery engine
use crate::engines::recovery::engine::SessionManagerTrait;
use crate::error::EngineError;

impl SessionManagerTrait for SessionEngine {
    fn get_session_state(&self, session_id: &SessionId) -> Option<Arc<SessionState>> {
        self.get_session(session_id)
    }

    fn update_session_state(
        &self,
        session_id: &SessionId,
        state: Arc<SessionState>,
    ) -> Result<(), EngineError> {
        // Update the session in the sessions map
        self.sessions.insert(session_id.clone(), state.clone());

        // Update eBPF map
        if let Err(e) = self.update_ebpf_session_map(session_id, &state) {
            return Err(EngineError::engine_coordination_error(format!(
                "Failed to update eBPF session map: {}",
                e
            )));
        }

        Ok(())
    }

    fn get_session_key(&self, _session_id: &SessionId) -> Option<SessionKey> {
        // Session key retrieval is not yet wired up to session state storage.
        // Once SessionState includes key management, this will retrieve the appropriate key.
        None
    }

    fn is_connection_established(&self) -> bool {
        self.connection_established.load(Ordering::Acquire)
    }
}
