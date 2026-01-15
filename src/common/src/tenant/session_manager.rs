//! Tenant session management
//!
//! This module implements per-tenant session management with isolation guarantees:
//! - TenantSessionId combining TenantId + SessionId
//! - Per-tenant session ID generation with collision avoidance
//! - Session routing table for packet dispatch

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::SessionId;
use crate::tenant::TenantId;
use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

/// Errors related to tenant session operations
#[derive(Error, Debug)]
pub enum TenantSessionError {
    #[error("Session ID exhausted after maximum attempts")]
    SessionIdExhausted,

    #[error("Session not found: tenant={tenant_id}, session={session_id}")]
    SessionNotFound {
        tenant_id: TenantId,
        session_id: SessionId,
    },

    #[error("Session already exists: tenant={tenant_id}, session={session_id}")]
    SessionAlreadyExists {
        tenant_id: TenantId,
        session_id: SessionId,
    },
}

/// Maximum attempts for session ID generation
const MAX_SESSION_ID_GENERATION_ATTEMPTS: usize = 100;

/// Tenant-scoped session identifier.
///
/// Ensures complete session isolation between tenants:
/// - Session IDs unique within tenant scope only
/// - No cross-tenant session ID collisions
/// - Efficient session lookup by tenant + session ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantSessionId {
    /// Tenant owning this session
    pub tenant_id: TenantId,

    /// Session ID unique within tenant scope
    pub session_id: SessionId,
}

impl TenantSessionId {
    /// Creates a new tenant-scoped session ID.
    pub const fn new(tenant_id: TenantId, session_id: SessionId) -> Self {
        Self {
            tenant_id,
            session_id,
        }
    }

    /// Returns the tenant ID component
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the session ID component
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

impl fmt::Display for TenantSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:session-{}", self.tenant_id, self.session_id.get())
    }
}

/// Session routing metadata for packet dispatch
#[derive(Debug, Clone)]
pub struct SessionRoutingEntry {
    /// Tenant-scoped session identifier
    pub tenant_session_id: TenantSessionId,

    /// Last packet timestamp (for timeout tracking)
    pub last_packet_ns: u64,

    /// Session state for routing decisions
    pub state: SessionState,
}

/// Session state for routing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// Session is being established
    Establishing = 0,

    /// Session is active and operational
    Active = 1,

    /// Session is terminating
    Terminating = 2,

    /// Session is terminated
    Terminated = 3,
}

/// Session ID generator with per-tenant collision tracking.
pub struct TenantSessionIdGenerator {
    /// Per-tenant session ID counters (for sequential allocation)
    tenant_counters: Arc<DashMap<TenantId, AtomicU64>>,

    /// Per-tenant active session sets (for collision detection)
    active_sessions: Arc<DashMap<TenantId, DashSet<SessionId>>>,
}

impl TenantSessionIdGenerator {
    /// Creates a new session ID generator
    pub fn new() -> Self {
        Self {
            tenant_counters: Arc::new(DashMap::new()),
            active_sessions: Arc::new(DashMap::new()),
        }
    }

    /// Generates a new session ID within tenant scope
    ///
    /// Uses atomic counter with collision detection to ensure uniqueness
    /// within the tenant's session namespace.
    pub fn generate(&self, tenant_id: TenantId) -> Result<SessionId, TenantSessionError> {
        let counter = self
            .tenant_counters
            .entry(tenant_id)
            .or_insert_with(|| AtomicU64::new(0));

        let active = self.active_sessions.entry(tenant_id).or_default();

        for _ in 0..MAX_SESSION_ID_GENERATION_ATTEMPTS {
            let raw_id = counter.fetch_add(1, Ordering::SeqCst);
            let session_id = SessionId::new(raw_id);

            // Check collision within tenant scope
            if active.insert(session_id.clone()) {
                return Ok(session_id);
            }
        }

        Err(TenantSessionError::SessionIdExhausted)
    }

    /// Releases a session ID within tenant scope
    pub fn release(&self, tenant_id: TenantId, session_id: &SessionId) {
        if let Some(active) = self.active_sessions.get(&tenant_id) {
            active.remove(session_id);
        }
    }

    /// Returns the count of active sessions for a tenant
    pub fn active_session_count(&self, tenant_id: TenantId) -> usize {
        self.active_sessions
            .get(&tenant_id)
            .map(|set| set.len())
            .unwrap_or(0)
    }
}

impl Default for TenantSessionIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Session manager with per-tenant isolation
pub struct TenantSessionManager {
    /// Session ID generator
    id_generator: Arc<TenantSessionIdGenerator>,

    /// Session routing table: (tenant_id, session_id) -> routing_entry
    routing_table: Arc<DashMap<(TenantId, SessionId), SessionRoutingEntry>>,

    /// Per-tenant session index: tenant_id -> set of session_ids
    tenant_sessions: Arc<DashMap<TenantId, DashSet<SessionId>>>,
}

impl TenantSessionManager {
    /// Creates a new tenant session manager
    pub fn new() -> Self {
        Self {
            id_generator: Arc::new(TenantSessionIdGenerator::new()),
            routing_table: Arc::new(DashMap::new()),
            tenant_sessions: Arc::new(DashMap::new()),
        }
    }

    /// Creates a new session for a tenant
    ///
    /// Generates a unique session ID within the tenant's namespace and
    /// adds routing entry to the dispatch table.
    pub fn create_session(
        &self,
        tenant_id: TenantId,
    ) -> Result<TenantSessionId, TenantSessionError> {
        let session_id = self.id_generator.generate(tenant_id)?;
        let tenant_session_id = TenantSessionId::new(tenant_id, session_id.clone());

        let routing_entry = SessionRoutingEntry {
            tenant_session_id: tenant_session_id.clone(),
            last_packet_ns: 0,
            state: SessionState::Establishing,
        };

        self.routing_table
            .insert((tenant_id, session_id.clone()), routing_entry);

        self.tenant_sessions
            .entry(tenant_id)
            .or_default()
            .insert(session_id);

        Ok(tenant_session_id)
    }

    /// Looks up session routing information
    pub fn lookup_session(
        &self,
        tenant_id: TenantId,
        session_id: &SessionId,
    ) -> Option<dashmap::mapref::one::Ref<'_, (TenantId, SessionId), SessionRoutingEntry>> {
        self.routing_table.get(&(tenant_id, session_id.clone()))
    }

    /// Updates session state
    pub fn update_session_state(
        &self,
        tenant_id: TenantId,
        session_id: &SessionId,
        new_state: SessionState,
    ) -> Result<(), TenantSessionError> {
        if let Some(mut entry) = self.routing_table.get_mut(&(tenant_id, session_id.clone())) {
            entry.state = new_state;
            Ok(())
        } else {
            Err(TenantSessionError::SessionNotFound {
                tenant_id,
                session_id: session_id.clone(),
            })
        }
    }

    /// Updates session last packet timestamp
    pub fn update_last_packet_time(
        &self,
        tenant_id: TenantId,
        session_id: &SessionId,
        timestamp_ns: u64,
    ) {
        if let Some(mut entry) = self.routing_table.get_mut(&(tenant_id, session_id.clone())) {
            entry.last_packet_ns = timestamp_ns;
        }
    }

    /// Removes a session
    pub fn remove_session(
        &self,
        tenant_id: TenantId,
        session_id: &SessionId,
    ) -> Option<SessionRoutingEntry> {
        if let Some((_, entry)) = self.routing_table.remove(&(tenant_id, session_id.clone())) {
            // Release session ID
            self.id_generator.release(tenant_id, session_id);

            // Remove from tenant index
            if let Some(sessions) = self.tenant_sessions.get(&tenant_id) {
                sessions.remove(session_id);
            }

            Some(entry)
        } else {
            None
        }
    }

    /// Lists all active sessions for a tenant
    pub fn list_tenant_sessions(&self, tenant_id: TenantId) -> Vec<SessionId> {
        self.tenant_sessions
            .get(&tenant_id)
            .map(|sessions| sessions.iter().map(|s| s.clone()).collect())
            .unwrap_or_default()
    }

    /// Returns the count of active sessions for a tenant
    pub fn tenant_session_count(&self, tenant_id: TenantId) -> usize {
        self.tenant_sessions
            .get(&tenant_id)
            .map(|sessions| sessions.len())
            .unwrap_or(0)
    }

    /// Returns total session count across all tenants
    pub fn total_session_count(&self) -> usize {
        self.routing_table.len()
    }
}

impl Default for TenantSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_session_id_creation() {
        let tenant_id = TenantId::from_u64(1);
        let session_id = SessionId::new(42);
        let ts_id = TenantSessionId::new(tenant_id, session_id);

        assert_eq!(ts_id.tenant_id(), tenant_id);
        assert_eq!(ts_id.session_id().get(), 42);
    }

    #[test]
    fn test_session_id_generator_uniqueness() {
        let generator = TenantSessionIdGenerator::new();
        let tenant_id = TenantId::from_u64(1);

        let id1 = generator.generate(tenant_id);
        let id2 = generator.generate(tenant_id);

        assert!(id1.is_ok());
        assert!(id2.is_ok());
        assert_ne!(id1.unwrap(), id2.unwrap());
    }

    #[test]
    fn test_session_id_generator_release() {
        let generator = TenantSessionIdGenerator::new();
        let tenant_id = TenantId::from_u64(1);

        let session_id = generator.generate(tenant_id).unwrap();
        assert_eq!(generator.active_session_count(tenant_id), 1);

        generator.release(tenant_id, &session_id);
        assert_eq!(generator.active_session_count(tenant_id), 0);
    }

    #[test]
    fn test_session_manager_create_session() {
        let manager = TenantSessionManager::new();
        let tenant_id = TenantId::from_u64(1);

        let ts_id = manager.create_session(tenant_id).unwrap();

        assert_eq!(ts_id.tenant_id(), tenant_id);
        assert_eq!(manager.tenant_session_count(tenant_id), 1);
    }

    #[test]
    fn test_session_manager_isolation() {
        let manager = TenantSessionManager::new();
        let tenant1 = TenantId::from_u64(1);
        let tenant2 = TenantId::from_u64(2);

        let ts_id1 = manager.create_session(tenant1).unwrap();
        let ts_id2 = manager.create_session(tenant2).unwrap();

        // Sessions should have different tenants
        assert_ne!(ts_id1.tenant_id(), ts_id2.tenant_id());

        // Each tenant should have 1 session
        assert_eq!(manager.tenant_session_count(tenant1), 1);
        assert_eq!(manager.tenant_session_count(tenant2), 1);
    }

    #[test]
    fn test_session_manager_lookup() {
        let manager = TenantSessionManager::new();
        let tenant_id = TenantId::from_u64(1);

        let ts_id = manager.create_session(tenant_id).unwrap();
        let entry = manager.lookup_session(tenant_id, &ts_id.session_id);

        assert!(entry.is_some());
        assert_eq!(
            entry.unwrap().tenant_session_id.tenant_id(),
            ts_id.tenant_id()
        );
    }

    #[test]
    fn test_session_manager_remove() {
        let manager = TenantSessionManager::new();
        let tenant_id = TenantId::from_u64(1);

        let ts_id = manager.create_session(tenant_id).unwrap();
        assert_eq!(manager.tenant_session_count(tenant_id), 1);

        let entry = manager.remove_session(tenant_id, &ts_id.session_id);
        assert!(entry.is_some());
        assert_eq!(manager.tenant_session_count(tenant_id), 0);
    }

    #[test]
    fn test_session_manager_list_sessions() {
        let manager = TenantSessionManager::new();
        let tenant_id = TenantId::from_u64(1);

        let ts_id1 = manager.create_session(tenant_id).unwrap();
        let ts_id2 = manager.create_session(tenant_id).unwrap();

        let sessions = manager.list_tenant_sessions(tenant_id);
        assert_eq!(sessions.len(), 2);
        assert!(sessions.contains(&ts_id1.session_id));
        assert!(sessions.contains(&ts_id2.session_id));
    }

    #[test]
    fn test_session_state_update() {
        let manager = TenantSessionManager::new();
        let tenant_id = TenantId::from_u64(1);

        let ts_id = manager.create_session(tenant_id).unwrap();

        manager
            .update_session_state(tenant_id, &ts_id.session_id, SessionState::Active)
            .unwrap();

        let entry = manager
            .lookup_session(tenant_id, &ts_id.session_id)
            .unwrap();
        assert_eq!(entry.state, SessionState::Active);
    }

    #[test]
    fn test_last_packet_time_update() {
        let manager = TenantSessionManager::new();
        let tenant_id = TenantId::from_u64(1);

        let ts_id = manager.create_session(tenant_id).unwrap();
        manager.update_last_packet_time(tenant_id, &ts_id.session_id, 12345);

        let entry = manager
            .lookup_session(tenant_id, &ts_id.session_id)
            .unwrap();
        assert_eq!(entry.last_packet_ns, 12345);
    }
}
