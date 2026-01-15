//! Cross-tenant security enforcement
//!
//! This module implements security boundaries between tenants:
//! - Session validation to prevent cross-tenant access
//! - Per-tenant source IP blocking
//! - Audit logging for security events

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::protocol::types::SessionId;
use crate::tenant::TenantId;
use crate::tenant::session_manager::SessionRoutingEntry;
use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Security-related errors
#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Cross-tenant access attempt: claimed={claimed_tenant_id}, actual={actual_tenant_id}")]
    CrossTenantAccessAttempt {
        claimed_tenant_id: TenantId,
        actual_tenant_id: TenantId,
    },

    #[error("Source IP blocked for tenant: tenant={tenant_id}, ip={source_ip}")]
    SourceBlocked {
        tenant_id: TenantId,
        source_ip: IpAddr,
    },

    #[error("Maximum authentication attempts exceeded: tenant={tenant_id}, ip={source_ip}")]
    MaxAuthAttemptsExceeded {
        tenant_id: TenantId,
        source_ip: IpAddr,
    },

    #[error("System time error: {0}")]
    SystemTimeError(String),
}

/// Security event types for audit logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityEventType {
    /// Authentication failure
    AuthenticationFailure = 0x01,

    /// Replay attack detected
    ReplayAttackDetected = 0x02,

    /// Cross-tenant access attempt
    CrossTenantAccessAttempt = 0x03,

    /// Rate limit exceeded
    RateLimitExceeded = 0x04,

    /// Invalid HMAC
    InvalidHmac = 0x05,

    /// Suspicious discovery pattern
    SuspiciousDiscoveryPattern = 0x06,

    /// Session hijack attempt
    SessionHijackAttempt = 0x07,

    /// Source IP blocked
    SourceIpBlocked = 0x08,

    /// Source IP unblocked
    SourceIpUnblocked = 0x09,
}

impl fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailure => write!(f, "AuthenticationFailure"),
            Self::ReplayAttackDetected => write!(f, "ReplayAttackDetected"),
            Self::CrossTenantAccessAttempt => write!(f, "CrossTenantAccessAttempt"),
            Self::RateLimitExceeded => write!(f, "RateLimitExceeded"),
            Self::InvalidHmac => write!(f, "InvalidHmac"),
            Self::SuspiciousDiscoveryPattern => write!(f, "SuspiciousDiscoveryPattern"),
            Self::SessionHijackAttempt => write!(f, "SessionHijackAttempt"),
            Self::SourceIpBlocked => write!(f, "SourceIpBlocked"),
            Self::SourceIpUnblocked => write!(f, "SourceIpUnblocked"),
        }
    }
}

/// Security event for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Tenant identifier
    pub tenant_id: TenantId,

    /// Timestamp (milliseconds since epoch)
    pub timestamp_ms: u64,

    /// Event type
    pub event_type: SecurityEventType,

    /// Source IP address
    pub source_ip: IpAddr,

    /// Optional session ID
    pub session_id: Option<SessionId>,

    /// Additional details (JSON-serializable)
    pub details: serde_json::Value,
}

/// Authentication attempt tracker
#[derive(Debug)]
struct AttemptCounter {
    /// Number of failures
    failures: AtomicUsize,

    /// Timestamp of first failure (milliseconds)
    first_failure_ms: AtomicU64,
}

impl AttemptCounter {
    fn new() -> Self {
        Self {
            failures: AtomicUsize::new(0),
            first_failure_ms: AtomicU64::new(0),
        }
    }

    fn increment(&self, now_ms: u64) -> usize {
        let first = self.first_failure_ms.load(Ordering::Acquire);

        // Reset if more than 5 minutes old
        if first > 0 && now_ms.saturating_sub(first) > 300_000 {
            self.failures.store(1, Ordering::Release);
            self.first_failure_ms.store(now_ms, Ordering::Release);
            1
        } else {
            if first == 0 {
                self.first_failure_ms.store(now_ms, Ordering::Release);
            }
            self.failures.fetch_add(1, Ordering::SeqCst) + 1
        }
    }

    fn reset(&self) {
        self.failures.store(0, Ordering::Release);
        self.first_failure_ms.store(0, Ordering::Release);
    }
}

/// Audit log buffer for per-tenant security events
#[derive(Debug)]
pub struct AuditLogBuffer {
    /// Circular buffer of recent events
    events: Arc<DashMap<u64, SecurityEvent>>,

    /// Current event ID counter
    event_counter: AtomicU64,

    /// Maximum events to retain
    max_events: usize,
}

impl AuditLogBuffer {
    const DEFAULT_MAX_EVENTS: usize = 10000;

    fn new() -> Self {
        Self {
            events: Arc::new(DashMap::new()),
            event_counter: AtomicU64::new(0),
            max_events: Self::DEFAULT_MAX_EVENTS,
        }
    }

    fn append(&self, event: SecurityEvent) {
        let event_id = self.event_counter.fetch_add(1, Ordering::SeqCst);

        self.events.insert(event_id, event);

        // Clean up old events if buffer is full
        if self.events.len() > self.max_events {
            let oldest_id = event_id.saturating_sub(self.max_events as u64);
            self.events.remove(&oldest_id);
        }
    }

    fn get_recent_events(&self, count: usize) -> Vec<SecurityEvent> {
        let current_id = self.event_counter.load(Ordering::Acquire);
        let start_id = current_id.saturating_sub(count as u64);

        let mut events: Vec<_> = self
            .events
            .iter()
            .filter(|entry| *entry.key() >= start_id)
            .map(|entry| entry.value().clone())
            .collect();

        events.sort_by_key(|e| e.timestamp_ms);
        events
    }
}

/// Cross-tenant security enforcer
pub struct CrossTenantSecurityEnforcer {
    /// Maximum authentication failures before blocking
    max_auth_failures: usize,

    /// Block duration in milliseconds
    block_duration_ms: u64,

    /// Tracks authentication attempts per (tenant, IP)
    auth_attempts: Arc<DashMap<(TenantId, IpAddr), AttemptCounter>>,

    /// Blocked sources per tenant
    blocked_sources: Arc<DashMap<TenantId, DashSet<IpAddr>>>,

    /// Audit log buffers per tenant
    audit_logs: Arc<DashMap<TenantId, AuditLogBuffer>>,
}

impl CrossTenantSecurityEnforcer {
    /// Default maximum authentication failures
    pub const DEFAULT_MAX_AUTH_FAILURES: usize = 5;

    /// Default block duration (5 minutes)
    pub const DEFAULT_BLOCK_DURATION_MS: u64 = 300_000;

    /// Creates a new security enforcer with default settings
    pub fn new() -> Self {
        Self {
            max_auth_failures: Self::DEFAULT_MAX_AUTH_FAILURES,
            block_duration_ms: Self::DEFAULT_BLOCK_DURATION_MS,
            auth_attempts: Arc::new(DashMap::new()),
            blocked_sources: Arc::new(DashMap::new()),
            audit_logs: Arc::new(DashMap::new()),
        }
    }

    /// Creates enforcer with custom settings
    pub fn with_config(max_auth_failures: usize, block_duration_ms: u64) -> Self {
        Self {
            max_auth_failures,
            block_duration_ms,
            auth_attempts: Arc::new(DashMap::new()),
            blocked_sources: Arc::new(DashMap::new()),
            audit_logs: Arc::new(DashMap::new()),
        }
    }

    /// Validates that packet session belongs to claimed tenant.
    ///
    /// Prevents cross-tenant session access by verifying session routing
    /// entry matches the claimed tenant ID.
    pub fn validate_tenant_session(
        &self,
        claimed_tenant_id: TenantId,
        session_id: &SessionId,
        session_routing_entry: &SessionRoutingEntry,
    ) -> Result<(), SecurityError> {
        let actual_tenant_id = session_routing_entry.tenant_session_id.tenant_id();

        if claimed_tenant_id != actual_tenant_id {
            let event = SecurityEvent {
                tenant_id: claimed_tenant_id,
                timestamp_ms: self.current_time_ms()?,
                event_type: SecurityEventType::CrossTenantAccessAttempt,
                source_ip: "0.0.0.0".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])),
                session_id: Some(session_id.clone()),
                details: serde_json::json!({
                    "claimed_tenant": claimed_tenant_id.as_u64(),
                    "actual_tenant": actual_tenant_id.as_u64(),
                }),
            };

            self.log_security_event(claimed_tenant_id, event);

            return Err(SecurityError::CrossTenantAccessAttempt {
                claimed_tenant_id,
                actual_tenant_id,
            });
        }

        Ok(())
    }

    /// Records authentication failure for source IP on a tenant
    pub fn record_auth_failure(
        &self,
        tenant_id: TenantId,
        source_ip: IpAddr,
    ) -> Result<(), SecurityError> {
        let now_ms = self.current_time_ms()?;
        let key = (tenant_id, source_ip);

        let counter = self
            .auth_attempts
            .entry(key)
            .or_insert_with(AttemptCounter::new);

        let failures = counter.increment(now_ms);

        let event = SecurityEvent {
            tenant_id,
            timestamp_ms: now_ms,
            event_type: SecurityEventType::AuthenticationFailure,
            source_ip,
            session_id: None,
            details: serde_json::json!({
                "failure_count": failures,
            }),
        };

        self.log_security_event(tenant_id, event);

        if failures >= self.max_auth_failures {
            self.block_source(tenant_id, source_ip)?;
            return Err(SecurityError::MaxAuthAttemptsExceeded {
                tenant_id,
                source_ip,
            });
        }

        Ok(())
    }

    /// Records successful authentication (resets counter)
    pub fn record_auth_success(&self, tenant_id: TenantId, source_ip: IpAddr) {
        let key = (tenant_id, source_ip);
        if let Some(counter) = self.auth_attempts.get(&key) {
            counter.reset();
        }
    }

    /// Checks if source is blocked for this tenant
    pub fn is_blocked(&self, tenant_id: TenantId, source_ip: IpAddr) -> bool {
        self.blocked_sources
            .get(&tenant_id)
            .map(|blocked| blocked.contains(&source_ip))
            .unwrap_or(false)
    }

    /// Blocks a source IP for a tenant
    pub fn block_source(
        &self,
        tenant_id: TenantId,
        source_ip: IpAddr,
    ) -> Result<(), SecurityError> {
        self.blocked_sources
            .entry(tenant_id)
            .or_default()
            .insert(source_ip);

        let event = SecurityEvent {
            tenant_id,
            timestamp_ms: self.current_time_ms()?,
            event_type: SecurityEventType::SourceIpBlocked,
            source_ip,
            session_id: None,
            details: serde_json::json!({
                "block_duration_ms": self.block_duration_ms,
            }),
        };

        self.log_security_event(tenant_id, event);

        Ok(())
    }

    /// Unblocks a source IP for a tenant
    pub fn unblock_source(
        &self,
        tenant_id: TenantId,
        source_ip: IpAddr,
    ) -> Result<(), SecurityError> {
        if let Some(blocked) = self.blocked_sources.get(&tenant_id) {
            blocked.remove(&source_ip);
        }

        let event = SecurityEvent {
            tenant_id,
            timestamp_ms: self.current_time_ms()?,
            event_type: SecurityEventType::SourceIpUnblocked,
            source_ip,
            session_id: None,
            details: serde_json::json!({}),
        };

        self.log_security_event(tenant_id, event);

        Ok(())
    }

    /// Logs a security event for a tenant
    pub fn log_security_event(&self, tenant_id: TenantId, event: SecurityEvent) {
        let log = self
            .audit_logs
            .entry(tenant_id)
            .or_insert_with(AuditLogBuffer::new);

        log.append(event.clone());

        // Structured logging
        tracing::warn!(
            tenant_id = %tenant_id,
            event_type = %event.event_type,
            source_ip = %event.source_ip,
            session_id = ?event.session_id,
            details = ?event.details,
            "Security event"
        );
    }

    /// Gets recent security events for a tenant
    pub fn get_recent_events(&self, tenant_id: TenantId, count: usize) -> Vec<SecurityEvent> {
        self.audit_logs
            .get(&tenant_id)
            .map(|log| log.get_recent_events(count))
            .unwrap_or_default()
    }

    /// Gets current time in milliseconds
    fn current_time_ms(&self) -> Result<u64, SecurityError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .map_err(|e| SecurityError::SystemTimeError(format!("{}", e)))
    }
}

impl Default for CrossTenantSecurityEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::session_manager::TenantSessionId;

    #[test]
    fn test_validate_tenant_session_success() {
        let enforcer = CrossTenantSecurityEnforcer::new();
        let tenant_id = TenantId::from_u64(1);
        let session_id = SessionId::new(42);

        let routing_entry = SessionRoutingEntry {
            tenant_session_id: TenantSessionId::new(tenant_id, session_id.clone()),
            last_packet_ns: 0,
            state: crate::tenant::session_manager::SessionState::Active,
        };

        let result = enforcer.validate_tenant_session(tenant_id, &session_id, &routing_entry);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tenant_session_cross_tenant_attempt() {
        let enforcer = CrossTenantSecurityEnforcer::new();
        let claimed_tenant = TenantId::from_u64(1);
        let actual_tenant = TenantId::from_u64(2);
        let session_id = SessionId::new(42);

        let routing_entry = SessionRoutingEntry {
            tenant_session_id: TenantSessionId::new(actual_tenant, session_id.clone()),
            last_packet_ns: 0,
            state: crate::tenant::session_manager::SessionState::Active,
        };

        let result = enforcer.validate_tenant_session(claimed_tenant, &session_id, &routing_entry);
        assert!(result.is_err());

        if let Err(SecurityError::CrossTenantAccessAttempt {
            claimed_tenant_id,
            actual_tenant_id,
        }) = result
        {
            assert_eq!(claimed_tenant_id, claimed_tenant);
            assert_eq!(actual_tenant_id, actual_tenant);
        } else {
            panic!("Expected CrossTenantAccessAttempt error");
        }
    }

    #[test]
    fn test_auth_failure_tracking() {
        let enforcer = CrossTenantSecurityEnforcer::new();
        let tenant_id = TenantId::from_u64(1);
        let source_ip: IpAddr = "192.168.1.1".parse().unwrap();

        for i in 1..5 {
            let result = enforcer.record_auth_failure(tenant_id, source_ip);
            assert!(result.is_ok(), "Failure {} should succeed", i);
        }

        // 5th failure should trigger block
        let result = enforcer.record_auth_failure(tenant_id, source_ip);
        assert!(result.is_err());
    }

    #[test]
    fn test_source_blocking() {
        let enforcer = CrossTenantSecurityEnforcer::new();
        let tenant_id = TenantId::from_u64(1);
        let source_ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(!enforcer.is_blocked(tenant_id, source_ip));

        enforcer.block_source(tenant_id, source_ip).unwrap();
        assert!(enforcer.is_blocked(tenant_id, source_ip));

        enforcer.unblock_source(tenant_id, source_ip).unwrap();
        assert!(!enforcer.is_blocked(tenant_id, source_ip));
    }

    #[test]
    fn test_tenant_isolation_in_blocking() {
        let enforcer = CrossTenantSecurityEnforcer::new();
        let tenant1 = TenantId::from_u64(1);
        let tenant2 = TenantId::from_u64(2);
        let source_ip: IpAddr = "192.168.1.1".parse().unwrap();

        enforcer.block_source(tenant1, source_ip).unwrap();

        assert!(enforcer.is_blocked(tenant1, source_ip));
        assert!(!enforcer.is_blocked(tenant2, source_ip));
    }

    #[test]
    fn test_auth_success_resets_counter() {
        let enforcer = CrossTenantSecurityEnforcer::new();
        let tenant_id = TenantId::from_u64(1);
        let source_ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..3 {
            enforcer.record_auth_failure(tenant_id, source_ip).unwrap();
        }

        enforcer.record_auth_success(tenant_id, source_ip);

        // Should be able to fail 4 more times before blocking
        for _ in 0..4 {
            let result = enforcer.record_auth_failure(tenant_id, source_ip);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_audit_logging() {
        let enforcer = CrossTenantSecurityEnforcer::new();
        let tenant_id = TenantId::from_u64(1);
        let source_ip: IpAddr = "192.168.1.1".parse().unwrap();

        enforcer.record_auth_failure(tenant_id, source_ip).unwrap();

        let events = enforcer.get_recent_events(tenant_id, 10);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            SecurityEventType::AuthenticationFailure
        );
    }

    #[test]
    fn test_audit_log_buffer_circular() {
        let buffer = AuditLogBuffer::new();
        let tenant_id = TenantId::from_u64(1);
        let source_ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Add events beyond buffer size
        for i in 0..12000 {
            let event = SecurityEvent {
                tenant_id,
                timestamp_ms: i,
                event_type: SecurityEventType::AuthenticationFailure,
                source_ip,
                session_id: None,
                details: serde_json::json!({}),
            };
            buffer.append(event);
        }

        // Buffer should not grow beyond max size
        assert!(buffer.events.len() <= buffer.max_events + 100);
    }
}
