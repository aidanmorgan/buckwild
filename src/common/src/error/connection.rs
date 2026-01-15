#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

//! Connection layer errors
//!
//! This module defines errors for connection state machine, lifecycle,
//! and integration failures. Errors include context such as SessionId,
//! SequenceNumber, and operation names for debugging.

use thiserror::Error;

use crate::error::{EngineError, ProtocolError, SecurityError};
use crate::protocol::types::{SequenceNumber, SessionId};

/// Connection layer error types covering state machine, lifecycle, and integration failures
#[derive(Error, Debug, Clone)]
pub enum ConnectionError {
    #[error(
        "Invalid state transition: {current_state} -> {attempted_state} in session {session_id} during {operation}"
    )]
    InvalidStateTransition {
        current_state: String,
        attempted_state: String,
        session_id: SessionId,
        operation: String,
    },

    #[error("Connection establishment failed for session {session_id}: {reason}")]
    EstablishmentFailed {
        session_id: SessionId,
        reason: String,
    },

    #[error("Connection termination failed for session {session_id}: {reason}")]
    TerminationFailed {
        session_id: SessionId,
        reason: String,
    },

    #[error("Connection not found: session {session_id}")]
    ConnectionNotFound { session_id: SessionId },

    #[error("Connection already exists: session {session_id}")]
    ConnectionAlreadyExists { session_id: SessionId },

    #[error("Connection timeout for session {session_id} during {operation}")]
    ConnectionTimeout {
        session_id: SessionId,
        operation: String,
    },

    #[error("Lifecycle error in session {session_id}: {details}")]
    LifecycleError {
        session_id: SessionId,
        details: String,
    },

    #[error("State corruption detected in session {session_id}: {details}")]
    StateCorruption {
        session_id: SessionId,
        details: String,
    },

    #[error("Coordinator error: {reason}")]
    CoordinatorError { reason: String },

    #[error("Manager error: {reason}")]
    ManagerError { reason: String },

    #[error("Security integration error in session {session_id}: {source}")]
    SecurityIntegration {
        session_id: SessionId,
        #[source]
        source: SecurityError,
    },

    #[error("Protocol integration error in session {session_id}, sequence {sequence}: {source}")]
    ProtocolIntegration {
        session_id: SessionId,
        sequence: SequenceNumber,
        #[source]
        source: ProtocolError,
    },

    #[error("Engine integration error in session {session_id}: {source}")]
    EngineIntegration {
        session_id: SessionId,
        #[source]
        source: EngineError,
    },

    #[error("Resource exhaustion in session {session_id}: {resource}")]
    ResourceExhaustion {
        session_id: SessionId,
        resource: String,
    },

    #[error("Maximum connections reached: {current}/{max}")]
    MaxConnectionsReached { current: usize, max: usize },

    #[error("Thread pool error: {reason}")]
    ThreadPoolError { reason: String },

    #[error("Async runtime error in session {session_id}: {reason}")]
    AsyncRuntimeError {
        session_id: SessionId,
        reason: String,
    },
}

impl ConnectionError {
    /// Create an invalid state transition error
    pub fn invalid_state_transition(
        current_state: impl Into<String>,
        attempted_state: impl Into<String>,
        session_id: SessionId,
        operation: impl Into<String>,
    ) -> Self {
        Self::InvalidStateTransition {
            current_state: current_state.into(),
            attempted_state: attempted_state.into(),
            session_id,
            operation: operation.into(),
        }
    }

    /// Create an establishment failed error
    pub fn establishment_failed(session_id: SessionId, reason: impl Into<String>) -> Self {
        Self::EstablishmentFailed {
            session_id,
            reason: reason.into(),
        }
    }

    /// Create a termination failed error
    pub fn termination_failed(session_id: SessionId, reason: impl Into<String>) -> Self {
        Self::TerminationFailed {
            session_id,
            reason: reason.into(),
        }
    }

    /// Create a connection not found error
    pub fn connection_not_found(session_id: SessionId) -> Self {
        Self::ConnectionNotFound { session_id }
    }

    /// Create a connection already exists error
    pub fn connection_already_exists(session_id: SessionId) -> Self {
        Self::ConnectionAlreadyExists { session_id }
    }

    /// Create a connection timeout error
    pub fn connection_timeout(session_id: SessionId, operation: impl Into<String>) -> Self {
        Self::ConnectionTimeout {
            session_id,
            operation: operation.into(),
        }
    }

    /// Create a lifecycle error
    pub fn lifecycle_error(session_id: SessionId, details: impl Into<String>) -> Self {
        Self::LifecycleError {
            session_id,
            details: details.into(),
        }
    }

    /// Create a state corruption error
    pub fn state_corruption(session_id: SessionId, details: impl Into<String>) -> Self {
        Self::StateCorruption {
            session_id,
            details: details.into(),
        }
    }

    /// Create a coordinator error
    pub fn coordinator_error(reason: impl Into<String>) -> Self {
        Self::CoordinatorError {
            reason: reason.into(),
        }
    }

    /// Create a manager error
    pub fn manager_error(reason: impl Into<String>) -> Self {
        Self::ManagerError {
            reason: reason.into(),
        }
    }

    /// Create a security integration error
    pub fn security_integration(session_id: SessionId, source: SecurityError) -> Self {
        Self::SecurityIntegration { session_id, source }
    }

    /// Create a protocol integration error
    pub fn protocol_integration(
        session_id: SessionId,
        sequence: SequenceNumber,
        source: ProtocolError,
    ) -> Self {
        Self::ProtocolIntegration {
            session_id,
            sequence,
            source,
        }
    }

    /// Create an engine integration error
    pub fn engine_integration(session_id: SessionId, source: EngineError) -> Self {
        Self::EngineIntegration { session_id, source }
    }

    /// Create a resource exhaustion error
    pub fn resource_exhaustion(session_id: SessionId, resource: impl Into<String>) -> Self {
        Self::ResourceExhaustion {
            session_id,
            resource: resource.into(),
        }
    }

    /// Create a max connections reached error
    pub fn max_connections_reached(current: usize, max: usize) -> Self {
        Self::MaxConnectionsReached { current, max }
    }

    /// Create a thread pool error
    pub fn thread_pool_error(reason: impl Into<String>) -> Self {
        Self::ThreadPoolError {
            reason: reason.into(),
        }
    }

    /// Create an async runtime error
    pub fn async_runtime_error(session_id: SessionId, reason: impl Into<String>) -> Self {
        Self::AsyncRuntimeError {
            session_id,
            reason: reason.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::InvalidStateTransition { .. } => false,
            Self::EstablishmentFailed { .. } => true,
            Self::TerminationFailed { .. } => true,
            Self::ConnectionNotFound { .. } => true,
            Self::ConnectionAlreadyExists { .. } => false,
            Self::ConnectionTimeout { .. } => true,
            Self::LifecycleError { .. } => true,
            Self::StateCorruption { .. } => false,
            Self::CoordinatorError { .. } => true,
            Self::ManagerError { .. } => true,
            Self::SecurityIntegration { source, .. } => source.is_recoverable(),
            Self::ProtocolIntegration { source, .. } => source.is_recoverable(),
            Self::EngineIntegration { source, .. } => source.is_recoverable(),
            Self::ResourceExhaustion { .. } => true,
            Self::MaxConnectionsReached { .. } => true,
            Self::ThreadPoolError { .. } => true,
            Self::AsyncRuntimeError { .. } => true,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::EstablishmentFailed { .. } => Some("Retry connection establishment"),
            Self::TerminationFailed { .. } => Some("Force termination"),
            Self::ConnectionNotFound { .. } => Some("Create new connection"),
            Self::ConnectionTimeout { .. } => Some("Retry with longer timeout"),
            Self::LifecycleError { .. } => Some("Reset connection lifecycle"),
            Self::CoordinatorError { .. } => Some("Restart coordinator"),
            Self::ManagerError { .. } => Some("Restart connection manager"),
            Self::SecurityIntegration { source, .. } => source.recovery_hint(),
            Self::ProtocolIntegration { source, .. } => source.recovery_hint(),
            Self::EngineIntegration { source, .. } => source.recovery_hint(),
            Self::ResourceExhaustion { .. } => Some("Free resources and retry"),
            Self::MaxConnectionsReached { .. } => Some("Wait for connections to close"),
            Self::ThreadPoolError { .. } => Some("Restart thread pool"),
            Self::AsyncRuntimeError { .. } => Some("Restart async runtime"),
            _ => None,
        }
    }

    /// Get the session ID if available
    pub fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::InvalidStateTransition { session_id, .. }
            | Self::EstablishmentFailed { session_id, .. }
            | Self::TerminationFailed { session_id, .. }
            | Self::ConnectionNotFound { session_id }
            | Self::ConnectionAlreadyExists { session_id }
            | Self::ConnectionTimeout { session_id, .. }
            | Self::LifecycleError { session_id, .. }
            | Self::StateCorruption { session_id, .. }
            | Self::SecurityIntegration { session_id, .. }
            | Self::ProtocolIntegration { session_id, .. }
            | Self::EngineIntegration { session_id, .. }
            | Self::ResourceExhaustion { session_id, .. }
            | Self::AsyncRuntimeError { session_id, .. } => Some(session_id.clone()),
            _ => None,
        }
    }
}

/// Connection layer result type
pub type ConnectionResult<T> = Result<T, ConnectionError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_state_transition() {
        let session = SessionId::new(1);
        let err = ConnectionError::invalid_state_transition("Idle", "Active", session, "send");

        assert!(!err.is_recoverable());
        assert!(err.recovery_hint().is_none());
        assert!(err.session_id().is_some());
    }

    #[test]
    fn test_establishment_failed() {
        let session = SessionId::new(1);
        let err = ConnectionError::establishment_failed(session, "handshake timeout");

        assert!(err.is_recoverable());
        assert_eq!(err.recovery_hint(), Some("Retry connection establishment"));
        assert!(err.session_id().is_some());
    }

    #[test]
    fn test_security_integration_preserves_context() {
        let session = SessionId::new(1);
        let security_err = SecurityError::hmac_verification_failed();
        let conn_err = ConnectionError::security_integration(session.clone(), security_err);

        // Should preserve session context
        assert_eq!(conn_err.session_id(), Some(session));
        // Should preserve recoverability from source
        assert!(!conn_err.is_recoverable());
    }

    #[test]
    fn test_protocol_integration_with_sequence() {
        let session = SessionId::new(1);
        let sequence = SequenceNumber::new(42);
        let protocol_err = ProtocolError::invalid_format("malformed header");
        let conn_err =
            ConnectionError::protocol_integration(session.clone(), sequence, protocol_err);

        assert_eq!(conn_err.session_id(), Some(session));
        assert!(!conn_err.is_recoverable());
    }

    #[test]
    fn test_engine_integration() {
        let session = SessionId::new(1);
        let engine_err = EngineError::port_hopping_error("port calculation failed");
        let conn_err = ConnectionError::engine_integration(session.clone(), engine_err);

        assert_eq!(conn_err.session_id(), Some(session));
        assert!(conn_err.is_recoverable());
        assert!(conn_err.recovery_hint().is_some());
    }

    #[test]
    fn test_max_connections_reached() {
        let err = ConnectionError::max_connections_reached(100, 100);

        assert!(err.is_recoverable());
        assert_eq!(err.recovery_hint(), Some("Wait for connections to close"));
        assert!(err.session_id().is_none());
    }
}
