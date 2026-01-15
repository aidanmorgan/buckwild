// Session layer errors
use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// Session layer error types
#[derive(Error, Debug, Clone)]
pub enum SessionError {
    #[error("Session management error: {reason}")]
    SessionManagementError { reason: String },

    #[error("Invalid session state: {session_id}")]
    InvalidState { session_id: SessionId },

    #[error("Session not found: {session_id}")]
    SessionNotFound { session_id: SessionId },

    #[error("Session already exists: {session_id}")]
    SessionAlreadyExists { session_id: SessionId },

    #[error("Session creation failed: {reason}")]
    SessionCreationFailed { reason: String },

    #[error("Session termination failed: {session_id}, reason: {reason}")]
    SessionTerminationFailed {
        session_id: SessionId,
        reason: String,
    },

    #[error(
        "Session state error: {session_id} in state {current_state}, cannot {attempted_action}"
    )]
    SessionStateError {
        session_id: SessionId,
        current_state: String,
        attempted_action: String,
    },

    #[error("Session lifecycle error: {session_id}, {reason}")]
    SessionLifecycleError {
        session_id: SessionId,
        reason: String,
    },

    #[error("Session coordination error: {reason}")]
    SessionCoordinationError { reason: String },

    #[error("Multi-session conflict: {session1} conflicts with {session2}")]
    MultiSessionConflict {
        session1: SessionId,
        session2: SessionId,
    },

    #[error("Connection management error: {reason}")]
    ConnectionManagementError { reason: String },

    #[error("Connection not found: {connection_id}")]
    ConnectionNotFound { connection_id: ConnectionId },

    #[error("Connection already exists: {connection_id}")]
    ConnectionAlreadyExists { connection_id: ConnectionId },

    #[error("Connection establishment failed: {endpoint}, reason: {reason}")]
    ConnectionEstablishmentFailed {
        endpoint: NetworkEndpoint,
        reason: String,
    },

    #[error("Connection termination failed: {connection_id}, reason: {reason}")]
    ConnectionTerminationFailed {
        connection_id: ConnectionId,
        reason: String,
    },

    #[error(
        "Connection state error: {connection_id} in state {current_state}, cannot {attempted_action}"
    )]
    ConnectionStateError {
        connection_id: ConnectionId,
        current_state: String,
        attempted_action: String,
    },

    #[error("Session capacity exceeded: {current}/{max} sessions")]
    SessionCapacityExceeded {
        current: SessionCount,
        max: SessionCount,
    },

    #[error("Connection capacity exceeded: {current}/{max} connections")]
    ConnectionCapacityExceeded {
        current: ConnectionCount,
        max: ConnectionCount,
    },

    #[error("Session timeout: {session_id} after {timeout_ms:?}ms")]
    SessionTimeout {
        session_id: SessionId,
        timeout_ms: ProtocolDuration,
    },

    #[error("Handshake error: {session_id}, {reason}")]
    HandshakeError {
        session_id: SessionId,
        reason: String,
    },

    #[error("Challenge validation failed: {session_id}")]
    ChallengeValidationFailed { session_id: SessionId },

    #[error("Response validation failed: {session_id}")]
    ResponseValidationFailed { session_id: SessionId },

    #[error("Session validation error: {session_id}, {reason}")]
    SessionValidationError {
        session_id: SessionId,
        reason: String,
    },

    #[error("Connection timeout: {connection_id} after {timeout_ms:?}ms")]
    ConnectionTimeout {
        connection_id: ConnectionId,
        timeout_ms: ProtocolDuration,
    },

    #[error("Session resource exhaustion: {resource}")]
    SessionResourceExhaustion { resource: String },

    #[error("Connection resource exhaustion: {resource}")]
    ConnectionResourceExhaustion { resource: String },

    #[error("Session configuration error: {parameter} = {value}")]
    SessionConfigurationError { parameter: String, value: String },

    #[error("Connection configuration error: {parameter} = {value}")]
    ConnectionConfigurationError { parameter: String, value: String },
}

impl SessionError {
    /// Create a session management error
    pub fn session_management_error(reason: impl Into<String>) -> Self {
        Self::SessionManagementError {
            reason: reason.into(),
        }
    }

    /// Create a session creation error
    pub fn session_creation_failed(reason: impl Into<String>) -> Self {
        Self::SessionCreationFailed {
            reason: reason.into(),
        }
    }

    /// Create a session termination error
    pub fn session_termination_failed(session_id: SessionId, reason: impl Into<String>) -> Self {
        Self::SessionTerminationFailed {
            session_id,
            reason: reason.into(),
        }
    }

    /// Create a session lifecycle error
    pub fn session_lifecycle_error(session_id: SessionId, reason: impl Into<String>) -> Self {
        Self::SessionLifecycleError {
            session_id,
            reason: reason.into(),
        }
    }

    /// Create a session coordination error
    pub fn session_coordination_error(reason: impl Into<String>) -> Self {
        Self::SessionCoordinationError {
            reason: reason.into(),
        }
    }

    /// Create a connection management error
    pub fn connection_management_error(reason: impl Into<String>) -> Self {
        Self::ConnectionManagementError {
            reason: reason.into(),
        }
    }

    /// Create a connection establishment error
    pub fn connection_establishment_failed(
        endpoint: NetworkEndpoint,
        reason: impl Into<String>,
    ) -> Self {
        Self::ConnectionEstablishmentFailed {
            endpoint,
            reason: reason.into(),
        }
    }

    /// Create a connection termination error
    pub fn connection_termination_failed(
        connection_id: ConnectionId,
        reason: impl Into<String>,
    ) -> Self {
        Self::ConnectionTerminationFailed {
            connection_id,
            reason: reason.into(),
        }
    }

    /// Create a session resource exhaustion error
    pub fn session_resource_exhaustion(resource: impl Into<String>) -> Self {
        Self::SessionResourceExhaustion {
            resource: resource.into(),
        }
    }

    /// Create a connection resource exhaustion error
    pub fn connection_resource_exhaustion(resource: impl Into<String>) -> Self {
        Self::ConnectionResourceExhaustion {
            resource: resource.into(),
        }
    }

    /// Create a session configuration error
    pub fn session_configuration_error(
        parameter: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self::SessionConfigurationError {
            parameter: parameter.into(),
            value: value.into(),
        }
    }

    /// Create a connection configuration error
    pub fn connection_configuration_error(
        parameter: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self::ConnectionConfigurationError {
            parameter: parameter.into(),
            value: value.into(),
        }
    }

    /// Create a handshake error
    pub fn handshake_error(session_id: SessionId, reason: impl Into<String>) -> Self {
        Self::HandshakeError {
            session_id,
            reason: reason.into(),
        }
    }

    /// Create a challenge validation failed error
    pub fn challenge_validation_failed(session_id: SessionId) -> Self {
        Self::ChallengeValidationFailed { session_id }
    }

    /// Create a response validation failed error
    pub fn response_validation_failed(session_id: SessionId) -> Self {
        Self::ResponseValidationFailed { session_id }
    }

    /// Create a session validation error
    pub fn session_validation_error(session_id: SessionId, reason: impl Into<String>) -> Self {
        Self::SessionValidationError {
            session_id,
            reason: reason.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::SessionManagementError { .. } => true,
            Self::InvalidState { .. } => false,
            Self::SessionNotFound { .. } => true,
            Self::SessionAlreadyExists { .. } => false,
            Self::SessionCreationFailed { .. } => true,
            Self::SessionTerminationFailed { .. } => true,
            Self::SessionStateError { .. } => false,
            Self::SessionLifecycleError { .. } => true,
            Self::SessionCoordinationError { .. } => true,
            Self::MultiSessionConflict { .. } => true,
            Self::ConnectionManagementError { .. } => true,
            Self::ConnectionNotFound { .. } => true,
            Self::ConnectionAlreadyExists { .. } => false,
            Self::ConnectionEstablishmentFailed { .. } => true,
            Self::ConnectionTerminationFailed { .. } => true,
            Self::ConnectionStateError { .. } => false,
            Self::SessionCapacityExceeded { .. } => true,
            Self::ConnectionCapacityExceeded { .. } => true,
            Self::SessionTimeout { .. } => true,
            Self::HandshakeError { .. } => true,
            Self::ChallengeValidationFailed { .. } => false,
            Self::ResponseValidationFailed { .. } => false,
            Self::SessionValidationError { .. } => false,
            Self::ConnectionTimeout { .. } => true,
            Self::SessionResourceExhaustion { .. } => true,
            Self::ConnectionResourceExhaustion { .. } => true,
            Self::SessionConfigurationError { .. } => false,
            Self::ConnectionConfigurationError { .. } => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::SessionManagementError { .. } => Some("Restart session manager"),
            Self::SessionNotFound { .. } => Some("Create new session"),
            Self::SessionCreationFailed { .. } => Some("Retry session creation"),
            Self::SessionTerminationFailed { .. } => Some("Force session termination"),
            Self::SessionLifecycleError { .. } => Some("Reset session lifecycle"),
            Self::SessionCoordinationError { .. } => Some("Resynchronize session coordination"),
            Self::MultiSessionConflict { .. } => Some("Resolve session conflict"),
            Self::ConnectionManagementError { .. } => Some("Restart connection manager"),
            Self::ConnectionNotFound { .. } => Some("Establish new connection"),
            Self::ConnectionEstablishmentFailed { .. } => Some("Retry connection establishment"),
            Self::ConnectionTerminationFailed { .. } => Some("Force connection termination"),
            Self::SessionCapacityExceeded { .. } => Some("Close idle sessions"),
            Self::ConnectionCapacityExceeded { .. } => Some("Close idle connections"),
            Self::SessionTimeout { .. } => Some("Extend session timeout or recreate"),
            Self::HandshakeError { .. } => Some("Retry handshake"),
            Self::ChallengeValidationFailed { .. } => {
                Some("Check challenge generation or reject session")
            }
            Self::ResponseValidationFailed { .. } => {
                Some("Check response validation or reject session")
            }
            Self::SessionValidationError { .. } => Some("Check session validation logic"),
            Self::ConnectionTimeout { .. } => Some("Extend connection timeout or reconnect"),
            Self::SessionResourceExhaustion { .. } => Some("Free session resources"),
            Self::ConnectionResourceExhaustion { .. } => Some("Free connection resources"),
            _ => None,
        }
    }

    /// Get the component type that caused this error
    pub fn component_type(&self) -> &'static str {
        match self {
            Self::SessionManagementError { .. }
            | Self::InvalidState { .. }
            | Self::SessionNotFound { .. }
            | Self::SessionAlreadyExists { .. }
            | Self::SessionCreationFailed { .. }
            | Self::SessionTerminationFailed { .. }
            | Self::SessionStateError { .. }
            | Self::SessionLifecycleError { .. }
            | Self::SessionCoordinationError { .. }
            | Self::MultiSessionConflict { .. }
            | Self::SessionCapacityExceeded { .. }
            | Self::SessionTimeout { .. }
            | Self::HandshakeError { .. }
            | Self::ChallengeValidationFailed { .. }
            | Self::ResponseValidationFailed { .. }
            | Self::SessionValidationError { .. }
            | Self::SessionResourceExhaustion { .. }
            | Self::SessionConfigurationError { .. } => "session",

            Self::ConnectionManagementError { .. }
            | Self::ConnectionNotFound { .. }
            | Self::ConnectionAlreadyExists { .. }
            | Self::ConnectionEstablishmentFailed { .. }
            | Self::ConnectionTerminationFailed { .. }
            | Self::ConnectionStateError { .. }
            | Self::ConnectionCapacityExceeded { .. }
            | Self::ConnectionTimeout { .. }
            | Self::ConnectionResourceExhaustion { .. }
            | Self::ConnectionConfigurationError { .. } => "connection",
        }
    }
}

/// Session layer result type
pub type SessionResult<T> = Result<T, SessionError>;

impl From<crate::protocol::types::ValidationError> for SessionError {
    fn from(err: crate::protocol::types::ValidationError) -> Self {
        SessionError::SessionManagementError {
            reason: format!("Validation error: {:?}", err),
        }
    }
}

impl From<crate::protocol::types::SessionError> for SessionError {
    fn from(err: crate::protocol::types::SessionError) -> Self {
        use crate::protocol::types::SessionError as ProtoSessionError;
        match err {
            ProtoSessionError::NotFound => SessionError::SessionManagementError {
                reason: "Session not found".into(),
            },
            ProtoSessionError::Expired => SessionError::SessionManagementError {
                reason: "Session expired".into(),
            },
            ProtoSessionError::InvalidState => SessionError::SessionManagementError {
                reason: "Invalid session state".into(),
            },
            ProtoSessionError::CreationFailed => SessionError::SessionCreationFailed {
                reason: "Session creation failed".into(),
            },
            ProtoSessionError::System(msg) => SessionError::SessionManagementError {
                reason: format!("Session system error: {}", msg),
            },
        }
    }
}
