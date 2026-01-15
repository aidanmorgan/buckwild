// Centralized error handling with hierarchical error system
pub mod adaptive;
pub mod authentication;
pub mod buffer;
pub mod configuration;
pub mod connection;
pub mod crypto;
pub mod cryptographic;
pub mod discovery;
pub mod ebpf;
pub mod engine;
pub mod enumeration;
pub mod flow_control;
pub mod fragmentation;
pub mod memory;
pub mod network;
pub mod permission;
pub mod protocol;
pub mod rate_limit;
pub mod recovery;
pub mod replay;
pub mod security;
pub mod session;
pub mod state;
pub mod system;
pub mod time;
pub mod timeout;
pub mod validation;
pub mod version;

// Import specific types to avoid circular dependencies
use crate::protocol::types::{IpAddress, MemorySize, NetworkEndpoint, Port};
use std::time::Duration;

// Re-export all error types
pub use adaptive::*;
pub use authentication::*;
pub use buffer::*;
pub use configuration::*;
pub use connection::*;
pub use crypto::*;
pub use cryptographic::*;
pub use discovery::*;
pub use ebpf::*;
pub use engine::*;
pub use enumeration::*;
pub use flow_control::*;
pub use fragmentation::*;
pub use memory::*;
pub use network::*;
pub use permission::*;
pub use protocol::*;
pub use rate_limit::*;
pub use recovery::*;
pub use replay::*;
pub use security::*;
pub use session::*;
pub use state::*;
pub use system::*;
pub use time::*;
pub use timeout::*;
pub use validation::*;
pub use version::*;

use thiserror::Error;

/// Top-level Buckwild error that wraps all layer-specific errors
/// This replaces all Box<dyn Error> usage with proper typed errors
#[derive(Error, Debug)]
pub enum BuckwildError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Engine error: {0}")]
    Engine(#[from] EngineError),

    #[error("Security error: {0}")]
    Security(#[from] SecurityError),

    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    #[error("Fragmentation error: {0}")]
    Fragmentation(#[from] FragmentationError),

    #[error("Flow control error: {0}")]
    FlowControl(#[from] FlowControlError),

    #[error("Time synchronization error: {0}")]
    Time(#[from] TimeError),

    #[error("Time calculation error: {0}")]
    TimeCalculation(String),

    #[error("Configuration error: {0}")]
    Configuration(#[from] ConfigurationError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("eBPF error: {0}")]
    Ebpf(#[from] EbpfError),

    #[error("System error: {0}")]
    System(#[from] SystemError),

    #[error("Discovery error: {0}")]
    Discovery(#[from] DiscoveryError),

    #[error("Recovery error: {0}")]
    Recovery(#[from] RecoveryError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Cryptographic error: {0}")]
    Cryptographic(#[from] CryptographicError),

    #[error("Authentication error: {0}")]
    Authentication(#[from] AuthenticationError),

    #[error("Replay error: {0}")]
    Replay(#[from] ReplayError),

    #[error("Enumeration error: {0}")]
    Enumeration(#[from] EnumerationError),

    #[error("Rate limit error: {0}")]
    RateLimit(#[from] RateLimitError),

    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),

    #[error("Timeout error: {0}")]
    Timeout(#[from] TimeoutError),

    #[error("State error: {0}")]
    State(#[from] StateError),

    #[error("Version error: {0}")]
    Version(#[from] VersionError),

    #[error("Buffer error: {0}")]
    Buffer(#[from] BufferError),

    #[error("Permission error: {0}")]
    Permission(#[from] PermissionError),

    #[error("Connection error: {0}")]
    Connection(#[from] ConnectionError),

    #[error("Adaptive networking error: {0}")]
    Adaptive(#[from] AdaptiveError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Lock error: {0}")]
    Lock(String),
}

impl BuckwildError {
    /// Create a configuration error
    pub fn configuration_error(msg: impl Into<String>) -> Self {
        Self::Configuration(ConfigurationError::config_validation_error(
            "general",
            msg.into(),
        ))
    }

    /// Create an invalid input error
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::Validation(ValidationError::invalid_input("input", msg.into()))
    }

    /// Create an invalid state error
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::State(StateError::StateCorruption {
            component: msg.into(),
        })
    }

    /// Create a resource exhausted error
    pub fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self::System(SystemError::resource_exhausted(msg.into()))
    }

    /// Create a not found error
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::Validation(ValidationError::required_field_missing(msg.into()))
    }

    /// Create an unsupported operation error
    pub fn unsupported_operation(msg: impl Into<String>) -> Self {
        Self::System(SystemError::SystemServiceUnavailable {
            service: msg.into(),
        })
    }

    /// Create an IO error
    pub fn io_error(msg: impl Into<String>) -> Self {
        Self::System(SystemError::FileSystemError {
            operation: "io".to_string(),
            path: msg.into(),
        })
    }

    /// Create a timeout error
    pub fn timeout_error(operation: impl Into<String>, timeout_ms: Duration) -> Self {
        Self::Timeout(TimeoutError::OperationTimeout {
            operation: operation.into(),
            timeout_ms,
        })
    }

    /// Create a memory error
    pub fn memory_error(size: MemorySize) -> Self {
        Self::Memory(MemoryError::AllocationFailed { size })
    }

    /// Create a network error
    pub fn network_error(_msg: impl Into<String>) -> Self {
        // Create a default endpoint since we only have a string message
        let endpoint = NetworkEndpoint::new(
            IpAddress::V4([0, 0, 0, 0]),
            Port::from_u16_unchecked(8080), // Use fallback port instead of 0
        );
        Self::Network(NetworkError::ConnectionFailed { endpoint })
    }

    /// Create a permission error
    pub fn permission_error(operation: impl Into<String>) -> Self {
        Self::Permission(PermissionError::PermissionDenied {
            operation: operation.into(),
        })
    }

    /// Create an internal error
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::System(SystemError::InternalError {
            details: msg.into(),
        })
    }

    /// Create a security error
    pub fn security_error(msg: impl Into<String>) -> Self {
        Self::Security(SecurityError::cryptographic_error(msg.into()))
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Protocol(e) => e.is_recoverable(),
            Self::Engine(e) => e.is_recoverable(),
            Self::Security(e) => e.is_recoverable(),
            Self::Session(e) => e.is_recoverable(),
            Self::Network(e) => e.is_recoverable(),
            Self::Fragmentation(e) => e.is_recoverable(),
            Self::FlowControl(e) => e.is_recoverable(),
            Self::Time(e) => e.is_recoverable(),
            Self::Configuration(e) => e.is_recoverable(),
            Self::Validation(e) => e.is_recoverable(),
            Self::Ebpf(e) => e.is_recoverable(),
            Self::System(e) => e.is_recoverable(),
            Self::Discovery(_) => true,
            Self::Recovery(_) => true,
            Self::Crypto(_) => false,
            Self::Cryptographic(_) => false,
            Self::Authentication(_) => true,
            Self::Replay(_) => false,
            Self::Enumeration(_) => false,
            Self::RateLimit(_) => true,
            Self::Memory(_) => true,
            Self::Timeout(_) => true,
            Self::State(_) => false,
            Self::Version(_) => false,
            Self::Buffer(_) => true,
            Self::Permission(_) => false,
            Self::Connection(e) => e.is_recoverable(),
            Self::Adaptive(e) => e.is_recoverable(),
            Self::Io(_) => true,
            Self::Lock(_) => true,
            Self::TimeCalculation(_) => false,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::Protocol(e) => e.recovery_hint(),
            Self::Engine(e) => e.recovery_hint(),
            Self::Security(e) => e.recovery_hint(),
            Self::Session(e) => e.recovery_hint(),
            Self::Network(e) => e.recovery_hint(),
            Self::Fragmentation(e) => e.recovery_hint(),
            Self::FlowControl(e) => e.recovery_hint(),
            Self::Time(e) => e.recovery_hint(),
            Self::Configuration(e) => e.recovery_hint(),
            Self::Validation(_) => Some("Fix validation errors"),
            Self::Ebpf(e) => e.recovery_hint(),
            Self::System(_) => Some("Check system resources"),
            Self::Discovery(_) => Some("Retry discovery"),
            Self::Recovery(_) => Some("Escalate recovery"),
            Self::Crypto(_) => Some("Check crypto configuration"),
            Self::Cryptographic(_) => Some("Check cryptographic setup"),
            Self::Authentication(_) => Some("Retry authentication"),
            Self::Replay(_) => Some("Reject replayed packet"),
            Self::Enumeration(_) => Some("Block enumeration attempt"),
            Self::RateLimit(_) => Some("Reduce request rate"),
            Self::Memory(_) => Some("Free memory and retry"),
            Self::Timeout(_) => Some("Increase timeout or retry"),
            Self::State(_) => Some("Reset state"),
            Self::Version(_) => Some("Update to compatible version"),
            Self::Buffer(_) => Some("Increase buffer size"),
            Self::Permission(_) => Some("Check permissions"),
            Self::Connection(e) => e.recovery_hint(),
            Self::Adaptive(e) => e.recovery_hint(),
            Self::Io(_) => Some("Retry I/O operation"),
            Self::Lock(_) => Some("Retry lock acquisition"),
            Self::TimeCalculation(_) => None,
        }
    }

    /// Get the error layer
    pub fn error_layer(&self) -> &'static str {
        match self {
            Self::Protocol(_) => "protocol",
            Self::Engine(_) => "engine",
            Self::Security(_) => "security",
            Self::Session(_) => "session",
            Self::Network(_) => "network",
            Self::Fragmentation(_) => "fragmentation",
            Self::FlowControl(_) => "flow_control",
            Self::Time(_) => "time",
            Self::Configuration(_) => "configuration",
            Self::Validation(_) => "validation",
            Self::Ebpf(_) => "ebpf",
            Self::System(_) => "system",
            Self::Discovery(_) => "discovery",
            Self::Recovery(_) => "recovery",
            Self::Crypto(_) => "crypto",
            Self::Cryptographic(_) => "cryptographic",
            Self::Authentication(_) => "authentication",
            Self::Replay(_) => "replay",
            Self::Enumeration(_) => "enumeration",
            Self::RateLimit(_) => "rate_limit",
            Self::Memory(_) => "memory",
            Self::Timeout(_) => "timeout",
            Self::State(_) => "state",
            Self::Version(_) => "version",
            Self::Buffer(_) => "buffer",
            Self::Permission(_) => "permission",
            Self::Connection(_) => "connection",
            Self::Adaptive(_) => "adaptive",
            Self::Io(_) => "io",
            Self::Lock(_) => "lock",
            Self::TimeCalculation(_) => "time_calculation",
        }
    }

    /// Check if this error indicates a potential security attack
    pub fn is_potential_attack(&self) -> bool {
        match self {
            Self::Security(e) => e.is_potential_attack(),
            Self::Fragmentation(e) => e.is_potential_attack(),
            Self::Replay(_) => true,
            Self::Enumeration(_) => true,
            Self::RateLimit(_) => true,
            _ => false,
        }
    }

    /// Get the security severity level for security-related errors
    pub fn security_severity(&self) -> Option<SecuritySeverity> {
        match self {
            Self::Security(e) => Some(e.severity_level()),
            Self::Replay(_) => Some(SecuritySeverity::Critical),
            Self::Enumeration(_) => Some(SecuritySeverity::High),
            Self::RateLimit(_) => Some(SecuritySeverity::Medium),
            Self::Authentication(_) => Some(SecuritySeverity::Medium),
            Self::Permission(_) => Some(SecuritySeverity::Medium),
            _ => None,
        }
    }

    /// Create a multiple errors error
    pub fn multiple_errors(errors: Vec<BuckwildError>) -> Self {
        let error_msg = errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Self::System(SystemError::InternalError {
            details: format!("Multiple errors: {}", error_msg),
        })
    }

    /// Get error context for logging and debugging
    pub fn error_context(&self) -> ErrorContext {
        ErrorContext {
            layer: self.error_layer().to_string(),
            recoverable: self.is_recoverable(),
            potential_attack: self.is_potential_attack(),
            security_severity: self.security_severity(),
            recovery_hint: self.recovery_hint().map(|s| s.to_string()),
        }
    }
}

/// Error context information for logging and debugging
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub layer: String,
    pub recoverable: bool,
    pub potential_attack: bool,
    pub security_severity: Option<SecuritySeverity>,
    pub recovery_hint: Option<String>,
}

/// Convert protocol::types::SessionError to BuckwildError
impl From<crate::protocol::types::SessionError> for BuckwildError {
    fn from(err: crate::protocol::types::SessionError) -> Self {
        // First convert to error::session::SessionError, then to BuckwildError
        let session_err: SessionError = err.into();
        session_err.into()
    }
}

/// Common result type for the Buckwild system
pub type BuckwildResult<T> = Result<T, BuckwildError>;
