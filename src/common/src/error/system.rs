// System layer errors
use thiserror::Error;

// Import consolidated types
use crate::protocol::types::*;

/// System layer error types
#[derive(Error, Debug, Clone)]
pub enum SystemError {
    #[error("System resource exhausted: {resource}")]
    ResourceExhausted { resource: String },

    #[error("System permission denied: {operation}")]
    PermissionDenied { operation: String },

    #[error("System call failed: {syscall}")]
    SystemCallFailed { syscall: String },

    #[error("Process creation failed: {command}")]
    ProcessCreationFailed { command: String },

    #[error("Process termination failed: {pid}")]
    ProcessTerminationFailed { pid: ProcessId },

    #[error("Thread creation failed: {reason}")]
    ThreadCreationFailed { reason: String },

    #[error("Internal system error: {details}")]
    InternalError { details: String },

    #[error("Thread join failed: {thread_id}")]
    ThreadJoinFailed { thread_id: String },

    #[error("Memory allocation failed: {size} bytes")]
    MemoryAllocationFailed { size: MemorySize },

    #[error("Memory mapping failed: {size} bytes")]
    MemoryMappingFailed { size: MemorySize },

    #[error("File system error: {operation} on {path}")]
    FileSystemError { operation: String, path: String },

    #[error("Device error: {device}")]
    DeviceError { device: String },

    #[error("Signal handling error: {signal}")]
    SignalHandlingError { signal: String },

    #[error("Environment variable error: {variable}")]
    EnvironmentVariableError { variable: String },

    #[error("System configuration error: {parameter}")]
    SystemConfigurationError { parameter: String },

    #[error("System limit exceeded: {limit} = {value}")]
    SystemLimitExceeded { limit: String, value: String },

    #[error("System service unavailable: {service}")]
    SystemServiceUnavailable { service: String },

    #[error("System shutdown in progress")]
    SystemShutdownInProgress,

    #[error("System startup failed: {reason}")]
    SystemStartupFailed { reason: String },

    #[error("System health check failed: {check}")]
    SystemHealthCheckFailed { check: String },
}

impl SystemError {
    /// Create a resource exhausted error
    pub fn resource_exhausted(resource: impl Into<String>) -> Self {
        Self::ResourceExhausted {
            resource: resource.into(),
        }
    }

    /// Create a permission denied error
    pub fn permission_denied(operation: impl Into<String>) -> Self {
        Self::PermissionDenied {
            operation: operation.into(),
        }
    }

    /// Create a system call failed error
    pub fn system_call_failed(syscall: impl Into<String>) -> Self {
        Self::SystemCallFailed {
            syscall: syscall.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::ResourceExhausted { .. } => true,
            Self::PermissionDenied { .. } => false,
            Self::SystemCallFailed { .. } => true,
            Self::ProcessCreationFailed { .. } => true,
            Self::ProcessTerminationFailed { .. } => true,
            Self::ThreadCreationFailed { .. } => true,
            Self::ThreadJoinFailed { .. } => true,
            Self::MemoryAllocationFailed { .. } => true,
            Self::MemoryMappingFailed { .. } => true,
            Self::FileSystemError { .. } => true,
            Self::DeviceError { .. } => true,
            Self::SignalHandlingError { .. } => true,
            Self::EnvironmentVariableError { .. } => false,
            Self::SystemConfigurationError { .. } => false,
            Self::SystemLimitExceeded { .. } => true,
            Self::SystemServiceUnavailable { .. } => true,
            Self::SystemShutdownInProgress => false,
            Self::SystemStartupFailed { .. } => true,
            Self::SystemHealthCheckFailed { .. } => true,
            Self::InternalError { .. } => false,
        }
    }
}

/// System layer result type
pub type SystemResult<T> = Result<T, SystemError>;

// tracing::Value implementation removed - trait is sealed
