// eBPF integration errors
use thiserror::Error;

// Import specific types to avoid circular dependencies
use crate::protocol::types::{
    EbpfAttachType, EbpfEventType, EbpfFileDescriptor, EbpfInstructionCount, EbpfMapKey,
    EbpfMapSize, EbpfMapType, EbpfProgramId, EbpfProgramType, EbpfReturnCode, EbpfStackSize,
    EbpfVerifierLog, RingBufferSize,
};

/// eBPF integration error types
/// NOTE: This is the ONLY module allowed to use Box<dyn Error> for C FFI boundaries
#[derive(Error, Debug)]
pub enum EbpfError {
    #[error("eBPF program load failed: {program_id}")]
    ProgramLoadFailed { program_id: EbpfProgramId },

    #[error("eBPF program attach failed: {program_id} to {attach_type:?}")]
    ProgramAttachFailed {
        program_id: EbpfProgramId,
        attach_type: EbpfAttachType,
    },

    #[error("eBPF program detach failed: {program_id}")]
    ProgramDetachFailed { program_id: EbpfProgramId },

    #[error("eBPF map creation failed: {map_type:?}")]
    MapCreationFailed { map_type: EbpfMapType },

    #[error("eBPF map access failed: {operation} on map {map_id}")]
    MapAccessFailed { map_id: String, operation: String },

    #[error("eBPF map key not found: {key:?}")]
    MapKeyNotFound { key: EbpfMapKey },

    #[error("eBPF map full: {map_id}")]
    MapFull { map_id: String },

    #[error("eBPF verifier error: {log}")]
    VerifierError { log: EbpfVerifierLog },

    #[error("eBPF instruction limit exceeded: {count} > {limit}")]
    InstructionLimitExceeded {
        count: EbpfInstructionCount,
        limit: EbpfInstructionCount,
    },

    #[error("eBPF stack overflow: {used} > {limit}")]
    StackOverflow {
        used: EbpfStackSize,
        limit: EbpfStackSize,
    },

    #[error("eBPF ring buffer error: {operation}")]
    RingBufferError { operation: String },

    #[error("eBPF ring buffer full: {size}")]
    RingBufferFull { size: RingBufferSize },

    #[error("eBPF event processing failed: {event_type:?}")]
    EventProcessingFailed { event_type: EbpfEventType },

    #[error("eBPF return code error: {code:?}")]
    ReturnCodeError { code: EbpfReturnCode },

    #[error("eBPF file descriptor error: {fd}")]
    FileDescriptorError { fd: EbpfFileDescriptor },

    #[error("eBPF permission denied: {operation}")]
    PermissionDenied { operation: String },

    #[error("eBPF resource exhausted: {resource}")]
    ResourceExhausted { resource: String },

    #[error("eBPF kernel version incompatible: {required} vs {actual}")]
    KernelVersionIncompatible { required: String, actual: String },

    #[error("eBPF feature not supported: {feature}")]
    FeatureNotSupported { feature: String },

    #[error("eBPF C FFI error: {operation}")]
    CFfiError {
        operation: String,
        // ONLY acceptable use of Box<dyn Error> - for C interop
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("eBPF program type mismatch: expected {expected:?}, got {actual:?}")]
    ProgramTypeMismatch {
        expected: EbpfProgramType,
        actual: EbpfProgramType,
    },

    #[error("eBPF map size exceeded: {current} > {max}")]
    MapSizeExceeded {
        current: EbpfMapSize,
        max: EbpfMapSize,
    },
}

impl EbpfError {
    /// Create a program load failed error
    pub fn program_load_failed(program_id: EbpfProgramId) -> Self {
        Self::ProgramLoadFailed { program_id }
    }

    /// Create a map creation failed error
    pub fn map_creation_failed(map_type: EbpfMapType) -> Self {
        Self::MapCreationFailed { map_type }
    }

    /// Create a map access failed error
    pub fn map_access_failed(map_id: impl Into<String>, operation: impl Into<String>) -> Self {
        Self::MapAccessFailed {
            map_id: map_id.into(),
            operation: operation.into(),
        }
    }

    /// Create a verifier error
    pub fn verifier_error(log: EbpfVerifierLog) -> Self {
        Self::VerifierError { log }
    }

    /// Create a ring buffer error
    pub fn ring_buffer_error(operation: impl Into<String>) -> Self {
        Self::RingBufferError {
            operation: operation.into(),
        }
    }

    /// Create a C FFI error (ONLY acceptable use of Box<dyn Error>)
    pub fn c_ffi_error(
        operation: impl Into<String>,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self::CFfiError {
            operation: operation.into(),
            source,
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::ProgramLoadFailed { .. } => true,
            Self::ProgramAttachFailed { .. } => true,
            Self::ProgramDetachFailed { .. } => true,
            Self::MapCreationFailed { .. } => true,
            Self::MapAccessFailed { .. } => true,
            Self::MapKeyNotFound { .. } => false,
            Self::MapFull { .. } => true,
            Self::VerifierError { .. } => false,
            Self::InstructionLimitExceeded { .. } => false,
            Self::StackOverflow { .. } => false,
            Self::RingBufferError { .. } => true,
            Self::RingBufferFull { .. } => true,
            Self::EventProcessingFailed { .. } => true,
            Self::ReturnCodeError { .. } => true,
            Self::FileDescriptorError { .. } => true,
            Self::PermissionDenied { .. } => false,
            Self::ResourceExhausted { .. } => true,
            Self::KernelVersionIncompatible { .. } => false,
            Self::FeatureNotSupported { .. } => false,
            Self::CFfiError { .. } => true,
            Self::ProgramTypeMismatch { .. } => false,
            Self::MapSizeExceeded { .. } => true,
        }
    }

    /// Get recovery hint for this error
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            Self::ProgramLoadFailed { .. } => Some("Check program bytecode and retry"),
            Self::ProgramAttachFailed { .. } => Some("Verify attach point and retry"),
            Self::ProgramDetachFailed { .. } => Some("Force detach or restart"),
            Self::MapCreationFailed { .. } => Some("Check map parameters and retry"),
            Self::MapAccessFailed { .. } => Some("Verify map permissions and retry"),
            Self::MapFull { .. } => Some("Clear old entries or increase map size"),
            Self::RingBufferError { .. } => Some("Reset ring buffer"),
            Self::RingBufferFull { .. } => Some("Consume pending events"),
            Self::EventProcessingFailed { .. } => Some("Retry event processing"),
            Self::ReturnCodeError { .. } => Some("Check program logic"),
            Self::FileDescriptorError { .. } => Some("Close and reopen file descriptor"),
            Self::ResourceExhausted { .. } => Some("Free resources and retry"),
            Self::CFfiError { .. } => Some("Check C library integration"),
            Self::MapSizeExceeded { .. } => Some("Reduce map size or increase limit"),
            _ => None,
        }
    }

    /// Get the eBPF component that caused this error
    pub fn component_type(&self) -> &'static str {
        match self {
            Self::ProgramLoadFailed { .. }
            | Self::ProgramAttachFailed { .. }
            | Self::ProgramDetachFailed { .. }
            | Self::ProgramTypeMismatch { .. } => "program",

            Self::MapCreationFailed { .. }
            | Self::MapAccessFailed { .. }
            | Self::MapKeyNotFound { .. }
            | Self::MapFull { .. }
            | Self::MapSizeExceeded { .. } => "map",

            Self::VerifierError { .. }
            | Self::InstructionLimitExceeded { .. }
            | Self::StackOverflow { .. } => "verifier",

            Self::RingBufferError { .. } | Self::RingBufferFull { .. } => "ring_buffer",

            Self::EventProcessingFailed { .. } => "event_processing",

            Self::CFfiError { .. } => "c_ffi",

            _ => "general",
        }
    }
}

/// eBPF integration result type
pub type EbpfResult<T> = Result<T, EbpfError>;
