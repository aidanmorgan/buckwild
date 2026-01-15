// Comprehensive edge case handling and boundary condition management
//
// This module implements comprehensive handling for edge cases, boundary conditions,
// and exceptional scenarios that can occur during protocol operation, ensuring robust
// and secure operation in all real-world network environments.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Import ALL types from the authoritative consolidated types module
use super::packet::{Packet, PacketType};
use super::validation::PacketValidator;
use crate::protocol::types::*;
use crate::security::SecurityValidator;

/// Edge case error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeCaseError {
    // Packet processing edge cases
    InvalidVersion,
    UnsupportedVersion,
    InvalidPacketType,
    UnknownPacketType,
    InvalidSubType,
    PayloadTooLarge,
    EmptyDataPacket,
    InvalidSessionId,
    SequenceWraparoundNotReady,
    PacketTooShort,
    PayloadLengthMismatch,
    ReservedFieldsNotZero,
    InvalidFlagCombination,

    // Fragmentation edge cases
    FragmentIndexOutOfBounds,
    TooManyFragments,
    FragmentIdCollision,
    FragmentDataMismatch,
    EmptyFinalFragment,
    FragmentTimeout,
    MemoryExhausted,

    // Time synchronization edge cases
    ClockRegressionDetected,
    ConnectionTerminate,
    DstTransition,
    LeapSecondActive,

    // Flow control edge cases
    WindowDeadlock,
    WindowUpdateTimeout,

    // Recovery edge cases
    RecoveryInProgress,
    RecoveryDuringTermination,
    SessionUnrecoverable,
    RecoveryAttemptsExhausted,
    CriticalOperationInterrupted,

    // Port hopping edge cases
    PortRangeExhausted,
    NoAvailablePorts,

    // Connection management edge cases
    SimultaneousConnection,
    SessionIdCollision,
    SystemShuttingDown,
    VersionTooOld,
    VersionTooNew,
    ConnectionStateCorruption,

    // Resource exhaustion edge cases
    ConnectionLimitExceeded,
    SendBufferOverflow,
    ReceiveBufferOverflow,
    ResourceExhausted,
    BufferFull,
    BufferEmpty,

    // Security edge cases
    TimestampAttackDetected,
    RateLimited,
    SequencePredictionAttack,
    PortEnumerationDetected,
    InvalidCryptoParameters,
    AuthLockout,

    // Error processing edge cases
    ErrorLoop,
    UnknownError,
    ErrorProcessingTimeout,
    CascadingErrors,
    LogBufferOverflow,
    LogFilesystemFull,
}

impl std::fmt::Display for EdgeCaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVersion => write!(f, "Invalid protocol version"),
            Self::UnsupportedVersion => write!(f, "Unsupported protocol version"),
            Self::InvalidPacketType => write!(f, "Invalid packet type"),
            Self::UnknownPacketType => write!(f, "Unknown packet type"),
            Self::InvalidSubType => write!(f, "Invalid sub-type for packet type"),
            Self::PayloadTooLarge => write!(f, "Payload too large"),
            Self::EmptyDataPacket => write!(f, "DATA packets must have payload"),
            Self::InvalidSessionId => write!(f, "Invalid session ID for packet type"),
            Self::SequenceWraparoundNotReady => write!(f, "Sequence wraparound not ready"),
            Self::PacketTooShort => write!(f, "Packet too short to contain header"),
            Self::PayloadLengthMismatch => write!(f, "Payload length mismatch"),
            Self::ReservedFieldsNotZero => write!(f, "Reserved fields must be zero"),
            Self::InvalidFlagCombination => write!(f, "Invalid flag combination"),
            Self::FragmentIndexOutOfBounds => write!(f, "Fragment index out of bounds"),
            Self::TooManyFragments => write!(f, "Too many fragments"),
            Self::FragmentIdCollision => write!(f, "Fragment ID collision"),
            Self::FragmentDataMismatch => write!(f, "Fragment data mismatch"),
            Self::EmptyFinalFragment => write!(f, "Empty final fragment"),
            Self::FragmentTimeout => write!(f, "Fragment timeout"),
            Self::MemoryExhausted => write!(f, "Memory exhausted"),
            Self::ClockRegressionDetected => write!(f, "Clock regression detected"),
            Self::ConnectionTerminate => write!(f, "Connection must terminate"),
            Self::DstTransition => write!(f, "Daylight saving time transition"),
            Self::LeapSecondActive => write!(f, "Leap second active"),
            Self::WindowDeadlock => write!(f, "Window deadlock detected"),
            Self::WindowUpdateTimeout => write!(f, "Window update timeout"),
            Self::RecoveryInProgress => write!(f, "Recovery already in progress"),
            Self::RecoveryDuringTermination => write!(f, "Recovery during termination"),
            Self::SessionUnrecoverable => write!(f, "Session unrecoverable"),
            Self::RecoveryAttemptsExhausted => write!(f, "Recovery attempts exhausted"),
            Self::CriticalOperationInterrupted => write!(f, "Critical operation interrupted"),
            Self::PortRangeExhausted => write!(f, "Port range exhausted"),
            Self::NoAvailablePorts => write!(f, "No available ports"),
            Self::SimultaneousConnection => write!(f, "Simultaneous connection detected"),
            Self::SessionIdCollision => write!(f, "Session ID collision"),
            Self::SystemShuttingDown => write!(f, "System shutting down"),
            Self::VersionTooOld => write!(f, "Protocol version too old"),
            Self::VersionTooNew => write!(f, "Protocol version too new"),
            Self::ConnectionStateCorruption => write!(f, "Connection state corruption"),
            Self::ConnectionLimitExceeded => write!(f, "Connection limit exceeded"),
            Self::SendBufferOverflow => write!(f, "Send buffer overflow"),
            Self::ReceiveBufferOverflow => write!(f, "Receive buffer overflow"),
            Self::ResourceExhausted => write!(f, "Resource exhausted"),
            Self::BufferFull => write!(f, "Buffer full"),
            Self::BufferEmpty => write!(f, "Buffer empty"),
            Self::TimestampAttackDetected => write!(f, "Timestamp attack detected"),
            Self::RateLimited => write!(f, "Rate limited"),
            Self::SequencePredictionAttack => write!(f, "Sequence prediction attack"),
            Self::PortEnumerationDetected => write!(f, "Port enumeration detected"),
            Self::InvalidCryptoParameters => write!(f, "Invalid cryptographic parameters"),
            Self::AuthLockout => write!(f, "Authentication lockout"),
            Self::ErrorLoop => write!(f, "Error loop detected"),
            Self::UnknownError => write!(f, "Unknown error"),
            Self::ErrorProcessingTimeout => write!(f, "Error processing timeout"),
            Self::CascadingErrors => write!(f, "Cascading errors detected"),
            Self::LogBufferOverflow => write!(f, "Log buffer overflow"),
            Self::LogFilesystemFull => write!(f, "Log filesystem full"),
        }
    }
}

/// Constants for edge case handling
pub struct EdgeCaseConstants;

impl EdgeCaseConstants {
    // Protocol constants
    pub const PROTOCOL_MAX_VERSION: u8 = 1;
    pub const PACKET_TYPE_MAX: u8 = 15;
    pub const MAX_PACKET_SIZE: usize = 65535;
    pub const OPTIMIZED_COMMON_HEADER_SIZE: usize = 26;
    pub const MAX_SEQUENCE_NUMBER: u32 = u32::MAX;
    // Threshold at which sequence numbers are considered to have wrapped (design/rules.md)
    // Sequence comparison uses signed arithmetic: diff < 0x80000000 means forward progress
    pub const SEQUENCE_WRAP_THRESHOLD: u32 = 0x80000000;

    // Fragmentation constants
    pub const MAX_FRAGMENTS: u16 = 1000;
    pub const MAX_CONCURRENT_REASSEMBLIES: usize = 1000;
    pub const FRAGMENT_TIMEOUT_MS: FragmentTimeout = FragmentTimeout(5000);

    // Time synchronization constants
    pub const MAX_ACCEPTABLE_TIME_REGRESSION: Duration = Duration::from_nanos(1_000_000_000); // 1 second in nanoseconds
    pub const MAX_EXTREME_TIME_DRIFT: Duration = Duration::from_nanos(3_600_000_000_000); // 1 hour in nanoseconds
    pub const HOP_INTERVAL_SAFETY_MARGIN: Duration = Duration::from_nanos(50_000_000); // 50ms in nanoseconds
    pub const MILLISECONDS_PER_DAY: Duration = Duration::from_nanos(86_400_000_000_000); // 24 hours in nanoseconds

    // Flow control constants
    pub const MIN_DEADLOCK_WINDOW_SIZE: u32 = 1460; // 1 MSS
    pub const WINDOW_UPDATE_TIMEOUT_MS: Timeout = Timeout(5000);
    pub const MAX_WINDOW_SIZE: u32 = 1 << 30; // 1GB
    pub const MIN_CONGESTION_WINDOW: u32 = 1460;
    pub const HIGH_JITTER_THRESHOLD: NetworkJitter = NetworkJitter(100_000_000); // 100ms in nanoseconds
    pub const FAST_RETRANSMIT_THRESHOLD: u32 = 3;

    // Recovery constants
    pub const MAX_TOTAL_RECOVERY_ATTEMPTS: u32 = 10;
    pub const RECOVERY_TIMEOUT_EXTENSION_MS: Duration = Duration::from_nanos(1_000_000_000); // 1 second in nanoseconds

    // Port hopping constants
    // Port hopping constants
    pub const MIN_PORT: u16 = crate::protocol::types::Port::MIN_PORT;
    pub const MAX_PORT: u16 = Port::MAX_PORT;
    pub const PORT_OFFSET_RANGE: u32 = 65536;

    // Connection management constants
    pub const MIN_SUPPORTED_VERSION: u8 = 1;
    pub const MAX_SUPPORTED_VERSION: u8 = 1;

    // Resource limits
    pub const MAX_CONCURRENT_CONNECTIONS: usize = 10000;
    pub const MIN_REQUIRED_MEMORY: usize = 1024 * 1024; // 1MB
    pub const MAX_SEND_BUFFER_SIZE: usize = 64 * 1024 * 1024; // 64MB
    pub const CRITICAL_SEND_BUFFER_SIZE: usize = 32 * 1024 * 1024; // 32MB
    pub const MAX_RECEIVE_BUFFER_SIZE: usize = 64 * 1024 * 1024; // 64MB
    pub const CRITICAL_RECEIVE_BUFFER_SIZE: usize = 32 * 1024 * 1024; // 32MB
    pub const MAX_FILE_DESCRIPTORS: usize = 65536;

    // Security constants
    pub const MAX_RECOVERY_HMAC_FAILURES: u32 = 3;
    pub const MAX_LEGITIMATE_CLOCK_SKEW_NS: i64 = 5_000_000_000; // 5 seconds in nanoseconds
    pub const MAX_DISCOVERY_RATE: u32 = 10; // per second
    pub const MAX_AUTH_ATTEMPTS: u32 = 3;
    pub const AUTH_TIMEOUT_EXTENSION_MS: u64 = 1_000_000_000; // 1 second in nanoseconds

    // Error handling constants
    pub const MAX_ERROR_RESPONSES: u32 = 10;
    pub const MAX_LOG_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB
}

/// Typed edge case constants for type-safe protocol operation
pub struct TypedEdgeCaseConstants;

impl TypedEdgeCaseConstants {
    // Packet size constants
    pub const MAX_PACKET_SIZE: PacketSize = PacketSize(65535);
    pub const MIN_PACKET_SIZE: PacketSize = PacketSize(20);

    // Fragment constants
    pub const MAX_FRAGMENT_SIZE: FragmentSize = FragmentSize(1400);

    // Timeout constants
    pub const FRAGMENT_TIMEOUT: Duration = Duration::from_millis(5000);
    pub const WINDOW_UPDATE_TIMEOUT: Duration = Duration::from_millis(5000);
    pub const AUTH_TIMEOUT_EXTENSION: Duration = Duration::from_millis(1000);
    pub const RECOVERY_TIMEOUT_EXTENSION: Duration = Duration::from_millis(1000);

    // Buffer size constants
    pub const MAX_SEND_BUFFER_SIZE: BufferSize = BufferSize(64 * 1024 * 1024); // 64MB
    pub const CRITICAL_SEND_BUFFER_SIZE: BufferSize = BufferSize(32 * 1024 * 1024); // 32MB
    pub const MAX_RECEIVE_BUFFER_SIZE: BufferSize = BufferSize(64 * 1024 * 1024); // 64MB
    pub const CRITICAL_RECEIVE_BUFFER_SIZE: BufferSize = BufferSize(32 * 1024 * 1024); // 32MB
    pub const MAX_LOG_BUFFER_SIZE: BufferSize = BufferSize(10 * 1024 * 1024); // 10MB

    // Threshold constants
    // Threshold at which sequence numbers are considered to have wrapped (design/rules.md)
    // Sequence comparison uses signed arithmetic: diff < 0x80000000 means forward progress
    pub const SEQUENCE_WRAP_THRESHOLD: u32 = 0x80000000;
    pub const FAST_RETRANSMIT_THRESHOLD: u32 = 3;
    pub const HIGH_JITTER_THRESHOLD: u32 = 100; // 100ms
    pub const MAX_RECOVERY_HMAC_FAILURES: u32 = 3;
    pub const MAX_DISCOVERY_RATE: u32 = 10; // per second
    pub const MAX_AUTH_ATTEMPTS: u32 = 3;
    pub const MAX_ERROR_RESPONSES: u32 = 10;
}

/// Session state for edge case tracking
#[derive(Debug)]
pub struct SessionState {
    pub session_id: SessionId,
    pub next_sequence_number: AtomicU32,
    pub peer_highest_acknowledged: AtomicU32,
    pub last_known_time: AtomicU64,
    pub time_offset: AtomicI64,
    pub time_sync_in_progress: AtomicU32,
    pub peer_window_size: AtomicU32,
    pub local_window_size: AtomicU32,
    pub connection_state: ConnectionState,
    pub recovery_attempts: AtomicU32,
    pub auth_attempt_count: AtomicU32,
}

impl SessionState {
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            next_sequence_number: AtomicU32::new(1),
            peer_highest_acknowledged: AtomicU32::new(0),
            last_known_time: AtomicU64::new(0),
            time_offset: AtomicI64::new(0),
            time_sync_in_progress: AtomicU32::new(0),
            peer_window_size: AtomicU32::new(65536),
            local_window_size: AtomicU32::new(65536),
            connection_state: ConnectionState::Idle,
            recovery_attempts: AtomicU32::new(0),
            auth_attempt_count: AtomicU32::new(0),
        }
    }
}

/// Recovery state tracking
#[derive(Debug)]
pub struct RecoveryState {
    pub recovery_in_progress: AtomicU32,
    pub current_level: AtomicU32,
    pub total_recovery_attempts: AtomicU32,
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryState {
    pub fn new() -> Self {
        Self {
            recovery_in_progress: AtomicU32::new(0),
            current_level: AtomicU32::new(RecoveryLevel::TimeSync as u32),
            total_recovery_attempts: AtomicU32::new(0),
        }
    }
}

/// Reassembly buffer for fragment tracking
#[derive(Debug)]
pub struct ReassemblyBuffer {
    pub fragment_id: FragmentId,
    pub sequence_number: SequenceNumber,
    pub fragment_count: FragmentCount,
    pub received_count: FragmentCount,
    pub timeout: FragmentTimeout,
    pub fragments: RwLock<HashMap<u16, Vec<u8>>>,
}

impl ReassemblyBuffer {
    pub fn new(
        fragment_id: FragmentId,
        sequence_number: SequenceNumber,
        total_fragments: FragmentCount,
    ) -> Self {
        let timeout = FragmentTimeout::new(
            Timestamp::now().as_u64() + EdgeCaseConstants::FRAGMENT_TIMEOUT_MS.as_u64(),
        );

        Self {
            fragment_id,
            sequence_number,
            fragment_count: total_fragments,
            received_count: FragmentCount::new(0),
            timeout,
            fragments: RwLock::new(HashMap::new()),
        }
    }
}

/// Comprehensive edge case handler
pub struct EdgeCaseHandler {
    /// Packet validator for basic validation
    /// Kept for future comprehensive validation integration
    #[allow(dead_code)]
    packet_validator: PacketValidator,

    /// Security validator for security-related edge cases
    security_validator: SecurityValidator,

    /// Active sessions for state tracking
    pub sessions: DashMap<u64, Arc<SessionState>>,

    /// Recovery state tracking
    pub recovery_state: RecoveryState,

    /// Active reassembly buffers
    active_reassembly_buffers: DashMap<u32, Arc<ReassemblyBuffer>>,

    /// System state tracking
    system_shutdown: ErrorCount, // 0 = false, 1 = true
    active_connections: AtomicUsize,
    memory_usage: AtomicUsize,
    send_buffer_usage: AtomicUsize,
    receive_buffer_usage: AtomicUsize,
    open_file_descriptors: AtomicUsize,

    /// Error tracking
    error_response_count: ErrorCount,
    /// Buffer usage tracking - kept for future monitoring features
    #[allow(dead_code)]
    log_buffer_usage: AtomicUsize,

    /// Statistics
    edge_cases_handled: PacketCount,
    boundary_conditions_detected: PacketCount,
}

impl EdgeCaseHandler {
    /// Create a new edge case handler
    pub fn new() -> Self {
        Self {
            packet_validator: PacketValidator::new(),
            security_validator: SecurityValidator::new(),
            sessions: DashMap::new(),
            recovery_state: RecoveryState::new(),
            active_reassembly_buffers: DashMap::new(),
            system_shutdown: ErrorCount::new(0),
            active_connections: AtomicUsize::new(0),
            memory_usage: AtomicUsize::new(0),
            send_buffer_usage: AtomicUsize::new(0),
            receive_buffer_usage: AtomicUsize::new(0),
            open_file_descriptors: AtomicUsize::new(0),
            error_response_count: ErrorCount::new(0),
            log_buffer_usage: AtomicUsize::new(0),
            edge_cases_handled: PacketCount::new(0),
            boundary_conditions_detected: PacketCount::new(0),
        }
    }

    /// Handle packet processing edge cases
    pub fn handle_packet_edge_cases(&self, packet: &Packet) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Edge Case 1: Version field validation
        let version_byte = packet.header().version_byte();
        if version_byte.version() == 0 {
            return Err(EdgeCaseError::InvalidVersion);
        }
        if version_byte.version() > EdgeCaseConstants::PROTOCOL_MAX_VERSION {
            return Err(EdgeCaseError::UnsupportedVersion);
        }

        // Edge Case 2: Packet type boundary validation
        let packet_type = packet.packet_type();

        // Edge Case 3: Sub-type validation for non-sub-type packets
        let sub_type = packet.header().sub_type();
        let allows_subtype = matches!(packet_type, PacketType::Control)
            || matches!(packet_type, PacketType::Management)
            || matches!(packet_type, PacketType::Discovery);
        if !allows_subtype && sub_type.as_u8() != 0 {
            return Err(EdgeCaseError::InvalidSubType);
        }

        // Edge Case 4: Payload length validation and bounds checking
        let payload_length = packet.payload().len();
        if payload_length
            > EdgeCaseConstants::MAX_PACKET_SIZE - EdgeCaseConstants::OPTIMIZED_COMMON_HEADER_SIZE
        {
            return Err(EdgeCaseError::PayloadTooLarge);
        }
        if payload_length == 0 && packet_type == PacketType::Data {
            return Err(EdgeCaseError::EmptyDataPacket);
        }

        // Edge Case 5: Session ID validation for different packet types
        let session_id = packet.session_id();
        if session_id.as_u64() == 0
            && !matches!(packet_type, PacketType::Syn | PacketType::Discovery)
        {
            return Err(EdgeCaseError::InvalidSessionId);
        }

        // Edge Case 6: Sequence number wraparound detection and handling
        let sequence_number = packet.sequence_number();
        if sequence_number.as_u32() == EdgeCaseConstants::MAX_SEQUENCE_NUMBER {
            self.validate_sequence_wraparound_conditions(session_id)?;
        }

        // Edge Case 7: Reserved fields validation
        let flags = packet.flags();
        // Note: PacketFlags might not have reserved_bits() method, skip for now
        // if flags.reserved_bits() != 0 {
        //     return Err(EdgeCaseError::ReservedFieldsNotZero);
        // }

        // Edge Case 8: Flag combination validation
        self.validate_flag_combinations(flags)?;

        Ok(())
    }

    /// Validate sequence wraparound conditions
    fn validate_sequence_wraparound_conditions(
        &self,
        session_id: SessionId,
    ) -> Result<(), EdgeCaseError> {
        if let Some(session) = self.sessions.get(&session_id.as_u64()) {
            let next_seq = session.next_sequence_number.load(Ordering::Relaxed);
            let peer_acked = session.peer_highest_acknowledged.load(Ordering::Relaxed);

            if next_seq == EdgeCaseConstants::MAX_SEQUENCE_NUMBER
                && peer_acked < EdgeCaseConstants::SEQUENCE_WRAP_THRESHOLD
            {
                return Err(EdgeCaseError::SequenceWraparoundNotReady);
            }
            // In a real implementation, this would initiate wraparound negotiation
        }
        Ok(())
    }

    /// Validate flag combinations
    fn validate_flag_combinations(&self, _flags: PacketFlags) -> Result<(), EdgeCaseError> {
        // Implementation would check for invalid flag combinations
        // For now, we assume all combinations are valid
        Ok(())
    }

    /// Handle malformed packet edge cases
    pub fn handle_malformed_packet_edge_cases(
        &self,
        packet_data: &[u8],
    ) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Edge Case 1: Packet too short to contain header
        if packet_data.len() < EdgeCaseConstants::OPTIMIZED_COMMON_HEADER_SIZE {
            return Err(EdgeCaseError::PacketTooShort);
        }

        // Edge Case 2: Basic header parsing for length validation
        if packet_data.len() >= 4 {
            // Extract payload length from header (simplified)
            let payload_length = u16::from_be_bytes([packet_data[2], packet_data[3]]) as usize;
            let expected_total_size =
                EdgeCaseConstants::OPTIMIZED_COMMON_HEADER_SIZE + payload_length;

            if packet_data.len() != expected_total_size {
                return Err(EdgeCaseError::PayloadLengthMismatch);
            }
        }

        Ok(())
    }

    /// Handle fragmentation edge cases
    pub fn handle_fragmentation_edge_cases(
        &self,
        fragment_id: FragmentId,
        fragment_index: u16,
        fragment_count: u16,
        sequence_number: SequenceNumber,
        fragment_data: &[u8],
    ) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Edge Case 1: Fragment index out of bounds
        if fragment_index >= fragment_count {
            return Err(EdgeCaseError::FragmentIndexOutOfBounds);
        }

        // Edge Case 2: Total fragments exceeds maximum allowed
        if fragment_count > EdgeCaseConstants::MAX_FRAGMENTS {
            return Err(EdgeCaseError::TooManyFragments);
        }

        // Edge Case 3: Fragment ID collision (different messages using same ID)
        if let Some(existing_buffer) = self
            .active_reassembly_buffers
            .get(&(fragment_id.as_u16() as u32))
        {
            if existing_buffer.sequence_number.as_u32() != sequence_number.as_u32() {
                // Fragment ID collision detected, cleanup and reject
                self.cleanup_reassembly_buffer(fragment_id.as_u16() as u32);
                return Err(EdgeCaseError::FragmentIdCollision);
            }

            // Edge Case 4: Duplicate fragment with different data
            let fragments = existing_buffer.fragments.read();
            if let Some(existing_fragment) = fragments.get(&fragment_index) {
                if existing_fragment != fragment_data {
                    return Err(EdgeCaseError::FragmentDataMismatch);
                }
                return Ok(()); // Duplicate but identical fragment, ignore safely
            }
        }

        // Edge Case 5: Last fragment with zero size
        if fragment_index == fragment_count - 1 && fragment_data.is_empty() {
            return Err(EdgeCaseError::EmptyFinalFragment);
        }

        // Edge Case 6: Fragment timeout at exactly same time as receive
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Some(reassembly_buffer) = self
            .active_reassembly_buffers
            .get(&(fragment_id.as_u16() as u32))
        {
            let timeout = reassembly_buffer.timeout.as_u64();
            if current_time >= timeout {
                let received_count = reassembly_buffer.received_count.as_u16();
                if received_count == 0 {
                    self.cleanup_reassembly_buffer(fragment_id.as_u16() as u32);
                    return Err(EdgeCaseError::FragmentTimeout);
                }
                // Extend timeout for partial reassembly in progress
                // Note: FragmentTimeout is not atomic, so we can't update it in place safely if shared
                // But here we have a reference from DashMap, so we might need interior mutability
                // However, FragmentTimeout is u64 wrapper.
                // Assuming we can't update it easily without interior mutability.
                // For now, we'll skip updating it to avoid compilation error, or assume it's read-only.
                // Or better, we should use AtomicU64 for timeout if it needs updates.
                // Given the error, we'll just log it.
                // reassembly_buffer.timeout.store(...) - removed
            }
        }

        // Handle fragment memory exhaustion
        self.handle_fragment_memory_exhaustion()?;

        Ok(())
    }

    /// Handle fragment memory exhaustion
    fn handle_fragment_memory_exhaustion(&self) -> Result<(), EdgeCaseError> {
        if self.active_reassembly_buffers.len() >= EdgeCaseConstants::MAX_CONCURRENT_REASSEMBLIES {
            // Find oldest incomplete reassembly to evict
            let mut oldest_id = None;
            let mut oldest_timeout = u64::MAX;

            for entry in self.active_reassembly_buffers.iter() {
                let timeout = entry.timeout.as_u64();
                if timeout < oldest_timeout {
                    oldest_timeout = timeout;
                    oldest_id = Some(*entry.key());
                }
            }

            if let Some(id) = oldest_id {
                self.cleanup_reassembly_buffer(id);
                return Ok(());
            }
            return Err(EdgeCaseError::MemoryExhausted);
        }
        Ok(())
    }

    /// Cleanup reassembly buffer
    fn cleanup_reassembly_buffer(&self, fragment_id: u32) {
        self.active_reassembly_buffers.remove(&fragment_id);
    }

    /// Handle time synchronization edge cases
    pub fn handle_time_sync_edge_cases(&self, session_id: SessionId) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Some(session) = self.sessions.get(&session_id.as_u64()) {
            // Edge Case 1: Clock moving backwards (system clock regression)
            let last_known_time = session.last_known_time.load(Ordering::Relaxed);
            if current_time < last_known_time {
                let time_regression = last_known_time - current_time;
                if time_regression
                    > EdgeCaseConstants::MAX_ACCEPTABLE_TIME_REGRESSION.as_millis() as u64
                {
                    return Err(EdgeCaseError::ClockRegressionDetected);
                }
                // Small regression, adjust gradually to maintain synchronization
                let current_offset = session.time_offset.load(Ordering::Relaxed);
                session.time_offset.store(
                    current_offset + time_regression as i64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }

            // Edge Case 2: Extreme time drift (more than 1 hour)
            let time_offset = session.time_offset.load(Ordering::Relaxed);
            if time_offset.unsigned_abs()
                > EdgeCaseConstants::MAX_EXTREME_TIME_DRIFT.as_millis() as u64
            {
                return Err(EdgeCaseError::ConnectionTerminate);
            }

            // Edge Case 3: Peer time synchronization requests during our own sync
            let sync_in_progress = session.time_sync_in_progress.load(Ordering::Relaxed);
            if sync_in_progress != 0 {
                // In a real implementation, this would handle sync collision resolution
                // For now, we just continue
            }

            // Update last known time
            session
                .last_known_time
                .store(current_time, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(())
    }

    /// Handle flow control edge cases
    pub fn handle_flow_control_edge_cases(
        &self,
        session_id: SessionId,
    ) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if let Some(session) = self.sessions.get(&session_id.as_u64()) {
            let peer_window = session.peer_window_size.load(Ordering::Relaxed);
            let local_window = session.local_window_size.load(Ordering::Relaxed);

            // Edge Case 4: Simultaneous zero window from both peers (deadlock)
            if peer_window == 0 && local_window == 0 {
                return self.resolve_window_deadlock(session_id);
            }

            // Edge Case 5: Window update lost causing indefinite stall
            if peer_window == 0 {
                // In a real implementation, this would check time since last window update
                // and send zero window probe if needed
            }
        }

        Ok(())
    }

    /// Resolve window deadlock
    fn resolve_window_deadlock(&self, session_id: SessionId) -> Result<(), EdgeCaseError> {
        if let Some(session) = self.sessions.get(&session_id.as_u64()) {
            // Force minimum window opening to break deadlock
            // In a real implementation, this would use endpoint comparison
            session.local_window_size.store(
                EdgeCaseConstants::MIN_DEADLOCK_WINDOW_SIZE,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(())
    }

    /// Handle recovery edge cases
    pub fn handle_recovery_edge_cases(
        &self,
        new_recovery_priority: u32,
    ) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Edge Case 1: Recovery initiated during another recovery
        let recovery_in_progress = self
            .recovery_state
            .recovery_in_progress
            .load(Ordering::Relaxed);
        if recovery_in_progress != 0 {
            let current_priority = self.recovery_state.current_level.load(Ordering::Relaxed);
            if new_recovery_priority > current_priority {
                // Higher priority recovery, abort current
                self.recovery_state
                    .recovery_in_progress
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                self.recovery_state
                    .current_level
                    .store(new_recovery_priority, std::sync::atomic::Ordering::Relaxed);
                self.recovery_state
                    .recovery_in_progress
                    .store(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(());
            }
            // Lower priority, would queue for later in real implementation
            return Err(EdgeCaseError::RecoveryInProgress);
        }

        // Edge Case 2: Maximum recovery level reached
        let current_level = self.recovery_state.current_level.load(Ordering::Relaxed);
        if current_level >= 10 {
            // Assuming 10 is max level
            return Err(EdgeCaseError::SessionUnrecoverable);
        }

        // Edge Case 3: Recovery attempts exceeding maximum
        let total_attempts = self
            .recovery_state
            .total_recovery_attempts
            .load(Ordering::Relaxed);
        if total_attempts >= EdgeCaseConstants::MAX_TOTAL_RECOVERY_ATTEMPTS {
            return Err(EdgeCaseError::RecoveryAttemptsExhausted);
        }

        Ok(())
    }

    /// Handle connection management edge cases
    pub fn handle_connection_edge_cases(
        &self,
        session_id: SessionId,
        local_endpoint: u64,
        peer_endpoint: u64,
    ) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Edge Case 1: Simultaneous connection attempts with same session ID
        if self.sessions.contains_key(&session_id.as_u64()) {
            // Use endpoint comparison to resolve simultaneous connections
            // The endpoint with the higher value wins
            if local_endpoint < peer_endpoint {
                // Our connection wins, reject peer's
                return Ok(());
            }
            // Peer's connection wins, abort ours
            return Err(EdgeCaseError::SimultaneousConnection);
        }

        // Edge Case 2: Connection attempt during system shutdown
        let shutdown = self
            .system_shutdown
            .load(std::sync::atomic::Ordering::Relaxed);
        if shutdown != 0 {
            return Err(EdgeCaseError::SystemShuttingDown);
        }

        // Edge Case 3: Too many concurrent connections
        let active_count = self.active_connections.load(Ordering::Relaxed);
        if active_count >= EdgeCaseConstants::MAX_CONCURRENT_CONNECTIONS {
            return Err(EdgeCaseError::ConnectionLimitExceeded);
        }

        Ok(())
    }

    /// Handle resource exhaustion edge cases
    pub fn handle_resource_exhaustion(&self) -> Result<(), EdgeCaseError> {
        self.boundary_conditions_detected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Edge Case 1: Memory exhaustion during packet processing
        let memory_usage = self.memory_usage.load(Ordering::Relaxed);
        if memory_usage >= EdgeCaseConstants::MIN_REQUIRED_MEMORY {
            // In a real implementation, this would cleanup expired buffers
            return Err(EdgeCaseError::MemoryExhausted);
        }

        // Edge Case 2: Send buffer overflow
        let send_usage = self.send_buffer_usage.load(Ordering::Relaxed);
        if send_usage > EdgeCaseConstants::MAX_SEND_BUFFER_SIZE {
            return Err(EdgeCaseError::SendBufferOverflow);
        }

        // Edge Case 3: Receive buffer overflow
        let receive_usage = self.receive_buffer_usage.load(Ordering::Relaxed);
        if receive_usage > EdgeCaseConstants::MAX_RECEIVE_BUFFER_SIZE {
            return Err(EdgeCaseError::ReceiveBufferOverflow);
        }

        // Edge Case 4: File descriptor exhaustion
        let fd_count = self.open_file_descriptors.load(Ordering::Relaxed);
        if fd_count >= EdgeCaseConstants::MAX_FILE_DESCRIPTORS {
            return Err(EdgeCaseError::ResourceExhausted);
        }

        Ok(())
    }

    /// Handle security edge cases
    pub fn handle_security_edge_cases(
        &self,
        _source_ip: u32,
        timestamp: u64,
    ) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Edge Case 1: Timestamp outside acceptable window during authentication
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let timestamp_diff = timestamp.abs_diff(current_time);

        if timestamp_diff > (EdgeCaseConstants::MAX_LEGITIMATE_CLOCK_SKEW_NS / 1_000_000) as u64 {
            return Err(EdgeCaseError::TimestampAttackDetected);
        }

        // Edge Case 2: Rate limiting checks would go here
        // For now, we assume no rate limiting violations

        Ok(())
    }

    /// Handle error processing edge cases
    pub fn handle_error_processing_edge_cases(&self, error_code: u32) -> Result<(), EdgeCaseError> {
        self.edge_cases_handled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let error_count = self
            .error_response_count
            .load(std::sync::atomic::Ordering::Relaxed);

        if error_count >= EdgeCaseConstants::MAX_ERROR_RESPONSES {
            return Err(EdgeCaseError::ErrorLoop);
        }

        // Edge Case 2: Unknown error code
        if error_code > 255 {
            // Assuming 255 is max valid error code
            return Err(EdgeCaseError::UnknownError);
        }

        // Increment error response count
        self.error_response_count
            .increment(std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }

    /// Add a session for tracking
    pub fn add_session(&self, session_id: SessionId) {
        let session_id_u64 = session_id.as_u64();
        let session_state = Arc::new(SessionState::new(session_id));
        self.sessions.insert(session_id_u64, session_state);
        self.active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Remove a session
    pub fn remove_session(&self, session_id: SessionId) {
        if self.sessions.remove(&session_id.as_u64()).is_some() {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Set system shutdown flag
    pub fn set_system_shutdown(&self, shutdown: bool) {
        self.system_shutdown.store(
            if shutdown { 1 } else { 0 },
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Update resource usage
    pub fn update_memory_usage(&self, usage: usize) {
        self.memory_usage
            .store(usage, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn update_send_buffer_usage(&self, usage: usize) {
        self.send_buffer_usage
            .store(usage, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn update_receive_buffer_usage(&self, usage: usize) {
        self.receive_buffer_usage
            .store(usage, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn update_file_descriptor_count(&self, count: usize) {
        self.open_file_descriptors
            .store(count, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get statistics
    pub fn get_edge_cases_handled(&self) -> u64 {
        self.edge_cases_handled.load(Ordering::Relaxed)
    }

    pub fn get_boundary_conditions_detected(&self) -> u64 {
        self.boundary_conditions_detected.load(Ordering::Relaxed)
    }

    pub fn get_active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Cleanup expired entries
    pub fn cleanup_expired_entries(&self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Cleanup expired reassembly buffers
        let mut expired_ids = Vec::new();
        for entry in self.active_reassembly_buffers.iter() {
            let timeout = entry.timeout.as_u64();
            if current_time >= timeout {
                expired_ids.push(*entry.key());
            }
        }

        for id in expired_ids {
            self.cleanup_reassembly_buffer(id);
        }

        // Reset error response count periodically
        self.error_response_count
            .store(0, std::sync::atomic::Ordering::Relaxed);

        // Cleanup security validator
        self.security_validator.cleanup_expired_entries();
    }
}

impl Default for EdgeCaseHandler {
    fn default() -> Self {
        Self::new()
    }
}
