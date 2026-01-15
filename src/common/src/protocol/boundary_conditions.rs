// Boundary condition management for comprehensive edge case handling
//
// This module provides a centralized boundary condition manager that coordinates
// edge case handling across all protocol components, ensuring consistent behavior
// and preventing security vulnerabilities from boundary conditions.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

// Import ALL types from the authoritative consolidated types module
use super::edge_cases::{EdgeCaseConstants, EdgeCaseError, EdgeCaseHandler};
use super::validation::PacketValidator;
use crate::error::{
    BuckwildError, ProtocolError, SecurityError, ValidationError as ErrorValidationError,
};
use crate::protocol::packet::Packet;
use crate::protocol::types::*;
use crate::security::SecurityValidator;

/// Handler function type for recovery actions
type RecoveryHandler =
    Box<dyn Fn(&BoundaryConditionEvent) -> Result<(), BuckwildError> + Send + Sync>;

/// Boundary condition types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoundaryConditionType {
    // Numeric boundaries
    SequenceNumberWrapAround,
    TimestampOverflow,
    SessionIdExhaustion,
    PortRangeExhaustion,

    // Resource boundaries
    MemoryExhaustion,
    ConnectionLimitReached,
    BufferOverflow,
    FileDescriptorLimit,

    // Time boundaries
    MonthBoundaryTransition,
    DaylightSavingTransition,
    LeapSecondTransition,
    ClockSynchronizationFailure,

    // Security boundaries
    AuthenticationFailureThreshold,
    RateLimitThreshold,
    AttackDetectionThreshold,
    CryptographicKeyExpiration,

    // Protocol boundaries
    PacketSizeLimit,
    FragmentationLimit,
    ReassemblyTimeout,
    ConnectionTimeout,

    // Network boundaries
    MTUDiscoveryFailure,
    PathMTUChange,
    NetworkPartition,
    AsymmetricRouting,
}

impl std::fmt::Display for BoundaryConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequenceNumberWrapAround => write!(f, "Sequence number wrap-around"),
            Self::TimestampOverflow => write!(f, "Timestamp overflow"),
            Self::SessionIdExhaustion => write!(f, "Session ID exhaustion"),
            Self::PortRangeExhaustion => write!(f, "Port range exhaustion"),
            Self::MemoryExhaustion => write!(f, "Memory exhaustion"),
            Self::ConnectionLimitReached => write!(f, "Connection limit reached"),
            Self::BufferOverflow => write!(f, "Buffer overflow"),
            Self::FileDescriptorLimit => write!(f, "File descriptor limit"),
            Self::MonthBoundaryTransition => write!(f, "Month boundary transition"),
            Self::DaylightSavingTransition => write!(f, "Daylight saving transition"),
            Self::LeapSecondTransition => write!(f, "Leap second transition"),
            Self::ClockSynchronizationFailure => write!(f, "Clock synchronization failure"),
            Self::AuthenticationFailureThreshold => write!(f, "Authentication failure threshold"),
            Self::RateLimitThreshold => write!(f, "Rate limit threshold"),
            Self::AttackDetectionThreshold => write!(f, "Attack detection threshold"),
            Self::CryptographicKeyExpiration => write!(f, "Cryptographic key expiration"),
            Self::PacketSizeLimit => write!(f, "Packet size limit"),
            Self::FragmentationLimit => write!(f, "Fragmentation limit"),
            Self::ReassemblyTimeout => write!(f, "Reassembly timeout"),
            Self::ConnectionTimeout => write!(f, "Connection timeout"),
            Self::MTUDiscoveryFailure => write!(f, "MTU discovery failure"),
            Self::PathMTUChange => write!(f, "Path MTU change"),
            Self::NetworkPartition => write!(f, "Network partition"),
            Self::AsymmetricRouting => write!(f, "Asymmetric routing"),
        }
    }
}

/// Boundary condition event
#[derive(Debug, Clone)]
pub struct BoundaryConditionEvent {
    pub condition_type: BoundaryConditionType,
    pub session_id: Option<SessionId>,
    pub timestamp: Timestamp,
    pub severity: BoundaryConditionSeverity,
    pub context: String,
    pub recovery_action: Option<BoundaryConditionRecovery>,
}

/// Boundary condition severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BoundaryConditionSeverity {
    Info,
    Warning,
    Error,
    Critical,
    Fatal,
}

impl std::fmt::Display for BoundaryConditionSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
            Self::Fatal => write!(f, "FATAL"),
        }
    }
}

/// Boundary condition recovery actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryConditionRecovery {
    // Automatic recovery actions
    GracefulDegradation,
    ResourceCleanup,
    ConnectionTermination,
    SessionReset,

    // Manual intervention required
    SystemRestart,
    ConfigurationUpdate,
    SecurityResponse,
    NetworkReconfiguration,

    // No recovery possible
    FatalError,
}

impl std::fmt::Display for BoundaryConditionRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GracefulDegradation => write!(f, "Graceful degradation"),
            Self::ResourceCleanup => write!(f, "Resource cleanup"),
            Self::ConnectionTermination => write!(f, "Connection termination"),
            Self::SessionReset => write!(f, "Session reset"),
            Self::SystemRestart => write!(f, "System restart required"),
            Self::ConfigurationUpdate => write!(f, "Configuration update required"),
            Self::SecurityResponse => write!(f, "Security response required"),
            Self::NetworkReconfiguration => write!(f, "Network reconfiguration required"),
            Self::FatalError => write!(f, "Fatal error - no recovery possible"),
        }
    }
}

/// Boundary condition statistics
#[derive(Debug, Default)]
pub struct BoundaryConditionStats {
    pub total_conditions_detected: PacketCount,
    pub conditions_by_type: DashMap<BoundaryConditionType, PacketCount>,
    pub conditions_by_severity: DashMap<BoundaryConditionSeverity, PacketCount>,
    pub successful_recoveries: PacketCount,
    pub failed_recoveries: PacketCount,
    pub fatal_conditions: PacketCount,
}

impl BoundaryConditionStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_condition(
        &self,
        condition_type: BoundaryConditionType,
        severity: BoundaryConditionSeverity,
    ) {
        self.total_conditions_detected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        self.conditions_by_type
            .entry(condition_type)
            .or_insert_with(|| PacketCount::new(0))
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        self.conditions_by_severity
            .entry(severity)
            .or_insert_with(|| PacketCount::new(0))
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if severity == BoundaryConditionSeverity::Fatal {
            self.fatal_conditions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn record_recovery_success(&self) {
        self.successful_recoveries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_recovery_failure(&self) {
        self.failed_recoveries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Comprehensive boundary condition manager
pub struct BoundaryConditionManager {
    /// Edge case handler for low-level edge cases
    pub edge_case_handler: EdgeCaseHandler,

    /// Packet validator for validation boundary conditions
    packet_validator: PacketValidator,

    /// Security validator for security boundary conditions
    security_validator: SecurityValidator,

    /// Event history for analysis
    event_history: RwLock<Vec<BoundaryConditionEvent>>,

    /// Statistics tracking
    stats: BoundaryConditionStats,

    /// Configuration thresholds
    sequence_wrap_threshold: AtomicU32,
    memory_warning_threshold: AtomicUsize,
    memory_critical_threshold: AtomicUsize,
    connection_warning_threshold: AtomicUsize,
    connection_critical_threshold: AtomicUsize,

    /// Recovery handlers
    recovery_handlers: DashMap<BoundaryConditionType, RecoveryHandler>,
}

impl BoundaryConditionManager {
    /// Create a new boundary condition manager
    pub fn new() -> Self {
        let manager = Self {
            edge_case_handler: EdgeCaseHandler::new(),
            packet_validator: PacketValidator::new(),
            security_validator: SecurityValidator::new(),
            event_history: RwLock::new(Vec::new()),
            stats: BoundaryConditionStats::new(),
            sequence_wrap_threshold: AtomicU32::new(EdgeCaseConstants::SEQUENCE_WRAP_THRESHOLD),
            memory_warning_threshold: AtomicUsize::new(EdgeCaseConstants::MIN_REQUIRED_MEMORY * 8),
            memory_critical_threshold: AtomicUsize::new(
                EdgeCaseConstants::MIN_REQUIRED_MEMORY * 16,
            ),
            connection_warning_threshold: AtomicUsize::new(
                EdgeCaseConstants::MAX_CONCURRENT_CONNECTIONS * 8 / 10,
            ),
            connection_critical_threshold: AtomicUsize::new(
                EdgeCaseConstants::MAX_CONCURRENT_CONNECTIONS * 9 / 10,
            ),
            recovery_handlers: DashMap::new(),
        };

        // Register default recovery handlers
        manager.register_default_recovery_handlers();

        manager
    }

    /// Register default recovery handlers
    fn register_default_recovery_handlers(&self) {
        // Memory exhaustion recovery
        self.recovery_handlers.insert(
            BoundaryConditionType::MemoryExhaustion,
            Box::new(|_event| {
                // In a real implementation, this would trigger garbage collection,
                // cleanup expired buffers, etc.
                Ok(())
            }),
        );

        // Connection limit recovery
        self.recovery_handlers.insert(
            BoundaryConditionType::ConnectionLimitReached,
            Box::new(|_event| {
                // In a real implementation, this would close idle connections,
                // reject new connections, etc.
                Ok(())
            }),
        );

        // Sequence number wraparound recovery
        self.recovery_handlers.insert(
            BoundaryConditionType::SequenceNumberWrapAround,
            Box::new(|_event| {
                // In a real implementation, this would initiate sequence number
                // wraparound negotiation with peer
                Ok(())
            }),
        );
    }

    /// Validate packet with comprehensive boundary condition checking
    pub fn validate_packet_with_boundary_checks(
        &self,
        packet: &Packet,
        _source_ip: IpAddress,
    ) -> Result<(), BuckwildError> {
        // Basic packet size validation
        let packet_size = packet.total_size();
        if !self.packet_validator.validate_size(packet_size) {
            self.handle_boundary_condition(
                BoundaryConditionType::PacketSizeLimit,
                Some(packet.session_id()),
                BoundaryConditionSeverity::Error,
                format!("Packet size {} outside valid range", packet_size),
            )?;

            return Err(BuckwildError::Validation(
                ErrorValidationError::validation_failed(format!(
                    "Invalid packet size: {}",
                    packet_size
                )),
            ));
        }

        // Validate packet structure
        if let Err(validation_error) = packet.validate() {
            // Map validation errors to boundary condition types
            let boundary_type = match &validation_error {
                ValidationError::InvalidLength | ValidationError::BufferTooSmall => {
                    BoundaryConditionType::PacketSizeLimit
                }
                ValidationError::InvalidSequenceNumber => {
                    BoundaryConditionType::SequenceNumberWrapAround
                }
                _ => BoundaryConditionType::PacketSizeLimit,
            };

            self.handle_boundary_condition(
                boundary_type,
                Some(packet.session_id()),
                BoundaryConditionSeverity::Error,
                format!("Packet validation failed: {}", validation_error),
            )?;

            return Err(BuckwildError::Validation(
                ErrorValidationError::validation_failed(validation_error.to_string()),
            ));
        }

        // Security validation: validate timestamp
        if let Err(security_error) = self
            .security_validator
            .validate_timestamp(packet.timestamp())
        {
            let (boundary_type, severity) = match &security_error {
                SecurityError::TimestampValidationFailed { .. } => (
                    BoundaryConditionType::ClockSynchronizationFailure,
                    BoundaryConditionSeverity::Error,
                ),
                SecurityError::DuplicatePacket { .. } => (
                    BoundaryConditionType::AttackDetectionThreshold,
                    BoundaryConditionSeverity::Warning,
                ),
                SecurityError::ReplayAttack { .. } => (
                    BoundaryConditionType::AttackDetectionThreshold,
                    BoundaryConditionSeverity::Critical,
                ),
                _ => (
                    BoundaryConditionType::AttackDetectionThreshold,
                    BoundaryConditionSeverity::Error,
                ),
            };

            self.handle_boundary_condition(
                boundary_type,
                Some(packet.session_id()),
                severity,
                format!("Security validation failed: {}", security_error),
            )?;

            return Err(BuckwildError::Security(security_error));
        }

        // Security validation: validate session ID
        if let Err(security_error) = self
            .security_validator
            .validate_session_id(packet.session_id())
        {
            self.handle_boundary_condition(
                BoundaryConditionType::SessionIdExhaustion,
                Some(packet.session_id()),
                BoundaryConditionSeverity::Error,
                format!("Session ID validation failed: {}", security_error),
            )?;

            return Err(BuckwildError::Security(security_error));
        }

        // Edge case validation
        if let Err(edge_case_error) = self.edge_case_handler.handle_packet_edge_cases(packet) {
            let boundary_type = match edge_case_error {
                EdgeCaseError::SequenceWraparoundNotReady => {
                    BoundaryConditionType::SequenceNumberWrapAround
                }
                EdgeCaseError::PayloadTooLarge => BoundaryConditionType::PacketSizeLimit,
                EdgeCaseError::MemoryExhausted => BoundaryConditionType::MemoryExhaustion,
                _ => BoundaryConditionType::PacketSizeLimit,
            };

            self.handle_boundary_condition(
                boundary_type,
                Some(packet.session_id()),
                BoundaryConditionSeverity::Error,
                format!("Edge case detected: {}", edge_case_error),
            )?;

            return Err(BuckwildError::Protocol(ProtocolError::invalid_format(
                edge_case_error.to_string(),
            )));
        }

        Ok(())
    }

    /// Handle a boundary condition event
    pub fn handle_boundary_condition(
        &self,
        condition_type: BoundaryConditionType,
        session_id: Option<SessionId>,
        severity: BoundaryConditionSeverity,
        context: String,
    ) -> Result<(), BuckwildError> {
        let timestamp = Timestamp::now();

        // Determine recovery action
        let recovery_action = self.determine_recovery_action(condition_type, severity);

        // Create event
        let event = BoundaryConditionEvent {
            condition_type,
            session_id,
            timestamp,
            severity,
            context,
            recovery_action,
        };

        // Record statistics
        self.stats.record_condition(condition_type, severity);

        // Add to event history
        {
            let mut history = self.event_history.write();
            history.push(event.clone());

            // Limit history size
            if history.len() > 10000 {
                history.drain(0..1000);
            }
        }

        // Execute recovery action
        if let Some(recovery) = recovery_action {
            match self.execute_recovery_action(&event, recovery) {
                Ok(()) => {
                    self.stats.record_recovery_success();
                }
                Err(e) => {
                    self.stats.record_recovery_failure();
                    if severity >= BoundaryConditionSeverity::Critical {
                        return Err(e);
                    }
                }
            }
        }

        // Log the event
        self.log_boundary_condition_event(&event);

        Ok(())
    }

    /// Determine appropriate recovery action for a boundary condition
    fn determine_recovery_action(
        &self,
        condition_type: BoundaryConditionType,
        severity: BoundaryConditionSeverity,
    ) -> Option<BoundaryConditionRecovery> {
        match (condition_type, severity) {
            // Memory-related conditions
            (BoundaryConditionType::MemoryExhaustion, BoundaryConditionSeverity::Warning) => {
                Some(BoundaryConditionRecovery::ResourceCleanup)
            }
            (BoundaryConditionType::MemoryExhaustion, BoundaryConditionSeverity::Critical) => {
                Some(BoundaryConditionRecovery::GracefulDegradation)
            }
            (BoundaryConditionType::MemoryExhaustion, BoundaryConditionSeverity::Fatal) => {
                Some(BoundaryConditionRecovery::FatalError)
            }

            // Connection-related conditions
            (BoundaryConditionType::ConnectionLimitReached, _) => {
                Some(BoundaryConditionRecovery::GracefulDegradation)
            }

            // Security-related conditions
            (
                BoundaryConditionType::AttackDetectionThreshold,
                BoundaryConditionSeverity::Critical,
            ) => Some(BoundaryConditionRecovery::SecurityResponse),

            // Protocol-related conditions
            (BoundaryConditionType::SequenceNumberWrapAround, _) => {
                Some(BoundaryConditionRecovery::SessionReset)
            }

            // Time-related conditions
            (BoundaryConditionType::MonthBoundaryTransition, _) => {
                Some(BoundaryConditionRecovery::GracefulDegradation)
            }

            // Fatal conditions
            (_, BoundaryConditionSeverity::Fatal) => Some(BoundaryConditionRecovery::FatalError),

            // Default: no specific recovery action
            _ => None,
        }
    }

    /// Execute a recovery action
    fn execute_recovery_action(
        &self,
        event: &BoundaryConditionEvent,
        recovery: BoundaryConditionRecovery,
    ) -> Result<(), BuckwildError> {
        match recovery {
            BoundaryConditionRecovery::GracefulDegradation => {
                // Implement graceful degradation logic
                self.execute_graceful_degradation(event)
            }
            BoundaryConditionRecovery::ResourceCleanup => {
                // Implement resource cleanup logic
                self.execute_resource_cleanup(event)
            }
            BoundaryConditionRecovery::ConnectionTermination => {
                // Implement connection termination logic
                self.execute_connection_termination(event)
            }
            BoundaryConditionRecovery::SessionReset => {
                // Implement session reset logic
                self.execute_session_reset(event)
            }
            BoundaryConditionRecovery::SecurityResponse => {
                // Implement security response logic
                self.execute_security_response(event)
            }
            BoundaryConditionRecovery::FatalError => {
                // Fatal error - no recovery possible
                Err(BuckwildError::internal_error(format!(
                    "Fatal boundary condition: {} - {}",
                    event.condition_type, event.context
                )))
            }
            _ => {
                // Other recovery actions require manual intervention
                Ok(())
            }
        }
    }

    /// Execute graceful degradation
    fn execute_graceful_degradation(
        &self,
        _event: &BoundaryConditionEvent,
    ) -> Result<(), BuckwildError> {
        // In a real implementation, this would:
        // - Reduce service quality
        // - Disable non-essential features
        // - Increase resource cleanup frequency
        // - Adjust protocol parameters for lower resource usage
        Ok(())
    }

    /// Execute resource cleanup
    fn execute_resource_cleanup(
        &self,
        _event: &BoundaryConditionEvent,
    ) -> Result<(), BuckwildError> {
        // Trigger cleanup in edge case handler
        self.edge_case_handler.cleanup_expired_entries();

        // Cleanup security validator
        self.security_validator.cleanup_expired_entries();

        // In a real implementation, this would also:
        // - Force garbage collection
        // - Clean up expired buffers
        // - Close idle connections
        // - Compress logs

        Ok(())
    }

    /// Execute connection termination
    fn execute_connection_termination(
        &self,
        event: &BoundaryConditionEvent,
    ) -> Result<(), BuckwildError> {
        if let Some(session_id) = event.session_id.clone() {
            // Remove session from edge case handler
            self.edge_case_handler.remove_session(session_id);

            // In a real implementation, this would:
            // - Send connection termination packets
            // - Clean up connection state
            // - Notify application layer
        }
        Ok(())
    }

    /// Execute session reset
    fn execute_session_reset(&self, event: &BoundaryConditionEvent) -> Result<(), BuckwildError> {
        if let Some(session_id) = event.session_id.clone() {
            // Remove and re-add session to reset state
            self.edge_case_handler.remove_session(session_id.clone());
            self.edge_case_handler.add_session(session_id);

            // In a real implementation, this would:
            // - Reset sequence numbers
            // - Renegotiate session parameters
            // - Clear session-specific caches
        }
        Ok(())
    }

    /// Execute security response
    fn execute_security_response(
        &self,
        _event: &BoundaryConditionEvent,
    ) -> Result<(), BuckwildError> {
        // In a real implementation, this would:
        // - Block attacking sources
        // - Increase security monitoring
        // - Alert security systems
        // - Adjust rate limiting parameters
        Ok(())
    }

    /// Log boundary condition event
    fn log_boundary_condition_event(&self, event: &BoundaryConditionEvent) {
        // In a real implementation, this would use proper logging
        eprintln!(
            "[{}] {} boundary condition: {} - {}",
            event.severity,
            event.condition_type,
            event.context,
            event
                .recovery_action
                .map_or("No recovery".to_string(), |r| r.to_string())
        );
    }

    /// Check resource boundaries
    pub fn check_resource_boundaries(&self) -> Result<(), BuckwildError> {
        // Check memory usage
        let memory_usage = self.edge_case_handler.get_active_connections() * 1024; // Simplified
        let memory_warning = self.memory_warning_threshold.load(Ordering::Relaxed);
        let memory_critical = self.memory_critical_threshold.load(Ordering::Relaxed);

        if memory_usage >= memory_critical {
            self.handle_boundary_condition(
                BoundaryConditionType::MemoryExhaustion,
                None,
                BoundaryConditionSeverity::Critical,
                format!("Memory usage: {} bytes", memory_usage),
            )?;
        } else if memory_usage >= memory_warning {
            self.handle_boundary_condition(
                BoundaryConditionType::MemoryExhaustion,
                None,
                BoundaryConditionSeverity::Warning,
                format!("Memory usage: {} bytes", memory_usage),
            )?;
        }

        // Check connection limits
        let connection_count = self.edge_case_handler.get_active_connections();
        let connection_warning = self.connection_warning_threshold.load(Ordering::Relaxed);
        let connection_critical = self.connection_critical_threshold.load(Ordering::Relaxed);

        if connection_count >= connection_critical {
            self.handle_boundary_condition(
                BoundaryConditionType::ConnectionLimitReached,
                None,
                BoundaryConditionSeverity::Critical,
                format!("Active connections: {}", connection_count),
            )?;
        } else if connection_count >= connection_warning {
            self.handle_boundary_condition(
                BoundaryConditionType::ConnectionLimitReached,
                None,
                BoundaryConditionSeverity::Warning,
                format!("Active connections: {}", connection_count),
            )?;
        }

        Ok(())
    }

    /// Check for sequence number wraparound conditions
    pub fn check_sequence_wraparound(
        &self,
        session_id: SessionId,
        sequence_number: SequenceNumber,
    ) -> Result<(), BuckwildError> {
        let threshold = self.sequence_wrap_threshold.load(Ordering::Relaxed);

        if sequence_number.as_u32() >= threshold {
            self.handle_boundary_condition(
                BoundaryConditionType::SequenceNumberWrapAround,
                Some(session_id),
                BoundaryConditionSeverity::Warning,
                format!(
                    "Sequence number {} approaching wraparound",
                    sequence_number.as_u32()
                ),
            )?;
        }

        Ok(())
    }

    /// Check for time boundary conditions
    pub fn check_time_boundaries(&self) -> Result<(), BuckwildError> {
        let current_time = Timestamp::now().as_u64() / 1_000_000_000; // Convert nanoseconds to seconds

        // Check for month boundary (simplified)
        let seconds_in_month = 30 * 24 * 60 * 60; // Approximate
        let seconds_until_month_end = seconds_in_month - (current_time % seconds_in_month);

        // Warn 1 hour before month boundary
        if seconds_until_month_end <= 3600 {
            self.handle_boundary_condition(
                BoundaryConditionType::MonthBoundaryTransition,
                None,
                BoundaryConditionSeverity::Warning,
                format!("Month boundary in {} seconds", seconds_until_month_end),
            )?;
        }

        Ok(())
    }

    /// Get boundary condition statistics
    pub fn get_stats(&self) -> &BoundaryConditionStats {
        &self.stats
    }

    /// Get recent boundary condition events
    pub fn get_recent_events(&self, limit: usize) -> Vec<BoundaryConditionEvent> {
        let history = self.event_history.read();
        let start = if history.len() > limit {
            history.len() - limit
        } else {
            0
        };
        history[start..].to_vec()
    }

    /// Set configuration thresholds
    pub fn set_memory_thresholds(&self, warning: MemorySize, critical: MemorySize) {
        self.memory_warning_threshold
            .store(warning.as_usize(), std::sync::atomic::Ordering::Relaxed);
        self.memory_critical_threshold
            .store(critical.as_usize(), std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_connection_thresholds(&self, warning: ConnectionCount, critical: ConnectionCount) {
        self.connection_warning_threshold
            .store(warning.as_u32() as usize, Ordering::Relaxed);
        self.connection_critical_threshold
            .store(critical.as_u32() as usize, Ordering::Relaxed);
    }

    pub fn set_sequence_wrap_threshold(&self, threshold: SequenceNumber) {
        self.sequence_wrap_threshold
            .store(threshold.as_u32(), Ordering::Relaxed);
    }

    /// Cleanup expired events and perform maintenance
    pub fn cleanup_and_maintenance(&self) {
        // Cleanup edge case handler
        self.edge_case_handler.cleanup_expired_entries();

        // Cleanup security validator
        self.security_validator.cleanup_expired_entries();

        // Cleanup old events
        {
            let mut history = self.event_history.write();
            if history.len() > 5000 {
                history.drain(0..1000);
            }
        }
    }
}

impl Default for BoundaryConditionManager {
    fn default() -> Self {
        Self::new()
    }
}
