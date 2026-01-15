// Protocol validation framework
//
// This module provides comprehensive validation for protocol packets including
// structural validation, security validation, and state validation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

// Import ALL types from the authoritative consolidated types module
use super::state::{ProtocolStateManager, StateTransitionRequest};
use crate::error::ProtocolError;
use crate::protocol::types::*;

// Import the Packet type from packet module
use crate::protocol::packet::{Packet, PacketHeader};

/// Helper to handle RwLock poisoning errors
fn lock_poisoned() -> ProtocolError {
    ProtocolError::invalid_format("Lock poisoned - concurrent panic detected")
}

/// Trait for built packets that can be validated
pub trait BuiltPacket {
    fn total_size(&self) -> usize;
    fn packet_type(&self) -> Option<PacketType>;
    fn session_id(&self) -> SessionId;
    fn sequence_number(&self) -> SequenceNumber;
    fn header(&self) -> &PacketHeader;
    fn payload(&self) -> &[u8];
    fn flags(&self) -> PacketFlags;
}

/// Implement BuiltPacket for the unified Packet enum
impl BuiltPacket for Packet {
    fn total_size(&self) -> usize {
        self.total_size()
    }

    fn packet_type(&self) -> Option<PacketType> {
        Some(self.packet_type())
    }

    fn session_id(&self) -> SessionId {
        self.session_id()
    }

    fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number()
    }

    fn header(&self) -> &PacketHeader {
        self.header()
    }

    fn payload(&self) -> &[u8] {
        self.payload()
    }

    fn flags(&self) -> PacketFlags {
        self.header().flags()
    }
}

/// Packet validator for boundary condition checking
#[derive(Debug, Default)]
pub struct PacketValidator {
    /// Maximum allowed packet size
    max_packet_size: usize,
    /// Minimum required packet size
    min_packet_size: usize,
}

impl PacketValidator {
    /// Create a new packet validator with default settings
    pub fn new() -> Self {
        Self {
            max_packet_size: 65536,
            min_packet_size: 8,
        }
    }

    /// Validate packet size bounds
    pub fn validate_size(&self, size: usize) -> bool {
        size >= self.min_packet_size && size <= self.max_packet_size
    }
}

/// Protocol validation framework
pub struct ProtocolValidator {
    /// State manager for state validation
    state_manager: Arc<ProtocolStateManager>,
    /// Validation rules
    rules: ValidationRules,
    /// Validation cache
    validation_cache: Arc<RwLock<HashMap<ValidationCacheKey, ValidationCacheEntry>>>,
    /// Statistics
    stats: Arc<RwLock<ValidationStats>>,
}

/// Validation rules configuration
#[derive(Debug, Clone)]
pub struct ValidationRules {
    /// Enable structural validation
    pub enable_structural_validation: bool,
    /// Enable state validation
    pub enable_state_validation: bool,
    /// Enable security validation
    pub enable_security_validation: bool,
    /// Enable timestamp validation
    pub enable_timestamp_validation: bool,
    /// Enable sequence validation
    pub enable_sequence_validation: bool,
    /// Maximum packet size
    pub max_packet_size: PacketSize,
    /// Minimum packet size
    pub min_packet_size: PacketSize,
    /// Timestamp window in seconds
    pub timestamp_window_sec: Duration,
    /// Enable validation caching
    pub enable_caching: bool,
    /// Cache timeout
    pub cache_timeout: Duration,
}

impl Default for ValidationRules {
    fn default() -> Self {
        Self {
            enable_structural_validation: true,
            enable_state_validation: true,
            enable_security_validation: true,
            enable_timestamp_validation: true,
            enable_sequence_validation: true,
            max_packet_size: PacketSize::new(65536),
            min_packet_size: PacketSize::new(20),
            timestamp_window_sec: Duration::from_secs(30), // 30 seconds
            enable_caching: true,
            cache_timeout: Duration::from_secs(60), // 60 seconds
        }
    }
}

/// Validation cache key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ValidationCacheKey {
    session_id: SessionId,
    packet_type: PacketType,
    sequence_number: SequenceNumber,
}

/// Validation cache entry
#[derive(Debug, Clone)]
struct ValidationCacheEntry {
    result: ValidationResult,
    timestamp: SystemTime,
}

/// Validation request
#[derive(Debug)]
pub struct ValidationRequest {
    /// Packet to validate
    pub packet: Packet,
    /// Source IP for context
    pub source_ip: Option<u32>,
    /// Whether this is a local packet
    pub is_local: bool,
    /// Additional context
    pub context: ValidationContext,
}

/// Validation context
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// Expected sequence number range
    pub expected_sequence_range: Option<(u32, u32)>,
    /// Connection state context
    pub connection_established: bool,
    /// Security level required
    pub required_security_level: SecurityLevel,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self {
            expected_sequence_range: None,
            connection_established: false,
            required_security_level: SecurityLevel::Standard,
        }
    }
}

/// Security level requirements
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Basic validation
    Basic,
    /// Standard validation
    Standard,
    /// High security validation
    High,
    /// Critical security validation
    Critical,
}

/// Validation result
#[derive(Debug, Clone)]
pub enum ValidationResult {
    /// Packet is valid
    Valid,
    /// Packet is valid with warnings
    ValidWithWarnings { warnings: Vec<ValidationWarning> },
    /// Packet is invalid
    Invalid { errors: Vec<ValidationError> },
}

/// Validation warning
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    /// Warning type
    pub warning_type: WarningType,
    /// Warning message
    pub message: String,
}

/// Warning types
#[derive(Debug, Clone)]
pub enum WarningType {
    /// Timestamp is old but within window
    OldTimestamp,
    /// Sequence number is out of order but valid
    OutOfOrderSequence,
    /// Packet size is unusual but valid
    UnusualPacketSize,
    /// Security validation was skipped
    SecuritySkipped,
}

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Error type
    pub error_type: ErrorType,
    /// Error message
    pub message: String,
    /// Severity level
    pub severity: ErrorSeverity,
}

/// Error types
#[derive(Debug, Clone)]
pub enum ErrorType {
    /// Structural validation error
    Structural,
    /// State validation error
    State,
    /// Security validation error
    Security,
    /// Timestamp validation error
    Timestamp,
    /// Sequence validation error
    Sequence,
}

/// Error severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Low severity - packet can be processed with caution
    Low,
    /// Medium severity - packet should be rejected
    Medium,
    /// High severity - potential security threat
    High,
    /// Critical severity - immediate action required
    Critical,
}

/// Validation statistics
#[derive(Debug, Clone)]
pub struct ValidationStats {
    /// Total validations performed
    pub total_validations: PacketCount,
    /// Valid packets
    pub valid_packets: PacketCount,
    /// Invalid packets
    pub invalid_packets: PacketCount,
    /// Packets with warnings
    pub packets_with_warnings: PacketCount,
    /// Cache hits
    pub cache_hits: CacheHitCount,
    /// Cache misses
    pub cache_misses: CacheMissCount,
    /// Validation errors by type
    pub errors_by_type: HashMap<String, ErrorCount>,
}

impl ProtocolValidator {
    /// Create a new protocol validator
    pub fn new(state_manager: Arc<ProtocolStateManager>) -> Self {
        Self::with_rules(state_manager, ValidationRules::default())
    }

    /// Create a new protocol validator with custom rules
    pub fn with_rules(state_manager: Arc<ProtocolStateManager>, rules: ValidationRules) -> Self {
        Self {
            state_manager,
            rules,
            validation_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ValidationStats {
                total_validations: PacketCount::new(0),
                valid_packets: PacketCount::new(0),
                invalid_packets: PacketCount::new(0),
                packets_with_warnings: PacketCount::new(0),
                cache_hits: CacheHitCount::new(0),
                cache_misses: CacheMissCount::new(0),
                errors_by_type: HashMap::new(),
            })),
        }
    }

    /// Validate a packet
    pub fn validate_packet(
        &self,
        request: ValidationRequest,
    ) -> Result<ValidationResult, ProtocolError> {
        let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;
        stats.total_validations = PacketCount::new(stats.total_validations.as_u64() + 1);
        drop(stats);

        // Check cache first
        if self.rules.enable_caching {
            if let Some(cached_result) = self.check_cache(&request.packet) {
                let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;
                stats.cache_hits = CacheHitCount::new(stats.cache_hits.as_u64() + 1);
                return Ok(cached_result);
            }
            let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;
            stats.cache_misses = CacheMissCount::new(stats.cache_misses.as_u64() + 1);
        }

        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Structural validation
        if self.rules.enable_structural_validation {
            self.validate_structure(&request.packet, &mut errors, &mut warnings)?;
        }

        // State validation
        if self.rules.enable_state_validation {
            self.validate_state(&request, &mut errors, &mut warnings)?;
        }

        // Security validation
        if self.rules.enable_security_validation {
            self.validate_security(&request, &mut errors, &mut warnings)?;
        }

        // Timestamp validation
        if self.rules.enable_timestamp_validation {
            self.validate_timestamp(&request.packet, &mut errors, &mut warnings)?;
        }

        // Sequence validation
        if self.rules.enable_sequence_validation {
            self.validate_sequence(&request, &mut errors, &mut warnings)?;
        }

        // Determine result
        let result = if !errors.is_empty() {
            ValidationResult::Invalid { errors }
        } else if !warnings.is_empty() {
            ValidationResult::ValidWithWarnings { warnings }
        } else {
            ValidationResult::Valid
        };

        // Update statistics
        {
            let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;
            match &result {
                ValidationResult::Valid => {
                    stats.valid_packets = PacketCount::new(stats.valid_packets.as_u64() + 1)
                }
                ValidationResult::ValidWithWarnings { .. } => {
                    stats.packets_with_warnings =
                        PacketCount::new(stats.packets_with_warnings.as_u64() + 1)
                }
                ValidationResult::Invalid { errors } => {
                    stats.invalid_packets = PacketCount::new(stats.invalid_packets.as_u64() + 1);
                    for error in errors {
                        let error_type = format!("{:?}", error.error_type);
                        let current_count = stats
                            .errors_by_type
                            .entry(error_type.clone())
                            .or_insert(ErrorCount::new(0));
                        *current_count = ErrorCount::new((current_count.as_u64() + 1) as u32);
                    }
                }
            }
        }

        // Cache result
        if self.rules.enable_caching {
            self.cache_result(&request.packet, result.clone());
        }

        Ok(result)
    }

    /// Validate packet structure
    fn validate_structure(
        &self,
        packet: &dyn BuiltPacket,
        errors: &mut Vec<ValidationError>,
        _warnings: &mut Vec<ValidationWarning>,
    ) -> Result<(), ProtocolError> {
        // Check packet size
        let packet_size = packet.total_size();
        if packet_size > self.rules.max_packet_size.as_usize() {
            errors.push(ValidationError {
                error_type: ErrorType::Structural,
                message: format!(
                    "Packet size {} exceeds maximum {}",
                    packet_size,
                    self.rules.max_packet_size.as_usize()
                ),
                severity: ErrorSeverity::Medium,
            });
        }

        if packet_size < self.rules.min_packet_size.as_usize() {
            errors.push(ValidationError {
                error_type: ErrorType::Structural,
                message: format!(
                    "Packet size {} below minimum {}",
                    packet_size,
                    self.rules.min_packet_size.as_usize()
                ),
                severity: ErrorSeverity::Medium,
            });
        }

        // Check packet type
        if packet.packet_type().is_none() {
            errors.push(ValidationError {
                error_type: ErrorType::Structural,
                message: "Invalid packet type".to_string(),
                severity: ErrorSeverity::High,
            });
        }

        // Check payload length consistency
        let header_payload_length = packet.header().payload_length().as_u16() as usize;
        let actual_payload_length = packet.payload().len();
        if header_payload_length != actual_payload_length {
            errors.push(ValidationError {
                error_type: ErrorType::Structural,
                message: format!(
                    "Payload length mismatch: header says {}, actual {}",
                    header_payload_length.clone(),
                    actual_payload_length
                ),
                severity: ErrorSeverity::High,
            });
        }

        Ok(())
    }

    /// Validate packet state
    fn validate_state(
        &self,
        request: &ValidationRequest,
        errors: &mut Vec<ValidationError>,
        _warnings: &mut Vec<ValidationWarning>,
    ) -> Result<(), ProtocolError> {
        let _packet_type = request.packet.packet_type();

        // Get current connection state
        let _connection_state = self
            .state_manager
            .get_connection_state(request.packet.session_id());

        // Validate state transition
        let state_request = StateTransitionRequest {
            session_id: request.packet.session_id(),
            packet: request.packet.clone(),
            is_local: request.is_local,
        };

        match self.state_manager.process_transition(state_request) {
            Ok(result) => {
                if let super::state::StateTransitionResult::InvalidTransition { reason, .. } =
                    result
                {
                    errors.push(ValidationError {
                        error_type: ErrorType::State,
                        message: format!("Invalid state transition: {}", reason),
                        severity: ErrorSeverity::Medium,
                    });
                }
            }
            Err(e) => {
                errors.push(ValidationError {
                    error_type: ErrorType::State,
                    message: format!("State validation error: {}", e),
                    severity: ErrorSeverity::High,
                });
            }
        }

        Ok(())
    }

    /// Validate packet security
    fn validate_security(
        &self,
        request: &ValidationRequest,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<(), ProtocolError> {
        // Check HMAC size
        let expected_hmac_size = match request.packet.header().hmac_policy() {
            HmacPolicy::Light => 16,
            HmacPolicy::Medium => 24,
            HmacPolicy::Strong => 32,
        };
        let actual_hmac_size = request.packet.hmac().len();

        if actual_hmac_size != expected_hmac_size {
            errors.push(ValidationError {
                error_type: ErrorType::Security,
                message: format!(
                    "HMAC size mismatch: expected {}, got {}",
                    expected_hmac_size, actual_hmac_size
                ),
                severity: ErrorSeverity::High,
            });
        }

        // Check security level requirements
        let packet_type = request.packet.packet_type();
        let required_level = match packet_type {
            PacketType::Syn | PacketType::SynAck | PacketType::Fin => SecurityLevel::High,
            PacketType::Control | PacketType::Management => SecurityLevel::Standard,
            _ => SecurityLevel::Basic,
        };

        if required_level > request.context.required_security_level {
            warnings.push(ValidationWarning {
                warning_type: WarningType::SecuritySkipped,
                message: format!(
                    "Packet requires {:?} security but only {:?} provided",
                    required_level, request.context.required_security_level
                ),
            });
        }

        Ok(())
    }

    /// Validate packet timestamp
    fn validate_timestamp(
        &self,
        packet: &dyn BuiltPacket,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<(), ProtocolError> {
        let now = Timestamp::now().as_u64() / 1_000_000_000; // Convert nanoseconds to seconds
        let packet_timestamp = packet.header().timestamp().as_u64() / 1_000; // Convert millis to seconds
        let window_sec = (self.rules.timestamp_window_sec.as_nanos() / 1_000_000_000) as u64; // Convert nanoseconds to seconds

        // Check if timestamp is too far in the future
        if packet_timestamp > now + 60 {
            // Allow 1 minute clock skew
            errors.push(ValidationError {
                error_type: ErrorType::Timestamp,
                message: "Timestamp is too far in the future".to_string(),
                severity: ErrorSeverity::Medium,
            });
        }

        // Check if timestamp is too old
        if packet_timestamp + window_sec < now {
            errors.push(ValidationError {
                error_type: ErrorType::Timestamp,
                message: "Timestamp is outside valid window".to_string(),
                severity: ErrorSeverity::Medium,
            });
        } else if packet_timestamp + (window_sec / 2) < now {
            warnings.push(ValidationWarning {
                warning_type: WarningType::OldTimestamp,
                message: "Timestamp is old but within window".to_string(),
            });
        }

        Ok(())
    }

    /// Validate packet sequence
    fn validate_sequence(
        &self,
        request: &ValidationRequest,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Result<(), ProtocolError> {
        if let Some((min_seq, max_seq)) = request.context.expected_sequence_range {
            let packet_seq = request.packet.sequence_number().as_u32();

            if packet_seq < min_seq || packet_seq > max_seq {
                errors.push(ValidationError {
                    error_type: ErrorType::Sequence,
                    message: format!(
                        "Sequence number {} outside expected range {}-{}",
                        packet_seq, min_seq, max_seq
                    ),
                    severity: ErrorSeverity::Medium,
                });
            } else if packet_seq != min_seq {
                warnings.push(ValidationWarning {
                    warning_type: WarningType::OutOfOrderSequence,
                    message: format!(
                        "Out of order sequence: got {}, expected {}",
                        packet_seq, min_seq
                    ),
                });
            }
        }

        Ok(())
    }

    /// Check validation cache
    fn check_cache(&self, packet: &dyn BuiltPacket) -> Option<ValidationResult> {
        if let Some(packet_type) = packet.packet_type() {
            let cache_key = ValidationCacheKey {
                session_id: packet.session_id(),
                packet_type,
                sequence_number: packet.sequence_number(),
            };

            let cache = self.validation_cache.read().ok()?;
            if let Some(entry) = cache.get(&cache_key) {
                let cache_timeout = std::time::Duration::from_nanos(
                    self.rules
                        .cache_timeout
                        .as_nanos()
                        .try_into()
                        .unwrap_or(u64::MAX),
                );
                if SystemTime::now()
                    .duration_since(entry.timestamp)
                    .unwrap_or_default()
                    < cache_timeout
                {
                    return Some(entry.result.clone());
                }
            }
        }

        None
    }

    /// Cache validation result
    fn cache_result(&self, packet: &dyn BuiltPacket, result: ValidationResult) {
        if let Some(packet_type) = packet.packet_type() {
            let cache_key = ValidationCacheKey {
                session_id: packet.session_id(),
                packet_type,
                sequence_number: packet.sequence_number(),
            };

            let cache_entry = ValidationCacheEntry {
                result,
                timestamp: SystemTime::now(),
            };

            let mut cache = self
                .validation_cache
                .write()
                .unwrap_or_else(|e| e.into_inner());
            cache.insert(cache_key, cache_entry);

            // Clean up old entries if cache is getting large
            if cache.len() > 10000 {
                let timeout = std::time::Duration::from_nanos(
                    self.rules
                        .cache_timeout
                        .as_nanos()
                        .try_into()
                        .unwrap_or(u64::MAX),
                );
                let now = SystemTime::now();
                cache.retain(|_, entry| {
                    now.duration_since(entry.timestamp).unwrap_or_default() < timeout
                });
            }
        }
    }

    /// Clean up expired cache entries
    pub fn cleanup_cache(&self) -> Result<(), ProtocolError> {
        let timeout = std::time::Duration::from_nanos(
            self.rules
                .cache_timeout
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        let now = SystemTime::now();

        let mut cache = self.validation_cache.write().map_err(|_| lock_poisoned())?;
        cache.retain(|_, entry| now.duration_since(entry.timestamp).unwrap_or_default() < timeout);
        Ok(())
    }

    /// Get validation statistics
    pub fn get_stats(&self) -> Result<ValidationStats, ProtocolError> {
        Ok(self.stats.read().map_err(|_| lock_poisoned())?.clone())
    }

    /// Reset statistics
    pub fn reset_stats(&self) -> Result<(), ProtocolError> {
        let mut stats = self.stats.write().map_err(|_| lock_poisoned())?;
        *stats = ValidationStats {
            total_validations: PacketCount::new(0),
            valid_packets: PacketCount::new(0),
            invalid_packets: PacketCount::new(0),
            packets_with_warnings: PacketCount::new(0),
            cache_hits: CacheHitCount::new(0),
            cache_misses: CacheMissCount::new(0),
            errors_by_type: HashMap::new(),
        };
        Ok(())
    }

    /// Update validation rules
    pub fn update_rules(&mut self, rules: ValidationRules) {
        self.rules = rules;
    }
}
