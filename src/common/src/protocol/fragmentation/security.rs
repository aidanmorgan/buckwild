// Fragment security validation
//
// This module provides security validation for fragmented packets including
// fragment validation, attack detection, and security policy enforcement.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

// Import ALL types from the authoritative consolidated types module
use crate::error::ProtocolError;
use crate::error::{FragmentationError, FragmentationResult};
use crate::protocol::types::*;
use crate::protocol::validation::BuiltPacket;

/// Fragment security engine for validating fragment security
pub struct FragmentSecurityEngine {
    /// Security policies
    policies: FragmentSecurityPolicies,
    /// Attack detection state
    attack_detector: Arc<RwLock<AttackDetector>>,
    /// Statistics
    stats: Arc<RwLock<FragmentSecurityStats>>,
}

/// Fragment security policies
#[derive(Debug, Clone)]
pub struct FragmentSecurityPolicies {
    /// Maximum fragment size allowed
    pub max_fragment_size: FragmentSize,
    /// Maximum fragments per session
    pub max_fragments_per_session: u16,
    /// Fragment timeout in seconds
    pub fragment_timeout_sec: u64,
    /// Enable fragment overlap detection
    pub enable_overlap_detection: bool,
    /// Enable fragment size validation
    pub enable_size_validation: bool,
    /// Enable fragment timing validation
    pub enable_timing_validation: bool,
    /// Enable attack detection
    pub enable_attack_detection: bool,
}

impl Default for FragmentSecurityPolicies {
    fn default() -> Self {
        Self {
            max_fragment_size: FragmentSize::new(1400),
            max_fragments_per_session: 256,
            fragment_timeout_sec: 30,
            enable_overlap_detection: true,
            enable_size_validation: true,
            enable_timing_validation: true,
            enable_attack_detection: true,
        }
    }
}

/// Attack detection for fragment-based attacks
#[derive(Debug)]
struct AttackDetector {
    /// Session fragment counts
    session_fragment_counts: HashMap<SessionId, SessionFragmentState>,
    /// Suspicious activity tracking
    suspicious_sessions: HashMap<SessionId, SuspiciousActivity>,
    /// Attack patterns
    attack_patterns: Vec<AttackPattern>,
}

/// Session fragment state for attack detection
#[derive(Debug)]
struct SessionFragmentState {
    /// Total fragments received
    fragment_count: u32,
    /// Fragments in last minute
    recent_fragments: u32,
    /// Last fragment timestamp
    last_fragment_time: SystemTime,
    /// Fragment size distribution
    size_distribution: Vec<usize>,
}

/// Suspicious activity tracking
#[derive(Debug)]
struct SuspiciousActivity {
    /// Number of violations
    #[allow(dead_code)]
    violation_count: u32,
    /// First violation time
    #[allow(dead_code)]
    first_violation: SystemTime,
    /// Last violation time
    last_violation: SystemTime,
    /// Violation types
    #[allow(dead_code)]
    violation_types: Vec<ViolationType>,
}

/// Types of security violations
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ViolationType {
    /// Fragment too large
    OversizedFragment,
    /// Too many fragments
    ExcessiveFragments,
    /// Fragment overlap detected
    FragmentOverlap,
    /// Timing anomaly
    TimingAnomaly,
    /// Size anomaly
    SizeAnomaly,
}

/// Attack pattern definition
struct AttackPattern {
    /// Pattern name
    name: String,
    /// Detection threshold
    threshold: u32,
    /// Time window for detection
    time_window: Duration,
    /// Pattern matcher
    matcher: Box<dyn Fn(&SessionFragmentState) -> bool + Send + Sync>,
}

impl std::fmt::Debug for AttackPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttackPattern")
            .field("name", &self.name)
            .field("threshold", &self.threshold)
            .field("time_window", &self.time_window)
            .field("matcher", &"<function>")
            .finish()
    }
}

/// Fragment security validation result
#[derive(Debug)]
pub enum SecurityValidationResult {
    /// Fragment is valid
    Valid,
    /// Fragment is suspicious but allowed
    Suspicious { reason: String },
    /// Fragment is rejected
    Rejected { reason: String },
}

/// Fragment security statistics
#[derive(Debug, Clone)]
pub struct FragmentSecurityStats {
    /// Total fragments validated
    pub total_validated: u64,
    /// Valid fragments
    pub valid_fragments: u64,
    /// Suspicious fragments
    pub suspicious_fragments: u64,
    /// Rejected fragments
    pub rejected_fragments: u64,
    /// Attack attempts detected
    pub attack_attempts: u64,
    /// Active suspicious sessions
    pub suspicious_sessions: usize,
}

impl FragmentSecurityEngine {
    /// Create a new fragment security engine
    pub fn new() -> Self {
        Self::with_policies(FragmentSecurityPolicies::default())
    }

    /// Create a new fragment security engine with custom policies
    pub fn with_policies(policies: FragmentSecurityPolicies) -> Self {
        let attack_detector = AttackDetector {
            session_fragment_counts: HashMap::new(),
            suspicious_sessions: HashMap::new(),
            attack_patterns: Self::create_default_attack_patterns(),
        };

        Self {
            policies,
            attack_detector: Arc::new(RwLock::new(attack_detector)),
            stats: Arc::new(RwLock::new(FragmentSecurityStats {
                total_validated: 0,
                valid_fragments: 0,
                suspicious_fragments: 0,
                rejected_fragments: 0,
                attack_attempts: 0,
                suspicious_sessions: 0,
            })),
        }
    }

    /// Validate a fragment for security compliance
    pub fn validate_fragment(
        &self,
        fragment: &dyn BuiltPacket,
    ) -> Result<SecurityValidationResult, ProtocolError> {
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.total_validated += 1;

        // Extract fragment information
        let fragment_info = self.extract_fragment_info(fragment)?;

        // Size validation
        if self.policies.enable_size_validation {
            if let Err(reason) = self.validate_fragment_size(&fragment_info) {
                stats.rejected_fragments += 1;
                return Ok(SecurityValidationResult::Rejected {
                    reason: reason.to_string(),
                });
            }
        }

        // Fragment count validation
        if let Err(reason) = self.validate_fragment_count(&fragment_info) {
            stats.rejected_fragments += 1;
            return Ok(SecurityValidationResult::Rejected {
                reason: reason.to_string(),
            });
        }

        // Timing validation
        if self.policies.enable_timing_validation {
            if let Some(reason) = self.validate_fragment_timing(&fragment_info) {
                stats.suspicious_fragments += 1;
                return Ok(SecurityValidationResult::Suspicious { reason });
            }
        }

        // Attack detection
        if self.policies.enable_attack_detection {
            if let Some(reason) = self.detect_attacks(&fragment_info) {
                stats.attack_attempts += 1;
                stats.rejected_fragments += 1;
                return Ok(SecurityValidationResult::Rejected { reason });
            }
        }

        // Update fragment state
        self.update_fragment_state(&fragment_info);

        stats.valid_fragments += 1;
        Ok(SecurityValidationResult::Valid)
    }

    /// Extract fragment information from packet
    fn extract_fragment_info(
        &self,
        fragment: &dyn BuiltPacket,
    ) -> Result<FragmentInfo, ProtocolError> {
        if !fragment.flags().is_frag() {
            return Err(ProtocolError::fragmentation_error(
                "Packet is not fragmented",
            ));
        }

        let payload = fragment.payload();
        if payload.len() < 8 {
            return Err(ProtocolError::fragmentation_error(
                "Fragment header too small",
            ));
        }

        let fragment_id = FragmentId::new(u16::from_be_bytes([payload[0], payload[1]]));
        let fragment_index = u16::from_be_bytes([payload[2], payload[3]]);
        let total_fragments = u16::from_be_bytes([payload[4], payload[5]]);

        Ok(FragmentInfo {
            session_id: fragment.session_id(),
            fragment_id,
            fragment_index,
            fragment_count: total_fragments,
            fragment_size: FragmentSize::new((payload.len() - 8) as u16), // Exclude fragment header
            timestamp: SystemTime::now(),
        })
    }

    /// Validate fragment size
    fn validate_fragment_size(&self, fragment_info: &FragmentInfo) -> FragmentationResult<()> {
        if fragment_info.fragment_size > self.policies.max_fragment_size {
            return Err(FragmentationError::fragment_too_large(
                fragment_info.fragment_size,
                self.policies.max_fragment_size,
            ));
        }

        // Check for suspiciously small fragments (potential attack)
        if fragment_info.fragment_size < FragmentSize::from_raw(8)
            && fragment_info.fragment_index > 0
        {
            return Err(FragmentationError::fragment_security_violation(
                "Suspiciously small fragment detected",
            ));
        }

        Ok(())
    }

    /// Validate fragment count
    fn validate_fragment_count(&self, fragment_info: &FragmentInfo) -> FragmentationResult<()> {
        if fragment_info.fragment_count > self.policies.max_fragments_per_session {
            return Err(FragmentationError::FragmentCountExceeded {
                count: FragmentCount::new(fragment_info.fragment_count),
                max_count: FragmentCount::new(self.policies.max_fragments_per_session),
            });
        }

        if fragment_info.fragment_index >= fragment_info.fragment_count {
            return Err(FragmentationError::InvalidFragmentIndex {
                index: FragmentIndex::new(fragment_info.fragment_index),
                fragment_count: FragmentCount::new(fragment_info.fragment_count),
            });
        }

        Ok(())
    }

    /// Validate fragment timing
    fn validate_fragment_timing(&self, fragment_info: &FragmentInfo) -> Option<String> {
        let detector = self
            .attack_detector
            .read()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(session_state) = detector
            .session_fragment_counts
            .get(&fragment_info.session_id)
        {
            let time_since_last = fragment_info
                .timestamp
                .duration_since(session_state.last_fragment_time)
                .unwrap_or_default();

            // Check for rapid fragment arrival (potential flood attack)
            if time_since_last < Duration::from_millis(1) {
                return Some("Fragments arriving too rapidly".to_string());
            }

            // Check for fragments arriving too late (potential reassembly timeout attack)
            if time_since_last > Duration::from_secs(self.policies.fragment_timeout_sec) {
                return Some("Fragment arrived after timeout".to_string());
            }
        }

        None
    }

    /// Detect fragment-based attacks
    fn detect_attacks(&self, fragment_info: &FragmentInfo) -> Option<String> {
        let detector = self
            .attack_detector
            .read()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(session_state) = detector
            .session_fragment_counts
            .get(&fragment_info.session_id)
        {
            // Check attack patterns
            for pattern in &detector.attack_patterns {
                if (pattern.matcher)(session_state) {
                    return Some(format!("Attack pattern detected: {}", pattern.name));
                }
            }

            // Check for fragment flood
            if session_state.recent_fragments > 100 {
                return Some("Fragment flood detected".to_string());
            }
        }

        None
    }

    /// Update fragment state for session
    fn update_fragment_state(&self, fragment_info: &FragmentInfo) {
        let mut detector = self
            .attack_detector
            .write()
            .unwrap_or_else(|e| e.into_inner());

        let session_state = detector
            .session_fragment_counts
            .entry(fragment_info.session_id.clone())
            .or_insert_with(|| SessionFragmentState {
                fragment_count: 0,
                recent_fragments: 0,
                last_fragment_time: SystemTime::now(),
                size_distribution: Vec::new(),
            });

        session_state.fragment_count += 1;
        session_state.recent_fragments += 1;
        session_state.last_fragment_time = fragment_info.timestamp;
        session_state
            .size_distribution
            .push(fragment_info.fragment_size.as_usize());

        // Reset recent counter if enough time has passed
        if fragment_info
            .timestamp
            .duration_since(session_state.last_fragment_time)
            .unwrap_or_default()
            > Duration::from_secs(60)
        {
            session_state.recent_fragments = 1;
        }
    }

    /// Create default attack patterns
    fn create_default_attack_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Fragment Size Anomaly".to_string(),
                threshold: 10,
                time_window: Duration::from_secs(60),
                matcher: Box::new(|state| {
                    // Detect if all fragments are unusually small or large
                    if state.size_distribution.len() > 10 {
                        let avg_size: f64 = state.size_distribution.iter().sum::<usize>() as f64
                            / state.size_distribution.len() as f64;
                        !(10.0..=1300.0).contains(&avg_size)
                    } else {
                        false
                    }
                }),
            },
            AttackPattern {
                name: "Fragment Flood".to_string(),
                threshold: 100,
                time_window: Duration::from_secs(10),
                matcher: Box::new(|state| state.recent_fragments > 100),
            },
        ]
    }

    /// Clean up expired session states
    pub fn cleanup_expired_states(&self) {
        let timeout = Duration::from_secs(self.policies.fragment_timeout_sec * 2);
        let now = SystemTime::now();

        let mut detector = self
            .attack_detector
            .write()
            .unwrap_or_else(|e| e.into_inner());

        detector.session_fragment_counts.retain(|_, state| {
            now.duration_since(state.last_fragment_time)
                .unwrap_or_default()
                < timeout
        });

        detector.suspicious_sessions.retain(|_, activity| {
            now.duration_since(activity.last_violation)
                .unwrap_or_default()
                < timeout
        });

        // Update stats
        let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.suspicious_sessions = detector.suspicious_sessions.len();
    }

    /// Get security statistics
    pub fn get_stats(&self) -> FragmentSecurityStats {
        self.stats.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Update security policies
    pub fn update_policies(&mut self, policies: FragmentSecurityPolicies) {
        self.policies = policies;
    }
}

impl Default for FragmentSecurityEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Fragment information for security validation
#[derive(Debug, Clone)]
struct FragmentInfo {
    session_id: SessionId,
    #[allow(dead_code)]
    fragment_id: FragmentId,
    fragment_index: u16,
    fragment_count: u16,
    fragment_size: FragmentSize,
    timestamp: SystemTime,
}
