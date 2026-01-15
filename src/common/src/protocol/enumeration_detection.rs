use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

// Import ALL types from the authoritative consolidated types module
use crate::error::BuckwildError;
use crate::protocol::types::*;

/// Enumeration attack detection engine with progressive rate limiting
#[derive(Debug)]
pub struct EnumerationDetector {
    /// Connection attempt tracking per source IP
    connection_attempts: Arc<RwLock<HashMap<IpAddr, ConnectionAttemptInfo>>>,
    /// Blocked sources with exponential backoff
    blocked_sources: Arc<RwLock<HashMap<IpAddr, BlockInfo>>>,
    /// Configuration parameters
    config: EnumerationConfig,
    /// Statistics for monitoring
    stats: Arc<RwLock<EnumerationStats>>,
}

/// Configuration for enumeration detection
#[derive(Debug, Clone)]
pub struct EnumerationConfig {
    /// Maximum connection attempts per time window
    pub max_attempts_per_window: AttemptCount,
    /// Time window for rate limiting (seconds)
    pub rate_limit_window_seconds: Duration,
    /// Initial block duration (seconds)
    pub initial_block_duration_seconds: Duration,
    /// Maximum block duration (seconds)
    pub max_block_duration_seconds: Duration,
    /// Backoff multiplier for repeated violations
    pub backoff_multiplier: f64,
    /// Threshold for attack pattern detection
    pub attack_pattern_threshold: AttemptCount,
    /// Cleanup interval for expired entries
    pub cleanup_interval_seconds: Duration,
}

/// Information about connection attempts from a source
#[derive(Debug, Clone)]
pub struct ConnectionAttemptInfo {
    /// Number of attempts in current window
    pub attempts_in_window: AttemptCount,
    /// Window start time
    pub window_start: SystemTime,
    /// Total attempts ever
    pub total_attempts: AttemptCount,
    /// Last attempt time
    pub last_attempt: SystemTime,
    /// Pattern analysis data
    pub pattern_data: PatternAnalysisData,
}

/// Data for attack pattern analysis
#[derive(Debug, Clone)]
pub struct PatternAnalysisData {
    /// Intervals between attempts (for pattern detection)
    pub attempt_intervals: Vec<Duration>,
    /// Ports targeted
    pub targeted_ports: Vec<Port>,
    /// Session IDs attempted
    pub attempted_sessions: Vec<SessionId>,
    /// Failure types encountered
    pub failure_types: Vec<String>,
}

/// Information about blocked sources
#[derive(Debug, Clone)]
pub struct BlockInfo {
    /// When the block started
    pub block_start: SystemTime,
    /// Duration of current block
    pub block_duration: Duration,
    /// Number of times this source has been blocked
    pub block_count: BlockCount,
    /// Reason for blocking
    pub block_reason: BlockReason,
}

/// Reason for blocking a source
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Attack pattern detected
    AttackPatternDetected,
    /// Repeated violations
    RepeatedViolations,
    /// Manual block
    ManualBlock,
}

/// Result of enumeration detection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnumerationDetectionResult {
    /// Connection attempt is allowed
    Allowed,
    /// Connection attempt is rate limited
    RateLimited,
    /// Source is temporarily blocked
    Blocked(Duration),
    /// Attack pattern detected
    AttackDetected,
}

/// Statistics for enumeration detection
#[derive(Debug, Clone, Default)]
pub struct EnumerationStats {
    /// Total connection attempts processed
    pub total_attempts: AttemptCount,
    /// Attempts blocked by rate limiting
    pub rate_limited_attempts: AttemptCount,
    /// Sources currently blocked
    pub blocked_sources: SourceCount,
    /// Attack patterns detected
    pub attack_patterns_detected: AttackCount,
    /// False positives (manual unblocks)
    pub false_positives: ErrorCount,
}

impl Default for EnumerationConfig {
    fn default() -> Self {
        Self {
            max_attempts_per_window: AttemptCount::new(10),
            rate_limit_window_seconds: Duration::from_secs(60), // 60 seconds
            initial_block_duration_seconds: Duration::from_secs(300), // 5 minutes
            max_block_duration_seconds: Duration::from_secs(3600), // 1 hour
            backoff_multiplier: 2.0,
            attack_pattern_threshold: AttemptCount::new(50),
            cleanup_interval_seconds: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl EnumerationDetector {
    /// Create a new enumeration detector with default configuration
    pub fn new() -> Self {
        Self::with_config(EnumerationConfig::default())
    }

    /// Create a new enumeration detector with custom configuration
    pub fn with_config(config: EnumerationConfig) -> Self {
        Self {
            connection_attempts: Arc::new(RwLock::new(HashMap::new())),
            blocked_sources: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(EnumerationStats::default())),
        }
    }

    /// Check if a connection attempt should be allowed
    pub fn check_connection_attempt(
        &self,
        source_ip: IpAddr,
        target_port: Port,
        session_id: Option<SessionId>,
        failure_type: Option<String>,
    ) -> Result<EnumerationDetectionResult, BuckwildError> {
        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_attempts = AttemptCount::new(stats.total_attempts.as_u32() + 1);
        }

        // Check if source is currently blocked
        if let Some(remaining_block) = self.check_blocked_source(source_ip)? {
            debug!(
                "Connection attempt from blocked source: {:?}, remaining: {:?}",
                source_ip, remaining_block
            );
            return Ok(EnumerationDetectionResult::Blocked(remaining_block));
        }

        // Update connection attempt tracking
        let should_block =
            self.update_connection_attempts(source_ip, target_port, session_id, failure_type)?;

        if should_block {
            self.block_source(source_ip, BlockReason::RateLimitExceeded)?;

            let mut stats = self.stats.write();
            stats.rate_limited_attempts =
                AttemptCount::new(stats.rate_limited_attempts.as_u32() + 1);

            return Ok(EnumerationDetectionResult::RateLimited);
        }

        // Check for attack patterns
        if self.detect_attack_pattern(source_ip)? {
            self.block_source(source_ip, BlockReason::AttackPatternDetected)?;

            let mut stats = self.stats.write();
            stats.attack_patterns_detected =
                AttackCount::new(stats.attack_patterns_detected.as_u32() + 1);

            warn!("Attack pattern detected from source: {:?}", source_ip);
            return Ok(EnumerationDetectionResult::AttackDetected);
        }

        debug!("Connection attempt allowed from source: {:?}", source_ip);
        Ok(EnumerationDetectionResult::Allowed)
    }

    /// Check if a source is currently blocked
    fn check_blocked_source(&self, source_ip: IpAddr) -> Result<Option<Duration>, BuckwildError> {
        let blocked_sources = self.blocked_sources.read();

        if let Some(block_info) = blocked_sources.get(&source_ip) {
            let current_time = SystemTime::now();
            let elapsed = current_time
                .duration_since(block_info.block_start)
                .map_err(|e| BuckwildError::TimeCalculation(format!("Block duration: {}", e)))?;

            if elapsed < block_info.block_duration {
                let remaining = block_info.block_duration - elapsed;
                return Ok(Some(remaining));
            }
        }

        Ok(None)
    }

    /// Update connection attempt tracking for a source
    fn update_connection_attempts(
        &self,
        source_ip: IpAddr,
        target_port: Port,
        session_id: Option<SessionId>,
        failure_type: Option<String>,
    ) -> Result<bool, BuckwildError> {
        let mut attempts = self.connection_attempts.write();
        let current_time = SystemTime::now();

        let attempt_info = attempts
            .entry(source_ip)
            .or_insert_with(|| ConnectionAttemptInfo {
                attempts_in_window: AttemptCount::new(0),
                window_start: current_time,
                total_attempts: AttemptCount::new(0),
                last_attempt: current_time,
                pattern_data: PatternAnalysisData {
                    attempt_intervals: Vec::new(),
                    targeted_ports: Vec::new(),
                    attempted_sessions: Vec::new(),
                    failure_types: Vec::new(),
                },
            });

        // Check if we need to reset the window
        let window_duration = self.config.rate_limit_window_seconds;
        if current_time
            .duration_since(attempt_info.window_start)
            .map_err(|e| BuckwildError::TimeCalculation(format!("Window duration: {}", e)))?
            > window_duration
        {
            attempt_info.attempts_in_window = AttemptCount::new(0);
            attempt_info.window_start = current_time;
        }

        // Update attempt tracking
        attempt_info.attempts_in_window =
            AttemptCount::new(attempt_info.attempts_in_window.as_u32() + 1);
        attempt_info.total_attempts = AttemptCount::new(attempt_info.total_attempts.as_u32() + 1);

        // Update pattern analysis data
        if let Ok(interval) = current_time.duration_since(attempt_info.last_attempt) {
            attempt_info.pattern_data.attempt_intervals.push(interval);

            // Keep only recent intervals for pattern analysis
            if attempt_info.pattern_data.attempt_intervals.len() > 100 {
                attempt_info.pattern_data.attempt_intervals.remove(0);
            }
        }

        attempt_info.pattern_data.targeted_ports.push(target_port);
        if let Some(session) = session_id {
            attempt_info.pattern_data.attempted_sessions.push(session);
        }
        if let Some(failure) = failure_type {
            attempt_info.pattern_data.failure_types.push(failure);
        }

        attempt_info.last_attempt = current_time;

        // Check if rate limit is exceeded
        let should_block =
            attempt_info.attempts_in_window.as_u32() > self.config.max_attempts_per_window.as_u32();

        if should_block {
            warn!(
                "Rate limit exceeded for source: {:?}, attempts: {}/{}",
                source_ip,
                attempt_info.attempts_in_window.as_u32(),
                self.config.max_attempts_per_window.as_u32()
            )
        }

        Ok(should_block)
    }

    /// Detect attack patterns in connection attempts
    fn detect_attack_pattern(&self, source_ip: IpAddr) -> Result<bool, BuckwildError> {
        let attempts = self.connection_attempts.read();

        if let Some(attempt_info) = attempts.get(&source_ip) {
            // Check total attempt threshold
            if attempt_info.total_attempts.as_u32() > self.config.attack_pattern_threshold.as_u32()
            {
                return Ok(true);
            }

            // Analyze timing patterns (regular intervals suggest automation)
            if self.analyze_timing_pattern(&attempt_info.pattern_data.attempt_intervals) {
                info!(
                    "Regular timing pattern detected from source: {:?}",
                    source_ip
                );
                return Ok(true);
            }

            // Analyze port scanning patterns
            if self.analyze_port_scanning_pattern(&attempt_info.pattern_data.targeted_ports) {
                info!(
                    "Port scanning pattern detected from source: {:?}",
                    source_ip
                );
                return Ok(true);
            }

            // Analyze session enumeration patterns
            if self
                .analyze_session_enumeration_pattern(&attempt_info.pattern_data.attempted_sessions)
            {
                info!(
                    "Session enumeration pattern detected from source: {:?}",
                    source_ip
                );
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Analyze timing patterns for automation detection
    fn analyze_timing_pattern(&self, intervals: &[Duration]) -> bool {
        if intervals.len() < 10 {
            return false;
        }

        // Calculate variance in intervals
        let mean_interval: f64 =
            intervals.iter().map(|d| d.as_millis() as f64).sum::<f64>() / intervals.len() as f64;

        let variance: f64 = intervals
            .iter()
            .map(|d| {
                let diff = d.as_millis() as f64 - mean_interval;
                diff * diff
            })
            .sum::<f64>()
            / intervals.len() as f64;

        let std_dev = variance.sqrt();
        let coefficient_of_variation = std_dev / mean_interval;

        // Low coefficient of variation suggests regular timing (automation)
        coefficient_of_variation < 0.1 && mean_interval < 1000.0 // Less than 1 second intervals
    }

    /// Analyze port scanning patterns
    fn analyze_port_scanning_pattern(&self, ports: &[Port]) -> bool {
        if ports.len() < 20 {
            return false;
        }

        // Check for sequential port scanning
        let mut sequential_count = 0;
        for window in ports.windows(2) {
            if window[1].as_u16() == window[0].as_u16() + 1
                || window[1].as_u16() == window[0].as_u16() - 1
            {
                sequential_count += 1;
            }
        }

        // If more than 50% of attempts are sequential, it's likely port scanning
        (sequential_count as f64 / (ports.len() - 1) as f64) > 0.5
    }

    /// Analyze session enumeration patterns
    fn analyze_session_enumeration_pattern(&self, sessions: &[SessionId]) -> bool {
        if sessions.len() < 10 {
            return false;
        }

        // Check for sequential session ID attempts
        let mut sequential_count = 0;
        for window in sessions.windows(2) {
            if window[1].as_u64() == window[0].as_u64() + 1
                || window[1].as_u64() == window[0].as_u64() - 1
            {
                sequential_count += 1;
            }
        }

        // If more than 30% of session attempts are sequential, it's likely enumeration
        (sequential_count as f64 / (sessions.len() - 1) as f64) > 0.3
    }

    /// Block a source with exponential backoff
    fn block_source(&self, source_ip: IpAddr, reason: BlockReason) -> Result<(), BuckwildError> {
        let mut blocked_sources = self.blocked_sources.write();
        let current_time = SystemTime::now();

        let block_duration = if let Some(existing_block) = blocked_sources.get(&source_ip) {
            // Exponential backoff for repeated violations
            let new_duration = Duration::from_secs(
                (existing_block.block_duration.as_secs() as f64 * self.config.backoff_multiplier)
                    as u64,
            );

            std::cmp::min(new_duration, self.config.max_block_duration_seconds)
        } else {
            self.config.initial_block_duration_seconds
        };

        let block_count = blocked_sources
            .get(&source_ip)
            .map(|b| BlockCount::new((b.block_count.as_u32() + 1) as usize))
            .unwrap_or(BlockCount::new(1));

        blocked_sources.insert(
            source_ip,
            BlockInfo {
                block_start: current_time,
                block_duration,
                block_count,
                block_reason: reason.clone(),
            },
        );

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.blocked_sources = SourceCount::new(blocked_sources.len());
        }

        warn!(
            "Blocked source: {:?}, reason: {:?}, duration: {:?}, count: {}",
            source_ip,
            reason,
            block_duration,
            block_count.as_u32()
        );

        Ok(())
    }

    /// Manually unblock a source (for false positive handling)
    pub fn unblock_source(&self, source_ip: IpAddr) -> Result<bool, BuckwildError> {
        let mut blocked_sources = self.blocked_sources.write();
        let was_blocked = blocked_sources.remove(&source_ip).is_some();

        if was_blocked {
            let mut stats = self.stats.write();
            stats.blocked_sources = SourceCount::new(blocked_sources.len());
            stats.false_positives = ErrorCount::new(stats.false_positives.as_u32() + 1);

            info!("Manually unblocked source: {:?}", source_ip);
        }

        Ok(was_blocked)
    }

    /// Clean up expired blocks and old attempt data
    pub fn cleanup_expired_entries(&self) -> Result<(usize, usize), BuckwildError> {
        let current_time = SystemTime::now();
        let blocks_removed;
        let attempts_removed;

        // Clean up expired blocks
        {
            let mut blocked_sources = self.blocked_sources.write();
            let initial_size = blocked_sources.len();

            blocked_sources.retain(|_, block_info| {
                current_time
                    .duration_since(block_info.block_start)
                    .map(|elapsed| elapsed < block_info.block_duration)
                    .unwrap_or(false)
            });

            blocks_removed = initial_size - blocked_sources.len();

            // Update statistics
            let mut stats = self.stats.write();
            stats.blocked_sources = SourceCount::new(blocked_sources.len());
        }

        // Clean up old attempt data
        {
            let mut attempts = self.connection_attempts.write();
            let cleanup_threshold = self.config.cleanup_interval_seconds * 2;
            let initial_size = attempts.len();

            attempts.retain(|_, attempt_info| {
                current_time
                    .duration_since(attempt_info.last_attempt)
                    .map(|elapsed| elapsed < cleanup_threshold)
                    .unwrap_or(false)
            });

            attempts_removed = initial_size - attempts.len();
        }

        if blocks_removed > 0 || attempts_removed > 0 {
            info!(
                "Cleanup completed: {} expired blocks, {} old attempts",
                blocks_removed, attempts_removed
            );
        }

        Ok((blocks_removed, attempts_removed))
    }

    /// Get current statistics
    pub fn get_stats(&self) -> EnumerationStats {
        self.stats.read().clone()
    }

    /// Get list of currently blocked sources
    pub fn get_blocked_sources(&self) -> Vec<(IpAddr, BlockInfo)> {
        self.blocked_sources
            .read()
            .iter()
            .map(|(ip, info)| (*ip, info.clone()))
            .collect()
    }

    /// Get connection attempt information for a source
    pub fn get_attempt_info(&self, source_ip: IpAddr) -> Option<ConnectionAttemptInfo> {
        self.connection_attempts.read().get(&source_ip).cloned()
    }
}

impl Default for EnumerationDetector {
    fn default() -> Self {
        Self::new()
    }
}
