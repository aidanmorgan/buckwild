// Replay attack pattern detection
//
// This module detects systematic replay attack attempts by tracking replay frequency
// and emitting security alerts when thresholds are exceeded.

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

use crate::error::SecurityError;
use crate::protocol::types::*;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Result type for pattern detector operations
pub type PatternDetectorResult<T> = Result<T, SecurityError>;

/// Security alert levels for replay patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertLevel {
    /// Warning: Elevated replay attempts detected
    Warning,
    /// Alert: High volume of replay attempts
    Alert,
    /// Block: Sustained replay attack pattern detected
    Block,
}

impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warning => write!(f, "WARNING"),
            Self::Alert => write!(f, "ALERT"),
            Self::Block => write!(f, "BLOCK"),
        }
    }
}

/// Security alert for replay pattern detection
#[derive(Debug, Clone)]
pub struct SecurityAlert {
    /// Alert level
    pub level: AlertLevel,

    /// Source session that triggered the alert
    pub session_id: SessionId,

    /// Number of replay attempts detected
    pub replay_count: u64,

    /// Time window in which replays occurred
    pub window_duration: Duration,

    /// Timestamp when alert was generated
    pub timestamp: Instant,

    /// Additional context
    pub message: String,
}

/// Configuration for replay pattern detection
#[derive(Debug, Clone)]
pub struct PatternDetectorConfig {
    /// Warning threshold: replays in 1 second
    pub warning_threshold: u64,
    pub warning_window: Duration,

    /// Alert threshold: replays in 10 seconds
    pub alert_threshold: u64,
    pub alert_window: Duration,

    /// Block threshold: replays in 60 seconds
    pub block_threshold: u64,
    pub block_window: Duration,

    /// Duration to track replay history per session
    pub history_retention: Duration,

    /// Maximum number of sessions to track
    pub max_tracked_sessions: usize,
}

impl Default for PatternDetectorConfig {
    fn default() -> Self {
        Self {
            warning_threshold: 10,
            warning_window: Duration::from_secs(1),

            alert_threshold: 100,
            alert_window: Duration::from_secs(10),

            block_threshold: 1000,
            block_window: Duration::from_secs(60),

            history_retention: Duration::from_secs(300), // 5 minutes
            max_tracked_sessions: 10000,
        }
    }
}

/// Replay attempt record
#[derive(Debug, Clone)]
struct ReplayAttempt {
    /// When the replay was detected
    timestamp: Instant,
}

/// Per-session replay tracking
#[derive(Debug)]
struct SessionReplayState {
    /// Recent replay attempts
    replay_attempts: VecDeque<ReplayAttempt>,

    /// Total replay count for this session
    total_replays: u64,

    /// Last alert level triggered
    last_alert: Option<AlertLevel>,

    /// Time of last alert
    last_alert_time: Option<Instant>,

    /// Session creation time
    created_at: Instant,
}

impl SessionReplayState {
    /// Create new session state
    fn new() -> Self {
        Self {
            replay_attempts: VecDeque::new(),
            total_replays: 0,
            last_alert: None,
            last_alert_time: None,
            created_at: Instant::now(),
        }
    }

    /// Record a replay attempt
    fn record_replay(&mut self, _sequence: SequenceNumber) {
        let attempt = ReplayAttempt {
            timestamp: Instant::now(),
        };

        self.replay_attempts.push_back(attempt);
        self.total_replays += 1;
    }

    /// Clean up old replay attempts outside retention window
    fn cleanup_old_attempts(&mut self, retention: Duration) {
        let now = Instant::now();

        while let Some(attempt) = self.replay_attempts.front() {
            if now.duration_since(attempt.timestamp) > retention {
                self.replay_attempts.pop_front();
            } else {
                break;
            }
        }
    }

    /// Count replays within a time window
    fn count_replays_in_window(&self, window: Duration) -> u64 {
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(self.created_at);

        self.replay_attempts
            .iter()
            .filter(|attempt| attempt.timestamp >= cutoff)
            .count() as u64
    }

    /// Update last alert
    fn update_alert(&mut self, level: AlertLevel) {
        self.last_alert = Some(level);
        self.last_alert_time = Some(Instant::now());
    }
}

/// Type alias for alert callback
type AlertCallback = Box<dyn Fn(&SecurityAlert) + Send + Sync>;

/// Replay pattern detector
pub struct ReplayPatternDetector {
    /// Configuration
    config: PatternDetectorConfig,

    /// Per-session state
    sessions: HashMap<SessionId, SessionReplayState>,

    /// Alert callback (optional)
    alert_callback: Option<AlertCallback>,
}

impl ReplayPatternDetector {
    /// Create a new pattern detector with default configuration
    pub fn new() -> Self {
        Self::with_config(PatternDetectorConfig::default())
    }

    /// Create a new pattern detector with custom configuration
    pub fn with_config(config: PatternDetectorConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            alert_callback: None,
        }
    }

    /// Set alert callback
    pub fn set_alert_callback<F>(&mut self, callback: F)
    where
        F: Fn(&SecurityAlert) + Send + Sync + 'static,
    {
        self.alert_callback = Some(Box::new(callback));
    }

    /// Record a replay attempt and check for patterns
    pub fn record_replay(
        &mut self,
        session_id: SessionId,
        sequence: SequenceNumber,
    ) -> PatternDetectorResult<Option<SecurityAlert>> {
        // Get or create session state and record the replay
        {
            let session_state = self
                .sessions
                .entry(session_id.clone())
                .or_insert_with(SessionReplayState::new);

            // Record the replay
            session_state.record_replay(sequence);

            // Clean up old attempts
            session_state.cleanup_old_attempts(self.config.history_retention);
        }

        // Check thresholds and generate alerts (must get mutable borrow in separate scope)
        let alert = if let Some(session_state) = self.sessions.get_mut(&session_id) {
            // Call check_thresholds which will update session_state.last_alert
            // This requires splitting into a method that doesn't borrow self
            Self::check_thresholds_static(&self.config, session_id.clone(), session_state)?
        } else {
            return Err(SecurityError::internal_error("Session disappeared"));
        };

        // Invoke callback if alert was generated
        if let (Some(ref alert), Some(ref callback)) =
            (alert.as_ref(), self.alert_callback.as_ref())
        {
            callback(alert);
        }

        // Enforce session limits
        self.enforce_session_limits();

        Ok(alert)
    }

    /// Static version of check_thresholds to avoid borrowing self
    fn check_thresholds_static(
        config: &PatternDetectorConfig,
        session_id: SessionId,
        session_state: &mut SessionReplayState,
    ) -> PatternDetectorResult<Option<SecurityAlert>> {
        // Count replays in each window
        let warning_count = session_state.count_replays_in_window(config.warning_window);
        let alert_count = session_state.count_replays_in_window(config.alert_window);
        let block_count = session_state.count_replays_in_window(config.block_window);

        // Check block threshold (most severe)
        if block_count >= config.block_threshold {
            session_state.update_alert(AlertLevel::Block);
            return Ok(Some(SecurityAlert {
                level: AlertLevel::Block,
                session_id,
                replay_count: block_count,
                window_duration: config.block_window,
                timestamp: Instant::now(),
                message: format!(
                    "Sustained replay attack: {} replays in {} seconds",
                    block_count,
                    config.block_window.as_secs()
                ),
            }));
        }

        // Check alert threshold
        if alert_count >= config.alert_threshold {
            if session_state.last_alert != Some(AlertLevel::Alert) {
                session_state.update_alert(AlertLevel::Alert);
                return Ok(Some(SecurityAlert {
                    level: AlertLevel::Alert,
                    session_id,
                    replay_count: alert_count,
                    window_duration: config.alert_window,
                    timestamp: Instant::now(),
                    message: format!(
                        "High volume replay attack: {} replays in {} seconds",
                        alert_count,
                        config.alert_window.as_secs()
                    ),
                }));
            }
        }

        // Check warning threshold
        if warning_count >= config.warning_threshold {
            if session_state.last_alert.is_none() {
                session_state.update_alert(AlertLevel::Warning);
                return Ok(Some(SecurityAlert {
                    level: AlertLevel::Warning,
                    session_id,
                    replay_count: warning_count,
                    window_duration: config.warning_window,
                    timestamp: Instant::now(),
                    message: format!(
                        "Replay attack detected: {} replays in {} seconds",
                        warning_count,
                        config.warning_window.as_secs()
                    ),
                }));
            }
        }

        Ok(None)
    }

    /// Enforce session tracking limits
    fn enforce_session_limits(&mut self) {
        if self.sessions.len() <= self.config.max_tracked_sessions {
            return;
        }

        // Collect session IDs to remove (oldest first)
        let remove_count = self.sessions.len() - self.config.max_tracked_sessions;
        let mut sessions_vec: Vec<_> = self
            .sessions
            .iter()
            .map(|(id, state)| (id.clone(), state.created_at))
            .collect();
        sessions_vec.sort_by_key(|(_, created)| *created);

        let to_remove: Vec<_> = sessions_vec
            .iter()
            .take(remove_count)
            .map(|(id, _)| id.clone())
            .collect();

        // Remove sessions
        for session_id in to_remove {
            self.sessions.remove(&session_id);
        }
    }

    /// Reset session state (for testing or after quiet period)
    pub fn reset_session(&mut self, session_id: SessionId) {
        self.sessions.remove(&session_id);
    }

    /// Get session statistics
    pub fn get_session_stats(&self, session_id: SessionId) -> Option<(u64, Option<AlertLevel>)> {
        self.sessions
            .get(&session_id)
            .map(|state| (state.total_replays, state.last_alert))
    }

    /// Get total statistics across all sessions
    pub fn get_total_stats(&self) -> (usize, u64) {
        let session_count = self.sessions.len();
        let total_replays = self
            .sessions
            .values()
            .map(|state| state.total_replays)
            .sum();
        (session_count, total_replays)
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Instant::now();
        let initial_count = self.sessions.len();

        self.sessions.retain(|_, state| {
            now.duration_since(state.created_at) < self.config.history_retention
                || !state.replay_attempts.is_empty()
        });

        initial_count - self.sessions.len()
    }

    /// Update configuration
    pub fn update_config(&mut self, config: PatternDetectorConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &PatternDetectorConfig {
        &self.config
    }
}

impl Default for ReplayPatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_session_id(id: u64) -> SessionId {
        SessionId::new(id)
    }

    fn create_sequence(seq: u32) -> SequenceNumber {
        SequenceNumber::new(seq)
    }

    #[test]
    fn test_normal_traffic_no_alerts() {
        let mut detector = ReplayPatternDetector::new();
        let session = create_session_id(1);

        // Record a few unique packets (not replays in real scenario)
        // In this test we're simulating that no replays trigger alerts
        for i in 0..5 {
            let result = detector.record_replay(session.clone(), create_sequence(i));
            assert!(result.is_ok());
            let alert = result.unwrap();
            assert!(alert.is_none(), "No alert expected for low replay count");
        }
    }

    #[test]
    fn test_warning_threshold() {
        let mut detector = ReplayPatternDetector::new();
        let session = create_session_id(1);

        // Record exactly 10 replays to trigger warning
        let mut last_alert = None;
        for i in 0..10 {
            let result = detector.record_replay(session.clone(), create_sequence(i));
            assert!(result.is_ok());
            if let Some(alert) = result.unwrap() {
                last_alert = Some(alert);
            }
        }

        // Verify warning was triggered
        assert!(last_alert.is_some());
        let alert = last_alert.unwrap();
        assert_eq!(alert.level, AlertLevel::Warning);
        assert_eq!(alert.replay_count, 10);
    }

    #[test]
    fn test_alert_threshold() {
        let mut detector = ReplayPatternDetector::new();
        let session = create_session_id(1);

        // Record 100 replays to trigger alert
        let mut last_alert = None;
        for i in 0..100 {
            let result = detector.record_replay(session.clone(), create_sequence(i));
            assert!(result.is_ok());
            if let Some(alert) = result.unwrap() {
                last_alert = Some(alert);
            }
        }

        // Verify alert was triggered
        assert!(last_alert.is_some());
        let alert = last_alert.unwrap();
        assert_eq!(alert.level, AlertLevel::Alert);
        assert_eq!(alert.replay_count, 100);
    }

    #[test]
    fn test_block_threshold() {
        let mut detector = ReplayPatternDetector::new();
        let session = create_session_id(1);

        // Record 1000 replays to trigger block
        let mut last_alert = None;
        for i in 0..1000 {
            let result = detector.record_replay(session.clone(), create_sequence(i));
            assert!(result.is_ok());
            if let Some(alert) = result.unwrap() {
                last_alert = Some(alert);
            }
        }

        // Verify block was triggered
        assert!(last_alert.is_some());
        let alert = last_alert.unwrap();
        assert_eq!(alert.level, AlertLevel::Block);
        assert_eq!(alert.replay_count, 1000);
    }

    #[test]
    fn test_counter_reset_after_quiet_period() {
        let config = PatternDetectorConfig {
            warning_threshold: 10,
            warning_window: Duration::from_millis(100),
            alert_threshold: 100,
            alert_window: Duration::from_secs(1),
            block_threshold: 1000,
            block_window: Duration::from_secs(10),
            history_retention: Duration::from_millis(200),
            max_tracked_sessions: 100,
        };

        let mut detector = ReplayPatternDetector::with_config(config);
        let session = create_session_id(1);

        // Record 10 replays to trigger warning
        for i in 0..10 {
            let _ = detector.record_replay(session.clone(), create_sequence(i));
        }

        // Verify warning was triggered
        let (total, alert) = detector.get_session_stats(session.clone()).unwrap();
        assert_eq!(total, 10);
        assert_eq!(alert, Some(AlertLevel::Warning));

        // Wait for history retention to expire
        std::thread::sleep(Duration::from_millis(250));

        // Clean up expired entries
        let session_state = detector.sessions.get_mut(&session).unwrap();
        session_state.cleanup_old_attempts(detector.config.history_retention);

        // Verify counters reset (attempts cleared but total remains)
        let count_in_window = session_state.count_replays_in_window(Duration::from_millis(100));
        assert_eq!(
            count_in_window, 0,
            "Counters should be reset after quiet period"
        );
    }

    #[test]
    fn test_session_statistics() {
        let mut detector = ReplayPatternDetector::new();
        let session = create_session_id(1);

        // Record some replays
        for i in 0..50 {
            let _ = detector.record_replay(session.clone(), create_sequence(i));
        }

        // Get session stats
        let stats = detector.get_session_stats(session.clone());
        assert!(stats.is_some());
        let (total, _) = stats.unwrap();
        assert_eq!(total, 50);

        // Get total stats
        let (session_count, total_replays) = detector.get_total_stats();
        assert_eq!(session_count, 1);
        assert_eq!(total_replays, 50);
    }

    #[test]
    fn test_alert_callback() {
        use std::sync::{Arc, Mutex};

        let mut detector = ReplayPatternDetector::new();
        let alerts = Arc::new(Mutex::new(Vec::new()));
        let alerts_clone = alerts.clone();

        // Set up callback to capture alerts
        detector.set_alert_callback(move |alert| {
            if let Ok(mut alerts) = alerts_clone.lock() {
                alerts.push(alert.clone());
            }
        });

        let session = create_session_id(1);

        // Trigger warning
        for i in 0..10 {
            let _ = detector.record_replay(session.clone(), create_sequence(i));
        }

        // Verify callback was invoked
        let captured_alerts = alerts.lock().unwrap();
        assert!(!captured_alerts.is_empty());
        assert_eq!(captured_alerts[0].level, AlertLevel::Warning);
    }
}
