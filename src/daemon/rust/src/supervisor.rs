use std::time::Duration;
use tracing::{debug, info, warn};

/// Lightweight supervisor for component restart management
///
/// Provides exponential backoff and restart limiting for individual components.
/// This is a simpler alternative to the actor-based `DaemonSupervisor` for
/// components that manage their own lifecycle.
///
/// Typical usage pattern:
/// 1. Create supervisor with `Supervisor::new(max_restarts)`
/// 2. In a loop, attempt to run your component
/// 3. On success, call `reset()` to clear the restart count
/// 4. On failure, check `should_restart()` - if true, wait for `backoff_delay()` then retry
/// 5. If `should_restart()` returns false, the max restart limit has been reached
pub struct Supervisor {
    /// Maximum restart attempts before giving up
    max_restarts: u32,
    /// Current restart count
    restart_count: u32,
    /// Backoff multiplier (exponential)
    backoff_ms: u64,
    /// Initial backoff in milliseconds
    initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds
    max_backoff_ms: u64,
}

impl Supervisor {
    /// Create a new supervisor with the specified maximum restart attempts
    ///
    /// Uses default backoff parameters:
    /// - Initial backoff: 100ms
    /// - Max backoff: 30s
    /// - Multiplier: 2x (exponential)
    ///
    /// # Arguments
    ///
    /// * `max_restarts` - Maximum number of restart attempts before giving up
    pub fn new(max_restarts: u32) -> Self {
        Self {
            max_restarts,
            restart_count: 0,
            backoff_ms: 100,
            initial_backoff_ms: 100,
            max_backoff_ms: 30_000,
        }
    }

    /// Create a supervisor with custom backoff parameters
    ///
    /// # Arguments
    ///
    /// * `max_restarts` - Maximum number of restart attempts
    /// * `initial_backoff_ms` - Initial backoff delay in milliseconds
    /// * `max_backoff_ms` - Maximum backoff delay in milliseconds
    pub fn with_backoff(max_restarts: u32, initial_backoff_ms: u64, max_backoff_ms: u64) -> Self {
        Self {
            max_restarts,
            restart_count: 0,
            backoff_ms: initial_backoff_ms,
            initial_backoff_ms,
            max_backoff_ms,
        }
    }

    /// Check if component should be restarted
    ///
    /// Returns `true` if the restart count is below the maximum limit.
    /// Each call to this method increments the restart count.
    ///
    /// # Returns
    ///
    /// * `true` - Component should be restarted
    /// * `false` - Maximum restart limit reached, do not restart
    pub fn should_restart(&mut self) -> bool {
        if self.restart_count >= self.max_restarts {
            warn!(
                restart_count = self.restart_count,
                max_restarts = self.max_restarts,
                "Maximum restart limit reached"
            );
            return false;
        }

        self.restart_count += 1;
        debug!(
            restart_count = self.restart_count,
            max_restarts = self.max_restarts,
            "Restart approved"
        );
        true
    }

    /// Reset restart counter (on successful operation)
    ///
    /// Call this when the component completes a successful operation cycle.
    /// Resets both the restart count and backoff delay to initial values.
    pub fn reset(&mut self) {
        if self.restart_count > 0 {
            info!(
                previous_restart_count = self.restart_count,
                "Successful operation, resetting supervisor"
            );
        }
        self.restart_count = 0;
        self.backoff_ms = self.initial_backoff_ms;
    }

    /// Get current backoff delay
    ///
    /// Returns the current backoff duration based on the restart count.
    /// The backoff increases exponentially (2x) with each restart, up to
    /// the configured maximum.
    ///
    /// Call this after `should_restart()` returns `true` to get the delay
    /// before attempting the restart.
    ///
    /// # Returns
    ///
    /// Duration to wait before next restart attempt
    pub fn backoff_delay(&mut self) -> Duration {
        let current_backoff = self.backoff_ms;

        self.backoff_ms = (self.backoff_ms * 2).min(self.max_backoff_ms);

        debug!(
            current_backoff_ms = current_backoff,
            next_backoff_ms = self.backoff_ms,
            restart_count = self.restart_count,
            "Calculated exponential backoff"
        );

        Duration::from_millis(current_backoff)
    }

    /// Get current restart count
    ///
    /// Returns the number of restarts that have occurred since creation
    /// or the last reset.
    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    /// Get maximum restart limit
    pub fn max_restarts(&self) -> u32 {
        self.max_restarts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_creation() {
        let supervisor = Supervisor::new(5);
        assert_eq!(supervisor.max_restarts(), 5);
        assert_eq!(supervisor.restart_count(), 0);
    }

    #[test]
    fn test_supervisor_with_custom_backoff() {
        let supervisor = Supervisor::with_backoff(3, 50, 10_000);
        assert_eq!(supervisor.max_restarts(), 3);
        assert_eq!(supervisor.initial_backoff_ms, 50);
        assert_eq!(supervisor.max_backoff_ms, 10_000);
    }

    #[test]
    fn test_should_restart_within_limit() {
        let mut supervisor = Supervisor::new(3);

        assert!(supervisor.should_restart());
        assert_eq!(supervisor.restart_count(), 1);

        assert!(supervisor.should_restart());
        assert_eq!(supervisor.restart_count(), 2);

        assert!(supervisor.should_restart());
        assert_eq!(supervisor.restart_count(), 3);
    }

    #[test]
    fn test_should_restart_exceeds_limit() {
        let mut supervisor = Supervisor::new(2);

        assert!(supervisor.should_restart());
        assert!(supervisor.should_restart());
        assert!(!supervisor.should_restart());
        assert_eq!(supervisor.restart_count(), 2);
    }

    #[test]
    fn test_exponential_backoff() {
        let mut supervisor = Supervisor::with_backoff(5, 100, 10_000);

        let delay1 = supervisor.backoff_delay();
        assert_eq!(delay1, Duration::from_millis(100));

        let delay2 = supervisor.backoff_delay();
        assert_eq!(delay2, Duration::from_millis(200));

        let delay3 = supervisor.backoff_delay();
        assert_eq!(delay3, Duration::from_millis(400));

        let delay4 = supervisor.backoff_delay();
        assert_eq!(delay4, Duration::from_millis(800));
    }

    #[test]
    fn test_backoff_caps_at_maximum() {
        let mut supervisor = Supervisor::with_backoff(10, 100, 500);

        supervisor.backoff_delay();
        supervisor.backoff_delay();
        supervisor.backoff_delay();
        let delay = supervisor.backoff_delay();
        assert_eq!(delay, Duration::from_millis(500));

        let delay = supervisor.backoff_delay();
        assert_eq!(delay, Duration::from_millis(500));
    }

    #[test]
    fn test_reset_clears_state() {
        let mut supervisor = Supervisor::new(5);

        supervisor.should_restart();
        supervisor.should_restart();
        supervisor.backoff_delay();

        assert_eq!(supervisor.restart_count(), 2);

        supervisor.reset();

        assert_eq!(supervisor.restart_count(), 0);
        assert_eq!(supervisor.backoff_ms, supervisor.initial_backoff_ms);
    }

    #[test]
    fn test_reset_backoff_after_successful_operation() {
        let mut supervisor = Supervisor::with_backoff(5, 100, 10_000);

        supervisor.backoff_delay();
        supervisor.backoff_delay();
        assert_eq!(supervisor.backoff_ms, 400);

        supervisor.reset();
        assert_eq!(supervisor.backoff_ms, 100);

        let delay = supervisor.backoff_delay();
        assert_eq!(delay, Duration::from_millis(100));
    }

    #[test]
    fn test_full_restart_cycle() {
        let mut supervisor = Supervisor::new(3);

        for i in 1..=3 {
            assert!(supervisor.should_restart());
            assert_eq!(supervisor.restart_count(), i);
            let _delay = supervisor.backoff_delay();
        }

        assert!(!supervisor.should_restart());
    }

    #[test]
    fn test_restart_after_reset() {
        let mut supervisor = Supervisor::new(2);

        assert!(supervisor.should_restart());
        assert!(supervisor.should_restart());
        assert!(!supervisor.should_restart());

        supervisor.reset();

        assert!(supervisor.should_restart());
        assert!(supervisor.should_restart());
        assert!(!supervisor.should_restart());
    }

    #[test]
    fn test_default_backoff_parameters() {
        let supervisor = Supervisor::new(3);
        assert_eq!(supervisor.initial_backoff_ms, 100);
        assert_eq!(supervisor.max_backoff_ms, 30_000);
    }

    #[test]
    fn test_backoff_sequence() {
        let mut supervisor = Supervisor::with_backoff(10, 100, 100_000);

        let expected_delays = vec![100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 51200];

        for expected_ms in expected_delays {
            let delay = supervisor.backoff_delay();
            assert_eq!(delay, Duration::from_millis(expected_ms));
        }
    }

    #[test]
    fn test_zero_max_restarts() {
        let mut supervisor = Supervisor::new(0);
        assert!(!supervisor.should_restart());
        assert_eq!(supervisor.restart_count(), 0);
    }
}
