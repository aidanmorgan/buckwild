use std::time::Duration;

/// Lightweight supervisor for component restart management
pub struct Supervisor {
    max_restarts: u32,
    restart_count: u32,
    backoff_ms: u64,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
}

impl Supervisor {
    pub fn new(max_restarts: u32) -> Self {
        Self {
            max_restarts,
            restart_count: 0,
            backoff_ms: 100,
            initial_backoff_ms: 100,
            max_backoff_ms: 30_000,
        }
    }

    pub fn with_backoff(max_restarts: u32, initial_backoff_ms: u64, max_backoff_ms: u64) -> Self {
        Self {
            max_restarts,
            restart_count: 0,
            backoff_ms: initial_backoff_ms,
            initial_backoff_ms,
            max_backoff_ms,
        }
    }

    pub fn should_restart(&mut self) -> bool {
        if self.restart_count >= self.max_restarts {
            return false;
        }

        self.restart_count += 1;
        true
    }

    pub fn reset(&mut self) {
        self.restart_count = 0;
        self.backoff_ms = self.initial_backoff_ms;
    }

    pub fn backoff_delay(&mut self) -> Duration {
        let current_backoff = self.backoff_ms;
        self.backoff_ms = (self.backoff_ms * 2).min(self.max_backoff_ms);
        Duration::from_millis(current_backoff)
    }

    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    pub fn max_restarts(&self) -> u32 {
        self.max_restarts
    }
}

#[test]
fn test_max_restarts_stops_after_limit() {
    let mut supervisor = Supervisor::new(3);

    assert!(supervisor.should_restart());
    assert!(supervisor.should_restart());
    assert!(supervisor.should_restart());
    assert!(!supervisor.should_restart());
    assert_eq!(supervisor.restart_count(), 3);
}

#[test]
fn test_exponential_backoff_increases_delay() {
    let mut supervisor = Supervisor::with_backoff(5, 100, 10_000);

    let delay1 = supervisor.backoff_delay();
    assert_eq!(delay1, Duration::from_millis(100));

    let delay2 = supervisor.backoff_delay();
    assert_eq!(delay2, Duration::from_millis(200));

    let delay3 = supervisor.backoff_delay();
    assert_eq!(delay3, Duration::from_millis(400));
}

#[test]
fn test_reset_clears_counter_and_backoff() {
    let mut supervisor = Supervisor::new(5);

    supervisor.should_restart();
    supervisor.should_restart();
    supervisor.backoff_delay();
    supervisor.backoff_delay();

    assert_eq!(supervisor.restart_count(), 2);

    supervisor.reset();

    assert_eq!(supervisor.restart_count(), 0);
    let delay = supervisor.backoff_delay();
    assert_eq!(delay, Duration::from_millis(100));
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
