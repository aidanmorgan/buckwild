//! Clock trait for time abstraction
//!
//! This module provides the Clock trait for abstracting time operations,
//! enabling time-travel in tests via mock implementations.

use crate::protocol::types::Timestamp;
use std::time::Duration;

/// Trait for time operations
///
/// This trait defines the interface for time-related operations,
/// enabling dependency injection of time sources for testing.
#[async_trait::async_trait]
pub trait Clock: Send + Sync {
    /// Get the current timestamp
    ///
    /// Returns a `Timestamp` representing the current time.
    /// In production, this uses the system clock.
    /// In tests, this can return a controllable value.
    fn now(&self) -> Timestamp;

    /// Sleep for the specified duration
    ///
    /// Asynchronously sleeps for the given duration.
    /// In production, this uses tokio::time::sleep.
    /// In tests, this can advance mock time instantly.
    async fn sleep(&self, duration: Duration);
}

/// System clock implementation using real time
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[async_trait::async_trait]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Mock clock for testing with controllable time
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct MockClock {
    current_time: std::sync::Arc<std::sync::Mutex<Timestamp>>,
}

#[cfg(test)]
impl MockClock {
    /// Create a new mock clock starting at the given timestamp
    pub fn new(start_time: Timestamp) -> Self {
        Self {
            current_time: std::sync::Arc::new(std::sync::Mutex::new(start_time)),
        }
    }

    /// Create a mock clock starting at the current system time
    pub fn now() -> Self {
        Self::new(Timestamp::now())
    }

    /// Advance the clock by the specified duration
    pub fn advance(&self, duration: Duration) {
        let mut time = self.current_time.lock().unwrap();
        *time = *time + duration.as_nanos() as u64;
    }

    /// Set the clock to a specific timestamp
    pub fn set(&self, timestamp: Timestamp) {
        let mut time = self.current_time.lock().unwrap();
        *time = timestamp;
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl Clock for MockClock {
    fn now(&self) -> Timestamp {
        *self.current_time.lock().unwrap()
    }

    async fn sleep(&self, duration: Duration) {
        // Mock sleep advances time instantly
        self.advance(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_system_clock_now() {
        let clock = SystemClock;
        let t1 = clock.now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let t2 = clock.now();
        assert!(t2 > t1, "Time should advance");
    }

    #[tokio::test]
    async fn test_mock_clock_now() {
        let start = Timestamp::from_millis(1000);
        let clock = MockClock::new(start);
        assert_eq!(clock.now(), start);
    }

    #[tokio::test]
    async fn test_mock_clock_advance() {
        let start = Timestamp::from_millis(1000);
        let clock = MockClock::new(start);

        clock.advance(Duration::from_millis(500));
        assert_eq!(clock.now(), Timestamp::from_millis(1500));

        clock.advance(Duration::from_secs(1));
        assert_eq!(clock.now(), Timestamp::from_millis(2500));
    }

    #[tokio::test]
    async fn test_mock_clock_set() {
        let clock = MockClock::new(Timestamp::from_millis(1000));

        clock.set(Timestamp::from_millis(5000));
        assert_eq!(clock.now(), Timestamp::from_millis(5000));
    }

    #[tokio::test]
    async fn test_mock_clock_sleep() {
        let clock = MockClock::new(Timestamp::from_millis(1000));

        clock.sleep(Duration::from_millis(100)).await;
        assert_eq!(clock.now(), Timestamp::from_millis(1100));
    }

    #[tokio::test]
    async fn test_system_clock_sleep() {
        let clock = SystemClock;
        let t1 = clock.now();
        clock.sleep(Duration::from_millis(50)).await;
        let t2 = clock.now();

        let elapsed = t2.as_millis().saturating_sub(t1.as_millis());
        assert!(
            elapsed >= 50,
            "Should sleep at least 50ms, got {}ms",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_monotonic_guarantee() {
        let clock = SystemClock;
        let mut prev = clock.now();

        for _ in 0..100 {
            let curr = clock.now();
            assert!(
                curr >= prev,
                "Clock must be monotonic: {} should be >= {}",
                curr.as_nanos(),
                prev.as_nanos()
            );
            prev = curr;
            tokio::time::sleep(Duration::from_micros(10)).await;
        }
    }

    #[tokio::test]
    async fn test_mock_clock_manipulation() {
        let clock = MockClock::new(Timestamp::from_millis(1000));

        assert_eq!(clock.now(), Timestamp::from_millis(1000));

        clock.advance(Duration::from_millis(250));
        assert_eq!(clock.now(), Timestamp::from_millis(1250));

        clock.set(Timestamp::from_millis(5000));
        assert_eq!(clock.now(), Timestamp::from_millis(5000));

        clock.advance(Duration::from_secs(2));
        assert_eq!(clock.now(), Timestamp::from_millis(7000));
    }
}
