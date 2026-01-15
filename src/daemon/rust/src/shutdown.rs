//! Graceful shutdown coordination for Buckwild daemon
//!
//! Provides broadcast-based shutdown signaling with atomic status checks.
//! Enables clean resource cleanup and graceful connection teardown.

use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::broadcast;

/// Capacity for shutdown signal broadcast channel
const SHUTDOWN_CHANNEL_CAPACITY: usize = 16;

/// Controller for coordinating graceful shutdown across daemon components
///
/// Uses a broadcast channel to notify all subscribers when shutdown is initiated,
/// combined with an atomic flag for fast status checks without channel overhead.
///
/// Usage pattern:
/// 1. Create a `ShutdownController::new()`
/// 2. Clone it to share across components
/// 3. Components can either:
///    - Subscribe with `subscribe()` to receive async notification
///    - Poll `is_shutting_down()` in hot paths (fast atomic check)
/// 4. Call `shutdown()` to initiate graceful shutdown
#[derive(Clone)]
pub struct ShutdownController {
    /// Signal sender for shutdown notification
    shutdown_tx: broadcast::Sender<()>,
    /// Flag indicating shutdown has started
    shutting_down: std::sync::Arc<AtomicBool>,
}

impl ShutdownController {
    /// Create a new shutdown controller
    ///
    /// Initializes the broadcast channel with default capacity and sets
    /// the shutdown flag to false.
    pub fn new() -> Self {
        let (shutdown_tx, _) = broadcast::channel(SHUTDOWN_CHANNEL_CAPACITY);
        Self {
            shutdown_tx,
            shutting_down: std::sync::Arc::new(AtomicBool::new(false)),
        }
    }

    /// Initiate graceful shutdown
    ///
    /// Sets the shutdown flag and broadcasts the shutdown signal to all
    /// subscribers. This method is idempotent - calling it multiple times
    /// is safe and has no additional effect.
    ///
    /// All active subscribers will receive the shutdown notification.
    /// The broadcast will succeed even if there are no active receivers.
    pub fn shutdown(&self) {
        // Set flag first (fastest path for status checks)
        self.shutting_down.store(true, Ordering::Release);

        // Broadcast to all subscribers (ignore error if no receivers)
        let _ = self.shutdown_tx.send(());
    }

    /// Check if shutdown is in progress
    ///
    /// Returns true if shutdown has been initiated. This is a fast
    /// atomic check suitable for hot paths (e.g., packet processing loops).
    ///
    /// # Returns
    ///
    /// * `true` - Shutdown has been initiated
    /// * `false` - System is running normally
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Get a receiver to listen for shutdown signal
    ///
    /// Returns a new receiver subscribed to the shutdown broadcast.
    /// The receiver will receive a signal when `shutdown()` is called.
    ///
    /// # Returns
    ///
    /// A `broadcast::Receiver` that will receive `()` on shutdown
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

impl Default for ShutdownController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    #[test]
    fn test_controller_creation() {
        let controller = ShutdownController::new();
        assert!(!controller.is_shutting_down());
    }

    #[test]
    fn test_default_constructor() {
        let controller = ShutdownController::default();
        assert!(!controller.is_shutting_down());
    }

    #[tokio::test]
    async fn test_shutdown_signal() {
        let controller = ShutdownController::new();
        let mut rx = controller.subscribe();

        controller.shutdown();

        let result = timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_flag_setting() {
        let controller = ShutdownController::new();
        assert!(!controller.is_shutting_down());

        controller.shutdown();
        assert!(controller.is_shutting_down());
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let controller = ShutdownController::new();
        let mut rx1 = controller.subscribe();
        let mut rx2 = controller.subscribe();
        let mut rx3 = controller.subscribe();

        controller.shutdown();

        // All subscribers should receive notification
        let result1 = timeout(Duration::from_millis(100), rx1.recv()).await;
        let result2 = timeout(Duration::from_millis(100), rx2.recv()).await;
        let result3 = timeout(Duration::from_millis(100), rx3.recv()).await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert!(result3.is_ok());
    }

    #[test]
    fn test_idempotent_shutdown() {
        let controller = ShutdownController::new();

        controller.shutdown();
        assert!(controller.is_shutting_down());

        // Multiple shutdown calls are safe
        controller.shutdown();
        controller.shutdown();
        assert!(controller.is_shutting_down());
    }

    #[tokio::test]
    async fn test_late_subscriber() {
        let controller = ShutdownController::new();

        controller.shutdown();

        // Subscribe after shutdown - receiver won't get the signal
        // but flag will still indicate shutdown
        let mut rx = controller.subscribe();
        assert!(controller.is_shutting_down());

        // Receiver won't get signal (already sent)
        let result = timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(result.is_err()); // Timeout

        // But flag correctly shows shutdown state
        assert!(controller.is_shutting_down());
    }

    #[tokio::test]
    async fn test_clone_shares_state() {
        let controller = ShutdownController::new();
        let controller_clone = controller.clone();

        let mut rx = controller_clone.subscribe();

        controller.shutdown();

        assert!(controller.is_shutting_down());
        assert!(controller_clone.is_shutting_down());

        let result = timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_shutdown_with_no_subscribers() {
        let controller = ShutdownController::new();

        // Shutdown with no subscribers should not panic
        controller.shutdown();
        assert!(controller.is_shutting_down());
    }

    #[tokio::test]
    async fn test_concurrent_shutdown_calls() {
        let controller = ShutdownController::new();
        let controller_clone = controller.clone();

        let handle1 = tokio::spawn(async move {
            controller.shutdown();
        });

        let handle2 = tokio::spawn(async move {
            controller_clone.shutdown();
        });

        handle1.await.unwrap();
        handle2.await.unwrap();
    }

    #[tokio::test]
    async fn test_receiver_dropped_before_send() {
        let controller = ShutdownController::new();
        let rx = controller.subscribe();

        drop(rx);

        // Should not panic even if receiver was dropped
        controller.shutdown();
        assert!(controller.is_shutting_down());
    }

    #[tokio::test]
    async fn test_multiple_shutdown_cycles() {
        // Verify controller can be reused in multiple shutdown scenarios
        for _ in 0..3 {
            let controller = ShutdownController::new();
            assert!(!controller.is_shutting_down());

            let mut rx = controller.subscribe();
            controller.shutdown();

            assert!(controller.is_shutting_down());
            assert!(rx.recv().await.is_ok());
        }
    }
}
