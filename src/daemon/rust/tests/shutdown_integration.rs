//! Integration tests for graceful shutdown functionality

use buckwild_daemon::shutdown::ShutdownController;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn test_shutdown_controller_basic() {
    let controller = ShutdownController::new();
    assert!(!controller.is_shutting_down());

    controller.shutdown();
    assert!(controller.is_shutting_down());
}

#[tokio::test]
async fn test_shutdown_broadcast() {
    let controller = ShutdownController::new();
    let mut rx1 = controller.subscribe();
    let mut rx2 = controller.subscribe();

    controller.shutdown();

    let result1 = timeout(Duration::from_millis(100), rx1.recv()).await;
    let result2 = timeout(Duration::from_millis(100), rx2.recv()).await;

    assert!(result1.is_ok(), "Receiver 1 should get signal");
    assert!(result2.is_ok(), "Receiver 2 should get signal");
}

#[tokio::test]
async fn test_shutdown_idempotent() {
    let controller = ShutdownController::new();
    let mut rx = controller.subscribe();

    controller.shutdown();
    controller.shutdown();
    controller.shutdown();

    assert!(controller.is_shutting_down());

    // Should only receive one signal
    let result = timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_shutdown_clone_shares_state() {
    let controller = ShutdownController::new();
    let cloned = controller.clone();

    let mut rx1 = controller.subscribe();
    let mut rx2 = cloned.subscribe();

    controller.shutdown();

    assert!(controller.is_shutting_down());
    assert!(cloned.is_shutting_down());

    assert!(rx1.recv().await.is_ok());
    assert!(rx2.recv().await.is_ok());
}

#[tokio::test]
async fn test_shutdown_no_subscribers() {
    let controller = ShutdownController::new();
    controller.shutdown();
    assert!(controller.is_shutting_down());
}
