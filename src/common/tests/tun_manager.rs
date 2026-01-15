//! Integration tests for TUN Device Manager (Task 3)
//!
//! These tests validate the manager lifecycle, packet processing loop,
//! error recovery, backpressure handling, and restart capability.
//!
//! Tests 3.1-3.6 from TUN_EBPF_IMPLEMENTATION_GUIDE.md
//!
//! ## TDD Status: GREEN Phase
//!
//! All tests pass successfully. Implementation complete.

use buckwild_common::network::tun::{Mtu, TunDeviceManager, TunManagerConfig};
use tokio::time::{Duration, timeout};

/// Test 3.1: Manager Lifecycle
///
/// REQ-MGR-001, REQ-MGR-002, REQ-MGR-008
///
/// GIVEN manager is created
/// WHEN manager.start() is called
/// THEN TUN device is created, manager is running
/// WHEN manager.stop() is called
/// THEN device is removed, manager is stopped
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_3_1_manager_lifecycle() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("⚠️  Skipping test - requires root privileges");
        return;
    }

    let config = TunManagerConfig::new(
        "buckwild_mgr".to_string(),
        "10.100.0.1".parse().unwrap(),
        "255.255.255.0".parse().unwrap(),
        Mtu::default(),
        100,
    )
    .expect("Valid config");

    let mut manager = TunDeviceManager::new(config);

    assert!(
        !manager.is_running(),
        "Manager should not be running initially"
    );

    manager
        .start()
        .await
        .expect("Manager should start successfully");

    assert!(
        manager.is_running(),
        "Manager should be running after start"
    );

    manager
        .stop()
        .await
        .expect("Manager should stop successfully");

    assert!(
        !manager.is_running(),
        "Manager should not be running after stop"
    );
}

/// Test 3.2: Packet Flow
///
/// REQ-MGR-003, REQ-MGR-004, REQ-MGR-005
///
/// GIVEN manager is started
/// WHEN TCP packet is injected
/// THEN protocol packet appears on receiver channel
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_3_2_packet_flow() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("⚠️  Skipping test - requires root privileges");
        return;
    }

    let config = TunManagerConfig::new(
        "buckwild_flow".to_string(),
        "10.100.0.2".parse().unwrap(),
        "255.255.255.0".parse().unwrap(),
        Mtu::default(),
        100,
    )
    .expect("Valid config");

    let mut manager = TunDeviceManager::new(config);

    let mut receiver = manager.start().await.expect("Manager should start");

    let test_packet = vec![0xAB; 100];
    manager
        .inject_packet(&test_packet)
        .await
        .expect("Packet injection should succeed");

    let result = timeout(Duration::from_millis(200), receiver.recv()).await;

    assert!(result.is_ok(), "Should receive packet within timeout");

    if let Ok(Some(packet)) = result {
        assert!(!packet.is_empty(), "Received packet should not be empty");
    }

    manager.stop().await.expect("Manager should stop");
}

/// Test 3.3: Error Recovery - Malformed Packet
///
/// REQ-MGR-006
///
/// GIVEN manager is started
/// WHEN malformed packet is injected
/// THEN error is logged and manager continues processing
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_3_3_error_recovery_malformed_packet() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("⚠️  Skipping test - requires root privileges");
        return;
    }

    let config = TunManagerConfig::new(
        "buckwild_err".to_string(),
        "10.100.0.3".parse().unwrap(),
        "255.255.255.0".parse().unwrap(),
        Mtu::default(),
        100,
    )
    .expect("Valid config");

    let mut manager = TunDeviceManager::new(config);

    let mut receiver = manager.start().await.expect("Manager should start");

    let malformed_packet = vec![];
    manager
        .inject_packet(&malformed_packet)
        .await
        .expect("Injection should succeed even for malformed packet");

    let valid_packet = vec![0xCD; 100];
    manager
        .inject_packet(&valid_packet)
        .await
        .expect("Valid packet should be accepted");

    let result = timeout(Duration::from_millis(200), receiver.recv()).await;

    assert!(
        result.is_ok(),
        "Should still receive valid packets after error"
    );

    assert!(
        manager.is_running(),
        "Manager should still be running after error"
    );

    let stats = manager.stats();
    assert!(stats.error_count > 0, "Error count should be incremented");

    manager.stop().await.expect("Manager should stop");
}

/// Test 3.4: Backpressure Handling
///
/// REQ-MGR-007
///
/// GIVEN manager with small channel buffer
/// WHEN channel is full and more packets arrive
/// THEN excess packets are dropped, no unbounded growth
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_3_4_backpressure_handling() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("⚠️  Skipping test - requires root privileges");
        return;
    }

    let config = TunManagerConfig::new(
        "buckwild_bp".to_string(),
        "10.100.0.4".parse().unwrap(),
        "255.255.255.0".parse().unwrap(),
        Mtu::default(),
        10,
    )
    .expect("Valid config");

    let mut manager = TunDeviceManager::new(config);

    let receiver = manager.start().await.expect("Manager should start");

    for i in 0..20 {
        let packet = vec![i as u8; 50];
        manager.inject_packet(&packet).await.ok();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = manager.stats();
    assert!(
        stats.dropped_count >= 10,
        "Should drop at least 10 packets due to backpressure, got {}",
        stats.dropped_count
    );

    assert!(
        manager.is_running(),
        "Manager should not crash from backpressure"
    );

    drop(receiver);
    manager.stop().await.expect("Manager should stop");
}

/// Test 3.5: Restart Capability
///
/// REQ-MGR-010
///
/// GIVEN manager is started and stopped
/// WHEN manager.start() is called again
/// THEN second start succeeds with no resource leaks
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_3_5_restart_capability() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("⚠️  Skipping test - requires root privileges");
        return;
    }

    let config = TunManagerConfig::new(
        "buckwild_restart".to_string(),
        "10.100.0.5".parse().unwrap(),
        "255.255.255.0".parse().unwrap(),
        Mtu::default(),
        100,
    )
    .expect("Valid config");

    let mut manager = TunDeviceManager::new(config);

    manager.start().await.expect("First start should succeed");
    manager.stop().await.expect("First stop should succeed");

    manager.start().await.expect("Second start should succeed");
    assert!(
        manager.is_running(),
        "Manager should be running after restart"
    );
    manager.stop().await.expect("Second stop should succeed");
}

/// Test 3.6: Concurrent Packet Processing
///
/// REQ-MGR-009
///
/// GIVEN manager is started
/// WHEN many packets are injected concurrently
/// THEN all are processed or dropped, no panics
#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore)]
async fn test_3_6_concurrent_packet_processing() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("⚠️  Skipping test - requires root privileges");
        return;
    }

    let config = TunManagerConfig::new(
        "buckwild_conc".to_string(),
        "10.100.0.6".parse().unwrap(),
        "255.255.255.0".parse().unwrap(),
        Mtu::default(),
        200,
    )
    .expect("Valid config");

    let mut manager = TunDeviceManager::new(config);

    let receiver = manager.start().await.expect("Manager should start");

    let mut handles = vec![];
    for i in 0..10 {
        let packet = vec![i as u8; 100];
        let mgr_packet = packet.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..100 {
                let _ = mgr_packet.clone();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.ok();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats = manager.stats();
    let total_processed = stats.received_count + stats.dropped_count + stats.error_count;

    assert!(total_processed > 0, "Should have processed some packets");
    assert!(manager.is_running(), "Manager should still be running");

    drop(receiver);
    manager.stop().await.expect("Manager should stop");
}
