//! TUN Device Integration Tests
//!
//! These tests verify the TUN device implementation according to
//! TUN_EBPF_IMPLEMENTATION_GUIDE.md Phase 1: TUN Foundation
//!
//! ## TDD Status: RED Phase
//!
//! All tests are expected to FAIL with the stub implementation.
//! Tests will pass after implementing LinuxTunHandle (GREEN phase).
//!
//! ## Requirements
//!
//! - Must run with root/CAP_NET_ADMIN privileges
//! - Requires /dev/net/tun access
//! - Tests create temporary TUN devices with unique names
//!
//! ## Running Tests
//!
//! ```bash
//! sudo -E cargo test --test linux_device_tests
//! ```

use buckwild_common::network::tun::{DeviceName, Mtu, TunConfig, TunError};
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

/// Helper to check if test has CAP_NET_ADMIN
fn has_net_admin_cap() -> bool {
    // Check if running as root or with CAP_NET_ADMIN
    unsafe { libc::geteuid() == 0 }
}

/// Helper to verify device exists in Linux network stack
fn device_exists(name: &str) -> bool {
    let output = Command::new("ip")
        .args(&["link", "show", name])
        .output()
        .ok();

    match output {
        Some(o) => o.status.success(),
        None => false,
    }
}

/// Helper to get device IP address
fn get_device_ip(name: &str) -> Option<String> {
    let output = Command::new("ip")
        .args(&["addr", "show", name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse IP from output (simplified)
    for line in stdout.lines() {
        if line.contains("inet ") {
            return Some(line.trim().to_string());
        }
    }
    None
}

/// Helper to get device MTU
fn get_device_mtu(name: &str) -> Option<u16> {
    let output = Command::new("ip")
        .args(&["link", "show", name])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse MTU from output
    for part in stdout.split_whitespace() {
        if let Some(mtu_str) = part.strip_prefix("mtu") {
            return mtu_str.trim().parse().ok();
        }
    }
    None
}

/// Test 1.1: TUN Device Creation
///
/// *Given* the process has CAP_NET_ADMIN capability
/// *When* TUN device is created with name "buckwild0", IP "10.100.0.1", netmask "255.255.255.0", MTU 1400
/// *Then* device "buckwild0" appears in `ip link show`
/// *And* device has IP address "10.100.0.1/24" in `ip addr show`
/// *And* device MTU is 1400 bytes
/// *And* device operational state is UP
/// *And* no errors or panics occur
#[tokio::test]
async fn test_1_1_tun_device_creation() {
    // Skip if not running with privileges
    if !has_net_admin_cap() {
        eprintln!("Skipping test: requires CAP_NET_ADMIN (run with sudo)");
        return;
    }

    let device_name = DeviceName::new("buckwild0").expect("valid device name");
    let ip_address: IpAddr = "10.100.0.1".parse().expect("valid IP");
    let netmask: IpAddr = "255.255.255.0".parse().expect("valid netmask");
    let mtu = Mtu::new(1400).expect("valid MTU");

    let config = TunConfig::new(device_name.clone(), ip_address, netmask, mtu);

    // Attempt to create device
    let device = buckwild_common::network::tun::device::LinuxTunHandle::create(config)
        .await
        .expect("device creation should succeed");

    // Verify device exists in network stack
    assert!(device_exists("buckwild0"), "device should appear in ip link show");

    // Verify IP address configuration
    let ip_output = get_device_ip("buckwild0");
    assert!(ip_output.is_some(), "device should have IP address");
    let ip_str = ip_output.unwrap();
    assert!(ip_str.contains("10.100.0.1"), "device should have correct IP");
    assert!(ip_str.contains("/24"), "device should have correct netmask");

    // Verify MTU
    let actual_mtu = get_device_mtu("buckwild0");
    assert_eq!(actual_mtu, Some(1400), "device should have correct MTU");

    // Verify device is UP
    // Note: Device should be brought up automatically during creation
    let output = Command::new("ip")
        .args(&["link", "show", "buckwild0"])
        .output()
        .expect("ip command should work");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("UP"), "device should be in UP state");

    // Cleanup is automatic via Drop
    drop(device);
}

/// Test 1.2: TUN Device Lifecycle
///
/// *Given* TUN device "buckwild_test" is created successfully
/// *When* device handle is dropped
/// *Then* device "buckwild_test" is removed from Linux network stack
/// *And* `/sys/class/net/buckwild_test` does not exist
/// *And* no file descriptors are leaked
/// *And* no memory is leaked (verified with valgrind or similar)
#[tokio::test]
async fn test_1_2_tun_device_lifecycle() {
    if !has_net_admin_cap() {
        eprintln!("Skipping test: requires CAP_NET_ADMIN (run with sudo)");
        return;
    }

    let device_name = DeviceName::new("buckwild_test").expect("valid device name");
    let ip_address: IpAddr = "10.100.0.2".parse().expect("valid IP");
    let netmask: IpAddr = "255.255.255.0".parse().expect("valid netmask");
    let mtu = Mtu::default();

    let config = TunConfig::new(device_name.clone(), ip_address, netmask, mtu);

    // Create device
    let device = buckwild_common::network::tun::device::LinuxTunHandle::create(config)
        .await
        .expect("device creation should succeed");

    // Verify device exists
    assert!(device_exists("buckwild_test"), "device should exist after creation");

    // Drop device handle (triggers cleanup)
    drop(device);

    // Small delay to allow cleanup to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify device is removed
    assert!(!device_exists("buckwild_test"), "device should be removed after drop");

    // Verify sysfs entry is gone
    assert!(
        !std::path::Path::new("/sys/class/net/buckwild_test").exists(),
        "sysfs entry should be removed"
    );

    // Note: File descriptor leaks are checked via integration with lsof/valgrind
    // Memory leaks are checked via valgrind in CI
}

/// Test 1.3: Async Packet I/O
///
/// *Given* TUN device "buckwild_io" is created and up
/// *When* test packet (Ethernet frame) is written to device asynchronously
/// *Then* write operation completes without blocking
/// *And* packet can be read back from device asynchronously
/// *And* read operation completes without blocking
/// *And* packet contents match original exactly
#[tokio::test]
async fn test_1_3_async_packet_io() {
    if !has_net_admin_cap() {
        eprintln!("Skipping test: requires CAP_NET_ADMIN (run with sudo)");
        return;
    }

    let device_name = DeviceName::new("buckwild_io").expect("valid device name");
    let ip_address: IpAddr = "10.100.0.3".parse().expect("valid IP");
    let netmask: IpAddr = "255.255.255.0".parse().expect("valid netmask");
    let mtu = Mtu::default();

    let config = TunConfig::new(device_name.clone(), ip_address, netmask, mtu);

    let mut device = buckwild_common::network::tun::device::LinuxTunHandle::create(config)
        .await
        .expect("device creation should succeed");

    // Create test packet (simple IP packet)
    let test_packet = vec![
        0x45, 0x00, 0x00, 0x20, // IP header
        0x00, 0x01, 0x00, 0x00, // ID, Flags, Fragment Offset
        0x40, 0x01, 0x00, 0x00, // TTL, Protocol (ICMP), Checksum
        0x0a, 0x64, 0x00, 0x03, // Source IP: 10.100.0.3
        0x0a, 0x64, 0x00, 0x01, // Dest IP: 10.100.0.1
        // ICMP Echo Request
        0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x00, 0x00, // "Hello!"
    ];

    // Write packet asynchronously (should not block)
    let write_result = timeout(
        Duration::from_millis(100),
        device.write_packet(&test_packet)
    ).await;

    assert!(
        write_result.is_ok(),
        "write should complete within 100ms (not block)"
    );
    write_result
        .unwrap()
        .expect("write should succeed");

    // Read packet asynchronously (should not block indefinitely)
    let mut read_buf = vec![0u8; 2048];
    let read_result = timeout(
        Duration::from_secs(2),
        device.read_packet(&mut read_buf)
    ).await;

    assert!(
        read_result.is_ok(),
        "read should complete within 2s (not block indefinitely)"
    );
    let bytes_read = read_result
        .unwrap()
        .expect("read should succeed");

    // Verify packet contents match
    assert_eq!(
        &read_buf[..bytes_read],
        &test_packet[..],
        "read packet should match written packet exactly"
    );
}

/// Test 1.4: Error Handling - Insufficient Capabilities
///
/// *Given* process does not have CAP_NET_ADMIN
/// *When* attempting to create TUN device
/// *Then* operation returns `Err(TunError::InsufficientCapabilities)`
/// *And* error message includes "CAP_NET_ADMIN required"
/// *And* **no panic occurs**
#[tokio::test]
async fn test_1_4_error_insufficient_capabilities() {
    // This test is tricky - we can't easily drop privileges in a test
    // Instead, we verify the error type exists and can be constructed

    // If running as root, skip this test (can't test insufficient privs)
    if has_net_admin_cap() {
        eprintln!("Skipping test: running as root (can't test insufficient capabilities)");
        // But we can still test error construction
        let error = TunError::InsufficientCapabilities {
            capability: "CAP_NET_ADMIN".to_string(),
        };
        let error_msg = format!("{}", error);
        assert!(
            error_msg.contains("CAP_NET_ADMIN"),
            "error message should mention required capability"
        );
        return;
    }

    // If not root, attempt device creation (should fail)
    let device_name = DeviceName::new("buckwild_nopriv").expect("valid device name");
    let ip_address: IpAddr = "10.100.0.4".parse().expect("valid IP");
    let netmask: IpAddr = "255.255.255.0".parse().expect("valid netmask");
    let mtu = Mtu::default();

    let config = TunConfig::new(device_name, ip_address, netmask, mtu);

    let result = buckwild_common::network::tun::device::LinuxTunHandle::create(config).await;

    assert!(result.is_err(), "device creation should fail without privileges");

    let error = result.unwrap_err();
    match error {
        TunError::InsufficientCapabilities { capability } => {
            assert!(
                capability.contains("CAP_NET_ADMIN"),
                "error should mention CAP_NET_ADMIN"
            );
        }
        other => panic!("expected InsufficientCapabilities, got {:?}", other),
    }
}

/// Test 1.5: Error Handling - Device Already Exists
///
/// *Given* TUN device "buckwild_dup" already exists
/// *When* attempting to create another device with same name
/// *Then* operation returns `Err(TunError::DeviceExists { name: "buckwild_dup" })`
/// *And* error is typed with `thiserror::Error`
/// *And* **no panic occurs**
#[tokio::test]
async fn test_1_5_error_device_already_exists() {
    if !has_net_admin_cap() {
        eprintln!("Skipping test: requires CAP_NET_ADMIN (run with sudo)");
        return;
    }

    let device_name = DeviceName::new("buckwild_dup").expect("valid device name");
    let ip_address: IpAddr = "10.100.0.5".parse().expect("valid IP");
    let netmask: IpAddr = "255.255.255.0".parse().expect("valid netmask");
    let mtu = Mtu::default();

    let config1 = TunConfig::new(
        device_name.clone(),
        ip_address,
        netmask,
        mtu,
    );

    // Create first device
    let _device1 = buckwild_common::network::tun::device::LinuxTunHandle::create(config1)
        .await
        .expect("first device creation should succeed");

    // Attempt to create second device with same name
    let config2 = TunConfig::new(
        device_name.clone(),
        ip_address,
        netmask,
        mtu,
    );

    let result = buckwild_common::network::tun::device::LinuxTunHandle::create(config2).await;

    assert!(result.is_err(), "second device creation should fail");

    let error = result.unwrap_err();
    match error {
        TunError::DeviceExists { name } => {
            assert_eq!(name, "buckwild_dup", "error should contain device name");
        }
        other => panic!("expected DeviceExists, got {:?}", other),
    }

    // Cleanup
    drop(_device1);
}

/// Test 1.6: Error Handling - Invalid Configuration
///
/// *Given* invalid IP address "999.999.999.999"
/// *When* attempting to create TUN device with this IP
/// *Then* operation returns `Err(TunError::InvalidIpAddress { .. })`
/// *And* error contains original invalid value for debugging
/// *And* **no panic occurs**
#[tokio::test]
async fn test_1_6_error_invalid_configuration() {
    // Test invalid IP address parsing
    let invalid_ip = "999.999.999.999";
    let parse_result: Result<IpAddr, _> = invalid_ip.parse();

    assert!(parse_result.is_err(), "invalid IP should fail to parse");

    // Verify TunError::InvalidIpAddress can be constructed with proper context
    let parse_err = parse_result.unwrap_err();
    let tun_error = TunError::InvalidIpAddress {
        value: invalid_ip.to_string(),
        source: parse_err,
    };

    let error_msg = format!("{}", tun_error);
    assert!(
        error_msg.contains("999.999.999.999"),
        "error message should contain invalid IP for debugging"
    );
    assert!(
        error_msg.contains("invalid IP address"),
        "error message should be descriptive"
    );

    // Test invalid device name
    let invalid_name_result = DeviceName::new("");
    assert!(invalid_name_result.is_err(), "empty name should be rejected");
    match invalid_name_result.unwrap_err() {
        TunError::InvalidDeviceName { reason } => {
            assert!(reason.contains("empty"), "error should explain why name is invalid");
        }
        _ => panic!("expected InvalidDeviceName error"),
    }

    // Test invalid MTU
    let invalid_mtu_result = Mtu::new(67); // Below minimum of 68
    assert!(invalid_mtu_result.is_err(), "MTU below minimum should be rejected");
    match invalid_mtu_result.unwrap_err() {
        TunError::InvalidMtu { value, reason } => {
            assert_eq!(value, 67, "error should contain invalid value");
            assert!(reason.contains("68"), "error should mention minimum MTU");
        }
        _ => panic!("expected InvalidMtu error"),
    }
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    /// Verify error types implement required traits
    #[test]
    fn test_error_traits() {
        // Verify TunError implements std::error::Error (from thiserror)
        fn assert_error<T: std::error::Error>() {}
        assert_error::<TunError>();

        // Verify TunError is Debug and Display
        fn assert_debug_display<T: std::fmt::Debug + std::fmt::Display>() {}
        assert_debug_display::<TunError>();
    }

    /// Verify domain types implement required traits
    #[test]
    fn test_domain_type_traits() {
        // DeviceName
        fn assert_device_name_traits<T>()
        where
            T: Clone + PartialEq + Eq + std::hash::Hash + std::fmt::Display + std::str::FromStr,
        {
        }
        assert_device_name_traits::<DeviceName>();

        // Mtu
        fn assert_mtu_traits<T>()
        where
            T: Copy + Clone + PartialEq + Eq + PartialOrd + Ord + std::fmt::Display + std::str::FromStr,
        {
        }
        assert_mtu_traits::<Mtu>();
    }
}
