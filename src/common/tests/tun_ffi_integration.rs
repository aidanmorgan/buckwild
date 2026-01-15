#![cfg(target_os = "linux")]
//! FFI Integration tests for TUN device C bindings
//!
//! These tests verify that Rust can successfully call the C TUN device
//! implementation through the FFI layer.
//!
//! **TDD Phase**: RED -> GREEN -> REFACTOR
//!
//! This test verifies REQ-FFI-001 through REQ-FFI-004:
//! - REQ-FFI-001: Rust can call C config functions
//! - REQ-FFI-002: Rust can create TUN device via C
//! - REQ-FFI-003: Rust can read/write via C FFI
//! - REQ-FFI-004: Proper cleanup of FFI resources
//!
//! ## Running Tests
//!
//! These tests require CAP_NET_ADMIN:
//! ```bash
//! sudo -E cargo test --test tun_ffi_integration -- --test-threads=1
//! ```

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// FFI bindings to C TUN device implementation
#[repr(C)]
struct BuckwildTunConfig {
    name: [c_char; 16],
    ip_addr: u32,
    netmask: u32,
    mtu: u16,
    persistent: bool,
}

/// Opaque pointer to C tun_device struct
#[repr(C)]
struct TunDevice {
    _private: [u8; 0],
}

#[link(name = "buckwild_network")]
unsafe extern "C" {
    fn buckwild_tun_config_init(config: *mut BuckwildTunConfig) -> c_int;
    fn buckwild_tun_config_set_name(config: *mut BuckwildTunConfig, name: *const c_char) -> c_int;
    fn buckwild_tun_config_set_ip_addr(config: *mut BuckwildTunConfig, ip_addr: u32) -> c_int;
    fn buckwild_tun_config_set_netmask(config: *mut BuckwildTunConfig, netmask: u32) -> c_int;
    fn buckwild_tun_config_set_mtu(config: *mut BuckwildTunConfig, mtu: u16) -> c_int;

    fn buckwild_tun_device_create(config: *const BuckwildTunConfig) -> *mut TunDevice;
    fn buckwild_tun_device_destroy(dev: *mut TunDevice);
    fn buckwild_tun_device_read(dev: *mut TunDevice, buf: *mut u8, len: usize) -> i64;
    fn buckwild_tun_device_write(dev: *mut TunDevice, buf: *const u8, len: usize) -> i64;
    fn buckwild_tun_device_get_fd(dev: *const TunDevice) -> c_int;
    fn buckwild_tun_device_get_name(dev: *const TunDevice, buf: *mut c_char, len: usize) -> c_int;
    fn buckwild_tun_device_get_mtu(dev: *const TunDevice) -> u16;
    fn buckwild_tun_device_is_up(dev: *const TunDevice) -> c_int;
    fn buckwild_tun_device_set_nonblock(dev: *mut TunDevice, nonblock: c_int) -> c_int;
    fn buckwild_tun_error_string(err: c_int) -> *const c_char;
}

/// Helper: Check if running as root
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Helper: Convert IP octets to u32 in native (host) byte order
/// The C FFI function expects host byte order and will convert to network byte order internally
fn ip_to_u32(a: u8, b: u8, c: u8, d: u8) -> u32 {
    // On little-endian: (d << 24) | (c << 16) | (b << 8) | a  = 0x010000C80A
    // On big-endian: (a << 24) | (b << 16) | (c << 8) | d = 0x0AC80001
    #[cfg(target_endian = "little")]
    {
        ((d as u32) << 24) | ((c as u32) << 16) | ((b as u32) << 8) | (a as u32)
    }
    #[cfg(target_endian = "big")]
    {
        ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
    }
}

/// Helper: Create test config
fn create_test_config() -> BuckwildTunConfig {
    BuckwildTunConfig {
        name: [0; 16],
        ip_addr: 0,
        netmask: 0,
        mtu: 0,
        persistent: false,
    }
}

//
// Test FFI-001: Configuration Functions
//
// Given: Rust code with FFI bindings to C
// When: Rust calls C config functions
// Then: Config is properly initialized and set
//
#[test]
fn test_ffi_001_config_functions() {
    unsafe {
        // Given: Empty config
        let mut config = create_test_config();

        // When: Initialize via FFI
        let ret = buckwild_tun_config_init(&mut config);

        // Then: Should succeed
        assert_eq!(ret, 0, "Config init should return 0");
        assert_eq!(config.mtu, 1400, "Default MTU should be 1400");

        // When: Set name via FFI
        let name = std::ffi::CString::new("buckwild_ffi").unwrap();
        let ret = buckwild_tun_config_set_name(&mut config, name.as_ptr());

        // Then: Should succeed
        assert_eq!(ret, 0, "Set name should return 0");

        // Verify name was set (compare C string)
        let set_name = CStr::from_ptr(config.name.as_ptr())
            .to_str()
            .expect("Valid UTF-8");
        assert_eq!(set_name, "buckwild_ffi", "Name should match");

        // When: Set IP address (10.200.0.1 in host byte order)
        let ip_host = ip_to_u32(10, 200, 0, 1);
        let ret = buckwild_tun_config_set_ip_addr(&mut config, ip_host);

        // Then: Should succeed
        assert_eq!(ret, 0, "Set IP should return 0");
        // Config stores in network byte order, so convert back to verify
        let ip_network = u32::from_be_bytes([10, 200, 0, 1]);
        assert_eq!(
            config.ip_addr, ip_network,
            "IP should be stored in network byte order"
        );

        // When: Set netmask (255.255.255.0 in host byte order)
        let mask_host = ip_to_u32(255, 255, 255, 0);
        let ret = buckwild_tun_config_set_netmask(&mut config, mask_host);

        // Then: Should succeed
        assert_eq!(ret, 0, "Set netmask should return 0");
        // Config stores in network byte order, so convert back to verify
        let mask_network = u32::from_be_bytes([255, 255, 255, 0]);
        assert_eq!(
            config.netmask, mask_network,
            "Netmask should be stored in network byte order"
        );

        // When: Set MTU
        let ret = buckwild_tun_config_set_mtu(&mut config, 1300);

        // Then: Should succeed
        assert_eq!(ret, 0, "Set MTU should return 0");
        assert_eq!(config.mtu, 1300, "MTU should be set");
    }
}

//
// Test FFI-002: Device Creation and Destruction
//
// Given: Valid config from Rust
// When: Rust creates TUN device via C FFI
// Then: Device is created and can be destroyed
//
#[test]
fn test_ffi_002_device_lifecycle() {
    // Skip if not root
    if !is_root() {
        eprintln!("SKIP: Test requires root privileges");
        return;
    }

    unsafe {
        // Given: Valid config
        let mut config = create_test_config();
        buckwild_tun_config_init(&mut config);

        let name = std::ffi::CString::new("buckwild_ffi").unwrap();
        buckwild_tun_config_set_name(&mut config, name.as_ptr());
        buckwild_tun_config_set_ip_addr(&mut config, ip_to_u32(10, 200, 0, 1));
        buckwild_tun_config_set_netmask(&mut config, ip_to_u32(255, 255, 255, 0));
        buckwild_tun_config_set_mtu(&mut config, 1400);

        // When: Create device via FFI
        let dev = buckwild_tun_device_create(&config);

        // Then: Should succeed
        assert!(!dev.is_null(), "Device creation should succeed");

        // Verify device properties via FFI
        let mtu = buckwild_tun_device_get_mtu(dev);
        assert_eq!(mtu, 1400, "MTU should match");

        let is_up = buckwild_tun_device_is_up(dev);
        assert_eq!(is_up, 1, "Device should be UP");

        let fd = buckwild_tun_device_get_fd(dev);
        assert!(fd >= 0, "FD should be valid");

        // Get device name via FFI
        let mut name_buf = [0 as c_char; 16];
        let ret = buckwild_tun_device_get_name(dev, name_buf.as_mut_ptr(), 16);
        assert_eq!(ret, 0, "Get name should succeed");

        let retrieved_name = CStr::from_ptr(name_buf.as_ptr())
            .to_str()
            .expect("Valid UTF-8");
        assert_eq!(retrieved_name, "buckwild_ffi", "Name should match");

        // When: Destroy device via FFI
        buckwild_tun_device_destroy(dev);

        // Then: No panic, proper cleanup
        // (We can't easily verify the device is gone from Rust without syscalls)
    }
}

//
// Test FFI-003: Packet I/O via FFI
//
// Given: TUN device created via C FFI
// When: Rust writes packet via C FFI
// Then: Packet can be read back via C FFI
//
#[test]
fn test_ffi_003_packet_io() {
    // Skip if not root
    if !is_root() {
        eprintln!("SKIP: Test requires root privileges");
        return;
    }

    unsafe {
        // Given: TUN device
        let mut config = create_test_config();
        buckwild_tun_config_init(&mut config);

        let name = std::ffi::CString::new("buckwild_ffi").unwrap();
        buckwild_tun_config_set_name(&mut config, name.as_ptr());
        buckwild_tun_config_set_ip_addr(&mut config, ip_to_u32(10, 200, 0, 1));
        buckwild_tun_config_set_netmask(&mut config, ip_to_u32(255, 255, 255, 0));

        let dev = buckwild_tun_device_create(&config);
        assert!(!dev.is_null(), "Device creation should succeed");

        // Set non-blocking mode
        let ret = buckwild_tun_device_set_nonblock(dev, 1);
        assert_eq!(ret, 0, "Set nonblock should succeed");

        // When: Write test packet (simple IPv4 header)
        let mut write_buf = [0u8; 64];
        write_buf[0] = 0x45; // IPv4, header length 5
        write_buf[1] = 0x00; // DSCP, ECN

        let written = buckwild_tun_device_write(dev, write_buf.as_ptr(), write_buf.len());

        // Then: Should succeed or return EAGAIN if buffer full
        assert!(
            written > 0 || written == -11, // -11 is EAGAIN
            "Write should succeed or return EAGAIN, got: {}",
            written
        );

        // When: Try to read back (may fail if no packets routing back)
        let mut read_buf = [0u8; 1500];
        let read_count = buckwild_tun_device_read(dev, read_buf.as_mut_ptr(), read_buf.len());

        // Then: Should either succeed or fail with EAGAIN (no data yet)
        assert!(
            read_count >= 0 || read_count == -11, // -11 is EAGAIN
            "Read should succeed or return EAGAIN, got: {}",
            read_count
        );

        // Cleanup
        buckwild_tun_device_destroy(dev);
    }
}

//
// Test FFI-004: Error Handling
//
// Given: Invalid parameters
// When: Rust calls C functions with invalid params
// Then: Proper error codes returned, no panics
//
#[test]
fn test_ffi_004_error_handling() {
    unsafe {
        // Given: NULL config pointer
        let ret = buckwild_tun_config_init(std::ptr::null_mut());

        // Then: Should return error
        assert_ne!(ret, 0, "Init with NULL should fail");

        // Given: Invalid device name (too long)
        let mut config = create_test_config();
        buckwild_tun_config_init(&mut config);

        let long_name =
            std::ffi::CString::new("this_name_is_way_too_long_for_a_tun_device").unwrap();
        let ret = buckwild_tun_config_set_name(&mut config, long_name.as_ptr());

        // Then: Should return error
        assert_ne!(ret, 0, "Long name should fail");

        // Given: NULL device pointer for operations
        let fd = buckwild_tun_device_get_fd(std::ptr::null());

        // Then: Should return error (negative)
        assert!(fd < 0, "Get FD with NULL should fail");

        // Test error string function (should never return NULL)
        let err_str = buckwild_tun_error_string(-5);
        assert!(!err_str.is_null(), "Error string should never be NULL");

        let err_msg = CStr::from_ptr(err_str).to_str().expect("Valid UTF-8");
        assert!(!err_msg.is_empty(), "Error message should not be empty");
    }
}

//
// Test FFI-005: Insufficient Capabilities
//
// Given: Process without root privileges
// When: Attempting to create device
// Then: Proper error returned (not panic)
//
#[test]
fn test_ffi_005_insufficient_capabilities() {
    // This test only meaningful when NOT root
    if is_root() {
        eprintln!("SKIP: Test requires non-root user");
        return;
    }

    unsafe {
        // Given: Valid config but no privileges
        let mut config = create_test_config();
        buckwild_tun_config_init(&mut config);

        let name = std::ffi::CString::new("buckwild_ffi").unwrap();
        buckwild_tun_config_set_name(&mut config, name.as_ptr());
        buckwild_tun_config_set_ip_addr(&mut config, ip_to_u32(10, 200, 0, 1));

        // When: Try to create without privileges
        let dev = buckwild_tun_device_create(&config);

        // Then: Should return NULL (failure), not panic
        assert!(
            dev.is_null(),
            "Device creation should fail without CAP_NET_ADMIN"
        );

        // No cleanup needed since creation failed
    }
}
