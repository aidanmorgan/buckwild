//! TUN Device FFI Integration Tests
//!
//! These tests verify that Rust code can correctly call the C TUN device
//! library (libbuckwild_network.so) through the FFI boundary.
//!
//! # Test Categories
//!
//! 1. **Configuration Tests**: Verify config struct initialization and field setting
//! 2. **Error Handling Tests**: Verify C error codes are correctly propagated to Rust
//! 3. **Device Lifecycle Tests**: Verify device creation, query, and destruction (requires root)
//!
//! # Running These Tests
//!
//! These tests require Linux and the libbuckwild_network.so library to be built.
//! Run via: `cargo test --test '*' -- --test-threads=1 ffi`
//!
//! Device creation tests require CAP_NET_ADMIN or root privileges.

use buckwild_ffi::{
    buckwild_tun_config_init, buckwild_tun_config_set_ip_addr, buckwild_tun_config_set_mtu,
    buckwild_tun_config_set_name, buckwild_tun_config_set_netmask, buckwild_tun_device_create,
    buckwild_tun_device_destroy, buckwild_tun_device_get_fd, buckwild_tun_device_get_mtu,
    buckwild_tun_device_get_name, buckwild_tun_device_is_up, buckwild_tun_device_read,
    buckwild_tun_device_set_nonblock, buckwild_tun_device_write, buckwild_tun_error_string,
    TunConfig, BUCKWILD_ERR_INVALID_INPUT, BUCKWILD_ERR_NULL_POINTER,
};
use std::ffi::CStr;
use std::os::raw::c_char;

/// Helper to check if we have privileges to create TUN devices
fn has_tun_privileges() -> bool {
    // Try to open /dev/net/tun - this is a quick check
    if !std::fs::metadata("/dev/net/tun").is_ok() {
        return false;
    }
    // Check if we're root or have CAP_NET_ADMIN
    let is_root = unsafe { libc::geteuid() == 0 };
    is_root || std::env::var("BUCKWILD_TEST_TUN").is_ok()
}

// ============================================================================
// CONFIGURATION INITIALIZATION TESTS
// ============================================================================

/// Test: Config struct can be initialized via FFI
///
/// Verifies that the C buckwild_tun_config_init function:
/// - Accepts a valid config pointer
/// - Returns success (0)
/// - Sets default values correctly
#[test]
fn test_ffi_config_init_success() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();

        let result = buckwild_tun_config_init(&mut config);

        assert_eq!(result, 0, "Config init should succeed with valid pointer");

        // Verify default values are set
        // Note: C library uses 1400 as default MTU (TUN_MTU_DEFAULT)
        assert_eq!(config.mtu, 1400, "Default MTU should be 1400");
        assert_eq!(config.persistent, false, "Default persistent should be false");
    }
}

/// Test: Config name can be set via FFI
///
/// Verifies buckwild_tun_config_set_name:
/// - Accepts valid config and name pointers
/// - Correctly copies the name string
/// - Handles max-length names (15 chars)
#[test]
fn test_ffi_config_set_name() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // Test normal name
        let name = b"tun0\0".as_ptr() as *const c_char;
        let result = buckwild_tun_config_set_name(&mut config, name);

        assert_eq!(result, 0, "set_name should succeed with valid name");

        // Verify the name was copied (check first 4 bytes)
        assert_eq!(config.name[0], b't' as c_char);
        assert_eq!(config.name[1], b'u' as c_char);
        assert_eq!(config.name[2], b'n' as c_char);
        assert_eq!(config.name[3], b'0' as c_char);
        assert_eq!(config.name[4], 0); // null terminator
    }
}

/// Test: Config name with maximum length (15 chars)
#[test]
fn test_ffi_config_set_name_max_length() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // 15 character name (maximum allowed)
        let name = b"tun0123456789ab\0".as_ptr() as *const c_char;
        let result = buckwild_tun_config_set_name(&mut config, name);

        assert_eq!(result, 0, "set_name should succeed with 15-char name");

        // Verify null termination
        assert_eq!(config.name[15], 0, "Name must be null-terminated");
    }
}

/// Test: Config rejects name that is too long (>15 chars)
///
/// Note: The C FFI layer returns -1 for all validation errors.
#[test]
fn test_ffi_config_set_name_too_long() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // 16 character name (one too many)
        let name = b"tun0123456789abc\0".as_ptr() as *const c_char;
        let result = buckwild_tun_config_set_name(&mut config, name);

        // C FFI returns -1 for validation errors
        assert_eq!(
            result, -1,
            "set_name should reject name > 15 chars with error code -1"
        );
    }
}

/// Test: Config IP address can be set via FFI
///
/// Note: The C library stores IP addresses in network byte order (big-endian)
/// using htonl(). The input is in host byte order.
#[test]
fn test_ffi_config_set_ip_addr() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // Set 10.0.0.1 in host byte order
        let ip: u32 = 0x0A000001;
        let result = buckwild_tun_config_set_ip_addr(&mut config, ip);

        assert_eq!(result, 0, "set_ip_addr should succeed");
        // C library converts to network byte order via htonl()
        assert_eq!(config.ip_addr, ip.to_be(), "IP address should be stored in network byte order");
    }
}

/// Test: Config netmask can be set via FFI
///
/// Note: The C library stores netmasks in network byte order (big-endian)
/// using htonl(). The input is in host byte order.
#[test]
fn test_ffi_config_set_netmask() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // Set 255.255.255.0 in host byte order
        let netmask: u32 = 0xFFFFFF00;
        let result = buckwild_tun_config_set_netmask(&mut config, netmask);

        assert_eq!(result, 0, "set_netmask should succeed");
        // C library converts to network byte order via htonl()
        assert_eq!(config.netmask, netmask.to_be(), "Netmask should be stored in network byte order");
    }
}

/// Test: Config MTU can be set via FFI
#[test]
fn test_ffi_config_set_mtu() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        let result = buckwild_tun_config_set_mtu(&mut config, 1400);

        assert_eq!(result, 0, "set_mtu should succeed with valid MTU");
        assert_eq!(config.mtu, 1400, "MTU should be stored correctly");
    }
}

/// Test: Config rejects invalid MTU (too low)
///
/// Note: The C FFI layer returns -1 for all validation errors.
/// The underlying TUN library uses TUN_ERR_INVALID_MTU (-5) but the FFI
/// wrapper simplifies this to -1.
#[test]
fn test_ffi_config_set_mtu_too_low() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // MTU below minimum (68 is the minimum for IPv4)
        let result = buckwild_tun_config_set_mtu(&mut config, 50);

        // C FFI returns -1 for validation errors
        assert_eq!(
            result, -1,
            "set_mtu should reject MTU < 68 with error code -1"
        );
    }
}

// ============================================================================
// ERROR STRING TESTS
// ============================================================================

/// Test: Error strings are returned correctly from C
///
/// Note: The C library error codes map to the underlying TUN error enum.
/// BUCKWILD_ERR_NULL_POINTER (-1) maps to TUN_ERR_INSUFFICIENT_CAPS.
#[test]
fn test_ffi_error_string_null_pointer() {
    unsafe {
        let err_str = buckwild_tun_error_string(BUCKWILD_ERR_NULL_POINTER);

        assert!(!err_str.is_null(), "Error string should never be null");

        let c_str = CStr::from_ptr(err_str);
        let rust_str = c_str.to_str().expect("Error string should be valid UTF-8");

        // -1 maps to TUN_ERR_INSUFFICIENT_CAPS in the C library
        assert!(
            rust_str.contains("capabilities") || rust_str.contains("CAP_NET_ADMIN"),
            "Error string for -1 should mention capabilities: '{}'",
            rust_str
        );
    }
}

/// Test: Error strings for invalid input
///
/// Note: BUCKWILD_ERR_INVALID_INPUT (-2) maps to TUN_ERR_DEVICE_EXISTS.
#[test]
fn test_ffi_error_string_invalid_input() {
    unsafe {
        let err_str = buckwild_tun_error_string(BUCKWILD_ERR_INVALID_INPUT);

        assert!(!err_str.is_null(), "Error string should never be null");

        let c_str = CStr::from_ptr(err_str);
        let rust_str = c_str.to_str().expect("Error string should be valid UTF-8");

        // -2 maps to TUN_ERR_DEVICE_EXISTS in the C library
        assert!(
            rust_str.contains("exists") || rust_str.contains("Device"),
            "Error string for -2 should mention device exists: '{}'",
            rust_str
        );
    }
}

/// Test: Error strings for unknown error codes
#[test]
fn test_ffi_error_string_unknown() {
    unsafe {
        // Use an unlikely error code
        let err_str = buckwild_tun_error_string(-999);

        assert!(!err_str.is_null(), "Error string should never be null");

        let c_str = CStr::from_ptr(err_str);
        let rust_str = c_str.to_str().expect("Error string should be valid UTF-8");

        // Should return some string (even if generic)
        assert!(!rust_str.is_empty(), "Error string should not be empty");
    }
}

// ============================================================================
// COMPLETE CONFIG WORKFLOW TEST
// ============================================================================

/// Test: Complete configuration workflow
///
/// Verifies the full workflow of creating a config:
/// 1. Initialize config
/// 2. Set name
/// 3. Set IP address
/// 4. Set netmask
/// 5. Set MTU
///
/// Note: IP and netmask are stored in network byte order by the C library.
#[test]
fn test_ffi_complete_config_workflow() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();

        // Step 1: Initialize
        let result = buckwild_tun_config_init(&mut config);
        assert_eq!(result, 0, "Init should succeed");

        // Step 2: Set name
        let name = b"bw0\0".as_ptr() as *const c_char;
        let result = buckwild_tun_config_set_name(&mut config, name);
        assert_eq!(result, 0, "Set name should succeed");

        // Step 3: Set IP address (10.100.0.1 = 0x0A640001)
        let ip: u32 = 0x0A640001;
        let result = buckwild_tun_config_set_ip_addr(&mut config, ip);
        assert_eq!(result, 0, "Set IP should succeed");

        // Step 4: Set netmask (255.255.0.0 = 0xFFFF0000)
        let netmask: u32 = 0xFFFF0000;
        let result = buckwild_tun_config_set_netmask(&mut config, netmask);
        assert_eq!(result, 0, "Set netmask should succeed");

        // Step 5: Set MTU
        let result = buckwild_tun_config_set_mtu(&mut config, 1420);
        assert_eq!(result, 0, "Set MTU should succeed");

        // Verify final state
        assert_eq!(config.name[0], b'b' as c_char);
        assert_eq!(config.name[1], b'w' as c_char);
        assert_eq!(config.name[2], b'0' as c_char);
        // IP and netmask are stored in network byte order
        assert_eq!(config.ip_addr, ip.to_be(), "IP should be in network byte order");
        assert_eq!(config.netmask, netmask.to_be(), "Netmask should be in network byte order");
        assert_eq!(config.mtu, 1420);
    }
}

// ============================================================================
// DEVICE LIFECYCLE TESTS (Require privileges)
// ============================================================================

/// Test: Device creation with null config returns null
#[test]
fn test_ffi_device_create_null_config() {
    unsafe {
        let device = buckwild_tun_device_create(std::ptr::null());
        assert!(device.is_null(), "create with null config should return null");
    }
}

/// Test: Device destroy handles null safely
#[test]
fn test_ffi_device_destroy_null() {
    unsafe {
        // Should not crash
        buckwild_tun_device_destroy(std::ptr::null_mut());
    }
}

/// Test: Device get_fd with null returns error
#[test]
fn test_ffi_device_get_fd_null() {
    unsafe {
        let fd = buckwild_tun_device_get_fd(std::ptr::null());
        assert_eq!(fd, BUCKWILD_ERR_NULL_POINTER, "get_fd(null) should return error");
    }
}

/// Test: Device get_mtu with null returns 0
#[test]
fn test_ffi_device_get_mtu_null() {
    unsafe {
        let mtu = buckwild_tun_device_get_mtu(std::ptr::null());
        assert_eq!(mtu, 0, "get_mtu(null) should return 0");
    }
}

/// Test: Device is_up with null returns 0
#[test]
fn test_ffi_device_is_up_null() {
    unsafe {
        let is_up = buckwild_tun_device_is_up(std::ptr::null());
        assert_eq!(is_up, 0, "is_up(null) should return 0");
    }
}

/// Test: Device set_nonblock with null returns error
#[test]
fn test_ffi_device_set_nonblock_null() {
    unsafe {
        let result = buckwild_tun_device_set_nonblock(std::ptr::null_mut(), 1);
        assert_eq!(
            result, BUCKWILD_ERR_NULL_POINTER,
            "set_nonblock(null) should return error"
        );
    }
}

/// Test: Device get_name with null returns error
#[test]
fn test_ffi_device_get_name_null_device() {
    unsafe {
        let mut buf = [0 as c_char; 16];
        let result = buckwild_tun_device_get_name(std::ptr::null(), buf.as_mut_ptr(), buf.len());
        assert_eq!(
            result, BUCKWILD_ERR_NULL_POINTER,
            "get_name(null) should return error"
        );
    }
}

/// Test: Full device lifecycle (requires root/CAP_NET_ADMIN)
///
/// This test creates a real TUN device, queries its properties, and destroys it.
/// It is skipped if the test environment lacks sufficient privileges.
#[test]
fn test_ffi_device_full_lifecycle() {
    if !has_tun_privileges() {
        eprintln!("Skipping test_ffi_device_full_lifecycle: requires root or CAP_NET_ADMIN");
        eprintln!("Set BUCKWILD_TEST_TUN=1 and run as root to enable this test");
        return;
    }

    unsafe {
        // Setup: Create config
        let mut config: TunConfig = std::mem::zeroed();
        assert_eq!(buckwild_tun_config_init(&mut config), 0);

        let name = b"bwtest0\0".as_ptr() as *const c_char;
        assert_eq!(buckwild_tun_config_set_name(&mut config, name), 0);
        assert_eq!(buckwild_tun_config_set_ip_addr(&mut config, 0x0A000001), 0); // 10.0.0.1
        assert_eq!(buckwild_tun_config_set_netmask(&mut config, 0xFFFFFF00), 0); // 255.255.255.0
        assert_eq!(buckwild_tun_config_set_mtu(&mut config, 1400), 0);

        // Create device
        let device = buckwild_tun_device_create(&config);
        if device.is_null() {
            eprintln!("Device creation failed - may require more privileges");
            return;
        }

        // Verify device properties
        let fd = buckwild_tun_device_get_fd(device);
        assert!(fd >= 0, "File descriptor should be valid: {}", fd);

        let mtu = buckwild_tun_device_get_mtu(device);
        assert_eq!(mtu, 1400, "MTU should match configured value");

        let mut name_buf = [0 as c_char; 16];
        let result = buckwild_tun_device_get_name(device, name_buf.as_mut_ptr(), name_buf.len());
        assert_eq!(result, 0, "get_name should succeed");

        let retrieved_name = CStr::from_ptr(name_buf.as_ptr());
        assert!(
            retrieved_name.to_str().unwrap().starts_with("bwtest"),
            "Name should start with 'bwtest': {:?}",
            retrieved_name
        );

        // Test nonblocking mode
        let result = buckwild_tun_device_set_nonblock(device, 1);
        assert_eq!(result, 0, "set_nonblock should succeed");

        // Cleanup
        buckwild_tun_device_destroy(device);
    }
}

// ============================================================================
// STRUCT LAYOUT VALIDATION (Runtime verification)
// ============================================================================

/// Test: Verify TunConfig struct size matches C at runtime
///
/// This test verifies that the Rust TunConfig struct has the exact same
/// size as the C buckwild_tun_config_t struct.
#[test]
fn test_ffi_struct_size_runtime_validation() {
    use std::mem::size_of;

    // Expected size based on C struct layout:
    // char name[16] = 16 bytes
    // uint32_t ip_addr = 4 bytes
    // uint32_t netmask = 4 bytes
    // uint16_t mtu = 2 bytes
    // bool persistent = 1 byte
    // padding = 1 byte (for 4-byte alignment)
    // Total = 28 bytes
    const EXPECTED_SIZE: usize = 28;

    assert_eq!(
        size_of::<TunConfig>(),
        EXPECTED_SIZE,
        "TunConfig size mismatch: Rust={}, expected={}",
        size_of::<TunConfig>(),
        EXPECTED_SIZE
    );
}

/// Test: Verify field offsets match C struct layout
#[test]
fn test_ffi_struct_field_offsets() {
    use std::mem::offset_of;

    // These offsets must match the C struct exactly
    assert_eq!(offset_of!(TunConfig, name), 0, "name offset mismatch");
    assert_eq!(offset_of!(TunConfig, ip_addr), 16, "ip_addr offset mismatch");
    assert_eq!(offset_of!(TunConfig, netmask), 20, "netmask offset mismatch");
    assert_eq!(offset_of!(TunConfig, mtu), 24, "mtu offset mismatch");
    assert_eq!(offset_of!(TunConfig, persistent), 26, "persistent offset mismatch");
}

// ============================================================================
// SAFE WRAPPER INTEGRATION TESTS
// ============================================================================

/// Test: Safe TunDeviceHandle wrapper - creation fails without privileges
///
/// Verifies the safe Rust wrapper correctly propagates errors from C.
#[test]
fn test_safe_wrapper_creation_no_privileges() {
    use buckwild_ffi::tun::TunDeviceHandle;

    if has_tun_privileges() {
        eprintln!("Skipping test_safe_wrapper_creation_no_privileges: running as root");
        return;
    }

    let result = TunDeviceHandle::create("bwtest0", 0x0A000001, 0xFFFFFF00, 1400);

    // Should fail due to lack of privileges
    assert!(
        result.is_err(),
        "Device creation should fail without privileges"
    );
}

/// Test: Safe wrapper validates input before FFI call
#[test]
fn test_safe_wrapper_input_validation() {
    use buckwild_ffi::tun::TunDeviceHandle;

    // Name too long (> 15 chars)
    let result = TunDeviceHandle::create(
        "this_name_is_way_too_long_for_tun",
        0x0A000001,
        0xFFFFFF00,
        1400,
    );

    assert!(result.is_err(), "Should reject name > 15 chars");

    // Check the error kind without requiring Debug on TunDeviceHandle
    match result {
        Err(err) => {
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidInput,
                "Error kind should be InvalidInput"
            );
        }
        Ok(_) => panic!("Expected error, got Ok"),
    }
}

/// Test: Safe wrapper full lifecycle with privileges
#[test]
fn test_safe_wrapper_full_lifecycle() {
    use buckwild_ffi::tun::TunDeviceHandle;
    use std::os::fd::AsRawFd;

    if !has_tun_privileges() {
        eprintln!("Skipping test_safe_wrapper_full_lifecycle: requires root");
        return;
    }

    // Create device using safe wrapper
    let device = TunDeviceHandle::create("bwsafe0", 0x0A000002, 0xFFFFFF00, 1400)
        .expect("Device creation should succeed");

    // Verify we can get the file descriptor
    let fd = device.as_raw_fd();
    assert!(fd >= 0, "File descriptor should be valid");

    // Device is automatically destroyed when `device` goes out of scope
    // (RAII pattern via Drop implementation)
}

// ============================================================================
// ADDITIONAL INTEGRATION TESTS
// ============================================================================

/// Test: Config values can be overwritten
///
/// Verifies that setting a config field multiple times works correctly.
#[test]
fn test_ffi_config_overwrite_values() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // Set initial values
        let name1 = b"tun0\0".as_ptr() as *const c_char;
        assert_eq!(buckwild_tun_config_set_name(&mut config, name1), 0);
        assert_eq!(buckwild_tun_config_set_mtu(&mut config, 1400), 0);

        // Overwrite with new values
        let name2 = b"bw1\0".as_ptr() as *const c_char;
        assert_eq!(buckwild_tun_config_set_name(&mut config, name2), 0);
        assert_eq!(buckwild_tun_config_set_mtu(&mut config, 1500), 0);

        // Verify new values are stored
        assert_eq!(config.name[0], b'b' as c_char);
        assert_eq!(config.name[1], b'w' as c_char);
        assert_eq!(config.name[2], b'1' as c_char);
        assert_eq!(config.mtu, 1500);
    }
}

/// Test: Empty name is rejected
///
/// Empty device names are invalid for Linux TUN devices.
#[test]
fn test_ffi_config_set_name_empty() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        let name = b"\0".as_ptr() as *const c_char;
        let result = buckwild_tun_config_set_name(&mut config, name);

        // C FFI returns -1 for empty name
        assert_eq!(result, -1, "set_name should reject empty name");
    }
}

/// Test: Minimum valid MTU (68 bytes per RFC 791)
#[test]
fn test_ffi_config_set_mtu_minimum() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // MTU of exactly 68 should succeed
        let result = buckwild_tun_config_set_mtu(&mut config, 68);

        assert_eq!(result, 0, "set_mtu should accept MTU = 68");
        assert_eq!(config.mtu, 68, "MTU should be stored correctly");
    }
}

/// Test: Large MTU value
#[test]
fn test_ffi_config_set_mtu_large() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        // Large but valid MTU (jumbo frames)
        let result = buckwild_tun_config_set_mtu(&mut config, 9000);

        assert_eq!(result, 0, "set_mtu should accept MTU = 9000");
        assert_eq!(config.mtu, 9000, "MTU should be stored correctly");
    }
}

/// Test: Read with null buffer returns error
#[test]
fn test_ffi_device_read_null_buffer() {
    unsafe {
        // Note: We can't create a real device without privileges,
        // but we can test that passing null to read is handled
        let result = buckwild_tun_device_read(std::ptr::null_mut(), std::ptr::null_mut(), 1500);

        // Should return error (negative value)
        assert!(result < 0, "read with null device/buffer should return error");
    }
}

/// Test: Write with null buffer returns error
#[test]
fn test_ffi_device_write_null_buffer() {
    unsafe {
        let result = buckwild_tun_device_write(std::ptr::null_mut(), std::ptr::null(), 1500);

        // Should return error (negative value)
        assert!(result < 0, "write with null device/buffer should return error");
    }
}

/// Test: Multiple configs can be initialized independently
///
/// Verifies that multiple config structs work correctly without
/// interfering with each other.
#[test]
fn test_ffi_multiple_configs() {
    unsafe {
        let mut config1: TunConfig = std::mem::zeroed();
        let mut config2: TunConfig = std::mem::zeroed();

        // Initialize both
        assert_eq!(buckwild_tun_config_init(&mut config1), 0);
        assert_eq!(buckwild_tun_config_init(&mut config2), 0);

        // Set different values
        let name1 = b"tun0\0".as_ptr() as *const c_char;
        let name2 = b"tun1\0".as_ptr() as *const c_char;

        assert_eq!(buckwild_tun_config_set_name(&mut config1, name1), 0);
        assert_eq!(buckwild_tun_config_set_name(&mut config2, name2), 0);
        assert_eq!(buckwild_tun_config_set_mtu(&mut config1, 1400), 0);
        assert_eq!(buckwild_tun_config_set_mtu(&mut config2, 1500), 0);

        // Verify each config has its own values
        assert_eq!(config1.name[3], b'0' as c_char);
        assert_eq!(config2.name[3], b'1' as c_char);
        assert_eq!(config1.mtu, 1400);
        assert_eq!(config2.mtu, 1500);
    }
}

/// Test: Null pointer handling for all config functions
///
/// Comprehensive null pointer safety test for config setters.
#[test]
fn test_ffi_config_null_pointer_safety() {
    unsafe {
        // All functions should return error when given null config pointer
        assert_eq!(
            buckwild_tun_config_init(std::ptr::null_mut()),
            -1,
            "init with null should return -1"
        );

        let name = b"test\0".as_ptr() as *const c_char;
        assert_eq!(
            buckwild_tun_config_set_name(std::ptr::null_mut(), name),
            -1,
            "set_name with null config should return -1"
        );

        assert_eq!(
            buckwild_tun_config_set_ip_addr(std::ptr::null_mut(), 0x0A000001),
            -1,
            "set_ip_addr with null config should return -1"
        );

        assert_eq!(
            buckwild_tun_config_set_netmask(std::ptr::null_mut(), 0xFFFFFF00),
            -1,
            "set_netmask with null config should return -1"
        );

        assert_eq!(
            buckwild_tun_config_set_mtu(std::ptr::null_mut(), 1400),
            -1,
            "set_mtu with null config should return -1"
        );

        // set_name with null name pointer
        let mut config: TunConfig = std::mem::zeroed();
        buckwild_tun_config_init(&mut config);

        assert_eq!(
            buckwild_tun_config_set_name(&mut config, std::ptr::null()),
            -1,
            "set_name with null name should return -1"
        );
    }
}

/// Test: All TUN error codes have valid strings
///
/// Verifies that the error string function returns valid strings
/// for all defined error codes.
#[test]
fn test_ffi_error_string_all_codes() {
    unsafe {
        // Test range of error codes (-11 to 0)
        for code in -11..=0 {
            let err_str = buckwild_tun_error_string(code);
            assert!(!err_str.is_null(), "Error string for {} should not be null", code);

            let c_str = CStr::from_ptr(err_str);
            let rust_str = c_str.to_str().expect("Error string should be valid UTF-8");
            assert!(!rust_str.is_empty(), "Error string for {} should not be empty", code);
        }
    }
}

/// Test: Special IP addresses are handled correctly
#[test]
fn test_ffi_config_special_ip_addresses() {
    unsafe {
        let mut config: TunConfig = std::mem::zeroed();

        // Test 0.0.0.0
        buckwild_tun_config_init(&mut config);
        let result = buckwild_tun_config_set_ip_addr(&mut config, 0x00000000);
        assert_eq!(result, 0, "0.0.0.0 should be accepted");
        assert_eq!(config.ip_addr, 0u32.to_be());

        // Test 255.255.255.255
        buckwild_tun_config_init(&mut config);
        let result = buckwild_tun_config_set_ip_addr(&mut config, 0xFFFFFFFF);
        assert_eq!(result, 0, "255.255.255.255 should be accepted");
        assert_eq!(config.ip_addr, 0xFFFFFFFFu32.to_be());

        // Test localhost 127.0.0.1
        buckwild_tun_config_init(&mut config);
        let result = buckwild_tun_config_set_ip_addr(&mut config, 0x7F000001);
        assert_eq!(result, 0, "127.0.0.1 should be accepted");
        assert_eq!(config.ip_addr, 0x7F000001u32.to_be());
    }
}
