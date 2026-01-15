//! FFI bindings to the C TUN device library
//!
//! This crate provides safe Rust wrappers around the C TUN device implementation.
//!
//! # Platform Requirements
//!
//! TUN device functionality requires Linux kernel with TUN/TAP support.
//! On non-Linux platforms, stub implementations are provided that return
//! clear error messages explaining the platform requirement.
//!
//! # Safety
//!
//! The raw FFI declarations are unsafe. The safe wrappers in the `tun` module
//! provide RAII semantics and enforce single-threaded access.
//!
//! # Error Codes
//!
//! FFI functions that return `c_int` use the following error codes:
//! - `BUCKWILD_ERR_NULL_POINTER` (-1): A required pointer argument was null
//! - `BUCKWILD_ERR_INVALID_INPUT` (-2): Invalid input parameter
//! - `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` (-3): Operation not supported on this platform
//! - Other negative values: Platform-specific errors

#[cfg(target_os = "linux")]
use libc::{c_char, c_int, size_t};

#[cfg(not(target_os = "linux"))]
#[allow(non_camel_case_types)]
type c_char = i8;
#[cfg(not(target_os = "linux"))]
#[allow(non_camel_case_types)]
type c_int = i32;
#[cfg(not(target_os = "linux"))]
#[allow(non_camel_case_types)]
type size_t = usize;

/// Error code: Null pointer passed to FFI function
pub const BUCKWILD_ERR_NULL_POINTER: c_int = -1;

/// Error code: Invalid input parameter
pub const BUCKWILD_ERR_INVALID_INPUT: c_int = -2;

/// Error code: Platform not supported
pub const BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED: c_int = -3;

/// Opaque handle to a TUN device (forward declaration from C)
///
/// # Zero-Sized Type (ZST) Safety
///
/// This is a zero-sized type used only for type safety. The actual device
/// data lives in C-allocated memory. Rust code must never:
/// - Perform pointer arithmetic on `*mut TunDevice` or `*const TunDevice`
/// - Dereference these pointers (opaque type - no layout guarantees)
/// - Create slices or arrays of `TunDevice`
///
/// All operations must go through the C FFI functions which handle the
/// actual device state internally.
#[repr(C)]
pub struct TunDevice {
    _private: [u8; 0],
}

/// FFI-safe TUN device configuration structure
///
/// Matches the C structure `buckwild_tun_config_t` exactly.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (null-terminated, max 15 chars)
    pub name: [c_char; 16],
    /// IPv4 address in network byte order
    pub ip_addr: u32,
    /// IPv4 netmask in network byte order
    pub netmask: u32,
    /// MTU value (68-65535)
    pub mtu: u16,
    /// Make device persistent across process exit
    pub persistent: bool,
}

#[cfg(target_os = "linux")]
extern "C" {
    /// Initialize FFI configuration with defaults
    pub fn buckwild_tun_config_init(config: *mut TunConfig) -> c_int;

    /// Set device name (max 15 chars, null-terminated)
    pub fn buckwild_tun_config_set_name(config: *mut TunConfig, name: *const c_char) -> c_int;

    /// Set IP address from host byte order
    pub fn buckwild_tun_config_set_ip_addr(config: *mut TunConfig, ip_addr: u32) -> c_int;

    /// Set netmask from host byte order
    pub fn buckwild_tun_config_set_netmask(config: *mut TunConfig, netmask: u32) -> c_int;

    /// Set MTU
    pub fn buckwild_tun_config_set_mtu(config: *mut TunConfig, mtu: u16) -> c_int;

    /// Create TUN device (returns opaque handle or NULL on failure)
    pub fn buckwild_tun_device_create(config: *const TunConfig) -> *mut TunDevice;

    /// Destroy TUN device (safe to call with NULL)
    pub fn buckwild_tun_device_destroy(dev: *mut TunDevice);

    /// Read packet from device
    pub fn buckwild_tun_device_read(dev: *mut TunDevice, buf: *mut u8, len: size_t) -> i64;

    /// Write packet to device
    pub fn buckwild_tun_device_write(dev: *mut TunDevice, buf: *const u8, len: size_t) -> i64;

    /// Get file descriptor for poll/epoll
    pub fn buckwild_tun_device_get_fd(dev: *const TunDevice) -> c_int;

    /// Get device name
    pub fn buckwild_tun_device_get_name(
        dev: *const TunDevice,
        buf: *mut c_char,
        len: size_t,
    ) -> c_int;

    /// Get device MTU
    pub fn buckwild_tun_device_get_mtu(dev: *const TunDevice) -> u16;

    /// Check if device is up
    pub fn buckwild_tun_device_is_up(dev: *const TunDevice) -> c_int;

    /// Set non-blocking mode
    pub fn buckwild_tun_device_set_nonblock(dev: *mut TunDevice, nonblock: c_int) -> c_int;

    /// Get error message string
    pub fn buckwild_tun_error_string(err: c_int) -> *const c_char;
}

/// Initialize a TUN configuration struct.
///
/// # Safety
///
/// - `config` must be a valid, non-null pointer to a `TunConfig` struct
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if `config` is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_config_init(_config: *mut TunConfig) -> c_int {
    if _config.is_null() {
        return BUCKWILD_ERR_NULL_POINTER;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED
}

/// Set the device name in a TUN configuration.
///
/// # Safety
///
/// - `config` must be a valid, non-null pointer to a `TunConfig` struct
/// - `name` must be a valid, non-null pointer to a null-terminated C string
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if any pointer is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_config_set_name(_config: *mut TunConfig, _name: *const c_char) -> c_int {
    if _config.is_null() || _name.is_null() {
        return BUCKWILD_ERR_NULL_POINTER;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED
}

/// Set the IP address in a TUN configuration.
///
/// # Safety
///
/// - `config` must be a valid, non-null pointer to a `TunConfig` struct
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if `config` is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_config_set_ip_addr(_config: *mut TunConfig, _ip_addr: u32) -> c_int {
    if _config.is_null() {
        return BUCKWILD_ERR_NULL_POINTER;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED
}

/// Set the netmask in a TUN configuration.
///
/// # Safety
///
/// - `config` must be a valid, non-null pointer to a `TunConfig` struct
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if `config` is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_config_set_netmask(_config: *mut TunConfig, _netmask: u32) -> c_int {
    if _config.is_null() {
        return BUCKWILD_ERR_NULL_POINTER;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED
}

/// Set the MTU in a TUN configuration.
///
/// # Safety
///
/// - `config` must be a valid, non-null pointer to a `TunConfig` struct
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if `config` is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_config_set_mtu(_config: *mut TunConfig, _mtu: u16) -> c_int {
    if _config.is_null() {
        return BUCKWILD_ERR_NULL_POINTER;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED
}

/// Create a TUN device from configuration.
///
/// # Safety
///
/// - `config` must be a valid, non-null pointer to a `TunConfig` struct
/// - Returns null if `config` is null or on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_create(_config: *const TunConfig) -> *mut TunDevice {
    if _config.is_null() {
        return std::ptr::null_mut();
    }
    std::ptr::null_mut()
}

/// Destroy a TUN device and release resources.
///
/// # Safety
///
/// - `dev` must be a valid pointer previously returned by `buckwild_tun_device_create`, or null
/// - Null pointers are safely ignored (no-op)
/// - After this call, the pointer is no longer valid
/// - This is a stub that does nothing on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_destroy(_dev: *mut TunDevice) {
    // Null pointer is safe to pass (no-op per C convention)
}

/// Read data from a TUN device.
///
/// # Safety
///
/// - `dev` must be a valid, non-null pointer previously returned by `buckwild_tun_device_create`
/// - `buf` must be a valid, non-null pointer with capacity for at least `len` bytes
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if any pointer is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_read(_dev: *mut TunDevice, _buf: *mut u8, _len: size_t) -> i64 {
    if _dev.is_null() || _buf.is_null() {
        return BUCKWILD_ERR_NULL_POINTER as i64;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED as i64
}

/// Write data to a TUN device.
///
/// # Safety
///
/// - `dev` must be a valid, non-null pointer previously returned by `buckwild_tun_device_create`
/// - `buf` must be a valid, non-null pointer to at least `len` readable bytes
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if any pointer is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_write(
    _dev: *mut TunDevice,
    _buf: *const u8,
    _len: size_t,
) -> i64 {
    if _dev.is_null() || _buf.is_null() {
        return BUCKWILD_ERR_NULL_POINTER as i64;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED as i64
}

/// Get the file descriptor for a TUN device.
///
/// # Safety
///
/// - `dev` must be a valid, non-null pointer previously returned by `buckwild_tun_device_create`
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if `dev` is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_get_fd(_dev: *const TunDevice) -> c_int {
    if _dev.is_null() {
        return BUCKWILD_ERR_NULL_POINTER;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED
}

/// Get the device name for a TUN device.
///
/// # Safety
///
/// - `dev` must be a valid, non-null pointer previously returned by `buckwild_tun_device_create`
/// - `buf` must be a valid, non-null pointer with capacity for at least `len` bytes
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if any pointer is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_get_name(
    _dev: *const TunDevice,
    _buf: *mut c_char,
    _len: size_t,
) -> c_int {
    if _dev.is_null() || _buf.is_null() {
        return BUCKWILD_ERR_NULL_POINTER;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED
}

/// Get the MTU for a TUN device.
///
/// # Safety
///
/// - `dev` must be a valid, non-null pointer previously returned by `buckwild_tun_device_create`
/// - Returns 0 if `dev` is null or on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_get_mtu(_dev: *const TunDevice) -> u16 {
    if _dev.is_null() {
        return 0;
    }
    0
}

/// Check if a TUN device is up.
///
/// # Safety
///
/// - `dev` must be a valid, non-null pointer previously returned by `buckwild_tun_device_create`
/// - Returns 0 (false) if `dev` is null or on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_is_up(_dev: *const TunDevice) -> c_int {
    if _dev.is_null() {
        return 0;
    }
    0
}

/// Set non-blocking mode on a TUN device.
///
/// # Safety
///
/// - `dev` must be a valid, non-null pointer previously returned by `buckwild_tun_device_create`
/// - Returns `BUCKWILD_ERR_NULL_POINTER` if `dev` is null
/// - Returns `BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED` on non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_device_set_nonblock(_dev: *mut TunDevice, _nonblock: c_int) -> c_int {
    if _dev.is_null() {
        return BUCKWILD_ERR_NULL_POINTER;
    }
    BUCKWILD_ERR_PLATFORM_NOT_SUPPORTED
}

/// Get an error string for an error code.
///
/// # Safety
///
/// - Returns a non-null pointer to a static, null-terminated C string
/// - The returned pointer is valid for the lifetime of the program
/// - Never returns null - always returns a valid error message
#[cfg(not(target_os = "linux"))]
pub unsafe fn buckwild_tun_error_string(_err: c_int) -> *const c_char {
    c"TUN device operations require Linux".as_ptr()
}

pub mod tun;

#[cfg(test)]
mod compatibility_tests;
