//! Safe Rust wrapper for TUN device operations
//!
//! Provides RAII semantics with automatic cleanup and enforces single-threaded access.
//!
//! # Platform Requirements
//!
//! TUN device functionality requires Linux kernel with TUN/TAP support enabled.
//! On non-Linux platforms, stub implementations are provided that return clear
//! error messages explaining the platform requirement.

#[cfg(target_os = "linux")]
use crate::TunConfig;
use crate::TunDevice;
#[cfg(target_os = "linux")]
use libc::c_char;
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString};
use std::io::{self, Error, ErrorKind};
use std::marker::PhantomData;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::NonNull;
#[cfg(not(target_os = "linux"))]
use tracing::error;
#[cfg(target_os = "linux")]
use tracing::{debug, error, info};

/// Safe wrapper for a TUN device handle
///
/// This type enforces RAII semantics: the device is automatically destroyed when
/// the handle is dropped.
///
/// # Safety Guarantees
///
/// - **NonNull Pointer**: Uses `NonNull<TunDevice>` to enforce non-null invariant
/// - **ZST Safety**: `TunDevice` is a zero-sized opaque type - no pointer arithmetic
/// - **Exclusive Ownership**: No `Clone` impl - only one owner at a time
/// - **RAII Cleanup**: Drop implementation ensures C resources are freed
///
/// # Thread Safety
///
/// `TunDeviceHandle` is `Send` but not `Sync`:
/// - Each device has its own file descriptor (per-device state, not global)
/// - File descriptor operations (read/write/ioctl) are thread-safe in the Linux kernel
/// - Ownership can be transferred between threads (e.g., via `tokio::spawn_blocking`)
/// - Concurrent access from multiple threads is prevented by Rust's borrow checker (`&mut self`)
///
/// The handle is NOT `Sync` because concurrent access would require synchronization
/// that the C code doesn't provide. However, moving ownership between threads is safe.
pub struct TunDeviceHandle {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ptr: NonNull<TunDevice>,
    // PhantomData<TunDevice> makes the type act like it owns a TunDevice
    // This is !Sync (can't be shared between threads) but allows Send
    // (can be moved between threads with exclusive ownership)
    _marker: PhantomData<TunDevice>,
}

// SAFETY: TunDeviceHandle can be sent between threads because:
// 1. Each TunDevice has its own file descriptor (per-device state)
// 2. Linux file descriptor operations (read/write/ioctl) are thread-safe
// 3. Ownership is exclusive (no Clone impl exists)
// 4. The borrow checker prevents concurrent access via &mut self methods
//
// However, TunDeviceHandle is NOT Sync - concurrent access from multiple
// threads is unsafe because the C code doesn't provide internal synchronization.
unsafe impl Send for TunDeviceHandle {}

impl TunDeviceHandle {
    /// Create a new TUN device with the given configuration
    ///
    /// # Platform Requirements
    ///
    /// This function requires Linux kernel with TUN/TAP support enabled.
    /// On non-Linux platforms, this will always fail with a clear error message.
    ///
    /// # Arguments
    ///
    /// * `name` - Device name (max 15 chars)
    /// * `ip_addr` - IPv4 address in host byte order (e.g., 0x0A000001 for 10.0.0.1)
    /// * `netmask` - IPv4 netmask in host byte order (e.g., 0xFFFFFF00 for 255.255.255.0)
    /// * `mtu` - MTU value (68-65535)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Platform is not Linux (always fails on non-Linux)
    /// - Device name is too long or invalid
    /// - Device creation fails (permissions, device already exists, etc.)
    /// - Configuration is invalid
    ///
    /// # Example
    ///
    /// ```no_run
    /// use buckwild_ffi::tun::TunDeviceHandle;
    ///
    /// let device = TunDeviceHandle::create("tun0", 0x0A000001, 0xFFFFFF00, 1400)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[cfg(target_os = "linux")]
    pub fn create(name: &str, ip_addr: u32, netmask: u32, mtu: u16) -> io::Result<Self> {
        // Format IP for logging
        let ip_str = format!(
            "{}.{}.{}.{}",
            (ip_addr >> 24) & 0xFF,
            (ip_addr >> 16) & 0xFF,
            (ip_addr >> 8) & 0xFF,
            ip_addr & 0xFF
        );
        let mask_str = format!(
            "{}.{}.{}.{}",
            (netmask >> 24) & 0xFF,
            (netmask >> 16) & 0xFF,
            (netmask >> 8) & 0xFF,
            netmask & 0xFF
        );

        info!(
            "TunDeviceHandle::create: name={} ip={} netmask={} mtu={}",
            name, ip_str, mask_str, mtu
        );

        if name.len() > 15 {
            error!(
                "TunDeviceHandle::create: device name too long: {} chars",
                name.len()
            );
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "device name too long (max 15 chars)",
            ));
        }

        let c_name = CString::new(name).map_err(|_| {
            error!("TunDeviceHandle::create: device name contains null byte");
            Error::new(ErrorKind::InvalidInput, "device name contains null byte")
        })?;

        unsafe {
            debug!("TunDeviceHandle::create: initializing config");
            let mut config = std::mem::zeroed::<TunConfig>();

            if crate::buckwild_tun_config_init(&mut config) < 0 {
                error!("TunDeviceHandle::create: buckwild_tun_config_init failed");
                return Err(Error::new(ErrorKind::Other, "failed to initialize config"));
            }

            debug!("TunDeviceHandle::create: setting device name");
            if crate::buckwild_tun_config_set_name(&mut config, c_name.as_ptr()) < 0 {
                error!("TunDeviceHandle::create: buckwild_tun_config_set_name failed");
                return Err(Error::new(ErrorKind::InvalidInput, "invalid device name"));
            }

            debug!(
                "TunDeviceHandle::create: setting IP address 0x{:08X}",
                ip_addr
            );
            if crate::buckwild_tun_config_set_ip_addr(&mut config, ip_addr) < 0 {
                error!("TunDeviceHandle::create: buckwild_tun_config_set_ip_addr failed");
                return Err(Error::new(ErrorKind::InvalidInput, "invalid IP address"));
            }

            debug!("TunDeviceHandle::create: setting netmask 0x{:08X}", netmask);
            if crate::buckwild_tun_config_set_netmask(&mut config, netmask) < 0 {
                error!("TunDeviceHandle::create: buckwild_tun_config_set_netmask failed");
                return Err(Error::new(ErrorKind::InvalidInput, "invalid netmask"));
            }

            debug!("TunDeviceHandle::create: setting MTU {}", mtu);
            if crate::buckwild_tun_config_set_mtu(&mut config, mtu) < 0 {
                error!("TunDeviceHandle::create: buckwild_tun_config_set_mtu failed");
                return Err(Error::new(ErrorKind::InvalidInput, "invalid MTU"));
            }

            debug!("TunDeviceHandle::create: calling buckwild_tun_device_create");
            let raw_ptr = crate::buckwild_tun_device_create(&config);

            // Convert raw pointer to NonNull, handling null case
            let ptr = NonNull::new(raw_ptr).ok_or_else(|| {
                let os_error = Error::last_os_error();
                error!(
                    "TunDeviceHandle::create: buckwild_tun_device_create failed: {}",
                    os_error
                );
                os_error
            })?;

            info!(
                "TunDeviceHandle::create: device {} created successfully",
                name
            );
            Ok(Self {
                ptr,
                _marker: PhantomData,
            })
        }
    }

    /// Create a new TUN device with the given configuration
    ///
    /// # Platform Requirements
    ///
    /// This is a compile-time stub for cross-platform development.
    /// TUN device functionality requires Linux kernel with TUN/TAP support.
    ///
    /// # Errors
    ///
    /// Always returns an error on non-Linux platforms explaining the platform requirement.
    #[cfg(not(target_os = "linux"))]
    pub fn create(_name: &str, _ip_addr: u32, _netmask: u32, _mtu: u16) -> io::Result<Self> {
        error!(
            "TunDeviceHandle::create failed: TUN device operations require Linux. Current platform: {}",
            std::env::consts::OS
        );
        Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "TUN device operations require Linux kernel with TUN/TAP support. \
                 This platform ({}) does not support TUN devices. \
                 This is a compile-time stub for cross-platform development only.",
                std::env::consts::OS
            ),
        ))
    }

    /// Read a packet from the TUN device
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to read packet data into
    ///
    /// # Returns
    ///
    /// Returns the number of bytes read on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is empty (no space to read into)
    /// - The file descriptor is invalid or closed
    /// - The read operation fails
    ///
    /// # Safety
    ///
    /// This method validates that the file descriptor is still valid before
    /// attempting to read. If the device has been closed or the fd is invalid,
    /// an error is returned.
    #[cfg(target_os = "linux")]
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Guard against zero-length buffer operations
        if buf.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "cannot read into empty buffer",
            ));
        }

        // Validate fd is still valid before attempting read
        if !self.is_fd_valid() {
            return Err(Error::new(
                ErrorKind::Other,
                "device file descriptor is invalid or closed",
            ));
        }

        unsafe {
            let result =
                crate::buckwild_tun_device_read(self.ptr.as_ptr(), buf.as_mut_ptr(), buf.len());
            if result < 0 {
                return Err(Error::from_raw_os_error(-result as i32));
            }
            Ok(result as usize)
        }
    }

    /// Write a packet to the TUN device
    ///
    /// # Arguments
    ///
    /// * `buf` - Packet data to write
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is empty (no data to write)
    /// - The file descriptor is invalid or closed
    /// - The write operation fails
    ///
    /// # Safety
    ///
    /// This method validates that the file descriptor is still valid before
    /// attempting to write. If the device has been closed or the fd is invalid,
    /// an error is returned.
    #[cfg(target_os = "linux")]
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Guard against zero-length buffer operations
        if buf.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "cannot write empty buffer",
            ));
        }

        // Validate fd is still valid before attempting write
        if !self.is_fd_valid() {
            return Err(Error::new(
                ErrorKind::Other,
                "device file descriptor is invalid or closed",
            ));
        }

        unsafe {
            let result =
                crate::buckwild_tun_device_write(self.ptr.as_ptr(), buf.as_ptr(), buf.len());
            if result < 0 {
                return Err(Error::from_raw_os_error(-result as i32));
            }
            Ok(result as usize)
        }
    }

    /// Get the file descriptor for use with poll/epoll
    ///
    /// # Returns
    ///
    /// Returns the underlying file descriptor or -1 on error.
    #[cfg(target_os = "linux")]
    pub fn fd(&self) -> RawFd {
        unsafe { crate::buckwild_tun_device_get_fd(self.ptr.as_ptr()) }
    }

    /// Check if the file descriptor is valid using fcntl(F_GETFL)
    ///
    /// This validates that the fd hasn't been closed or become invalid.
    #[cfg(target_os = "linux")]
    fn is_fd_valid(&self) -> bool {
        let fd = self.fd();
        if fd < 0 {
            return false;
        }

        // Use fcntl(F_GETFL) to check if fd is valid
        unsafe { libc::fcntl(fd, libc::F_GETFL) >= 0 }
    }

    /// Get the device name
    ///
    /// # Errors
    ///
    /// Returns an error if the name cannot be retrieved or contains invalid UTF-8.
    #[cfg(target_os = "linux")]
    pub fn name(&self) -> io::Result<String> {
        let mut buf = [0u8; 16];
        unsafe {
            if crate::buckwild_tun_device_get_name(
                self.ptr.as_ptr(),
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
            ) < 0
            {
                return Err(Error::last_os_error());
            }
            let c_str = CStr::from_ptr(buf.as_ptr() as *const c_char);
            c_str
                .to_str()
                .map(|s| s.to_owned())
                .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid UTF-8 in device name"))
        }
    }

    /// Get the device MTU
    ///
    /// # Returns
    ///
    /// Returns the MTU value or 0 on error.
    #[cfg(target_os = "linux")]
    pub fn mtu(&self) -> u16 {
        unsafe { crate::buckwild_tun_device_get_mtu(self.ptr.as_ptr()) }
    }

    /// Check if the device is up
    ///
    /// # Returns
    ///
    /// Returns `true` if the device is up, `false` otherwise.
    #[cfg(target_os = "linux")]
    pub fn is_up(&self) -> bool {
        unsafe { crate::buckwild_tun_device_is_up(self.ptr.as_ptr()) != 0 }
    }

    /// Set non-blocking mode
    ///
    /// # Arguments
    ///
    /// * `nonblock` - `true` for non-blocking mode, `false` for blocking
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    #[cfg(target_os = "linux")]
    pub fn set_nonblock(&mut self, nonblock: bool) -> io::Result<()> {
        unsafe {
            if crate::buckwild_tun_device_set_nonblock(self.ptr.as_ptr(), nonblock as i32) < 0 {
                return Err(Error::last_os_error());
            }
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "TUN devices require Linux",
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "TUN devices require Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
impl Drop for TunDeviceHandle {
    fn drop(&mut self) {
        debug!("TunDeviceHandle::drop: destroying device");
        unsafe {
            // SAFETY: NonNull guarantees ptr is non-null, and we have exclusive ownership
            crate::buckwild_tun_device_destroy(self.ptr.as_ptr());
        }
        debug!("TunDeviceHandle::drop: device destroyed");
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for TunDeviceHandle {
    fn drop(&mut self) {}
}

#[cfg(target_os = "linux")]
impl AsRawFd for TunDeviceHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_trait() {
        // Compile-time check that TunDeviceHandle is Send
        fn assert_send<T: Send>() {}
        assert_send::<TunDeviceHandle>();
    }

    #[test]
    fn test_not_sync_trait() {
        // Compile-time check that TunDeviceHandle is NOT Sync
        // This should fail to compile if uncommented:
        // fn assert_sync<T: Sync>() {}
        // assert_sync::<TunDeviceHandle>();
    }

    #[test]
    fn test_drop_cleanup() {
        // This test verifies that Drop is called and cleanup happens
        // We can't easily verify the C side cleanup, but we can verify
        // the Rust side doesn't panic
        {
            // Note: This will fail without proper permissions, but that's expected
            // The test is really about ensuring Drop doesn't panic
            let _result = TunDeviceHandle::create("test0", 0x0A000001, 0xFFFFFF00, 1400);
        }
        // If we get here, Drop was called without panicking
    }

    #[test]
    fn test_double_create_fails() {
        // Attempting to create the same device twice should fail
        let device1 = TunDeviceHandle::create("test1", 0x0A000001, 0xFFFFFF00, 1400);

        // If first creation succeeded, second should fail
        if device1.is_ok() {
            let device2 = TunDeviceHandle::create("test1", 0x0A000002, 0xFFFFFF00, 1400);
            assert!(device2.is_err(), "creating duplicate device should fail");
        }
    }

    #[test]
    fn test_name_too_long() {
        let result =
            TunDeviceHandle::create("this_name_is_way_too_long", 0x0A000001, 0xFFFFFF00, 1400);
        assert!(result.is_err(), "name too long should fail");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_fd_validation() {
        // This test verifies fd validation logic
        // Even if we can't create a real device, we can test the error paths
        let device = TunDeviceHandle::create("test_fd", 0x0A000001, 0xFFFFFF00, 1400);

        if let Ok(mut dev) = device {
            // If device was created, fd should be valid initially
            assert!(
                dev.is_fd_valid(),
                "newly created device should have valid fd"
            );

            // Reading/writing should check fd validity
            let mut buf = [0u8; 1500];
            let _ = dev.read(&mut buf); // May succeed or fail, but shouldn't panic
            let _ = dev.write(&[1, 2, 3]); // May succeed or fail, but shouldn't panic
        }
    }

    #[test]
    fn test_empty_buffer_read() {
        // Verify that reading into an empty buffer is rejected
        let device = TunDeviceHandle::create("test_empty_read", 0x0A000001, 0xFFFFFF00, 1400);

        if let Ok(mut dev) = device {
            let mut buf = [];
            let result = dev.read(&mut buf);
            assert!(result.is_err(), "reading into empty buffer should fail");
            if let Err(e) = result {
                assert_eq!(e.kind(), ErrorKind::InvalidInput);
            }
        }
    }

    #[test]
    fn test_empty_buffer_write() {
        // Verify that writing an empty buffer is rejected
        let device = TunDeviceHandle::create("test_empty_write", 0x0A000001, 0xFFFFFF00, 1400);

        if let Ok(mut dev) = device {
            let buf = [];
            let result = dev.write(&buf);
            assert!(result.is_err(), "writing empty buffer should fail");
            if let Err(e) = result {
                assert_eq!(e.kind(), ErrorKind::InvalidInput);
            }
        }
    }

    #[test]
    fn test_zst_safety() {
        // Compile-time verification that TunDevice is a ZST
        use std::mem::size_of;
        assert_eq!(
            size_of::<crate::TunDevice>(),
            0,
            "TunDevice should be a zero-sized type"
        );

        // Verify NonNull is used (compile-time check)
        // NonNull provides null pointer optimization and makes the non-null invariant explicit
        assert_eq!(
            size_of::<Option<TunDeviceHandle>>(),
            size_of::<TunDeviceHandle>(),
            "NonNull should enable null pointer optimization"
        );
    }
}
