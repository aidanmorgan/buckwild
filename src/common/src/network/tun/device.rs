//! TUN device implementation for Linux
//!
//! This module provides the platform-specific TUN device implementation
//! following the Test-Driven Development approach specified in
//! TUN_EBPF_IMPLEMENTATION_GUIDE.md.
//!
//! ## TDD Status: GREEN Phase
//!
//! Implementation passes tests 1.1-1.6 from TUN_EBPF_IMPLEMENTATION_GUIDE.md

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
use super::error::{TunError, TunResult};
use super::types::{DeviceName, Mtu, TunConfig};

#[cfg(target_os = "linux")]
use futures_util::TryStreamExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::{FromRawFd, RawFd};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(target_os = "linux")]
use tracing::instrument;

// Linux TUN/TAP constants
#[cfg(target_os = "linux")]
const TUNSETIFF: u64 = 0x400454ca;
#[cfg(target_os = "linux")]
const IFF_TUN: i16 = 0x0001;
#[cfg(target_os = "linux")]
const IFF_NO_PI: i16 = 0x1000;

/// Trait for TUN device operations
///
/// This trait defines the async interface for TUN device management
/// including creation, packet I/O, and lifecycle management.
#[async_trait::async_trait]
pub trait TunDevice: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// Create a new TUN device with the given configuration
    ///
    /// # Errors
    ///
    /// Returns `TunError` if device creation fails:
    /// - `InsufficientCapabilities` if CAP_NET_ADMIN is missing
    /// - `DeviceExists` if device name is already in use
    /// - `InvalidIpAddress` if IP configuration is invalid
    /// - `IoctlFailed` if ioctl operations fail
    /// - `NetlinkFailed` if rtnetlink operations fail
    async fn create(config: TunConfig) -> TunResult<Self>
    where
        Self: Sized;

    /// Read a packet from the TUN device
    ///
    /// Reads a single packet into the provided buffer.
    /// Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns `TunError::Io` if read fails
    async fn read_packet(&mut self, buf: &mut [u8]) -> TunResult<usize>;

    /// Write a packet to the TUN device
    ///
    /// Writes a single packet from the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns `TunError::Io` if write fails
    async fn write_packet(&mut self, buf: &[u8]) -> TunResult<()>;

    /// Get the device name
    fn name(&self) -> &DeviceName;

    /// Get the device MTU
    fn mtu(&self) -> Mtu;
}

/// Linux TUN device handle
///
/// Platform-specific implementation for Linux using ioctl and rtnetlink.
///
/// ## Requirements
///
/// - Requires CAP_NET_ADMIN capability
/// - Uses /dev/net/tun for device creation
/// - Uses rtnetlink for IP configuration
/// - Implements async I/O with tokio
///
/// ## Lifecycle
///
/// The device is automatically removed when the handle is dropped,
/// ensuring no resource leaks.
#[cfg(target_os = "linux")]
pub struct LinuxTunHandle {
    /// Device configuration
    config: TunConfig,
    /// Async file wrapper for tokio I/O operations
    file: tokio::fs::File,
    /// Raw file descriptor (stored for debugging and resource tracking)
    fd: RawFd,
}

#[cfg(not(target_os = "linux"))]
pub struct LinuxTunHandle {
    config: TunConfig,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for LinuxTunHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxTunHandle")
            .field("config", &self.config)
            .field("fd", &self.fd)
            .finish()
    }
}

#[cfg(not(target_os = "linux"))]
impl std::fmt::Debug for LinuxTunHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxTunHandle")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl LinuxTunHandle {
    /// Create a new Linux TUN device
    ///
    /// Implements REQ-TUN-001 through REQ-TUN-008 from TUN_EBPF_IMPLEMENTATION_GUIDE.md
    ///
    /// # Errors
    ///
    /// Returns appropriate `TunError` variants for different failure conditions
    #[instrument(name = "tun.create", skip(config), fields(device_name = %config.name))]
    pub async fn create(config: TunConfig) -> TunResult<Self> {
        // REQ-TUN-008: Check for CAP_NET_ADMIN
        if unsafe { libc::geteuid() } != 0 {
            // Not root - check if we have CAP_NET_ADMIN
            // For simplicity, we'll require root. A full implementation would use libcap.
            return Err(TunError::InsufficientCapabilities {
                capability: "CAP_NET_ADMIN required to create TUN device".to_string(),
            });
        }

        // REQ-TUN-001: Create TUN device using ioctl interface
        let fd = Self::open_tun_device(&config.name)?;

        // Convert to tokio File for async I/O
        let std_file = unsafe { std::fs::File::from_raw_fd(fd) };
        let file = tokio::fs::File::from_std(std_file);

        let mut handle = Self { config, file, fd };

        // REQ-TUN-002: Configure IP address, netmask, and MTU using rtnetlink
        handle.configure_device().await?;

        tracing::info!(
            device = %handle.config.name,
            ip = %handle.config.ip_address,
            mtu = handle.config.mtu.get(),
            "TUN device created successfully"
        );

        Ok(handle)
    }

    /// Open /dev/net/tun and create TUN device with ioctl
    ///
    /// REQ-TUN-001: Uses TUNSETIFF ioctl command
    #[instrument(skip(name), fields(device = %name))]
    fn open_tun_device(name: &DeviceName) -> TunResult<RawFd> {
        use std::ffi::CString;

        // Open /dev/net/tun
        let path = CString::new("/dev/net/tun").map_err(|e| TunError::Io {
            operation: "create CString for /dev/net/tun".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
        })?;

        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK, 0) };

        if fd < 0 {
            return Err(TunError::Io {
                operation: "open /dev/net/tun".to_string(),
                source: std::io::Error::last_os_error(),
            });
        }

        // Prepare ifreq structure for TUNSETIFF ioctl
        #[repr(C)]
        struct ifreq {
            ifr_name: [u8; libc::IFNAMSIZ],
            ifr_flags: i16,
            _pad: [u8; 22], // Padding to match kernel struct size
        }

        let mut req = ifreq {
            ifr_name: [0u8; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };

        // Copy device name into ifreq
        let name_bytes = name.as_str().as_bytes();
        req.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

        // Call TUNSETIFF ioctl
        let result = unsafe { libc::ioctl(fd, TUNSETIFF as libc::c_ulong, &req) };

        if result < 0 {
            unsafe { libc::close(fd) };
            let err = std::io::Error::last_os_error();

            // Check for specific error conditions
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Err(TunError::DeviceExists {
                    name: name.to_string(),
                });
            }

            // Convert OS error to nix::Error, using EINVAL if raw_os_error is None
            let errno = err
                .raw_os_error()
                .map(|e| nix::errno::Errno::from_raw(e))
                .unwrap_or(nix::errno::Errno::EINVAL);

            return Err(TunError::IoctlFailed {
                operation: "TUNSETIFF".to_string(),
                source: errno,
            });
        }

        Ok(fd)
    }

    /// Configure device IP address, netmask, MTU using rtnetlink
    ///
    /// REQ-TUN-002: Configure using rtnetlink protocol
    /// REQ-TUN-003: Set MTU accounting for protocol headers
    #[instrument(skip(self), fields(device = %self.config.name))]
    async fn configure_device(&mut self) -> TunResult<()> {
        use rtnetlink::new_connection;
        use std::net::IpAddr;

        // Create rtnetlink connection
        let (connection, handle, _) = new_connection().map_err(|e| TunError::Io {
            operation: "create rtnetlink connection".to_string(),
            source: e,
        })?;

        // Spawn connection in background
        tokio::spawn(connection);

        // Get link index for our device
        let link_index = self.get_link_index(&handle).await?;

        // Set device UP
        handle
            .link()
            .set(link_index)
            .up()
            .execute()
            .await
            .map_err(|e| TunError::NetlinkFailed {
                operation: "set device UP".to_string(),
                source: e,
            })?;

        // Configure IP address
        let prefix_len = self.config.prefix();
        match self.config.ip_address {
            IpAddr::V4(addr) => {
                handle
                    .address()
                    .add(link_index, addr.into(), prefix_len)
                    .execute()
                    .await
                    .map_err(|e| TunError::NetlinkFailed {
                        operation: "add IPv4 address".to_string(),
                        source: e,
                    })?;
            }
            IpAddr::V6(addr) => {
                handle
                    .address()
                    .add(link_index, addr.into(), prefix_len)
                    .execute()
                    .await
                    .map_err(|e| TunError::NetlinkFailed {
                        operation: "add IPv6 address".to_string(),
                        source: e,
                    })?;
            }
        }

        // Set MTU (REQ-TUN-003)
        handle
            .link()
            .set(link_index)
            .mtu(self.config.mtu.get() as u32)
            .execute()
            .await
            .map_err(|e| TunError::NetlinkFailed {
                operation: "set MTU".to_string(),
                source: e,
            })?;

        Ok(())
    }

    /// Get link index for device name
    #[instrument(skip(self, handle), fields(device = %self.config.name))]
    async fn get_link_index(&self, handle: &rtnetlink::Handle) -> TunResult<u32> {
        let mut links = handle
            .link()
            .get()
            .match_name(self.config.name.as_str().to_string())
            .execute();

        if let Some(link) = links
            .try_next()
            .await
            .map_err(|e| TunError::NetlinkFailed {
                operation: "get link by name".to_string(),
                source: e,
            })?
        {
            Ok(link.header.index)
        } else {
            Err(TunError::DeviceNotFound {
                name: self.config.name.to_string(),
            })
        }
    }

    /// Read packet from device
    ///
    /// REQ-TUN-004: Async packet read without blocking tokio runtime
    #[instrument(skip(self, buf), fields(device = %self.config.name))]
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> TunResult<usize> {
        use tokio::io::AsyncReadExt;

        self.file.read(buf).await.map_err(|e| TunError::Io {
            operation: "read packet from TUN device".to_string(),
            source: e,
        })
    }

    /// Write packet to device
    ///
    /// REQ-TUN-005: Async packet write without blocking tokio runtime
    #[instrument(skip(self, buf), fields(device = %self.config.name, len = buf.len()))]
    pub async fn write_packet(&mut self, buf: &[u8]) -> TunResult<()> {
        use tokio::io::AsyncWriteExt;

        self.file.write_all(buf).await.map_err(|e| TunError::Io {
            operation: "write packet to TUN device".to_string(),
            source: e,
        })
    }

    /// Get device name
    pub fn name(&self) -> &DeviceName {
        &self.config.name
    }

    /// Get device MTU
    pub fn mtu(&self) -> Mtu {
        self.config.mtu
    }
}

#[cfg(not(target_os = "linux"))]
impl LinuxTunHandle {
    pub async fn create(_config: TunConfig) -> TunResult<Self> {
        // Return error on non-Linux platforms
        Err(TunError::Io {
            operation: "create TUN device".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TUN devices only supported on Linux",
            ),
        })
    }

    pub async fn read_packet(&mut self, _buf: &mut [u8]) -> TunResult<usize> {
        Err(TunError::Io {
            operation: "read packet".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TUN devices only supported on Linux",
            ),
        })
    }

    pub async fn write_packet(&mut self, _buf: &[u8]) -> TunResult<()> {
        Err(TunError::Io {
            operation: "write packet".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TUN devices only supported on Linux",
            ),
        })
    }

    pub fn name(&self) -> &DeviceName {
        &self.config.name
    }

    pub fn mtu(&self) -> Mtu {
        self.config.mtu
    }
}

// Implement AsyncRead trait for tokio integration
#[cfg(target_os = "linux")]
impl AsyncRead for LinuxTunHandle {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

#[cfg(not(target_os = "linux"))]
impl AsyncRead for LinuxTunHandle {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN devices only supported on Linux",
        )))
    }
}

// Implement AsyncWrite trait for tokio integration
#[cfg(target_os = "linux")]
impl AsyncWrite for LinuxTunHandle {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.file).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.file).poll_shutdown(cx)
    }
}

#[cfg(not(target_os = "linux"))]
impl AsyncWrite for LinuxTunHandle {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN devices only supported on Linux",
        )))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

// REQ-TUN-006: Remove device on Drop
#[cfg(target_os = "linux")]
impl Drop for LinuxTunHandle {
    #[instrument(skip(self), fields(device = %self.config.name))]
    fn drop(&mut self) {
        // Close file descriptor
        // The tokio File will close the fd automatically, but we need to ensure
        // the device is removed from the network stack

        // Note: TUN devices are automatically removed when their fd is closed
        // on Linux, so we don't need explicit cleanup via rtnetlink

        tracing::info!(
            device = %self.config.name,
            "TUN device dropped, file descriptor closed"
        );

        // File descriptor cleanup happens automatically via tokio::fs::File Drop
    }
}

// Implement Send + Sync (required for tokio)
//
// SAFETY JUSTIFICATION for Send + Sync implementation:
//
// LinuxTunHandle is safe to Send and Sync because:
//
// 1. **Owned Resources**: All fields are owned by the struct:
//    - `config: TunConfig` - owned configuration struct
//    - `file: tokio::fs::File` - owned async file handle
//    - `fd: RawFd` - copy-only integer file descriptor (for debugging)
//
// 2. **No Shared Mutable State**: The struct has no interior mutability
//    (no RefCell, Cell, or raw pointers to shared state)
//
// 3. **Thread-Safe File Descriptor**: The underlying file descriptor is:
//    - Protected by tokio's async runtime
//    - Only accessed through tokio::fs::File which is Send + Sync
//    - Closed automatically on Drop (no manual fd management needed)
//
// 4. **No Race Conditions**: All mutable operations (&mut self methods)
//    require exclusive access enforced by Rust's borrow checker
//
// 5. **Tokio Compatibility**: Required for use in tokio::spawn and
//    async task boundaries
//
// This implementation follows the pattern established by tokio::fs::File
// and other async I/O primitives.
unsafe impl Send for LinuxTunHandle {}
unsafe impl Sync for LinuxTunHandle {}

// Implement TunDevice trait for LinuxTunHandle
#[async_trait::async_trait]
impl TunDevice for LinuxTunHandle {
    async fn create(config: TunConfig) -> TunResult<Self> {
        LinuxTunHandle::create(config).await
    }

    async fn read_packet(&mut self, buf: &mut [u8]) -> TunResult<usize> {
        self.read_packet(buf).await
    }

    async fn write_packet(&mut self, buf: &[u8]) -> TunResult<()> {
        self.write_packet(buf).await
    }

    fn name(&self) -> &DeviceName {
        self.name()
    }

    fn mtu(&self) -> Mtu {
        self.mtu()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_sizes() {
        // Verify LinuxTunHandle type exists and has expected layout
        assert!(std::mem::size_of::<LinuxTunHandle>() > 0);
    }

    #[test]
    fn test_send_sync() {
        // Verify LinuxTunHandle implements Send + Sync
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<LinuxTunHandle>();
        assert_sync::<LinuxTunHandle>();
    }
}
