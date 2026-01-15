//! Platform-agnostic TUN device interface
//!
//! This module re-exports the TUN device implementation with platform-specific
//! behavior. On Linux, it provides full TUN device functionality. On other
//! platforms, it provides stub implementations that return appropriate errors.

// Re-export TUN types for convenience
pub use crate::network::tun::{
    DeviceName, LinuxTunHandle, ManagerError, ManagerResult, Mtu, TranslatorError,
    TranslatorResult, TunConfig, TunDevice, TunError, TunResult,
};

use super::{PlatformCapabilities, PlatformError, PlatformResult};

/// Check if TUN device support is available on this platform
///
/// This is a convenience wrapper around `PlatformCapabilities::has_tun_support()`.
#[must_use]
pub const fn is_supported() -> bool {
    PlatformCapabilities::has_tun_support()
}

/// Verify TUN support and return an error if unavailable
///
/// This function checks if TUN device support is available on the current
/// platform and returns a descriptive error if not.
///
/// # Errors
///
/// Returns `PlatformError::UnsupportedPlatform` if TUN devices are not
/// supported on the current platform.
pub fn verify_support() -> PlatformResult<()> {
    if is_supported() {
        Ok(())
    } else {
        Err(PlatformError::UnsupportedPlatform {
            feature: "TUN device".to_string(),
            current_platform: PlatformCapabilities::platform_name().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_support_detection() {
        #[cfg(target_os = "linux")]
        {
            assert!(is_supported());
            assert!(verify_support().is_ok());
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(!is_supported());
            assert!(verify_support().is_err());
            let err = verify_support().unwrap_err();
            assert!(err.to_string().contains("TUN device"));
            assert!(err.to_string().contains(std::env::consts::OS));
        }
    }
}
