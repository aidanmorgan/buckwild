//! Platform capability detection
//!
//! This module provides compile-time and runtime detection of platform capabilities
//! for TUN devices, eBPF, and other OS-specific features.

/// Platform capability detection
///
/// This struct provides compile-time information about which features are available
/// on the current platform. All methods are const fn to enable compile-time evaluation.
pub struct PlatformCapabilities;

impl PlatformCapabilities {
    /// Check if TUN device support is available
    ///
    /// Returns `true` on Linux, `false` on other platforms.
    #[must_use]
    pub const fn has_tun_support() -> bool {
        cfg!(target_os = "linux")
    }

    /// Check if eBPF support is available
    ///
    /// Returns `true` on Linux, `false` on other platforms.
    #[must_use]
    pub const fn has_ebpf_support() -> bool {
        cfg!(target_os = "linux")
    }

    /// Check if rtnetlink support is available
    ///
    /// Returns `true` on Linux, `false` on other platforms.
    #[must_use]
    pub const fn has_rtnetlink_support() -> bool {
        cfg!(target_os = "linux")
    }

    /// Get the current platform name
    ///
    /// Returns a string identifying the current platform (e.g., "linux", "macos", "windows").
    #[must_use]
    pub const fn platform_name() -> &'static str {
        std::env::consts::OS
    }

    /// Check if all buckwild features are supported
    ///
    /// Returns `true` if the platform supports all required features (TUN + eBPF).
    #[must_use]
    pub const fn is_fully_supported() -> bool {
        Self::has_tun_support() && Self::has_ebpf_support()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        // These should be consistent with compile target
        #[cfg(target_os = "linux")]
        {
            assert!(PlatformCapabilities::has_tun_support());
            assert!(PlatformCapabilities::has_ebpf_support());
            assert!(PlatformCapabilities::has_rtnetlink_support());
            assert!(PlatformCapabilities::is_fully_supported());
            assert_eq!(PlatformCapabilities::platform_name(), "linux");
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(!PlatformCapabilities::has_tun_support());
            assert!(!PlatformCapabilities::has_ebpf_support());
            assert!(!PlatformCapabilities::has_rtnetlink_support());
            assert!(!PlatformCapabilities::is_fully_supported());
            assert_ne!(PlatformCapabilities::platform_name(), "linux");
        }
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_const_fn() {
        // Verify that capability checks can be evaluated at compile time
        const TUN_SUPPORTED: bool = PlatformCapabilities::has_tun_support();
        const EBPF_SUPPORTED: bool = PlatformCapabilities::has_ebpf_support();
        const FULLY_SUPPORTED: bool = PlatformCapabilities::is_fully_supported();
        const PLATFORM: &str = PlatformCapabilities::platform_name();

        // These assertions verify the const fn works
        #[cfg(target_os = "linux")]
        {
            assert!(TUN_SUPPORTED);
            assert!(EBPF_SUPPORTED);
            assert!(FULLY_SUPPORTED);
            assert_eq!(PLATFORM, "linux");
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(!TUN_SUPPORTED);
            assert!(!EBPF_SUPPORTED);
            assert!(!FULLY_SUPPORTED);
            assert_ne!(PLATFORM, "linux");
        }
    }
}
