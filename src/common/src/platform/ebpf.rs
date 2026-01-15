//! Platform-agnostic eBPF interface
//!
//! This module provides a platform-agnostic interface to eBPF functionality.
//! On Linux, it provides access to the full eBPF implementation from buckwild-ebpf.
//! On other platforms, it provides compile-time stubs.
//!
//! ## Note
//!
//! This module is only available on Linux (`#[cfg(target_os = "linux")]`).
//! Non-Linux platforms should use the `PlatformCapabilities::has_ebpf_support()`
//! check before attempting to use eBPF functionality.

use super::{PlatformCapabilities, PlatformError, PlatformResult};

/// Check if eBPF support is available on this platform
///
/// This is a convenience wrapper around `PlatformCapabilities::has_ebpf_support()`.
#[must_use]
pub const fn is_supported() -> bool {
    PlatformCapabilities::has_ebpf_support()
}

/// Verify eBPF support and return an error if unavailable
///
/// This function checks if eBPF support is available on the current platform
/// and returns a descriptive error if not.
///
/// # Errors
///
/// Returns `PlatformError::UnsupportedPlatform` if eBPF is not supported
/// on the current platform.
pub fn verify_support() -> PlatformResult<()> {
    if is_supported() {
        Ok(())
    } else {
        Err(PlatformError::UnsupportedPlatform {
            feature: "eBPF".to_string(),
            current_platform: PlatformCapabilities::platform_name().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_support_detection() {
        // eBPF is only supported on Linux
        assert!(is_supported());
        assert!(verify_support().is_ok());
    }
}
