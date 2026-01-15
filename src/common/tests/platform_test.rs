//! Integration test for platform abstraction layer

use buckwild_common::platform::{PlatformCapabilities, PlatformError};

#[test]
fn test_platform_capabilities() {
    // Test that platform capabilities can be queried
    let _tun_supported = PlatformCapabilities::has_tun_support();
    let _ebpf_supported = PlatformCapabilities::has_ebpf_support();
    let _rtnetlink_supported = PlatformCapabilities::has_rtnetlink_support();
    let _fully_supported = PlatformCapabilities::is_fully_supported();
    let _platform = PlatformCapabilities::platform_name();
}

#[test]
fn test_platform_name() {
    // Verify platform name matches compile target
    assert_eq!(PlatformCapabilities::platform_name(), std::env::consts::OS);
}

#[test]
#[cfg(target_os = "linux")]
fn test_linux_capabilities() {
    // On Linux, all features should be supported
    assert!(PlatformCapabilities::has_tun_support());
    assert!(PlatformCapabilities::has_ebpf_support());
    assert!(PlatformCapabilities::is_fully_supported());
}

#[test]
#[cfg(not(target_os = "linux"))]
fn test_non_linux_capabilities() {
    // On non-Linux platforms, features should not be supported
    assert!(!PlatformCapabilities::has_tun_support());
    assert!(!PlatformCapabilities::has_ebpf_support());
    assert!(!PlatformCapabilities::is_fully_supported());
}

#[test]
fn test_platform_error_unsupported() {
    let err = PlatformError::UnsupportedPlatform {
        feature: "TUN".to_string(),
        current_platform: "macos".to_string(),
    };

    let msg = err.to_string();
    assert!(msg.contains("TUN"));
    assert!(msg.contains("macos"));
}
