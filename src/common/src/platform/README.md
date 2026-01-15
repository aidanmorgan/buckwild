# Platform Abstraction Layer

This module provides a unified interface for OS-specific functionality, with real implementations on Linux and stub implementations on other platforms.

## Design Principles

1. **Compile-time platform detection**: Use `#[cfg(target_os = "linux")]` to select implementations at compile time
2. **Clear error messages**: Non-Linux platforms return descriptive errors explaining platform requirements
3. **Zero runtime overhead**: No runtime checks, all platform selection happens at compile time
4. **Type safety**: Traits define platform-agnostic interfaces

## Module Structure

```
platform/
├── mod.rs              # Module exports and documentation
├── capabilities.rs     # Compile-time capability detection
├── error.rs           # Platform-specific error types
├── tun.rs             # TUN device abstraction (re-exports from network::tun)
└── ebpf.rs            # eBPF abstraction (Linux-only)
```

## Supported Platforms

| Platform | TUN Support | eBPF Support | Status |
|----------|-------------|--------------|--------|
| Linux    | ✓           | ✓            | Full support |
| macOS    | ✗           | ✗            | Stub implementations |
| Windows  | ✗           | ✗            | Stub implementations |
| Other    | ✗           | ✗            | Stub implementations |

## Usage

### Checking Platform Capabilities

```rust
use buckwild_common::platform::PlatformCapabilities;

if PlatformCapabilities::has_tun_support() {
    println!("TUN devices are supported");
}

if PlatformCapabilities::has_ebpf_support() {
    println!("eBPF is supported");
}

if PlatformCapabilities::is_fully_supported() {
    println!("All buckwild features are available");
}
```

### Using TUN Devices

```rust
use buckwild_common::platform::tun::{self, TunConfig, TunDevice};

// Check support before attempting to create device
if let Err(e) = tun::verify_support() {
    eprintln!("TUN not supported: {}", e);
    return;
}

// Create TUN device (will fail on non-Linux platforms)
let config = TunConfig::new(/* ... */);
let device = tun::LinuxTunHandle::create(config).await?;
```

### Using eBPF (Linux only)

```rust
#[cfg(target_os = "linux")]
use buckwild_common::platform::ebpf;

#[cfg(target_os = "linux")]
fn setup_ebpf() {
    if let Err(e) = ebpf::verify_support() {
        eprintln!("eBPF not supported: {}", e);
        return;
    }

    // eBPF functionality is in buckwild-ebpf crate
    // This module just provides capability detection
}
```

## Error Handling

The platform module defines clear error types for unsupported platforms:

```rust
use buckwild_common::platform::{PlatformError, PlatformResult};

fn require_linux_feature() -> PlatformResult<()> {
    tun::verify_support()?;
    // Feature implementation here
    Ok(())
}
```

Errors include:
- `UnsupportedPlatform`: Feature requires Linux but running on different OS
- `InsufficientKernelVersion`: Feature requires newer kernel version
- `InsufficientCapabilities`: Feature requires specific Linux capabilities
- `DetectionFailed`: Platform detection failed

## Conditional Compilation

The platform abstraction uses Rust's `cfg` attributes for conditional compilation:

```rust
// Linux-specific code
#[cfg(target_os = "linux")]
mod linux_impl {
    // Full implementation using kernel APIs
}

// Non-Linux stub
#[cfg(not(target_os = "linux"))]
mod stub_impl {
    // Stub that returns errors
}
```

This ensures:
- Clean compilation on all platforms
- No runtime overhead for platform checks
- Clear compile-time errors when using Linux-only APIs

## Testing

The platform module includes comprehensive tests:

```rust
#[test]
#[cfg(target_os = "linux")]
fn test_linux_capabilities() {
    assert!(PlatformCapabilities::has_tun_support());
    assert!(PlatformCapabilities::has_ebpf_support());
}

#[test]
#[cfg(not(target_os = "linux"))]
fn test_non_linux_capabilities() {
    assert!(!PlatformCapabilities::has_tun_support());
    assert!(!PlatformCapabilities::has_ebpf_support());
}
```

Run tests with:
```bash
cargo test --package buckwild-common --test platform_test
```

## Integration with Existing Code

This module consolidates existing platform-specific patterns:

1. **TUN devices**: Already had `#[cfg(target_os = "linux")]` in `network/tun/device.rs`
2. **eBPF**: Already had platform stubs in `buckwild-ebpf/src/lib.rs`

The platform module provides:
- A single place to check platform capabilities
- Consistent error messages across all platform-specific features
- Clear documentation of platform requirements

## Future Extensions

The platform module can be extended to support:
- Kernel version detection
- Capability detection (CAP_NET_ADMIN, CAP_BPF)
- Feature-specific checks (e.g., XDP availability)
- Runtime platform information

To add a new platform-specific feature:

1. Add a capability check to `capabilities.rs`
2. Add error variants to `error.rs` if needed
3. Create a module (e.g., `my_feature.rs`) with Linux and stub implementations
4. Re-export from `mod.rs`
