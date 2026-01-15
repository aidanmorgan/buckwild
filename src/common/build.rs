// Build script for buckwild-common
//
// Emits cfg flags for platform-specific features

use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    // Emit platform detection cfg flags
    if target_os == "linux" {
        // Enable Linux-specific features automatically when building on Linux
        println!("cargo:rustc-cfg=platform_linux");

        // These features are available on Linux
        println!("cargo:rustc-cfg=has_tun_support");
        println!("cargo:rustc-cfg=has_ebpf_support");
        println!("cargo:rustc-cfg=has_rtnetlink_support");
    } else {
        // Non-Linux platforms: only stub implementations available
        println!(
            "cargo:warning=buckwild-common: Building with stubs for {target_os} (full features require Linux)"
        );
    }

    // Rerun if platform detection changes (this is mostly for documentation)
    println!("cargo:rerun-if-changed=build.rs");
}
