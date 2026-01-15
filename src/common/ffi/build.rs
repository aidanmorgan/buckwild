use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_os == "linux" {
        // Link against the shared C library
        // The library is built by CMake and should be available in the build output
        println!("cargo:rustc-link-lib=dylib=buckwild_network");

        // Add library search path if BUILD_DIR is set (for CMake integration)
        if let Ok(build_dir) = env::var("BUILD_DIR") {
            println!(
                "cargo:rustc-link-search=native={}/src/common/c/network",
                build_dir
            );
        }

        // Also check standard CMake build directories
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let project_root = std::path::Path::new(&manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap();

        println!(
            "cargo:rustc-link-search=native={}/build/src/common/c/network",
            project_root.display()
        );
        println!(
            "cargo:rustc-link-search=native={}/cmake-build-debug/src/common/c/network",
            project_root.display()
        );
        println!(
            "cargo:rustc-link-search=native={}/cmake-build-release/src/common/c/network",
            project_root.display()
        );

        // Rerun if the C header changes
        println!("cargo:rerun-if-changed=../../../include/buckwild/network/tun_device_ffi.h");
    } else {
        // Non-Linux platforms: provide stub implementations via Rust code
        // No C library linking required
        println!(
            "cargo:warning=buckwild-ffi: Building stubs for {} (TUN devices require Linux)",
            target_os
        );
    }
}
