use std::env;
use std::path::PathBuf;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    // Only generate bindings and link C library on Linux where the FFI is relevant
    if target_os == "linux" {
        generate_ffi_bindings();
        link_c_library();
    } else {
        println!(
            "cargo:warning=Skipping FFI bindings and C library linking for {} (Linux-only features)",
            target_os
        );
    }
}

fn generate_ffi_bindings() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // Navigate to project root: daemon/rust -> daemon -> src -> root
    let project_root = PathBuf::from(&manifest_dir)
        .parent()
        .expect("Failed to get parent directory")
        .parent()
        .expect("Failed to get parent directory")
        .parent()
        .expect("Failed to get parent directory")
        .to_path_buf();

    let include_dir = project_root.join("include/buckwild/ffi");

    // Verify headers exist
    let types_header = include_dir.join("types.h");
    let tun_header = include_dir.join("tun_device.h");
    let ebpf_header = include_dir.join("ebpf_loader.h");

    if !types_header.exists() {
        panic!("types.h not found at {:?}", types_header);
    }
    if !tun_header.exists() {
        panic!("tun_device.h not found at {:?}", tun_header);
    }
    if !ebpf_header.exists() {
        panic!("ebpf_loader.h not found at {:?}", ebpf_header);
    }

    // Create a wrapper header that includes all FFI headers
    let wrapper_header = format!(
        r#"
#include "{}/types.h"
#include "{}/tun_device.h"
#include "{}/ebpf_loader.h"
"#,
        include_dir.display(),
        include_dir.display(),
        include_dir.display()
    );

    let bindings = bindgen::Builder::default()
        // Use wrapper header content
        .header_contents("wrapper.h", &wrapper_header)
        // Add include directory for header resolution
        .clang_arg(format!("-I{}", include_dir.display()))
        // Generate bindings for all FFI types and functions
        .allowlist_type("Buckwild.*")
        .allowlist_function("buckwild_.*")
        .allowlist_var("BUCKWILD_.*")
        // Derive common traits
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_partialeq(true)
        // Use Rust types for better ergonomics
        .use_core()
        .ctypes_prefix("::std::os::raw")
        // Parse callbacks for cargo integration
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Generate bindings
        .generate()
        .expect("Unable to generate FFI bindings");

    // Write bindings to OUT_DIR
    let out_path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings.rs");

    // Rerun if any header changes
    println!("cargo:rerun-if-changed={}", types_header.display());
    println!("cargo:rerun-if-changed={}", tun_header.display());
    println!("cargo:rerun-if-changed={}", ebpf_header.display());
}

fn link_c_library() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // Navigate to project root: daemon/rust -> daemon -> src -> root
    let project_root = PathBuf::from(&manifest_dir)
        .parent()
        .expect("Failed to get parent directory")
        .parent()
        .expect("Failed to get parent directory")
        .parent()
        .expect("Failed to get parent directory")
        .to_path_buf();

    // Look for the static library in the CMake build directory
    // Try multiple possible build directories
    let possible_lib_dirs = vec![
        project_root.join("build/lib"),
        project_root.join("build_ebpf/lib"),
        project_root.join("target/lib"),
    ];

    let mut lib_path = None;
    for dir in &possible_lib_dirs {
        let candidate = dir.join("libbuckwild_c.a");
        if candidate.exists() {
            lib_path = Some(dir.clone());
            break;
        }
    }

    if let Some(lib_dir) = lib_path {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=static=buckwild_c");

        // Also need to link transitive dependencies
        // OpenSSL (for crypto)
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=ssl");

        // libbpf and its dependencies (for eBPF)
        println!("cargo:rustc-link-lib=elf");
        println!("cargo:rustc-link-lib=z");

        // Rerun if the library changes
        println!(
            "cargo:rerun-if-changed={}",
            lib_dir.join("libbuckwild_c.a").display()
        );
    } else {
        println!(
            "cargo:warning=C library not found in any build directory. \
             Run CMake build first: cmake -B build && cmake --build build"
        );
    }
}
