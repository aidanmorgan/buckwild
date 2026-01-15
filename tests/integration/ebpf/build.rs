// Build script for C test helpers
//
// This compiles the C test helper library and links it to Rust integration tests

use std::env;
use std::path::PathBuf;

fn main() {
    // Get the directory containing the C source
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let c_source = PathBuf::from(&manifest_dir)
        .join("tests/integration/ebpf/c_test_helper.c");

    // Compile the C helper library
    cc::Build::new()
        .file(&c_source)
        .warnings(true)
        .flag("-std=c11")
        .flag("-O2")
        .compile("c_test_helper");

    // Tell cargo to recompile if the C source changes
    println!("cargo:rerun-if-changed={}", c_source.display());

    // Link instructions
    println!("cargo:rustc-link-lib=static=c_test_helper");
}
