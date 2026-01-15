// Build script for buckwild-ebpf
//
// Compiles C logic wrapper library for FFI integration

fn main() {
    #[cfg(target_os = "linux")]
    {
        use std::env;
        use std::path::PathBuf;

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

        // Compile the C logic wrapper library
        cc::Build::new()
            .file("c_wrapper/logic_wrapper.c")
            .opt_level(2)
            .flag("-Wall")
            .flag("-Wextra")
            .flag("-std=c11")
            .warnings_into_errors(false)
            .compile("buckwild_logic");

        // Tell Cargo to link the library
        println!("cargo:rustc-link-lib=static=buckwild_logic");
        println!("cargo:rustc-link-search=native={}", out_dir.display());

        // Rerun if wrapper changes
        println!("cargo:rerun-if-changed=c_wrapper/logic_wrapper.c");

        // Also watch the header files in case they change
        println!("cargo:rerun-if-changed=../../ebpf/c/include/logic/packet_detection.h");
        println!("cargo:rerun-if-changed=../../ebpf/c/include/logic/header_parsing.h");
        println!("cargo:rerun-if-changed=../../ebpf/c/include/logic/session_validation.h");
        println!("cargo:rerun-if-changed=../../ebpf/c/include/logic/port_calculation.h");
        println!("cargo:rerun-if-changed=../../ebpf/c/include/logic/security_checks.h");
    }
}
