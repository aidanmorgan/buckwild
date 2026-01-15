# Unit tests CMake configuration

message(STATUS "    Building unit tests:")

# Build C unit tests if they exist and not in RUST_ONLY mode
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c AND NOT RUST_ONLY)
    message(STATUS "      - C unit tests")
    add_subdirectory(c)
else()
    message(STATUS "      - C unit tests: SKIPPED (RUST_ONLY mode)")
endif()

# Add Rust unit test targets (integrated with CTest)
message(STATUS "      - Rust unit tests")

# Rust common library tests
add_test(
    NAME rust_common_tests
    COMMAND cargo test --lib --manifest-path ${CMAKE_SOURCE_DIR}/src/common/Cargo.toml
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(rust_common_tests PROPERTIES
    LABELS "rust;unit;common"
    TIMEOUT 300
)

# Rust eBPF library tests
add_test(
    NAME rust_ebpf_tests
    COMMAND cargo test --lib --manifest-path ${CMAKE_SOURCE_DIR}/src/ebpf/rust/Cargo.toml
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(rust_ebpf_tests PROPERTIES
    LABELS "rust;unit;ebpf"
    TIMEOUT 300
)

# Rust daemon library tests
# Note: Daemon tests need LD_LIBRARY_PATH to find shared libraries built by CMake
add_test(
    NAME rust_daemon_tests
    COMMAND cargo test --lib --manifest-path ${CMAKE_SOURCE_DIR}/src/daemon/rust/Cargo.toml
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(rust_daemon_tests PROPERTIES
    LABELS "rust;unit;daemon"
    TIMEOUT 300
    ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/src/common/c/network:${CMAKE_BINARY_DIR}/src/net/ssd:${CMAKE_BINARY_DIR}/src/common/c:$ENV{LD_LIBRARY_PATH}"
)

# Rust FFI integration tests
# Tests that verify Rust code can correctly call C code through the FFI boundary
# Note: These tests require libbuckwild_network.so to be built first
add_test(
    NAME rust_ffi_integration_tests
    COMMAND cargo test --manifest-path ${CMAKE_SOURCE_DIR}/src/common/ffi/Cargo.toml
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(rust_ffi_integration_tests PROPERTIES
    LABELS "rust;unit;ffi;integration"
    TIMEOUT 300
    ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/src/common/c/network:${CMAKE_BINARY_DIR}/src/net/ssd:${CMAKE_BINARY_DIR}/src/common/c:$ENV{LD_LIBRARY_PATH}"
)

# Convenience target to run all Rust tests (for backwards compatibility)
add_custom_target(rust_unit_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -L rust
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running all Rust unit tests via CTest"
)