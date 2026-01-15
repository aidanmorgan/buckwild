# Integration tests CMake configuration

message(STATUS "    Building integration tests:")

# Add Rust integration test target
message(STATUS "      - Rust integration tests")
add_custom_target(rust_integration_tests
    COMMAND cargo test --test '*' --manifest-path ${CMAKE_SOURCE_DIR}/src/common/Cargo.toml
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running Rust integration tests"
)