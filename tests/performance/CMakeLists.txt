# Performance tests CMake configuration

message(STATUS "    Building performance tests:")

# Add Rust performance test target (benchmarks)
message(STATUS "      - Rust performance benchmarks")
add_custom_target(rust_performance_tests
    COMMAND cargo bench --manifest-path ${CMAKE_SOURCE_DIR}/src/common/Cargo.toml
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running Rust performance benchmarks"
)