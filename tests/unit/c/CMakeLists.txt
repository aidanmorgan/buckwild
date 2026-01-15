# CMake configuration for C unit tests using Unity framework

cmake_minimum_required(VERSION 3.16)
project(buckwild_c_tests)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find Unity framework (we'll include it as a submodule or download)
include(FetchContent)

FetchContent_Declare(
    unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG v2.5.2
)

FetchContent_MakeAvailable(unity)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
    ${CMAKE_SOURCE_DIR}/src/common/c
    ${unity_SOURCE_DIR}/src
)

# Common test utilities
add_library(test_utils STATIC
    utils/test_utils.c
    utils/mock_helpers.c
)

target_link_libraries(test_utils unity)

# Common utilities tests (time, buffer, etc.)
add_subdirectory(common)

# eBPF C code tests (if enabled)
if(BUILD_EBPF)
    add_subdirectory(ebpf)
endif()

# Crypto C code tests
add_subdirectory(crypto)

# Network utilities tests
add_subdirectory(network)

# Enable testing
enable_testing()

# Add a custom target to run all C tests
add_custom_target(run_c_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -j1 --verbose
    DEPENDS
        test_ebpf_xdp
        test_ebpf_tc
        test_crypto_simd
        test_network_utils
    COMMENT "Running all C unit tests (serial execution)"
)