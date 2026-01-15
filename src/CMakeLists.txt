# Source directory CMake configuration

# Include build utilities
include(${CMAKE_SOURCE_DIR}/cmake/BuildRust.cmake)

# Build components in dependency order
message(STATUS "Building source components:")

# 1. Common library (foundation)
message(STATUS "  - Common library")
add_subdirectory(common)

# 2. eBPF programs (if enabled)
if(BUILD_EBPF)
    message(STATUS "  - eBPF programs")
    add_subdirectory(ebpf)
else()
    message(STATUS "  - eBPF programs (SKIPPED - BUILD_EBPF=OFF)")
endif()

# 3. Daemon
message(STATUS "  - Daemon")
add_subdirectory(daemon)

# 4. Tools
message(STATUS "  - Tools")
add_subdirectory(tools)

# 5. Network utilities
message(STATUS "  - Network utilities")
add_subdirectory(net)