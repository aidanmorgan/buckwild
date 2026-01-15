cmake_minimum_required(VERSION 3.16)

# Force serial builds to prevent resource conflicts and crashes
# This can be overridden with: cmake --build build --parallel N
if(NOT DEFINED CMAKE_BUILD_PARALLEL_LEVEL)
    set(CMAKE_BUILD_PARALLEL_LEVEL 1 CACHE STRING "Number of parallel build jobs" FORCE)
endif()

# Parse RUST_ONLY option early
option(RUST_ONLY "Build only Rust components, skip C/C++ compilation" OFF)

# Set languages based on RUST_ONLY option
if(RUST_ONLY)
    project(buckwild VERSION 0.1.0)
    message(STATUS "RUST_ONLY mode enabled - skipping C/C++ compilation")
else()
    project(buckwild VERSION 0.1.0 LANGUAGES C CXX)
endif()

# Set C/C++ standards (only if not RUST_ONLY)
if(NOT RUST_ONLY)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)
endif()

# Add CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Include GNUInstallDirs for standard installation directories
include(GNUInstallDirs)

# Include Rust build functions
include(BuildRust)

# Include static analysis and sanitizer configurations (C/C++ only)
if(NOT RUST_ONLY)
    include(StaticAnalysis)
    include(Sanitizers)
endif()

# Find dependencies
find_package(Rust REQUIRED)

# C/C++ dependencies only if not RUST_ONLY
if(NOT RUST_ONLY)
    # Build external dependencies from submodules
    include(External)

    # PkgConfig for other dependencies
    find_package(PkgConfig REQUIRED)
endif()

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Build configuration options
option(BUILD_DAEMON "Build the Buckwild daemon" ON)
option(BUILD_TOOLS "Build command-line tools" ON)
option(BUILD_EBPF "Build eBPF programs" ON)
option(BUILD_TESTS "Build test suite" ON)
option(RUST_ONLY "Build only Rust components, skip C/C++ compilation" OFF)
option(ENABLE_SIMD "Enable SIMD optimizations" ON)
option(ENABLE_SECURITY_HARDENING "Enable security hardening features" ON)

# Set compiler flags (only if not RUST_ONLY)
if(NOT RUST_ONLY)
    if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -fPIC")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -fPIC")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
        
        # Security hardening flags
        if(ENABLE_SECURITY_HARDENING)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
            # -z relro/now only supported on Linux
            if(NOT APPLE)
                set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now")
            endif()
        endif()
    endif()
endif()

# SIMD detection and configuration (only if not RUST_ONLY)
if(ENABLE_SIMD AND NOT RUST_ONLY)
    include(CheckCSourceCompiles)
    
    # Check for AVX2 support
    check_c_source_compiles("
        #include <immintrin.h>
        int main() { __m256i v = _mm256_setzero_si256(); return 0; }
    " HAVE_AVX2)
    
    # Check for AVX512 support
    check_c_source_compiles("
        #include <immintrin.h>
        int main() { __m512i v = _mm512_setzero_si512(); return 0; }
    " HAVE_AVX512)
    
    if(HAVE_AVX2)
        add_compile_definitions(HAVE_AVX2=1)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2")
    endif()
    
    if(HAVE_AVX512)
        add_compile_definitions(HAVE_AVX512=1)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx512f")
    endif()
endif()

# Global include directories (only if not RUST_ONLY)
if(NOT RUST_ONLY)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}/include
    )

    # Create build info header
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_info.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/include/buckwild/build_info.h"
        @ONLY
    )
endif()

# Build components in dependency order
if(RUST_ONLY)
    message(STATUS "Building Buckwild Rust components only:")
    
    # 1. Build common library (Rust only)
    message(STATUS "  - Common library (Rust)")
    add_subdirectory(src/common)
    
    # 2. Build eBPF programs (if enabled)
    if(BUILD_EBPF)
        message(STATUS "  - eBPF programs (Rust)")
        add_subdirectory(src/ebpf)
    else()
        message(STATUS "  - eBPF programs (SKIPPED - BUILD_EBPF=OFF)")
    endif()

    # 3. Build daemon (Rust only)
    message(STATUS "  - Daemon (Rust)")
    add_subdirectory(src/daemon)
    
    # 4. Build tools (Rust only)
    message(STATUS "  - Command-line tools (Rust)")
    add_subdirectory(src/tools)
    
    # 5. Build tests (Rust only)
    if(BUILD_TESTS)
        message(STATUS "  - Test suite (Rust)")
        enable_testing()

        # Configure CTest to run tests serially (1 at a time)
        # Copy CTestCustom.cmake to build directory
        configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/CTestCustom.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake"
            COPYONLY
        )

        add_subdirectory(tests)
    endif()
    
    
else()
    message(STATUS "Building Buckwild components (Rust + C/C++):")
    
    # 1. Build common library (foundation for everything)
    message(STATUS "  - Common library (Rust + C)")
    add_subdirectory(src/common)

    # 2. Build eBPF programs (if enabled)
    if(BUILD_EBPF)
        message(STATUS "  - eBPF programs")
        add_subdirectory(src/ebpf)
    else()
        message(STATUS "  - eBPF programs (SKIPPED - BUILD_EBPF=OFF)")
    endif()

    # 3. Build daemon (depends on common)
    message(STATUS "  - Daemon")
    add_subdirectory(src/daemon)

    # 4. Build tools (depends on common)
    message(STATUS "  - Command-line tools")
    add_subdirectory(src/tools)

    # 5. Build network utilities
    message(STATUS "  - Network utilities")
    add_subdirectory(src/net)

    # 6. Build headers
    add_subdirectory(include)

    # 7. Build tests
    message(STATUS "  - Test suite")
    enable_testing()

    # Configure CTest to run tests serially (1 at a time)
    # Copy CTestCustom.cmake to build directory
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/CTestCustom.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake"
        COPYONLY
    )

    add_subdirectory(tests)

endif()

# ============================================================================
# Build Targets - Organized by language/component type
# ============================================================================

# ----------------------------------------------------------------------------
# Rust-only build targets
# ----------------------------------------------------------------------------
add_custom_target(all_rust
    COMMENT "Building all Rust components"
)

# Add Rust component dependencies
add_dependencies(all_rust
    buckwild_common_rust
    buckwild_daemon_rust
    buckwild_tools_rust
)

# Add Rust eBPF if it exists
if(TARGET buckwild_ebpf_rust)
    add_dependencies(all_rust buckwild_ebpf_rust)
endif()

# Convenient alias for rust-only builds
add_custom_target(rust_only
    DEPENDS all_rust
    COMMENT "Building Rust components only"
)

# ----------------------------------------------------------------------------
# C-only build targets (not available in RUST_ONLY mode)
# ----------------------------------------------------------------------------
if(NOT RUST_ONLY)
    add_custom_target(all_c
        COMMENT "Building all C/C++ components"
    )

    # Add C component dependencies
    add_dependencies(all_c buckwild_common_c)

    # Add C crypto component if it exists
    if(TARGET buckwild_common_crypto)
        add_dependencies(all_c buckwild_common_crypto)
    endif()

    # Add C network component if it exists
    if(TARGET buckwild_network)
        add_dependencies(all_c buckwild_network)
    endif()

    # Add C eBPF component if it exists
    if(TARGET buckwild_ebpf)
        add_dependencies(all_c buckwild_ebpf)
    endif()

    # Add unified C library if it exists
    if(TARGET buckwild_c)
        add_dependencies(all_c buckwild_c)
    endif()

    # Add network SSD utility if it exists
    if(TARGET buckwild_netssd)
        add_dependencies(all_c buckwild_netssd)
    endif()

    # Convenient alias for c-only builds
    add_custom_target(c_only
        DEPENDS all_c
        COMMENT "Building C/C++ components only"
    )

    # ----------------------------------------------------------------------------
    # eBPF-specific build target
    # ----------------------------------------------------------------------------
    add_custom_target(all_ebpf
        COMMENT "Building all eBPF programs"
    )

    # Add eBPF dependencies (both C and Rust)
    if(TARGET buckwild_ebpf_rust)
        add_dependencies(all_ebpf buckwild_ebpf_rust)
    endif()
    if(TARGET ebpf_programs)
        add_dependencies(all_ebpf ebpf_programs)
    endif()
    if(TARGET buckwild_ebpf)
        add_dependencies(all_ebpf buckwild_ebpf)
    endif()
endif()

# ----------------------------------------------------------------------------
# Comprehensive build targets
# ----------------------------------------------------------------------------
if(RUST_ONLY)
    add_custom_target(build_all
        DEPENDS all_rust
        COMMENT "Building all components (Rust only)"
    )

    # Alias: make everything
    add_custom_target(everything DEPENDS build_all)
else()
    add_custom_target(build_all
        DEPENDS all_rust all_c
        COMMENT "Building all components (Rust + C/C++)"
    )

    # Alias: make everything
    add_custom_target(everything DEPENDS build_all)

    # Build both languages separately but in sequence
    add_custom_target(build_by_lang
        COMMENT "Building all components by language"
    )
    add_dependencies(build_by_lang all_c all_rust)
endif()

# ----------------------------------------------------------------------------
# Test targets
# ----------------------------------------------------------------------------
if(BUILD_TESTS AND NOT RUST_ONLY)
    add_custom_target(all_tests
        DEPENDS all_c all_rust
        COMMENT "Building all test executables"
    )

    # Add test executable dependencies if they exist
    if(TARGET test_time_utils)
        add_dependencies(all_tests test_time_utils)
    endif()
    if(TARGET test_crypto)
        add_dependencies(all_tests test_crypto)
    endif()
    if(TARGET test_buffer)
        add_dependencies(all_tests test_buffer)
    endif()
    if(TARGET test_port_hopping)
        add_dependencies(all_tests test_port_hopping)
    endif()
endif()

# Installation configuration
set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Installation prefix")

# Install configuration files
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/config")
    install(DIRECTORY config/
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/buckwild
        COMPONENT config
    )
endif()

# Create package configuration
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/buckwild-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/buckwild-config.cmake"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/buckwild-config.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/buckwild
    COMPONENT development
)

# Create uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)

# Build summary
message(STATUS "")
if(RUST_ONLY)
    message(STATUS "Buckwild Build Configuration Summary (RUST ONLY MODE):")
    message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
    message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
    message(STATUS "  Parallel Build Jobs: ${CMAKE_BUILD_PARALLEL_LEVEL}")
    message(STATUS "  Rust Only Mode: ON")
    message(STATUS "  Build Daemon: ${BUILD_DAEMON}")
    message(STATUS "  Build Tools: ${BUILD_TOOLS}")
    message(STATUS "  Build eBPF: ${BUILD_EBPF}")
    message(STATUS "  Build Tests: ${BUILD_TESTS}")
    message(STATUS "  C/C++ Compilation: DISABLED")
    message(STATUS "  SIMD Support: DISABLED (Rust-only mode)")
    message(STATUS "  Security Hardening: DISABLED (Rust-only mode)")
else()
    message(STATUS "Buckwild Build Configuration Summary:")
    message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
    message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
    message(STATUS "  Parallel Build Jobs: ${CMAKE_BUILD_PARALLEL_LEVEL}")
    message(STATUS "  Rust Only Mode: OFF")
    message(STATUS "  Build Daemon: ${BUILD_DAEMON}")
    message(STATUS "  Build Tools: ${BUILD_TOOLS}")
    message(STATUS "  Build eBPF: ${BUILD_EBPF}")
    message(STATUS "  Build Tests: ${BUILD_TESTS}")
    message(STATUS "  SIMD Support: ${ENABLE_SIMD}")
    if(ENABLE_SIMD)
        message(STATUS "    AVX2: ${HAVE_AVX2}")
        message(STATUS "    AVX512: ${HAVE_AVX512}")
    endif()
    message(STATUS "  Security Hardening: ${ENABLE_SECURITY_HARDENING}")
endif()
message(STATUS "")