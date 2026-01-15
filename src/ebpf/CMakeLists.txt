# eBPF CMake configuration

message(STATUS "    Building eBPF components:")

# Find required packages for eBPF compilation
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF libbpf)

if(NOT LIBBPF_FOUND)
    message(WARNING "LibBPF not found - eBPF programs will not be compiled")
    return()
endif()

# Find clang for eBPF compilation
find_program(CLANG_EXECUTABLE clang REQUIRED)
find_program(LLC_EXECUTABLE llc)
find_program(LLVM_STRIP_EXECUTABLE llvm-strip)

# eBPF compilation flags with security optimizations
set(EBPF_CFLAGS
    -O2
    -g
    -Wall
    -Wextra
    -Werror
    -target bpf
    -D__TARGET_ARCH_x86
    -I${CMAKE_CURRENT_SOURCE_DIR}/c/include
    -I${LIBBPF_INCLUDE_DIRS}
    -fno-stack-protector
    -fno-jump-tables
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
)

# Security-specific compilation flags
if(ENABLE_SECURITY_HARDENING)
    list(APPEND EBPF_CFLAGS
        -DSECURITY_HARDENING=1
        -DFRAGMENT_SECURITY=1
        -DANTI_REPLAY_PROTECTION=1
        -DATTACK_DETECTION=1
        -DRATE_LIMITING=1
    )
endif()

# BTF generation flags for CO-RE support
set(EBPF_BTF_CFLAGS
    -g
    -gdwarf-4
)

# Function to compile eBPF programs with security features
function(compile_ebpf_program)
    cmake_parse_arguments(EBPF "" "NAME;SOURCE;OUTPUT_DIR" "DEPENDS" ${ARGN})
    
    if(NOT EBPF_NAME)
        message(FATAL_ERROR "eBPF program name is required")
    endif()
    
    if(NOT EBPF_SOURCE)
        message(FATAL_ERROR "eBPF source file is required")
    endif()
    
    if(NOT EBPF_OUTPUT_DIR)
        set(EBPF_OUTPUT_DIR ${CMAKE_BINARY_DIR}/lib/bpf)
    endif()
    
    # Create output directory
    file(MAKE_DIRECTORY ${EBPF_OUTPUT_DIR})
    
    # Set output file paths
    set(EBPF_OBJECT ${EBPF_OUTPUT_DIR}/${EBPF_NAME}.o)
    set(EBPF_BTF ${EBPF_OUTPUT_DIR}/${EBPF_NAME}.btf)
    
    # Compile eBPF program with security features
    add_custom_command(
        OUTPUT ${EBPF_OBJECT}
        COMMAND ${CLANG_EXECUTABLE}
            ${EBPF_CFLAGS}
            ${EBPF_BTF_CFLAGS}
            -c ${EBPF_SOURCE}
            -o ${EBPF_OBJECT}
        DEPENDS ${EBPF_SOURCE} ${EBPF_DEPENDS}
        COMMENT "Compiling eBPF program ${EBPF_NAME} with security features"
        VERBATIM
    )
    
    # Generate BTF information for CO-RE support
    # Use llvm-objcopy to extract BTF section (more portable than llvm-strip)
    find_program(LLVM_OBJCOPY_EXECUTABLE NAMES llvm-objcopy llvm-objcopy-14 llvm-objcopy-15 llvm-objcopy-16)
    if(LLVM_OBJCOPY_EXECUTABLE)
        add_custom_command(
            OUTPUT ${EBPF_BTF}
            COMMAND ${LLVM_OBJCOPY_EXECUTABLE}
                --only-section=.BTF
                --set-section-flags .BTF=alloc
                -O binary
                ${EBPF_OBJECT}
                ${EBPF_BTF}
            DEPENDS ${EBPF_OBJECT}
            COMMENT "Generating BTF information for ${EBPF_NAME}"
            VERBATIM
        )
        set(BTF_TARGET ${EBPF_BTF})
    else()
        message(WARNING "llvm-objcopy not found, BTF generation disabled")
        set(BTF_TARGET "")
    endif()
    
    # Create target for eBPF program
    add_custom_target(${EBPF_NAME}_ebpf
        DEPENDS ${EBPF_OBJECT} ${BTF_TARGET}
    )
    
    # Add to global eBPF programs list
    set_property(GLOBAL APPEND PROPERTY EBPF_PROGRAMS ${EBPF_NAME}_ebpf)
    set_property(GLOBAL APPEND PROPERTY EBPF_OBJECTS ${EBPF_OBJECT})
    
    # Set program-specific properties
    set_target_properties(${EBPF_NAME}_ebpf PROPERTIES
        EBPF_OBJECT_FILE ${EBPF_OBJECT}
        EBPF_BTF_FILE ${BTF_TARGET}
        EBPF_SOURCE_FILE ${EBPF_SOURCE}
    )
endfunction()

# Compile eBPF programs if source files exist
message(STATUS "      - eBPF C programs")

# Compile XDP programs
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c/xdp/buckwild_xdp.c)
    compile_ebpf_program(
        NAME buckwild_xdp
        SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/c/xdp/buckwild_xdp.c
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/maps.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/events.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/protocol.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/security.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/fragment_security.h
    )
endif()

# Compile TC programs
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c/tc/buckwild_tc.c)
    compile_ebpf_program(
        NAME buckwild_tc
        SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/c/tc/buckwild_tc.c
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/maps.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/protocol.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/security.h
    )
endif()

# Compile socket filter programs
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c/socket_filter/session_filter.c)
    compile_ebpf_program(
        NAME buckwild_session_filter
        SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/c/socket_filter/session_filter.c
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/maps.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/protocol.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/security.h
    )
endif()

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c/socket_filter/security_filter.c)
    compile_ebpf_program(
        NAME buckwild_security_filter
        SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/c/socket_filter/security_filter.c
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/maps.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/protocol.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/security.h
    )
endif()

# Create combined eBPF programs target
get_property(EBPF_PROGRAM_TARGETS GLOBAL PROPERTY EBPF_PROGRAMS)
if(EBPF_PROGRAM_TARGETS)
    add_custom_target(ebpf_programs ALL)
    add_dependencies(ebpf_programs ${EBPF_PROGRAM_TARGETS})
endif()

# Build Rust eBPF integration
message(STATUS "      - Rust eBPF integration")
build_rust_crate(
    NAME buckwild_ebpf
    CRATE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/rust
    TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/rust-target
    DEPENDS buckwild_common_rust
    FEATURES ""
)

# Add dependency on eBPF programs if they exist
if(TARGET ebpf_programs)
    add_dependencies(buckwild_ebpf_build ebpf_programs)
endif()

# Create eBPF development headers target
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c/include)
    add_custom_target(ebpf_headers
        SOURCES
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/maps.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/protocol.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/security.h
            ${CMAKE_CURRENT_SOURCE_DIR}/c/include/fragment_security.h
    )
endif()

# Installation targets for eBPF programs
get_property(EBPF_OBJECT_FILES GLOBAL PROPERTY EBPF_OBJECTS)
if(EBPF_OBJECT_FILES)
    install(
        DIRECTORY ${CMAKE_BINARY_DIR}/lib/bpf/
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/buckwild/bpf
        COMPONENT runtime
        FILES_MATCHING 
            PATTERN "*.o"
            PATTERN "*.btf"
    )
endif()

# Install eBPF headers for development
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c/include)
    install(
        DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/c/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/buckwild/ebpf
        COMPONENT development
        FILES_MATCHING PATTERN "*.h"
    )
endif()

# Generate version header if template exists
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c/include/version.h.in)
    set(EBPF_VERSION_MAJOR 1)
    set(EBPF_VERSION_MINOR 0)
    set(EBPF_VERSION_PATCH 0)
    set(EBPF_VERSION "${EBPF_VERSION_MAJOR}.${EBPF_VERSION_MINOR}.${EBPF_VERSION_PATCH}")

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/c/include/version.h.in
        ${CMAKE_BINARY_DIR}/include/buckwild/ebpf/version.h
        @ONLY
    )

    install(
        FILES ${CMAKE_BINARY_DIR}/include/buckwild/ebpf/version.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/buckwild/ebpf
        COMPONENT development
    )
endif()