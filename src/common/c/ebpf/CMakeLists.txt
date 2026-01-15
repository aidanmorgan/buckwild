# eBPF components C library
# This module is Linux-specific (uses Linux eBPF/XDP/TC APIs)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "eBPF module requires Linux")
endif()

# Build and find libbpf from submodule
set(LIBBPF_SRC_DIR ${CMAKE_SOURCE_DIR}/third_party/libbpf/src)
set(LIBBPF_BUILD_DIR ${CMAKE_BINARY_DIR}/external/libbpf)
set(LIBBPF_INCLUDE_DIR ${LIBBPF_BUILD_DIR}/usr/include)
set(LIBBPF_LIBRARY_DIR ${LIBBPF_BUILD_DIR}/usr/lib64)

# Check if libbpf headers need to be installed
if(NOT EXISTS ${LIBBPF_INCLUDE_DIR}/bpf/libbpf.h)
    message(STATUS "Installing libbpf headers...")
    execute_process(
        COMMAND make install_headers DESTDIR=${LIBBPF_BUILD_DIR} prefix=/usr
        WORKING_DIRECTORY ${LIBBPF_SRC_DIR}
        RESULT_VARIABLE LIBBPF_INSTALL_RESULT
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(NOT LIBBPF_INSTALL_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to install libbpf headers")
    endif()
endif()

# Check if libbpf library needs to be built
if(NOT EXISTS ${LIBBPF_LIBRARY_DIR}/libbpf.a)
    message(STATUS "Building libbpf...")
    execute_process(
        COMMAND make BUILD_STATIC_ONLY=y DESTDIR=${LIBBPF_BUILD_DIR} prefix=/usr install
        WORKING_DIRECTORY ${LIBBPF_SRC_DIR}
        RESULT_VARIABLE LIBBPF_BUILD_RESULT
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(NOT LIBBPF_BUILD_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build libbpf")
    endif()
endif()

set(LIBBPF_LIBRARY ${LIBBPF_LIBRARY_DIR}/libbpf.a)

message(STATUS "libbpf configured:")
message(STATUS "  Include: ${LIBBPF_INCLUDE_DIR}")
message(STATUS "  Library: ${LIBBPF_LIBRARY}")

# eBPF loader and manager implementation
add_library(buckwild_ebpf STATIC
    ebpf_manager.c
    ebpf_xdp_loader.c
    ebpf_tc_loader.c
)

# Include directories
target_include_directories(buckwild_ebpf PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIR}
)

# Link with libbpf
if(LIBBPF_LIBRARY)
    target_link_libraries(buckwild_ebpf PUBLIC
        ${LIBBPF_LIBRARY}
        elf
        z
    )
elseif(LIBBPF_FOUND)
    target_link_libraries(buckwild_ebpf PUBLIC
        ${LIBBPF_LIBRARIES}
    )
endif()

# Apply sanitizers if enabled
if(COMMAND add_sanitizer_flags)
    add_sanitizer_flags(buckwild_ebpf)
endif()

# Also create a shared library for FFI usage (Rust, etc.)
add_library(buckwild_ebpf_shared SHARED
    ebpf_manager.c
    ebpf_xdp_loader.c
    ebpf_tc_loader.c
)

target_include_directories(buckwild_ebpf_shared PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIR}
)

if(LIBBPF_LIBRARY)
    target_link_libraries(buckwild_ebpf_shared PUBLIC
        ${LIBBPF_LIBRARY}
        elf
        z
    )
elseif(LIBBPF_FOUND)
    target_link_libraries(buckwild_ebpf_shared PUBLIC
        ${LIBBPF_LIBRARIES}
    )
endif()

# Apply sanitizers to shared library too
if(COMMAND add_sanitizer_flags)
    add_sanitizer_flags(buckwild_ebpf_shared)
endif()

# Set library properties
set_target_properties(buckwild_ebpf_shared PROPERTIES
    VERSION 0.1.0
    SOVERSION 0
    OUTPUT_NAME buckwild_ebpf
)

# Install shared library for FFI usage
install(TARGETS buckwild_ebpf_shared
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
