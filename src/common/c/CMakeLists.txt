# Common C library CMake configuration

# Add subdirectories
add_subdirectory(crypto)

# Network components (Linux only - uses TUN/TAP devices)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(network)
    set(HAVE_NETWORK_SUPPORT TRUE)
    message(STATUS "Network TUN/TAP support: ENABLED (Linux)")
else()
    set(HAVE_NETWORK_SUPPORT FALSE)
    message(STATUS "Network TUN/TAP support: DISABLED (requires Linux)")
endif()

# eBPF components (Linux only - uses eBPF/XDP/TC)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND BUILD_EBPF)
    add_subdirectory(ebpf)
    set(HAVE_EBPF_SUPPORT TRUE)
    message(STATUS "eBPF/XDP/TC support: ENABLED (Linux)")
elseif(NOT BUILD_EBPF)
    set(HAVE_EBPF_SUPPORT FALSE)
    message(STATUS "eBPF/XDP/TC support: DISABLED (BUILD_EBPF=OFF)")
else()
    set(HAVE_EBPF_SUPPORT FALSE)
    message(STATUS "eBPF/XDP/TC support: DISABLED (requires Linux)")
endif()

# Create common C library target
add_library(buckwild_common_c STATIC
    fragment_security.c
    time_utils.c
    port_hopping.c
    buffer.c
)

# Include directories
target_include_directories(buckwild_common_c PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Link with crypto component (always)
target_link_libraries(buckwild_common_c PUBLIC
    buckwild_common_crypto
)

# Link with network component (Linux only)
if(HAVE_NETWORK_SUPPORT)
    target_link_libraries(buckwild_common_c PUBLIC
        buckwild_network
    )
endif()

# Link with eBPF component (Linux only)
if(HAVE_EBPF_SUPPORT)
    target_link_libraries(buckwild_common_c PUBLIC
        buckwild_ebpf
    )
endif()

# Create unified static library for FFI/Rust consumption
# This combines all C components into a single library
# Note: buckwild_c_stub.c is required because CMake needs at least one source file
add_library(buckwild_c STATIC
    buckwild_c_stub.c
)

# Link all C components
target_link_libraries(buckwild_c PUBLIC
    buckwild_common_c
    buckwild_common_crypto
)

if(HAVE_NETWORK_SUPPORT)
    target_link_libraries(buckwild_c PUBLIC
        buckwild_network
    )
endif()

if(HAVE_EBPF_SUPPORT)
    target_link_libraries(buckwild_c PUBLIC
        buckwild_ebpf
    )
endif()

# Ensure unified library is built to a known location for Rust build.rs
set_target_properties(buckwild_c PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    OUTPUT_NAME "buckwild_c"
)

# Export the library path for Rust build.rs
set(BUCKWILD_C_LIBRARY_PATH "${CMAKE_BINARY_DIR}/lib/libbuckwild_c.a" CACHE INTERNAL "Path to unified C library")
set(BUCKWILD_C_LIBRARY_DIR "${CMAKE_BINARY_DIR}/lib" CACHE INTERNAL "Directory containing C library")