# Network components C library
# This module is Linux-specific (uses Linux TUN/TAP APIs)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Network TUN/TAP module requires Linux")
endif()

# TUN/TAP device implementation
add_library(buckwild_network STATIC
    tun_device.c
    tun_device_ffi.c
)

# Include directories
target_include_directories(buckwild_network PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# No external dependencies needed for TUN (uses standard Linux APIs)

# Apply sanitizers if enabled
if(COMMAND add_sanitizer_flags)
    add_sanitizer_flags(buckwild_network)
endif()

# Also create a shared library for FFI usage (Rust, etc.)
add_library(buckwild_network_shared SHARED
    tun_device.c
    tun_device_ffi.c
)

target_include_directories(buckwild_network_shared PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Apply sanitizers to shared library too
if(COMMAND add_sanitizer_flags)
    add_sanitizer_flags(buckwild_network_shared)
endif()

# Set library properties
set_target_properties(buckwild_network_shared PROPERTIES
    VERSION 0.1.0
    SOVERSION 0
    OUTPUT_NAME buckwild_network
)

# Install shared library for FFI usage
install(TARGETS buckwild_network_shared
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
