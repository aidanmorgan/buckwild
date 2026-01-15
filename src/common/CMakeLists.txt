# Common library CMake configuration

message(STATUS "    Building common library components:")

# Build Rust common library first
message(STATUS "      - Rust common library")
build_rust_crate(
    NAME buckwild_common
    CRATE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}
    TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/rust-target
    FEATURES ""
)

# Build C common library (only if not RUST_ONLY)
if(NOT RUST_ONLY)
    message(STATUS "      - C common library")
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/c)
        add_subdirectory(c)
    endif()
else()
    message(STATUS "      - C common library: SKIPPED (RUST_ONLY mode)")
endif()

# Create unified common library target (only if C component exists)
# Note: build_rust_crate already creates a buckwild_common alias -> buckwild_common_rust
if(NOT RUST_ONLY AND TARGET buckwild_common_c)
    # Create a unified target that includes both Rust and C
    add_library(buckwild_common_all INTERFACE)
    target_link_libraries(buckwild_common_all INTERFACE
        buckwild_common_rust
        buckwild_common_c
    )
    target_include_directories(buckwild_common_all INTERFACE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    install(TARGETS buckwild_common_all
        EXPORT buckwild-targets
        COMPONENT development
    )
endif()

# Install headers
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/buckwild/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/buckwild
    COMPONENT development
    FILES_MATCHING PATTERN "*.h"
)