# Tools CMake configuration

message(STATUS "    Building tools components:")

# Build Rust tools
message(STATUS "      - Rust tools")
build_rust_crate(
    NAME buckwild_tools
    CRATE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/rust
    TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/rust-target
    DEPENDS buckwild_common_rust
    FEATURES ""
)

# The Rust tools is a binary crate, so buckwild_tools_rust is an executable
# Create an alias for the tools executable
add_executable(buckwild_tools ALIAS buckwild_tools_rust)

# Install tools
install(PROGRAMS ${buckwild_tools_EXECUTABLE_PATH}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    RENAME buckwild_tools
    COMPONENT runtime
)