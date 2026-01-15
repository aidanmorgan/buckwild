# FindRust.cmake - Find Rust compiler and cargo

# Find rustc
find_program(RUSTC_EXECUTABLE rustc)
mark_as_advanced(RUSTC_EXECUTABLE)

# Find cargo
find_program(CARGO_EXECUTABLE cargo)
mark_as_advanced(CARGO_EXECUTABLE)

# Get Rust version
if(RUSTC_EXECUTABLE)
    execute_process(
        COMMAND ${RUSTC_EXECUTABLE} --version
        OUTPUT_VARIABLE RUSTC_VERSION_OUTPUT
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    if(RUSTC_VERSION_OUTPUT MATCHES "rustc ([0-9]+\\.[0-9]+\\.[0-9]+)")
        set(RUSTC_VERSION "${CMAKE_MATCH_1}")
    endif()
endif()

# Get Cargo version
if(CARGO_EXECUTABLE)
    execute_process(
        COMMAND ${CARGO_EXECUTABLE} --version
        OUTPUT_VARIABLE CARGO_VERSION_OUTPUT
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    if(CARGO_VERSION_OUTPUT MATCHES "cargo ([0-9]+\\.[0-9]+\\.[0-9]+)")
        set(CARGO_VERSION "${CMAKE_MATCH_1}")
    endif()
endif()

# Handle standard arguments
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Rust
    REQUIRED_VARS RUSTC_EXECUTABLE CARGO_EXECUTABLE
    VERSION_VAR RUSTC_VERSION
)