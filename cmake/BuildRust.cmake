# BuildRust.cmake - Build Rust crates from CMake

# Find Rust
find_package(Rust REQUIRED)

# Function to build a Rust crate
function(build_rust_crate)
    # Parse arguments
    set(options RELEASE DEBUG SHARED STATIC)
    set(oneValueArgs NAME CRATE_ROOT TARGET_DIR OUTPUT_DIR CRATE_TYPE)
    set(multiValueArgs FEATURES DEPENDS ENVIRONMENT)
    cmake_parse_arguments(RUST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    # Validate arguments
    if(NOT RUST_NAME)
        message(FATAL_ERROR "build_rust_crate requires NAME argument")
    endif()
    
    if(NOT RUST_CRATE_ROOT)
        message(FATAL_ERROR "build_rust_crate requires CRATE_ROOT argument")
    endif()
    
    if(NOT RUST_TARGET_DIR)
        set(RUST_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust-target")
    endif()
    
    if(NOT RUST_OUTPUT_DIR)
        set(RUST_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
    endif()
    
    # Determine build type
    if(RUST_DEBUG OR (CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT RUST_RELEASE))
        set(CARGO_BUILD_TYPE "debug")
        set(CARGO_RELEASE_FLAG "")
    else()
        set(CARGO_BUILD_TYPE "release")
        set(CARGO_RELEASE_FLAG "--release")
    endif()
    
    # Determine target platform
    if(WIN32)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(CARGO_TARGET "x86_64-pc-windows-msvc")
        else()
            set(CARGO_TARGET "i686-pc-windows-msvc")
        endif()
    elseif(APPLE)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
                set(CARGO_TARGET "aarch64-apple-darwin")
            else()
                set(CARGO_TARGET "x86_64-apple-darwin")
            endif()
        else()
            set(CARGO_TARGET "i686-apple-darwin")
        endif()
    elseif(UNIX)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
                set(CARGO_TARGET "aarch64-unknown-linux-gnu")
            else()
                set(CARGO_TARGET "x86_64-unknown-linux-gnu")
            endif()
        else()
            set(CARGO_TARGET "i686-unknown-linux-gnu")
        endif()
    endif()
    
    # Build features string
    set(FEATURES_FLAG "")
    if(RUST_FEATURES)
        list(JOIN RUST_FEATURES "," FEATURES_STRING)
        set(FEATURES_FLAG "--features" "${FEATURES_STRING}")
    endif()
    
    # Determine crate type
    set(CRATE_TYPE_FLAG "")
    if(RUST_CRATE_TYPE)
        set(CRATE_TYPE_FLAG "--crate-type" "${RUST_CRATE_TYPE}")
    endif()
    
    # Build environment variables
    set(CARGO_ENV "")
    if(RUST_ENVIRONMENT)
        foreach(env_var ${RUST_ENVIRONMENT})
            list(APPEND CARGO_ENV "${env_var}")
        endforeach()
    endif()
    
    # Add common environment variables
    list(APPEND CARGO_ENV "CARGO_TARGET_DIR=${RUST_TARGET_DIR}")
    
    # Create build command
    set(CARGO_CMD 
        ${CMAKE_COMMAND} -E env ${CARGO_ENV}
        ${CARGO_EXECUTABLE} build 
        ${CARGO_RELEASE_FLAG} 
        --target-dir ${RUST_TARGET_DIR}
        ${FEATURES_FLAG}
        ${CRATE_TYPE_FLAG}
    )
    
    # Create custom target
    add_custom_target(${RUST_NAME}_build ALL
        COMMAND ${CARGO_CMD}
        WORKING_DIRECTORY ${RUST_CRATE_ROOT}
        COMMENT "Building Rust crate ${RUST_NAME} (${CARGO_BUILD_TYPE})"
        VERBATIM
    )
    
    # Add dependencies
    if(RUST_DEPENDS)
        add_dependencies(${RUST_NAME}_build ${RUST_DEPENDS})
    endif()
    
    # Determine library name and extension
    if(WIN32)
        set(LIB_PREFIX "")
        set(STATIC_LIB_SUFFIX ".lib")
        set(SHARED_LIB_SUFFIX ".dll")
        set(EXECUTABLE_SUFFIX ".exe")
    else()
        set(LIB_PREFIX "lib")
        set(STATIC_LIB_SUFFIX ".a")
        set(EXECUTABLE_SUFFIX "")
        if(APPLE)
            set(SHARED_LIB_SUFFIX ".dylib")
        else()
            set(SHARED_LIB_SUFFIX ".so")
        endif()
    endif()
    
    # Determine output file paths
    set(STATIC_LIB_PATH "${RUST_TARGET_DIR}/${CARGO_TARGET}/${CARGO_BUILD_TYPE}/${LIB_PREFIX}${RUST_NAME}${STATIC_LIB_SUFFIX}")
    set(SHARED_LIB_PATH "${RUST_TARGET_DIR}/${CARGO_TARGET}/${CARGO_BUILD_TYPE}/${LIB_PREFIX}${RUST_NAME}${SHARED_LIB_SUFFIX}")
    set(EXECUTABLE_PATH "${RUST_TARGET_DIR}/${CARGO_TARGET}/${CARGO_BUILD_TYPE}/${RUST_NAME}${EXECUTABLE_SUFFIX}")
    
    # Check if this is a binary crate by looking for main.rs or bin/ directory
    if(EXISTS "${RUST_CRATE_ROOT}/src/main.rs" OR EXISTS "${RUST_CRATE_ROOT}/src/bin")
        # Create imported executable target
        add_executable(${RUST_NAME}_rust IMPORTED GLOBAL)
        set_target_properties(${RUST_NAME}_rust PROPERTIES
            IMPORTED_LOCATION "${EXECUTABLE_PATH}"
        )
        add_dependencies(${RUST_NAME}_rust ${RUST_NAME}_build)
        
        # Set output path for convenience
        set(${RUST_NAME}_EXECUTABLE_PATH "${EXECUTABLE_PATH}" PARENT_SCOPE)
    else()
        # Create imported library target (default to static)
        if(RUST_SHARED)
            add_library(${RUST_NAME}_rust SHARED IMPORTED GLOBAL)
            set_target_properties(${RUST_NAME}_rust PROPERTIES
                IMPORTED_LOCATION "${SHARED_LIB_PATH}"
            )
        else()
            add_library(${RUST_NAME}_rust STATIC IMPORTED GLOBAL)
            set_target_properties(${RUST_NAME}_rust PROPERTIES
                IMPORTED_LOCATION "${STATIC_LIB_PATH}"
            )
        endif()
        
        # Set common properties
        set_target_properties(${RUST_NAME}_rust PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${RUST_CRATE_ROOT}/include"
        )
        add_dependencies(${RUST_NAME}_rust ${RUST_NAME}_build)
        
        # Add system dependencies
        if(WIN32)
            set_property(TARGET ${RUST_NAME}_rust PROPERTY
                INTERFACE_LINK_LIBRARIES "ws2_32;userenv;bcrypt;ntdll")
        elseif(UNIX)
            set_property(TARGET ${RUST_NAME}_rust PROPERTY
                INTERFACE_LINK_LIBRARIES "pthread;dl;m")
            if(NOT APPLE)
                set_property(TARGET ${RUST_NAME}_rust APPEND PROPERTY
                    INTERFACE_LINK_LIBRARIES "rt")
            endif()
        endif()
        
        # Set output paths for convenience
        set(${RUST_NAME}_STATIC_LIB_PATH "${STATIC_LIB_PATH}" PARENT_SCOPE)
        if(RUST_SHARED)
            set(${RUST_NAME}_SHARED_LIB_PATH "${SHARED_LIB_PATH}" PARENT_SCOPE)
        endif()
    endif()
    
    # Create a convenience alias (only for library targets)
    if(NOT TARGET ${RUST_NAME} AND TARGET ${RUST_NAME}_rust)
        get_target_property(TARGET_TYPE ${RUST_NAME}_rust TYPE)
        if(TARGET_TYPE MATCHES "SHARED_LIBRARY|STATIC_LIBRARY|INTERFACE_LIBRARY")
            add_library(${RUST_NAME} ALIAS ${RUST_NAME}_rust)
        endif()
    endif()
endfunction()

# Function to build a Rust workspace
function(build_rust_workspace)
    set(options RELEASE DEBUG)
    set(oneValueArgs NAME WORKSPACE_ROOT TARGET_DIR)
    set(multiValueArgs PACKAGES FEATURES ENVIRONMENT)
    cmake_parse_arguments(RUST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT RUST_NAME)
        message(FATAL_ERROR "build_rust_workspace requires NAME argument")
    endif()
    
    if(NOT RUST_WORKSPACE_ROOT)
        message(FATAL_ERROR "build_rust_workspace requires WORKSPACE_ROOT argument")
    endif()
    
    if(NOT RUST_TARGET_DIR)
        set(RUST_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust-workspace-target")
    endif()
    
    # Determine build type
    if(RUST_DEBUG OR (CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT RUST_RELEASE))
        set(CARGO_RELEASE_FLAG "")
    else()
        set(CARGO_RELEASE_FLAG "--release")
    endif()
    
    # Build packages string
    set(PACKAGES_FLAG "")
    if(RUST_PACKAGES)
        foreach(package ${RUST_PACKAGES})
            list(APPEND PACKAGES_FLAG "--package" "${package}")
        endforeach()
    endif()
    
    # Build features string
    set(FEATURES_FLAG "")
    if(RUST_FEATURES)
        list(JOIN RUST_FEATURES "," FEATURES_STRING)
        set(FEATURES_FLAG "--features" "${FEATURES_STRING}")
    endif()
    
    # Build environment variables
    set(CARGO_ENV "")
    if(RUST_ENVIRONMENT)
        foreach(env_var ${RUST_ENVIRONMENT})
            list(APPEND CARGO_ENV "${env_var}")
        endforeach()
    endif()
    list(APPEND CARGO_ENV "CARGO_TARGET_DIR=${RUST_TARGET_DIR}")
    
    # Create build command
    set(CARGO_CMD 
        ${CMAKE_COMMAND} -E env ${CARGO_ENV}
        ${CARGO_EXECUTABLE} build 
        ${CARGO_RELEASE_FLAG} 
        --target-dir ${RUST_TARGET_DIR}
        ${PACKAGES_FLAG}
        ${FEATURES_FLAG}
    )
    
    # Create custom target
    add_custom_target(${RUST_NAME}_workspace_build ALL
        COMMAND ${CARGO_CMD}
        WORKING_DIRECTORY ${RUST_WORKSPACE_ROOT}
        COMMENT "Building Rust workspace ${RUST_NAME}"
        VERBATIM
    )
endfunction()