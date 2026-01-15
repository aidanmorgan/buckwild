# External dependencies built from submodules

include(ExternalProject)

# ============================================================================
# OpenSSL Configuration
# ============================================================================

set(OPENSSL_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/openssl")
set(OPENSSL_INSTALL_DIR "${CMAKE_BINARY_DIR}/external/openssl")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include")
set(OPENSSL_LIB_DIR "${OPENSSL_INSTALL_DIR}/lib")

# Determine OpenSSL configure command based on platform
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(OPENSSL_CONFIGURE_CMD ./config)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(OPENSSL_CONFIGURE_CMD ./Configure darwin64-x86_64-cc)
else()
    set(OPENSSL_CONFIGURE_CMD ./config)
endif()

# Build OpenSSL from submodule
ExternalProject_Add(openssl_external
    SOURCE_DIR ${OPENSSL_SOURCE_DIR}
    CONFIGURE_COMMAND ${OPENSSL_CONFIGURE_CMD}
        --prefix=${OPENSSL_INSTALL_DIR}
        --openssldir=${OPENSSL_INSTALL_DIR}
        no-shared
        no-tests
    BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
    INSTALL_COMMAND make install_sw
    BUILD_IN_SOURCE 1
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
)

# Create directories that will be populated by the build
file(MAKE_DIRECTORY "${OPENSSL_INCLUDE_DIR}")
file(MAKE_DIRECTORY "${OPENSSL_LIB_DIR}")

# Create imported targets for OpenSSL
add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)
add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)

set_target_properties(OpenSSL::SSL PROPERTIES
    IMPORTED_LOCATION "${OPENSSL_LIB_DIR}/libssl.a"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
)

set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION "${OPENSSL_LIB_DIR}/libcrypto.a"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
)

# Ensure the library files exist before they're used
add_dependencies(OpenSSL::SSL openssl_external)
add_dependencies(OpenSSL::Crypto openssl_external)

# Set OpenSSL variables for find_package compatibility
set(OPENSSL_FOUND TRUE)
set(OPENSSL_INCLUDE_DIR "${OPENSSL_INCLUDE_DIR}")
set(OPENSSL_LIBRARIES "${OPENSSL_LIB_DIR}/libssl.a;${OPENSSL_LIB_DIR}/libcrypto.a")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_LIB_DIR}/libssl.a")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_LIB_DIR}/libcrypto.a")

# ============================================================================
# LibBPF Configuration
# ============================================================================

set(LIBBPF_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/libbpf")
set(LIBBPF_INSTALL_DIR "${CMAKE_BINARY_DIR}/external/libbpf")
set(LIBBPF_INCLUDE_DIR "${LIBBPF_INSTALL_DIR}/include")
set(LIBBPF_LIB_DIR "${LIBBPF_INSTALL_DIR}/lib")

# Build LibBPF from submodule
ExternalProject_Add(libbpf_external
    SOURCE_DIR ${LIBBPF_SOURCE_DIR}/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
        BUILD_STATIC_ONLY=y
        OBJDIR=${CMAKE_BINARY_DIR}/libbpf-build
        -C ${LIBBPF_SOURCE_DIR}/src
    INSTALL_COMMAND make install
        BUILD_STATIC_ONLY=y
        DESTDIR=${LIBBPF_INSTALL_DIR}
        PREFIX=
        LIBDIR=/lib
        -C ${LIBBPF_SOURCE_DIR}/src
    BUILD_IN_SOURCE 0
    LOG_BUILD ON
    LOG_INSTALL ON
)

# Create directories that will be populated by the build
file(MAKE_DIRECTORY "${LIBBPF_INCLUDE_DIR}")
file(MAKE_DIRECTORY "${LIBBPF_LIB_DIR}")

# Create imported target for LibBPF
add_library(LibBPF::LibBPF STATIC IMPORTED GLOBAL)

set_target_properties(LibBPF::LibBPF PROPERTIES
    IMPORTED_LOCATION "${LIBBPF_LIB_DIR}/libbpf.a"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBBPF_INCLUDE_DIR}"
)

# Ensure the library file exists before it's used
add_dependencies(LibBPF::LibBPF libbpf_external)

# Set LibBPF variables for find_package compatibility
set(LIBBPF_FOUND TRUE)
set(LIBBPF_INCLUDE_DIR "${LIBBPF_INCLUDE_DIR}")
set(LIBBPF_LIBRARY "${LIBBPF_LIB_DIR}/libbpf.a")
set(LIBBPF_LIBRARIES "${LIBBPF_LIBRARY}")

message(STATUS "External dependencies configured:")
message(STATUS "  OpenSSL: ${OPENSSL_INSTALL_DIR}")
message(STATUS "    - Include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "    - Library: ${OPENSSL_LIB_DIR}")
message(STATUS "  LibBPF:  ${LIBBPF_INSTALL_DIR}")
message(STATUS "    - Include: ${LIBBPF_INCLUDE_DIR}")
message(STATUS "    - Library: ${LIBBPF_LIB_DIR}")
