# src/net/ssd/CMakeLists.txt
# Network SSD (Secure Socket Daemon) components

cmake_minimum_required(VERSION 3.16)
project(buckwild_netssd C)

# Define workspace root (can be overridden via -DWORKSPACE_ROOT=...)
if(NOT DEFINED WORKSPACE_ROOT)
    set(WORKSPACE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
endif()

# Add custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Find kernel headers
include(FindKernelHeaders)

# Find OpenSSL (required for crypto)
find_package(OpenSSL REQUIRED)

# Set compiler warning flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

# Create network SSD library
add_library(buckwild_netssd SHARED
    netssd.c
    ${WORKSPACE_ROOT}/src/common/c/port_hopping.c
    ${WORKSPACE_ROOT}/src/common/c/crypto/hmac.c
    ${WORKSPACE_ROOT}/src/common/c/crypto/kdf.c
    ${WORKSPACE_ROOT}/src/common/c/crypto/secure_memory.c
    ${WORKSPACE_ROOT}/src/common/c/buffer.c
    ${WORKSPACE_ROOT}/src/common/c/time_utils.c
)

target_include_directories(buckwild_netssd PUBLIC
    ${WORKSPACE_ROOT}/include
    ${KERNEL_HEADERS_INCLUDE_DIRS}
)

target_link_libraries(buckwild_netssd PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Install library
install(
    TARGETS buckwild_netssd
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT runtime
)