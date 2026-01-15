# FindKernelHeaders.cmake
# Locate kernel headers
# This module defines:
#  KERNEL_HEADERS_FOUND - True if kernel headers were found
#  KERNEL_HEADERS_INCLUDE_DIRS - Include directories for kernel headers
#  KERNEL_HEADERS_VERSION - Version of the kernel headers

# Find kernel headers
find_path(KERNEL_HEADERS_INCLUDE_DIR
    NAMES linux/version.h
    PATHS /usr/src/linux-headers-$(uname -r)
          /usr/src/kernels/$(uname -r)
          /usr/include
    PATH_SUFFIXES linux
)

# Get kernel version
if(KERNEL_HEADERS_INCLUDE_DIR)
    file(STRINGS "${KERNEL_HEADERS_INCLUDE_DIR}/linux/version.h" KERNEL_VERSION_MAJOR_LINE REGEX "^#define[ \t]+LINUX_VERSION_MAJOR[ \t]+[0-9]+$")
    file(STRINGS "${KERNEL_HEADERS_INCLUDE_DIR}/linux/version.h" KERNEL_VERSION_MINOR_LINE REGEX "^#define[ \t]+LINUX_VERSION_MINOR[ \t]+[0-9]+$")
    file(STRINGS "${KERNEL_HEADERS_INCLUDE_DIR}/linux/version.h" KERNEL_VERSION_PATCH_LINE REGEX "^#define[ \t]+LINUX_VERSION_PATCHLEVEL[ \t]+[0-9]+$")
    
    string(REGEX REPLACE "^#define[ \t]+LINUX_VERSION_MAJOR[ \t]+([0-9]+)$" "\\1" KERNEL_VERSION_MAJOR "${KERNEL_VERSION_MAJOR_LINE}")
    string(REGEX REPLACE "^#define[ \t]+LINUX_VERSION_MINOR[ \t]+([0-9]+)$" "\\1" KERNEL_VERSION_MINOR "${KERNEL_VERSION_MINOR_LINE}")
    string(REGEX REPLACE "^#define[ \t]+LINUX_VERSION_PATCHLEVEL[ \t]+([0-9]+)$" "\\1" KERNEL_VERSION_PATCH "${KERNEL_VERSION_PATCH_LINE}")
    
    set(KERNEL_HEADERS_VERSION "${KERNEL_VERSION_MAJOR}.${KERNEL_VERSION_MINOR}.${KERNEL_VERSION_PATCH}")
endif()

# Handle standard arguments
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(KernelHeaders
    REQUIRED_VARS KERNEL_HEADERS_INCLUDE_DIR
    VERSION_VAR KERNEL_HEADERS_VERSION
)

# Set output variables
if(KERNEL_HEADERS_FOUND)
    set(KERNEL_HEADERS_INCLUDE_DIRS ${KERNEL_HEADERS_INCLUDE_DIR})
endif()

mark_as_advanced(KERNEL_HEADERS_INCLUDE_DIR)