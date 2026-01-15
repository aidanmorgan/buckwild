# FindLibBPF.cmake - Find libbpf library

# Find libbpf include directory
find_path(LIBBPF_INCLUDE_DIR
    NAMES bpf/libbpf.h
    PATHS /usr/include
          /usr/local/include
          /opt/local/include
)

# Find libbpf library
find_library(LIBBPF_LIBRARY
    NAMES bpf libbpf
    PATHS /usr/lib
          /usr/local/lib
          /opt/local/lib
)

# Handle standard arguments
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibBPF
    REQUIRED_VARS LIBBPF_LIBRARY LIBBPF_INCLUDE_DIR
)

# Create imported target
if(LIBBPF_FOUND AND NOT TARGET LibBPF::LibBPF)
    add_library(LibBPF::LibBPF UNKNOWN IMPORTED)
    set_target_properties(LibBPF::LibBPF PROPERTIES
        IMPORTED_LOCATION "${LIBBPF_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBBPF_INCLUDE_DIR}"
    )
endif()