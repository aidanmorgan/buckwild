# Crypto C library CMake configuration
# Note: OpenSSL::Crypto target is provided by cmake/External.cmake

# Create crypto library target (baseline + Stage 5 ECDH)
add_library(buckwild_common_crypto STATIC
    hmac.c
    kdf.c
    secure_memory.c
    ecdh.c
)

# Include directories
target_include_directories(buckwild_common_crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Link OpenSSL crypto library (provided by External.cmake)
target_link_libraries(buckwild_common_crypto PUBLIC
    OpenSSL::Crypto
)

# Make sure OpenSSL is built before this library
add_dependencies(buckwild_common_crypto openssl_external)

# Check for SIMD support
include(CheckCCompilerFlag)
check_c_compiler_flag("-mavx2" HAVE_AVX2)
check_c_compiler_flag("-mavx512f" HAVE_AVX512)

# Add SIMD compile flags if we have sources
if(CRYPTO_SOURCES AND HAVE_AVX2 AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/simd/hmac_sha256_avx2.c)
    target_compile_definitions(buckwild_common_crypto PRIVATE HAVE_AVX2=1)
    set_source_files_properties(simd/hmac_sha256_avx2.c PROPERTIES COMPILE_FLAGS "-mavx2")
endif()

if(CRYPTO_SOURCES AND HAVE_AVX512 AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/simd/hmac_sha256_avx512.c)
    target_compile_definitions(buckwild_common_crypto PRIVATE HAVE_AVX512=1)
    set_source_files_properties(simd/hmac_sha256_avx512.c PROPERTIES COMPILE_FLAGS "-mavx512f")
endif()