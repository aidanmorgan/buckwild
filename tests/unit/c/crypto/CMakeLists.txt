# Crypto C code tests

# Test for SIMD crypto implementations
add_executable(test_crypto_simd
    test_simd_crypto.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/simd/hmac_sha256_avx2.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/simd/hmac_sha256_avx512.c
)

target_link_libraries(test_crypto_simd unity test_utils)
target_compile_definitions(test_crypto_simd PRIVATE -DUNIT_TEST)

add_test(NAME test_crypto_simd COMMAND test_crypto_simd)
set_tests_properties(test_crypto_simd PROPERTIES LABELS "c;unit;crypto;simd")

# Test for HKDF implementation with RFC 5869 test vectors
add_executable(test_hkdf
    test_hkdf.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/kdf.c
)

target_link_libraries(test_hkdf unity test_utils OpenSSL::Crypto)
target_compile_definitions(test_hkdf PRIVATE -DUNIT_TEST)

add_test(NAME test_hkdf COMMAND test_hkdf)
set_tests_properties(test_hkdf PROPERTIES LABELS "c;unit;crypto;kdf")

# Test for HMAC-SHA256 with RFC 4231 test vectors
add_executable(test_hmac_rfc4231
    test_hmac_rfc4231.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/hmac.c
)

target_link_libraries(test_hmac_rfc4231 unity test_utils OpenSSL::Crypto)
target_compile_definitions(test_hmac_rfc4231 PRIVATE -DUNIT_TEST)

add_test(NAME test_hmac_rfc4231 COMMAND test_hmac_rfc4231)
set_tests_properties(test_hmac_rfc4231 PROPERTIES LABELS "c;unit;crypto;hmac")

# Test for secure memory operations (if source files exist)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_secure_memory.c)
    add_executable(test_secure_memory
        test_secure_memory.c
        ${CMAKE_SOURCE_DIR}/src/common/c/fragment_security.c
    )

    target_link_libraries(test_secure_memory unity test_utils)
    target_compile_definitions(test_secure_memory PRIVATE -DUNIT_TEST)

    add_test(NAME test_secure_memory COMMAND test_secure_memory)
endif()