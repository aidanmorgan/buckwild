# CMake configuration for common utility tests
# Note: OpenSSL::Crypto target is provided by cmake/External.cmake

# Time utilities test
add_executable(test_time_utils
    test_time_utils.c
    ${CMAKE_SOURCE_DIR}/src/common/c/time_utils.c
)

target_include_directories(test_time_utils PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${unity_SOURCE_DIR}/src
)

target_link_libraries(test_time_utils unity)

add_test(NAME test_time_utils COMMAND test_time_utils)
set_tests_properties(test_time_utils PROPERTIES LABELS "c;unit;common")

# Set compiler flags
target_compile_options(test_time_utils PRIVATE -Wall -Wextra -Werror)

# Crypto utilities test
add_executable(test_crypto
    test_crypto.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/hmac.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/kdf.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/secure_memory.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/ecdh.c
)

target_include_directories(test_crypto PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${unity_SOURCE_DIR}/src
)

target_link_libraries(test_crypto unity OpenSSL::Crypto)

add_test(NAME test_crypto COMMAND test_crypto)
set_tests_properties(test_crypto PROPERTIES LABELS "c;unit;common;crypto")

# Set compiler flags
target_compile_options(test_crypto PRIVATE -Wall -Wextra -Werror)

# Secure memory comprehensive test (Task 3.1.5)
add_executable(test_secure_memory
    test_secure_memory.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/secure_memory.c
)

target_include_directories(test_secure_memory PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${unity_SOURCE_DIR}/src
)

target_link_libraries(test_secure_memory unity)

add_test(NAME test_secure_memory COMMAND test_secure_memory)
set_tests_properties(test_secure_memory PROPERTIES LABELS "c;unit;common;crypto;secure_memory")

# Set compiler flags
target_compile_options(test_secure_memory PRIVATE -Wall -Wextra -Werror)

# ECDH comprehensive test (Task 3.1.4)
add_executable(test_ecdh
    test_ecdh.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/ecdh.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/secure_memory.c
)

target_include_directories(test_ecdh PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${unity_SOURCE_DIR}/src
)

target_link_libraries(test_ecdh unity OpenSSL::Crypto)

add_test(NAME test_ecdh COMMAND test_ecdh)
set_tests_properties(test_ecdh PROPERTIES LABELS "c;unit;common;crypto;ecdh")

# Set compiler flags
target_compile_options(test_ecdh PRIVATE -Wall -Wextra -Werror)

# Buffer utilities test
add_executable(test_buffer
    test_buffer.c
    ${CMAKE_SOURCE_DIR}/src/common/c/buffer.c
)

target_include_directories(test_buffer PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${unity_SOURCE_DIR}/src
)

target_link_libraries(test_buffer unity)

add_test(NAME test_buffer COMMAND test_buffer)
set_tests_properties(test_buffer PROPERTIES LABELS "c;unit;common")

# Set compiler flags
target_compile_options(test_buffer PRIVATE -Wall -Wextra -Werror)

# Port hopping test
add_executable(test_port_hopping
    test_port_hopping.c
    ${CMAKE_SOURCE_DIR}/src/common/c/port_hopping.c
    ${CMAKE_SOURCE_DIR}/src/common/c/time_utils.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/hmac.c
)

target_include_directories(test_port_hopping PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${unity_SOURCE_DIR}/src
)

target_link_libraries(test_port_hopping unity OpenSSL::Crypto)

add_test(NAME test_port_hopping COMMAND test_port_hopping)
set_tests_properties(test_port_hopping PROPERTIES LABELS "c;unit;common;protocol")

# Set compiler flags
target_compile_options(test_port_hopping PRIVATE -Wall -Wextra -Werror)

# Port hopping protocol alignment test
add_executable(test_port_hopping_protocol
    test_port_hopping_protocol.c
    ${CMAKE_SOURCE_DIR}/src/common/c/port_hopping.c
    ${CMAKE_SOURCE_DIR}/src/common/c/time_utils.c
    ${CMAKE_SOURCE_DIR}/src/common/c/crypto/hmac.c
)

target_include_directories(test_port_hopping_protocol PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${unity_SOURCE_DIR}/src
)

target_link_libraries(test_port_hopping_protocol unity OpenSSL::Crypto)

add_test(NAME test_port_hopping_protocol COMMAND test_port_hopping_protocol)
set_tests_properties(test_port_hopping_protocol PROPERTIES LABELS "c;unit;common;protocol")

# Set compiler flags
target_compile_options(test_port_hopping_protocol PRIVATE -Wall -Wextra -Werror)
