# Network utilities C code tests

# Test for network socket state daemon
add_executable(test_network_utils
    test_network_utils.c
    ${CMAKE_SOURCE_DIR}/src/net/ssd/netssd.c
)

target_link_libraries(test_network_utils unity test_utils buckwild_common_c buckwild_common_crypto)
target_compile_definitions(test_network_utils PRIVATE -DUNIT_TEST)

add_test(NAME test_network_utils COMMAND test_network_utils)
set_tests_properties(test_network_utils PROPERTIES LABELS "c;unit;network")

# Test for TUN device implementation (Linux only)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_tun_device
        test_tun_device.c
    )

    target_link_libraries(test_tun_device
        unity
        test_utils
        buckwild_network
    )

    target_compile_definitions(test_tun_device PRIVATE -DUNIT_TEST)

    # Apply sanitizers if enabled
    if(COMMAND add_sanitizer_flags)
        add_sanitizer_flags(test_tun_device)
    endif()

    add_test(NAME test_tun_device COMMAND test_tun_device)
    set_tests_properties(test_tun_device PROPERTIES LABELS "c;unit;network;linux;tun")

    message(STATUS "TUN device tests: ENABLED (Linux)")
else()
    message(STATUS "TUN device tests: DISABLED (requires Linux)")
endif()