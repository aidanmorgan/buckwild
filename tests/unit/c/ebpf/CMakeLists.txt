# eBPF Logic Unit Tests (Tier 1 - Rootless)
#
# These tests validate pure C logic from src/ebpf/c/include/logic/*.h
# No BPF helpers, no root required, runs in standard userspace

# Test: Port Validation Logic
add_executable(test_ebpf_port_logic
    test_port_validation_logic.c
)

target_include_directories(test_ebpf_port_logic PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(test_ebpf_port_logic
    unity
)

add_test(
    NAME test_ebpf_port_logic
    COMMAND test_ebpf_port_logic
)
set_tests_properties(test_ebpf_port_logic PROPERTIES LABELS "c;unit;ebpf;linux")

# Test: Protocol Parsing
add_executable(test_protocol_parsing
    test_protocol_parsing.c
    protocol_test_impl.c
    ../utils/test_utils.c
)

target_include_directories(test_protocol_parsing PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(test_protocol_parsing
    unity
    buckwild_common_c
)

add_test(
    NAME test_protocol_parsing
    COMMAND test_protocol_parsing
)
set_tests_properties(test_protocol_parsing PROPERTIES LABELS "c;unit;ebpf;protocol")

# Test: XDP Packet Filtering
add_executable(test_xdp_packet_filtering
    test_xdp_packet_filtering.c
    xdp_test_helpers.c
    ../utils/test_utils.c
)

target_include_directories(test_xdp_packet_filtering PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
)

target_link_libraries(test_xdp_packet_filtering
    unity
    ssl
    crypto
)

add_test(
    NAME test_xdp_packet_filtering
    COMMAND test_xdp_packet_filtering
)
set_tests_properties(test_xdp_packet_filtering PROPERTIES LABELS "c;unit;ebpf;linux;xdp")

# Test: Stage 4 TC Programs (TDD)
add_executable(test_tc_programs
    test_tc_programs.c
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/tc/rate_limiting.c
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/tc/qos.c
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/tc/congestion.c
)

target_include_directories(test_tc_programs PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
)

target_link_libraries(test_tc_programs
    unity
    test_utils
)

add_test(
    NAME test_tc_programs
    COMMAND test_tc_programs
)
set_tests_properties(test_tc_programs PROPERTIES LABELS "c;unit;ebpf;linux;tc")

# Test: Protocol Helpers Comprehensive (67 tests)
# Tests all inline functions in protocol.h with corner cases
add_executable(test_protocol_helpers_comprehensive
    test_protocol_helpers_comprehensive.c
)

target_include_directories(test_protocol_helpers_comprehensive PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
)

target_link_libraries(test_protocol_helpers_comprehensive
    unity
)

add_test(
    NAME test_protocol_helpers_comprehensive
    COMMAND test_protocol_helpers_comprehensive
)
set_tests_properties(test_protocol_helpers_comprehensive PROPERTIES LABELS "c;unit;ebpf;protocol")

# Test: Security Validation Comprehensive (40 tests)
# Tests security.h attack detection and rate limiting
add_executable(test_security_validation_comprehensive
    test_security_validation_comprehensive.c
)

target_include_directories(test_security_validation_comprehensive PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
)

target_link_libraries(test_security_validation_comprehensive
    unity
)

add_test(
    NAME test_security_validation_comprehensive
    COMMAND test_security_validation_comprehensive
)
set_tests_properties(test_security_validation_comprehensive PROPERTIES LABELS "c;unit;ebpf;security")

# Test: TC Token Bucket Edge Cases (27 tests)
# Tests overflow-safe arithmetic and boundary conditions
add_executable(test_tc_token_bucket_edge_cases
    test_tc_token_bucket_edge_cases.c
)

target_include_directories(test_tc_token_bucket_edge_cases PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
)

target_link_libraries(test_tc_token_bucket_edge_cases
    unity
)

add_test(
    NAME test_tc_token_bucket_edge_cases
    COMMAND test_tc_token_bucket_edge_cases
)
set_tests_properties(test_tc_token_bucket_edge_cases PROPERTIES LABELS "c;unit;ebpf;tc;police")

# Test: XDP Filter Logic (HIGH-014)
# Tests XDP packet filtering paths: valid, invalid, bounds, drop, pass
add_executable(test_xdp_filter
    test_xdp_filter.c
)

target_include_directories(test_xdp_filter PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
)

target_link_libraries(test_xdp_filter
    unity
)

add_test(
    NAME test_xdp_filter
    COMMAND test_xdp_filter
)
set_tests_properties(test_xdp_filter PROPERTIES LABELS "c;unit;ebpf;xdp;audit")

# Test: TC Classifier Logic (HIGH-014)
# Tests TC traffic classifier: rate limit, QoS, mark, drop
add_executable(test_tc_classifier
    test_tc_classifier.c
)

target_include_directories(test_tc_classifier PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/ebpf/c/include
)

target_link_libraries(test_tc_classifier
    unity
)

add_test(
    NAME test_tc_classifier
    COMMAND test_tc_classifier
)
set_tests_properties(test_tc_classifier PROPERTIES LABELS "c;unit;ebpf;tc;audit")
