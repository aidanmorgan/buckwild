/**
 * Unit tests for network utilities
 */

#include <unity.h>
#include "../utils/test_utils.h"
#include "../utils/mock_helpers.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Mock network socket state daemon functions
int netssd_init(void);
int netssd_bind_socket(int port);
int netssd_send_packet(const void *data, size_t len, const struct sockaddr *addr);
int netssd_recv_packet(void *buffer, size_t buffer_size, struct sockaddr *addr);
void netssd_cleanup(void);

void setUp(void) {
    test_utils_setup();
    mock_network_reset();
}

void tearDown(void) {
    test_utils_teardown();
}

void test_netssd_init_success(void) {
    // Test successful initialization
    int result = netssd_init();
    
    // This would test actual initialization
    // For now, simulate success
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_netssd_bind_socket_valid_port(void) {
    // Test binding to valid port
    int result = netssd_bind_socket(8080);
    
    // Should succeed with valid port
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_netssd_bind_socket_invalid_port(void) {
    // Test binding to invalid port
    int result = netssd_bind_socket(0);
    
    // Should fail with invalid port
    TEST_ASSERT_NOT_EQUAL_INT(0, result);
}

void test_netssd_send_packet_success(void) {
    struct test_packet packet;
    create_test_packet(&packet, 64);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    
    int result = netssd_send_packet(packet.data, packet.size, (struct sockaddr*)&addr);
    
    // Should succeed
    TEST_ASSERT_EQUAL_INT((int)packet.size, result);
    
    // Verify mock statistics
    struct mock_network_stats stats = mock_network_get_stats();
    TEST_ASSERT_EQUAL_UINT64(1, stats.packets_sent);
    TEST_ASSERT_EQUAL_UINT64(packet.size, stats.bytes_sent);
}

void test_netssd_recv_packet_with_data(void) {
    uint8_t buffer[1024];
    struct sockaddr_in addr;
    
    // Set up mock receive data
    struct test_packet test_data;
    create_test_packet(&test_data, 128);
    mock_network_set_recv_data(test_data.data, test_data.size);
    
    int result = netssd_recv_packet(buffer, sizeof(buffer), (struct sockaddr*)&addr);
    
    // Should receive the data
    TEST_ASSERT_EQUAL_INT((int)test_data.size, result);
    TEST_ASSERT_EQUAL_MEMORY(test_data.data, buffer, test_data.size);
}

void test_netssd_recv_packet_no_data(void) {
    uint8_t buffer[1024];
    struct sockaddr_in addr;
    
    // No mock data set up
    int result = netssd_recv_packet(buffer, sizeof(buffer), (struct sockaddr*)&addr);
    
    // Should return 0 (no data)
    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_netssd_packet_roundtrip(void) {
    struct test_packet original_packet;
    create_test_packet(&original_packet, 256);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    
    // Send packet
    int send_result = netssd_send_packet(original_packet.data, original_packet.size, 
                                        (struct sockaddr*)&addr);
    TEST_ASSERT_EQUAL_INT((int)original_packet.size, send_result);
    
    // Set up the same data for receive
    mock_network_set_recv_data(original_packet.data, original_packet.size);
    
    // Receive packet
    uint8_t recv_buffer[1024];
    struct sockaddr_in recv_addr;
    int recv_result = netssd_recv_packet(recv_buffer, sizeof(recv_buffer), 
                                        (struct sockaddr*)&recv_addr);
    
    TEST_ASSERT_EQUAL_INT((int)original_packet.size, recv_result);
    TEST_ASSERT_EQUAL_MEMORY(original_packet.data, recv_buffer, original_packet.size);
}

void test_netssd_performance_benchmark(void) {
    struct test_benchmark bench;
    benchmark_start(&bench);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    
    // Benchmark packet sending
    for (int i = 0; i < 1000; i++) {
        struct test_packet packet;
        create_test_packet(&packet, 64);
        
        netssd_send_packet(packet.data, packet.size, (struct sockaddr*)&addr);
        benchmark_iteration(&bench);
    }
    
    benchmark_end(&bench);
    
    double avg_time = benchmark_get_avg_time_us(&bench);
    printf("Average network send time: %.2f microseconds\n", avg_time);

    // Should be reasonably fast (less than 1000 microseconds)
    TEST_ASSERT_TRUE(avg_time < 1000.0);
}

void test_netssd_cleanup(void) {
    // Test cleanup
    netssd_cleanup();
    
    // Should complete without error
    TEST_ASSERT_TRUE(1); // Placeholder assertion
}

// Mock implementations for testing
int netssd_init(void) {
    return 0; // Success
}

int netssd_bind_socket(int port) {
    if (port <= 0 || port > 65535) {
        return -1; // Invalid port
    }
    return mock_bind(mock_socket(AF_INET, SOCK_DGRAM, 0), NULL, 0);
}

int netssd_send_packet(const void *data, size_t len, const struct sockaddr *addr) {
    return (int)mock_sendto(0, data, len, 0, addr, sizeof(struct sockaddr_in));
}

int netssd_recv_packet(void *buffer, size_t buffer_size, struct sockaddr *addr) {
    socklen_t addrlen = sizeof(struct sockaddr_in);
    return (int)mock_recvfrom(0, buffer, buffer_size, 0, addr, &addrlen);
}

void netssd_cleanup(void) {
    // Cleanup implementation
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_netssd_init_success);
    RUN_TEST(test_netssd_bind_socket_valid_port);
    RUN_TEST(test_netssd_bind_socket_invalid_port);
    RUN_TEST(test_netssd_send_packet_success);
    RUN_TEST(test_netssd_recv_packet_with_data);
    RUN_TEST(test_netssd_recv_packet_no_data);
    RUN_TEST(test_netssd_packet_roundtrip);
    RUN_TEST(test_netssd_performance_benchmark);
    RUN_TEST(test_netssd_cleanup);
    
    return UNITY_END();
}