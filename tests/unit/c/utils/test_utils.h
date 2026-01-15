/**
 * Common test utilities header
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <unity.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_TEST_PACKET_SIZE 2048

/**
 * Test packet structure for testing
 */
struct test_packet {
    uint8_t data[MAX_TEST_PACKET_SIZE];
    size_t size;
};

/**
 * Benchmark structure for performance testing
 */
struct test_benchmark {
    uint64_t start_time;
    uint64_t end_time;
    uint64_t duration_ns;
    uint32_t iterations;
};

/**
 * Test setup and teardown
 */
void test_utils_setup(void);
void test_utils_teardown(void);

/**
 * Packet creation utilities
 */
void create_test_packet(struct test_packet *packet, size_t size);
void create_random_packet(struct test_packet *packet, size_t size);
int compare_packets(const struct test_packet *a, const struct test_packet *b);

/**
 * Enhanced assertion helpers
 */
void assert_packet_equal(const struct test_packet *expected, const struct test_packet *actual);
void assert_memory_zeroed(const void *ptr, size_t size);

/**
 * Timing utilities
 */
uint64_t get_test_timestamp(void);

/**
 * Benchmark utilities
 */
void benchmark_start(struct test_benchmark *bench);
void benchmark_end(struct test_benchmark *bench);
void benchmark_iteration(struct test_benchmark *bench);
double benchmark_get_avg_time_us(const struct test_benchmark *bench);

#endif // TEST_UTILS_H