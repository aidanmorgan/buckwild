/**
 * Common test utilities for C unit tests
 */

#include "test_utils.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

void test_utils_setup(void) {
    // Initialize random seed for tests
    srand((unsigned int)time(NULL));
}

void test_utils_teardown(void) {
    // Cleanup any global test state
}

void create_test_packet(struct test_packet *packet, size_t size) {
    if (!packet || size == 0 || size > MAX_TEST_PACKET_SIZE) {
        return;
    }
    
    packet->size = size;
    
    // Fill with test pattern
    for (size_t i = 0; i < size; i++) {
        packet->data[i] = (uint8_t)(i % 256);
    }
}

void create_random_packet(struct test_packet *packet, size_t size) {
    if (!packet || size == 0 || size > MAX_TEST_PACKET_SIZE) {
        return;
    }
    
    packet->size = size;
    
    // Fill with random data
    for (size_t i = 0; i < size; i++) {
        packet->data[i] = (uint8_t)(rand() % 256);
    }
}

int compare_packets(const struct test_packet *a, const struct test_packet *b) {
    if (!a || !b) {
        return -1;
    }
    
    if (a->size != b->size) {
        return (int)(a->size - b->size);
    }
    
    return memcmp(a->data, b->data, a->size);
}

void assert_packet_equal(const struct test_packet *expected, const struct test_packet *actual) {
    TEST_ASSERT_NOT_NULL(expected);
    TEST_ASSERT_NOT_NULL(actual);
    TEST_ASSERT_EQUAL_size_t(expected->size, actual->size);
    TEST_ASSERT_EQUAL_MEMORY(expected->data, actual->data, expected->size);
}

void assert_memory_zeroed(const void *ptr, size_t size) {
    TEST_ASSERT_NOT_NULL(ptr);
    
    const uint8_t *bytes = (const uint8_t *)ptr;
    for (size_t i = 0; i < size; i++) {
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, bytes[i], "Memory not properly zeroed");
    }
}

uint64_t get_test_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void benchmark_start(struct test_benchmark *bench) {
    if (!bench) return;
    
    bench->start_time = get_test_timestamp();
    bench->iterations = 0;
}

void benchmark_end(struct test_benchmark *bench) {
    if (!bench) return;
    
    bench->end_time = get_test_timestamp();
    bench->duration_ns = bench->end_time - bench->start_time;
}

void benchmark_iteration(struct test_benchmark *bench) {
    if (!bench) return;
    
    bench->iterations++;
}

double benchmark_get_avg_time_us(const struct test_benchmark *bench) {
    if (!bench || bench->iterations == 0) {
        return 0.0;
    }
    
    return (double)bench->duration_ns / (double)bench->iterations / 1000.0;
}