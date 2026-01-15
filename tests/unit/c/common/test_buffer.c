/**
 * @file test_buffer.c
 * @brief Unit tests for safe buffer operations
 *
 * Tests cover:
 * - Buffer initialization and validation
 * - Safe write operations with bounds checking
 * - Safe read operations with bounds checking
 * - Network byte order conversions
 * - Buffer overflow prevention
 */

#include "unity.h"
#include "buckwild/common/buffer.h"
#include <string.h>
#include <arpa/inet.h>

void setUp(void) {
    // Run before each test
}

void tearDown(void) {
    // Run after each test
}

// ============================================================================
// Buffer Initialization Tests
// ============================================================================

void test_buffer_init_valid(void) {
    uint8_t storage[128];
    buckwild_buffer_t buf;

    int result = buckwild_buffer_init(&buf, storage, sizeof(storage));

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_size_t(0, buckwild_buffer_position(&buf));
    TEST_ASSERT_EQUAL_size_t(128, buckwild_buffer_remaining(&buf));
    TEST_ASSERT_EQUAL_size_t(128, buckwild_buffer_capacity(&buf));
}

void test_buffer_init_null_buffer(void) {
    uint8_t storage[128];

    int result = buckwild_buffer_init(NULL, storage, sizeof(storage));

    TEST_ASSERT_EQUAL_INT(-EINVAL, result);
}

void test_buffer_init_null_storage(void) {
    buckwild_buffer_t buf;

    int result = buckwild_buffer_init(&buf, NULL, 128);

    TEST_ASSERT_EQUAL_INT(-EINVAL, result);
}

void test_buffer_init_zero_size(void) {
    uint8_t storage[128];
    buckwild_buffer_t buf;

    int result = buckwild_buffer_init(&buf, storage, 0);

    TEST_ASSERT_EQUAL_INT(-EINVAL, result);
}

// ============================================================================
// Buffer Write Tests
// ============================================================================

void test_buffer_write_u8(void) {
    uint8_t storage[16];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    int result = buckwild_buffer_write_u8(&buf, 0x42);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8(0x42, storage[0]);
    TEST_ASSERT_EQUAL_size_t(1, buckwild_buffer_position(&buf));
    TEST_ASSERT_EQUAL_size_t(15, buckwild_buffer_remaining(&buf));
}

void test_buffer_write_u16_be(void) {
    uint8_t storage[16];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    int result = buckwild_buffer_write_u16_be(&buf, 0x1234);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8(0x12, storage[0]);
    TEST_ASSERT_EQUAL_UINT8(0x34, storage[1]);
    TEST_ASSERT_EQUAL_size_t(2, buckwild_buffer_position(&buf));
}

void test_buffer_write_u32_be(void) {
    uint8_t storage[16];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    int result = buckwild_buffer_write_u32_be(&buf, 0x12345678);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8(0x12, storage[0]);
    TEST_ASSERT_EQUAL_UINT8(0x34, storage[1]);
    TEST_ASSERT_EQUAL_UINT8(0x56, storage[2]);
    TEST_ASSERT_EQUAL_UINT8(0x78, storage[3]);
    TEST_ASSERT_EQUAL_size_t(4, buckwild_buffer_position(&buf));
}

void test_buffer_write_u64_be(void) {
    uint8_t storage[16];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    int result = buckwild_buffer_write_u64_be(&buf, 0x123456789ABCDEF0ULL);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8(0x12, storage[0]);
    TEST_ASSERT_EQUAL_UINT8(0x34, storage[1]);
    TEST_ASSERT_EQUAL_UINT8(0x56, storage[2]);
    TEST_ASSERT_EQUAL_UINT8(0x78, storage[3]);
    TEST_ASSERT_EQUAL_UINT8(0x9A, storage[4]);
    TEST_ASSERT_EQUAL_UINT8(0xBC, storage[5]);
    TEST_ASSERT_EQUAL_UINT8(0xDE, storage[6]);
    TEST_ASSERT_EQUAL_UINT8(0xF0, storage[7]);
    TEST_ASSERT_EQUAL_size_t(8, buckwild_buffer_position(&buf));
}

void test_buffer_write_bytes(void) {
    uint8_t storage[16];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    int result = buckwild_buffer_write_bytes(&buf, data, sizeof(data));

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(data, storage, 4);
    TEST_ASSERT_EQUAL_size_t(4, buckwild_buffer_position(&buf));
}

// ============================================================================
// Buffer Read Tests
// ============================================================================

void test_buffer_read_u8(void) {
    uint8_t storage[16] = {0x42, 0x00};
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    uint8_t value;
    int result = buckwild_buffer_read_u8(&buf, &value);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8(0x42, value);
    TEST_ASSERT_EQUAL_size_t(1, buckwild_buffer_position(&buf));
}

void test_buffer_read_u16_be(void) {
    uint8_t storage[16] = {0x12, 0x34, 0x00};
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    uint16_t value;
    int result = buckwild_buffer_read_u16_be(&buf, &value);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT16(0x1234, value);
    TEST_ASSERT_EQUAL_size_t(2, buckwild_buffer_position(&buf));
}

void test_buffer_read_u32_be(void) {
    uint8_t storage[16] = {0x12, 0x34, 0x56, 0x78, 0x00};
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    uint32_t value;
    int result = buckwild_buffer_read_u32_be(&buf, &value);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT32(0x12345678, value);
    TEST_ASSERT_EQUAL_size_t(4, buckwild_buffer_position(&buf));
}

void test_buffer_read_u64_be(void) {
    uint8_t storage[16] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00};
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    uint64_t value;
    int result = buckwild_buffer_read_u64_be(&buf, &value);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT64(0x123456789ABCDEF0ULL, value);
    TEST_ASSERT_EQUAL_size_t(8, buckwild_buffer_position(&buf));
}

void test_buffer_read_bytes(void) {
    uint8_t storage[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0x00};
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    uint8_t data[4];
    int result = buckwild_buffer_read_bytes(&buf, data, sizeof(data));

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(storage, data, 4);
    TEST_ASSERT_EQUAL_size_t(4, buckwild_buffer_position(&buf));
}

// ============================================================================
// Buffer Overflow Protection Tests
// ============================================================================

void test_buffer_write_u8_overflow(void) {
    uint8_t storage[1];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    // First write should succeed
    int result1 = buckwild_buffer_write_u8(&buf, 0x42);
    TEST_ASSERT_EQUAL_INT(0, result1);

    // Second write should fail (overflow)
    int result2 = buckwild_buffer_write_u8(&buf, 0x43);
    TEST_ASSERT_EQUAL_INT(-ENOBUFS, result2);
}

void test_buffer_write_u32_overflow(void) {
    uint8_t storage[3];  // Only 3 bytes, but u32 needs 4
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    int result = buckwild_buffer_write_u32_be(&buf, 0x12345678);

    TEST_ASSERT_EQUAL_INT(-ENOBUFS, result);
}

void test_buffer_read_u8_overflow(void) {
    uint8_t storage[1] = {0x42};
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    uint8_t value;

    // First read should succeed
    int result1 = buckwild_buffer_read_u8(&buf, &value);
    TEST_ASSERT_EQUAL_INT(0, result1);

    // Second read should fail (overflow)
    int result2 = buckwild_buffer_read_u8(&buf, &value);
    TEST_ASSERT_EQUAL_INT(-ENOBUFS, result2);
}

void test_buffer_read_u32_overflow(void) {
    uint8_t storage[3] = {0x12, 0x34, 0x56};  // Only 3 bytes, but u32 needs 4
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    uint32_t value;
    int result = buckwild_buffer_read_u32_be(&buf, &value);

    TEST_ASSERT_EQUAL_INT(-ENOBUFS, result);
}

// ============================================================================
// Buffer Reset and Positioning Tests
// ============================================================================

void test_buffer_reset(void) {
    uint8_t storage[16];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    // Write some data
    buckwild_buffer_write_u32_be(&buf, 0x12345678);
    TEST_ASSERT_EQUAL_size_t(4, buckwild_buffer_position(&buf));

    // Reset buffer
    buckwild_buffer_reset(&buf);

    TEST_ASSERT_EQUAL_size_t(0, buckwild_buffer_position(&buf));
    TEST_ASSERT_EQUAL_size_t(16, buckwild_buffer_remaining(&buf));
}

void test_buffer_seek(void) {
    uint8_t storage[16];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    int result = buckwild_buffer_seek(&buf, 8);

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_size_t(8, buckwild_buffer_position(&buf));
    TEST_ASSERT_EQUAL_size_t(8, buckwild_buffer_remaining(&buf));
}

void test_buffer_seek_overflow(void) {
    uint8_t storage[16];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    int result = buckwild_buffer_seek(&buf, 20);  // Beyond buffer size

    TEST_ASSERT_EQUAL_INT(-EINVAL, result);
}

// ============================================================================
// Combined Read/Write Test
// ============================================================================

void test_buffer_combined_operations(void) {
    uint8_t storage[32];
    buckwild_buffer_t buf;
    buckwild_buffer_init(&buf, storage, sizeof(storage));

    // Write various types
    TEST_ASSERT_EQUAL_INT(0, buckwild_buffer_write_u8(&buf, 0x01));
    TEST_ASSERT_EQUAL_INT(0, buckwild_buffer_write_u16_be(&buf, 0x0203));
    TEST_ASSERT_EQUAL_INT(0, buckwild_buffer_write_u32_be(&buf, 0x04050607));

    // Reset and read back
    buckwild_buffer_reset(&buf);

    uint8_t v8;
    uint16_t v16;
    uint32_t v32;

    TEST_ASSERT_EQUAL_INT(0, buckwild_buffer_read_u8(&buf, &v8));
    TEST_ASSERT_EQUAL_UINT8(0x01, v8);

    TEST_ASSERT_EQUAL_INT(0, buckwild_buffer_read_u16_be(&buf, &v16));
    TEST_ASSERT_EQUAL_UINT16(0x0203, v16);

    TEST_ASSERT_EQUAL_INT(0, buckwild_buffer_read_u32_be(&buf, &v32));
    TEST_ASSERT_EQUAL_UINT32(0x04050607, v32);
}

// ============================================================================
// Test Runner
// ============================================================================

int main(void) {
    UNITY_BEGIN();

    // Initialization tests
    RUN_TEST(test_buffer_init_valid);
    RUN_TEST(test_buffer_init_null_buffer);
    RUN_TEST(test_buffer_init_null_storage);
    RUN_TEST(test_buffer_init_zero_size);

    // Write tests
    RUN_TEST(test_buffer_write_u8);
    RUN_TEST(test_buffer_write_u16_be);
    RUN_TEST(test_buffer_write_u32_be);
    RUN_TEST(test_buffer_write_u64_be);
    RUN_TEST(test_buffer_write_bytes);

    // Read tests
    RUN_TEST(test_buffer_read_u8);
    RUN_TEST(test_buffer_read_u16_be);
    RUN_TEST(test_buffer_read_u32_be);
    RUN_TEST(test_buffer_read_u64_be);
    RUN_TEST(test_buffer_read_bytes);

    // Overflow protection tests
    RUN_TEST(test_buffer_write_u8_overflow);
    RUN_TEST(test_buffer_write_u32_overflow);
    RUN_TEST(test_buffer_read_u8_overflow);
    RUN_TEST(test_buffer_read_u32_overflow);

    // Reset and positioning tests
    RUN_TEST(test_buffer_reset);
    RUN_TEST(test_buffer_seek);
    RUN_TEST(test_buffer_seek_overflow);

    // Combined operations test
    RUN_TEST(test_buffer_combined_operations);

    return UNITY_END();
}
