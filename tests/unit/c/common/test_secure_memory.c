/**
 * @file test_secure_memory.c
 * @brief Comprehensive tests for secure memory operations
 *
 * Tests cover:
 * - Basic secure zeroing functionality
 * - Edge cases (NULL, zero length, partial zeroing)
 * - Compiler optimization resistance
 * - Buffer boundary protection
 * - Different data patterns
 */

#include "unity.h"
#include "buckwild/common/crypto/secure_memory.h"
#include <string.h>

void setUp(void) {
    // Run before each test
}

void tearDown(void) {
    // Run after each test
}

// ============================================================================
// Basic Functionality Tests
// ============================================================================

void test_secure_zero_memory_zeros_single_byte(void) {
    uint8_t data = 0xFF;
    buckwild_secure_zero_memory(&data, 1);
    TEST_ASSERT_EQUAL_UINT8(0, data);
}

void test_secure_zero_memory_zeros_small_buffer(void) {
    uint8_t buffer[16];

    // Fill with pattern
    for (int i = 0; i < 16; i++) {
        buffer[i] = (uint8_t)(0xAA + i);
    }

    // Zero securely
    buckwild_secure_zero_memory(buffer, 16);

    // Verify all zeros
    for (int i = 0; i < 16; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }
}

void test_secure_zero_memory_zeros_large_buffer(void) {
    uint8_t buffer[1024];

    // Fill with pattern
    for (int i = 0; i < 1024; i++) {
        buffer[i] = (uint8_t)(i & 0xFF);
    }

    // Zero securely
    buckwild_secure_zero_memory(buffer, 1024);

    // Verify all zeros
    for (int i = 0; i < 1024; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }
}

void test_secure_zero_memory_zeros_key_material(void) {
    // Simulate sensitive key material (32-byte key)
    uint8_t key[32];

    // Fill with pseudorandom data
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)((i * 7 + 13) & 0xFF);
    }

    // Zero securely
    buckwild_secure_zero_memory(key, 32);

    // Verify complete zeroing
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, key[i]);
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

void test_secure_zero_memory_null_pointer(void) {
    // Should not crash
    buckwild_secure_zero_memory(NULL, 64);
    TEST_ASSERT_TRUE(1);
}

void test_secure_zero_memory_zero_length(void) {
    uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    // Zero-length should be no-op
    buckwild_secure_zero_memory(data, 0);

    // Data should be unchanged
    TEST_ASSERT_EQUAL_UINT8(1, data[0]);
    TEST_ASSERT_EQUAL_UINT8(8, data[7]);
}

void test_secure_zero_memory_partial_buffer(void) {
    uint8_t buffer[32];

    // Fill entire buffer
    for (int i = 0; i < 32; i++) {
        buffer[i] = (uint8_t)(i + 100);
    }

    // Zero only first half
    buckwild_secure_zero_memory(buffer, 16);

    // First half should be zero
    for (int i = 0; i < 16; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }

    // Second half should be unchanged
    for (int i = 16; i < 32; i++) {
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(i + 100), buffer[i]);
    }
}

// ============================================================================
// Optimization Resistance Tests
// ============================================================================

void test_secure_zero_memory_not_optimized_away_stack(void) {
    // This test verifies that zeroing happens even for stack-allocated data
    // that goes out of scope immediately after zeroing

    uint8_t sensitive_data[64];

    // Fill with pattern
    for (int i = 0; i < 64; i++) {
        sensitive_data[i] = (uint8_t)(0x55 + i);
    }

    // Zero - compiler should not optimize this away even though
    // the data goes out of scope after this function
    buckwild_secure_zero_memory(sensitive_data, 64);

    // Verify zeroing happened
    for (int i = 0; i < 64; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, sensitive_data[i]);
    }
}

void test_secure_zero_memory_different_patterns(void) {
    // Test with different bit patterns to ensure thorough zeroing
    uint8_t buffer[16];

    const uint8_t patterns[] = {0x00, 0xFF, 0xAA, 0x55, 0x0F, 0xF0};

    for (size_t p = 0; p < sizeof(patterns); p++) {
        // Fill with pattern
        memset(buffer, patterns[p], 16);

        // Zero securely
        buckwild_secure_zero_memory(buffer, 16);

        // Verify all zeros
        for (int i = 0; i < 16; i++) {
            TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
        }
    }
}

// ============================================================================
// Buffer Boundary Tests
// ============================================================================

void test_secure_zero_memory_respects_boundaries(void) {
    // Create a buffer with sentinel values before and after the target region
    struct {
        uint8_t before[8];
        uint8_t target[32];
        uint8_t after[8];
    } __attribute__((packed)) test_buffer;

    // Fill sentinels with non-zero pattern
    memset(test_buffer.before, 0xBE, 8);
    memset(test_buffer.after, 0xAF, 8);

    // Fill target with different pattern
    memset(test_buffer.target, 0x42, 32);

    // Zero only the target region
    buckwild_secure_zero_memory(test_buffer.target, 32);

    // Verify target is zeroed
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, test_buffer.target[i]);
    }

    // Verify sentinels are unchanged (no buffer overrun)
    for (int i = 0; i < 8; i++) {
        TEST_ASSERT_EQUAL_UINT8(0xBE, test_buffer.before[i]);
        TEST_ASSERT_EQUAL_UINT8(0xAF, test_buffer.after[i]);
    }
}

void test_secure_zero_memory_odd_length(void) {
    // Test with non-power-of-2 lengths
    uint8_t buffer[37];

    // Fill with pattern
    for (int i = 0; i < 37; i++) {
        buffer[i] = (uint8_t)(i + 200);
    }

    // Zero with odd length
    buckwild_secure_zero_memory(buffer, 37);

    // Verify all zeros
    for (int i = 0; i < 37; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }
}

void test_secure_zero_memory_unaligned_pointer(void) {
    // Test with unaligned memory access
    uint8_t buffer[64];

    // Fill entire buffer
    for (int i = 0; i < 64; i++) {
        buffer[i] = (uint8_t)(i + 50);
    }

    // Zero from an unaligned offset
    buckwild_secure_zero_memory(buffer + 3, 40);

    // Verify first 3 bytes unchanged
    TEST_ASSERT_EQUAL_UINT8(50, buffer[0]);
    TEST_ASSERT_EQUAL_UINT8(51, buffer[1]);
    TEST_ASSERT_EQUAL_UINT8(52, buffer[2]);

    // Verify middle 40 bytes zeroed
    for (int i = 3; i < 43; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }

    // Verify last bytes unchanged
    for (int i = 43; i < 64; i++) {
        TEST_ASSERT_EQUAL_UINT8((uint8_t)(i + 50), buffer[i]);
    }
}

// ============================================================================
// Security Property Tests
// ============================================================================

void test_secure_zero_memory_multiple_calls(void) {
    // Test that multiple zeroing operations work correctly
    uint8_t buffer[32];

    // First fill and zero
    memset(buffer, 0xAA, 32);
    buckwild_secure_zero_memory(buffer, 32);

    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }

    // Second fill and zero
    memset(buffer, 0x55, 32);
    buckwild_secure_zero_memory(buffer, 32);

    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }
}

void test_secure_zero_memory_after_use_pattern(void) {
    // Simulate typical usage: allocate, use, zero, deallocate
    const size_t key_size = 32;
    uint8_t session_key[32];

    // Simulate key generation
    for (size_t i = 0; i < key_size; i++) {
        session_key[i] = (uint8_t)((i * 17 + 23) & 0xFF);
    }

    // Simulate key usage (verify key is not all zeros)
    int non_zero_count = 0;
    for (size_t i = 0; i < key_size; i++) {
        if (session_key[i] != 0) {
            non_zero_count++;
        }
    }
    TEST_ASSERT_GREATER_THAN(0, non_zero_count);

    // Clear before "deallocation"
    buckwild_secure_zero_memory(session_key, key_size);

    // Verify complete zeroing
    for (size_t i = 0; i < key_size; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, session_key[i]);
    }
}

// ============================================================================
// Test Runner
// ============================================================================

int main(void) {
    UNITY_BEGIN();

    // Basic functionality
    RUN_TEST(test_secure_zero_memory_zeros_single_byte);
    RUN_TEST(test_secure_zero_memory_zeros_small_buffer);
    RUN_TEST(test_secure_zero_memory_zeros_large_buffer);
    RUN_TEST(test_secure_zero_memory_zeros_key_material);

    // Edge cases
    RUN_TEST(test_secure_zero_memory_null_pointer);
    RUN_TEST(test_secure_zero_memory_zero_length);
    RUN_TEST(test_secure_zero_memory_partial_buffer);

    // Optimization resistance
    RUN_TEST(test_secure_zero_memory_not_optimized_away_stack);
    RUN_TEST(test_secure_zero_memory_different_patterns);

    // Buffer boundaries
    RUN_TEST(test_secure_zero_memory_respects_boundaries);
    RUN_TEST(test_secure_zero_memory_odd_length);
    RUN_TEST(test_secure_zero_memory_unaligned_pointer);

    // Security properties
    RUN_TEST(test_secure_zero_memory_multiple_calls);
    RUN_TEST(test_secure_zero_memory_after_use_pattern);

    return UNITY_END();
}
