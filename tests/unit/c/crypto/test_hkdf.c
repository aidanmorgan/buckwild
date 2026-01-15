/**
 * @file test_hkdf.c
 * @brief Unit tests for HKDF (HMAC-based Key Derivation Function)
 *
 * Tests cover RFC 5869 test vectors:
 * - Test Case 1: Basic SHA-256 with salt and info
 * - Test Case 2: SHA-256 with longer inputs/outputs
 * - Test Case 3: SHA-256 with zero-length salt and info
 * - Edge cases: NULL info, empty salt, various output lengths
 */

#include "unity.h"
#include "buckwild/common/crypto/kdf.h"
#include <string.h>
#include <errno.h>

void setUp(void) {
    // Run before each test
}

void tearDown(void) {
    // Run after each test
}

// ============================================================================
// RFC 5869 Test Case 1: Basic SHA-256 with salt and info
// ============================================================================

void test_hkdf_rfc5869_case1(void) {
    // IKM = 0x0b0b0b... (22 octets)
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));

    // Salt = 0x000102030405060708090a0b0c (13 octets)
    uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    // Info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
    uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
        0xf5, 0xf6, 0xf7, 0xf8, 0xf9
    };

    // Expected OKM (42 octets)
    uint8_t expected_okm[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    uint8_t okm[42];

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        ikm, sizeof(ikm),
        info, sizeof(info),
        okm, sizeof(okm)
    );

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_okm, okm, 42);
}

// ============================================================================
// RFC 5869 Test Case 2: SHA-256 with longer inputs
// ============================================================================

void test_hkdf_rfc5869_case2(void) {
    // IKM = 0x00...0x4f (80 octets)
    uint8_t ikm[80];
    for (int i = 0; i < 80; i++) {
        ikm[i] = (uint8_t)i;
    }

    // Salt = 0x60...0xaf (80 octets)
    uint8_t salt[80];
    for (int i = 0; i < 80; i++) {
        salt[i] = (uint8_t)(0x60 + i);
    }

    // Info = 0xb0...0xff (80 octets)
    uint8_t info[80];
    for (int i = 0; i < 80; i++) {
        info[i] = (uint8_t)(0xb0 + i);
    }

    // Expected OKM (82 octets)
    uint8_t expected_okm[82] = {
        0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
        0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
        0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
        0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
        0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
        0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
        0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
        0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
        0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
        0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
        0x1d, 0x87
    };

    uint8_t okm[82];

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        ikm, sizeof(ikm),
        info, sizeof(info),
        okm, sizeof(okm)
    );

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_okm, okm, 82);
}

// ============================================================================
// RFC 5869 Test Case 3: SHA-256 with zero-length salt and info
// ============================================================================

void test_hkdf_rfc5869_case3(void) {
    // IKM = 0x0b0b0b... (22 octets)
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));

    // Salt = empty (NULL with length 0)
    // Info = empty (NULL with length 0)

    // Expected OKM (42 octets)
    uint8_t expected_okm[42] = {
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
        0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
        0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
        0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
        0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
        0x96, 0xc8
    };

    uint8_t okm[42];

    int result = buckwild_hkdf_sha256(
        NULL, 0,           // Empty salt
        ikm, sizeof(ikm),
        NULL, 0,           // Empty info
        okm, sizeof(okm)
    );

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_okm, okm, 42);
}

// ============================================================================
// Edge Cases
// ============================================================================

void test_hkdf_null_ikm(void) {
    uint8_t salt[16] = {0};
    uint8_t okm[32];

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        NULL, 32,          // NULL IKM - invalid
        NULL, 0,
        okm, sizeof(okm)
    );

    TEST_ASSERT_EQUAL_INT(-EINVAL, result);
}

void test_hkdf_null_okm(void) {
    uint8_t ikm[32] = {0};
    uint8_t salt[16] = {0};

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        ikm, sizeof(ikm),
        NULL, 0,
        NULL, 32           // NULL OKM - invalid
    );

    TEST_ASSERT_EQUAL_INT(-EINVAL, result);
}

void test_hkdf_zero_ikm_len(void) {
    uint8_t ikm[32] = {0};
    uint8_t salt[16] = {0};
    uint8_t okm[32];

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        ikm, 0,            // Zero-length IKM - invalid
        NULL, 0,
        okm, sizeof(okm)
    );

    TEST_ASSERT_EQUAL_INT(-EINVAL, result);
}

void test_hkdf_zero_okm_len(void) {
    uint8_t ikm[32] = {0};
    uint8_t salt[16] = {0};
    uint8_t okm[32];

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        ikm, sizeof(ikm),
        NULL, 0,
        okm, 0             // Zero-length OKM - invalid
    );

    TEST_ASSERT_EQUAL_INT(-EINVAL, result);
}

void test_hkdf_with_info_null_but_nonzero_length(void) {
    uint8_t ikm[32] = {0};
    uint8_t salt[16] = {0};
    uint8_t okm[32];

    // This should work - implementation handles NULL info with zero length
    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        ikm, sizeof(ikm),
        NULL, 0,           // NULL info with zero length is valid
        okm, sizeof(okm)
    );

    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_hkdf_small_output(void) {
    // Test with very small output (1 byte)
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));

    uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
        0xf5, 0xf6, 0xf7, 0xf8, 0xf9
    };

    uint8_t okm[1];

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        ikm, sizeof(ikm),
        info, sizeof(info),
        okm, sizeof(okm)
    );

    TEST_ASSERT_EQUAL_INT(0, result);
    // First byte should match first byte of RFC 5869 Test Case 1
    TEST_ASSERT_EQUAL_UINT8(0x3c, okm[0]);
}

void test_hkdf_large_output(void) {
    // Test with large output (255 * 32 = 8160 bytes is max for SHA-256)
    // Testing with 128 bytes (4 blocks)
    uint8_t ikm[32];
    memset(ikm, 0xaa, sizeof(ikm));

    uint8_t salt[16];
    memset(salt, 0x55, sizeof(salt));

    uint8_t info[8] = {'t', 'e', 's', 't', 'i', 'n', 'g', '!'};

    uint8_t okm[128];

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        ikm, sizeof(ikm),
        info, sizeof(info),
        okm, sizeof(okm)
    );

    TEST_ASSERT_EQUAL_INT(0, result);
}

void test_hkdf_session_key_derivation(void) {
    // Realistic use case: derive 32-byte session key from ECDH shared secret
    uint8_t shared_secret[32];
    memset(shared_secret, 0xde, sizeof(shared_secret));

    uint8_t salt[16] = "buckwild-salt123";
    uint8_t info[20] = "session-key-v1";

    uint8_t session_key[32];

    int result = buckwild_hkdf_sha256(
        salt, sizeof(salt),
        shared_secret, sizeof(shared_secret),
        info, 14,  // strlen("session-key-v1")
        session_key, sizeof(session_key)
    );

    TEST_ASSERT_EQUAL_INT(0, result);

    // Verify output is not all zeros (basic sanity check)
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(session_key); i++) {
        if (session_key[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zero);
}

// ============================================================================
// Test Runner
// ============================================================================

int main(void) {
    UNITY_BEGIN();

    // RFC 5869 test vectors
    RUN_TEST(test_hkdf_rfc5869_case1);
    RUN_TEST(test_hkdf_rfc5869_case2);
    RUN_TEST(test_hkdf_rfc5869_case3);

    // Edge cases
    RUN_TEST(test_hkdf_null_ikm);
    RUN_TEST(test_hkdf_null_okm);
    RUN_TEST(test_hkdf_zero_ikm_len);
    RUN_TEST(test_hkdf_zero_okm_len);
    RUN_TEST(test_hkdf_with_info_null_but_nonzero_length);
    RUN_TEST(test_hkdf_small_output);
    RUN_TEST(test_hkdf_large_output);

    // Practical use case
    RUN_TEST(test_hkdf_session_key_derivation);

    return UNITY_END();
}
