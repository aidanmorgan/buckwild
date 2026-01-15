/**
 * @file test_crypto.c
 * @brief Unit tests for cryptographic utilities (TDD - Tests First)
 *
 * Protocol Requirements:
 * - HMAC-SHA256 for message authentication
 * - PBKDF2-HMAC-SHA256 for key derivation (4096 iterations)
 * - HKDF-SHA256 for key expansion
 * - ECDH P-256 for key exchange (Stage 5)
 * - Constant-time HMAC comparison (timing attack resistance)
 * - Secure memory zeroing (prevent key leakage)
 */

#include "unity.h"
#include "buckwild/common/crypto/hmac.h"
#include "buckwild/common/crypto/kdf.h"
#include "buckwild/common/crypto/ecdh.h"
#include "buckwild/common/crypto/secure_memory.h"
#include <string.h>
#include <stdint.h>

// Test fixtures
void setUp(void) {
    // Reset any global state before each test
}

void tearDown(void) {
    // Clean up after each test
}

// ============================================================================
// Test Group 1: HMAC-SHA256 Calculation
// ============================================================================

/**
 * Test: HMAC-SHA256 produces correct output for known test vectors
 * Test Vector from RFC 4231
 */
void test_hmac_sha256_rfc4231_test_case_1(void) {
    // Test Case 1: RFC 4231
    // Key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
    // Data = "Hi There" (8 bytes)
    // HMAC = 0xb0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7

    uint8_t key[20];
    memset(key, 0x0b, 20);

    const char *data = "Hi There";

    uint8_t hmac[32];
    int result = buckwild_hmac_sha256(key, 20, (const uint8_t *)data, 8, hmac);

    // Expected HMAC from RFC 4231
    uint8_t expected[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, hmac, 32);
}

/**
 * Test: HMAC-SHA256 with longer key (RFC 4231 Test Case 2)
 */
void test_hmac_sha256_rfc4231_test_case_2(void) {
    // Key = "Jefe" (4 bytes)
    // Data = "what do ya want for nothing?" (28 bytes)
    const char *key = "Jefe";
    const char *data = "what do ya want for nothing?";

    uint8_t hmac[32];
    int result = buckwild_hmac_sha256((const uint8_t *)key, 4,
                                      (const uint8_t *)data, 28, hmac);

    // Expected HMAC from RFC 4231
    uint8_t expected[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, hmac, 32);
}

/**
 * Test: HMAC-SHA256 with empty data
 */
void test_hmac_sha256_empty_data(void) {
    uint8_t key[32] = {1, 2, 3, 4, 5};
    uint8_t hmac[32];

    // Empty data should still produce valid HMAC
    int result = buckwild_hmac_sha256(key, 32, NULL, 0, hmac);

    TEST_ASSERT_EQUAL_INT(0, result);
    // HMAC should not be all zeros
    int all_zeros = 1;
    for (int i = 0; i < 32; i++) {
        if (hmac[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zeros);
}

/**
 * Test: HMAC-SHA256 is deterministic (same input → same output)
 */
void test_hmac_sha256_deterministic(void) {
    uint8_t key[32] = {0x42};
    const char *data = "test data";

    uint8_t hmac1[32];
    uint8_t hmac2[32];

    buckwild_hmac_sha256(key, 32, (const uint8_t *)data, 9, hmac1);
    buckwild_hmac_sha256(key, 32, (const uint8_t *)data, 9, hmac2);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(hmac1, hmac2, 32);
}

// ============================================================================
// Test Group 2: Constant-Time HMAC Verification
// ============================================================================

/**
 * Test: Constant-time comparison accepts matching HMACs
 */
void test_hmac_verify_constant_time_match(void) {
    uint8_t hmac1[32];
    uint8_t hmac2[32];

    // Fill with same data
    for (int i = 0; i < 32; i++) {
        hmac1[i] = hmac2[i] = (uint8_t)i;
    }

    int result = buckwild_hmac_verify_constant_time(hmac1, hmac2, 32);
    TEST_ASSERT_EQUAL_INT(0, result); // 0 = match
}

/**
 * Test: Constant-time comparison rejects differing HMACs
 */
void test_hmac_verify_constant_time_mismatch(void) {
    uint8_t hmac1[32];
    uint8_t hmac2[32];

    // Fill with different data (differs in last byte)
    for (int i = 0; i < 32; i++) {
        hmac1[i] = (uint8_t)i;
        hmac2[i] = (uint8_t)i;
    }
    hmac2[31] = 0xFF; // Change last byte

    int result = buckwild_hmac_verify_constant_time(hmac1, hmac2, 32);
    TEST_ASSERT_NOT_EQUAL(0, result); // Non-zero = mismatch
}

/**
 * Test: Constant-time comparison works for partial HMACs (truncated)
 */
void test_hmac_verify_constant_time_truncated(void) {
    uint8_t hmac1[32];
    uint8_t hmac2[32];

    for (int i = 0; i < 32; i++) {
        hmac1[i] = hmac2[i] = (uint8_t)(i * 3);
    }

    // Verify only first 8 bytes (HMAC_LIGHT)
    int result = buckwild_hmac_verify_constant_time(hmac1, hmac2, 8);
    TEST_ASSERT_EQUAL_INT(0, result);

    // Change byte 10 (outside 8-byte comparison)
    hmac2[10] = 0xFF;
    result = buckwild_hmac_verify_constant_time(hmac1, hmac2, 8);
    TEST_ASSERT_EQUAL_INT(0, result); // Still matches (only comparing first 8)

    // Change byte 5 (inside 8-byte comparison)
    hmac2[5] = 0xFF;
    result = buckwild_hmac_verify_constant_time(hmac1, hmac2, 8);
    TEST_ASSERT_NOT_EQUAL(0, result); // Mismatch
}

// ============================================================================
// Test Group 3: PBKDF2-HMAC-SHA256 Key Derivation
// ============================================================================

/**
 * Test: PBKDF2 with known test vector (RFC 6070)
 */
void test_pbkdf2_rfc6070_test_case_1(void) {
    // Test Case 1 from RFC 6070
    // Password: "password"
    // Salt: "salt"
    // Iterations: 1
    // Key Length: 20 bytes

    const char *password = "password";
    const char *salt = "salt";
    uint8_t output[20];

    int result = buckwild_pbkdf2_hmac_sha256(
        (const uint8_t *)password, 8,
        (const uint8_t *)salt, 4,
        1,
        output, 20
    );

    // Expected output from RFC 6070
    uint8_t expected[20] = {
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
        0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9
    };

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, output, 20);
}

/**
 * Test: PBKDF2 with 4096 iterations (protocol requirement)
 */
void test_pbkdf2_protocol_iterations(void) {
    const char *password = "test_password_123";
    const char *salt = "buckwild_salt_456";
    uint8_t output[32];

    // Protocol requires 4096 iterations
    int result = buckwild_pbkdf2_hmac_sha256(
        (const uint8_t *)password, strlen(password),
        (const uint8_t *)salt, strlen(salt),
        4096,
        output, 32
    );

    TEST_ASSERT_EQUAL_INT(0, result);

    // Output should not be all zeros
    int all_zeros = 1;
    for (int i = 0; i < 32; i++) {
        if (output[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zeros);

    // Same input should produce same output (deterministic)
    uint8_t output2[32];
    buckwild_pbkdf2_hmac_sha256(
        (const uint8_t *)password, strlen(password),
        (const uint8_t *)salt, strlen(salt),
        4096,
        output2, 32
    );
    TEST_ASSERT_EQUAL_UINT8_ARRAY(output, output2, 32);
}

/**
 * Test: PBKDF2 produces different outputs for different salts
 */
void test_pbkdf2_different_salts(void) {
    const char *password = "same_password";
    const char *salt1 = "salt_one";
    const char *salt2 = "salt_two";

    uint8_t output1[32];
    uint8_t output2[32];

    buckwild_pbkdf2_hmac_sha256(
        (const uint8_t *)password, strlen(password),
        (const uint8_t *)salt1, strlen(salt1),
        1000, output1, 32
    );

    buckwild_pbkdf2_hmac_sha256(
        (const uint8_t *)password, strlen(password),
        (const uint8_t *)salt2, strlen(salt2),
        1000, output2, 32
    );

    // Outputs should be different
    int same = 1;
    for (int i = 0; i < 32; i++) {
        if (output1[i] != output2[i]) {
            same = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(same);
}

// ============================================================================
// Test Group 4: HKDF-SHA256 Key Expansion
// ============================================================================

/**
 * Test: HKDF with RFC 5869 test vector
 */
void test_hkdf_rfc5869_test_case_1(void) {
    // Test Case 1 from RFC 5869
    // IKM (Input Keying Material): 0x0b0b0b0b... (22 bytes)
    // Salt: 0x000102030405060708090a0b0c (13 bytes)
    // Info: 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
    // L (output length): 42 bytes

    uint8_t ikm[22];
    memset(ikm, 0x0b, 22);

    uint8_t salt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};

    uint8_t info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                        0xf5, 0xf6, 0xf7, 0xf8, 0xf9};

    uint8_t output[42];

    int result = buckwild_hkdf_sha256(
        salt, 13,
        ikm, 22,
        info, 10,
        output, 42
    );

    // Expected output from RFC 5869
    uint8_t expected[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, output, 42);
}

/**
 * Test: HKDF produces deterministic output
 */
void test_hkdf_deterministic(void) {
    uint8_t ikm[32] = {0x42};
    uint8_t salt[16] = {0x01};
    uint8_t info[8] = {0xFF};

    uint8_t output1[64];
    uint8_t output2[64];

    buckwild_hkdf_sha256(salt, 16, ikm, 32, info, 8, output1, 64);
    buckwild_hkdf_sha256(salt, 16, ikm, 32, info, 8, output2, 64);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(output1, output2, 64);
}

/**
 * Test: HKDF with NULL salt uses zero salt
 */
void test_hkdf_null_salt(void) {
    uint8_t ikm[32] = {0x42};
    uint8_t info[8] = {0xFF};
    uint8_t output[32];

    // NULL salt should be handled gracefully
    int result = buckwild_hkdf_sha256(NULL, 0, ikm, 32, info, 8, output, 32);

    TEST_ASSERT_EQUAL_INT(0, result);

    // Output should not be all zeros
    int all_zeros = 1;
    for (int i = 0; i < 32; i++) {
        if (output[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zeros);
}

// ============================================================================
// Test Group 5: Secure Memory Operations
// ============================================================================

/**
 * Test: Secure memory zeroing actually zeros memory
 */
void test_secure_zero_memory_zeros_data(void) {
    uint8_t sensitive_data[64];

    // Fill with non-zero data
    for (int i = 0; i < 64; i++) {
        sensitive_data[i] = (uint8_t)(i + 1);
    }

    // Zero securely
    buckwild_secure_zero_memory(sensitive_data, 64);

    // Verify all bytes are zero
    for (int i = 0; i < 64; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, sensitive_data[i]);
    }
}

/**
 * Test: Secure zeroing handles NULL pointer gracefully
 */
void test_secure_zero_memory_null_pointer(void) {
    // Should not crash
    buckwild_secure_zero_memory(NULL, 64);
    TEST_ASSERT_TRUE(1); // If we get here, test passed
}

/**
 * Test: Secure zeroing handles zero length
 */
void test_secure_zero_memory_zero_length(void) {
    uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    // Zero-length should be no-op
    buckwild_secure_zero_memory(data, 0);

    // Data should be unchanged
    TEST_ASSERT_EQUAL_UINT8(1, data[0]);
    TEST_ASSERT_EQUAL_UINT8(8, data[7]);
}

// ============================================================================
// Test Group 5: ECDH P-256 Key Exchange (Stage 5)
// ============================================================================

/**
 * Test: ECDH key generation produces valid keys
 */
void test_ecdh_generate_keypair_success(void) {
    uint8_t private_key[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];

    int result = buckwild_ecdh_generate_keypair(private_key, public_key);

    TEST_ASSERT_EQUAL_INT(0, result);

    // Verify keys are not all zeros
    int private_all_zeros = 1;
    for (int i = 0; i < BUCKWILD_ECDH_PRIVATE_KEY_SIZE; i++) {
        if (private_key[i] != 0) {
            private_all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(private_all_zeros);

    int public_all_zeros = 1;
    for (int i = 0; i < BUCKWILD_ECDH_PUBLIC_KEY_SIZE; i++) {
        if (public_key[i] != 0) {
            public_all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(public_all_zeros);

    // Clean up
    buckwild_secure_zero_memory(private_key, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
}

/**
 * Test: ECDH key generation produces different keys on each call
 */
void test_ecdh_generate_keypair_randomness(void) {
    uint8_t private_key1[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key1[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];
    uint8_t private_key2[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key2[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];

    buckwild_ecdh_generate_keypair(private_key1, public_key1);
    buckwild_ecdh_generate_keypair(private_key2, public_key2);

    // Keys should be different (statistically certain)
    int keys_different = 0;
    for (int i = 0; i < BUCKWILD_ECDH_PRIVATE_KEY_SIZE; i++) {
        if (private_key1[i] != private_key2[i]) {
            keys_different = 1;
            break;
        }
    }
    TEST_ASSERT_TRUE(keys_different);

    // Clean up
    buckwild_secure_zero_memory(private_key1, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    buckwild_secure_zero_memory(private_key2, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
}

/**
 * Test: ECDH shared secret computation succeeds with valid keys
 */
void test_ecdh_compute_shared_secret_success(void) {
    // Generate two key pairs
    uint8_t private_a[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_a[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];
    uint8_t private_b[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_b[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];

    buckwild_ecdh_generate_keypair(private_a, public_a);
    buckwild_ecdh_generate_keypair(private_b, public_b);

    // Compute shared secrets
    uint8_t shared_secret_a[BUCKWILD_ECDH_SHARED_SECRET_SIZE];
    uint8_t shared_secret_b[BUCKWILD_ECDH_SHARED_SECRET_SIZE];

    int result_a = buckwild_ecdh_compute_shared_secret(private_a, public_b, shared_secret_a);
    int result_b = buckwild_ecdh_compute_shared_secret(private_b, public_a, shared_secret_b);

    TEST_ASSERT_EQUAL_INT(0, result_a);
    TEST_ASSERT_EQUAL_INT(0, result_b);

    // Shared secrets should match (ECDH property)
    TEST_ASSERT_EQUAL_UINT8_ARRAY(shared_secret_a, shared_secret_b, BUCKWILD_ECDH_SHARED_SECRET_SIZE);

    // Shared secret should not be all zeros
    int all_zeros = 1;
    for (int i = 0; i < BUCKWILD_ECDH_SHARED_SECRET_SIZE; i++) {
        if (shared_secret_a[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zeros);

    // Clean up
    buckwild_secure_zero_memory(private_a, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    buckwild_secure_zero_memory(private_b, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    buckwild_secure_zero_memory(shared_secret_a, BUCKWILD_ECDH_SHARED_SECRET_SIZE);
    buckwild_secure_zero_memory(shared_secret_b, BUCKWILD_ECDH_SHARED_SECRET_SIZE);
}

/**
 * Test: ECDH shared secret is deterministic
 */
void test_ecdh_shared_secret_deterministic(void) {
    // Generate key pairs
    uint8_t private_a[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_a[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];
    uint8_t private_b[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_b[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];

    buckwild_ecdh_generate_keypair(private_a, public_a);
    buckwild_ecdh_generate_keypair(private_b, public_b);

    // Compute shared secret twice
    uint8_t shared_secret1[BUCKWILD_ECDH_SHARED_SECRET_SIZE];
    uint8_t shared_secret2[BUCKWILD_ECDH_SHARED_SECRET_SIZE];

    buckwild_ecdh_compute_shared_secret(private_a, public_b, shared_secret1);
    buckwild_ecdh_compute_shared_secret(private_a, public_b, shared_secret2);

    // Should be identical
    TEST_ASSERT_EQUAL_UINT8_ARRAY(shared_secret1, shared_secret2, BUCKWILD_ECDH_SHARED_SECRET_SIZE);

    // Clean up
    buckwild_secure_zero_memory(private_a, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    buckwild_secure_zero_memory(private_b, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    buckwild_secure_zero_memory(shared_secret1, BUCKWILD_ECDH_SHARED_SECRET_SIZE);
    buckwild_secure_zero_memory(shared_secret2, BUCKWILD_ECDH_SHARED_SECRET_SIZE);
}

/**
 * Test: Different key pairs produce different shared secrets
 */
void test_ecdh_different_keys_different_secrets(void) {
    // Generate three key pairs
    uint8_t private_a[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_a[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];
    uint8_t private_b[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_b[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];
    uint8_t private_c[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_c[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];

    buckwild_ecdh_generate_keypair(private_a, public_a);
    buckwild_ecdh_generate_keypair(private_b, public_b);
    buckwild_ecdh_generate_keypair(private_c, public_c);

    // Compute different shared secrets
    uint8_t shared_ab[BUCKWILD_ECDH_SHARED_SECRET_SIZE];
    uint8_t shared_ac[BUCKWILD_ECDH_SHARED_SECRET_SIZE];

    buckwild_ecdh_compute_shared_secret(private_a, public_b, shared_ab);
    buckwild_ecdh_compute_shared_secret(private_a, public_c, shared_ac);

    // Shared secrets should be different
    int secrets_different = 0;
    for (int i = 0; i < BUCKWILD_ECDH_SHARED_SECRET_SIZE; i++) {
        if (shared_ab[i] != shared_ac[i]) {
            secrets_different = 1;
            break;
        }
    }
    TEST_ASSERT_TRUE(secrets_different);

    // Clean up
    buckwild_secure_zero_memory(private_a, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    buckwild_secure_zero_memory(private_b, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    buckwild_secure_zero_memory(private_c, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    buckwild_secure_zero_memory(shared_ab, BUCKWILD_ECDH_SHARED_SECRET_SIZE);
    buckwild_secure_zero_memory(shared_ac, BUCKWILD_ECDH_SHARED_SECRET_SIZE);
}

/**
 * Test: ECDH rejects NULL private key output
 */
void test_ecdh_generate_keypair_null_private_key(void) {
    uint8_t public_key[BUCKWILD_ECDH_PUBLIC_KEY_SIZE];

    int result = buckwild_ecdh_generate_keypair(NULL, public_key);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

/**
 * Test: ECDH rejects NULL public key output
 */
void test_ecdh_generate_keypair_null_public_key(void) {
    uint8_t private_key[BUCKWILD_ECDH_PRIVATE_KEY_SIZE];

    int result = buckwild_ecdh_generate_keypair(private_key, NULL);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

/**
 * Test: ECDH shared secret rejects NULL private key
 */
void test_ecdh_compute_shared_secret_null_private_key(void) {
    uint8_t public_key[BUCKWILD_ECDH_PUBLIC_KEY_SIZE] = {0};
    uint8_t shared_secret[BUCKWILD_ECDH_SHARED_SECRET_SIZE] = {0};

    int result = buckwild_ecdh_compute_shared_secret(NULL, public_key, shared_secret);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

/**
 * Test: ECDH shared secret rejects NULL public key
 */
void test_ecdh_compute_shared_secret_null_public_key(void) {
    uint8_t private_key[BUCKWILD_ECDH_PRIVATE_KEY_SIZE] = {0};
    uint8_t shared_secret[BUCKWILD_ECDH_SHARED_SECRET_SIZE] = {0};

    int result = buckwild_ecdh_compute_shared_secret(private_key, NULL, shared_secret);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

/**
 * Test: ECDH shared secret rejects NULL output
 */
void test_ecdh_compute_shared_secret_null_output(void) {
    uint8_t private_key[BUCKWILD_ECDH_PRIVATE_KEY_SIZE] = {0};
    uint8_t public_key[BUCKWILD_ECDH_PUBLIC_KEY_SIZE] = {0};

    int result = buckwild_ecdh_compute_shared_secret(private_key, public_key, NULL);

    TEST_ASSERT_NOT_EQUAL(0, result);
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main(void) {
    UNITY_BEGIN();

    // HMAC-SHA256 calculation tests
    RUN_TEST(test_hmac_sha256_rfc4231_test_case_1);
    RUN_TEST(test_hmac_sha256_rfc4231_test_case_2);
    RUN_TEST(test_hmac_sha256_empty_data);
    RUN_TEST(test_hmac_sha256_deterministic);

    // Constant-time HMAC verification tests
    RUN_TEST(test_hmac_verify_constant_time_match);
    RUN_TEST(test_hmac_verify_constant_time_mismatch);
    RUN_TEST(test_hmac_verify_constant_time_truncated);

    // PBKDF2 key derivation tests
    RUN_TEST(test_pbkdf2_rfc6070_test_case_1);
    RUN_TEST(test_pbkdf2_protocol_iterations);
    RUN_TEST(test_pbkdf2_different_salts);

    // HKDF key expansion tests
    RUN_TEST(test_hkdf_rfc5869_test_case_1);
    RUN_TEST(test_hkdf_deterministic);
    RUN_TEST(test_hkdf_null_salt);

    // Secure memory operation tests
    RUN_TEST(test_secure_zero_memory_zeros_data);
    RUN_TEST(test_secure_zero_memory_null_pointer);
    RUN_TEST(test_secure_zero_memory_zero_length);

    // ECDH P-256 key exchange tests (Stage 5)
    RUN_TEST(test_ecdh_generate_keypair_success);
    RUN_TEST(test_ecdh_generate_keypair_randomness);
    RUN_TEST(test_ecdh_compute_shared_secret_success);
    RUN_TEST(test_ecdh_shared_secret_deterministic);
    RUN_TEST(test_ecdh_different_keys_different_secrets);
    RUN_TEST(test_ecdh_generate_keypair_null_private_key);
    RUN_TEST(test_ecdh_generate_keypair_null_public_key);
    RUN_TEST(test_ecdh_compute_shared_secret_null_private_key);
    RUN_TEST(test_ecdh_compute_shared_secret_null_public_key);
    RUN_TEST(test_ecdh_compute_shared_secret_null_output);

    return UNITY_END();
}
