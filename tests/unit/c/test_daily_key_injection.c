/**
 * @file test_daily_key_injection.c
 * @brief Unit tests for daily key injection via FFI (TASK-010)
 *
 * Tests the netssd_set_daily_key() and callback mechanism that enables
 * Rust DailyKeyScheduler to inject daily keys into C network stack.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

// Forward declarations of netssd functions
int netssd_set_daily_key(const uint8_t *key, size_t key_len);
typedef void (*netssd_key_update_callback_t)(const uint8_t *key, size_t key_len);
int netssd_register_key_update_callback(netssd_key_update_callback_t callback);
int buckwild_netssd_init(const char *config_path);
int buckwild_netssd_shutdown(void);

// Test callback state
static int callback_invoked = 0;
static uint8_t callback_key[32];
static size_t callback_key_len = 0;

void test_key_update_callback(const uint8_t *key, size_t key_len) {
    callback_invoked = 1;
    callback_key_len = key_len;
    if (key && key_len <= 32) {
        memcpy(callback_key, key, key_len);
    }
}

void test_key_injection_basic(void) {
    printf("TEST: Key injection basic validation...\n");

    // Valid 32-byte key
    uint8_t valid_key[32];
    for (int i = 0; i < 32; i++) {
        valid_key[i] = (uint8_t)(i + 1); // Non-zero key
    }

    int result = netssd_set_daily_key(valid_key, 32);
    assert(result == 0);
    printf("  PASS: Valid key accepted\n");
}

void test_key_injection_null_key(void) {
    printf("TEST: Null key rejection...\n");

    int result = netssd_set_daily_key(NULL, 32);
    assert(result < 0);
    printf("  PASS: Null key rejected\n");
}

void test_key_injection_wrong_length(void) {
    printf("TEST: Wrong key length rejection...\n");

    uint8_t key[16];
    memset(key, 0x42, sizeof(key));

    int result = netssd_set_daily_key(key, 16);
    assert(result < 0);
    printf("  PASS: Wrong length (16 bytes) rejected\n");

    result = netssd_set_daily_key(key, 64);
    assert(result < 0);
    printf("  PASS: Wrong length (64 bytes) rejected\n");
}

void test_key_injection_zero_key(void) {
    printf("TEST: All-zero key rejection...\n");

    uint8_t zero_key[32];
    memset(zero_key, 0, sizeof(zero_key));

    int result = netssd_set_daily_key(zero_key, 32);
    assert(result < 0);
    printf("  PASS: All-zero key rejected\n");
}

void test_key_update_callback_mechanism(void) {
    printf("TEST: Key update callback mechanism...\n");

    // Reset callback state
    callback_invoked = 0;
    callback_key_len = 0;
    memset(callback_key, 0, sizeof(callback_key));

    // Register callback
    int result = netssd_register_key_update_callback(test_key_update_callback);
    assert(result == 0);
    printf("  PASS: Callback registered\n");

    // Set key - should trigger callback
    uint8_t test_key[32];
    for (int i = 0; i < 32; i++) {
        test_key[i] = (uint8_t)(i + 0x10);
    }

    result = netssd_set_daily_key(test_key, 32);
    assert(result == 0);
    assert(callback_invoked == 1);
    assert(callback_key_len == 32);
    assert(memcmp(callback_key, test_key, 32) == 0);
    printf("  PASS: Callback invoked with correct key\n");

    // Unregister callback
    result = netssd_register_key_update_callback(NULL);
    assert(result == 0);
    printf("  PASS: Callback unregistered\n");
}

void test_key_update_persistence(void) {
    printf("TEST: Key update persistence...\n");

    // Set first key
    uint8_t key1[32];
    for (int i = 0; i < 32; i++) {
        key1[i] = (uint8_t)(i + 1);
    }

    int result = netssd_set_daily_key(key1, 32);
    assert(result == 0);
    printf("  PASS: First key set\n");

    // Update to second key
    uint8_t key2[32];
    for (int i = 0; i < 32; i++) {
        key2[i] = (uint8_t)(i + 100);
    }

    result = netssd_set_daily_key(key2, 32);
    assert(result == 0);
    printf("  PASS: Key updated successfully\n");
}

int main(void) {
    printf("=== TASK-010: Daily Key Injection Tests ===\n\n");

    // Initialize netssd
    int result = buckwild_netssd_init(NULL);
    if (result != 0) {
        fprintf(stderr, "ERROR: Failed to initialize netssd: %d\n", result);
        return 1;
    }

    // Run tests
    test_key_injection_basic();
    test_key_injection_null_key();
    test_key_injection_wrong_length();
    test_key_injection_zero_key();
    test_key_update_callback_mechanism();
    test_key_update_persistence();

    // Cleanup
    result = buckwild_netssd_shutdown();
    if (result != 0) {
        fprintf(stderr, "ERROR: Failed to shutdown netssd: %d\n", result);
        return 1;
    }

    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
