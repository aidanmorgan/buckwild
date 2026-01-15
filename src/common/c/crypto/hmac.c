/**
 * @file hmac.c
 * @brief HMAC-SHA256 implementation using OpenSSL
 */

#include "buckwild/common/crypto/hmac.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <errno.h>

int buckwild_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *hmac_output) {
    if (!key || !hmac_output) {
        return -EINVAL;
    }

    // Allow NULL data if data_len is 0
    if (data_len > 0 && !data) {
        return -EINVAL;
    }

    unsigned int hmac_len = 0;

    // Compute HMAC-SHA256 using OpenSSL
    uint8_t *result = HMAC(EVP_sha256(),
                           key, (int)key_len,
                           data, data_len,
                           hmac_output,
                           &hmac_len);

    if (!result || hmac_len != BUCKWILD_HMAC_SHA256_SIZE) {
        return -EIO;
    }

    return 0;
}

int buckwild_hmac_verify_constant_time(const uint8_t *hmac1,
                                       const uint8_t *hmac2,
                                       size_t hmac_len) {
    if (!hmac1 || !hmac2 || hmac_len == 0) {
        return 1; // Invalid input = mismatch
    }

    // Constant-time comparison
    // XOR all bytes and accumulate the result
    volatile uint8_t result = 0;

    for (size_t i = 0; i < hmac_len; i++) {
        result |= (hmac1[i] ^ hmac2[i]);
    }

    // result will be 0 if all bytes match, non-zero otherwise
    return result;
}
