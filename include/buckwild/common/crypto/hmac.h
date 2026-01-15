/**
 * @file hmac.h
 * @brief HMAC-SHA256 operations for message authentication
 *
 * Provides HMAC-SHA256 calculation and constant-time verification
 * for the Buckwild protocol's adaptive HMAC policies.
 */

#ifndef BUCKWILD_CRYPTO_HMAC_H
#define BUCKWILD_CRYPTO_HMAC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// HMAC sizes for adaptive policies
#define BUCKWILD_HMAC_SHA256_SIZE       32  // Full HMAC-SHA256 (256 bits)
#define BUCKWILD_HMAC_STRONG_SIZE       32  // Strong policy (256 bits)
#define BUCKWILD_HMAC_MEDIUM_SIZE       16  // Medium policy (128 bits)
#define BUCKWILD_HMAC_LIGHT_SIZE        8   // Light policy (64 bits)

/**
 * @brief Calculate HMAC-SHA256
 *
 * Computes HMAC-SHA256 over the provided data using the given key.
 * This is the foundation for all HMAC operations in the protocol.
 *
 * @param key Pointer to key material
 * @param key_len Length of key in bytes
 * @param data Pointer to data to authenticate
 * @param data_len Length of data in bytes
 * @param hmac_output Output buffer for HMAC (must be at least 32 bytes)
 * @return 0 on success, negative error code on failure
 *
 * Example:
 *   uint8_t key[32] = {...};
 *   uint8_t data[100] = {...};
 *   uint8_t hmac[32];
 *   buckwild_hmac_sha256(key, 32, data, 100, hmac);
 */
int buckwild_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *hmac_output);

/**
 * @brief Verify HMAC in constant time (timing attack resistant)
 *
 * Compares two HMAC values in constant time to prevent timing attacks.
 * Returns 0 if HMACs match, non-zero if they differ.
 *
 * SECURITY: This function runs in constant time regardless of where
 * the first difference occurs, preventing timing side-channel attacks.
 *
 * @param hmac1 First HMAC to compare
 * @param hmac2 Second HMAC to compare
 * @param hmac_len Length of HMAC to compare (8, 16, or 32 bytes)
 * @return 0 if equal, 1 if different
 *
 * Example:
 *   uint8_t received_hmac[32] = {...};
 *   uint8_t computed_hmac[32] = {...};
 *   if (buckwild_hmac_verify_constant_time(received_hmac, computed_hmac, 32) == 0) {
 *       // HMACs match - message is authentic
 *   }
 */
int buckwild_hmac_verify_constant_time(const uint8_t *hmac1,
                                       const uint8_t *hmac2,
                                       size_t hmac_len);

#ifdef __cplusplus
}
#endif

#endif // BUCKWILD_CRYPTO_HMAC_H
