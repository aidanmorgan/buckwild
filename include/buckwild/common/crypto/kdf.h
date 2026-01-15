/**
 * @file kdf.h
 * @brief Key Derivation Functions (PBKDF2, HKDF)
 *
 * Provides key derivation for the Buckwild protocol:
 * - PBKDF2-HMAC-SHA256 for password-based key derivation
 * - HKDF-SHA256 for key expansion
 */

#ifndef BUCKWILD_CRYPTO_KDF_H
#define BUCKWILD_CRYPTO_KDF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Protocol constants
#define BUCKWILD_PBKDF2_ITERATIONS      4096    // Protocol requirement
#define BUCKWILD_SESSION_KEY_SIZE       32      // 256-bit session keys

/**
 * @brief PBKDF2-HMAC-SHA256 key derivation
 *
 * Derives a key from a password using PBKDF2 with HMAC-SHA256.
 * Used for deriving session parameters from ECDH shared secrets.
 *
 * @param password Input password/secret
 * @param password_len Length of password in bytes
 * @param salt Salt value
 * @param salt_len Length of salt in bytes
 * @param iterations Number of iterations (protocol uses 4096)
 * @param output Output buffer for derived key
 * @param output_len Desired length of derived key in bytes
 * @return 0 on success, negative error code on failure
 *
 * Example:
 *   uint8_t shared_secret[32] = {...};
 *   uint8_t salt[16] = {...};
 *   uint8_t session_key[32];
 *   buckwild_pbkdf2_hmac_sha256(shared_secret, 32, salt, 16,
 *                               4096, session_key, 32);
 */
int buckwild_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                                const uint8_t *salt, size_t salt_len,
                                uint32_t iterations,
                                uint8_t *output, size_t output_len);

/**
 * @brief HKDF-SHA256 key expansion
 *
 * Expands a key using HKDF (HMAC-based Key Derivation Function).
 * Used for deriving multiple keys from a single master key.
 *
 * @param salt Optional salt value (can be NULL for zero salt)
 * @param salt_len Length of salt in bytes
 * @param ikm Input Keying Material (master key)
 * @param ikm_len Length of IKM in bytes
 * @param info Optional context/application-specific info (can be NULL)
 * @param info_len Length of info in bytes
 * @param okm Output Keying Material (derived keys)
 * @param okm_len Desired length of output in bytes
 * @return 0 on success, negative error code on failure
 *
 * Example:
 *   uint8_t master_key[32] = {...};
 *   uint8_t salt[16] = {...};
 *   uint8_t info[] = "session_key_v1";
 *   uint8_t derived_keys[64];
 *   buckwild_hkdf_sha256(salt, 16, master_key, 32,
 *                        info, 14, derived_keys, 64);
 */
int buckwild_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif // BUCKWILD_CRYPTO_KDF_H
