/**
 * @file simd.h
 * @brief SIMD-accelerated cryptographic operations for the Buckwild protocol
 */

#ifndef BUCKWILD_CRYPTO_SIMD_H
#define BUCKWILD_CRYPTO_SIMD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check if AVX2 is available
 * 
 * @return int 1 if available, 0 if not
 */
int buckwild_simd_has_avx2(void);

/**
 * @brief Check if AVX-512 is available
 * 
 * @return int 1 if available, 0 if not
 */
int buckwild_simd_has_avx512(void);

/**
 * @brief SIMD-accelerated HMAC-SHA256 using AVX2
 * 
 * @param key HMAC key
 * @param key_len Length of the HMAC key
 * @param data Data to hash
 * @param data_len Length of the data
 * @param out Buffer to store the HMAC (32 bytes)
 * @return int 0 on success, non-zero on error
 */
int buckwild_simd_hmac_sha256_avx2(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* out
);

/**
 * @brief SIMD-accelerated HMAC-SHA256 using AVX-512
 * 
 * @param key HMAC key
 * @param key_len Length of the HMAC key
 * @param data Data to hash
 * @param data_len Length of the data
 * @param out Buffer to store the HMAC (32 bytes)
 * @return int 0 on success, non-zero on error
 */
int buckwild_simd_hmac_sha256_avx512(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* out
);

/**
 * @brief SIMD-accelerated AES-GCM encryption using AVX2
 * 
 * @param key AES key (16, 24, or 32 bytes)
 * @param iv Initialization vector (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of the additional authenticated data
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Length of the plaintext
 * @param ciphertext Buffer to store the ciphertext
 * @param tag Buffer to store the authentication tag (16 bytes)
 * @return int 0 on success, non-zero on error
 */
int buckwild_simd_aes_gcm_encrypt_avx2(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag
);

/**
 * @brief SIMD-accelerated AES-GCM decryption using AVX2
 * 
 * @param key AES key (16, 24, or 32 bytes)
 * @param iv Initialization vector (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of the additional authenticated data
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Length of the ciphertext
 * @param tag Authentication tag (16 bytes)
 * @param plaintext Buffer to store the plaintext
 * @return int 0 on success, non-zero on error
 */
int buckwild_simd_aes_gcm_decrypt_avx2(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext
);

/**
 * @brief SIMD-accelerated AES-GCM encryption using AVX-512
 * 
 * @param key AES key (16, 24, or 32 bytes)
 * @param iv Initialization vector (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of the additional authenticated data
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Length of the plaintext
 * @param ciphertext Buffer to store the ciphertext
 * @param tag Buffer to store the authentication tag (16 bytes)
 * @return int 0 on success, non-zero on error
 */
int buckwild_simd_aes_gcm_encrypt_avx512(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t* tag
);

/**
 * @brief SIMD-accelerated AES-GCM decryption using AVX-512
 * 
 * @param key AES key (16, 24, or 32 bytes)
 * @param iv Initialization vector (12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len Length of the additional authenticated data
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Length of the ciphertext
 * @param tag Authentication tag (16 bytes)
 * @param plaintext Buffer to store the plaintext
 * @return int 0 on success, non-zero on error
 */
int buckwild_simd_aes_gcm_decrypt_avx512(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext
);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_CRYPTO_SIMD_H */