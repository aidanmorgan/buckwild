/**
 * @file crypto.h
 * @brief Cryptographic operations for the Buckwild protocol
 */

#ifndef BUCKWILD_CRYPTO_H
#define BUCKWILD_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes for cryptographic operations
 */
typedef enum {
    BUCKWILD_CRYPTO_SUCCESS = 0,
    BUCKWILD_CRYPTO_ERROR_KEY_GENERATION = 1,
    BUCKWILD_CRYPTO_ERROR_KEY_AGREEMENT = 2,
    BUCKWILD_CRYPTO_ERROR_KEY_DERIVATION = 3,
    BUCKWILD_CRYPTO_ERROR_HMAC = 4,
    BUCKWILD_CRYPTO_ERROR_MEMORY = 5,
    BUCKWILD_CRYPTO_ERROR_INVALID_PARAMETER = 6,
    BUCKWILD_CRYPTO_ERROR_VERIFICATION_FAILED = 7,
    BUCKWILD_CRYPTO_ERROR_UNSUPPORTED_OPERATION = 8,
    BUCKWILD_CRYPTO_ERROR_INTERNAL = 9,
} buckwild_crypto_error_t;

/**
 * @brief HMAC security policy
 */
typedef enum {
    BUCKWILD_HMAC_POLICY_LIGHT = 0,   /**< 64-bit HMAC */
    BUCKWILD_HMAC_POLICY_MEDIUM = 1,  /**< 128-bit HMAC */
    BUCKWILD_HMAC_POLICY_STRONG = 2,  /**< 256-bit HMAC */
} buckwild_hmac_policy_t;

/**
 * @brief Opaque handle for ECDH manager
 */
typedef struct buckwild_ecdh_manager_t buckwild_ecdh_manager_t;

/**
 * @brief Opaque handle for HMAC context
 */
typedef struct buckwild_hmac_context_t buckwild_hmac_context_t;

/**
 * @brief Opaque handle for secure memory
 */
typedef struct buckwild_secure_bytes_t buckwild_secure_bytes_t;

/**
 * @brief Create a new ECDH manager
 * 
 * @param expiration_minutes Key expiration time in minutes
 * @param manager Pointer to store the manager handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_ecdh_manager_create(
    uint64_t expiration_minutes,
    buckwild_ecdh_manager_t** manager
);

/**
 * @brief Destroy an ECDH manager
 * 
 * @param manager Manager handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_ecdh_manager_destroy(
    buckwild_ecdh_manager_t* manager
);

/**
 * @brief Generate a key pair
 * 
 * @param manager Manager handle
 * @param id Key identifier
 * @param id_len Length of the key identifier
 * @param public_key Buffer to store the public key
 * @param public_key_len Pointer to the length of the public key buffer
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_ecdh_generate_key_pair(
    buckwild_ecdh_manager_t* manager,
    const char* id,
    size_t id_len,
    uint8_t* public_key,
    size_t* public_key_len
);

/**
 * @brief Compute a shared secret
 * 
 * @param manager Manager handle
 * @param local_id Local key identifier
 * @param local_id_len Length of the local key identifier
 * @param remote_public_key Remote public key
 * @param remote_public_key_len Length of the remote public key
 * @param shared_secret Buffer to store the shared secret
 * @param shared_secret_len Pointer to the length of the shared secret buffer
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_ecdh_compute_shared_secret(
    buckwild_ecdh_manager_t* manager,
    const char* local_id,
    size_t local_id_len,
    const uint8_t* remote_public_key,
    size_t remote_public_key_len,
    uint8_t* shared_secret,
    size_t* shared_secret_len
);

/**
 * @brief Rotate all keys in the cache
 * 
 * @param manager Manager handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_ecdh_rotate_keys(
    buckwild_ecdh_manager_t* manager
);

/**
 * @brief Create a new HMAC context
 * 
 * @param key HMAC key
 * @param key_len Length of the HMAC key
 * @param policy HMAC security policy
 * @param context Pointer to store the context handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_hmac_context_create(
    const uint8_t* key,
    size_t key_len,
    buckwild_hmac_policy_t policy,
    buckwild_hmac_context_t** context
);

/**
 * @brief Destroy an HMAC context
 * 
 * @param context Context handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_hmac_context_destroy(
    buckwild_hmac_context_t* context
);

/**
 * @brief Sign a message
 * 
 * @param context Context handle
 * @param message Message to sign
 * @param message_len Length of the message
 * @param tag Buffer to store the tag
 * @param tag_len Pointer to the length of the tag buffer
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_hmac_sign(
    buckwild_hmac_context_t* context,
    const uint8_t* message,
    size_t message_len,
    uint8_t* tag,
    size_t* tag_len
);

/**
 * @brief Verify a tag
 * 
 * @param context Context handle
 * @param message Message to verify
 * @param message_len Length of the message
 * @param tag Tag to verify
 * @param tag_len Length of the tag
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_hmac_verify(
    buckwild_hmac_context_t* context,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* tag,
    size_t tag_len
);

/**
 * @brief Get the tag length for a policy
 * 
 * @param policy HMAC security policy
 * @return size_t Tag length
 */
size_t buckwild_hmac_tag_length(
    buckwild_hmac_policy_t policy
);

/**
 * @brief Create secure memory
 * 
 * @param size Size of the memory
 * @param secure_bytes Pointer to store the secure memory handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_secure_bytes_create(
    size_t size,
    buckwild_secure_bytes_t** secure_bytes
);

/**
 * @brief Create secure memory from a buffer
 * 
 * @param data Buffer to copy
 * @param data_len Length of the buffer
 * @param secure_bytes Pointer to store the secure memory handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_secure_bytes_from_buffer(
    const uint8_t* data,
    size_t data_len,
    buckwild_secure_bytes_t** secure_bytes
);

/**
 * @brief Destroy secure memory
 * 
 * @param secure_bytes Secure memory handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_secure_bytes_destroy(
    buckwild_secure_bytes_t* secure_bytes
);

/**
 * @brief Get the data from secure memory
 * 
 * @param secure_bytes Secure memory handle
 * @param data Buffer to store the data
 * @param data_len Pointer to the length of the buffer
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_secure_bytes_get_data(
    buckwild_secure_bytes_t* secure_bytes,
    uint8_t* data,
    size_t* data_len
);

/**
 * @brief Set the data in secure memory
 * 
 * @param secure_bytes Secure memory handle
 * @param data Buffer to copy
 * @param data_len Length of the buffer
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_secure_bytes_set_data(
    buckwild_secure_bytes_t* secure_bytes,
    const uint8_t* data,
    size_t data_len
);

/**
 * @brief Clear secure memory
 * 
 * @param secure_bytes Secure memory handle
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_secure_bytes_clear(
    buckwild_secure_bytes_t* secure_bytes
);

/**
 * @brief Compare two buffers in constant time
 * 
 * @param a First buffer
 * @param a_len Length of the first buffer
 * @param b Second buffer
 * @param b_len Length of the second buffer
 * @return int 1 if equal, 0 if not equal
 */
int buckwild_constant_time_eq(
    const uint8_t* a,
    size_t a_len,
    const uint8_t* b,
    size_t b_len
);

/**
 * @brief Derive parameters from a key
 * 
 * @param key Key to derive parameters from
 * @param key_len Length of the key
 * @param salt Salt for PBKDF2
 * @param salt_len Length of the salt
 * @param iterations Number of iterations for PBKDF2
 * @param params Buffer to store the parameters
 * @param params_len Pointer to the length of the parameters buffer
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_derive_parameters(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t* params,
    size_t* params_len
);

/**
 * @brief Get a chunk from derived parameters
 * 
 * @param params Derived parameters
 * @param params_len Length of the parameters
 * @param chunk_type Chunk type
 * @param index Chunk index
 * @param chunk Pointer to store the chunk
 * @return buckwild_crypto_error_t Error code
 */
buckwild_crypto_error_t buckwild_get_parameter_chunk(
    const uint8_t* params,
    size_t params_len,
    uint8_t chunk_type,
    size_t index,
    uint16_t* chunk
);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_CRYPTO_H */