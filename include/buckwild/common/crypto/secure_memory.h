/**
 * @file secure_memory.h
 * @brief Secure memory operations
 *
 * Provides secure memory handling to prevent key material leakage.
 */

#ifndef BUCKWILD_CRYPTO_SECURE_MEMORY_H
#define BUCKWILD_CRYPTO_SECURE_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Securely zero memory
 *
 * Zeros memory in a way that cannot be optimized away by the compiler.
 * Essential for clearing sensitive data (keys, passwords) from memory.
 *
 * SECURITY: Uses compiler barriers and volatile pointer to prevent
 * dead store elimination optimization.
 *
 * @param ptr Pointer to memory to zero
 * @param len Length of memory in bytes
 *
 * Example:
 *   uint8_t session_key[32];
 *   // ... use session_key ...
 *   buckwild_secure_zero_memory(session_key, 32); // Clear before deallocation
 */
void buckwild_secure_zero_memory(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif // BUCKWILD_CRYPTO_SECURE_MEMORY_H
