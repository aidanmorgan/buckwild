/**
 * @file ecdh.h
 * @brief ECDH P-256 key exchange for perfect forward secrecy
 *
 * Provides P-256 (NIST P-256 / secp256r1) elliptic curve Diffie-Hellman
 * key exchange for the Buckwild protocol's session key derivation.
 */

#ifndef BUCKWILD_CRYPTO_ECDH_H
#define BUCKWILD_CRYPTO_ECDH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ECDH key sizes
#define BUCKWILD_ECDH_PRIVATE_KEY_SIZE  32  // P-256 private key (256 bits)
#define BUCKWILD_ECDH_PUBLIC_KEY_SIZE   64  // P-256 public key uncompressed (x || y)
#define BUCKWILD_ECDH_SHARED_SECRET_SIZE 32 // Shared secret (256 bits)

/**
 * @brief Generate a P-256 ECDH key pair
 *
 * Generates a new P-256 key pair using cryptographically secure random.
 * The public key is encoded as uncompressed coordinates (x || y) without
 * the 0x04 prefix.
 *
 * @param private_key_out Output buffer for private key (32 bytes)
 * @param public_key_out Output buffer for public key (64 bytes: x || y)
 * @return 0 on success, negative error code on failure
 *
 * Example:
 *   uint8_t private_key[32];
 *   uint8_t public_key[64];
 *   if (buckwild_ecdh_generate_keypair(private_key, public_key) == 0) {
 *       // Keys generated successfully
 *   }
 *
 * SECURITY: The private key must be zeroized after use with
 *           buckwild_secure_zero() to prevent key leakage.
 */
int buckwild_ecdh_generate_keypair(uint8_t *private_key_out,
                                    uint8_t *public_key_out);

/**
 * @brief Compute ECDH shared secret
 *
 * Performs P-256 ECDH key agreement between a local private key and
 * a remote public key, producing a 32-byte shared secret.
 *
 * @param local_private_key Local private key (32 bytes)
 * @param remote_public_key Remote public key (64 bytes: x || y)
 * @param shared_secret_out Output buffer for shared secret (32 bytes)
 * @return 0 on success, negative error code on failure
 *
 * Example:
 *   uint8_t local_private[32] = {...};
 *   uint8_t remote_public[64] = {...};
 *   uint8_t shared_secret[32];
 *   if (buckwild_ecdh_compute_shared_secret(local_private, remote_public,
 *                                            shared_secret) == 0) {
 *       // Shared secret computed successfully
 *       // Use shared secret for key derivation (HKDF)
 *       buckwild_secure_zero(shared_secret, 32);  // Zeroize when done
 *   }
 *
 * SECURITY: Both the private key and shared secret must be zeroized
 *           after use to prevent key leakage.
 */
int buckwild_ecdh_compute_shared_secret(const uint8_t *local_private_key,
                                        const uint8_t *remote_public_key,
                                        uint8_t *shared_secret_out);

#ifdef __cplusplus
}
#endif

#endif // BUCKWILD_CRYPTO_ECDH_H
