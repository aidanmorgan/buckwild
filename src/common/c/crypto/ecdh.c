/**
 * @file ecdh.c
 * @brief ECDH P-256 key exchange implementation using OpenSSL 3.0+ EVP API
 */

#include "buckwild/common/crypto/ecdh.h"
#include "buckwild/common/crypto/secure_memory.h"
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <errno.h>

/**
 * @brief Generate a P-256 ECDH key pair using OpenSSL 3.0 EVP API
 */
int buckwild_ecdh_generate_keypair(uint8_t *private_key_out,
                                    uint8_t *public_key_out) {
    if (!private_key_out || !public_key_out) {
        return -EINVAL;
    }

    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *priv_bn = NULL;
    BIGNUM *pub_x = NULL;
    BIGNUM *pub_y = NULL;
    OSSL_PARAM params[2];
    const char *curve_name = "prime256v1";
    int ret = -EIO;

    // Create context for P-256 key generation
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) {
        goto cleanup;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        goto cleanup;
    }

    // Set curve to P-256 using OSSL_PARAM
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                  (char *)curve_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        goto cleanup;
    }

    // Generate key pair
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        goto cleanup;
    }

    // Extract private key
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) <= 0) {
        goto cleanup;
    }

    // Convert private key to bytes (32 bytes, big-endian)
    memset(private_key_out, 0, BUCKWILD_ECDH_PRIVATE_KEY_SIZE);
    if (BN_bn2binpad(priv_bn, private_key_out, BUCKWILD_ECDH_PRIVATE_KEY_SIZE) < 0) {
        goto cleanup;
    }

    // Extract public key X coordinate
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &pub_x) <= 0) {
        goto cleanup;
    }

    // Extract public key Y coordinate
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &pub_y) <= 0) {
        goto cleanup;
    }

    // Convert public key to bytes (64 bytes: 32-byte X || 32-byte Y)
    memset(public_key_out, 0, BUCKWILD_ECDH_PUBLIC_KEY_SIZE);
    if (BN_bn2binpad(pub_x, public_key_out, 32) < 0) {
        goto cleanup;
    }
    if (BN_bn2binpad(pub_y, public_key_out + 32, 32) < 0) {
        goto cleanup;
    }

    ret = 0;  // Success

cleanup:
    if (priv_bn) BN_clear_free(priv_bn);  // Securely clear private key
    if (pub_x) BN_free(pub_x);
    if (pub_y) BN_free(pub_y);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);

    return ret;
}

/**
 * @brief Compute ECDH shared secret using raw EC operations (simpler approach)
 *
 * ECDH: shared_secret = remote_public_key_point * local_private_scalar
 * This computes the X-coordinate of the resulting point as the shared secret.
 */
int buckwild_ecdh_compute_shared_secret(const uint8_t *local_private_key,
                                        const uint8_t *remote_public_key,
                                        uint8_t *shared_secret_out) {
    if (!local_private_key || !remote_public_key || !shared_secret_out) {
        return -EINVAL;
    }

    EC_GROUP *group = NULL;
    EC_POINT *peer_point = NULL;
    EC_POINT *shared_point = NULL;
    BIGNUM *priv_bn = NULL;
    BIGNUM *peer_x = NULL;
    BIGNUM *peer_y = NULL;
    BIGNUM *shared_x = NULL;
    BN_CTX *bn_ctx = NULL;
    int ret = -EIO;

    // Create EC group for P-256
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        goto cleanup;
    }

    // Create BN context
    bn_ctx = BN_CTX_new();
    if (!bn_ctx) {
        goto cleanup;
    }

    // Convert local private key to BIGNUM
    priv_bn = BN_bin2bn(local_private_key, BUCKWILD_ECDH_PRIVATE_KEY_SIZE, NULL);
    if (!priv_bn) {
        goto cleanup;
    }

    // Convert peer public key (x || y) to BIGNUMs
    peer_x = BN_bin2bn(remote_public_key, 32, NULL);
    peer_y = BN_bin2bn(remote_public_key + 32, 32, NULL);
    if (!peer_x || !peer_y) {
        goto cleanup;
    }

    // Create EC_POINT from peer's public key coordinates
    peer_point = EC_POINT_new(group);
    if (!peer_point) {
        goto cleanup;
    }

    if (EC_POINT_set_affine_coordinates(group, peer_point, peer_x, peer_y, bn_ctx) != 1) {
        goto cleanup;
    }

    // Verify peer point is on curve
    if (EC_POINT_is_on_curve(group, peer_point, bn_ctx) != 1) {
        ret = -EINVAL;  // Invalid public key
        goto cleanup;
    }

    // Create point for shared secret
    shared_point = EC_POINT_new(group);
    if (!shared_point) {
        goto cleanup;
    }

    // Perform ECDH: shared_point = priv_bn * peer_point
    if (EC_POINT_mul(group, shared_point, NULL, peer_point, priv_bn, bn_ctx) != 1) {
        goto cleanup;
    }

    // Extract X-coordinate of shared point as shared secret
    shared_x = BN_new();
    if (!shared_x) {
        goto cleanup;
    }

    if (EC_POINT_get_affine_coordinates(group, shared_point, shared_x, NULL, bn_ctx) != 1) {
        goto cleanup;
    }

    // Convert shared secret X-coordinate to bytes (32 bytes)
    memset(shared_secret_out, 0, BUCKWILD_ECDH_SHARED_SECRET_SIZE);
    if (BN_bn2binpad(shared_x, shared_secret_out, BUCKWILD_ECDH_SHARED_SECRET_SIZE) < 0) {
        goto cleanup;
    }

    ret = 0;  // Success

cleanup:
    if (priv_bn) BN_clear_free(priv_bn);  // Securely clear private key
    if (peer_x) BN_free(peer_x);
    if (peer_y) BN_free(peer_y);
    if (shared_x) BN_clear_free(shared_x);  // Shared secret is sensitive
    if (peer_point) EC_POINT_free(peer_point);
    if (shared_point) EC_POINT_clear_free(shared_point);  // Clear shared point
    if (bn_ctx) BN_CTX_free(bn_ctx);
    if (group) EC_GROUP_free(group);

    return ret;
}
