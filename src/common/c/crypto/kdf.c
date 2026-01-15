/**
 * @file kdf.c
 * @brief Key Derivation Functions implementation using OpenSSL
 */

#include "buckwild/common/crypto/kdf.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <string.h>
#include <errno.h>

int buckwild_pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                                const uint8_t *salt, size_t salt_len,
                                uint32_t iterations,
                                uint8_t *output, size_t output_len) {
    if (!password || !salt || !output) {
        return -EINVAL;
    }

    if (password_len == 0 || salt_len == 0 || output_len == 0 || iterations == 0) {
        return -EINVAL;
    }

    // Use OpenSSL's PBKDF2 implementation
    int result = PKCS5_PBKDF2_HMAC(
        (const char *)password, (int)password_len,
        salt, (int)salt_len,
        (int)iterations,
        EVP_sha256(),
        (int)output_len,
        output
    );

    if (result != 1) {
        return -EIO;
    }

    return 0;
}

int buckwild_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *okm, size_t okm_len) {
    if (!ikm || !okm) {
        return -EINVAL;
    }

    if (ikm_len == 0 || okm_len == 0) {
        return -EINVAL;
    }

    // Use OpenSSL 3.0 EVP_KDF API for HKDF
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        return -EIO;
    }

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (!ctx) {
        return -EIO;
    }

    // Handle NULL salt - use zero-filled salt
    uint8_t zero_salt[32] = {0};
    const uint8_t *actual_salt = salt ? salt : zero_salt;
    size_t actual_salt_len = salt ? salt_len : 32;

    // Build parameters for HKDF
    OSSL_PARAM params[5];
    int param_idx = 0;

    params[param_idx++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[param_idx++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    params[param_idx++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, (void *)actual_salt, actual_salt_len);

    if (info && info_len > 0) {
        params[param_idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    }

    params[param_idx] = OSSL_PARAM_construct_end();

    // Derive key
    int result = EVP_KDF_derive(ctx, okm, okm_len, params);

    EVP_KDF_CTX_free(ctx);

    if (result != 1) {
        return -EIO;
    }

    return 0;
}
