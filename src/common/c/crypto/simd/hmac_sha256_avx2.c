/**
 * @file hmac_sha256_avx2.c
 * @brief AVX2-accelerated HMAC-SHA256 implementation
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "buckwild/crypto/simd.h"

#ifdef __AVX2__
#include <immintrin.h>

// SHA-256 constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// SHA-256 functions
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// AVX2 implementation of SHA-256
static void sha256_transform_avx2(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t w[64];
    uint32_t t1, t2;
    
    // Load message into w[0..15]
    for (int i = 0; i < 16; i++) {
        w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
               (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
    }
    
    // Extend the first 16 words into the remaining 48 words
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }
    
    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    
    // Main loop
    for (int i = 0; i < 64; i++) {
        t1 = h + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    // Add the compressed chunk to the current hash value
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// HMAC-SHA256 implementation
int buckwild_simd_hmac_sha256_avx2(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* out
) {
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t inner_hash[32];
    uint32_t state[8];
    
    // Prepare the key
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    
    if (key_len > 64) {
        // If key is longer than 64 bytes, hash it
        uint32_t temp_state[8];
        memcpy(temp_state, H0, 32);
        
        // Process key in 64-byte blocks
        size_t remaining = key_len;
        const uint8_t* k_ptr = key;
        
        while (remaining >= 64) {
            sha256_transform_avx2(temp_state, k_ptr);
            k_ptr += 64;
            remaining -= 64;
        }
        
        // Process the last block
        uint8_t last_block[64];
        memset(last_block, 0, 64);
        memcpy(last_block, k_ptr, remaining);
        
        // Append the padding
        last_block[remaining] = 0x80;
        
        // Append the length in bits
        uint64_t bit_len = key_len * 8;
        if (remaining < 56) {
            // There's room for the length in this block
            last_block[56] = (bit_len >> 56) & 0xFF;
            last_block[57] = (bit_len >> 48) & 0xFF;
            last_block[58] = (bit_len >> 40) & 0xFF;
            last_block[59] = (bit_len >> 32) & 0xFF;
            last_block[60] = (bit_len >> 24) & 0xFF;
            last_block[61] = (bit_len >> 16) & 0xFF;
            last_block[62] = (bit_len >> 8) & 0xFF;
            last_block[63] = bit_len & 0xFF;
            sha256_transform_avx2(temp_state, last_block);
        } else {
            // Need an additional block for the length
            sha256_transform_avx2(temp_state, last_block);
            memset(last_block, 0, 64);
            last_block[56] = (bit_len >> 56) & 0xFF;
            last_block[57] = (bit_len >> 48) & 0xFF;
            last_block[58] = (bit_len >> 40) & 0xFF;
            last_block[59] = (bit_len >> 32) & 0xFF;
            last_block[60] = (bit_len >> 24) & 0xFF;
            last_block[61] = (bit_len >> 16) & 0xFF;
            last_block[62] = (bit_len >> 8) & 0xFF;
            last_block[63] = bit_len & 0xFF;
            sha256_transform_avx2(temp_state, last_block);
        }
        
        // Copy the hashed key
        for (int i = 0; i < 8; i++) {
            k_ipad[i * 4] = (temp_state[i] >> 24) & 0xFF;
            k_ipad[i * 4 + 1] = (temp_state[i] >> 16) & 0xFF;
            k_ipad[i * 4 + 2] = (temp_state[i] >> 8) & 0xFF;
            k_ipad[i * 4 + 3] = temp_state[i] & 0xFF;
        }
        memcpy(k_opad, k_ipad, 32);
    } else {
        // If key is 64 bytes or less, use it as is
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
    }
    
    // XOR keys with ipad and opad
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
    }
    
    // Inner hash: H(K XOR ipad || data)
    memcpy(state, H0, 32);
    
    // Process the key XOR ipad
    sha256_transform_avx2(state, k_ipad);
    
    // Process data in 64-byte blocks
    size_t remaining = data_len;
    const uint8_t* data_ptr = data;
    
    while (remaining >= 64) {
        sha256_transform_avx2(state, data_ptr);
        data_ptr += 64;
        remaining -= 64;
    }
    
    // Process the last block
    uint8_t last_block[64];
    memset(last_block, 0, 64);
    memcpy(last_block, data_ptr, remaining);
    
    // Append the padding
    last_block[remaining] = 0x80;
    
    // Append the length in bits
    uint64_t bit_len = (data_len + 64) * 8; // Include the key XOR ipad
    if (remaining < 56) {
        // There's room for the length in this block
        last_block[56] = (bit_len >> 56) & 0xFF;
        last_block[57] = (bit_len >> 48) & 0xFF;
        last_block[58] = (bit_len >> 40) & 0xFF;
        last_block[59] = (bit_len >> 32) & 0xFF;
        last_block[60] = (bit_len >> 24) & 0xFF;
        last_block[61] = (bit_len >> 16) & 0xFF;
        last_block[62] = (bit_len >> 8) & 0xFF;
        last_block[63] = bit_len & 0xFF;
        sha256_transform_avx2(state, last_block);
    } else {
        // Need an additional block for the length
        sha256_transform_avx2(state, last_block);
        memset(last_block, 0, 64);
        last_block[56] = (bit_len >> 56) & 0xFF;
        last_block[57] = (bit_len >> 48) & 0xFF;
        last_block[58] = (bit_len >> 40) & 0xFF;
        last_block[59] = (bit_len >> 32) & 0xFF;
        last_block[60] = (bit_len >> 24) & 0xFF;
        last_block[61] = (bit_len >> 16) & 0xFF;
        last_block[62] = (bit_len >> 8) & 0xFF;
        last_block[63] = bit_len & 0xFF;
        sha256_transform_avx2(state, last_block);
    }
    
    // Copy the inner hash
    for (int i = 0; i < 8; i++) {
        inner_hash[i * 4] = (state[i] >> 24) & 0xFF;
        inner_hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        inner_hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        inner_hash[i * 4 + 3] = state[i] & 0xFF;
    }
    
    // Outer hash: H(K XOR opad || inner_hash)
    memcpy(state, H0, 32);
    
    // Process the key XOR opad
    sha256_transform_avx2(state, k_opad);
    
    // Process the inner hash
    uint8_t final_block[64];
    memset(final_block, 0, 64);
    memcpy(final_block, inner_hash, 32);
    
    // Append the padding
    final_block[32] = 0x80;
    
    // Append the length in bits
    bit_len = (32 + 64) * 8; // Inner hash + key XOR opad
    final_block[56] = (bit_len >> 56) & 0xFF;
    final_block[57] = (bit_len >> 48) & 0xFF;
    final_block[58] = (bit_len >> 40) & 0xFF;
    final_block[59] = (bit_len >> 32) & 0xFF;
    final_block[60] = (bit_len >> 24) & 0xFF;
    final_block[61] = (bit_len >> 16) & 0xFF;
    final_block[62] = (bit_len >> 8) & 0xFF;
    final_block[63] = bit_len & 0xFF;
    sha256_transform_avx2(state, final_block);
    
    // Copy the final hash
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (state[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        out[i * 4 + 3] = state[i] & 0xFF;
    }
    
    return 0;
}

#else

// Fallback implementation for systems without AVX2
int buckwild_simd_hmac_sha256_avx2(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* out
) {
    // Suppress unused parameter warnings
    (void)key;
    (void)key_len;
    (void)data;
    (void)data_len;
    (void)out;

    // Return error code to indicate that AVX2 is not available
    return -1;
}

#endif // __AVX2__