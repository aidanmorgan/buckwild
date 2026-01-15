/**
 * @file hmac_sha256_avx512.c
 * @brief AVX-512-accelerated HMAC-SHA256 implementation
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "buckwild/crypto/simd.h"

#ifdef __AVX512F__
#include <immintrin.h>

// AVX-512 optimized HMAC-SHA256 implementation
// This implementation uses AVX-512 instructions for high-performance HMAC computation

// HMAC constants
#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5C
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

// AVX-512 SHA-256 round function
static inline __m512i sha256_round_avx512(__m512i a, __m512i b, __m512i c, __m512i d,
                                         __m512i e, __m512i f, __m512i g, __m512i h,
                                         __m512i w, uint32_t k) {
    __m512i k_vec = _mm512_set1_epi32(k);
    __m512i ch = _mm512_xor_si512(_mm512_and_si512(e, f), _mm512_andnot_si512(e, g));
    __m512i maj = _mm512_xor_si512(_mm512_xor_si512(_mm512_and_si512(a, b), _mm512_and_si512(a, c)), _mm512_and_si512(b, c));
    
    __m512i s0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi32(a, 2), _mm512_ror_epi32(a, 13)), _mm512_ror_epi32(a, 22));
    __m512i s1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi32(e, 6), _mm512_ror_epi32(e, 11)), _mm512_ror_epi32(e, 25));
    
    __m512i temp1 = _mm512_add_epi32(_mm512_add_epi32(_mm512_add_epi32(_mm512_add_epi32(h, s1), ch), k_vec), w);
    __m512i temp2 = _mm512_add_epi32(s0, maj);
    
    return _mm512_add_epi32(temp1, temp2);
}

// Process SHA-256 block with AVX-512
static void sha256_process_block_avx512(uint32_t state[8], const uint8_t block[64]) {
    __m512i w[16];
    __m512i a, b, c, d, e, f, g, h;
    
    // Load initial state
    a = _mm512_set1_epi32(state[0]);
    b = _mm512_set1_epi32(state[1]);
    c = _mm512_set1_epi32(state[2]);
    d = _mm512_set1_epi32(state[3]);
    e = _mm512_set1_epi32(state[4]);
    f = _mm512_set1_epi32(state[5]);
    g = _mm512_set1_epi32(state[6]);
    h = _mm512_set1_epi32(state[7]);
    
    // Load message schedule
    for (int i = 0; i < 16; i++) {
        uint32_t word = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
                       ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
        w[i] = _mm512_set1_epi32(word);
    }
    
    // SHA-256 round constants
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    // Main compression loop
    for (int i = 0; i < 64; i++) {
        __m512i wi;
        if (i < 16) {
            wi = w[i];
        } else {
            // Message schedule extension
            __m512i w15 = w[(i-15) & 15];
            __m512i w2 = w[(i-2) & 15];
            __m512i w16 = w[(i-16) & 15];
            __m512i w7 = w[(i-7) & 15];
            
            __m512i s0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi32(w15, 7), _mm512_ror_epi32(w15, 18)), _mm512_srli_epi32(w15, 3));
            __m512i s1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_ror_epi32(w2, 17), _mm512_ror_epi32(w2, 19)), _mm512_srli_epi32(w2, 10));
            
            wi = _mm512_add_epi32(_mm512_add_epi32(_mm512_add_epi32(w16, s0), w7), s1);
            w[i & 15] = wi;
        }
        
        __m512i temp1 = sha256_round_avx512(a, b, c, d, e, f, g, h, wi, k[i]);
        
        // Rotate state
        h = g;
        g = f;
        f = e;
        e = _mm512_add_epi32(d, temp1);
        d = c;
        c = b;
        b = a;
        a = temp1;
    }
    
    // Add to state
    state[0] += _mm512_extract_epi32(a, 0);
    state[1] += _mm512_extract_epi32(b, 0);
    state[2] += _mm512_extract_epi32(c, 0);
    state[3] += _mm512_extract_epi32(d, 0);
    state[4] += _mm512_extract_epi32(e, 0);
    state[5] += _mm512_extract_epi32(f, 0);
    state[6] += _mm512_extract_epi32(g, 0);
    state[7] += _mm512_extract_epi32(h, 0);
}

// SHA-256 implementation using AVX-512
static void sha256_avx512(const uint8_t* data, size_t len, uint8_t* hash) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t block[64];
    size_t processed = 0;
    
    // Process full blocks
    while (processed + 64 <= len) {
        sha256_process_block_avx512(state, data + processed);
        processed += 64;
    }
    
    // Handle final block with padding
    size_t remaining = len - processed;
    memcpy(block, data + processed, remaining);
    block[remaining] = 0x80;
    
    if (remaining >= 56) {
        memset(block + remaining + 1, 0, 64 - remaining - 1);
        sha256_process_block_avx512(state, block);
        memset(block, 0, 56);
    } else {
        memset(block + remaining + 1, 0, 56 - remaining - 1);
    }
    
    // Add length in bits
    uint64_t bit_len = len * 8;
    for (int i = 0; i < 8; i++) {
        block[56 + i] = (bit_len >> (56 - i * 8)) & 0xff;
    }
    
    sha256_process_block_avx512(state, block);
    
    // Output hash
    for (int i = 0; i < 8; i++) {
        hash[i*4] = (state[i] >> 24) & 0xff;
        hash[i*4+1] = (state[i] >> 16) & 0xff;
        hash[i*4+2] = (state[i] >> 8) & 0xff;
        hash[i*4+3] = state[i] & 0xff;
    }
}

int buckwild_simd_hmac_sha256_avx512(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* out
) {
    if (!key || !data || !out) {
        return -1;
    }
    
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    
    // Prepare key
    if (key_len > SHA256_BLOCK_SIZE) {
        // Hash long keys
        sha256_avx512(key, key_len, k_ipad);
        memset(k_ipad + SHA256_DIGEST_SIZE, 0, SHA256_BLOCK_SIZE - SHA256_DIGEST_SIZE);
    } else {
        // Pad short keys
        memcpy(k_ipad, key, key_len);
        memset(k_ipad + key_len, 0, SHA256_BLOCK_SIZE - key_len);
    }
    
    memcpy(k_opad, k_ipad, SHA256_BLOCK_SIZE);
    
    // XOR with ipad and opad
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= HMAC_IPAD;
        k_opad[i] ^= HMAC_OPAD;
    }
    
    // Inner hash: H(K XOR ipad, text)
    size_t inner_len = SHA256_BLOCK_SIZE + data_len;
    uint8_t* inner_data = malloc(inner_len);
    if (!inner_data) {
        return -1;
    }
    
    memcpy(inner_data, k_ipad, SHA256_BLOCK_SIZE);
    memcpy(inner_data + SHA256_BLOCK_SIZE, data, data_len);
    
    sha256_avx512(inner_data, inner_len, inner_hash);
    free(inner_data);
    
    // Outer hash: H(K XOR opad, inner_hash)
    size_t outer_len = SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE;
    uint8_t* outer_data = malloc(outer_len);
    if (!outer_data) {
        return -1;
    }
    
    memcpy(outer_data, k_opad, SHA256_BLOCK_SIZE);
    memcpy(outer_data + SHA256_BLOCK_SIZE, inner_hash, SHA256_DIGEST_SIZE);
    
    sha256_avx512(outer_data, outer_len, out);
    free(outer_data);
    
    // Clear sensitive data
    memset(k_ipad, 0, SHA256_BLOCK_SIZE);
    memset(k_opad, 0, SHA256_BLOCK_SIZE);
    memset(inner_hash, 0, SHA256_DIGEST_SIZE);
    
    return 0;
}

#else

// Fallback implementation for systems without AVX-512
int buckwild_simd_hmac_sha256_avx512(
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

    // Return error code to indicate that AVX-512 is not available
    return -1;
}

#endif // __AVX512F__