/**
 * @file secure_memory.c
 * @brief Secure memory operations implementation
 */

#include "buckwild/common/crypto/secure_memory.h"
#include <string.h>

#ifdef __STDC_LIB_EXT1__
// C11 Annex K: memset_s is available
#define HAVE_MEMSET_S 1
#endif

#ifdef __OpenBSD__
// OpenBSD has explicit_bzero
#define HAVE_EXPLICIT_BZERO 1
#endif

void buckwild_secure_zero_memory(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

#if defined(HAVE_MEMSET_S)
    // Use C11 memset_s if available (guaranteed not to be optimized away)
    memset_s(ptr, len, 0, len);

#elif defined(HAVE_EXPLICIT_BZERO)
    // Use OpenBSD's explicit_bzero
    explicit_bzero(ptr, len);

#elif defined(__GNUC__)
    // GCC/Clang: Use memset with memory barrier
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");

#else
    // Fallback: Use volatile pointer to prevent optimization
    volatile uint8_t *volatile_ptr = (volatile uint8_t *)ptr;
    while (len--) {
        *volatile_ptr++ = 0;
    }
#endif
}
