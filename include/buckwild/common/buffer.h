/**
 * @file buffer.h
 * @brief Safe buffer operations with bounds checking
 *
 * Provides a safe buffer abstraction for reading and writing binary data
 * with automatic bounds checking to prevent buffer overflows. All multi-byte
 * values use big-endian (network byte order) encoding.
 *
 * Features:
 * - Bounds checking on all read/write operations
 * - Position tracking
 * - Network byte order (big-endian) for multi-byte values
 * - Zero-copy design (operates on caller-provided storage)
 */

#ifndef BUCKWILD_COMMON_BUFFER_H
#define BUCKWILD_COMMON_BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Buffer structure for safe I/O operations
 *
 * Maintains a pointer to external storage along with size and position
 * information for bounds-checked operations.
 */
typedef struct {
    uint8_t *data;      ///< Pointer to buffer storage
    size_t capacity;    ///< Total buffer size in bytes
    size_t position;    ///< Current read/write position
} buckwild_buffer_t;

// ============================================================================
// Buffer Initialization and Management
// ============================================================================

/**
 * @brief Initialize a buffer with external storage
 *
 * Sets up a buffer structure to operate on caller-provided storage.
 * The buffer does not take ownership of the storage.
 *
 * @param buffer Pointer to buffer structure to initialize
 * @param storage Pointer to backing storage (must remain valid while buffer is used)
 * @param size Size of storage in bytes
 * @return 0 on success, -EINVAL if parameters are invalid
 */
int buckwild_buffer_init(buckwild_buffer_t *buffer, uint8_t *storage, size_t size);

/**
 * @brief Reset buffer position to beginning
 *
 * Resets the read/write position to the start of the buffer.
 * Does not clear the buffer contents.
 *
 * @param buffer Buffer to reset
 */
void buckwild_buffer_reset(buckwild_buffer_t *buffer);

/**
 * @brief Get current buffer position
 *
 * @param buffer Buffer to query
 * @return Current position (offset from start)
 */
size_t buckwild_buffer_position(const buckwild_buffer_t *buffer);

/**
 * @brief Get remaining space in buffer
 *
 * @param buffer Buffer to query
 * @return Number of bytes remaining from current position to end
 */
size_t buckwild_buffer_remaining(const buckwild_buffer_t *buffer);

/**
 * @brief Get total buffer capacity
 *
 * @param buffer Buffer to query
 * @return Total buffer size in bytes
 */
size_t buckwild_buffer_capacity(const buckwild_buffer_t *buffer);

/**
 * @brief Seek to absolute position in buffer
 *
 * @param buffer Buffer to seek
 * @param position Absolute position to seek to
 * @return 0 on success, -EINVAL if position is beyond buffer capacity
 */
int buckwild_buffer_seek(buckwild_buffer_t *buffer, size_t position);

// ============================================================================
// Write Operations (Big-Endian / Network Byte Order)
// ============================================================================

/**
 * @brief Write an 8-bit unsigned integer
 *
 * @param buffer Buffer to write to
 * @param value Value to write
 * @return 0 on success, -EINVAL if buffer is NULL, -ENOBUFS if insufficient space
 */
int buckwild_buffer_write_u8(buckwild_buffer_t *buffer, uint8_t value);

/**
 * @brief Write a 16-bit unsigned integer (big-endian)
 *
 * @param buffer Buffer to write to
 * @param value Value to write
 * @return 0 on success, -EINVAL if buffer is NULL, -ENOBUFS if insufficient space
 */
int buckwild_buffer_write_u16_be(buckwild_buffer_t *buffer, uint16_t value);

/**
 * @brief Write a 32-bit unsigned integer (big-endian)
 *
 * @param buffer Buffer to write to
 * @param value Value to write
 * @return 0 on success, -EINVAL if buffer is NULL, -ENOBUFS if insufficient space
 */
int buckwild_buffer_write_u32_be(buckwild_buffer_t *buffer, uint32_t value);

/**
 * @brief Write a 64-bit unsigned integer (big-endian)
 *
 * @param buffer Buffer to write to
 * @param value Value to write
 * @return 0 on success, -EINVAL if buffer is NULL, -ENOBUFS if insufficient space
 */
int buckwild_buffer_write_u64_be(buckwild_buffer_t *buffer, uint64_t value);

/**
 * @brief Write arbitrary bytes to buffer
 *
 * @param buffer Buffer to write to
 * @param data Data to write
 * @param length Number of bytes to write
 * @return 0 on success, -EINVAL if parameters are invalid, -ENOBUFS if insufficient space
 */
int buckwild_buffer_write_bytes(buckwild_buffer_t *buffer, const uint8_t *data, size_t length);

// ============================================================================
// Read Operations (Big-Endian / Network Byte Order)
// ============================================================================

/**
 * @brief Read an 8-bit unsigned integer
 *
 * @param buffer Buffer to read from
 * @param value Pointer to store read value
 * @return 0 on success, -EINVAL if parameters are invalid, -ENOBUFS if insufficient data
 */
int buckwild_buffer_read_u8(buckwild_buffer_t *buffer, uint8_t *value);

/**
 * @brief Read a 16-bit unsigned integer (big-endian)
 *
 * @param buffer Buffer to read from
 * @param value Pointer to store read value
 * @return 0 on success, -EINVAL if parameters are invalid, -ENOBUFS if insufficient data
 */
int buckwild_buffer_read_u16_be(buckwild_buffer_t *buffer, uint16_t *value);

/**
 * @brief Read a 32-bit unsigned integer (big-endian)
 *
 * @param buffer Buffer to read from
 * @param value Pointer to store read value
 * @return 0 on success, -EINVAL if parameters are invalid, -ENOBUFS if insufficient data
 */
int buckwild_buffer_read_u32_be(buckwild_buffer_t *buffer, uint32_t *value);

/**
 * @brief Read a 64-bit unsigned integer (big-endian)
 *
 * @param buffer Buffer to read from
 * @param value Pointer to store read value
 * @return 0 on success, -EINVAL if parameters are invalid, -ENOBUFS if insufficient data
 */
int buckwild_buffer_read_u64_be(buckwild_buffer_t *buffer, uint64_t *value);

/**
 * @brief Read arbitrary bytes from buffer
 *
 * @param buffer Buffer to read from
 * @param data Destination for read data
 * @param length Number of bytes to read
 * @return 0 on success, -EINVAL if parameters are invalid, -ENOBUFS if insufficient data
 */
int buckwild_buffer_read_bytes(buckwild_buffer_t *buffer, uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif // BUCKWILD_COMMON_BUFFER_H
