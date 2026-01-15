/**
 * @file buffer.c
 * @brief Safe buffer operations implementation
 */

#include "buckwild/common/buffer.h"
#include <string.h>

// ============================================================================
// Buffer Initialization and Management
// ============================================================================

int buckwild_buffer_init(buckwild_buffer_t *buffer, uint8_t *storage, size_t size) {
    if (!buffer || !storage || size == 0) {
        return -EINVAL;
    }

    buffer->data = storage;
    buffer->capacity = size;
    buffer->position = 0;

    return 0;
}

void buckwild_buffer_reset(buckwild_buffer_t *buffer) {
    if (buffer) {
        buffer->position = 0;
    }
}

size_t buckwild_buffer_position(const buckwild_buffer_t *buffer) {
    return buffer ? buffer->position : 0;
}

size_t buckwild_buffer_remaining(const buckwild_buffer_t *buffer) {
    if (!buffer || buffer->position > buffer->capacity) {
        return 0;
    }
    return buffer->capacity - buffer->position;
}

size_t buckwild_buffer_capacity(const buckwild_buffer_t *buffer) {
    return buffer ? buffer->capacity : 0;
}

int buckwild_buffer_seek(buckwild_buffer_t *buffer, size_t position) {
    if (!buffer || position > buffer->capacity) {
        return -EINVAL;
    }

    buffer->position = position;
    return 0;
}

// ============================================================================
// Write Operations (Big-Endian / Network Byte Order)
// ============================================================================

int buckwild_buffer_write_u8(buckwild_buffer_t *buffer, uint8_t value) {
    if (!buffer) {
        return -EINVAL;
    }

    if (buckwild_buffer_remaining(buffer) < 1) {
        return -ENOBUFS;
    }

    buffer->data[buffer->position++] = value;
    return 0;
}

int buckwild_buffer_write_u16_be(buckwild_buffer_t *buffer, uint16_t value) {
    if (!buffer) {
        return -EINVAL;
    }

    if (buckwild_buffer_remaining(buffer) < 2) {
        return -ENOBUFS;
    }

    buffer->data[buffer->position++] = (uint8_t)(value >> 8);
    buffer->data[buffer->position++] = (uint8_t)(value & 0xFF);
    return 0;
}

int buckwild_buffer_write_u32_be(buckwild_buffer_t *buffer, uint32_t value) {
    if (!buffer) {
        return -EINVAL;
    }

    if (buckwild_buffer_remaining(buffer) < 4) {
        return -ENOBUFS;
    }

    buffer->data[buffer->position++] = (uint8_t)(value >> 24);
    buffer->data[buffer->position++] = (uint8_t)((value >> 16) & 0xFF);
    buffer->data[buffer->position++] = (uint8_t)((value >> 8) & 0xFF);
    buffer->data[buffer->position++] = (uint8_t)(value & 0xFF);
    return 0;
}

int buckwild_buffer_write_u64_be(buckwild_buffer_t *buffer, uint64_t value) {
    if (!buffer) {
        return -EINVAL;
    }

    if (buckwild_buffer_remaining(buffer) < 8) {
        return -ENOBUFS;
    }

    buffer->data[buffer->position++] = (uint8_t)(value >> 56);
    buffer->data[buffer->position++] = (uint8_t)((value >> 48) & 0xFF);
    buffer->data[buffer->position++] = (uint8_t)((value >> 40) & 0xFF);
    buffer->data[buffer->position++] = (uint8_t)((value >> 32) & 0xFF);
    buffer->data[buffer->position++] = (uint8_t)((value >> 24) & 0xFF);
    buffer->data[buffer->position++] = (uint8_t)((value >> 16) & 0xFF);
    buffer->data[buffer->position++] = (uint8_t)((value >> 8) & 0xFF);
    buffer->data[buffer->position++] = (uint8_t)(value & 0xFF);
    return 0;
}

int buckwild_buffer_write_bytes(buckwild_buffer_t *buffer, const uint8_t *data, size_t length) {
    if (!buffer || !data) {
        return -EINVAL;
    }

    if (length == 0) {
        return 0;
    }

    if (buckwild_buffer_remaining(buffer) < length) {
        return -ENOBUFS;
    }

    memcpy(&buffer->data[buffer->position], data, length);
    buffer->position += length;
    return 0;
}

// ============================================================================
// Read Operations (Big-Endian / Network Byte Order)
// ============================================================================

int buckwild_buffer_read_u8(buckwild_buffer_t *buffer, uint8_t *value) {
    if (!buffer || !value) {
        return -EINVAL;
    }

    if (buckwild_buffer_remaining(buffer) < 1) {
        return -ENOBUFS;
    }

    *value = buffer->data[buffer->position++];
    return 0;
}

int buckwild_buffer_read_u16_be(buckwild_buffer_t *buffer, uint16_t *value) {
    if (!buffer || !value) {
        return -EINVAL;
    }

    if (buckwild_buffer_remaining(buffer) < 2) {
        return -ENOBUFS;
    }

    *value = ((uint16_t)buffer->data[buffer->position] << 8) |
             ((uint16_t)buffer->data[buffer->position + 1]);
    buffer->position += 2;
    return 0;
}

int buckwild_buffer_read_u32_be(buckwild_buffer_t *buffer, uint32_t *value) {
    if (!buffer || !value) {
        return -EINVAL;
    }

    if (buckwild_buffer_remaining(buffer) < 4) {
        return -ENOBUFS;
    }

    *value = ((uint32_t)buffer->data[buffer->position] << 24) |
             ((uint32_t)buffer->data[buffer->position + 1] << 16) |
             ((uint32_t)buffer->data[buffer->position + 2] << 8) |
             ((uint32_t)buffer->data[buffer->position + 3]);
    buffer->position += 4;
    return 0;
}

int buckwild_buffer_read_u64_be(buckwild_buffer_t *buffer, uint64_t *value) {
    if (!buffer || !value) {
        return -EINVAL;
    }

    if (buckwild_buffer_remaining(buffer) < 8) {
        return -ENOBUFS;
    }

    *value = ((uint64_t)buffer->data[buffer->position] << 56) |
             ((uint64_t)buffer->data[buffer->position + 1] << 48) |
             ((uint64_t)buffer->data[buffer->position + 2] << 40) |
             ((uint64_t)buffer->data[buffer->position + 3] << 32) |
             ((uint64_t)buffer->data[buffer->position + 4] << 24) |
             ((uint64_t)buffer->data[buffer->position + 5] << 16) |
             ((uint64_t)buffer->data[buffer->position + 6] << 8) |
             ((uint64_t)buffer->data[buffer->position + 7]);
    buffer->position += 8;
    return 0;
}

int buckwild_buffer_read_bytes(buckwild_buffer_t *buffer, uint8_t *data, size_t length) {
    if (!buffer || !data) {
        return -EINVAL;
    }

    if (length == 0) {
        return 0;
    }

    if (buckwild_buffer_remaining(buffer) < length) {
        return -ENOBUFS;
    }

    memcpy(data, &buffer->data[buffer->position], length);
    buffer->position += length;
    return 0;
}
