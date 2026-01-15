/**
 * @file tun_device_ffi.h
 * @brief FFI-safe C bindings for TUN device operations
 *
 * This header provides a Foreign Function Interface (FFI) layer for
 * the TUN device implementation, allowing safe interoperation with
 * other languages (primarily Rust).
 *
 * PLATFORM: Linux only
 * FFI-SAFE: All functions use C-compatible types
 *
 * The FFI layer wraps the standard tun_device.h API with additional
 * safety guarantees:
 * - All pointers are non-null or explicitly documented
 * - All return values are clearly defined
 * - No platform-specific types exposed
 * - Thread-safe (device handles are independent)
 */

#ifndef BUCKWILD_TUN_DEVICE_FFI_H
#define BUCKWILD_TUN_DEVICE_FFI_H

/* Platform check - TUN/TAP is Linux-specific */
#if !defined(__linux__)
#error "TUN/TAP device FFI requires Linux"
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct tun_device;

/**
 * FFI-safe device configuration structure
 *
 * All fields use fixed-size types suitable for FFI.
 */
typedef struct {
	/** Device name (null-terminated, max 15 chars) */
	char name[16];
	/** IPv4 address in network byte order */
	uint32_t ip_addr;
	/** IPv4 netmask in network byte order */
	uint32_t netmask;
	/** MTU value (68-65535) */
	uint16_t mtu;
	/** Make device persistent across process exit */
	bool persistent;
} buckwild_tun_config_t;

/**
 * buckwild_tun_config_init() - Initialize FFI configuration
 * @config: Configuration structure to initialize
 *
 * Return: 0 on success, negative error code on failure
 */
int buckwild_tun_config_init(buckwild_tun_config_t *config);

/**
 * buckwild_tun_config_set_name() - Set device name
 * @config: Configuration structure
 * @name: Device name (max 15 chars, null-terminated)
 *
 * Return: 0 on success, negative error code on failure
 */
int buckwild_tun_config_set_name(buckwild_tun_config_t *config,
				  const char *name);

/**
 * buckwild_tun_config_set_ip_addr() - Set IP address from host byte order
 * @config: Configuration structure
 * @ip_addr: IPv4 address in host byte order
 *
 * Return: 0 on success, negative error code on failure
 */
int buckwild_tun_config_set_ip_addr(buckwild_tun_config_t *config,
				     uint32_t ip_addr);

/**
 * buckwild_tun_config_set_netmask() - Set netmask from host byte order
 * @config: Configuration structure
 * @netmask: IPv4 netmask in host byte order
 *
 * Return: 0 on success, negative error code on failure
 */
int buckwild_tun_config_set_netmask(buckwild_tun_config_t *config,
				     uint32_t netmask);

/**
 * buckwild_tun_config_set_mtu() - Set MTU
 * @config: Configuration structure
 * @mtu: MTU value
 *
 * Return: 0 on success, negative error code on failure
 */
int buckwild_tun_config_set_mtu(buckwild_tun_config_t *config, uint16_t mtu);

/**
 * buckwild_tun_device_create() - Create TUN device
 * @config: Device configuration (must not be NULL)
 *
 * Creates and configures a TUN device. The returned handle must be
 * freed with buckwild_tun_device_destroy() when no longer needed.
 *
 * Return: Opaque device handle on success, NULL on failure
 */
struct tun_device *buckwild_tun_device_create(
	const buckwild_tun_config_t *config);

/**
 * buckwild_tun_device_destroy() - Destroy TUN device
 * @dev: Device handle (may be NULL)
 *
 * Destroys the TUN device and frees all associated resources.
 * Safe to call with NULL pointer.
 */
void buckwild_tun_device_destroy(struct tun_device *dev);

/**
 * buckwild_tun_device_read() - Read packet from device
 * @dev: Device handle (must not be NULL)
 * @buf: Buffer to store packet data (must not be NULL)
 * @len: Buffer size
 *
 * Reads a single packet from the TUN device.
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
int64_t buckwild_tun_device_read(struct tun_device *dev, uint8_t *buf,
				  size_t len);

/**
 * buckwild_tun_device_write() - Write packet to device
 * @dev: Device handle (must not be NULL)
 * @buf: Packet data (must not be NULL)
 * @len: Packet size
 *
 * Writes a single packet to the TUN device.
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
int64_t buckwild_tun_device_write(struct tun_device *dev, const uint8_t *buf,
				   size_t len);

/**
 * buckwild_tun_device_get_fd() - Get file descriptor
 * @dev: Device handle (must not be NULL)
 *
 * Returns the underlying file descriptor for use with poll/epoll.
 *
 * Return: File descriptor >= 0 on success, negative error code on failure
 */
int buckwild_tun_device_get_fd(const struct tun_device *dev);

/**
 * buckwild_tun_device_get_name() - Get device name
 * @dev: Device handle (must not be NULL)
 * @buf: Buffer to store name (must not be NULL)
 * @len: Buffer size (must be >= 16)
 *
 * Copies the device name into the provided buffer.
 *
 * Return: 0 on success, negative error code on failure
 */
int buckwild_tun_device_get_name(const struct tun_device *dev, char *buf,
				  size_t len);

/**
 * buckwild_tun_device_get_mtu() - Get device MTU
 * @dev: Device handle (must not be NULL)
 *
 * Return: MTU value on success, 0 on error
 */
uint16_t buckwild_tun_device_get_mtu(const struct tun_device *dev);

/**
 * buckwild_tun_device_is_up() - Check if device is up
 * @dev: Device handle (must not be NULL)
 *
 * Return: 1 if device is up, 0 if down or on error
 */
int buckwild_tun_device_is_up(const struct tun_device *dev);

/**
 * buckwild_tun_device_set_nonblock() - Set non-blocking mode
 * @dev: Device handle (must not be NULL)
 * @nonblock: 1 for non-blocking, 0 for blocking
 *
 * Return: 0 on success, negative error code on failure
 */
int buckwild_tun_device_set_nonblock(struct tun_device *dev, int nonblock);

/**
 * buckwild_tun_error_string() - Get error message
 * @err: Error code
 *
 * Returns a human-readable error message for the given error code.
 *
 * Return: Error message string (never NULL)
 */
const char *buckwild_tun_error_string(int err);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_TUN_DEVICE_FFI_H */
