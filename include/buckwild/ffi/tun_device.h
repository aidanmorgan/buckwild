/**
 * @file tun_device.h
 * @brief TUN device FFI bindings for Buckwild
 *
 * This header provides C bindings for TUN device lifecycle management and
 * packet I/O operations. The TUN device is used for network packet processing
 * in the Buckwild frequency hopping protocol.
 *
 * ## Memory Ownership
 *
 * - **Device Handle**: Returned by `buckwild_tun_create()`, must be freed with
 *   `buckwild_tun_destroy()`. The caller owns the handle.
 *
 * - **Config String**: Caller-owned, read-only during `buckwild_tun_create()`.
 *   Not modified or stored by the library.
 *
 * - **Read Buffer**: Caller-allocated, filled by `buckwild_tun_read()`.
 *   Ownership remains with caller.
 *
 * - **Write Buffer**: Caller-owned, read-only during `buckwild_tun_write()`.
 *   Not modified or stored by the library.
 *
 * - **Name Buffer**: Caller-allocated, filled by `buckwild_tun_get_name()`.
 *   Ownership remains with caller.
 *
 * ## Threading
 *
 * - Device handles are NOT thread-safe. Do not call operations on the same
 *   handle from multiple threads concurrently.
 * - Different handles can be used safely from different threads.
 *
 * ## Platform Support
 *
 * - Linux: Full support using /dev/net/tun and rtnetlink
 * - macOS: Not supported (returns BUCKWILD_ERR_NOT_SUPPORTED)
 * - Windows: Not supported (returns BUCKWILD_ERR_NOT_SUPPORTED)
 *
 * FFI-SAFE: All types use C-compatible representations
 */

#ifndef BUCKWILD_FFI_TUN_DEVICE_H
#define BUCKWILD_FFI_TUN_DEVICE_H

#include "types.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * BuckwildTunDevice - Opaque handle to a TUN device
 *
 * This is an opaque pointer managed by the Rust implementation.
 * Do not attempt to dereference or modify the pointer directly.
 *
 * Lifecycle:
 * 1. Create with buckwild_tun_create()
 * 2. Use with read/write operations
 * 3. Destroy with buckwild_tun_destroy()
 */
typedef struct BuckwildTunDevice BuckwildTunDevice;

/**
 * BuckwildTunConfig - TUN device configuration
 *
 * Configuration parameters for creating a TUN device.
 * All string fields must be null-terminated UTF-8.
 */
typedef struct {
	/** Device name (max 15 chars, e.g., "buckwild0") */
	const char *name;
	/** IP address (e.g., "10.100.0.1") */
	const char *ip_address;
	/** Network mask (e.g., "255.255.255.0") */
	const char *netmask;
	/** Maximum transmission unit (68-65535, 0 for default 1400) */
	uint16_t mtu;
} BuckwildTunConfig;

/**
 * buckwild_tun_create() - Create a new TUN device
 * @config: Device configuration (caller-owned, not modified)
 *
 * Creates and configures a TUN device with the specified parameters.
 * On Linux, requires CAP_NET_ADMIN capability or root privileges.
 *
 * The device is automatically set UP and configured with the specified
 * IP address, netmask, and MTU.
 *
 * ## Errors
 *
 * - BUCKWILD_ERR_NULL_POINTER: config or config fields are NULL
 * - BUCKWILD_ERR_INVALID_ARGUMENT: Invalid device name, IP, or MTU
 * - BUCKWILD_ERR_TUN_CREATE_FAILED: Device creation failed
 * - BUCKWILD_ERR_TUN_CONFIGURE_FAILED: Device configuration failed
 * - BUCKWILD_ERR_TUN_PERMISSION_DENIED: Insufficient privileges
 * - BUCKWILD_ERR_INTERFACE_CREATE_FAILED: Interface creation failed
 * - BUCKWILD_ERR_INVALID_ADDRESS: Invalid IP address format
 * - BUCKWILD_ERR_NOT_SUPPORTED: Platform does not support TUN devices
 *
 * Return: BuckwildPtrResult with device handle on success, error on failure
 *
 * ## Example
 *
 * ```c
 * BuckwildTunConfig config = {
 *     .name = "buckwild0",
 *     .ip_address = "10.100.0.1",
 *     .netmask = "255.255.255.0",
 *     .mtu = 1400
 * };
 *
 * BuckwildPtrResult result = buckwild_tun_create(&config);
 * if (result.error != BUCKWILD_OK) {
 *     fprintf(stderr, "Failed to create TUN device: %s\n",
 *             buckwild_error_string(result.error));
 *     return -1;
 * }
 *
 * BuckwildTunDevice *device = (BuckwildTunDevice *)result.ptr;
 * ```
 */
BuckwildPtrResult buckwild_tun_create(const BuckwildTunConfig *config);

/**
 * buckwild_tun_destroy() - Destroy a TUN device
 * @device: Device handle to destroy (must not be NULL)
 *
 * Destroys the TUN device and frees all associated resources.
 * The device is automatically brought DOWN and removed from the system.
 *
 * After this call, the device handle is invalid and must not be used.
 *
 * ## Errors
 *
 * - BUCKWILD_ERR_NULL_POINTER: device is NULL
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * ## Example
 *
 * ```c
 * BuckwildError err = buckwild_tun_destroy(device);
 * if (err != BUCKWILD_OK) {
 *     fprintf(stderr, "Failed to destroy TUN device: %s\n",
 *             buckwild_error_string(err));
 * }
 * device = NULL;  // Prevent use-after-free
 * ```
 */
BuckwildError buckwild_tun_destroy(BuckwildTunDevice *device);

/**
 * buckwild_tun_read() - Read a packet from the TUN device
 * @device: Device handle (must not be NULL)
 * @buffer: Buffer to store packet data (must not be NULL)
 * @buffer_len: Size of buffer in bytes
 *
 * Reads a single packet from the TUN device into the provided buffer.
 * This operation blocks until a packet is available or an error occurs.
 *
 * The buffer should be at least as large as the device MTU to avoid
 * truncation. Use `buckwild_tun_get_mtu()` to determine the required size.
 *
 * ## Errors
 *
 * - BUCKWILD_ERR_NULL_POINTER: device or buffer is NULL
 * - BUCKWILD_ERR_BUFFER_TOO_SMALL: buffer_len is 0
 * - BUCKWILD_ERR_TUN_READ_FAILED: Read operation failed
 * - BUCKWILD_ERR_WOULD_BLOCK: No data available (non-blocking mode)
 * - BUCKWILD_ERR_TIMEOUT: Read operation timed out
 * - BUCKWILD_ERR_CONNECTION_CLOSED: Device was closed
 *
 * Return: BuckwildResult with bytes read on success, error on failure
 *
 * ## Example
 *
 * ```c
 * uint8_t buffer[2048];
 * BuckwildResult result = buckwild_tun_read(device, buffer, sizeof(buffer));
 * if (result.error != BUCKWILD_OK) {
 *     fprintf(stderr, "Failed to read packet: %s\n",
 *             buckwild_error_string(result.error));
 *     return -1;
 * }
 *
 * size_t bytes_read = (size_t)result.value;
 * printf("Read %zu bytes\n", bytes_read);
 * ```
 */
BuckwildResult buckwild_tun_read(BuckwildTunDevice *device,
                                  uint8_t *buffer,
                                  size_t buffer_len);

/**
 * buckwild_tun_write() - Write a packet to the TUN device
 * @device: Device handle (must not be NULL)
 * @buffer: Packet data to write (must not be NULL)
 * @buffer_len: Size of packet data in bytes
 *
 * Writes a single packet to the TUN device from the provided buffer.
 * This operation blocks until the packet is written or an error occurs.
 *
 * The packet size must not exceed the device MTU. Use
 * `buckwild_tun_get_mtu()` to determine the maximum packet size.
 *
 * ## Errors
 *
 * - BUCKWILD_ERR_NULL_POINTER: device or buffer is NULL
 * - BUCKWILD_ERR_INVALID_ARGUMENT: buffer_len is 0
 * - BUCKWILD_ERR_MTU_EXCEEDED: buffer_len exceeds device MTU
 * - BUCKWILD_ERR_TUN_WRITE_FAILED: Write operation failed
 * - BUCKWILD_ERR_WOULD_BLOCK: Write would block (non-blocking mode)
 * - BUCKWILD_ERR_TIMEOUT: Write operation timed out
 * - BUCKWILD_ERR_CONNECTION_CLOSED: Device was closed
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * ## Example
 *
 * ```c
 * const uint8_t packet[] = { ... };
 * BuckwildError err = buckwild_tun_write(device, packet, sizeof(packet));
 * if (err != BUCKWILD_OK) {
 *     fprintf(stderr, "Failed to write packet: %s\n",
 *             buckwild_error_string(err));
 *     return -1;
 * }
 * ```
 */
BuckwildError buckwild_tun_write(BuckwildTunDevice *device,
                                  const uint8_t *buffer,
                                  size_t buffer_len);

/**
 * buckwild_tun_get_name() - Get the device name
 * @device: Device handle (must not be NULL)
 * @buffer: Buffer to store device name (must not be NULL)
 * @buffer_len: Size of buffer in bytes
 *
 * Copies the device name into the provided buffer as a null-terminated string.
 * The buffer should be at least 16 bytes (IFNAMSIZ) to hold any device name.
 *
 * ## Errors
 *
 * - BUCKWILD_ERR_NULL_POINTER: device or buffer is NULL
 * - BUCKWILD_ERR_BUFFER_TOO_SMALL: buffer_len is too small for name + null
 *
 * Return: BUCKWILD_OK on success, error code on failure
 *
 * ## Example
 *
 * ```c
 * char name[16];
 * BuckwildError err = buckwild_tun_get_name(device, name, sizeof(name));
 * if (err != BUCKWILD_OK) {
 *     fprintf(stderr, "Failed to get device name: %s\n",
 *             buckwild_error_string(err));
 *     return -1;
 * }
 * printf("Device name: %s\n", name);
 * ```
 */
BuckwildError buckwild_tun_get_name(BuckwildTunDevice *device,
                                     char *buffer,
                                     size_t buffer_len);

/**
 * buckwild_tun_get_mtu() - Get the device MTU
 * @device: Device handle (must not be NULL)
 *
 * Returns the device Maximum Transmission Unit (MTU) in bytes.
 * This is the maximum packet size that can be written to the device.
 *
 * ## Errors
 *
 * - BUCKWILD_ERR_NULL_POINTER: device is NULL
 *
 * Return: BuckwildResult with MTU value on success, error on failure
 *
 * ## Example
 *
 * ```c
 * BuckwildResult result = buckwild_tun_get_mtu(device);
 * if (result.error != BUCKWILD_OK) {
 *     fprintf(stderr, "Failed to get MTU: %s\n",
 *             buckwild_error_string(result.error));
 *     return -1;
 * }
 * printf("Device MTU: %ld bytes\n", result.value);
 * ```
 */
BuckwildResult buckwild_tun_get_mtu(BuckwildTunDevice *device);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_FFI_TUN_DEVICE_H */
