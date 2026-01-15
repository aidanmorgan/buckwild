/**
 * @file tun_device.h
 * @brief TUN/TAP device management for Linux
 *
 * This module provides platform-specific TUN device implementation following
 * Linux kernel coding conventions and the buckwild protocol specification.
 *
 * PLATFORM: Linux only - uses Linux-specific TUN/TAP kernel APIs
 *
 * Protocol References:
 * - design/protocol/03-packet-architecture.md - Header sizes for MTU calculation
 * - design/protocol/01-protocol-overview.md - Session tracking requirements
 *
 * Requirements Implemented:
 * - REQ-TUN-001: Create TUN devices using Linux ioctl interface with TUNSETIFF
 * - REQ-TUN-002: Configure IP address, netmask, and MTU using rtnetlink
 * - REQ-TUN-003: Set MTU to account for buckwild protocol headers
 * - REQ-TUN-004: Support asynchronous packet read operations
 * - REQ-TUN-005: Support asynchronous packet write operations
 * - REQ-TUN-006: Remove TUN device from Linux network stack on cleanup
 * - REQ-TUN-007: Return typed errors for all operations (never panic)
 * - REQ-TUN-008: Check for CAP_NET_ADMIN capability
 */

#ifndef BUCKWILD_TUN_DEVICE_H
#define BUCKWILD_TUN_DEVICE_H

/* Platform check - TUN/TAP is Linux-specific */
#if !defined(__linux__)
#error "TUN/TAP device support requires Linux"
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes for TUN device operations */
enum tun_error {
	TUN_SUCCESS = 0,
	TUN_ERR_INSUFFICIENT_CAPS = -1,	/* Missing CAP_NET_ADMIN */
	TUN_ERR_DEVICE_EXISTS = -2,	/* Device name already in use */
	TUN_ERR_INVALID_IP = -3,	/* Invalid IP address */
	TUN_ERR_INVALID_NAME = -4,	/* Invalid device name */
	TUN_ERR_INVALID_MTU = -5,	/* Invalid MTU value */
	TUN_ERR_IOCTL_FAILED = -6,	/* ioctl operation failed */
	TUN_ERR_NETLINK_FAILED = -7,	/* rtnetlink operation failed */
	TUN_ERR_NOT_FOUND = -8,		/* Device not found */
	TUN_ERR_IO = -9,		/* I/O error */
	TUN_ERR_INVALID_STATE = -10,	/* Invalid device state */
	TUN_ERR_NOMEM = -11,		/* Out of memory */
};

/* Device name constraints (Linux IFNAMSIZ) */
#define TUN_NAME_MAX_LEN 15

/* MTU constraints */
#define TUN_MTU_MIN 68		/* IPv4 minimum per RFC 791 */
#define TUN_MTU_MAX 65535	/* Maximum IP packet size */
#define TUN_MTU_DEFAULT 1400	/* Default accounting for protocol headers */

/* Maximum packet size for I/O buffers */
#define TUN_PACKET_MAX (TUN_MTU_MAX + 4)  /* +4 for TUN packet info */

/**
 * struct tun_config - TUN device configuration
 * @name: Device name (max 15 chars, NULL-terminated)
 * @ip_addr: IP address to assign to device
 * @netmask: Network mask
 * @mtu: Maximum transmission unit
 * @persistent: Make device persistent across process exit
 */
struct tun_config {
	char name[TUN_NAME_MAX_LEN + 1];
	struct in_addr ip_addr;
	struct in_addr netmask;
	uint16_t mtu;
	bool persistent;
};

/**
 * struct tun_device - Opaque TUN device handle
 *
 * Internal structure - do not access members directly.
 * Use accessor functions instead.
 */
struct tun_device;

/**
 * tun_config_init() - Initialize configuration with defaults
 * @config: Configuration structure to initialize
 *
 * Sets default values:
 * - MTU: TUN_MTU_DEFAULT (1400)
 * - Persistent: false
 * - Name, IP, netmask: zero-initialized
 *
 * Return: 0 on success, negative error code on failure
 */
int tun_config_init(struct tun_config *config);

/**
 * tun_config_set_name() - Set device name with validation
 * @config: Configuration structure
 * @name: Device name (max 15 chars)
 *
 * Validates that name is:
 * - Non-empty
 * - <= 15 characters
 * - Contains only valid characters
 *
 * Return: 0 on success, TUN_ERR_INVALID_NAME on failure
 */
int tun_config_set_name(struct tun_config *config, const char *name);

/**
 * tun_config_set_ip() - Set IP address from string
 * @config: Configuration structure
 * @ip_str: IP address string (e.g., "10.100.0.1")
 *
 * Return: 0 on success, TUN_ERR_INVALID_IP on failure
 */
int tun_config_set_ip(struct tun_config *config, const char *ip_str);

/**
 * tun_config_set_netmask() - Set netmask from string
 * @config: Configuration structure
 * @mask_str: Netmask string (e.g., "255.255.255.0")
 *
 * Return: 0 on success, TUN_ERR_INVALID_IP on failure
 */
int tun_config_set_netmask(struct tun_config *config, const char *mask_str);

/**
 * tun_config_set_mtu() - Set MTU with validation
 * @config: Configuration structure
 * @mtu: MTU value
 *
 * Validates that MTU is >= TUN_MTU_MIN (68)
 *
 * Return: 0 on success, TUN_ERR_INVALID_MTU on failure
 */
int tun_config_set_mtu(struct tun_config *config, uint16_t mtu);

/**
 * tun_device_create() - Create and configure TUN device
 * @config: Device configuration
 *
 * Creates TUN device using ioctl (REQ-TUN-001) and configures
 * IP address, netmask, and MTU using rtnetlink (REQ-TUN-002, REQ-TUN-003).
 *
 * Requires CAP_NET_ADMIN capability (REQ-TUN-008).
 *
 * Return: Pointer to device handle on success, NULL on failure
 */
struct tun_device *tun_device_create(const struct tun_config *config);

/**
 * tun_device_destroy() - Destroy TUN device and cleanup resources
 * @dev: Device handle
 *
 * Removes device from network stack (REQ-TUN-006) and frees all resources.
 * Safe to call with NULL pointer.
 */
void tun_device_destroy(struct tun_device *dev);

/**
 * tun_device_read() - Read packet from TUN device
 * @dev: Device handle
 * @buf: Buffer to store packet data
 * @len: Buffer size
 *
 * Reads a single packet from the TUN device (REQ-TUN-004).
 * This is a blocking call - use poll/epoll for async operation.
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
ssize_t tun_device_read(struct tun_device *dev, void *buf, size_t len);

/**
 * tun_device_write() - Write packet to TUN device
 * @dev: Device handle
 * @buf: Packet data to write
 * @len: Packet size
 *
 * Writes a single packet to the TUN device (REQ-TUN-005).
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
ssize_t tun_device_write(struct tun_device *dev, const void *buf, size_t len);

/**
 * tun_device_get_fd() - Get file descriptor for async I/O
 * @dev: Device handle
 *
 * Returns the underlying file descriptor for use with poll()/epoll().
 *
 * Return: File descriptor >= 0 on success, negative error code on failure
 */
int tun_device_get_fd(const struct tun_device *dev);

/**
 * tun_device_get_name() - Get device name
 * @dev: Device handle
 *
 * Return: Device name string, NULL on error
 */
const char *tun_device_get_name(const struct tun_device *dev);

/**
 * tun_device_get_mtu() - Get device MTU
 * @dev: Device handle
 *
 * Return: MTU value, 0 on error
 */
uint16_t tun_device_get_mtu(const struct tun_device *dev);

/**
 * tun_device_is_up() - Check if device is up
 * @dev: Device handle
 *
 * Return: true if device is up, false otherwise
 */
bool tun_device_is_up(const struct tun_device *dev);

/**
 * tun_device_set_nonblock() - Set non-blocking mode
 * @dev: Device handle
 * @nonblock: true for non-blocking, false for blocking
 *
 * Return: 0 on success, negative error code on failure
 */
int tun_device_set_nonblock(struct tun_device *dev, bool nonblock);

/**
 * tun_error_string() - Get human-readable error message
 * @err: Error code
 *
 * Return: Error message string
 */
const char *tun_error_string(int err);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_TUN_DEVICE_H */
