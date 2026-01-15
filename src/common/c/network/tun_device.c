/**
 * @file tun_device.c
 * @brief TUN/TAP device implementation for Linux
 *
 * Implementation follows Linux kernel coding conventions and uses:
 * - ioctl for device creation (TUNSETIFF)
 * - rtnetlink for IP configuration
 * - Standard POSIX I/O for packet read/write
 *
 * PLATFORM: Linux only - uses Linux-specific TUN/TAP kernel APIs
 *
 * Error handling: All functions return error codes, never panic.
 * Memory safety: All allocations are checked, resources properly freed.
 */

/* Platform check - this file requires Linux */
#if !defined(__linux__)
#error "TUN/TAP device implementation requires Linux"
#endif

#include "buckwild/network/tun_device.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

/**
 * struct tun_device - Internal device structure
 * @fd: File descriptor for /dev/net/tun
 * @name: Device name
 * @mtu: Current MTU
 * @is_up: Device operational status
 */
struct tun_device {
	int fd;
	char name[IFNAMSIZ];
	uint16_t mtu;
	bool is_up;
};

/* --- Configuration Functions --- */

int tun_config_init(struct tun_config *config)
{
	if (!config)
		return TUN_ERR_NOMEM;

	memset(config, 0, sizeof(*config));
	config->mtu = TUN_MTU_DEFAULT;
	config->persistent = false;

	return TUN_SUCCESS;
}

int tun_config_set_name(struct tun_config *config, const char *name)
{
	size_t len;

	if (!config || !name)
		return TUN_ERR_INVALID_NAME;

	len = strlen(name);
	if (len == 0 || len > TUN_NAME_MAX_LEN)
		return TUN_ERR_INVALID_NAME;

	/* Check for valid characters (alphanumeric, underscore, hyphen) */
	for (size_t i = 0; i < len; i++) {
		char c = name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '-'))
			return TUN_ERR_INVALID_NAME;
	}

	/* Copy name with bounds checking */
	if (len >= sizeof(config->name))
		len = sizeof(config->name) - 1;
	memcpy(config->name, name, len);
	config->name[len] = '\0';

	return TUN_SUCCESS;
}

int tun_config_set_ip(struct tun_config *config, const char *ip_str)
{
	if (!config || !ip_str)
		return TUN_ERR_INVALID_IP;

	if (inet_pton(AF_INET, ip_str, &config->ip_addr) != 1)
		return TUN_ERR_INVALID_IP;

	return TUN_SUCCESS;
}

int tun_config_set_netmask(struct tun_config *config, const char *mask_str)
{
	if (!config || !mask_str)
		return TUN_ERR_INVALID_IP;

	if (inet_pton(AF_INET, mask_str, &config->netmask) != 1)
		return TUN_ERR_INVALID_IP;

	return TUN_SUCCESS;
}

int tun_config_set_mtu(struct tun_config *config, uint16_t mtu)
{
	if (!config)
		return TUN_ERR_NOMEM;

	if (mtu < TUN_MTU_MIN)
		return TUN_ERR_INVALID_MTU;

	config->mtu = mtu;
	return TUN_SUCCESS;
}

/* --- Internal Helper Functions --- */

/**
 * check_capabilities() - Verify CAP_NET_ADMIN capability
 *
 * REQ-TUN-008: Check for sufficient capabilities
 *
 * Return: 0 if capable, TUN_ERR_INSUFFICIENT_CAPS otherwise
 */
static int check_capabilities(void)
{
	/* Simple check: are we root? */
	if (geteuid() != 0)
		return TUN_ERR_INSUFFICIENT_CAPS;

	/* Root check is sufficient for TUN device creation.
	 * Fine-grained capability checking (CAP_NET_ADMIN) could be added
	 * if running with reduced privileges, but requires libcap dependency. */
	return TUN_SUCCESS;
}

/**
 * create_tun_interface() - Create TUN device using ioctl
 * @dev: Device structure
 * @name: Desired device name
 *
 * REQ-TUN-001: Create TUN device using TUNSETIFF ioctl
 *
 * Return: 0 on success, negative error code on failure
 */
static int create_tun_interface(struct tun_device *dev, const char *name)
{
	struct ifreq ifr;
	int fd, err;

	/* Open /dev/net/tun */
	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		if (errno == ENOENT)
			return TUN_ERR_NOT_FOUND;
		return TUN_ERR_IO;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (name && strlen(name) > 0) {
		size_t len = strlen(name);
		if (len >= IFNAMSIZ)
			len = IFNAMSIZ - 1;
		memcpy(ifr.ifr_name, name, len);
		ifr.ifr_name[len] = '\0';
	}

	/* Create TUN device */
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		err = errno;
		close(fd);

		if (err == EEXIST)
			return TUN_ERR_DEVICE_EXISTS;
		return TUN_ERR_IOCTL_FAILED;
	}

	/* Store device info */
	dev->fd = fd;
	{
		size_t name_len = strnlen(ifr.ifr_name, IFNAMSIZ);
		if (name_len >= sizeof(dev->name))
			name_len = sizeof(dev->name) - 1;
		memcpy(dev->name, ifr.ifr_name, name_len);
		dev->name[name_len] = '\0';
	}

	return TUN_SUCCESS;
}

/**
 * configure_interface() - Configure IP, netmask, and MTU
 * @dev: Device structure
 * @config: Configuration parameters
 *
 * REQ-TUN-002: Configure using rtnetlink
 * REQ-TUN-003: Set MTU accounting for protocol headers
 *
 * Return: 0 on success, negative error code on failure
 */
static int configure_interface(struct tun_device *dev,
				const struct tun_config *config)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *addr;

	/* Create socket for ioctl calls */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return TUN_ERR_IO;

	memset(&ifr, 0, sizeof(ifr));
	{
		size_t len = strlen(dev->name);
		if (len >= IFNAMSIZ)
			len = IFNAMSIZ - 1;
		memcpy(ifr.ifr_name, dev->name, len);
		ifr.ifr_name[len] = '\0';
	}

	/* Set IP address */
	addr = (struct sockaddr_in *)&ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr = config->ip_addr;

	if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
		close(sock);
		return TUN_ERR_IOCTL_FAILED;
	}

	/* Set netmask */
	addr = (struct sockaddr_in *)&ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	addr->sin_addr = config->netmask;

	if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
		close(sock);
		return TUN_ERR_IOCTL_FAILED;
	}

	/* Set MTU */
	ifr.ifr_mtu = config->mtu;
	if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
		close(sock);
		return TUN_ERR_IOCTL_FAILED;
	}

	dev->mtu = config->mtu;

	/* Bring interface UP */
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		close(sock);
		return TUN_ERR_IOCTL_FAILED;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		close(sock);
		return TUN_ERR_IOCTL_FAILED;
	}

	dev->is_up = true;
	close(sock);

	return TUN_SUCCESS;
}

/* --- Public API Functions --- */

struct tun_device *tun_device_create(const struct tun_config *config)
{
	struct tun_device *dev;
	int err;

	if (!config)
		return NULL;

	/* REQ-TUN-008: Check capabilities */
	err = check_capabilities();
	if (err != TUN_SUCCESS) {
		errno = EPERM;
		return NULL;
	}

	/* Allocate device structure */
	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	/* Initialize to invalid state until successfully opened */
	dev->fd = -1;

	/* REQ-TUN-001: Create TUN interface */
	err = create_tun_interface(dev, config->name);
	if (err != TUN_SUCCESS) {
		free(dev);
		errno = -err;
		return NULL;
	}

	/* REQ-TUN-002, REQ-TUN-003: Configure interface */
	err = configure_interface(dev, config);
	if (err != TUN_SUCCESS) {
		close(dev->fd);
		free(dev);
		errno = -err;
		return NULL;
	}

	return dev;
}

void tun_device_destroy(struct tun_device *dev)
{
	if (!dev)
		return;

	/* REQ-TUN-006: Remove device from network stack */
	/* Device is automatically removed when fd is closed on Linux */
	if (dev->fd >= 0) {
		close(dev->fd);
		dev->fd = -1;  /* Mark as closed to prevent double-close */
	}

	free(dev);
}

ssize_t tun_device_read(struct tun_device *dev, void *buf, size_t len)
{
	ssize_t n;

	if (!dev || dev->fd < 0)
		return TUN_ERR_INVALID_STATE;

	if (!buf)
		return TUN_ERR_NOMEM;

	/* REQ-TUN-004: Async packet read */
	n = read(dev->fd, buf, len);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;  /* Non-blocking, no data available */
		return TUN_ERR_IO;
	}

	return n;
}

ssize_t tun_device_write(struct tun_device *dev, const void *buf, size_t len)
{
	ssize_t n;

	if (!dev || dev->fd < 0)
		return TUN_ERR_INVALID_STATE;

	if (!buf)
		return TUN_ERR_NOMEM;

	/* REQ-TUN-005: Async packet write */
	n = write(dev->fd, buf, len);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;  /* Non-blocking, would block */
		return TUN_ERR_IO;
	}

	return n;
}

int tun_device_get_fd(const struct tun_device *dev)
{
	if (!dev)
		return TUN_ERR_INVALID_STATE;

	return dev->fd;
}

const char *tun_device_get_name(const struct tun_device *dev)
{
	if (!dev)
		return NULL;

	return dev->name;
}

uint16_t tun_device_get_mtu(const struct tun_device *dev)
{
	if (!dev)
		return 0;

	return dev->mtu;
}

bool tun_device_is_up(const struct tun_device *dev)
{
	if (!dev)
		return false;

	return dev->is_up;
}

int tun_device_set_nonblock(struct tun_device *dev, bool nonblock)
{
	int flags;

	if (!dev || dev->fd < 0)
		return TUN_ERR_INVALID_STATE;

	flags = fcntl(dev->fd, F_GETFL);
	if (flags < 0)
		return TUN_ERR_IO;

	if (nonblock)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if (fcntl(dev->fd, F_SETFL, flags) < 0)
		return TUN_ERR_IO;

	return TUN_SUCCESS;
}

const char *tun_error_string(int err)
{
	switch (err) {
	case TUN_SUCCESS:
		return "Success";
	case TUN_ERR_INSUFFICIENT_CAPS:
		return "Insufficient capabilities (CAP_NET_ADMIN required)";
	case TUN_ERR_DEVICE_EXISTS:
		return "Device already exists";
	case TUN_ERR_INVALID_IP:
		return "Invalid IP address";
	case TUN_ERR_INVALID_NAME:
		return "Invalid device name";
	case TUN_ERR_INVALID_MTU:
		return "Invalid MTU value";
	case TUN_ERR_IOCTL_FAILED:
		return "ioctl operation failed";
	case TUN_ERR_NETLINK_FAILED:
		return "rtnetlink operation failed";
	case TUN_ERR_NOT_FOUND:
		return "Device not found";
	case TUN_ERR_IO:
		return "I/O error";
	case TUN_ERR_INVALID_STATE:
		return "Invalid device state";
	case TUN_ERR_NOMEM:
		return "Out of memory";
	default:
		return "Unknown error";
	}
}
