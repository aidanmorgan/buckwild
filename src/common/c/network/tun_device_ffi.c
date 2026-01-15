/**
 * @file tun_device_ffi.c
 * @brief FFI implementation for TUN device operations
 *
 * This file provides the FFI layer implementation that wraps
 * the core TUN device functions for safe interoperation with
 * other languages (primarily Rust).
 *
 * PLATFORM: Linux only
 */

/* Platform check - this file requires Linux */
#if !defined(__linux__)
#error "TUN/TAP device FFI implementation requires Linux"
#endif

#include "buckwild/network/tun_device_ffi.h"
#include "buckwild/network/tun_device.h"

#include <string.h>
#include <arpa/inet.h>

/* --- Configuration Functions --- */

int buckwild_tun_config_init(buckwild_tun_config_t *config)
{
	if (!config)
		return -1;

	memset(config, 0, sizeof(*config));
	config->mtu = 1400; /* TUN_MTU_DEFAULT */
	config->persistent = false;

	return 0;
}

int buckwild_tun_config_set_name(buckwild_tun_config_t *config,
				  const char *name)
{
	size_t len;

	if (!config || !name)
		return -1;

	len = strlen(name);
	if (len == 0 || len > 15)
		return -1;

	strncpy(config->name, name, 15);
	config->name[15] = '\0';

	return 0;
}

int buckwild_tun_config_set_ip_addr(buckwild_tun_config_t *config,
				     uint32_t ip_addr)
{
	if (!config)
		return -1;

	/* Convert host to network byte order */
	config->ip_addr = htonl(ip_addr);
	return 0;
}

int buckwild_tun_config_set_netmask(buckwild_tun_config_t *config,
				     uint32_t netmask)
{
	if (!config)
		return -1;

	/* Convert host to network byte order */
	config->netmask = htonl(netmask);
	return 0;
}

int buckwild_tun_config_set_mtu(buckwild_tun_config_t *config, uint16_t mtu)
{
	if (!config)
		return -1;

	if (mtu < 68) /* TUN_MTU_MIN */
		return -1;

	config->mtu = mtu;
	return 0;
}

/* --- Device Functions --- */

struct tun_device *buckwild_tun_device_create(
	const buckwild_tun_config_t *config)
{
	struct tun_config c_config;
	struct in_addr addr;

	if (!config)
		return NULL;

	/* Convert FFI config to internal config */
	if (tun_config_init(&c_config) != TUN_SUCCESS)
		return NULL;

	if (tun_config_set_name(&c_config, config->name) != TUN_SUCCESS)
		return NULL;

	/* Convert IP address from network byte order */
	addr.s_addr = config->ip_addr;
	char ip_str[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)))
		return NULL;

	if (tun_config_set_ip(&c_config, ip_str) != TUN_SUCCESS)
		return NULL;

	/* Convert netmask from network byte order */
	addr.s_addr = config->netmask;
	char mask_str[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &addr, mask_str, sizeof(mask_str)))
		return NULL;

	if (tun_config_set_netmask(&c_config, mask_str) != TUN_SUCCESS)
		return NULL;

	if (tun_config_set_mtu(&c_config, config->mtu) != TUN_SUCCESS)
		return NULL;

	c_config.persistent = config->persistent;

	/* Create the device */
	return tun_device_create(&c_config);
}

void buckwild_tun_device_destroy(struct tun_device *dev)
{
	tun_device_destroy(dev);
}

int64_t buckwild_tun_device_read(struct tun_device *dev, uint8_t *buf,
				  size_t len)
{
	ssize_t result;

	if (!dev || !buf)
		return -1;

	result = tun_device_read(dev, buf, len);
	return (int64_t)result;
}

int64_t buckwild_tun_device_write(struct tun_device *dev, const uint8_t *buf,
				   size_t len)
{
	ssize_t result;

	if (!dev || !buf)
		return -1;

	result = tun_device_write(dev, buf, len);
	return (int64_t)result;
}

int buckwild_tun_device_get_fd(const struct tun_device *dev)
{
	if (!dev)
		return -1;

	return tun_device_get_fd(dev);
}

int buckwild_tun_device_get_name(const struct tun_device *dev, char *buf,
				  size_t len)
{
	const char *name;

	if (!dev || !buf || len < 16)
		return -1;

	name = tun_device_get_name(dev);
	if (!name)
		return -1;

	strncpy(buf, name, len - 1);
	buf[len - 1] = '\0';

	return 0;
}

uint16_t buckwild_tun_device_get_mtu(const struct tun_device *dev)
{
	if (!dev)
		return 0;

	return tun_device_get_mtu(dev);
}

int buckwild_tun_device_is_up(const struct tun_device *dev)
{
	if (!dev)
		return 0;

	return tun_device_is_up(dev) ? 1 : 0;
}

int buckwild_tun_device_set_nonblock(struct tun_device *dev, int nonblock)
{
	if (!dev)
		return -1;

	return tun_device_set_nonblock(dev, nonblock != 0);
}

const char *buckwild_tun_error_string(int err)
{
	return tun_error_string(err);
}
