/**
 * @file test_tun_device.c
 * @brief Unit tests for TUN device implementation
 *
 * PLATFORM: Linux only - tests Linux-specific TUN/TAP APIs
 *
 * Tests based on TUN_EBPF_IMPLEMENTATION_GUIDE.md Phase 1 requirements:
 * - Test 1.1: TUN Device Creation
 * - Test 1.2: TUN Device Lifecycle
 * - Test 1.3: Async Packet I/O
 * - Test 1.4: Error Handling - Insufficient Capabilities
 * - Test 1.5: Error Handling - Device Already Exists
 * - Test 1.6: Error Handling - Invalid Configuration
 */

/* Platform check - TUN tests require Linux */
#if !defined(__linux__)
#error "TUN device tests require Linux"
#endif

#include <unity.h>
#include "buckwild/network/tun_device.h"
#include "../utils/test_utils.h"
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>

/* Test device configuration */
static struct tun_config test_config;
static struct tun_device *test_dev = NULL;

void setUp(void)
{
	test_utils_setup();

	/* Initialize default test configuration */
	tun_config_init(&test_config);
	tun_config_set_name(&test_config, "buckwild0");
	tun_config_set_ip(&test_config, "10.100.0.1");
	tun_config_set_netmask(&test_config, "255.255.255.0");
	tun_config_set_mtu(&test_config, 1400);
}

void tearDown(void)
{
	/* Clean up test device if created */
	if (test_dev) {
		tun_device_destroy(test_dev);
		test_dev = NULL;
	}

	test_utils_teardown();
}

/**
 * Test 1.1: TUN Device Creation
 *
 * Given: Process has CAP_NET_ADMIN capability (root)
 * When: TUN device is created with valid config
 * Then: Device is created successfully with correct parameters
 */
void test_tun_device_creation(void)
{
	const char *name;
	uint16_t mtu;

	/* Skip if not root */
	if (geteuid() != 0) {
		TEST_IGNORE_MESSAGE("Test requires root privileges");
		return;
	}

	/* Create TUN device */
	test_dev = tun_device_create(&test_config);
	TEST_ASSERT_NOT_NULL_MESSAGE(test_dev, "Device creation failed");

	/* Verify device properties */
	name = tun_device_get_name(test_dev);
	TEST_ASSERT_NOT_NULL(name);
	TEST_ASSERT_EQUAL_STRING("buckwild0", name);

	mtu = tun_device_get_mtu(test_dev);
	TEST_ASSERT_EQUAL_UINT16(1400, mtu);

	TEST_ASSERT_TRUE_MESSAGE(tun_device_is_up(test_dev),
				 "Device should be UP");
}

/**
 * Test 1.2: TUN Device Lifecycle
 *
 * Given: TUN device is created
 * When: Device handle is destroyed
 * Then: Device is removed from Linux network stack
 */
void test_tun_device_lifecycle(void)
{
	char path[256];
	struct stat st;

	/* Skip if not root */
	if (geteuid() != 0) {
		TEST_IGNORE_MESSAGE("Test requires root privileges");
		return;
	}

	/* Create device */
	test_dev = tun_device_create(&test_config);
	TEST_ASSERT_NOT_NULL(test_dev);

	/* Verify device exists in sysfs */
	snprintf(path, sizeof(path), "/sys/class/net/%s",
		 tun_device_get_name(test_dev));
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, stat(path, &st),
				      "Device should exist in sysfs");

	/* Destroy device */
	tun_device_destroy(test_dev);
	test_dev = NULL;

	/* Verify device is removed */
	TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(0, stat(path, &st),
					  "Device should be removed from sysfs");
}

/**
 * Test 1.3: Async Packet I/O
 *
 * Given: TUN device is created and up
 * When: Test packet is written asynchronously
 * Then: Packet can be read back asynchronously
 */
void test_tun_async_packet_io(void)
{
	uint8_t write_buf[1500];
	uint8_t read_buf[1500];
	ssize_t n;
	int fd;
	struct pollfd pfd;

	/* Skip if not root */
	if (geteuid() != 0) {
		TEST_IGNORE_MESSAGE("Test requires root privileges");
		return;
	}

	/* Create device */
	test_dev = tun_device_create(&test_config);
	TEST_ASSERT_NOT_NULL(test_dev);

	/* Set non-blocking mode */
	TEST_ASSERT_EQUAL_INT(TUN_SUCCESS,
			      tun_device_set_nonblock(test_dev, true));

	/* Prepare test packet (simple IPv4 header) */
	memset(write_buf, 0, sizeof(write_buf));
	write_buf[0] = 0x45;  /* IPv4, header length 5 */
	write_buf[1] = 0x00;  /* DSCP, ECN */

	/* Write packet */
	n = tun_device_write(test_dev, write_buf, 64);
	TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, n,
					     "Write should succeed");

	/* Wait for packet to be readable (with timeout) */
	fd = tun_device_get_fd(test_dev);
	TEST_ASSERT_GREATER_OR_EQUAL_INT(0, fd);

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	/* Poll with 1 second timeout */
	int poll_ret = poll(&pfd, 1, 1000);
	TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, poll_ret,
					     "Poll should succeed");

	/* Read packet back */
	n = tun_device_read(test_dev, read_buf, sizeof(read_buf));
	TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, n,
					     "Read should succeed");

	/* Note: Packet contents might be modified by kernel routing,
	 * so we just verify we got data back */
}

/**
 * Test 1.4: Error Handling - Insufficient Capabilities
 *
 * Given: Process does not have CAP_NET_ADMIN (simulated)
 * When: Attempting to create TUN device
 * Then: Operation returns error, no panic
 */
void test_tun_insufficient_capabilities(void)
{
	/* This test can only run if NOT root */
	if (geteuid() == 0) {
		TEST_IGNORE_MESSAGE("Test requires non-root user");
		return;
	}

	/* Attempt to create device without privileges */
	test_dev = tun_device_create(&test_config);
	TEST_ASSERT_NULL_MESSAGE(test_dev,
				 "Should fail without CAP_NET_ADMIN");

	/* Verify errno is set appropriately */
	TEST_ASSERT_EQUAL_INT_MESSAGE(EPERM, errno,
				      "Should return EPERM");
}

/**
 * Test 1.5: Error Handling - Device Already Exists
 *
 * Given: TUN device already exists
 * When: Attempting to create another device with same name
 * Then: Operation returns error, no panic
 */
void test_tun_device_already_exists(void)
{
	struct tun_device *dev2;

	/* Skip if not root */
	if (geteuid() != 0) {
		TEST_IGNORE_MESSAGE("Test requires root privileges");
		return;
	}

	/* Create first device */
	test_dev = tun_device_create(&test_config);
	TEST_ASSERT_NOT_NULL(test_dev);

	/* Attempt to create duplicate */
	dev2 = tun_device_create(&test_config);
	TEST_ASSERT_NULL_MESSAGE(dev2,
				 "Duplicate device creation should fail");

	/* Note: errno might be EEXIST or other error depending on timing */
}

/**
 * Test 1.6: Error Handling - Invalid Configuration
 *
 * Test various invalid configurations
 */
void test_tun_invalid_config(void)
{
	struct tun_config invalid_config;
	int ret;

	/* Test: Empty device name */
	tun_config_init(&invalid_config);
	ret = tun_config_set_name(&invalid_config, "");
	TEST_ASSERT_EQUAL_INT_MESSAGE(TUN_ERR_INVALID_NAME, ret,
				      "Empty name should fail");

	/* Test: Device name too long */
	ret = tun_config_set_name(&invalid_config,
				  "this_name_is_way_too_long_for_interface");
	TEST_ASSERT_EQUAL_INT_MESSAGE(TUN_ERR_INVALID_NAME, ret,
				      "Long name should fail");

	/* Test: Invalid IP address */
	tun_config_init(&invalid_config);
	tun_config_set_name(&invalid_config, "buckwild_test");
	ret = tun_config_set_ip(&invalid_config, "999.999.999.999");
	TEST_ASSERT_EQUAL_INT_MESSAGE(TUN_ERR_INVALID_IP, ret,
				      "Invalid IP should fail");

	/* Test: Invalid MTU (too small) */
	tun_config_init(&invalid_config);
	ret = tun_config_set_mtu(&invalid_config, 67);  /* Below minimum */
	TEST_ASSERT_EQUAL_INT_MESSAGE(TUN_ERR_INVALID_MTU, ret,
				      "MTU below minimum should fail");
}

/**
 * Test: Configuration Initialization
 */
void test_tun_config_init(void)
{
	struct tun_config config;

	TEST_ASSERT_EQUAL_INT(TUN_SUCCESS, tun_config_init(&config));

	/* Verify defaults */
	TEST_ASSERT_EQUAL_UINT16(TUN_MTU_DEFAULT, config.mtu);
	TEST_ASSERT_FALSE(config.persistent);
	TEST_ASSERT_EQUAL_STRING("", config.name);
}

/**
 * Test: Valid Configuration
 */
void test_tun_valid_config(void)
{
	struct tun_config config;
	int ret;

	tun_config_init(&config);

	/* Set valid device name */
	ret = tun_config_set_name(&config, "buckwild_test");
	TEST_ASSERT_EQUAL_INT(TUN_SUCCESS, ret);
	TEST_ASSERT_EQUAL_STRING("buckwild_test", config.name);

	/* Set valid IP */
	ret = tun_config_set_ip(&config, "192.168.1.1");
	TEST_ASSERT_EQUAL_INT(TUN_SUCCESS, ret);

	/* Set valid netmask */
	ret = tun_config_set_netmask(&config, "255.255.255.0");
	TEST_ASSERT_EQUAL_INT(TUN_SUCCESS, ret);

	/* Set valid MTU */
	ret = tun_config_set_mtu(&config, 9000);
	TEST_ASSERT_EQUAL_INT(TUN_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT16(9000, config.mtu);
}

/**
 * Test: Error String Function
 */
void test_tun_error_strings(void)
{
	const char *msg;

	msg = tun_error_string(TUN_SUCCESS);
	TEST_ASSERT_NOT_NULL(msg);
	TEST_ASSERT_EQUAL_STRING("Success", msg);

	msg = tun_error_string(TUN_ERR_INSUFFICIENT_CAPS);
	TEST_ASSERT_NOT_NULL(msg);
	/* Just verify it's not empty */
	TEST_ASSERT_GREATER_THAN_size_t(0, strlen(msg));

	msg = tun_error_string(TUN_ERR_INVALID_MTU);
	TEST_ASSERT_NOT_NULL(msg);
	TEST_ASSERT_GREATER_THAN_size_t(0, strlen(msg));
}

/**
 * Test: Get File Descriptor
 */
void test_tun_get_fd(void)
{
	int fd;

	/* Skip if not root */
	if (geteuid() != 0) {
		TEST_IGNORE_MESSAGE("Test requires root privileges");
		return;
	}

	test_dev = tun_device_create(&test_config);
	TEST_ASSERT_NOT_NULL(test_dev);

	fd = tun_device_get_fd(test_dev);
	TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(0, fd,
						 "FD should be valid");

	/* Verify FD is valid by doing fcntl */
	int flags = fcntl(fd, F_GETFL);
	TEST_ASSERT_NOT_EQUAL_INT(-1, flags);
}

/* Main test runner */
int main(void)
{
	UNITY_BEGIN();

	/* Configuration tests */
	RUN_TEST(test_tun_config_init);
	RUN_TEST(test_tun_valid_config);
	RUN_TEST(test_tun_invalid_config);
	RUN_TEST(test_tun_error_strings);

	/* Device creation and lifecycle tests */
	RUN_TEST(test_tun_device_creation);
	RUN_TEST(test_tun_device_lifecycle);
	RUN_TEST(test_tun_get_fd);

	/* I/O tests */
	RUN_TEST(test_tun_async_packet_io);

	/* Error handling tests */
	RUN_TEST(test_tun_insufficient_capabilities);
	RUN_TEST(test_tun_device_already_exists);

	return UNITY_END();
}
