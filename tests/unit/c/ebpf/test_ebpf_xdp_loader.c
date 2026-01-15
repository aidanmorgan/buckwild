/**
 * @file test_ebpf_xdp_loader.c
 * @brief Unit tests for XDP loader implementation
 *
 * PLATFORM: Linux only - tests Linux-specific XDP APIs
 *
 * Tests validate:
 * - XDP loader creation and destruction
 * - Configuration validation
 * - Session management operations
 * - Callback registration
 * - State management
 */

/* Platform check - XDP tests require Linux */
#if !defined(__linux__)
#error "XDP loader tests require Linux"
#endif

#include <unity.h>
#include "buckwild/ebpf/ebpf.h"
#include "../utils/test_utils.h"
#include <string.h>

static buckwild_xdp_config_t test_config;

void setUp(void)
{
	test_utils_setup();

	/* Initialize default test configuration */
	memset(&test_config, 0, sizeof(test_config));
	test_config.interface = "lo"; /* loopback interface always exists */
	test_config.attach_mode = BUCKWILD_XDP_MODE_GENERIC;
	test_config.ring_buffer_size = 4096;

	/* Default security config */
	test_config.security.enable_security_features = true;
	test_config.security.enable_fragment_security = true;
	test_config.security.enable_attack_detection = true;
	test_config.security.enable_rate_limiting = false;
	test_config.security.rate_limit_pps = 0;
	test_config.security.rate_limit_bps = 0;
	test_config.security.fragment_timeout_ms = 1000;
	test_config.security.attack_threshold = 10;
	test_config.security.security_level = 2;

	buckwild_ebpf_init();
}

void tearDown(void)
{
	buckwild_ebpf_cleanup();
	test_utils_teardown();
}

/**
 * Test: XDP loader creation with valid config
 */
void test_xdp_loader_create_valid(void)
{
	buckwild_xdp_loader_t *loader;

	loader = buckwild_xdp_loader_create(&test_config);
	TEST_ASSERT_NOT_NULL_MESSAGE(loader, "Loader creation should succeed");

	buckwild_xdp_loader_destroy(loader);
}

/**
 * Test: XDP loader creation with NULL config
 */
void test_xdp_loader_create_null_config(void)
{
	buckwild_xdp_loader_t *loader;

	loader = buckwild_xdp_loader_create(NULL);
	TEST_ASSERT_NULL_MESSAGE(loader,
				 "Loader creation with NULL config should fail");
}

/**
 * Test: XDP loader creation with NULL interface
 */
void test_xdp_loader_create_null_interface(void)
{
	buckwild_xdp_loader_t *loader;
	buckwild_xdp_config_t config = test_config;

	config.interface = NULL;

	loader = buckwild_xdp_loader_create(&config);
	TEST_ASSERT_NULL_MESSAGE(loader,
				 "Loader creation with NULL interface should fail");
}

/**
 * Test: XDP loader creation with empty interface name
 */
void test_xdp_loader_create_empty_interface(void)
{
	buckwild_xdp_loader_t *loader;
	buckwild_xdp_config_t config = test_config;

	config.interface = "";

	loader = buckwild_xdp_loader_create(&config);
	TEST_ASSERT_NULL_MESSAGE(loader,
				 "Loader creation with empty interface should fail");
}

/**
 * Test: XDP loader creation with invalid interface
 */
void test_xdp_loader_create_invalid_interface(void)
{
	buckwild_xdp_loader_t *loader;
	buckwild_xdp_config_t config = test_config;

	config.interface = "nonexistent999";

	loader = buckwild_xdp_loader_create(&config);
	TEST_ASSERT_NULL_MESSAGE(loader,
				 "Loader creation with invalid interface should fail");
}

/**
 * Test: XDP loader destroy with NULL
 */
void test_xdp_loader_destroy_null(void)
{
	/* Should not crash */
	buckwild_xdp_loader_destroy(NULL);
}

/**
 * Test: XDP loader is_loaded before loading
 */
void test_xdp_loader_is_loaded_false(void)
{
	buckwild_xdp_loader_t *loader;
	bool loaded;

	loader = buckwild_xdp_loader_create(&test_config);
	TEST_ASSERT_NOT_NULL(loader);

	loaded = buckwild_xdp_loader_is_loaded(loader);
	TEST_ASSERT_FALSE_MESSAGE(loaded,
				  "Loader should not be loaded initially");

	buckwild_xdp_loader_destroy(loader);
}

/**
 * Test: XDP loader is_loaded with NULL
 */
void test_xdp_loader_is_loaded_null(void)
{
	bool loaded;

	loaded = buckwild_xdp_loader_is_loaded(NULL);
	TEST_ASSERT_FALSE_MESSAGE(loaded, "NULL loader should return false");
}

/**
 * Test: XDP loader is_security_validated before validation
 */
void test_xdp_loader_is_security_validated_false(void)
{
	buckwild_xdp_loader_t *loader;
	bool validated;

	loader = buckwild_xdp_loader_create(&test_config);
	TEST_ASSERT_NOT_NULL(loader);

	validated = buckwild_xdp_loader_is_security_validated(loader);
	TEST_ASSERT_FALSE_MESSAGE(validated,
				  "Loader should not be validated initially");

	buckwild_xdp_loader_destroy(loader);
}

/**
 * Test: Set packet callback
 */
void test_xdp_loader_set_packet_callback(void)
{
	buckwild_xdp_loader_t *loader;
	int ret;
	int user_data = 42;

	loader = buckwild_xdp_loader_create(&test_config);
	TEST_ASSERT_NOT_NULL(loader);

	/* Dummy callback */
	buckwild_packet_callback_t callback =
		(buckwild_packet_callback_t)(void *)0x1234;

	ret = buckwild_xdp_loader_set_packet_callback(loader, callback,
						      &user_data);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_SUCCESS, ret,
				      "Set callback should succeed");

	buckwild_xdp_loader_destroy(loader);
}

/**
 * Test: Set packet callback with NULL loader
 */
void test_xdp_loader_set_packet_callback_null_loader(void)
{
	int ret;
	buckwild_packet_callback_t callback =
		(buckwild_packet_callback_t)(void *)0x1234;

	ret = buckwild_xdp_loader_set_packet_callback(NULL, callback, NULL);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "NULL loader should fail");
}

/**
 * Test: Set security callback
 */
void test_xdp_loader_set_security_callback(void)
{
	buckwild_xdp_loader_t *loader;
	int ret;
	int user_data = 42;

	loader = buckwild_xdp_loader_create(&test_config);
	TEST_ASSERT_NOT_NULL(loader);

	/* Dummy callback */
	buckwild_security_event_callback_t callback =
		(buckwild_security_event_callback_t)(void *)0x1234;

	ret = buckwild_xdp_loader_set_security_callback(loader, callback,
							&user_data);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_SUCCESS, ret,
				      "Set callback should succeed");

	buckwild_xdp_loader_destroy(loader);
}

/**
 * Test: Session operations before loading should fail
 */
void test_xdp_loader_session_operations_before_load(void)
{
	buckwild_xdp_loader_t *loader;
	buckwild_session_info_t session_info;
	int ret;
	uint64_t session_id = 12345;

	memset(&session_info, 0, sizeof(session_info));
	session_info.session_id = session_id;

	loader = buckwild_xdp_loader_create(&test_config);
	TEST_ASSERT_NOT_NULL(loader);

	/* Update should fail - not loaded */
	ret = buckwild_xdp_loader_update_session(loader, session_id,
						 &session_info);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "Update before load should fail");

	/* Get should fail - not loaded */
	ret = buckwild_xdp_loader_get_session(loader, session_id,
					      &session_info);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "Get before load should fail");

	/* Remove should fail - not loaded */
	ret = buckwild_xdp_loader_remove_session(loader, session_id);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "Remove before load should fail");

	buckwild_xdp_loader_destroy(loader);
}

/**
 * Test: Processing operations before loading should fail
 */
void test_xdp_loader_processing_before_load(void)
{
	buckwild_xdp_loader_t *loader;
	int ret;

	loader = buckwild_xdp_loader_create(&test_config);
	TEST_ASSERT_NOT_NULL(loader);

	/* Start processing should fail - not loaded */
	ret = buckwild_xdp_loader_start_processing(loader);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "Start processing before load should fail");

	buckwild_xdp_loader_destroy(loader);
}

/**
 * Test: Detach before attach should fail
 */
void test_xdp_loader_detach_before_attach(void)
{
	buckwild_xdp_loader_t *loader;
	int ret;

	loader = buckwild_xdp_loader_create(&test_config);
	TEST_ASSERT_NOT_NULL(loader);

	/* Detach should fail - not attached */
	ret = buckwild_xdp_loader_detach(loader);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "Detach before attach should fail");

	buckwild_xdp_loader_destroy(loader);
}

/* Main test runner */
int main(void)
{
	UNITY_BEGIN();

	/* Creation and destruction tests */
	RUN_TEST(test_xdp_loader_create_valid);
	RUN_TEST(test_xdp_loader_create_null_config);
	RUN_TEST(test_xdp_loader_create_null_interface);
	RUN_TEST(test_xdp_loader_create_empty_interface);
	RUN_TEST(test_xdp_loader_create_invalid_interface);
	RUN_TEST(test_xdp_loader_destroy_null);

	/* State tests */
	RUN_TEST(test_xdp_loader_is_loaded_false);
	RUN_TEST(test_xdp_loader_is_loaded_null);
	RUN_TEST(test_xdp_loader_is_security_validated_false);

	/* Callback tests */
	RUN_TEST(test_xdp_loader_set_packet_callback);
	RUN_TEST(test_xdp_loader_set_packet_callback_null_loader);
	RUN_TEST(test_xdp_loader_set_security_callback);

	/* Operation tests */
	RUN_TEST(test_xdp_loader_session_operations_before_load);
	RUN_TEST(test_xdp_loader_processing_before_load);
	RUN_TEST(test_xdp_loader_detach_before_attach);

	return UNITY_END();
}
