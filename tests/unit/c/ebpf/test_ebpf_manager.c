/**
 * @file test_ebpf_manager.c
 * @brief Unit tests for eBPF manager implementation
 *
 * PLATFORM: Linux only - tests Linux-specific eBPF APIs
 *
 * Tests validate:
 * - eBPF subsystem initialization and cleanup
 * - Kernel compatibility checking
 * - Version information
 * - Error handling
 */

/* Platform check - eBPF tests require Linux */
#if !defined(__linux__)
#error "eBPF tests require Linux"
#endif

#include <unity.h>
#include "buckwild/ebpf/ebpf.h"
#include "../utils/test_utils.h"
#include <string.h>

void setUp(void)
{
	test_utils_setup();
}

void tearDown(void)
{
	buckwild_ebpf_cleanup();
	test_utils_teardown();
}

/**
 * Test: eBPF subsystem initialization
 */
void test_ebpf_init(void)
{
	int ret;

	ret = buckwild_ebpf_init();
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_SUCCESS, ret,
				      "Init should succeed");

	/* Double init should succeed (idempotent) */
	ret = buckwild_ebpf_init();
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_SUCCESS, ret,
				      "Double init should succeed");
}

/**
 * Test: eBPF manager creation and destruction
 */
void test_ebpf_manager_create_destroy(void)
{
	buckwild_ebpf_manager_t *manager;

	manager = buckwild_ebpf_manager_create();
	TEST_ASSERT_NOT_NULL_MESSAGE(manager,
				     "Manager creation should succeed");

	buckwild_ebpf_manager_destroy(manager);

	/* Destroying NULL should be safe */
	buckwild_ebpf_manager_destroy(NULL);
}

/**
 * Test: Kernel compatibility check
 */
void test_ebpf_kernel_compatibility(void)
{
	int ret;

	ret = buckwild_ebpf_check_kernel_compatibility();

	/* Result depends on kernel version, but should not crash */
	TEST_ASSERT_TRUE_MESSAGE(
		ret == BUCKWILD_EBPF_SUCCESS ||
		ret == BUCKWILD_EBPF_ERROR_VALIDATION,
		"Kernel check should return valid result");
}

/**
 * Test: Version information
 */
void test_ebpf_get_version(void)
{
	uint32_t major, minor, patch;
	int ret;

	ret = buckwild_ebpf_get_version(&major, &minor, &patch);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_SUCCESS, ret,
				      "Get version should succeed");

	/* Version should be 0.1.0 */
	TEST_ASSERT_EQUAL_UINT32(0, major);
	TEST_ASSERT_EQUAL_UINT32(1, minor);
	TEST_ASSERT_EQUAL_UINT32(0, patch);

	/* NULL parameter should fail */
	ret = buckwild_ebpf_get_version(NULL, &minor, &patch);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "NULL major should fail");

	ret = buckwild_ebpf_get_version(&major, NULL, &patch);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "NULL minor should fail");

	ret = buckwild_ebpf_get_version(&major, &minor, NULL);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "NULL patch should fail");
}

/**
 * Test: Error message retrieval
 */
void test_ebpf_get_error_message(void)
{
	const char *msg;

	msg = buckwild_ebpf_get_error_message();
	TEST_ASSERT_NOT_NULL_MESSAGE(msg, "Error message should not be NULL");

	/* Should be "No error" or some default message initially */
	TEST_ASSERT_TRUE_MESSAGE(strlen(msg) > 0,
				 "Error message should not be empty");
}

/**
 * Test: Security feature validation with invalid path
 */
void test_ebpf_validate_security_features_invalid(void)
{
	int ret;

	/* NULL path should fail */
	ret = buckwild_ebpf_validate_security_features(NULL);
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_INVALID, ret,
				      "NULL path should fail");

	/* Non-existent file should fail */
	ret = buckwild_ebpf_validate_security_features(
		"/nonexistent/path/to/program.o");
	TEST_ASSERT_EQUAL_INT_MESSAGE(BUCKWILD_EBPF_ERROR_NOT_FOUND, ret,
				      "Non-existent file should fail");
}

/**
 * Test: Cleanup without init
 */
void test_ebpf_cleanup_without_init(void)
{
	/* Should not crash */
	buckwild_ebpf_cleanup();
	buckwild_ebpf_cleanup(); /* Double cleanup */
}

/* Main test runner */
int main(void)
{
	UNITY_BEGIN();

	RUN_TEST(test_ebpf_init);
	RUN_TEST(test_ebpf_manager_create_destroy);
	RUN_TEST(test_ebpf_kernel_compatibility);
	RUN_TEST(test_ebpf_get_version);
	RUN_TEST(test_ebpf_get_error_message);
	RUN_TEST(test_ebpf_validate_security_features_invalid);
	RUN_TEST(test_ebpf_cleanup_without_init);

	return UNITY_END();
}
