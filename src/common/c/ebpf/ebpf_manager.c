/**
 * @file ebpf_manager.c
 * @brief eBPF subsystem manager implementation
 *
 * This file implements the eBPF manager which provides subsystem
 * initialization, cleanup, and utilities.
 *
 * PLATFORM: Linux only
 */

/* Platform check - eBPF is Linux-specific */
#if !defined(__linux__)
#error "eBPF manager requires Linux"
#endif

#include "buckwild/ebpf/ebpf.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <bpf/libbpf.h>

/* eBPF manager structure */
struct buckwild_ebpf_manager {
	bool initialized;
	uint32_t loader_count;
};

/* Global state */
static bool subsystem_initialized = false;
static struct buckwild_ebpf_manager global_manager;

/* Error message buffer */
static __thread char error_msg[256] = {0};

/* --- Internal Helper Functions --- */

void set_error(const char *msg)
{
	size_t len = strlen(msg);
	if (len >= sizeof(error_msg))
		len = sizeof(error_msg) - 1;
	memcpy(error_msg, msg, len);
	error_msg[len] = '\0';
}

static int parse_kernel_version(struct utsname *uts, int *major, int *minor)
{
	int ret = sscanf(uts->release, "%d.%d", major, minor);
	if (ret != 2)
		return -1;
	return 0;
}

/* --- Public API Implementation --- */

int buckwild_ebpf_init(void)
{
	if (subsystem_initialized)
		return BUCKWILD_EBPF_SUCCESS;

	/* Initialize libbpf */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Set libbpf print callback to suppress verbose output */
	libbpf_set_print(NULL);

	/* Initialize global manager */
	memset(&global_manager, 0, sizeof(global_manager));
	global_manager.initialized = true;
	global_manager.loader_count = 0;

	subsystem_initialized = true;

	return BUCKWILD_EBPF_SUCCESS;
}

void buckwild_ebpf_cleanup(void)
{
	if (!subsystem_initialized)
		return;

	subsystem_initialized = false;
	global_manager.initialized = false;
}

buckwild_ebpf_manager_t *buckwild_ebpf_manager_create(void)
{
	struct buckwild_ebpf_manager *manager;

	/* Ensure subsystem is initialized */
	if (!subsystem_initialized) {
		if (buckwild_ebpf_init() != BUCKWILD_EBPF_SUCCESS) {
			set_error("Failed to initialize eBPF subsystem");
			return NULL;
		}
	}

	manager = calloc(1, sizeof(*manager));
	if (!manager) {
		set_error("Memory allocation failed");
		return NULL;
	}

	manager->initialized = true;
	manager->loader_count = 0;

	return manager;
}

void buckwild_ebpf_manager_destroy(buckwild_ebpf_manager_t *manager)
{
	if (!manager)
		return;

	manager->initialized = false;
	free(manager);
}

int buckwild_ebpf_check_kernel_compatibility(void)
{
	struct utsname uts;
	int major, minor;

	if (uname(&uts) != 0) {
		set_error("Failed to get kernel version");
		return BUCKWILD_EBPF_ERROR_RESOURCE;
	}

	if (parse_kernel_version(&uts, &major, &minor) != 0) {
		set_error("Failed to parse kernel version");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Require Linux 5.10+ for BPF ring buffer support */
	if (major < 5 || (major == 5 && minor < 10)) {
		set_error("Kernel 5.10+ required for eBPF features");
		return BUCKWILD_EBPF_ERROR_VALIDATION;
	}

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_ebpf_get_version(uint32_t *major, uint32_t *minor,
			      uint32_t *patch)
{
	if (!major || !minor || !patch)
		return BUCKWILD_EBPF_ERROR_INVALID;

	/* Version of this eBPF loader implementation */
	*major = 0;
	*minor = 1;
	*patch = 0;

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_ebpf_validate_security_features(const char *program_path)
{
	struct bpf_object *obj;
	int err;

	if (!program_path) {
		set_error("Invalid program path");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Check if file exists */
	if (access(program_path, R_OK) != 0) {
		set_error("eBPF program file not accessible");
		return BUCKWILD_EBPF_ERROR_NOT_FOUND;
	}

	/* Try to open and validate the eBPF object */
	obj = bpf_object__open(program_path);
	if (!obj) {
		set_error("Failed to open eBPF program");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Validate that it loads successfully */
	err = bpf_object__load(obj);
	if (err) {
		bpf_object__close(obj);
		set_error("Failed to load eBPF program");
		return BUCKWILD_EBPF_ERROR_VALIDATION;
	}

	/* Additional security validation could be added:
	 * - Verify expected maps exist (bpf_object__find_map_by_name)
	 * - Verify expected programs exist (bpf_object__find_program_by_name)
	 * - Check BTF information for type safety
	 * - Validate security features are present
	 * Basic load validation is sufficient for now. */

	bpf_object__close(obj);

	return BUCKWILD_EBPF_SUCCESS;
}

const char *buckwild_ebpf_get_error_message(void)
{
	if (error_msg[0] == '\0')
		return "No error";
	return error_msg;
}
