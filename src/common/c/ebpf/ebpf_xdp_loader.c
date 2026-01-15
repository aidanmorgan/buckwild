/**
 * @file ebpf_xdp_loader.c
 * @brief XDP program loader implementation with security features
 *
 * This file implements XDP program loading, attachment, and session management
 * for the Buckwild security protocol using libbpf.
 *
 * PLATFORM: Linux only
 */

/* Platform check - eBPF is Linux-specific */
#if !defined(__linux__)
#error "eBPF XDP loader requires Linux"
#endif

#include "buckwild/ebpf/ebpf.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Internal XDP loader structure */
struct buckwild_xdp_loader {
	char interface[IFNAMSIZ];
	buckwild_xdp_mode_t attach_mode;
	buckwild_security_config_t security;
	size_t ring_buffer_size;

	/* libbpf objects */
	struct bpf_object *bpf_obj;
	struct bpf_program *bpf_prog;
	struct bpf_link *bpf_link;

	/* eBPF maps */
	int session_map_fd;
	int stats_map_fd;
	int config_map_fd;
	int event_ring_fd;

	/* Ring buffer for events */
	struct ring_buffer *ring_buf;

	/* Callbacks */
	buckwild_packet_callback_t packet_callback;
	void *packet_user_data;
	buckwild_security_event_callback_t security_callback;
	void *security_user_data;

	/* State */
	bool loaded;
	bool attached;
	bool processing;
	bool security_validated;
	int ifindex;
};

/* Global error message buffer */
static __thread char error_msg[256];

/* --- Internal Helper Functions --- */

static void set_error(const char *msg)
{
	size_t len = strlen(msg);
	if (len >= sizeof(error_msg))
		len = sizeof(error_msg) - 1;
	memcpy(error_msg, msg, len);
	error_msg[len] = '\0';
}

static int get_ifindex(const char *ifname)
{
	unsigned int idx = if_nametoindex(ifname);
	if (idx == 0) {
		set_error("Network interface not found");
		return -1;
	}
	return (int)idx;
}

static uint32_t xdp_mode_to_flags(buckwild_xdp_mode_t mode) __attribute__((unused));

static uint32_t xdp_mode_to_flags(buckwild_xdp_mode_t mode)
{
	switch (mode) {
	case BUCKWILD_XDP_MODE_GENERIC:
		return XDP_FLAGS_SKB_MODE;
	case BUCKWILD_XDP_MODE_NATIVE:
		return XDP_FLAGS_DRV_MODE;
	case BUCKWILD_XDP_MODE_OFFLOAD:
		return XDP_FLAGS_HW_MODE;
	default:
		return XDP_FLAGS_SKB_MODE;
	}
}

/* --- Public API Implementation --- */

buckwild_xdp_loader_t *buckwild_xdp_loader_create(
	const buckwild_xdp_config_t *config)
{
	struct buckwild_xdp_loader *loader;
	size_t len;

	if (!config || !config->interface) {
		set_error("Invalid configuration");
		return NULL;
	}

	/* Validate interface name */
	len = strlen(config->interface);
	if (len == 0 || len >= IFNAMSIZ) {
		set_error("Invalid interface name");
		return NULL;
	}

	/* Allocate loader structure */
	loader = calloc(1, sizeof(*loader));
	if (!loader) {
		set_error("Memory allocation failed");
		return NULL;
	}

	/* Initialize fields */
	memcpy(loader->interface, config->interface, len);
	loader->interface[len] = '\0';

	loader->attach_mode = config->attach_mode;
	loader->security = config->security;
	loader->ring_buffer_size = config->ring_buffer_size;

	/* Mark file descriptors as invalid */
	loader->session_map_fd = -1;
	loader->stats_map_fd = -1;
	loader->config_map_fd = -1;
	loader->event_ring_fd = -1;

	/* Get interface index */
	loader->ifindex = get_ifindex(config->interface);
	if (loader->ifindex < 0) {
		free(loader);
		return NULL;
	}

	loader->loaded = false;
	loader->attached = false;
	loader->processing = false;
	loader->security_validated = false;

	return loader;
}

void buckwild_xdp_loader_destroy(buckwild_xdp_loader_t *loader)
{
	if (!loader)
		return;

	/* Stop processing if running */
	if (loader->processing)
		buckwild_xdp_loader_stop_processing(loader);

	/* Detach if attached */
	if (loader->attached)
		buckwild_xdp_loader_detach(loader);

	/* Cleanup ring buffer */
	if (loader->ring_buf)
		ring_buffer__free(loader->ring_buf);

	/* Cleanup libbpf objects */
	if (loader->bpf_link)
		bpf_link__destroy(loader->bpf_link);

	if (loader->bpf_obj)
		bpf_object__close(loader->bpf_obj);

	/* Close map file descriptors */
	if (loader->session_map_fd >= 0)
		close(loader->session_map_fd);
	if (loader->stats_map_fd >= 0)
		close(loader->stats_map_fd);
	if (loader->config_map_fd >= 0)
		close(loader->config_map_fd);
	if (loader->event_ring_fd >= 0)
		close(loader->event_ring_fd);

	free(loader);
}

int buckwild_xdp_loader_load_and_attach(buckwild_xdp_loader_t *loader)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	(void)open_opts; /* Unused for now */

	if (!loader) {
		set_error("Invalid loader");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (loader->loaded) {
		set_error("Program already loaded");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* XDP eBPF program loading is not yet fully implemented.
	 * Implementation requires:
	 * 1. Path to compiled eBPF .o file
	 * 2. bpf_object__open_file() to open object
	 * 3. bpf_object__load() to load into kernel
	 * 4. bpf_object__find_program_by_name() to get program handle
	 * 5. bpf_program__attach_xdp() to attach to network interface
	 * Placeholder returns error until implementation is complete. */

	set_error("eBPF program loading not yet implemented");
	return BUCKWILD_EBPF_ERROR_NOT_FOUND;
}

int buckwild_xdp_loader_detach(buckwild_xdp_loader_t *loader)
{
	if (!loader) {
		set_error("Invalid loader");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (!loader->attached) {
		set_error("Program not attached");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Destroy BPF link */
	if (loader->bpf_link) {
		bpf_link__destroy(loader->bpf_link);
		loader->bpf_link = NULL;
	}

	loader->attached = false;
	loader->loaded = false;

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_xdp_loader_update_session(buckwild_xdp_loader_t *loader,
				       uint64_t session_id,
				       const buckwild_session_info_t *info)
{
	int ret;

	if (!loader || !info) {
		set_error("Invalid parameters");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (!loader->loaded || loader->session_map_fd < 0) {
		set_error("Program not loaded or session map not available");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Update session in eBPF map */
	ret = bpf_map_update_elem(loader->session_map_fd, &session_id, info, BPF_ANY);
	if (ret != 0) {
		set_error("Failed to update session map");
		return BUCKWILD_EBPF_ERROR_RESOURCE;
	}

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_xdp_loader_remove_session(buckwild_xdp_loader_t *loader,
				       uint64_t session_id)
{
	int ret;

	if (!loader) {
		set_error("Invalid loader");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (!loader->loaded || loader->session_map_fd < 0) {
		set_error("Program not loaded or session map not available");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Delete session from eBPF map */
	ret = bpf_map_delete_elem(loader->session_map_fd, &session_id);
	if (ret != 0) {
		set_error("Failed to remove session from map");
		return BUCKWILD_EBPF_ERROR_RESOURCE;
	}

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_xdp_loader_get_session(buckwild_xdp_loader_t *loader,
				    uint64_t session_id,
				    buckwild_session_info_t *info)
{
	int ret;

	if (!loader || !info) {
		set_error("Invalid parameters");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (!loader->loaded || loader->session_map_fd < 0) {
		set_error("Program not loaded or session map not available");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Lookup session in eBPF map */
	ret = bpf_map_lookup_elem(loader->session_map_fd, &session_id, info);
	if (ret != 0) {
		set_error("Session not found in map");
		return BUCKWILD_EBPF_ERROR_NOT_FOUND;
	}

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_xdp_loader_get_security_stats(buckwild_xdp_loader_t *loader,
					   buckwild_security_stats_t *stats)
{
	uint32_t key = 0;
	int ret;

	if (!loader || !stats) {
		set_error("Invalid parameters");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (!loader->loaded || loader->stats_map_fd < 0) {
		set_error("Program not loaded or stats map not available");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Read statistics from eBPF map (key 0) */
	ret = bpf_map_lookup_elem(loader->stats_map_fd, &key, stats);
	if (ret != 0) {
		set_error("Failed to read statistics");
		return BUCKWILD_EBPF_ERROR_RESOURCE;
	}

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_xdp_loader_set_packet_callback(
	buckwild_xdp_loader_t *loader,
	buckwild_packet_callback_t callback,
	void *user_data)
{
	if (!loader) {
		set_error("Invalid loader");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	loader->packet_callback = callback;
	loader->packet_user_data = user_data;

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_xdp_loader_set_security_callback(
	buckwild_xdp_loader_t *loader,
	buckwild_security_event_callback_t callback,
	void *user_data)
{
	if (!loader) {
		set_error("Invalid loader");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	loader->security_callback = callback;
	loader->security_user_data = user_data;

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_xdp_loader_start_processing(buckwild_xdp_loader_t *loader)
{
	if (!loader) {
		set_error("Invalid loader");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (!loader->loaded) {
		set_error("Program not loaded");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (loader->processing) {
		set_error("Processing already started");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	/* Ring buffer polling setup is not yet implemented.
	 * Implementation would:
	 * 1. Get ring buffer map FD from loaded eBPF object
	 * 2. Create ring_buffer instance with ring_buffer__new()
	 * 3. Start polling thread or integrate with event loop
	 * Currently returns success as placeholder. */

	loader->processing = true;

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_xdp_loader_stop_processing(buckwild_xdp_loader_t *loader)
{
	if (!loader) {
		set_error("Invalid loader");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	if (!loader->processing) {
		set_error("Processing not started");
		return BUCKWILD_EBPF_ERROR_INVALID;
	}

	loader->processing = false;

	return BUCKWILD_EBPF_SUCCESS;
}

bool buckwild_xdp_loader_is_loaded(const buckwild_xdp_loader_t *loader)
{
	if (!loader)
		return false;

	return loader->loaded;
}

bool buckwild_xdp_loader_is_security_validated(
	const buckwild_xdp_loader_t *loader)
{
	if (!loader)
		return false;

	return loader->security_validated;
}
