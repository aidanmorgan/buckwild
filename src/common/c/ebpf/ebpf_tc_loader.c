/**
 * @file ebpf_tc_loader.c
 * @brief TC (Traffic Control) program loader implementation
 *
 * This file implements TC program loading, attachment, and traffic shaping
 * for the Buckwild security protocol using libbpf.
 *
 * PLATFORM: Linux only
 */

/* Platform check - eBPF is Linux-specific */
#if !defined(__linux__)
#error "eBPF TC loader requires Linux"
#endif

#include "buckwild/ebpf/ebpf.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Internal TC loader structure */
struct buckwild_tc_loader {
	char interface[IFNAMSIZ];
	bool enable_egress;
	bool enable_ingress;
	buckwild_security_config_t security;
	uint32_t rate_limit_bps;
	uint8_t priority_levels;

	/* libbpf objects */
	struct bpf_object *bpf_obj;
	struct bpf_program *ingress_prog;
	struct bpf_program *egress_prog;
	struct bpf_link *ingress_link;
	struct bpf_link *egress_link;

	/* eBPF maps */
	int traffic_map_fd;
	int stats_map_fd;
	int config_map_fd;

	/* State */
	bool loaded;
	bool attached;
	int ifindex;
};

/* External error message setter */
extern void set_error(const char *msg);

/* --- Internal Helper Functions --- */

static int get_ifindex(const char *ifname)
{
	unsigned int idx = if_nametoindex(ifname);
	if (idx == 0)
		return -1;
	return (int)idx;
}

/* --- Public API Implementation --- */

buckwild_tc_loader_t *buckwild_tc_loader_create(
	const buckwild_tc_config_t *config)
{
	struct buckwild_tc_loader *loader;
	size_t len;

	if (!config || !config->interface) {
		return NULL;
	}

	/* Validate interface name */
	len = strlen(config->interface);
	if (len == 0 || len >= IFNAMSIZ)
		return NULL;

	/* Allocate loader structure */
	loader = calloc(1, sizeof(*loader));
	if (!loader)
		return NULL;

	/* Initialize fields */
	memcpy(loader->interface, config->interface, len);
	loader->interface[len] = '\0';

	loader->enable_egress = config->enable_egress;
	loader->enable_ingress = config->enable_ingress;
	loader->security = config->security;
	loader->rate_limit_bps = config->rate_limit_bps;
	loader->priority_levels = config->priority_levels;

	/* Mark file descriptors as invalid */
	loader->traffic_map_fd = -1;
	loader->stats_map_fd = -1;
	loader->config_map_fd = -1;

	/* Get interface index */
	loader->ifindex = get_ifindex(config->interface);
	if (loader->ifindex < 0) {
		free(loader);
		return NULL;
	}

	loader->loaded = false;
	loader->attached = false;

	return loader;
}

void buckwild_tc_loader_destroy(buckwild_tc_loader_t *loader)
{
	if (!loader)
		return;

	/* Detach if attached */
	if (loader->attached)
		buckwild_tc_loader_detach(loader);

	/* Cleanup libbpf objects */
	if (loader->ingress_link)
		bpf_link__destroy(loader->ingress_link);
	if (loader->egress_link)
		bpf_link__destroy(loader->egress_link);

	if (loader->bpf_obj)
		bpf_object__close(loader->bpf_obj);

	/* Close map file descriptors */
	if (loader->traffic_map_fd >= 0)
		close(loader->traffic_map_fd);
	if (loader->stats_map_fd >= 0)
		close(loader->stats_map_fd);
	if (loader->config_map_fd >= 0)
		close(loader->config_map_fd);

	free(loader);
}

int buckwild_tc_loader_load_and_attach(buckwild_tc_loader_t *loader)
{
	if (!loader)
		return BUCKWILD_EBPF_ERROR_INVALID;

	if (loader->loaded)
		return BUCKWILD_EBPF_ERROR_INVALID;

	/* TC eBPF program loading is not yet implemented.
	 * Implementation requires:
	 * 1. Open and load eBPF object file via libbpf
	 * 2. Find ingress/egress programs
	 * 3. Attach to TC hook points using BPF_PROG_TYPE_SCHED_CLS
	 * See ebpf_xdp_loader.c for XDP loading reference. */

	return BUCKWILD_EBPF_ERROR_NOT_FOUND;
}

int buckwild_tc_loader_detach(buckwild_tc_loader_t *loader)
{
	if (!loader)
		return BUCKWILD_EBPF_ERROR_INVALID;

	if (!loader->attached)
		return BUCKWILD_EBPF_ERROR_INVALID;

	/* Destroy BPF links */
	if (loader->ingress_link) {
		bpf_link__destroy(loader->ingress_link);
		loader->ingress_link = NULL;
	}

	if (loader->egress_link) {
		bpf_link__destroy(loader->egress_link);
		loader->egress_link = NULL;
	}

	loader->attached = false;
	loader->loaded = false;

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_tc_loader_update_traffic_shaping(buckwild_tc_loader_t *loader,
					      uint64_t session_id,
					      uint32_t rate_limit_bps,
					      uint8_t priority)
{
	struct {
		uint32_t rate_limit_bps;
		uint8_t priority;
		uint8_t padding[3];
	} config;
	int ret;

	if (!loader)
		return BUCKWILD_EBPF_ERROR_INVALID;

	if (!loader->loaded || loader->traffic_map_fd < 0)
		return BUCKWILD_EBPF_ERROR_INVALID;

	/* Prepare configuration */
	config.rate_limit_bps = rate_limit_bps;
	config.priority = priority;

	/* Update traffic shaping map */
	ret = bpf_map_update_elem(loader->traffic_map_fd, &session_id,
				  &config, BPF_ANY);
	if (ret != 0)
		return BUCKWILD_EBPF_ERROR_RESOURCE;

	return BUCKWILD_EBPF_SUCCESS;
}

int buckwild_tc_loader_get_traffic_stats(buckwild_tc_loader_t *loader,
					 uint64_t session_id,
					 uint64_t *bytes_sent,
					 uint64_t *packets_sent)
{
	struct {
		uint64_t bytes;
		uint64_t packets;
	} stats;
	int ret;

	if (!loader || !bytes_sent || !packets_sent)
		return BUCKWILD_EBPF_ERROR_INVALID;

	if (!loader->loaded || loader->stats_map_fd < 0)
		return BUCKWILD_EBPF_ERROR_INVALID;

	/* Lookup traffic stats */
	ret = bpf_map_lookup_elem(loader->stats_map_fd, &session_id, &stats);
	if (ret != 0)
		return BUCKWILD_EBPF_ERROR_NOT_FOUND;

	*bytes_sent = stats.bytes;
	*packets_sent = stats.packets;

	return BUCKWILD_EBPF_SUCCESS;
}
