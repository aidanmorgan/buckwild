/**
 * Mock helpers for C unit tests
 */

#include "mock_helpers.h"
#include <string.h>
#include <stdlib.h>

// Mock eBPF map operations
static struct mock_map_entry mock_maps[MAX_MOCK_MAPS];
static size_t mock_map_count = 0;

int mock_bpf_map_lookup_elem(int fd, const void *key, void *value) {
    for (size_t i = 0; i < mock_map_count; i++) {
        if (mock_maps[i].fd == fd && 
            memcmp(mock_maps[i].key, key, mock_maps[i].key_size) == 0) {
            memcpy(value, mock_maps[i].value, mock_maps[i].value_size);
            return 0;
        }
    }
    return -1; // Not found
}

int mock_bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags) {
    (void)flags;
    // Find existing entry or create new one
    for (size_t i = 0; i < mock_map_count; i++) {
        if (mock_maps[i].fd == fd && 
            memcmp(mock_maps[i].key, key, mock_maps[i].key_size) == 0) {
            // Update existing
            memcpy(mock_maps[i].value, value, mock_maps[i].value_size);
            return 0;
        }
    }
    
    // Create new entry if space available
    if (mock_map_count < MAX_MOCK_MAPS) {
        mock_maps[mock_map_count].fd = fd;
        memcpy(mock_maps[mock_map_count].key, key, sizeof(mock_maps[mock_map_count].key));
        memcpy(mock_maps[mock_map_count].value, value, sizeof(mock_maps[mock_map_count].value));
        mock_maps[mock_map_count].key_size = 32; // Default key size
        mock_maps[mock_map_count].value_size = 64; // Default value size
        mock_map_count++;
        return 0;
    }
    
    return -1; // No space
}

int mock_bpf_map_delete_elem(int fd, const void *key) {
    for (size_t i = 0; i < mock_map_count; i++) {
        if (mock_maps[i].fd == fd && 
            memcmp(mock_maps[i].key, key, mock_maps[i].key_size) == 0) {
            // Remove by shifting remaining entries
            memmove(&mock_maps[i], &mock_maps[i + 1], 
                   (mock_map_count - i - 1) * sizeof(struct mock_map_entry));
            mock_map_count--;
            return 0;
        }
    }
    return -1; // Not found
}

void mock_maps_reset(void) {
    memset(mock_maps, 0, sizeof(mock_maps));
    mock_map_count = 0;
}

// Mock network operations
static struct mock_network_state network_state = {0};

int mock_socket(int domain, int type, int protocol) {
    (void)domain;
    (void)type;
    (void)protocol;
    return network_state.next_socket_fd++;
}

int mock_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd;
    (void)addr;
    (void)addrlen;
    if (network_state.bind_should_fail) {
        return -1;
    }
    return 0;
}

ssize_t mock_sendto(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen) {
    (void)sockfd;
    (void)buf;
    (void)flags;
    (void)dest_addr;
    (void)addrlen;
    if (network_state.sendto_should_fail) {
        return -1;
    }

    network_state.bytes_sent += len;
    network_state.packets_sent++;

    return (ssize_t)len;
}

ssize_t mock_recvfrom(int sockfd, void *buf, size_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen) {
    (void)sockfd;
    (void)flags;
    (void)src_addr;
    (void)addrlen;
    if (network_state.recvfrom_should_fail) {
        return -1;
    }

    // Return mock data if available
    if (network_state.mock_recv_data_size > 0) {
        size_t copy_size = len < network_state.mock_recv_data_size ?
                          len : network_state.mock_recv_data_size;
        memcpy(buf, network_state.mock_recv_data, copy_size);
        network_state.mock_recv_data_size = 0; // Consume the data
        return (ssize_t)copy_size;
    }

    return 0; // No data available
}

void mock_network_reset(void) {
    memset(&network_state, 0, sizeof(network_state));
    network_state.next_socket_fd = 100; // Start from 100 to avoid conflicts
}

void mock_network_set_recv_data(const void *data, size_t size) {
    if (size <= sizeof(network_state.mock_recv_data)) {
        memcpy(network_state.mock_recv_data, data, size);
        network_state.mock_recv_data_size = size;
    }
}

struct mock_network_stats mock_network_get_stats(void) {
    struct mock_network_stats stats = {
        .packets_sent = network_state.packets_sent,
        .bytes_sent = network_state.bytes_sent,
        .packets_received = network_state.packets_received,
        .bytes_received = network_state.bytes_received
    };
    return stats;
}

// Mock time operations
static uint64_t mock_time_offset = 0;

uint64_t mock_get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec + mock_time_offset;
}

void mock_time_advance(uint64_t ns) {
    mock_time_offset += ns;
}

void mock_time_reset(void) {
    mock_time_offset = 0;
}