/**
 * Mock helpers header for C unit tests
 */

#ifndef MOCK_HELPERS_H
#define MOCK_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>

#define MAX_MOCK_MAPS 100
#define MAX_MOCK_DATA_SIZE 256

/**
 * Mock eBPF map entry
 */
struct mock_map_entry {
    int fd;
    uint8_t key[32];
    uint8_t value[64];
    size_t key_size;
    size_t value_size;
};

/**
 * Mock network state
 */
struct mock_network_state {
    int next_socket_fd;
    bool bind_should_fail;
    bool sendto_should_fail;
    bool recvfrom_should_fail;
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t packets_received;
    uint64_t bytes_received;
    uint8_t mock_recv_data[MAX_MOCK_DATA_SIZE];
    size_t mock_recv_data_size;
};

/**
 * Mock network statistics
 */
struct mock_network_stats {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t packets_received;
    uint64_t bytes_received;
};

/**
 * Mock eBPF map operations
 */
int mock_bpf_map_lookup_elem(int fd, const void *key, void *value);
int mock_bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags);
int mock_bpf_map_delete_elem(int fd, const void *key);
void mock_maps_reset(void);

/**
 * Mock network operations
 */
int mock_socket(int domain, int type, int protocol);
int mock_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t mock_sendto(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t mock_recvfrom(int sockfd, void *buf, size_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen);

void mock_network_reset(void);
void mock_network_set_recv_data(const void *data, size_t size);
struct mock_network_stats mock_network_get_stats(void);

/**
 * Mock time operations
 */
uint64_t mock_get_time_ns(void);
void mock_time_advance(uint64_t ns);
void mock_time_reset(void);

#endif // MOCK_HELPERS_H