//! Network SSD (Secure Socket Daemon) header
//!
//! This file defines the interface for the Network SSD component,
//! which provides secure socket operations for the Buckwild protocol.

#ifndef BUCKWILD_NETSSD_H
#define BUCKWILD_NETSSD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * @brief Initialize the Network SSD
 * 
 * @param config_path Path to the configuration file
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_init(const char *config_path);

/**
 * @brief Shutdown the Network SSD
 * 
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_shutdown(void);

/**
 * @brief Create a secure socket
 * 
 * @param domain Socket domain (AF_INET, AF_INET6)
 * @param type Socket type (SOCK_STREAM, SOCK_DGRAM)
 * @param protocol Socket protocol
 * @return Socket file descriptor on success, negative error code on failure
 */
int buckwild_netssd_socket(int domain, int type, int protocol);

/**
 * @brief Close a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_close(int sockfd);

/**
 * @brief Connect a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @param addr Socket address
 * @param addrlen Address length
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

/**
 * @brief Bind a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @param addr Socket address
 * @param addrlen Address length
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

/**
 * @brief Listen on a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @param backlog Maximum length of the queue of pending connections
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_listen(int sockfd, int backlog);

/**
 * @brief Accept a connection on a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @param addr Socket address
 * @param addrlen Address length
 * @return New socket file descriptor on success, negative error code on failure
 */
int buckwild_netssd_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/**
 * @brief Send data on a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @param buf Data buffer
 * @param len Buffer length
 * @param flags Send flags
 * @return Number of bytes sent on success, negative error code on failure
 */
ssize_t buckwild_netssd_send(int sockfd, const void *buf, size_t len, int flags);

/**
 * @brief Receive data on a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @param buf Data buffer
 * @param len Buffer length
 * @param flags Receive flags
 * @return Number of bytes received on success, negative error code on failure
 */
ssize_t buckwild_netssd_recv(int sockfd, void *buf, size_t len, int flags);

/**
 * @brief Send data to a specific address on a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @param buf Data buffer
 * @param len Buffer length
 * @param flags Send flags
 * @param dest_addr Destination address
 * @param addrlen Address length
 * @return Number of bytes sent on success, negative error code on failure
 */
ssize_t buckwild_netssd_sendto(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen);

/**
 * @brief Receive data from a specific address on a secure socket
 * 
 * @param sockfd Socket file descriptor
 * @param buf Data buffer
 * @param len Buffer length
 * @param flags Receive flags
 * @param src_addr Source address
 * @param addrlen Address length
 * @return Number of bytes received on success, negative error code on failure
 */
ssize_t buckwild_netssd_recvfrom(int sockfd, void *buf, size_t len, int flags,
                                struct sockaddr *src_addr, socklen_t *addrlen);

/**
 * @brief Get socket options
 * 
 * @param sockfd Socket file descriptor
 * @param level Option level
 * @param optname Option name
 * @param optval Option value
 * @param optlen Option length
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_getsockopt(int sockfd, int level, int optname,
                              void *optval, socklen_t *optlen);

/**
 * @brief Set socket options
 * 
 * @param sockfd Socket file descriptor
 * @param level Option level
 * @param optname Option name
 * @param optval Option value
 * @param optlen Option length
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_setsockopt(int sockfd, int level, int optname,
                              const void *optval, socklen_t optlen);

/**
 * @brief Get socket name
 * 
 * @param sockfd Socket file descriptor
 * @param addr Socket address
 * @param addrlen Address length
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/**
 * @brief Get peer name
 *
 * @param sockfd Socket file descriptor
 * @param addr Socket address
 * @param addrlen Address length
 * @return 0 on success, negative error code on failure
 */
int buckwild_netssd_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/**
 * @brief HMAC policy enumeration
 */
enum hmac_policy {
    HMAC_POLICY_LIGHT = 0,   // 64-bit HMAC (8 bytes)
    HMAC_POLICY_MEDIUM = 1,  // 128-bit HMAC (16 bytes)
    HMAC_POLICY_STRONG = 2   // 256-bit HMAC (32 bytes)
};

/**
 * @brief Add HMAC to packet (send-path authentication)
 *
 * Computes HMAC-SHA256 over packet data and appends the HMAC tag
 * according to the specified policy. The packet buffer must have
 * sufficient space for the HMAC tag (8/16/32 bytes).
 *
 * @param packet Pointer to packet buffer (must have space for HMAC)
 * @param packet_len Length of packet data (excluding HMAC space)
 * @param key Pointer to session key (must be 32 bytes)
 * @param key_len Length of key in bytes
 * @param policy HMAC policy (LIGHT=0, MEDIUM=1, STRONG=2)
 * @return 0 on success, negative error code on failure
 */
int netssd_add_hmac(uint8_t *packet, size_t packet_len,
                    const uint8_t *key, size_t key_len,
                    enum hmac_policy policy);

/**
 * @brief Verify HMAC on received packet (receive-path authentication)
 *
 * Computes HMAC-SHA256 over packet data and verifies it matches the
 * received HMAC tag using constant-time comparison. The packet_len
 * must include both data and HMAC tag.
 *
 * @param packet Pointer to packet buffer (data + HMAC)
 * @param packet_len Total length of packet including HMAC
 * @param key Pointer to session key (must be 32 bytes)
 * @param key_len Length of key in bytes
 * @param policy HMAC policy (LIGHT=0, MEDIUM=1, STRONG=2)
 * @return 0 on success (HMAC valid), negative error code on failure
 */
int netssd_verify_hmac(const uint8_t *packet, size_t packet_len,
                       const uint8_t *key, size_t key_len,
                       enum hmac_policy policy);

/**
 * @brief Set daily key for port hopping
 *
 * Securely injects the daily key from Rust DailyKeyScheduler.
 * The key is copied into secure memory and used for base port derivation.
 *
 * @param key Pointer to daily key (must be 32 bytes)
 * @param key_len Length of key in bytes (must be 32)
 * @return 0 on success, negative error code on failure
 */
int netssd_set_daily_key(const uint8_t *key, size_t key_len);

/**
 * @brief Update daily key callback mechanism
 *
 * Register a callback function to be invoked when daily key changes.
 * This enables automatic key rotation from Rust to C.
 *
 * @param callback Function pointer to key update callback
 * @return 0 on success, negative error code on failure
 */
typedef void (*netssd_key_update_callback_t)(const uint8_t *key, size_t key_len);
int netssd_register_key_update_callback(netssd_key_update_callback_t callback);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_NETSSD_H */
