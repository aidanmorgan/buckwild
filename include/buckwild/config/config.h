/**
 * @file config.h
 * @brief Configuration management API for Buckwild protocol
 *
 * This header provides C API functions for managing Buckwild protocol configuration,
 * including PSK management, host configuration, and daemon settings.
 */

#ifndef BUCKWILD_CONFIG_H
#define BUCKWILD_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes for configuration operations
 */
typedef enum {
    BUCKWILD_CONFIG_SUCCESS = 0,
    BUCKWILD_CONFIG_ERROR_INVALID_ARGUMENT = -1,
    BUCKWILD_CONFIG_ERROR_FILE_NOT_FOUND = -2,
    BUCKWILD_CONFIG_ERROR_PARSE_FAILED = -3,
    BUCKWILD_CONFIG_ERROR_VALIDATION_FAILED = -4,
    BUCKWILD_CONFIG_ERROR_MEMORY_ALLOCATION = -5,
    BUCKWILD_CONFIG_ERROR_PERMISSION_DENIED = -6,
    BUCKWILD_CONFIG_ERROR_ALREADY_EXISTS = -7,
    BUCKWILD_CONFIG_ERROR_NOT_FOUND = -8,
    BUCKWILD_CONFIG_ERROR_INTERNAL = -9,
} buckwild_config_error_t;

/**
 * @brief HMAC policy types
 */
typedef enum {
    BUCKWILD_HMAC_POLICY_LIGHT = 0,  /**< 64-bit HMAC */
    BUCKWILD_HMAC_POLICY_MEDIUM = 1, /**< 128-bit HMAC */
    BUCKWILD_HMAC_POLICY_STRONG = 2, /**< 256-bit HMAC */
} buckwild_hmac_policy_t;

/**
 * @brief Opaque handle to configuration context
 */
typedef struct buckwild_config_context* buckwild_config_context_t;

/**
 * @brief Opaque handle to PSK context
 */
typedef struct buckwild_psk_context* buckwild_psk_context_t;

/**
 * @brief Host configuration structure
 */
typedef struct {
    char ip[64];                 /**< IP address (IPv4 or IPv6) */
    char psk_fingerprint[65];    /**< PSK fingerprint (64 hex chars + null) */
    char description[256];       /**< Optional description */
    char port_range[32];         /**< Optional port range */
    buckwild_hmac_policy_t hmac_policy; /**< HMAC policy */
    uint32_t priority;           /**< Priority (lower is higher) */
} buckwild_host_config_t;

/**
 * @brief Network settings structure
 */
typedef struct {
    char tun_device[32];         /**< TUN device name */
    int ipv6_enabled;            /**< Whether IPv6 is enabled */
    char port_range[32];         /**< Base port range */
    uint32_t max_connections;    /**< Maximum number of connections */
    uint32_t connection_timeout; /**< Connection timeout in seconds */
    uint32_t port_hop_interval;  /**< Port hopping interval in milliseconds */
    uint16_t mtu;                /**< Maximum transmission unit */
    int tcp_compatibility;       /**< Whether TCP compatibility is enabled */
} buckwild_network_settings_t;

/**
 * @brief Security settings structure
 */
typedef struct {
    buckwild_hmac_policy_t default_hmac_policy; /**< Default HMAC policy */
    int lock_memory;             /**< Whether to lock memory */
    uint32_t key_rotation;       /**< Key rotation interval in minutes */
    uint32_t max_psk_size;       /**< Maximum PSK size in bytes */
    int replay_protection;       /**< Whether replay protection is enabled */
    uint32_t replay_window;      /**< Replay protection window in seconds */
} buckwild_security_settings_t;

/**
 * @brief Create a new configuration context
 *
 * @param[out] context Pointer to store the created context
 * @return Error code
 */
buckwild_config_error_t buckwild_config_create(buckwild_config_context_t* context);

/**
 * @brief Destroy a configuration context
 *
 * @param context Configuration context
 * @return Error code
 */
buckwild_config_error_t buckwild_config_destroy(buckwild_config_context_t context);

/**
 * @brief Load configuration from a file
 *
 * @param context Configuration context
 * @param path Path to configuration file
 * @return Error code
 */
buckwild_config_error_t buckwild_config_load(buckwild_config_context_t context, const char* path);

/**
 * @brief Save configuration to a file
 *
 * @param context Configuration context
 * @param path Path to configuration file
 * @return Error code
 */
buckwild_config_error_t buckwild_config_save(buckwild_config_context_t context, const char* path);

/**
 * @brief Get network settings
 *
 * @param context Configuration context
 * @param[out] settings Pointer to store network settings
 * @return Error code
 */
buckwild_config_error_t buckwild_config_get_network_settings(
    buckwild_config_context_t context,
    buckwild_network_settings_t* settings
);

/**
 * @brief Set network settings
 *
 * @param context Configuration context
 * @param settings Network settings
 * @return Error code
 */
buckwild_config_error_t buckwild_config_set_network_settings(
    buckwild_config_context_t context,
    const buckwild_network_settings_t* settings
);

/**
 * @brief Get security settings
 *
 * @param context Configuration context
 * @param[out] settings Pointer to store security settings
 * @return Error code
 */
buckwild_config_error_t buckwild_config_get_security_settings(
    buckwild_config_context_t context,
    buckwild_security_settings_t* settings
);

/**
 * @brief Set security settings
 *
 * @param context Configuration context
 * @param settings Security settings
 * @return Error code
 */
buckwild_config_error_t buckwild_config_set_security_settings(
    buckwild_config_context_t context,
    const buckwild_security_settings_t* settings
);

/**
 * @brief Create a new PSK context
 *
 * @param[out] context Pointer to store the created context
 * @return Error code
 */
buckwild_config_error_t buckwild_psk_create(buckwild_psk_context_t* context);

/**
 * @brief Destroy a PSK context
 *
 * @param context PSK context
 * @return Error code
 */
buckwild_config_error_t buckwild_psk_destroy(buckwild_psk_context_t context);

/**
 * @brief Set PSK directory
 *
 * @param context PSK context
 * @param directory Path to PSK directory
 * @return Error code
 */
buckwild_config_error_t buckwild_psk_set_directory(
    buckwild_psk_context_t context,
    const char* directory
);

/**
 * @brief Add a PSK file
 *
 * @param context PSK context
 * @param path Path to PSK file
 * @param[out] fingerprint Buffer to store fingerprint (must be at least 65 bytes)
 * @param fingerprint_size Size of fingerprint buffer
 * @return Error code
 */
buckwild_config_error_t buckwild_psk_add_file(
    buckwild_psk_context_t context,
    const char* path,
    char* fingerprint,
    size_t fingerprint_size
);

/**
 * @brief Remove a PSK by fingerprint
 *
 * @param context PSK context
 * @param fingerprint PSK fingerprint
 * @return Error code
 */
buckwild_config_error_t buckwild_psk_remove(
    buckwild_psk_context_t context,
    const char* fingerprint
);

/**
 * @brief Get the number of loaded PSKs
 *
 * @param context PSK context
 * @param[out] count Pointer to store the count
 * @return Error code
 */
buckwild_config_error_t buckwild_psk_get_count(
    buckwild_psk_context_t context,
    size_t* count
);

/**
 * @brief Get all PSK fingerprints
 *
 * @param context PSK context
 * @param[out] fingerprints Array to store fingerprints (each must be at least 65 bytes)
 * @param max_fingerprints Maximum number of fingerprints to retrieve
 * @param[out] count Pointer to store the actual number of fingerprints retrieved
 * @return Error code
 */
buckwild_config_error_t buckwild_psk_get_all_fingerprints(
    buckwild_psk_context_t context,
    char** fingerprints,
    size_t max_fingerprints,
    size_t* count
);

/**
 * @brief Load hosts configuration from a file
 *
 * @param context Configuration context
 * @param path Path to hosts configuration file
 * @return Error code
 */
buckwild_config_error_t buckwild_hosts_load(
    buckwild_config_context_t context,
    const char* path
);

/**
 * @brief Save hosts configuration to a file
 *
 * @param context Configuration context
 * @param path Path to hosts configuration file
 * @return Error code
 */
buckwild_config_error_t buckwild_hosts_save(
    buckwild_config_context_t context,
    const char* path
);

/**
 * @brief Add a host to the configuration
 *
 * @param context Configuration context
 * @param host Host configuration
 * @return Error code
 */
buckwild_config_error_t buckwild_hosts_add(
    buckwild_config_context_t context,
    const buckwild_host_config_t* host
);

/**
 * @brief Remove a host from the configuration
 *
 * @param context Configuration context
 * @param ip Host IP address
 * @return Error code
 */
buckwild_config_error_t buckwild_hosts_remove(
    buckwild_config_context_t context,
    const char* ip
);

/**
 * @brief Get a host configuration by IP address
 *
 * @param context Configuration context
 * @param ip Host IP address
 * @param[out] host Pointer to store host configuration
 * @return Error code
 */
buckwild_config_error_t buckwild_hosts_get(
    buckwild_config_context_t context,
    const char* ip,
    buckwild_host_config_t* host
);

/**
 * @brief Get the number of hosts in the configuration
 *
 * @param context Configuration context
 * @param[out] count Pointer to store the count
 * @return Error code
 */
buckwild_config_error_t buckwild_hosts_get_count(
    buckwild_config_context_t context,
    size_t* count
);

/**
 * @brief Get all hosts in the configuration
 *
 * @param context Configuration context
 * @param[out] hosts Array to store host configurations
 * @param max_hosts Maximum number of hosts to retrieve
 * @param[out] count Pointer to store the actual number of hosts retrieved
 * @return Error code
 */
buckwild_config_error_t buckwild_hosts_get_all(
    buckwild_config_context_t context,
    buckwild_host_config_t* hosts,
    size_t max_hosts,
    size_t* count
);

/**
 * @brief Update routing table based on hosts configuration
 *
 * @param context Configuration context
 * @return Error code
 */
buckwild_config_error_t buckwild_hosts_update_routing(
    buckwild_config_context_t context
);

/**
 * @brief Get the last error message
 *
 * @param context Configuration context
 * @param[out] buffer Buffer to store error message
 * @param buffer_size Size of buffer
 * @return Error code
 */
buckwild_config_error_t buckwild_config_get_last_error(
    buckwild_config_context_t context,
    char* buffer,
    size_t buffer_size
);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_CONFIG_H */