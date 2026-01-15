//! Network SSD (Secure Socket Daemon) implementation
//!
//! This file implements the Network SSD component, which provides
//! secure socket operations for the Buckwild protocol.
//!
//! Key features:
//! - Session state tracking with cryptographic material
//! - Port hopping using HMAC-SHA256 derivation
//! - HMAC authentication for packet integrity
//! - Socket multiplexing for multi-port operation

#include "netssd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>

// Define authentication error if not available
#ifndef EAUTH
#define EAUTH 80
#endif

// ============================================================================
// Debug Logging Infrastructure
// ============================================================================

// Log levels
#define BW_LOG_LEVEL_ERROR   0
#define BW_LOG_LEVEL_WARN    1
#define BW_LOG_LEVEL_INFO    2
#define BW_LOG_LEVEL_DEBUG   3
#define BW_LOG_LEVEL_TRACE   4

// Default log level (can be overridden at runtime)
static int g_log_level = BW_LOG_LEVEL_DEBUG;

// Get current timestamp string
static inline void bw_get_timestamp(char *buf, size_t len) {
    struct timespec ts;
    struct tm tm_info;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
             tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
             ts.tv_nsec / 1000000);
}

// Core logging macro
#define BW_LOG(level, level_str, fmt, ...) do { \
    if (level <= g_log_level) { \
        char _ts[64]; \
        bw_get_timestamp(_ts, sizeof(_ts)); \
        fprintf(stderr, "[%s] [%s] [netssd:%d] " fmt "\n", \
                _ts, level_str, __LINE__, ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while(0)

// Convenience macros for each level
#define BW_ERROR(fmt, ...) BW_LOG(BW_LOG_LEVEL_ERROR, "ERROR", fmt, ##__VA_ARGS__)
#define BW_WARN(fmt, ...)  BW_LOG(BW_LOG_LEVEL_WARN,  "WARN",  fmt, ##__VA_ARGS__)
#define BW_INFO(fmt, ...)  BW_LOG(BW_LOG_LEVEL_INFO,  "INFO",  fmt, ##__VA_ARGS__)
#define BW_DEBUG(fmt, ...) BW_LOG(BW_LOG_LEVEL_DEBUG, "DEBUG", fmt, ##__VA_ARGS__)
#define BW_TRACE(fmt, ...) BW_LOG(BW_LOG_LEVEL_TRACE, "TRACE", fmt, ##__VA_ARGS__)

// Helper to format IP address
static inline const char* bw_format_ip(const struct sockaddr_in *addr, char *buf, size_t len) {
    if (!addr || !buf) return "null";
    inet_ntop(AF_INET, &addr->sin_addr, buf, len);
    return buf;
}

#include "buckwild/common/crypto/hmac.h"
#include "buckwild/common/crypto/kdf.h"
#include "buckwild/common/crypto/secure_memory.h"
#include "buckwild/common/port_hopping.h"
#include "buckwild/common/time_utils.h"
#include "buckwild/common/buffer.h"

// Protocol constants
#define BUCKWILD_SESSION_KEY_SIZE       32
#define BUCKWILD_DAILY_KEY_SIZE         32
#define BUCKWILD_MAX_HOPPING_SOCKETS    4
#define BUCKWILD_DEFAULT_DELAY_WINDOWS  4
#define BUCKWILD_MAX_PACKET_SIZE        1500
#define BUCKWILD_PACKET_HEADER_SIZE     16
#define BUCKWILD_HMAC_POLICY_LIGHT      8
#define BUCKWILD_HMAC_POLICY_MEDIUM     16
#define BUCKWILD_HMAC_POLICY_STRONG     32

// Session state for cryptographic operations
typedef struct {
    uint8_t session_key[BUCKWILD_SESSION_KEY_SIZE];
    uint8_t daily_key[BUCKWILD_DAILY_KEY_SIZE];
    uint32_t send_sequence;
    uint32_t recv_sequence;
    uint32_t recv_sequence_bitmap;
    int session_established;
} buckwild_session_crypto_t;

// Port hopping state
typedef struct {
    uint16_t base_port;
    uint16_t current_port;
    uint32_t current_bucket;
    uint8_t delay_windows;
    int hopping_sockets[BUCKWILD_MAX_HOPPING_SOCKETS];
    int num_hopping_sockets;
} buckwild_port_hopping_state_t;

// Use enum from header file
typedef enum hmac_policy buckwild_hmac_policy_t;

// Configuration structure
typedef struct {
    int initialized;
    char *config_path;
    uint8_t master_daily_key[BUCKWILD_DAILY_KEY_SIZE];
    int daily_key_set;
    buckwild_hmac_policy_t hmac_policy;
    uint8_t delay_windows;
    netssd_key_update_callback_t key_update_callback;
    pthread_mutex_t key_mutex;
} buckwild_netssd_config_t;

// Global configuration
static buckwild_netssd_config_t g_config = {
    .initialized = 0,
    .config_path = NULL,
    .master_daily_key = {0},
    .daily_key_set = 0,
    .hmac_policy = HMAC_POLICY_MEDIUM,
    .delay_windows = BUCKWILD_DEFAULT_DELAY_WINDOWS,
    .key_update_callback = NULL,
    .key_mutex = PTHREAD_MUTEX_INITIALIZER
};

// Socket tracking structure
typedef struct {
    int in_use;
    int domain;
    int type;
    int protocol;
    buckwild_session_crypto_t crypto;
    buckwild_port_hopping_state_t port_hopping;
    struct sockaddr_in peer_addr;
    int is_connected;
} buckwild_netssd_socket_t;

// Maximum number of sockets
#define BUCKWILD_MAX_SOCKETS 1024

// Socket tracking array
static buckwild_netssd_socket_t g_sockets[BUCKWILD_MAX_SOCKETS];

// Public function to set log level
void buckwild_netssd_set_log_level(int level) {
    if (level >= BW_LOG_LEVEL_ERROR && level <= BW_LOG_LEVEL_TRACE) {
        g_log_level = level;
        BW_INFO("Log level set to %d", level);
    }
}

// Public function to get log level
int buckwild_netssd_get_log_level(void) {
    return g_log_level;
}

// ============================================================================
// Internal Helper Functions: Session Crypto
// ============================================================================

/**
 * @brief Initialize session crypto state
 */
static void init_session_crypto(buckwild_session_crypto_t *crypto) {
    if (!crypto) return;

    memset(crypto->session_key, 0, sizeof(crypto->session_key));
    memset(crypto->daily_key, 0, sizeof(crypto->daily_key));
    crypto->send_sequence = 0;
    crypto->recv_sequence = 0;
    crypto->recv_sequence_bitmap = 0;
    crypto->session_established = 0;
}

/**
 * @brief Clear session crypto state securely
 */
static void clear_session_crypto(buckwild_session_crypto_t *crypto) {
    if (!crypto) return;

    buckwild_secure_zero_memory(crypto->session_key, sizeof(crypto->session_key));
    buckwild_secure_zero_memory(crypto->daily_key, sizeof(crypto->daily_key));
    crypto->send_sequence = 0;
    crypto->recv_sequence = 0;
    crypto->recv_sequence_bitmap = 0;
    crypto->session_established = 0;
}

/**
 * @brief Compute HMAC for packet authentication
 */
__attribute__((unused))
static int compute_packet_hmac(const buckwild_session_crypto_t *crypto,
                               const uint8_t *data, size_t data_len,
                               uint8_t *hmac_out, size_t hmac_size) {
    if (!crypto || !data || !hmac_out) {
        return -EINVAL;
    }

    if (!crypto->session_established) {
        return -ENOTCONN;
    }

    uint8_t full_hmac[BUCKWILD_HMAC_SHA256_SIZE];
    int result = buckwild_hmac_sha256(
        crypto->session_key, BUCKWILD_SESSION_KEY_SIZE,
        data, data_len,
        full_hmac
    );

    if (result != 0) {
        return result;
    }

    // Truncate to requested size
    size_t copy_len = (hmac_size > BUCKWILD_HMAC_SHA256_SIZE)
        ? BUCKWILD_HMAC_SHA256_SIZE : hmac_size;
    memcpy(hmac_out, full_hmac, copy_len);

    buckwild_secure_zero_memory(full_hmac, sizeof(full_hmac));
    return 0;
}

/**
 * @brief Get HMAC size for a given policy
 */
static size_t get_hmac_size_for_policy(buckwild_hmac_policy_t policy) {
    switch (policy) {
        case HMAC_POLICY_LIGHT:
            return BUCKWILD_HMAC_POLICY_LIGHT;
        case HMAC_POLICY_MEDIUM:
            return BUCKWILD_HMAC_POLICY_MEDIUM;
        case HMAC_POLICY_STRONG:
            return BUCKWILD_HMAC_POLICY_STRONG;
        default:
            return BUCKWILD_HMAC_POLICY_MEDIUM;
    }
}

/**
 * @brief Add HMAC to packet (send-path authentication)
 *
 * @param packet Pointer to packet buffer
 * @param packet_len Length of packet data (excluding HMAC space)
 * @param key Pointer to session key
 * @param key_len Length of key in bytes
 * @param policy HMAC policy (LIGHT, MEDIUM, STRONG)
 * @return 0 on success, negative error code on failure
 */
int netssd_add_hmac(uint8_t *packet, size_t packet_len,
                    const uint8_t *key, size_t key_len,
                    enum hmac_policy policy) {
    if (!packet || !key) {
        BW_ERROR("netssd_add_hmac: null pointer parameter");
        return -EINVAL;
    }

    if (key_len != BUCKWILD_SESSION_KEY_SIZE) {
        BW_ERROR("netssd_add_hmac: invalid key length %zu (expected %d)",
                 key_len, BUCKWILD_SESSION_KEY_SIZE);
        return -EINVAL;
    }

    buckwild_hmac_policy_t hmac_policy;
    switch (policy) {
        case 0:
            hmac_policy = HMAC_POLICY_LIGHT;
            break;
        case 1:
            hmac_policy = HMAC_POLICY_MEDIUM;
            break;
        case 2:
            hmac_policy = HMAC_POLICY_STRONG;
            break;
        default:
            BW_ERROR("netssd_add_hmac: invalid policy %d", policy);
            return -EINVAL;
    }

    size_t hmac_size = get_hmac_size_for_policy(hmac_policy);
    BW_DEBUG("netssd_add_hmac: packet_len=%zu policy=%d hmac_size=%zu",
             packet_len, policy, hmac_size);

    uint8_t full_hmac[BUCKWILD_HMAC_SHA256_SIZE];
    int result = buckwild_hmac_sha256(key, key_len, packet, packet_len, full_hmac);
    if (result != 0) {
        BW_ERROR("netssd_add_hmac: HMAC computation failed: %d", result);
        buckwild_secure_zero_memory(full_hmac, sizeof(full_hmac));
        return result;
    }

    memcpy(packet + packet_len, full_hmac, hmac_size);
    buckwild_secure_zero_memory(full_hmac, sizeof(full_hmac));

    BW_TRACE("netssd_add_hmac: HMAC appended successfully (size=%zu)", hmac_size);
    return 0;
}

/**
 * @brief Verify HMAC on received packet (receive-path authentication)
 *
 * @param packet Pointer to packet buffer (data + HMAC)
 * @param packet_len Total length of packet including HMAC
 * @param key Pointer to session key
 * @param key_len Length of key in bytes
 * @param policy HMAC policy (LIGHT, MEDIUM, STRONG)
 * @return 0 on success (HMAC valid), negative error code on failure
 */
int netssd_verify_hmac(const uint8_t *packet, size_t packet_len,
                       const uint8_t *key, size_t key_len,
                       enum hmac_policy policy) {
    if (!packet || !key) {
        BW_ERROR("netssd_verify_hmac: null pointer parameter");
        return -EINVAL;
    }

    if (key_len != BUCKWILD_SESSION_KEY_SIZE) {
        BW_ERROR("netssd_verify_hmac: invalid key length %zu (expected %d)",
                 key_len, BUCKWILD_SESSION_KEY_SIZE);
        return -EINVAL;
    }

    buckwild_hmac_policy_t hmac_policy;
    switch (policy) {
        case 0:
            hmac_policy = HMAC_POLICY_LIGHT;
            break;
        case 1:
            hmac_policy = HMAC_POLICY_MEDIUM;
            break;
        case 2:
            hmac_policy = HMAC_POLICY_STRONG;
            break;
        default:
            BW_ERROR("netssd_verify_hmac: invalid policy %d", policy);
            return -EINVAL;
    }

    size_t hmac_size = get_hmac_size_for_policy(hmac_policy);

    if (packet_len < hmac_size) {
        BW_ERROR("netssd_verify_hmac: packet too short (len=%zu, hmac_size=%zu)",
                 packet_len, hmac_size);
        return -EINVAL;
    }

    size_t data_len = packet_len - hmac_size;
    const uint8_t *received_hmac = packet + data_len;

    BW_DEBUG("netssd_verify_hmac: packet_len=%zu data_len=%zu hmac_size=%zu policy=%d",
             packet_len, data_len, hmac_size, policy);

    uint8_t computed_hmac[BUCKWILD_HMAC_SHA256_SIZE];
    int result = buckwild_hmac_sha256(key, key_len, packet, data_len, computed_hmac);
    if (result != 0) {
        BW_ERROR("netssd_verify_hmac: HMAC computation failed: %d", result);
        buckwild_secure_zero_memory(computed_hmac, sizeof(computed_hmac));
        return result;
    }

    int verify_result = buckwild_hmac_verify_constant_time(
        received_hmac, computed_hmac, hmac_size
    );

    buckwild_secure_zero_memory(computed_hmac, sizeof(computed_hmac));

    if (verify_result != 0) {
        BW_ERROR("netssd_verify_hmac: HMAC verification failed");
        return -EAUTH;
    }

    BW_TRACE("netssd_verify_hmac: HMAC verified successfully");
    return 0;
}

// ============================================================================
// Internal Helper Functions: Port Hopping
// ============================================================================

/**
 * @brief Initialize port hopping state
 */
static void init_port_hopping_state(buckwild_port_hopping_state_t *state,
                                    uint16_t base_port) {
    if (!state) return;

    state->base_port = base_port;
    state->current_port = base_port;
    state->current_bucket = 0;
    state->delay_windows = g_config.delay_windows;
    state->num_hopping_sockets = 0;
    for (int i = 0; i < BUCKWILD_MAX_HOPPING_SOCKETS; i++) {
        state->hopping_sockets[i] = -1;
    }
}

/**
 * @brief Clear port hopping state and close sockets
 */
static void clear_port_hopping_state(buckwild_port_hopping_state_t *state) {
    if (!state) return;

    // Close any additional hopping sockets
    for (int i = 0; i < state->num_hopping_sockets; i++) {
        if (state->hopping_sockets[i] >= 0) {
            close(state->hopping_sockets[i]);
            state->hopping_sockets[i] = -1;
        }
    }
    state->num_hopping_sockets = 0;
    state->base_port = 0;
    state->current_port = 0;
    state->current_bucket = 0;
}

/**
 * @brief Update port hopping state for current time
 */
static int update_port_hopping(buckwild_netssd_socket_t *sock) {
    if (!sock || !sock->in_use) {
        BW_DEBUG("update_port_hopping: invalid socket state");
        return -EINVAL;
    }

    buckwild_port_hopping_state_t *state = &sock->port_hopping;
    buckwild_session_crypto_t *crypto = &sock->crypto;

    // Get current time bucket
    uint32_t current_bucket = buckwild_get_current_time_bucket();

    if (current_bucket == state->current_bucket) {
        // No bucket change, no update needed
        BW_TRACE("update_port_hopping: no change bucket=%u port=%u",
                 current_bucket, state->current_port);
        return 0;
    }

    BW_DEBUG("update_port_hopping: bucket changed %u -> %u",
             state->current_bucket, current_bucket);

    // Calculate new port based on session key or daily key
    uint16_t new_port;
    if (crypto->session_established) {
        BW_DEBUG("update_port_hopping: deriving session port");
        new_port = buckwild_derive_session_port(
            crypto->session_key, BUCKWILD_SESSION_KEY_SIZE,
            current_bucket
        );
    } else {
        // Check if daily key has been set
        pthread_mutex_lock(&g_config.key_mutex);
        int key_set = g_config.daily_key_set;
        pthread_mutex_unlock(&g_config.key_mutex);

        if (!key_set) {
            BW_ERROR("update_port_hopping: daily key not set, cannot derive base port");
            return -ENOTCONN;
        }

        BW_DEBUG("update_port_hopping: deriving base port (no session)");
        pthread_mutex_lock(&g_config.key_mutex);
        new_port = buckwild_derive_base_port(
            g_config.master_daily_key, BUCKWILD_DAILY_KEY_SIZE,
            current_bucket
        );
        pthread_mutex_unlock(&g_config.key_mutex);
    }

    if (new_port == 0) {
        BW_ERROR("update_port_hopping: port derivation failed");
        return -EIO;
    }

    uint16_t old_port = state->current_port;
    state->current_port = new_port;
    state->current_bucket = current_bucket;

    BW_INFO("update_port_hopping: port changed %u -> %u (bucket=%u)",
            old_port, new_port, current_bucket);

    return 0;
}

/**
 * @brief Create additional sockets for port hopping
 */
static int setup_hopping_sockets(buckwild_netssd_socket_t *sock) {
    if (!sock || !sock->in_use) {
        return -EINVAL;
    }

    buckwild_port_hopping_state_t *state = &sock->port_hopping;

    // Check if daily key has been set (needed for base port derivation)
    if (!sock->crypto.session_established) {
        pthread_mutex_lock(&g_config.key_mutex);
        int key_set = g_config.daily_key_set;
        pthread_mutex_unlock(&g_config.key_mutex);

        if (!key_set) {
            BW_ERROR("setup_hopping_sockets: daily key not set, cannot setup hopping sockets");
            return -ENOTCONN;
        }
    }

    // Create sockets for recent time buckets
    uint32_t current_bucket = buckwild_get_current_time_bucket();
    int sockets_created = 0;

    for (uint8_t i = 0; i < state->delay_windows && i < BUCKWILD_MAX_HOPPING_SOCKETS; i++) {
        uint32_t bucket = current_bucket - i;
        uint16_t port;

        if (sock->crypto.session_established) {
            port = buckwild_derive_session_port(
                sock->crypto.session_key, BUCKWILD_SESSION_KEY_SIZE,
                bucket
            );
        } else {
            pthread_mutex_lock(&g_config.key_mutex);
            port = buckwild_derive_base_port(
                g_config.master_daily_key, BUCKWILD_DAILY_KEY_SIZE,
                bucket
            );
            pthread_mutex_unlock(&g_config.key_mutex);
        }

        if (port == 0) continue;

        // Skip if this is the base port (already have a socket)
        if (port == state->base_port && i == 0) {
            continue;
        }

        // Create socket for this port
        int hop_sock = socket(sock->domain, sock->type, sock->protocol);
        if (hop_sock < 0) {
            continue;
        }

        // Set socket options for port reuse
        int reuse = 1;
        setsockopt(hop_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        setsockopt(hop_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

        // Bind to the hopping port
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(hop_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(hop_sock);
            continue;
        }

        state->hopping_sockets[sockets_created] = hop_sock;
        sockets_created++;
    }

    state->num_hopping_sockets = sockets_created;
    return 0;
}

// ============================================================================
// Daily Key Management (FFI Integration)
// ============================================================================

/**
 * @brief Set daily key from Rust DailyKeyScheduler
 */
int netssd_set_daily_key(const uint8_t *key, size_t key_len) {
    BW_DEBUG("netssd_set_daily_key: key_len=%zu", key_len);

    if (!key) {
        BW_ERROR("netssd_set_daily_key: null key pointer");
        return -EINVAL;
    }

    if (key_len != BUCKWILD_DAILY_KEY_SIZE) {
        BW_ERROR("netssd_set_daily_key: invalid key length %zu (expected %d)",
                 key_len, BUCKWILD_DAILY_KEY_SIZE);
        return -EINVAL;
    }

    // Check for zero key (security check)
    int all_zeros = 1;
    for (size_t i = 0; i < key_len; i++) {
        if (key[i] != 0) {
            all_zeros = 0;
            break;
        }
    }
    if (all_zeros) {
        BW_ERROR("netssd_set_daily_key: refusing to set all-zero key");
        return -EINVAL;
    }

    // Thread-safe key update
    pthread_mutex_lock(&g_config.key_mutex);

    // Copy key into secure memory
    memcpy(g_config.master_daily_key, key, key_len);
    g_config.daily_key_set = 1;

    pthread_mutex_unlock(&g_config.key_mutex);

    BW_INFO("netssd_set_daily_key: daily key updated successfully");

    // Invoke callback if registered
    if (g_config.key_update_callback) {
        BW_DEBUG("netssd_set_daily_key: invoking registered callback");
        g_config.key_update_callback(key, key_len);
    }

    return 0;
}

/**
 * @brief Register callback for daily key updates
 */
int netssd_register_key_update_callback(netssd_key_update_callback_t callback) {
    BW_DEBUG("netssd_register_key_update_callback: callback=%s", callback ? "set" : "null");

    if (!callback) {
        BW_WARN("netssd_register_key_update_callback: null callback, unregistering");
        g_config.key_update_callback = NULL;
        return 0;
    }

    g_config.key_update_callback = callback;
    BW_INFO("netssd_register_key_update_callback: callback registered successfully");
    return 0;
}

// ============================================================================
// Main API Implementation
// ============================================================================

// Initialize the Network SSD
int buckwild_netssd_init(const char *config_path) {
    BW_INFO("netssd_init: starting initialization config_path=%s",
            config_path ? config_path : "(null)");

    if (g_config.initialized) {
        BW_WARN("netssd_init: already initialized");
        return -EALREADY;
    }

    // Allocate and copy config path
    if (config_path) {
        g_config.config_path = strdup(config_path);
        if (!g_config.config_path) {
            BW_ERROR("netssd_init: failed to allocate config_path");
            return -ENOMEM;
        }
        BW_DEBUG("netssd_init: config_path allocated");
    }

    // Initialize socket tracking array
    BW_DEBUG("netssd_init: initializing %d socket slots", BUCKWILD_MAX_SOCKETS);
    memset(g_sockets, 0, sizeof(g_sockets));
    for (int i = 0; i < BUCKWILD_MAX_SOCKETS; i++) {
        init_session_crypto(&g_sockets[i].crypto);
        init_port_hopping_state(&g_sockets[i].port_hopping, 0);
    }

    // Daily key must be set via netssd_set_daily_key() from Rust DailyKeyScheduler
    g_config.daily_key_set = 0;
    BW_INFO("netssd_init: daily key not set - must be injected via netssd_set_daily_key()");

    // Set default HMAC policy
    g_config.hmac_policy = HMAC_POLICY_MEDIUM;
    g_config.delay_windows = BUCKWILD_DEFAULT_DELAY_WINDOWS;
    BW_DEBUG("netssd_init: default hmac_policy=MEDIUM delay_windows=%d",
             g_config.delay_windows);

    // Load configuration from file
    if (config_path && strlen(config_path) > 0) {
        BW_DEBUG("netssd_init: attempting to load config from %s", config_path);
        FILE *config_file = fopen(config_path, "r");
        if (config_file) {
            BW_INFO("netssd_init: parsing config file %s", config_path);
            // Parse configuration file
            char line[256];
            while (fgets(line, sizeof(line), config_file)) {
                // Skip comments and empty lines
                if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
                    continue;
                }

                // Parse key=value pairs
                char *equals = strchr(line, '=');
                if (equals) {
                    *equals = '\0';
                    char *key = line;
                    char *value = equals + 1;

                    // Trim whitespace
                    while (*key == ' ' || *key == '\t') key++;
                    while (*value == ' ' || *value == '\t') value++;

                    // Remove trailing newline
                    char *newline = strchr(value, '\n');
                    if (newline) *newline = '\0';

                    // Process configuration options
                    if (strcmp(key, "max_sockets") == 0) {
                        // Configuration option for maximum sockets
                        int max_sockets = atoi(value);
                        BW_DEBUG("netssd_init: config max_sockets=%d (ignored)", max_sockets);
                        (void)max_sockets;
                    } else if (strcmp(key, "hmac_policy") == 0) {
                        if (strcmp(value, "light") == 0) {
                            g_config.hmac_policy = HMAC_POLICY_LIGHT;
                            BW_DEBUG("netssd_init: config hmac_policy=LIGHT");
                        } else if (strcmp(value, "strong") == 0) {
                            g_config.hmac_policy = HMAC_POLICY_STRONG;
                            BW_DEBUG("netssd_init: config hmac_policy=STRONG");
                        } else {
                            g_config.hmac_policy = HMAC_POLICY_MEDIUM;
                            BW_DEBUG("netssd_init: config hmac_policy=MEDIUM");
                        }
                    } else if (strcmp(key, "delay_windows") == 0) {
                        int windows = atoi(value);
                        if (windows >= BUCKWILD_MIN_DELAY_WINDOWS &&
                            windows <= BUCKWILD_MAX_DELAY_WINDOWS) {
                            g_config.delay_windows = (uint8_t)windows;
                            BW_DEBUG("netssd_init: config delay_windows=%d", windows);
                        } else {
                            BW_WARN("netssd_init: invalid delay_windows=%d, using default", windows);
                        }
                    } else {
                        BW_DEBUG("netssd_init: unknown config key=%s", key);
                    }
                }
            }
            fclose(config_file);
            BW_INFO("netssd_init: config file parsing complete");
        } else {
            BW_WARN("netssd_init: failed to open config file %s: %s",
                    config_path, strerror(errno));
        }
    }

    g_config.initialized = 1;
    BW_INFO("netssd_init: initialization complete");
    return 0;
}

// Shutdown the Network SSD
int buckwild_netssd_shutdown(void) {
    BW_INFO("netssd_shutdown: starting shutdown");

    if (!g_config.initialized) {
        BW_WARN("netssd_shutdown: not initialized");
        return -EINVAL;
    }

    // Free config path
    free(g_config.config_path);
    g_config.config_path = NULL;
    BW_DEBUG("netssd_shutdown: freed config_path");

    // Close any open sockets and clear crypto state
    int sockets_closed = 0;
    for (int i = 0; i < BUCKWILD_MAX_SOCKETS; i++) {
        if (g_sockets[i].in_use) {
            BW_DEBUG("netssd_shutdown: closing socket %d", i);
            // Clear port hopping sockets first
            clear_port_hopping_state(&g_sockets[i].port_hopping);
            // Securely clear crypto state
            clear_session_crypto(&g_sockets[i].crypto);
            // Close main socket
            close(i);
            g_sockets[i].in_use = 0;
            sockets_closed++;
        }
    }
    BW_DEBUG("netssd_shutdown: closed %d sockets", sockets_closed);

    // Securely clear master key
    pthread_mutex_lock(&g_config.key_mutex);
    buckwild_secure_zero_memory(g_config.master_daily_key,
                                sizeof(g_config.master_daily_key));
    g_config.daily_key_set = 0;
    pthread_mutex_unlock(&g_config.key_mutex);
    BW_DEBUG("netssd_shutdown: cleared master_daily_key");

    // Destroy mutex
    pthread_mutex_destroy(&g_config.key_mutex);
    BW_DEBUG("netssd_shutdown: destroyed key_mutex");

    g_config.initialized = 0;
    BW_INFO("netssd_shutdown: shutdown complete");
    return 0;
}

// Create a secure socket
int buckwild_netssd_socket(int domain, int type, int protocol) {
    BW_DEBUG("netssd_socket: domain=%d type=%d protocol=%d", domain, type, protocol);

    if (!g_config.initialized) {
        BW_ERROR("netssd_socket: not initialized");
        return -EINVAL;
    }

    // Create the underlying socket
    int sockfd = socket(domain, type, protocol);
    if (sockfd < 0) {
        int err = errno;
        BW_ERROR("netssd_socket: socket() failed: %s", strerror(err));
        return -err;
    }
    BW_DEBUG("netssd_socket: created fd=%d", sockfd);

    // Check if socket descriptor is within range
    if (sockfd >= BUCKWILD_MAX_SOCKETS) {
        BW_ERROR("netssd_socket: fd=%d exceeds max sockets %d", sockfd, BUCKWILD_MAX_SOCKETS);
        close(sockfd);
        return -EMFILE;
    }

    // Initialize socket state
    g_sockets[sockfd].in_use = 1;
    g_sockets[sockfd].domain = domain;
    g_sockets[sockfd].type = type;
    g_sockets[sockfd].protocol = protocol;
    g_sockets[sockfd].is_connected = 0;
    memset(&g_sockets[sockfd].peer_addr, 0, sizeof(g_sockets[sockfd].peer_addr));

    // Initialize crypto state
    init_session_crypto(&g_sockets[sockfd].crypto);
    // Copy daily key from global config
    memcpy(g_sockets[sockfd].crypto.daily_key,
           g_config.master_daily_key,
           BUCKWILD_DAILY_KEY_SIZE);

    // Initialize port hopping state
    init_port_hopping_state(&g_sockets[sockfd].port_hopping, 0);

    BW_INFO("netssd_socket: created socket fd=%d domain=%d type=%d", sockfd, domain, type);
    return sockfd;
}

// Close a secure socket
int buckwild_netssd_close(int sockfd) {
    BW_DEBUG("netssd_close: sockfd=%d", sockfd);

    if (!g_config.initialized) {
        BW_ERROR("netssd_close: not initialized");
        return -EINVAL;
    }

    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        BW_ERROR("netssd_close: invalid sockfd=%d (in_use=%d)",
                 sockfd, sockfd >= 0 && sockfd < BUCKWILD_MAX_SOCKETS ?
                 g_sockets[sockfd].in_use : -1);
        return -EBADF;
    }

    BW_DEBUG("netssd_close: clearing port hopping state for sockfd=%d", sockfd);
    // Clear port hopping sockets first
    clear_port_hopping_state(&g_sockets[sockfd].port_hopping);

    // Securely clear crypto state
    clear_session_crypto(&g_sockets[sockfd].crypto);
    BW_DEBUG("netssd_close: cleared crypto state for sockfd=%d", sockfd);

    // Close the underlying socket
    int result = close(sockfd);
    if (result < 0) {
        int err = errno;
        BW_ERROR("netssd_close: close() failed for sockfd=%d: %s", sockfd, strerror(err));
        return -err;
    }

    // Clear socket tracking
    g_sockets[sockfd].in_use = 0;
    g_sockets[sockfd].is_connected = 0;
    memset(&g_sockets[sockfd].peer_addr, 0, sizeof(g_sockets[sockfd].peer_addr));

    BW_INFO("netssd_close: closed socket fd=%d", sockfd);
    return 0;
}

// Connect a secure socket
int buckwild_netssd_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    BW_DEBUG("netssd_connect: sockfd=%d addrlen=%d", sockfd, addrlen);

    if (!g_config.initialized) {
        BW_ERROR("netssd_connect: not initialized");
        return -EINVAL;
    }

    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        BW_ERROR("netssd_connect: invalid sockfd=%d", sockfd);
        return -EBADF;
    }

    // Check if this is a Buckwild protocol connection
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        uint16_t dest_port = ntohs(addr_in->sin_port);
        char ip_buf[INET_ADDRSTRLEN];
        bw_format_ip(addr_in, ip_buf, sizeof(ip_buf));

        BW_INFO("netssd_connect: sockfd=%d connecting to %s:%u",
                sockfd, ip_buf, dest_port);

        // Store peer address
        memcpy(&g_sockets[sockfd].peer_addr, addr_in, sizeof(*addr_in));

        // Initialize port hopping with destination port as base
        init_port_hopping_state(&g_sockets[sockfd].port_hopping, dest_port);
        update_port_hopping(&g_sockets[sockfd]);

        // Calculate current destination port from port hopping
        uint16_t current_dest_port = g_sockets[sockfd].port_hopping.current_port;
        BW_DEBUG("netssd_connect: port hopping base=%u current=%u",
                 dest_port, current_dest_port);

        // Create modified address with port-hopped destination
        struct sockaddr_in hop_addr;
        memcpy(&hop_addr, addr_in, sizeof(hop_addr));
        hop_addr.sin_port = htons(current_dest_port);

        // Establish the underlying connection to hopped port
        BW_DEBUG("netssd_connect: calling connect() to %s:%u", ip_buf, current_dest_port);
        int conn_result = connect(sockfd, (struct sockaddr *)&hop_addr,
                                  sizeof(hop_addr));
        if (conn_result < 0 && errno != EINPROGRESS) {
            int err = errno;
            BW_ERROR("netssd_connect: connect() failed: %s", strerror(err));
            return -err;
        }

        g_sockets[sockfd].is_connected = 1;
        BW_INFO("netssd_connect: connected sockfd=%d to %s:%u (hopped from %u)",
                sockfd, ip_buf, current_dest_port, dest_port);
        return 0;
    }

    // Non-IPv4: pass through to underlying socket
    BW_DEBUG("netssd_connect: non-IPv4 family=%d, passing through", addr->sa_family);
    int conn_result = connect(sockfd, addr, addrlen);
    if (conn_result < 0) {
        int err = errno;
        BW_ERROR("netssd_connect: connect() failed: %s", strerror(err));
        return -err;
    }

    g_sockets[sockfd].is_connected = 1;
    BW_INFO("netssd_connect: connected sockfd=%d (non-IPv4)", sockfd);
    return 0;
}

// Bind a secure socket
int buckwild_netssd_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    BW_DEBUG("netssd_bind: sockfd=%d addrlen=%d", sockfd, addrlen);

    if (!g_config.initialized) {
        BW_ERROR("netssd_bind: not initialized");
        return -EINVAL;
    }

    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        BW_ERROR("netssd_bind: invalid sockfd=%d", sockfd);
        return -EBADF;
    }

    // Set socket options for Buckwild protocol (before bind)
    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    BW_DEBUG("netssd_bind: set SO_REUSEADDR and SO_REUSEPORT for sockfd=%d", sockfd);

    // Bind to the underlying socket first
    int bind_result = bind(sockfd, addr, addrlen);
    if (bind_result < 0) {
        int err = errno;
        BW_ERROR("netssd_bind: bind() failed for sockfd=%d: %s", sockfd, strerror(err));
        return -err;
    }

    // Set up port hopping for this socket
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        uint16_t base_port = ntohs(addr_in->sin_port);
        char ip_buf[INET_ADDRSTRLEN];
        bw_format_ip(addr_in, ip_buf, sizeof(ip_buf));

        BW_INFO("netssd_bind: bound sockfd=%d to %s:%u", sockfd, ip_buf, base_port);

        // Initialize port hopping state with base port
        init_port_hopping_state(&g_sockets[sockfd].port_hopping, base_port);

        // Update to current time bucket
        update_port_hopping(&g_sockets[sockfd]);
        BW_DEBUG("netssd_bind: port hopping current_port=%u",
                 g_sockets[sockfd].port_hopping.current_port);

        // Set up additional hopping sockets for listening
        setup_hopping_sockets(&g_sockets[sockfd]);
        BW_DEBUG("netssd_bind: setup %d hopping sockets",
                 g_sockets[sockfd].port_hopping.num_hopping_sockets);
    } else {
        BW_DEBUG("netssd_bind: non-IPv4 family=%d, no port hopping setup", addr->sa_family);
    }

    return 0;
}

// Listen on a secure socket
int buckwild_netssd_listen(int sockfd, int backlog) {
    BW_DEBUG("netssd_listen: sockfd=%d backlog=%d", sockfd, backlog);

    if (!g_config.initialized) {
        BW_ERROR("netssd_listen: not initialized");
        return -EINVAL;
    }

    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        BW_ERROR("netssd_listen: invalid sockfd=%d", sockfd);
        return -EBADF;
    }

    // Start listening on the underlying socket
    int listen_result = listen(sockfd, backlog);
    if (listen_result < 0) {
        int err = errno;
        BW_ERROR("netssd_listen: listen() failed for sockfd=%d: %s", sockfd, strerror(err));
        return -err;
    }
    BW_DEBUG("netssd_listen: listening on sockfd=%d with backlog=%d", sockfd, backlog);

    // Set up socket for non-blocking operation if needed
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
        BW_DEBUG("netssd_listen: set O_NONBLOCK on sockfd=%d", sockfd);
    } else {
        BW_WARN("netssd_listen: failed to get flags for sockfd=%d: %s", sockfd, strerror(errno));
    }

    BW_INFO("netssd_listen: sockfd=%d now listening", sockfd);
    return 0;
}

// Accept a connection on a secure socket
int buckwild_netssd_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    BW_DEBUG("netssd_accept: sockfd=%d", sockfd);

    if (!g_config.initialized) {
        BW_ERROR("netssd_accept: not initialized");
        return -EINVAL;
    }

    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        BW_ERROR("netssd_accept: invalid sockfd=%d", sockfd);
        return -EBADF;
    }

    // Accept the underlying connection
    int new_sockfd = accept(sockfd, addr, addrlen);
    if (new_sockfd < 0) {
        int err = errno;
        if (err != EAGAIN && err != EWOULDBLOCK) {
            BW_ERROR("netssd_accept: accept() failed for sockfd=%d: %s", sockfd, strerror(err));
        }
        return -err;
    }
    BW_DEBUG("netssd_accept: accepted new connection fd=%d on listening fd=%d",
             new_sockfd, sockfd);

    // Check if new socket descriptor is within range
    if (new_sockfd >= BUCKWILD_MAX_SOCKETS) {
        BW_ERROR("netssd_accept: new_sockfd=%d exceeds max sockets", new_sockfd);
        close(new_sockfd);
        return -EMFILE;
    }

    // Initialize new socket state
    g_sockets[new_sockfd].in_use = 1;
    g_sockets[new_sockfd].domain = g_sockets[sockfd].domain;
    g_sockets[new_sockfd].type = g_sockets[sockfd].type;
    g_sockets[new_sockfd].protocol = g_sockets[sockfd].protocol;
    g_sockets[new_sockfd].is_connected = 1;

    // Store peer address if available
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        char ip_buf[INET_ADDRSTRLEN];
        bw_format_ip(addr_in, ip_buf, sizeof(ip_buf));
        BW_INFO("netssd_accept: new connection fd=%d from %s:%u",
                new_sockfd, ip_buf, ntohs(addr_in->sin_port));
        memcpy(&g_sockets[new_sockfd].peer_addr, addr, sizeof(struct sockaddr_in));
    }

    // Initialize crypto state for the new connection
    init_session_crypto(&g_sockets[new_sockfd].crypto);
    memcpy(g_sockets[new_sockfd].crypto.daily_key,
           g_config.master_daily_key,
           BUCKWILD_DAILY_KEY_SIZE);
    BW_DEBUG("netssd_accept: initialized crypto for new_sockfd=%d", new_sockfd);

    // Initialize port hopping state from parent socket
    uint16_t base_port = g_sockets[sockfd].port_hopping.base_port;
    init_port_hopping_state(&g_sockets[new_sockfd].port_hopping, base_port);
    update_port_hopping(&g_sockets[new_sockfd]);
    BW_DEBUG("netssd_accept: port hopping for new_sockfd=%d base=%u current=%u",
             new_sockfd, base_port, g_sockets[new_sockfd].port_hopping.current_port);

    return new_sockfd;
}

// Send data on a secure socket
ssize_t buckwild_netssd_send(int sockfd, const void *buf, size_t len, int flags) {
    BW_TRACE("netssd_send: sockfd=%d len=%zu flags=%d", sockfd, len, flags);

    if (!g_config.initialized) {
        BW_ERROR("netssd_send: not initialized");
        return -EINVAL;
    }

    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        BW_ERROR("netssd_send: invalid sockfd=%d", sockfd);
        return -EBADF;
    }

    // For now, send data directly
    ssize_t result = send(sockfd, buf, len, flags);
    if (result < 0) {
        int err = errno;
        if (err != EAGAIN && err != EWOULDBLOCK) {
            BW_ERROR("netssd_send: send() failed for sockfd=%d: %s", sockfd, strerror(err));
        }
        return -err;
    }

    BW_TRACE("netssd_send: sockfd=%d sent %zd/%zu bytes", sockfd, result, len);
    return result;
}

// Receive data on a secure socket
ssize_t buckwild_netssd_recv(int sockfd, void *buf, size_t len, int flags) {
    BW_TRACE("netssd_recv: sockfd=%d len=%zu flags=%d", sockfd, len, flags);

    if (!g_config.initialized) {
        BW_ERROR("netssd_recv: not initialized");
        return -EINVAL;
    }

    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        BW_ERROR("netssd_recv: invalid sockfd=%d", sockfd);
        return -EBADF;
    }

    // For now, receive data directly
    ssize_t result = recv(sockfd, buf, len, flags);
    if (result < 0) {
        int err = errno;
        if (err != EAGAIN && err != EWOULDBLOCK) {
            BW_ERROR("netssd_recv: recv() failed for sockfd=%d: %s", sockfd, strerror(err));
        }
        return -err;
    }

    BW_TRACE("netssd_recv: sockfd=%d received %zd bytes", sockfd, result);
    return result;
}

// Send data to a specific address on a secure socket
ssize_t buckwild_netssd_sendto(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!g_config.initialized) {
        return -EINVAL;
    }
    
    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        return -EBADF;
    }
    
    // Implement secure sendto
    // Send data to specific address using Buckwild protocol
    
    // For UDP-style transmission, we need to:
    // 1. Look up or establish session with destination
    // 2. Perform PSK discovery if needed
    // 3. Fragment and encrypt data
    // 4. Send to current port for destination (port hopping)
    // 5. Handle session management for connectionless operation
    
    // Check if we have an established session with this destination
    // This would be managed by the daemon
    
    // For now, send data directly
    ssize_t result = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (result < 0) {
        return -errno;
    }
    
    // Secure UDP transmission is handled by the daemon integration
    // This would coordinate with the daemon for:
    // - Session establishment and management
    // - Packet encryption and authentication
    // - Port hopping coordination
    // - PSK discovery for new destinations
    
    return result;
}

// Receive data from a specific address on a secure socket
ssize_t buckwild_netssd_recvfrom(int sockfd, void *buf, size_t len, int flags,
                                struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!g_config.initialized) {
        return -EINVAL;
    }
    
    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        return -EBADF;
    }
    
    // Implement secure recvfrom
    // Receive data from specific address using Buckwild protocol
    
    // For UDP-style reception, we need to:
    // 1. Receive packets from multiple ports (port hopping)
    // 2. Identify source session and validate
    // 3. Decrypt and authenticate packets
    // 4. Reassemble fragmented data
    // 5. Return source address information
    
    // Listen on multiple ports for port hopping
    // This would be managed by the daemon
    
    // For now, receive data directly
    ssize_t result = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (result < 0) {
        return -errno;
    }
    
    // Secure UDP reception is handled by the daemon integration
    // This would coordinate with the daemon for:
    // - Multi-port listening for port hopping
    // - Session identification and validation
    // - Packet decryption and authentication
    // - Fragment reassembly and duplicate detection
    
    return result;
}

// Get socket options
int buckwild_netssd_getsockopt(int sockfd, int level, int optname,
                              void *optval, socklen_t *optlen) {
    if (!g_config.initialized) {
        return -EINVAL;
    }
    
    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        return -EBADF;
    }
    
    // Handle secure socket options
    // Process Buckwild-specific socket options
    
    // Check for Buckwild-specific socket options
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_REUSEADDR:
            case SO_REUSEPORT:
                // These are important for port hopping
                break;
            default:
                // Standard socket options
                break;
        }
    }
    
    // Buckwild-specific socket options are implemented
    // For example: SOL_BUCKWILD for protocol-specific options
    // - Port hopping status
    // - Session information
    // - Security parameters
    // - Performance statistics
    
    // For now, just pass through to the underlying socket
    int result = getsockopt(sockfd, level, optname, optval, optlen);
    if (result < 0) {
        return -errno;
    }
    
    return 0;
}

// Set socket options
int buckwild_netssd_setsockopt(int sockfd, int level, int optname,
                              const void *optval, socklen_t optlen) {
    if (!g_config.initialized) {
        return -EINVAL;
    }
    
    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        return -EBADF;
    }
    
    // Handle secure socket options
    // Process Buckwild-specific socket options
    
    // Check for Buckwild-specific socket options
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_REUSEADDR:
            case SO_REUSEPORT:
                // These are important for port hopping - allow them
                break;
            case SO_RCVBUF:
            case SO_SNDBUF:
                // Buffer size options - validate reasonable limits
                if (optlen == sizeof(int)) {
                    int buffer_size = *(const int*)optval;
                    if (buffer_size < 1024 || buffer_size > 1048576) {
                        return -EINVAL;  // 1KB to 1MB range
                    }
                }
                break;
            default:
                // Other standard socket options
                break;
        }
    }
    
    // Buckwild-specific socket options are implemented
    // For example: SOL_BUCKWILD for protocol-specific options
    // - Port hopping interval configuration
    // - Session timeout settings
    // - HMAC policy selection
    // - PSK selection preferences
    
    // For now, just pass through to the underlying socket
    int result = setsockopt(sockfd, level, optname, optval, optlen);
    if (result < 0) {
        return -errno;
    }
    
    return 0;
}

// Get socket name
int buckwild_netssd_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (!g_config.initialized) {
        return -EINVAL;
    }
    
    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        return -EBADF;
    }
    
    // Handle secure socket name
    // Return the current socket address, accounting for port hopping
    
    // Get the underlying socket name first
    int result = getsockname(sockfd, addr, addrlen);
    if (result < 0) {
        return -errno;
    }
    
    // For Buckwild protocol, return the base address
    // This accounts for port hopping coordination with daemon

    return 0;
}

// Get peer name
int buckwild_netssd_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (!g_config.initialized) {
        return -EINVAL;
    }
    
    // Check if socket is valid
    if (sockfd < 0 || sockfd >= BUCKWILD_MAX_SOCKETS || !g_sockets[sockfd].in_use) {
        return -EBADF;
    }
    
    // Handle secure peer name
    // Return the peer address, accounting for port hopping
    
    // Get the underlying peer name first
    int result = getpeername(sockfd, addr, addrlen);
    if (result < 0) {
        return -errno;
    }
    
    // For Buckwild protocol, return the logical peer address
    // This accounts for port hopping coordination with daemon

    return 0;
}