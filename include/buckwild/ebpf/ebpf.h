#ifndef BUCKWILD_EBPF_H
#define BUCKWILD_EBPF_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct buckwild_ebpf_manager buckwild_ebpf_manager_t;
typedef struct buckwild_xdp_loader buckwild_xdp_loader_t;
typedef struct buckwild_tc_loader buckwild_tc_loader_t;

// Error codes
#define BUCKWILD_EBPF_SUCCESS           0
#define BUCKWILD_EBPF_ERROR_INVALID     -1
#define BUCKWILD_EBPF_ERROR_NOT_FOUND   -2
#define BUCKWILD_EBPF_ERROR_PERMISSION  -3
#define BUCKWILD_EBPF_ERROR_RESOURCE    -4
#define BUCKWILD_EBPF_ERROR_SECURITY    -5
#define BUCKWILD_EBPF_ERROR_VALIDATION  -6

// XDP attachment modes
typedef enum {
    BUCKWILD_XDP_MODE_GENERIC = 0,
    BUCKWILD_XDP_MODE_NATIVE = 1,
    BUCKWILD_XDP_MODE_OFFLOAD = 2
} buckwild_xdp_mode_t;

// Security configuration
typedef struct {
    bool enable_security_features;
    bool enable_fragment_security;
    bool enable_attack_detection;
    bool enable_rate_limiting;
    uint32_t rate_limit_pps;
    uint32_t rate_limit_bps;
    uint32_t fragment_timeout_ms;
    uint32_t attack_threshold;
    uint8_t security_level;
} buckwild_security_config_t;

// XDP configuration
typedef struct {
    const char *interface;
    buckwild_xdp_mode_t attach_mode;
    buckwild_security_config_t security;
    size_t ring_buffer_size;
} buckwild_xdp_config_t;

// TC configuration
typedef struct {
    const char *interface;
    bool enable_egress;
    bool enable_ingress;
    buckwild_security_config_t security;
    uint32_t rate_limit_bps;
    uint8_t priority_levels;
} buckwild_tc_config_t;

// Session information
typedef struct {
    uint64_t session_id;
    uint32_t last_sequence;
    uint32_t expected_port;
    uint64_t last_packet_time;
    uint32_t packet_count;
    uint8_t session_state;
    uint8_t hmac_policy;
    uint8_t session_id_length;
    uint8_t timestamp_length;
    uint32_t src_ip;
    uint16_t src_port;
    uint64_t creation_time;
    uint32_t security_violations;
    uint8_t attack_detected;
} buckwild_session_info_t;

// Security statistics
typedef struct {
    uint64_t total_packets;
    uint64_t dropped_packets;
    uint64_t security_events;
    uint64_t rate_limit_violations;
    uint64_t fragment_attacks;
    uint64_t replay_attacks;
    uint64_t enumeration_attempts;
    uint64_t timing_attacks;
    uint64_t blocked_sources;
    uint64_t last_update_time;
} buckwild_security_stats_t;

// Security event
typedef struct {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t session_id;
    uint8_t event_type;
    uint8_t severity;
    uint8_t action_taken;
    uint32_t additional_data;
} buckwild_security_event_t;

// Packet metadata
typedef struct {
    uint64_t session_id;
    uint32_t sequence_number;
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t packet_size;
    uint64_t timestamp;
    uint8_t packet_type;
    uint8_t hmac_policy;
    uint8_t security_flags;
    uint8_t validation_status;
    uint32_t src_ip;
    uint32_t dst_ip;
    buckwild_security_event_t sec_event;
} buckwild_packet_metadata_t;

// Event callback types
typedef void (*buckwild_packet_callback_t)(const buckwild_packet_metadata_t *packet, void *user_data);
typedef void (*buckwild_security_event_callback_t)(const buckwild_security_event_t *event, void *user_data);

/**
 * @brief Create a new eBPF manager instance
 * 
 * @return Pointer to eBPF manager or NULL on failure
 */
buckwild_ebpf_manager_t *buckwild_ebpf_manager_create(void);

/**
 * @brief Destroy eBPF manager and cleanup resources
 * 
 * @param manager eBPF manager instance
 */
void buckwild_ebpf_manager_destroy(buckwild_ebpf_manager_t *manager);

/**
 * @brief Create XDP program loader with security features
 * 
 * @param config XDP configuration
 * @return Pointer to XDP loader or NULL on failure
 */
buckwild_xdp_loader_t *buckwild_xdp_loader_create(const buckwild_xdp_config_t *config);

/**
 * @brief Destroy XDP loader and cleanup resources
 * 
 * @param loader XDP loader instance
 */
void buckwild_xdp_loader_destroy(buckwild_xdp_loader_t *loader);

/**
 * @brief Load and attach XDP program with security validation
 * 
 * @param loader XDP loader instance
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_load_and_attach(buckwild_xdp_loader_t *loader);

/**
 * @brief Detach XDP program with security cleanup
 * 
 * @param loader XDP loader instance
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_detach(buckwild_xdp_loader_t *loader);

/**
 * @brief Update session information in eBPF map with security validation
 * 
 * @param loader XDP loader instance
 * @param session_id Session identifier
 * @param info Session information
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_update_session(buckwild_xdp_loader_t *loader,
                                       uint64_t session_id,
                                       const buckwild_session_info_t *info);

/**
 * @brief Remove session with security cleanup
 * 
 * @param loader XDP loader instance
 * @param session_id Session identifier
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_remove_session(buckwild_xdp_loader_t *loader,
                                       uint64_t session_id);

/**
 * @brief Get session information with security context
 * 
 * @param loader XDP loader instance
 * @param session_id Session identifier
 * @param info Output buffer for session information
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_get_session(buckwild_xdp_loader_t *loader,
                                    uint64_t session_id,
                                    buckwild_session_info_t *info);

/**
 * @brief Get security statistics from eBPF
 * 
 * @param loader XDP loader instance
 * @param stats Output buffer for security statistics
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_get_security_stats(buckwild_xdp_loader_t *loader,
                                           buckwild_security_stats_t *stats);

/**
 * @brief Set packet processing callback
 * 
 * @param loader XDP loader instance
 * @param callback Packet callback function
 * @param user_data User data passed to callback
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_set_packet_callback(buckwild_xdp_loader_t *loader,
                                            buckwild_packet_callback_t callback,
                                            void *user_data);

/**
 * @brief Set security event callback
 * 
 * @param loader XDP loader instance
 * @param callback Security event callback function
 * @param user_data User data passed to callback
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_set_security_callback(buckwild_xdp_loader_t *loader,
                                              buckwild_security_event_callback_t callback,
                                              void *user_data);

/**
 * @brief Start packet processing loop
 * 
 * @param loader XDP loader instance
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_start_processing(buckwild_xdp_loader_t *loader);

/**
 * @brief Stop packet processing loop
 * 
 * @param loader XDP loader instance
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_xdp_loader_stop_processing(buckwild_xdp_loader_t *loader);

/**
 * @brief Check if XDP program is loaded
 * 
 * @param loader XDP loader instance
 * @return true if loaded, false otherwise
 */
bool buckwild_xdp_loader_is_loaded(const buckwild_xdp_loader_t *loader);

/**
 * @brief Check if security features are validated
 * 
 * @param loader XDP loader instance
 * @return true if validated, false otherwise
 */
bool buckwild_xdp_loader_is_security_validated(const buckwild_xdp_loader_t *loader);

/**
 * @brief Create TC program loader with security enforcement
 * 
 * @param config TC configuration
 * @return Pointer to TC loader or NULL on failure
 */
buckwild_tc_loader_t *buckwild_tc_loader_create(const buckwild_tc_config_t *config);

/**
 * @brief Destroy TC loader and cleanup resources
 * 
 * @param loader TC loader instance
 */
void buckwild_tc_loader_destroy(buckwild_tc_loader_t *loader);

/**
 * @brief Load and attach TC program with security enforcement
 * 
 * @param loader TC loader instance
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_tc_loader_load_and_attach(buckwild_tc_loader_t *loader);

/**
 * @brief Detach TC program with security cleanup
 * 
 * @param loader TC loader instance
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_tc_loader_detach(buckwild_tc_loader_t *loader);

/**
 * @brief Update traffic shaping configuration
 * 
 * @param loader TC loader instance
 * @param session_id Session identifier
 * @param rate_limit_bps Rate limit in bytes per second
 * @param priority Traffic priority (0-7)
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_tc_loader_update_traffic_shaping(buckwild_tc_loader_t *loader,
                                              uint64_t session_id,
                                              uint32_t rate_limit_bps,
                                              uint8_t priority);

/**
 * @brief Get traffic statistics
 * 
 * @param loader TC loader instance
 * @param session_id Session identifier
 * @param bytes_sent Output for bytes sent
 * @param packets_sent Output for packets sent
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_tc_loader_get_traffic_stats(buckwild_tc_loader_t *loader,
                                         uint64_t session_id,
                                         uint64_t *bytes_sent,
                                         uint64_t *packets_sent);

/**
 * @brief Validate eBPF program security features
 * 
 * @param program_path Path to eBPF program object file
 * @return BUCKWILD_EBPF_SUCCESS if valid, error code on failure
 */
int buckwild_ebpf_validate_security_features(const char *program_path);

/**
 * @brief Get eBPF program version information
 * 
 * @param major Output for major version
 * @param minor Output for minor version
 * @param patch Output for patch version
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_ebpf_get_version(uint32_t *major, uint32_t *minor, uint32_t *patch);

/**
 * @brief Check kernel compatibility for eBPF features
 * 
 * @return BUCKWILD_EBPF_SUCCESS if compatible, error code on failure
 */
int buckwild_ebpf_check_kernel_compatibility(void);

/**
 * @brief Initialize eBPF subsystem with security features
 * 
 * @return BUCKWILD_EBPF_SUCCESS on success, error code on failure
 */
int buckwild_ebpf_init(void);

/**
 * @brief Cleanup eBPF subsystem
 */
void buckwild_ebpf_cleanup(void);

/**
 * @brief Get last error message
 * 
 * @return Error message string
 */
const char *buckwild_ebpf_get_error_message(void);

#ifdef __cplusplus
}
#endif

#endif // BUCKWILD_EBPF_H