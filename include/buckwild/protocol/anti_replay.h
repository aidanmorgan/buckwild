/**
 * @file anti_replay.h
 * @brief Anti-replay protection API for the Buckwild protocol
 * 
 * This header provides C API functions for anti-replay protection including
 * timestamp validation, duplicate detection, enumeration attack detection,
 * and replay prevention with comprehensive security features.
 * 
 * All functions are thread-safe and use constant-time operations for
 * security-critical validations to prevent timing attacks.
 */

#ifndef BUCKWILD_ANTI_REPLAY_H
#define BUCKWILD_ANTI_REPLAY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle for timestamp validator
 */
typedef struct buckwild_timestamp_validator buckwild_timestamp_validator_t;

/**
 * @brief Opaque handle for duplicate detector
 */
typedef struct buckwild_duplicate_detector buckwild_duplicate_detector_t;

/**
 * @brief Opaque handle for enumeration detector
 */
typedef struct buckwild_enumeration_detector buckwild_enumeration_detector_t;

/**
 * @brief Opaque handle for replay prevention engine
 */
typedef struct buckwild_replay_engine buckwild_replay_engine_t;

/**
 * @brief Epoch types for timestamp validation
 */
typedef enum {
    BUCKWILD_EPOCH_DAILY = 0,   /**< Daily epoch for base port hopping */
    BUCKWILD_EPOCH_MONTHLY = 1  /**< Monthly epoch for session packets */
} buckwild_epoch_type_t;

/**
 * @brief Timestamp validation results
 */
typedef enum {
    BUCKWILD_TIMESTAMP_VALID = 0,           /**< Timestamp is valid */
    BUCKWILD_TIMESTAMP_TOO_OLD = 1,         /**< Timestamp is too old */
    BUCKWILD_TIMESTAMP_TOO_FUTURE = 2,      /**< Timestamp is too far in future */
    BUCKWILD_TIMESTAMP_DUPLICATE = 3,       /**< Timestamp is duplicate */
    BUCKWILD_TIMESTAMP_CLOCK_SKEW = 4,      /**< Clock skew exceeded */
    BUCKWILD_TIMESTAMP_INVALID_EPOCH = 5    /**< Invalid epoch format */
} buckwild_timestamp_result_t;

/**
 * @brief Duplicate detection results
 */
typedef enum {
    BUCKWILD_DUPLICATE_UNIQUE = 0,          /**< Packet is unique */
    BUCKWILD_DUPLICATE_FOUND = 1,           /**< Duplicate detected */
    BUCKWILD_DUPLICATE_REORDER = 2,         /**< Legitimate reorder */
    BUCKWILD_DUPLICATE_TOO_OLD = 3          /**< Sequence too old */
} buckwild_duplicate_result_t;

/**
 * @brief Enumeration detection results
 */
typedef enum {
    BUCKWILD_ENUM_ALLOWED = 0,              /**< Connection allowed */
    BUCKWILD_ENUM_RATE_LIMITED = 1,         /**< Rate limited */
    BUCKWILD_ENUM_BLOCKED = 2,              /**< Source blocked */
    BUCKWILD_ENUM_ATTACK_DETECTED = 3       /**< Attack pattern detected */
} buckwild_enumeration_result_t;

/**
 * @brief Replay prevention results
 */
typedef enum {
    BUCKWILD_REPLAY_ALLOWED = 0,            /**< Operation allowed */
    BUCKWILD_REPLAY_OUT_OF_ORDER = 1,       /**< Out of order but valid */
    BUCKWILD_REPLAY_DETECTED = 2,           /**< Replay detected */
    BUCKWILD_REPLAY_INVALID_NONCE = 3,      /**< Invalid nonce */
    BUCKWILD_REPLAY_EXPIRED = 4,            /**< Operation expired */
    BUCKWILD_REPLAY_TOO_OLD = 5             /**< Sequence too old */
} buckwild_replay_result_t;

/**
 * @brief IP address structure for C API
 */
typedef struct {
    uint8_t family;     /**< Address family (4 for IPv4, 6 for IPv6) */
    union {
        uint32_t ipv4;  /**< IPv4 address in network byte order */
        uint8_t ipv6[16]; /**< IPv6 address */
    } addr;
} buckwild_ip_addr_t;

/**
 * @brief Cache statistics structure
 */
typedef struct {
    size_t entry_count;         /**< Number of entries in cache */
    size_t memory_usage_bytes;  /**< Memory usage in bytes */
} buckwild_cache_stats_t;

/**
 * @brief Duplicate detection statistics
 */
typedef struct {
    uint64_t total_packets;         /**< Total packets processed */
    uint64_t duplicates_detected;   /**< Duplicates detected */
    uint64_t legitimate_reorders;   /**< Legitimate reorders */
    uint64_t cache_hits;           /**< Cache hits */
    uint64_t cache_misses;         /**< Cache misses */
    uint64_t cache_evictions;      /**< Cache evictions */
} buckwild_duplicate_stats_t;

/**
 * @brief Enumeration detection statistics
 */
typedef struct {
    uint64_t total_attempts;            /**< Total connection attempts */
    uint64_t rate_limited_attempts;     /**< Rate limited attempts */
    uint64_t blocked_sources;           /**< Currently blocked sources */
    uint64_t attack_patterns_detected;  /**< Attack patterns detected */
    uint64_t false_positives;           /**< False positives */
} buckwild_enumeration_stats_t;

/**
 * @brief Replay prevention statistics
 */
typedef struct {
    uint64_t total_packets;         /**< Total packets processed */
    uint64_t replay_attacks_detected; /**< Replay attacks detected */
    uint64_t out_of_order_packets;  /**< Out of order packets */
    uint64_t invalid_nonces;        /**< Invalid nonces */
    uint64_t expired_operations;    /**< Expired operations */
    uint64_t active_sessions;       /**< Active sessions */
    uint64_t active_nonces;         /**< Active nonces */
} buckwild_replay_stats_t;

/* ========================================================================
 * Timestamp Validator API
 * ======================================================================== */

/**
 * @brief Create a new timestamp validator
 * @return Pointer to validator instance, or NULL on failure
 */
buckwild_timestamp_validator_t* buckwild_timestamp_validator_new(void);

/**
 * @brief Destroy a timestamp validator
 * @param validator Validator instance to destroy
 */
void buckwild_timestamp_validator_free(buckwild_timestamp_validator_t* validator);

/**
 * @brief Validate a timestamp with dual-epoch support
 * @param validator Validator instance
 * @param timestamp Timestamp to validate (500ms buckets)
 * @param epoch_type Epoch type (daily or monthly)
 * @param session_id Session ID for validation
 * @param sequence_number Sequence number for validation
 * @return Validation result
 */
buckwild_timestamp_result_t buckwild_timestamp_validate(
    buckwild_timestamp_validator_t* validator,
    uint64_t timestamp,
    buckwild_epoch_type_t epoch_type,
    uint64_t session_id,
    uint32_t sequence_number
);

/**
 * @brief Validate clock skew between peers
 * @param validator Validator instance
 * @param peer_timestamp Peer's timestamp
 * @param local_timestamp Local timestamp
 * @return true if skew is acceptable, false otherwise
 */
bool buckwild_timestamp_validate_clock_skew(
    buckwild_timestamp_validator_t* validator,
    uint64_t peer_timestamp,
    uint64_t local_timestamp
);

/**
 * @brief Get cache statistics
 * @param validator Validator instance
 * @param stats Output statistics structure
 * @return 0 on success, negative on error
 */
int buckwild_timestamp_get_stats(
    buckwild_timestamp_validator_t* validator,
    buckwild_cache_stats_t* stats
);

/* ========================================================================
 * Duplicate Detector API
 * ======================================================================== */

/**
 * @brief Create a new duplicate detector
 * @param max_cache_size Maximum cache size
 * @return Pointer to detector instance, or NULL on failure
 */
buckwild_duplicate_detector_t* buckwild_duplicate_detector_new(size_t max_cache_size);

/**
 * @brief Destroy a duplicate detector
 * @param detector Detector instance to destroy
 */
void buckwild_duplicate_detector_free(buckwild_duplicate_detector_t* detector);

/**
 * @brief Detect if a packet is a duplicate
 * @param detector Detector instance
 * @param timestamp Packet timestamp
 * @param session_id Session ID
 * @param sequence_number Sequence number
 * @param source_ip Source IP address (optional, can be NULL)
 * @return Detection result
 */
buckwild_duplicate_result_t buckwild_duplicate_detect(
    buckwild_duplicate_detector_t* detector,
    uint64_t timestamp,
    uint64_t session_id,
    uint32_t sequence_number,
    const buckwild_ip_addr_t* source_ip
);

/**
 * @brief Validate sequence order
 * @param detector Detector instance
 * @param session_id Session ID
 * @param sequence_number Received sequence number
 * @param expected_sequence Expected sequence number
 * @return true if sequence is valid, false otherwise
 */
bool buckwild_duplicate_validate_sequence(
    buckwild_duplicate_detector_t* detector,
    uint64_t session_id,
    uint32_t sequence_number,
    uint32_t expected_sequence
);

/**
 * @brief Clean up expired entries
 * @param detector Detector instance
 * @param max_age_seconds Maximum age in seconds
 * @return Number of entries removed, or negative on error
 */
int buckwild_duplicate_cleanup(
    buckwild_duplicate_detector_t* detector,
    uint64_t max_age_seconds
);

/**
 * @brief Get duplicate detection statistics
 * @param detector Detector instance
 * @param stats Output statistics structure
 * @return 0 on success, negative on error
 */
int buckwild_duplicate_get_stats(
    buckwild_duplicate_detector_t* detector,
    buckwild_duplicate_stats_t* stats
);

/* ========================================================================
 * Enumeration Detector API
 * ======================================================================== */

/**
 * @brief Create a new enumeration detector
 * @return Pointer to detector instance, or NULL on failure
 */
buckwild_enumeration_detector_t* buckwild_enumeration_detector_new(void);

/**
 * @brief Destroy an enumeration detector
 * @param detector Detector instance to destroy
 */
void buckwild_enumeration_detector_free(buckwild_enumeration_detector_t* detector);

/**
 * @brief Check if a connection attempt should be allowed
 * @param detector Detector instance
 * @param source_ip Source IP address
 * @param target_port Target port
 * @param session_id Session ID (optional, can be 0)
 * @param failure_type Failure type string (optional, can be NULL)
 * @return Detection result
 */
buckwild_enumeration_result_t buckwild_enumeration_check(
    buckwild_enumeration_detector_t* detector,
    const buckwild_ip_addr_t* source_ip,
    uint16_t target_port,
    uint64_t session_id,
    const char* failure_type
);

/**
 * @brief Manually unblock a source
 * @param detector Detector instance
 * @param source_ip Source IP to unblock
 * @return true if source was blocked, false otherwise
 */
bool buckwild_enumeration_unblock(
    buckwild_enumeration_detector_t* detector,
    const buckwild_ip_addr_t* source_ip
);

/**
 * @brief Clean up expired entries
 * @param detector Detector instance
 * @return Number of entries removed, or negative on error
 */
int buckwild_enumeration_cleanup(buckwild_enumeration_detector_t* detector);

/**
 * @brief Get enumeration detection statistics
 * @param detector Detector instance
 * @param stats Output statistics structure
 * @return 0 on success, negative on error
 */
int buckwild_enumeration_get_stats(
    buckwild_enumeration_detector_t* detector,
    buckwild_enumeration_stats_t* stats
);

/* ========================================================================
 * Replay Prevention Engine API
 * ======================================================================== */

/**
 * @brief Create a new replay prevention engine
 * @return Pointer to engine instance, or NULL on failure
 */
buckwild_replay_engine_t* buckwild_replay_engine_new(void);

/**
 * @brief Destroy a replay prevention engine
 * @param engine Engine instance to destroy
 */
void buckwild_replay_engine_free(buckwild_replay_engine_t* engine);

/**
 * @brief Validate packet sequence number
 * @param engine Engine instance
 * @param session_id Session ID
 * @param sequence_number Sequence number to validate
 * @return Validation result
 */
buckwild_replay_result_t buckwild_replay_validate_sequence(
    buckwild_replay_engine_t* engine,
    uint64_t session_id,
    uint32_t sequence_number
);

/**
 * @brief Generate a new nonce for challenge-response
 * @param engine Engine instance
 * @param session_id Session ID
 * @param operation_type Operation type string
 * @param challenge_data Challenge data
 * @param challenge_len Length of challenge data
 * @param nonce_out Output buffer for nonce (must be at least 32 bytes)
 * @return 0 on success, negative on error
 */
int buckwild_replay_generate_nonce(
    buckwild_replay_engine_t* engine,
    uint64_t session_id,
    const char* operation_type,
    const uint8_t* challenge_data,
    size_t challenge_len,
    uint8_t* nonce_out
);

/**
 * @brief Validate a nonce for challenge-response
 * @param engine Engine instance
 * @param nonce Nonce to validate
 * @param nonce_len Length of nonce
 * @param session_id Session ID
 * @param operation_type Operation type string
 * @param challenge_data Challenge data
 * @param challenge_len Length of challenge data
 * @return Validation result
 */
buckwild_replay_result_t buckwild_replay_validate_nonce(
    buckwild_replay_engine_t* engine,
    const uint8_t* nonce,
    size_t nonce_len,
    uint64_t session_id,
    const char* operation_type,
    const uint8_t* challenge_data,
    size_t challenge_len
);

/**
 * @brief Register a time-sensitive operation
 * @param engine Engine instance
 * @param operation_id Operation ID string
 * @param session_id Session ID
 * @param operation_data Operation data
 * @param operation_len Length of operation data
 * @param timeout_seconds Timeout in seconds
 * @return 0 on success, negative on error
 */
int buckwild_replay_register_operation(
    buckwild_replay_engine_t* engine,
    const char* operation_id,
    uint64_t session_id,
    const uint8_t* operation_data,
    size_t operation_len,
    uint64_t timeout_seconds
);

/**
 * @brief Validate a time-sensitive operation
 * @param engine Engine instance
 * @param operation_id Operation ID string
 * @param session_id Session ID
 * @param operation_data Operation data
 * @param operation_len Length of operation data
 * @return Validation result
 */
buckwild_replay_result_t buckwild_replay_validate_operation(
    buckwild_replay_engine_t* engine,
    const char* operation_id,
    uint64_t session_id,
    const uint8_t* operation_data,
    size_t operation_len
);

/**
 * @brief Complete a time-sensitive operation
 * @param engine Engine instance
 * @param operation_id Operation ID string
 * @return true if operation existed, false otherwise
 */
bool buckwild_replay_complete_operation(
    buckwild_replay_engine_t* engine,
    const char* operation_id
);

/**
 * @brief Clean up expired entries
 * @param engine Engine instance
 * @return Number of entries removed, or negative on error
 */
int buckwild_replay_cleanup(buckwild_replay_engine_t* engine);

/**
 * @brief Get replay prevention statistics
 * @param engine Engine instance
 * @param stats Output statistics structure
 * @return 0 on success, negative on error
 */
int buckwild_replay_get_stats(
    buckwild_replay_engine_t* engine,
    buckwild_replay_stats_t* stats
);

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

/**
 * @brief Convert IPv4 address to buckwild_ip_addr_t
 * @param ipv4 IPv4 address in network byte order
 * @param addr Output address structure
 */
void buckwild_ip_from_ipv4(uint32_t ipv4, buckwild_ip_addr_t* addr);

/**
 * @brief Convert IPv6 address to buckwild_ip_addr_t
 * @param ipv6 IPv6 address (16 bytes)
 * @param addr Output address structure
 */
void buckwild_ip_from_ipv6(const uint8_t ipv6[16], buckwild_ip_addr_t* addr);

/**
 * @brief Get current timestamp in 500ms buckets since epoch
 * @param epoch_type Epoch type (daily or monthly)
 * @return Current timestamp
 */
uint64_t buckwild_get_current_timestamp(buckwild_epoch_type_t epoch_type);

/**
 * @brief Get error message for the last error
 * @return Error message string, or NULL if no error
 */
const char* buckwild_get_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_ANTI_REPLAY_H */