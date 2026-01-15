/**
 * @file fragment_security.h
 * @brief Fragment security API for Buckwild protocol
 * 
 * This header provides C API functions for fragment security validation,
 * including session binding validation, cryptographic binding verification,
 * and origin validation to prevent fragment-based attacks.
 */

#ifndef BUCKWILD_FRAGMENT_SECURITY_H
#define BUCKWILD_FRAGMENT_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fragment security validator handle
 */
typedef struct buckwild_fragment_security_validator buckwild_fragment_security_validator_t;

/**
 * @brief Fragment security configuration
 */
typedef struct {
    /** Maximum fragments per session */
    uint32_t max_fragments_per_session;
    
    /** Maximum sessions per source IP */
    uint32_t max_sessions_per_source;
    
    /** Session binding timeout (seconds) */
    uint64_t session_binding_timeout_s;
    
    /** Origin tracking timeout (seconds) */
    uint64_t origin_tracking_timeout_s;
    
    /** Maximum violations before blocking */
    uint32_t max_violations_before_block;
    
    /** Block duration for violations (seconds) */
    uint64_t violation_block_duration_s;
    
    /** Enable strict source IP validation */
    bool strict_source_validation;
    
    /** Enable cryptographic binding verification */
    bool enable_crypto_binding;
} buckwild_fragment_security_config_t;

/**
 * @brief Fragment validation request
 */
typedef struct {
    /** Session ID */
    uint64_t session_id;
    
    /** Fragment ID */
    uint16_t fragment_id;
    
    /** Fragment index */
    uint16_t fragment_index;
    
    /** Total fragments */
    uint16_t total_fragments;
    
    /** Fragment payload */
    const uint8_t* payload;
    
    /** Payload size */
    size_t payload_size;
    
    /** Source IP address */
    uint32_t source_ip;
    
    /** Fragment timestamp */
    uint64_t timestamp;
    
    /** HMAC policy (0=Light, 1=Medium, 2=Strong) */
    uint8_t hmac_policy;
} buckwild_fragment_validation_request_t;

/**
 * @brief Fragment validation result
 */
typedef enum {
    /** Fragment is valid and can be processed */
    BUCKWILD_FRAGMENT_VALID = 0,
    
    /** Cross-session injection attempt detected */
    BUCKWILD_FRAGMENT_CROSS_SESSION_INJECTION = 1,
    
    /** Cryptographic binding verification failed */
    BUCKWILD_FRAGMENT_BINDING_VERIFICATION_FAILED = 2,
    
    /** Origin validation failed */
    BUCKWILD_FRAGMENT_ORIGIN_VALIDATION_FAILED = 3,
    
    /** Session not found or expired */
    BUCKWILD_FRAGMENT_SESSION_NOT_FOUND = 4,
    
    /** Source IP blocked due to violations */
    BUCKWILD_FRAGMENT_SOURCE_BLOCKED = 5,
    
    /** Fragment limit exceeded for session */
    BUCKWILD_FRAGMENT_LIMIT_EXCEEDED = 6,
    
    /** Invalid fragment parameters */
    BUCKWILD_FRAGMENT_INVALID_PARAMETERS = 7
} buckwild_fragment_validation_result_t;

/**
 * @brief Fragment security statistics
 */
typedef struct {
    /** Cross-session injection attempts */
    uint64_t injection_attempts;
    
    /** Cryptographic binding failures */
    uint64_t binding_failures;
    
    /** Origin validation failures */
    uint64_t origin_failures;
    
    /** Cryptographic verification failures */
    uint64_t crypto_failures;
    
    /** Session hijacking attempts */
    uint64_t hijacking_attempts;
    
    /** Source IP violations */
    uint64_t source_violations;
    
    /** Active session bindings */
    uint64_t active_session_bindings;
    
    /** Tracked origins */
    uint64_t tracked_origins;
} buckwild_fragment_security_stats_t;

/**
 * @brief Create a new fragment security validator
 * 
 * @param config Configuration for the validator (NULL for default)
 * @return Validator handle or NULL on error
 */
buckwild_fragment_security_validator_t* buckwild_fragment_security_validator_new(
    const buckwild_fragment_security_config_t* config
);

/**
 * @brief Destroy a fragment security validator
 * 
 * @param validator Validator handle
 */
void buckwild_fragment_security_validator_free(
    buckwild_fragment_security_validator_t* validator
);

/**
 * @brief Register a session binding for fragment validation
 * 
 * @param validator Validator handle
 * @param session_id Session ID
 * @param session_key Session HMAC key (32 bytes)
 * @param allowed_sources Array of allowed source IP addresses
 * @param source_count Number of allowed sources
 * @return 0 on success, negative error code on failure
 */
int buckwild_fragment_security_register_session(
    buckwild_fragment_security_validator_t* validator,
    uint64_t session_id,
    const uint8_t* session_key,
    const uint32_t* allowed_sources,
    size_t source_count
);

/**
 * @brief Validate fragment security
 * 
 * @param validator Validator handle
 * @param request Fragment validation request
 * @return Validation result
 */
buckwild_fragment_validation_result_t buckwild_fragment_security_validate(
    buckwild_fragment_security_validator_t* validator,
    const buckwild_fragment_validation_request_t* request
);

/**
 * @brief Unregister a session binding
 * 
 * @param validator Validator handle
 * @param session_id Session ID to unregister
 */
void buckwild_fragment_security_unregister_session(
    buckwild_fragment_security_validator_t* validator,
    uint64_t session_id
);

/**
 * @brief Clean up expired session bindings and origin states
 * 
 * @param validator Validator handle
 */
void buckwild_fragment_security_cleanup_expired(
    buckwild_fragment_security_validator_t* validator
);

/**
 * @brief Get fragment security statistics
 * 
 * @param validator Validator handle
 * @param stats Output statistics structure
 * @return 0 on success, negative error code on failure
 */
int buckwild_fragment_security_get_stats(
    buckwild_fragment_security_validator_t* validator,
    buckwild_fragment_security_stats_t* stats
);

/**
 * @brief Get default fragment security configuration
 * 
 * @param config Output configuration structure
 */
void buckwild_fragment_security_get_default_config(
    buckwild_fragment_security_config_t* config
);

/**
 * @brief Convert validation result to string
 * 
 * @param result Validation result
 * @return String representation of the result
 */
const char* buckwild_fragment_validation_result_to_string(
    buckwild_fragment_validation_result_t result
);

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_FRAGMENT_SECURITY_H */