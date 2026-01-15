/**
 * @file fragment_security.c
 * @brief C wrapper implementation for fragment security API
 * 
 * This file implements C wrapper functions around the Rust fragment security
 * operations, providing a C-compatible API for fragment validation and security.
 */

#include "buckwild/protocol/fragment_security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

// Forward declarations for Rust FFI functions
extern void* buckwild_rust_fragment_security_validator_new(
    const buckwild_fragment_security_config_t* config
);

extern void buckwild_rust_fragment_security_validator_free(
    void* validator
);

extern int buckwild_rust_fragment_security_register_session(
    void* validator,
    uint64_t session_id,
    const uint8_t* session_key,
    const uint32_t* allowed_sources,
    size_t source_count
);

extern buckwild_fragment_validation_result_t buckwild_rust_fragment_security_validate(
    void* validator,
    const buckwild_fragment_validation_request_t* request
);

extern void buckwild_rust_fragment_security_unregister_session(
    void* validator,
    uint64_t session_id
);

extern void buckwild_rust_fragment_security_cleanup_expired(
    void* validator
);

extern int buckwild_rust_fragment_security_get_stats(
    void* validator,
    buckwild_fragment_security_stats_t* stats
);

// C wrapper implementations

buckwild_fragment_security_validator_t* buckwild_fragment_security_validator_new(
    const buckwild_fragment_security_config_t* config
) {
    if (!config) {
        // Use default configuration
        buckwild_fragment_security_config_t default_config;
        buckwild_fragment_security_get_default_config(&default_config);
        return (buckwild_fragment_security_validator_t*)buckwild_rust_fragment_security_validator_new(&default_config);
    }
    
    return (buckwild_fragment_security_validator_t*)buckwild_rust_fragment_security_validator_new(config);
}

void buckwild_fragment_security_validator_free(
    buckwild_fragment_security_validator_t* validator
) {
    if (validator) {
        buckwild_rust_fragment_security_validator_free((void*)validator);
    }
}

int buckwild_fragment_security_register_session(
    buckwild_fragment_security_validator_t* validator,
    uint64_t session_id,
    const uint8_t* session_key,
    const uint32_t* allowed_sources,
    size_t source_count
) {
    if (!validator) {
        return -EINVAL;
    }
    
    if (!session_key) {
        return -EINVAL;
    }
    
    if (source_count > 0 && !allowed_sources) {
        return -EINVAL;
    }
    
    return buckwild_rust_fragment_security_register_session(
        (void*)validator,
        session_id,
        session_key,
        allowed_sources,
        source_count
    );
}

buckwild_fragment_validation_result_t buckwild_fragment_security_validate(
    buckwild_fragment_security_validator_t* validator,
    const buckwild_fragment_validation_request_t* request
) {
    if (!validator || !request) {
        return BUCKWILD_FRAGMENT_INVALID_PARAMETERS;
    }
    
    if (!request->payload && request->payload_size > 0) {
        return BUCKWILD_FRAGMENT_INVALID_PARAMETERS;
    }
    
    if (request->payload_size == 0) {
        return BUCKWILD_FRAGMENT_INVALID_PARAMETERS;
    }
    
    if (request->fragment_index >= request->total_fragments) {
        return BUCKWILD_FRAGMENT_INVALID_PARAMETERS;
    }
    
    return buckwild_rust_fragment_security_validate((void*)validator, request);
}

void buckwild_fragment_security_unregister_session(
    buckwild_fragment_security_validator_t* validator,
    uint64_t session_id
) {
    if (validator) {
        buckwild_rust_fragment_security_unregister_session((void*)validator, session_id);
    }
}

void buckwild_fragment_security_cleanup_expired(
    buckwild_fragment_security_validator_t* validator
) {
    if (validator) {
        buckwild_rust_fragment_security_cleanup_expired((void*)validator);
    }
}

int buckwild_fragment_security_get_stats(
    buckwild_fragment_security_validator_t* validator,
    buckwild_fragment_security_stats_t* stats
) {
    if (!validator || !stats) {
        return -EINVAL;
    }
    
    return buckwild_rust_fragment_security_get_stats((void*)validator, stats);
}

void buckwild_fragment_security_get_default_config(
    buckwild_fragment_security_config_t* config
) {
    if (!config) {
        return;
    }
    
    // Set default configuration values
    config->max_fragments_per_session = 1000;
    config->max_sessions_per_source = 10;
    config->session_binding_timeout_s = 300; // 5 minutes
    config->origin_tracking_timeout_s = 600; // 10 minutes
    config->max_violations_before_block = 5;
    config->violation_block_duration_s = 300; // 5 minutes
    config->strict_source_validation = true;
    config->enable_crypto_binding = true;
}

const char* buckwild_fragment_validation_result_to_string(
    buckwild_fragment_validation_result_t result
) {
    switch (result) {
        case BUCKWILD_FRAGMENT_VALID:
            return "Valid";
        case BUCKWILD_FRAGMENT_CROSS_SESSION_INJECTION:
            return "Cross-session injection";
        case BUCKWILD_FRAGMENT_BINDING_VERIFICATION_FAILED:
            return "Binding verification failed";
        case BUCKWILD_FRAGMENT_ORIGIN_VALIDATION_FAILED:
            return "Origin validation failed";
        case BUCKWILD_FRAGMENT_SESSION_NOT_FOUND:
            return "Session not found";
        case BUCKWILD_FRAGMENT_SOURCE_BLOCKED:
            return "Source blocked";
        case BUCKWILD_FRAGMENT_LIMIT_EXCEEDED:
            return "Fragment limit exceeded";
        case BUCKWILD_FRAGMENT_INVALID_PARAMETERS:
            return "Invalid parameters";
        default:
            return "Unknown";
    }
}

// Helper functions for error handling and logging

/**
 * @brief Log fragment security event
 * 
 * @param level Log level (0=debug, 1=info, 2=warn, 3=error)
 * @param session_id Session ID
 * @param fragment_id Fragment ID
 * @param source_ip Source IP address
 * @param message Log message
 */
void buckwild_fragment_security_log_event(
    int level,
    uint64_t session_id,
    uint16_t fragment_id,
    uint32_t source_ip,
    const char* message
) {
    // Convert IP address to string
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
        (source_ip >> 24) & 0xFF,
        (source_ip >> 16) & 0xFF,
        (source_ip >> 8) & 0xFF,
        source_ip & 0xFF
    );
    
    const char* level_str;
    switch (level) {
        case 0: level_str = "DEBUG"; break;
        case 1: level_str = "INFO"; break;
        case 2: level_str = "WARN"; break;
        case 3: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }
    
    // Log to stderr for now (in production, this would use proper logging)
    fprintf(stderr, "[%s] Fragment Security - Session: 0x%016lx, Fragment: %u, Source: %s - %s\n",
        level_str, session_id, fragment_id, ip_str, message ? message : "");
}

/**
 * @brief Validate fragment security configuration
 * 
 * @param config Configuration to validate
 * @return 0 if valid, negative error code if invalid
 */
int buckwild_fragment_security_validate_config(
    const buckwild_fragment_security_config_t* config
) {
    if (!config) {
        return -EINVAL;
    }
    
    // Validate configuration parameters
    if (config->max_fragments_per_session == 0) {
        return -EINVAL;
    }
    
    if (config->max_sessions_per_source == 0) {
        return -EINVAL;
    }
    
    if (config->session_binding_timeout_s == 0) {
        return -EINVAL;
    }
    
    if (config->origin_tracking_timeout_s == 0) {
        return -EINVAL;
    }
    
    if (config->max_violations_before_block == 0) {
        return -EINVAL;
    }
    
    if (config->violation_block_duration_s == 0) {
        return -EINVAL;
    }
    
    // Check for reasonable limits
    if (config->max_fragments_per_session > 100000) {
        return -EINVAL; // Too many fragments
    }
    
    if (config->max_sessions_per_source > 1000) {
        return -EINVAL; // Too many sessions
    }
    
    if (config->session_binding_timeout_s > 86400) {
        return -EINVAL; // More than 24 hours
    }
    
    return 0;
}

/**
 * @brief Create a fragment validation request
 * 
 * @param session_id Session ID
 * @param fragment_id Fragment ID
 * @param fragment_index Fragment index
 * @param total_fragments Total fragments
 * @param payload Fragment payload
 * @param payload_size Payload size
 * @param source_ip Source IP address
 * @param timestamp Fragment timestamp
 * @param hmac_policy HMAC policy
 * @param request Output request structure
 * @return 0 on success, negative error code on failure
 */
int buckwild_fragment_security_create_request(
    uint64_t session_id,
    uint16_t fragment_id,
    uint16_t fragment_index,
    uint16_t total_fragments,
    const uint8_t* payload,
    size_t payload_size,
    uint32_t source_ip,
    uint64_t timestamp,
    uint8_t hmac_policy,
    buckwild_fragment_validation_request_t* request
) {
    if (!request) {
        return -EINVAL;
    }
    
    if (!payload && payload_size > 0) {
        return -EINVAL;
    }
    
    if (payload_size == 0) {
        return -EINVAL;
    }
    
    if (fragment_index >= total_fragments) {
        return -EINVAL;
    }
    
    if (total_fragments == 0) {
        return -EINVAL;
    }
    
    if (hmac_policy > 2) { // 0=Light, 1=Medium, 2=Strong
        return -EINVAL;
    }
    
    // Fill in the request structure
    memset(request, 0, sizeof(*request));
    request->session_id = session_id;
    request->fragment_id = fragment_id;
    request->fragment_index = fragment_index;
    request->total_fragments = total_fragments;
    request->payload = payload;
    request->payload_size = payload_size;
    request->source_ip = source_ip;
    request->timestamp = timestamp;
    request->hmac_policy = hmac_policy;
    
    return 0;
}

/**
 * @brief Get current timestamp in seconds since Unix epoch
 * 
 * @return Current timestamp
 */
uint64_t buckwild_fragment_security_get_timestamp(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (uint64_t)ts.tv_sec;
    }
    return 0;
}