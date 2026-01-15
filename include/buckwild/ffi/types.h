/**
 * @file types.h
 * @brief Common FFI types for Buckwild C/Rust interoperation
 *
 * This header defines shared types used across all Buckwild FFI bindings,
 * providing a consistent error handling and result pattern for C code
 * interfacing with Rust components.
 *
 * FFI-SAFE: All types use C-compatible representations
 * PLATFORM: Cross-platform (Linux, macOS, Windows)
 */

#ifndef BUCKWILD_FFI_TYPES_H
#define BUCKWILD_FFI_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * BuckwildError - Common error codes for FFI operations
 *
 * Error codes are organized by category with reserved ranges:
 * - 0: Success
 * - 1-99: General errors
 * - 100-199: Network errors
 * - 200-299: Crypto errors
 * - 300-399: eBPF errors
 * - 400-499: Protocol errors
 * - 500-599: Configuration errors
 * - 600-699: Resource errors
 * - 700-799: Permission errors
 */
typedef enum {
	/* Success */
	BUCKWILD_OK = 0,

	/* General errors (1-99) */
	BUCKWILD_ERR_UNKNOWN = 1,
	BUCKWILD_ERR_NULL_POINTER = 2,
	BUCKWILD_ERR_INVALID_ARGUMENT = 3,
	BUCKWILD_ERR_OUT_OF_RANGE = 4,
	BUCKWILD_ERR_BUFFER_TOO_SMALL = 5,
	BUCKWILD_ERR_NOT_INITIALIZED = 6,
	BUCKWILD_ERR_ALREADY_INITIALIZED = 7,
	BUCKWILD_ERR_NOT_SUPPORTED = 8,
	BUCKWILD_ERR_TIMEOUT = 9,
	BUCKWILD_ERR_WOULD_BLOCK = 10,
	BUCKWILD_ERR_INTERNAL = 11,

	/* Network errors (100-199) */
	BUCKWILD_ERR_NETWORK_UNREACHABLE = 100,
	BUCKWILD_ERR_HOST_UNREACHABLE = 101,
	BUCKWILD_ERR_CONNECTION_FAILED = 102,
	BUCKWILD_ERR_CONNECTION_REFUSED = 103,
	BUCKWILD_ERR_CONNECTION_RESET = 104,
	BUCKWILD_ERR_CONNECTION_TIMEOUT = 105,
	BUCKWILD_ERR_SOCKET_BIND_FAILED = 106,
	BUCKWILD_ERR_SOCKET_LISTEN_FAILED = 107,
	BUCKWILD_ERR_SOCKET_ACCEPT_FAILED = 108,
	BUCKWILD_ERR_SOCKET_CONNECT_FAILED = 109,
	BUCKWILD_ERR_SEND_FAILED = 110,
	BUCKWILD_ERR_RECEIVE_FAILED = 111,
	BUCKWILD_ERR_MTU_EXCEEDED = 112,
	BUCKWILD_ERR_NETWORK_CONGESTION = 113,
	BUCKWILD_ERR_BANDWIDTH_LIMIT_EXCEEDED = 114,
	BUCKWILD_ERR_INVALID_ADDRESS = 115,
	BUCKWILD_ERR_INVALID_PORT = 116,
	BUCKWILD_ERR_PORT_UNREACHABLE = 117,
	BUCKWILD_ERR_DNS_RESOLUTION_FAILED = 118,

	/* TUN/Interface errors (120-149) */
	BUCKWILD_ERR_INTERFACE_NOT_FOUND = 120,
	BUCKWILD_ERR_INTERFACE_DOWN = 121,
	BUCKWILD_ERR_INTERFACE_UP_FAILED = 122,
	BUCKWILD_ERR_INTERFACE_CREATE_FAILED = 123,
	BUCKWILD_ERR_INTERFACE_CONFIGURE_FAILED = 124,
	BUCKWILD_ERR_TUN_CREATE_FAILED = 125,
	BUCKWILD_ERR_TUN_CONFIGURE_FAILED = 126,
	BUCKWILD_ERR_TUN_READ_FAILED = 127,
	BUCKWILD_ERR_TUN_WRITE_FAILED = 128,
	BUCKWILD_ERR_TUN_DEVICE_NOT_FOUND = 129,

	/* Routing errors (150-169) */
	BUCKWILD_ERR_ROUTING_ERROR = 150,
	BUCKWILD_ERR_ROUTE_ADD_FAILED = 151,
	BUCKWILD_ERR_ROUTE_DELETE_FAILED = 152,
	BUCKWILD_ERR_ROUTE_LOOKUP_FAILED = 153,
	BUCKWILD_ERR_ROUTE_NOT_FOUND = 154,

	/* Crypto errors (200-299) */
	BUCKWILD_ERR_CRYPTO_FAILED = 200,
	BUCKWILD_ERR_KEY_GENERATION_FAILED = 201,
	BUCKWILD_ERR_KEY_DERIVATION_FAILED = 202,
	BUCKWILD_ERR_ENCRYPTION_FAILED = 203,
	BUCKWILD_ERR_DECRYPTION_FAILED = 204,
	BUCKWILD_ERR_AUTHENTICATION_FAILED = 205,
	BUCKWILD_ERR_SIGNATURE_VERIFICATION_FAILED = 206,
	BUCKWILD_ERR_INVALID_KEY = 207,
	BUCKWILD_ERR_INVALID_KEY_LENGTH = 208,
	BUCKWILD_ERR_HMAC_FAILED = 209,
	BUCKWILD_ERR_HKDF_FAILED = 210,
	BUCKWILD_ERR_RANDOM_GENERATION_FAILED = 211,

	/* eBPF errors (300-399) */
	BUCKWILD_ERR_EBPF_NOT_SUPPORTED = 300,
	BUCKWILD_ERR_EBPF_LOAD_FAILED = 301,
	BUCKWILD_ERR_EBPF_ATTACH_FAILED = 302,
	BUCKWILD_ERR_EBPF_DETACH_FAILED = 303,
	BUCKWILD_ERR_EBPF_MAP_OPERATION_FAILED = 304,
	BUCKWILD_ERR_EBPF_VERIFICATION_FAILED = 305,
	BUCKWILD_ERR_EBPF_PROGRAM_NOT_FOUND = 306,
	BUCKWILD_ERR_EBPF_MAP_NOT_FOUND = 307,

	/* Protocol errors (400-499) */
	BUCKWILD_ERR_INVALID_PACKET = 400,
	BUCKWILD_ERR_PACKET_TOO_SMALL = 401,
	BUCKWILD_ERR_PACKET_TOO_LARGE = 402,
	BUCKWILD_ERR_INVALID_HEADER = 403,
	BUCKWILD_ERR_INVALID_PAYLOAD = 404,
	BUCKWILD_ERR_UNSUPPORTED_VERSION = 405,
	BUCKWILD_ERR_REPLAY_ATTACK_DETECTED = 406,
	BUCKWILD_ERR_SEQUENCE_OUT_OF_ORDER = 407,
	BUCKWILD_ERR_TIMESTAMP_OUT_OF_WINDOW = 408,
	BUCKWILD_ERR_FRAGMENTATION_FAILED = 409,
	BUCKWILD_ERR_REASSEMBLY_FAILED = 410,
	BUCKWILD_ERR_REASSEMBLY_TIMEOUT = 411,
	BUCKWILD_ERR_INVALID_FRAGMENT = 412,

	/* Configuration errors (500-599) */
	BUCKWILD_ERR_CONFIG_INVALID = 500,
	BUCKWILD_ERR_CONFIG_PARSE_FAILED = 501,
	BUCKWILD_ERR_CONFIG_VALIDATION_FAILED = 502,
	BUCKWILD_ERR_CONFIG_FILE_NOT_FOUND = 503,
	BUCKWILD_ERR_CONFIG_FILE_READ_FAILED = 504,

	/* Resource errors (600-699) */
	BUCKWILD_ERR_OUT_OF_MEMORY = 600,
	BUCKWILD_ERR_RESOURCE_EXHAUSTED = 601,
	BUCKWILD_ERR_TOO_MANY_CONNECTIONS = 602,
	BUCKWILD_ERR_BUFFER_POOL_EXHAUSTED = 603,
	BUCKWILD_ERR_QUEUE_FULL = 604,

	/* Permission errors (700-799) */
	BUCKWILD_ERR_PERMISSION_DENIED = 700,
	BUCKWILD_ERR_INSUFFICIENT_PRIVILEGES = 701,
	BUCKWILD_ERR_TUN_PERMISSION_DENIED = 702,

	/* State errors (800-899) */
	BUCKWILD_ERR_INVALID_STATE = 800,
	BUCKWILD_ERR_NOT_CONNECTED = 801,
	BUCKWILD_ERR_ALREADY_CONNECTED = 802,
	BUCKWILD_ERR_CONNECTION_CLOSED = 803,
} BuckwildError;

/**
 * BuckwildResult - Generic result type for operations returning a value
 *
 * This structure provides Rust-style Result<T, E> semantics in C.
 * Callers should check `error` first before accessing `value`.
 *
 * Usage:
 *   BuckwildResult result = some_operation();
 *   if (result.error != BUCKWILD_OK) {
 *       // Handle error
 *       return result.error;
 *   }
 *   // Use result.value
 */
typedef struct {
	/** Error code (BUCKWILD_OK on success) */
	BuckwildError error;
	/** Result value (valid only if error == BUCKWILD_OK) */
	int64_t value;
} BuckwildResult;

/**
 * BuckwildPtrResult - Result type for operations returning a pointer
 *
 * Similar to BuckwildResult but for pointer return values.
 * The pointer is valid only if error == BUCKWILD_OK.
 *
 * Usage:
 *   BuckwildPtrResult result = create_something();
 *   if (result.error != BUCKWILD_OK) {
 *       // Handle error
 *       return result.error;
 *   }
 *   void *ptr = result.ptr;
 */
typedef struct {
	/** Error code (BUCKWILD_OK on success) */
	BuckwildError error;
	/** Result pointer (valid only if error == BUCKWILD_OK) */
	void *ptr;
} BuckwildPtrResult;

/**
 * buckwild_error_string() - Get human-readable error message
 * @error: Error code
 *
 * Returns a static string describing the error. The returned string
 * is valid for the lifetime of the program and must not be freed.
 *
 * Return: Error message string (never NULL)
 */
const char *buckwild_error_string(BuckwildError error);

/**
 * buckwild_error_is_recoverable() - Check if error is recoverable
 * @error: Error code
 *
 * Determines whether the error represents a transient condition
 * that might succeed on retry.
 *
 * Return: true if error is potentially recoverable, false otherwise
 */
bool buckwild_error_is_recoverable(BuckwildError error);

/**
 * buckwild_result_ok() - Create a successful result
 * @value: Result value
 *
 * Helper function to create a successful BuckwildResult.
 *
 * Return: BuckwildResult with error set to BUCKWILD_OK
 */
static inline BuckwildResult buckwild_result_ok(int64_t value)
{
	BuckwildResult result = { .error = BUCKWILD_OK, .value = value };
	return result;
}

/**
 * buckwild_result_err() - Create an error result
 * @error: Error code
 *
 * Helper function to create an error BuckwildResult.
 *
 * Return: BuckwildResult with specified error code
 */
static inline BuckwildResult buckwild_result_err(BuckwildError error)
{
	BuckwildResult result = { .error = error, .value = 0 };
	return result;
}

/**
 * buckwild_ptr_result_ok() - Create a successful pointer result
 * @ptr: Result pointer
 *
 * Helper function to create a successful BuckwildPtrResult.
 *
 * Return: BuckwildPtrResult with error set to BUCKWILD_OK
 */
static inline BuckwildPtrResult buckwild_ptr_result_ok(void *ptr)
{
	BuckwildPtrResult result = { .error = BUCKWILD_OK, .ptr = ptr };
	return result;
}

/**
 * buckwild_ptr_result_err() - Create an error pointer result
 * @error: Error code
 *
 * Helper function to create an error BuckwildPtrResult.
 *
 * Return: BuckwildPtrResult with specified error code
 */
static inline BuckwildPtrResult buckwild_ptr_result_err(BuckwildError error)
{
	BuckwildPtrResult result = { .error = error, .ptr = NULL };
	return result;
}

#ifdef __cplusplus
}
#endif

#endif /* BUCKWILD_FFI_TYPES_H */
