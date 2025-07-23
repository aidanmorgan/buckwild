# Protocol Error Codes

## Overview

This document defines the comprehensive set of error codes used throughout the protocol for error reporting, debugging, and automated error recovery. Each error code provides specific information about failure conditions and enables appropriate response strategies.

## Purpose and Rationale

Standardized error codes serve several critical functions:

- **Debugging and Diagnostics**: Enable precise identification of failure points in complex protocol interactions
- **Automated Recovery**: Allow implementations to programmatically respond to specific error conditions
- **Security Monitoring**: Help detect and categorize potential security threats and attacks
- **Interoperability**: Ensure consistent error reporting across different implementations
- **Operational Monitoring**: Provide structured data for network operations and performance analysis

The error code design follows a hierarchical structure where similar error types are grouped into ranges, making it easier to categorize and handle errors systematically.

## Key Concepts

- **Error Categories**: Grouped by functionality (authentication, timing, protocol state, etc.)
- **Severity Levels**: Implicit severity based on error type (recoverable vs. fatal)
- **Recovery Actions**: Each error suggests specific recovery mechanisms
- **Diagnostic Information**: Detailed error context for troubleshooting

## Enumerated Protocol Error Codes

```pseudocode
// Protocol error codes
ERROR_SUCCESS = 0x00
ERROR_INVALID_PACKET = 0x01
ERROR_AUTHENTICATION_FAILED = 0x02
ERROR_TIMESTAMP_INVALID = 0x03
ERROR_REPLAY_ATTACK = 0x04
ERROR_SESSION_NOT_FOUND = 0x05
ERROR_STATE_INVALID = 0x06
ERROR_WINDOW_OVERFLOW = 0x07
ERROR_SEQUENCE_INVALID = 0x08
ERROR_FRAGMENT_INVALID = 0x09
ERROR_SYNC_FAILED = 0x0A
ERROR_RECOVERY_FAILED = 0x0B
ERROR_TIMEOUT = 0x0C
ERROR_MEMORY_EXHAUSTED = 0x0D
ERROR_INVALID_PARAMETER = 0x0E
ERROR_PORT_CALCULATION_FAILED = 0x0F
ERROR_FRAGMENT_REASSEMBLY_FAILED = 0x10
ERROR_CONGESTION_CONTROL_FAILED = 0x11
ERROR_DISCOVERY_FAILED = 0x12
ERROR_PSK_NOT_FOUND = 0x13
ERROR_ECDH_KEY_EXCHANGE_FAILED = 0x14
ERROR_DISCOVERY_TIMEOUT = 0x15
ERROR_ECDH_VERIFICATION_FAILED = 0x16
ERROR_PSK_ENUMERATION_ATTEMPT = 0x17

// CONTROL packet sub-type errors
ERROR_TIME_SYNC_REQUEST_FAILED = 0x18
ERROR_TIME_SYNC_RESPONSE_FAILED = 0x19
ERROR_RECOVERY_REQUEST_FAILED = 0x1A
ERROR_SEQUENCE_NEGOTIATION_FAILED = 0x1B

// MANAGEMENT packet sub-type errors
ERROR_REKEY_REQUEST_FAILED = 0x1C
ERROR_REKEY_RESPONSE_FAILED = 0x1D
ERROR_REPAIR_REQUEST_FAILED = 0x1E
ERROR_REPAIR_RESPONSE_FAILED = 0x1F

// DISCOVERY packet sub-type errors
ERROR_DISCOVERY_REQUEST_FAILED = 0x20
ERROR_DISCOVERY_RESPONSE_FAILED = 0x21
ERROR_DISCOVERY_CONFIRM_FAILED = 0x22

// Fragmentation and flow control errors
ERROR_FRAGMENT_TIMEOUT = 0x23
ERROR_FRAGMENT_OVERLAP = 0x24
ERROR_FRAGMENT_BOMB = 0x25
ERROR_ZERO_WINDOW_DEADLOCK = 0x26
ERROR_WINDOW_UPDATE_FAILED = 0x27

// Multi-connection errors
ERROR_PORT_COLLISION = 0x28
ERROR_SESSION_ID_COLLISION = 0x29
ERROR_CONNECTION_LIMIT_EXCEEDED = 0x2A

// Security attack detection errors
ERROR_RATE_LIMITED = 0x2B
ERROR_ENUMERATION_DETECTED = 0x2C
ERROR_INJECTION_ATTEMPT = 0x2D
ERROR_TAMPERING_DETECTED = 0x2E

// Privacy-preserving set intersection errors
ERROR_PSI_BLOOM_FILTER_INVALID = 0x2F
ERROR_PSI_NO_INTERSECTION = 0x30
ERROR_PSI_CANDIDATE_VERIFICATION_FAILED = 0x31
ERROR_PSK_CONFIRMATION_INVALID = 0x32
ERROR_PSI_BLINDED_FINGERPRINT_FAILED = 0x33
ERROR_BLOOM_FILTER_SIZE_INVALID = 0x34

// Additional error codes for edge case handling
ERROR_ZERO_KNOWLEDGE_PROOF_FAILED = 0x35
ERROR_UNSUPPORTED_VERSION = 0x36
ERROR_INVALID_PACKET_TYPE = 0x37
ERROR_UNKNOWN_PACKET_TYPE = 0x38
ERROR_INVALID_SUB_TYPE = 0x39
ERROR_PAYLOAD_TOO_LARGE = 0x3A
ERROR_EMPTY_DATA_PACKET = 0x3B
ERROR_INVALID_SESSION_ID = 0x3C

// Connection termination error
ERROR_CONNECTION_TERMINATE = 0x3D
```

## Error Code Descriptions

| Code | Name | Description |
|------|------|-------------|
| 0x00 | ERROR_SUCCESS | Operation completed successfully |
| 0x01 | ERROR_INVALID_PACKET | Packet format is invalid or corrupted |
| 0x02 | ERROR_AUTHENTICATION_FAILED | HMAC verification failed |
| 0x03 | ERROR_TIMESTAMP_INVALID | Packet timestamp is outside acceptable window |
| 0x04 | ERROR_REPLAY_ATTACK | Packet appears to be a replay attack |
| 0x05 | ERROR_SESSION_NOT_FOUND | Referenced session does not exist |
| 0x06 | ERROR_STATE_INVALID | Operation not valid in current connection state |
| 0x07 | ERROR_WINDOW_OVERFLOW | Flow control window exceeded |
| 0x08 | ERROR_SEQUENCE_INVALID | Sequence number is invalid or out of range |
| 0x09 | ERROR_FRAGMENT_INVALID | Fragment packet is malformed or invalid |
| 0x0A | ERROR_SYNC_FAILED | Time or port synchronization failed |
| 0x0B | ERROR_RECOVERY_FAILED | Recovery procedure failed |
| 0x0C | ERROR_TIMEOUT | Operation timed out |
| 0x0D | ERROR_MEMORY_EXHAUSTED | Insufficient memory to complete operation |
| 0x0E | ERROR_INVALID_PARAMETER | Parameter value is invalid |
| 0x0F | ERROR_PORT_CALCULATION_FAILED | Port calculation algorithm failed |
| 0x10 | ERROR_FRAGMENT_REASSEMBLY_FAILED | Fragment reassembly failed |
| 0x11 | ERROR_CONGESTION_CONTROL_FAILED | Congestion control algorithm failed |
| 0x12 | ERROR_DISCOVERY_FAILED | Discovery process failed |
| 0x13 | ERROR_PSK_NOT_FOUND | Pre-shared key not found |
| 0x14 | ERROR_ECDH_KEY_EXCHANGE_FAILED | ECDH key exchange failed or invalid public key |
| 0x15 | ERROR_DISCOVERY_TIMEOUT | Discovery process timed out |
| 0x16 | ERROR_ECDH_VERIFICATION_FAILED | ECDH shared secret verification failed |
| 0x17 | ERROR_PSK_ENUMERATION_ATTEMPT | Detected PSK enumeration attack |
| 0x18 | ERROR_TIME_SYNC_REQUEST_FAILED | Time synchronization request failed |
| 0x19 | ERROR_TIME_SYNC_RESPONSE_FAILED | Time synchronization response failed |
| 0x1A | ERROR_RECOVERY_REQUEST_FAILED | Recovery request failed |
| 0x1B | ERROR_SEQUENCE_NEGOTIATION_FAILED | Sequence number negotiation failed |
| 0x1C | ERROR_REKEY_REQUEST_FAILED | Session rekey request failed |
| 0x1D | ERROR_REKEY_RESPONSE_FAILED | Session rekey response failed |
| 0x1E | ERROR_REPAIR_REQUEST_FAILED | Sequence repair request failed |
| 0x1F | ERROR_REPAIR_RESPONSE_FAILED | Sequence repair response failed |
| 0x20 | ERROR_DISCOVERY_REQUEST_FAILED | PSK discovery request failed |
| 0x21 | ERROR_DISCOVERY_RESPONSE_FAILED | PSK discovery response failed |
| 0x22 | ERROR_DISCOVERY_CONFIRM_FAILED | PSK discovery confirmation failed |
| 0x23 | ERROR_FRAGMENT_TIMEOUT | Fragment reassembly timeout |
| 0x24 | ERROR_FRAGMENT_OVERLAP | Fragment overlap attack detected |
| 0x25 | ERROR_FRAGMENT_BOMB | Fragment bomb attack detected |
| 0x26 | ERROR_ZERO_WINDOW_DEADLOCK | Zero window flow control deadlock |
| 0x27 | ERROR_WINDOW_UPDATE_FAILED | Window update operation failed |
| 0x28 | ERROR_PORT_COLLISION | Port collision between connections |
| 0x29 | ERROR_SESSION_ID_COLLISION | Session ID collision detected |
| 0x2A | ERROR_CONNECTION_LIMIT_EXCEEDED | Maximum connections exceeded |
| 0x2B | ERROR_RATE_LIMITED | Rate limiting triggered |
| 0x2C | ERROR_ENUMERATION_DETECTED | Enumeration attack detected |
| 0x2D | ERROR_INJECTION_ATTEMPT | Packet injection attempt detected |
| 0x2E | ERROR_TAMPERING_DETECTED | Packet tampering detected |
| 0x2F | ERROR_PSI_BLOOM_FILTER_INVALID | Invalid Bloom filter in PSI discovery |
| 0x30 | ERROR_PSI_NO_INTERSECTION | No PSK intersection found in PSI discovery |
| 0x31 | ERROR_PSI_CANDIDATE_VERIFICATION_FAILED | PSI candidate verification failed |
| 0x32 | ERROR_PSK_CONFIRMATION_INVALID | PSK confirmation hash invalid |
| 0x33 | ERROR_PSI_BLINDED_FINGERPRINT_FAILED | Failed to create blinded PSK fingerprint |
| 0x34 | ERROR_BLOOM_FILTER_SIZE_INVALID | Bloom filter size exceeds maximum allowed |
| 0x35 | ERROR_ZERO_KNOWLEDGE_PROOF_FAILED | Zero knowledge proof verification failed |
| 0x36 | ERROR_UNSUPPORTED_VERSION | Protocol version not supported |
| 0x37 | ERROR_INVALID_PACKET_TYPE | Packet type value is invalid |
| 0x38 | ERROR_UNKNOWN_PACKET_TYPE | Packet type is unknown or unrecognized |
| 0x39 | ERROR_INVALID_SUB_TYPE | Packet sub-type value is invalid |
| 0x3A | ERROR_PAYLOAD_TOO_LARGE | Packet payload exceeds maximum size |
| 0x3B | ERROR_EMPTY_DATA_PACKET | DATA packet has empty payload |
| 0x3C | ERROR_INVALID_SESSION_ID | Session ID is invalid or malformed |
| 0x3D | ERROR_CONNECTION_TERMINATE | Connection must be terminated |

## Error Handling Guidelines

### Critical Errors (Connection Termination)
- ERROR_AUTHENTICATION_FAILED
- ERROR_PSK_NOT_FOUND
- ERROR_PSK_ENUMERATION_ATTEMPT
- ERROR_ZERO_KNOWLEDGE_PROOF_FAILED
- ERROR_TAMPERING_DETECTED
- ERROR_INJECTION_ATTEMPT
- ERROR_CONNECTION_TERMINATE

### Recoverable Errors (Retry/Recovery)
- ERROR_SYNC_FAILED
- ERROR_TIMEOUT
- ERROR_DISCOVERY_FAILED
- ERROR_FRAGMENT_REASSEMBLY_FAILED
- ERROR_TIME_SYNC_REQUEST_FAILED
- ERROR_TIME_SYNC_RESPONSE_FAILED
- ERROR_RECOVERY_REQUEST_FAILED
- ERROR_REKEY_REQUEST_FAILED
- ERROR_REKEY_RESPONSE_FAILED
- ERROR_REPAIR_REQUEST_FAILED
- ERROR_REPAIR_RESPONSE_FAILED
- ERROR_DISCOVERY_REQUEST_FAILED
- ERROR_DISCOVERY_RESPONSE_FAILED
- ERROR_DISCOVERY_CONFIRM_FAILED

### State-Dependent Errors
- ERROR_STATE_INVALID
- ERROR_SEQUENCE_INVALID
- ERROR_WINDOW_OVERFLOW
- ERROR_SEQUENCE_NEGOTIATION_FAILED
- ERROR_ZERO_WINDOW_DEADLOCK
- ERROR_WINDOW_UPDATE_FAILED

### Security-Related Errors
- ERROR_REPLAY_ATTACK
- ERROR_TIMESTAMP_INVALID
- ERROR_PSK_ENUMERATION_ATTEMPT
- ERROR_FRAGMENT_OVERLAP
- ERROR_FRAGMENT_BOMB
- ERROR_RATE_LIMITED
- ERROR_ENUMERATION_DETECTED
- ERROR_INJECTION_ATTEMPT
- ERROR_TAMPERING_DETECTED

### Multi-Connection Errors
- ERROR_PORT_COLLISION
- ERROR_SESSION_ID_COLLISION
- ERROR_CONNECTION_LIMIT_EXCEEDED

### Fragmentation Errors
- ERROR_FRAGMENT_TIMEOUT
- ERROR_FRAGMENT_OVERLAP
- ERROR_FRAGMENT_BOMB