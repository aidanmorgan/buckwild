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
ERROR_ZERO_KNOWLEDGE_PROOF_FAILED = 0x14
ERROR_DISCOVERY_TIMEOUT = 0x15
ERROR_PEDERSEN_COMMITMENT_FAILED = 0x16
ERROR_PSK_ENUMERATION_ATTEMPT = 0x17
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
| 0x14 | ERROR_ZERO_KNOWLEDGE_PROOF_FAILED | Zero-knowledge proof verification failed |
| 0x15 | ERROR_DISCOVERY_TIMEOUT | Discovery process timed out |
| 0x16 | ERROR_PEDERSEN_COMMITMENT_FAILED | Pedersen commitment verification failed |
| 0x17 | ERROR_PSK_ENUMERATION_ATTEMPT | Detected PSK enumeration attack |

## Error Handling Guidelines

### Critical Errors (Connection Termination)
- ERROR_AUTHENTICATION_FAILED
- ERROR_PSK_NOT_FOUND
- ERROR_PSK_ENUMERATION_ATTEMPT
- ERROR_ZERO_KNOWLEDGE_PROOF_FAILED

### Recoverable Errors (Retry/Recovery)
- ERROR_SYNC_FAILED
- ERROR_TIMEOUT
- ERROR_DISCOVERY_FAILED
- ERROR_FRAGMENT_REASSEMBLY_FAILED

### State-Dependent Errors
- ERROR_STATE_INVALID
- ERROR_SEQUENCE_INVALID
- ERROR_WINDOW_OVERFLOW

### Security-Related Errors
- ERROR_REPLAY_ATTACK
- ERROR_TIMESTAMP_INVALID
- ERROR_PSK_ENUMERATION_ATTEMPT