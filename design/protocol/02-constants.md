# Protocol Constants and Default Values

## Overview

This document defines all constant values, timing parameters, and default configurations used throughout the protocol implementation. These constants establish the fundamental operational parameters that ensure consistent behavior across all protocol components.

## Purpose and Rationale

Constants serve several critical functions in the protocol:

- **Timing Synchronization**: Establishes precise timing windows for port hopping and time synchronization
- **Performance Tuning**: Defines optimal values for flow control, congestion control, and network adaptation
- **Security Parameters**: Sets authentication timeouts, replay protection windows, and cryptographic constraints
- **Reliability Boundaries**: Configures retry limits, timeout values, and failure detection thresholds
- **Resource Management**: Controls buffer sizes, queue lengths, and memory allocation limits

These values have been carefully chosen based on network performance analysis, security requirements, and real-world deployment considerations.

## Key Concepts

- **Time Windows**: 250ms intervals that synchronize port hopping across all peers
- **Adaptive Parameters**: Constants that enable dynamic adjustment to network conditions
- **Security Boundaries**: Timing and size limits that prevent attacks and ensure authenticity
- **Performance Tuning**: Values optimized for throughput, latency, and resource utilization
- **Compatibility Ranges**: Minimum and maximum values that maintain protocol interoperability

## Core Protocol Constants

```pseudocode
// Protocol structure constants
OPTIMIZED_COMMON_HEADER_SIZE = 50        // Optimized header size in bytes (used in: packet-structure.md, fragmentation.md)
FRAGMENT_HEADER_SIZE = 8                 // Fragment header size in bytes (used in: fragmentation.md)

// Time-related constants  
HOP_INTERVAL_MS = 250                    // Port hop interval in milliseconds (250ms time windows - used in: port-hopping.md, time-sync.md)
TIME_SYNC_TOLERANCE_MS = 50              // Maximum allowed clock drift (used in: time-sync.md)
HEARTBEAT_INTERVAL_MS = 30000            // Heartbeat interval (30 seconds - used in: timeout-handling.md)
HEARTBEAT_TIMEOUT_MS = 90000             // Heartbeat timeout (90 seconds - used in: timeout-handling.md)
MAX_PACKET_LIFETIME_MS = 60000           // Maximum packet age (60 seconds - used in: timeout-handling.md)
TIMESTAMP_WINDOW_MS = 30000              // Anti-replay timestamp window (used in: crypto.md)
SAFETY_MARGIN_MS = 100                   // Safety margin for delay calculations
BASE_TRANSMISSION_DELAY_ALLOWANCE_MS = 1000 // Base allowance for network transmission delay
ADAPTIVE_DELAY_WINDOW_MIN = 1            // Minimum delay window size (time windows - used in: delay-tuning.md)
ADAPTIVE_DELAY_WINDOW_MAX = 16           // Maximum delay window size (time windows - used in: delay-tuning.md)
DELAY_MEASUREMENT_SAMPLES = 10           // Number of samples for delay measurement (used in: delay-tuning.md)
DELAY_NEGOTIATION_INTERVAL_MS = 60000    // Delay parameters negotiation interval (1 minute - used in: delay-tuning.md)
DELAY_PERCENTILE_TARGET = 95             // Target percentile for delay allowance (95th percentile - used in: delay-tuning.md)
BASE_HEARTBEAT_PAYLOAD_SIZE = 8          // Size of base heartbeat payload (bytes)
MILLISECONDS_PER_DAY = 86400000          // Milliseconds in a day (for timestamp calculation)

// Sequence and window constants
SEQUENCE_NEGOTIATION_TIMEOUT_MS = 10000  // Sequence number negotiation timeout (used in: sequence-negotiation.md)
SEQUENCE_COMMITMENT_SIZE = 32            // Size of sequence number commitment in bytes (used in: sequence-negotiation.md)
SEQUENCE_NONCE_SIZE = 16                 // Size of sequence negotiation nonce in bytes (used in: sequence-negotiation.md)
MAX_SEQUENCE_NUMBER = 0xFFFFFFFF         // Maximum sequence number (used in: sequence-negotiation.md)
SEQUENCE_WRAP_THRESHOLD = 0x80000000     // Threshold for sequence wraparound (used in: sequence-negotiation.md)
SEQUENCE_WINDOW_SIZE = 1000              // Sequence number acceptance window (used in: recovery.md)
INITIAL_CONGESTION_WINDOW = 1460         // Initial congestion window (bytes - used in: flow-control.md)
MIN_CONGESTION_WINDOW = 292              // Minimum congestion window (bytes - used in: flow-control.md)
MAX_CONGESTION_WINDOW = 65535            // Maximum congestion window (bytes - used in: flow-control.md)
INITIAL_RECEIVE_WINDOW = 65535           // Initial receive window (bytes - used in: flow-control.md)
MAX_RECEIVE_WINDOW = 65535               // Maximum receive window (bytes)

// Retransmission and timeout constants
MIN_RETRANSMISSION_TIMEOUT_MS = 200      // Minimum RTO
MAX_RETRANSMISSION_TIMEOUT_MS = 60000    // Maximum RTO
ACK_DELAY_MS = 50                        // ACK delay for batching
MAX_ACK_BATCH_SIZE = 10                  // Maximum ACKs per batch
CONNECTION_TIMEOUT_MS = 30000            // Connection establishment timeout
STATE_TIMEOUT_MS = 30000                 // State transition timeout
TIME_WAIT_TIMEOUT_MS = 60000             // TIME_WAIT state timeout

// RTO calculation constants (RFC 6298)
RTT_ALPHA = 0.875                        // RTT smoothing factor
RTT_BETA = 0.125                         // RTT variance factor
RTT_G = 0.25                             // RTT gain factor
RTT_K = 4                                // RTT variance multiplier
RTT_INITIAL_MS = 1000                    // Initial RTT estimate
RTT_MIN_MS = 100                         // Minimum RTT
RTT_MAX_MS = 60000                       // Maximum RTT

// Buffer and memory constants
REORDER_BUFFER_SIZE = 1000               // Maximum out-of-order packets
RECENT_SEQUENCES_SIZE = 100              // Recent sequence number cache
RECENT_TIMESTAMPS_SIZE = 1000            // Recent timestamp cache for replay detection
PORT_HISTORY_SIZE = 10                   // Number of recent ports to track

// Retry and attempt limits
MAX_RETRANSMISSION_ATTEMPTS = 8          // Maximum retransmission attempts
MAX_RECOVERY_ATTEMPTS = 5                // Maximum recovery attempts
MAX_SYNC_FAILURES = 3                    // Maximum sync failures before emergency

// Port and network constants
MIN_PORT = 1024                          // Minimum port (expanded range)
MAX_PORT = 65535                         // Maximum port
PORT_RANGE = 64512                       // Available port range (65535-1024+1)
PORT_OFFSET_RANGE = 16128                // Port offset range (PORT_RANGE / 4)
MAX_CONNECTION_OFFSET = 4095             // Maximum offset value (12-bit)
DISCOVERY_PORT = 1025                   // Well-known port for discovery process
DEFAULT_MTU = 1500                       // Default MTU size
FRAGMENTATION_THRESHOLD = 1400           // Size threshold for fragmentation
MAX_FRAGMENTS = 255                      // Maximum fragments per packet

// Congestion control constants
SLOW_START_THRESHOLD = 65535             // Initial slow start threshold
CONGESTION_AVOIDANCE_INCREMENT = 1       // Window increment in congestion avoidance
FAST_RECOVERY_MULTIPLIER = 0.5          // Window reduction in fast recovery
MSS = 1460                               // Maximum segment size in bytes
MAX_CONGESTION_WINDOW = 65535            // Maximum congestion window size
MIN_CONGESTION_WINDOW = 292              // Minimum congestion window size
MAX_RECEIVE_WINDOW = 65535               // Maximum receive window size
MIN_RECEIVE_WINDOW = 1024                // Minimum receive window size

// Congestion control states
SLOW_START = 1                           // Slow start state
CONGESTION_AVOIDANCE = 2                 // Congestion avoidance state
FAST_RECOVERY = 3                        // Fast recovery state

// Discovery and zero-knowledge proof constants
MAX_PSK_COUNT = 256                     // Maximum number of PSKs per peer
DISCOVERY_TIMEOUT_MS = 10000            // Discovery process timeout (10 seconds)
DISCOVERY_RETRY_COUNT = 3               // Maximum discovery retry attempts
PEDERSEN_COMMITMENT_SIZE = 64           // Size of Pedersen commitment in bytes
DISCOVERY_CHALLENGE_SIZE = 32           // Size of challenge nonce in bytes
PSK_ID_LENGTH = 32                      // Length of PSK identifier
FRAGMENT_TIMEOUT_MS = 30000             // Fragment reassembly timeout (30 seconds - used in: fragmentation.md, timeout-handling.md)
BLOCK_DURATION_MS = 300000              // Block duration for enumeration attempts (5 minutes)
REPLAY_THRESHOLD = 5                    // Threshold for replay attack detection

// Recovery timeout constants
RECOVERY_TIMEOUT_MS = 15000             // Recovery process timeout (15 seconds)
RECOVERY_RETRY_INTERVAL_MS = 2000       // Interval between recovery attempts
RECOVERY_MAX_ATTEMPTS = 3               // Maximum recovery attempts before failure
TIME_RESYNC_TIMEOUT_MS = 5000           // Time resynchronization timeout
SEQUENCE_REPAIR_TIMEOUT_MS = 8000       // Sequence repair timeout
EMERGENCY_RECOVERY_TIMEOUT_MS = 30000   // Emergency recovery timeout
REKEY_TIMEOUT_MS = 10000                // Session rekey timeout

// Fragmentation constants
MAX_FRAGMENT_SIZE = 1400                // Maximum fragment payload size (bytes)
FRAGMENT_REASSEMBLY_BUFFER_SIZE = 64    // Maximum fragments in reassembly buffer
FRAGMENT_ID_SPACE = 0xFFFF              // Fragment ID space (16-bit)
FRAGMENT_DUPLICATE_WINDOW = 100         // Window for detecting duplicate fragments

// Flow control constants
INITIAL_SEND_WINDOW = 8192              // Initial send window size (bytes)
INITIAL_RECEIVE_WINDOW = 16384          // Initial receive window size (bytes)
WINDOW_SCALE_FACTOR = 1                 // Window scaling factor
WINDOW_UPDATE_THRESHOLD = 0.5           // Threshold for sending window updates (fraction)
ZERO_WINDOW_PROBE_INTERVAL_MS = 5000    // Zero window probe interval
WINDOW_TIMEOUT_MS = 60000               // Window timeout for flow control

// Discovery states
DISCOVERY_IDLE = 0                      // No discovery in progress
DISCOVERY_INITIATED = 1                 // Discovery initiated, waiting for response
DISCOVERY_RESPONDED = 2                 // Discovery response received, waiting for confirmation
DISCOVERY_COMPLETED = 3                 // Discovery completed, PSK selected
DISCOVERY_FAILED = 4                    // Discovery failed, no common PSK found
```