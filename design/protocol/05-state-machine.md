# Complete State Machine Specification

## Overview

This document defines the complete state machine that governs protocol connection lifecycle, session management, and state transitions. The state machine ensures deterministic behavior and proper sequencing of protocol operations throughout the connection lifetime.

## Purpose and Rationale

The state machine provides essential structure for protocol operations:

- **Connection Lifecycle Management**: Defines clear phases from connection establishment to termination
- **Error Recovery Coordination**: Manages state transitions during various recovery scenarios
- **Security State Tracking**: Maintains cryptographic and authentication state throughout the session
- **Resource Management**: Controls when resources are allocated, used, and cleaned up
- **Concurrency Control**: Ensures thread-safe state transitions in multi-threaded implementations

The state machine design prevents invalid state transitions and ensures that protocol operations occur in the correct sequence, maintaining both security and reliability.

## Key Concepts

- **Connection States**: Discrete phases of connection lifecycle (CLOSED, CONNECTING, ESTABLISHED, etc.)
- **State Transitions**: Controlled changes between states triggered by events or conditions  
- **State Variables**: Data that persists across the connection and influences state behavior
- **Event Handling**: Processing of packets, timeouts, and user actions that drive state changes
- **Recovery States**: Special states for handling various failure and recovery scenarios

## Session State Variables
```pseudocode
// Session state variables for flow control and congestion control
session_state = {
    // Connection state
    'state': CLOSED,
    'session_id': 0,
    'session_key': None,
    'daily_key': None,
    
    // Sequence numbers
    'send_sequence': INITIAL_SEQUENCE_NUMBER,
    'receive_sequence': 0,
    'send_unacked': 0,
    'send_next': 0,
    'receive_next': 0,
    
    // Flow control
    'send_window': INITIAL_CONGESTION_WINDOW,
    'receive_window': INITIAL_RECEIVE_WINDOW,
    'congestion_window': INITIAL_CONGESTION_WINDOW,
    'slow_start_threshold': SLOW_START_THRESHOLD,
    'congestion_state': SLOW_START,
    
    // Buffers
    'send_buffer': [],
    'receive_buffer': [],
    'reorder_buffer': [],
    
    // Timing
    'rtt_srtt': RTT_INITIAL_MS,
    'rtt_rttvar': RTT_INITIAL_MS / 2,
    'rtt_rto': RTT_INITIAL_MS,
    'last_ack_time': 0,
    
    // Port hopping
    'current_port': 0,
    'port_history': [],
    'time_offset': 0,
    
    // Discovery
    'discovery_state': DISCOVERY_IDLE,
    'discovered_psk': None,
    'discovery_id': 0,
    'challenge_nonce': 0,
    'response_nonce': 0,
    
    // Error handling
    'retry_count': 0,
    'last_error': None,
    'recovery_attempts': 0
}
```

## Simplified Session States with Enhanced Recovery
```pseudocode
Session States:
- CLOSED: No session exists
- CONNECTING: Client attempting connection (includes discovery if needed)
- LISTENING: Server waiting for connection
- ESTABLISHED: Connection active, data flowing
- CLOSING: Connection termination in progress
- RECOVERING: Connection recovery in progress
- ERROR: Error state, connection should be closed

// Recovery states (sub-states within main states)
Recovery Sub-States:
- NORMAL: Normal operation
- RESYNC: Time synchronization recovery
- REKEY: Session key rotation/recovery
- REPAIR: Connection repair (sequence number recovery)
- EMERGENCY: Emergency recovery mode
```

## Simplified State Transitions with Integrated Recovery
```pseudocode
// Core state transitions with automatic recovery
CLOSED -> CONNECTING: connect() [Start connection with discovery if needed]
CLOSED -> LISTENING: bind() [Start listening for connections]

CONNECTING -> ESTABLISHED: connection_established() [Normal connection]
CONNECTING -> CLOSED: connection_failed() [Connection failed after retries]
CONNECTING -> RECOVERING: connection_recovery_needed() [Recovery required]

LISTENING -> ESTABLISHED: connection_established() [Normal connection]
LISTENING -> CLOSED: timeout() or error [Listen timeout or error]

ESTABLISHED -> CLOSING: close_requested() [Normal close]
ESTABLISHED -> RECOVERING: recovery_triggered() [Recovery needed]
ESTABLISHED -> ERROR: critical_error() [Critical error]

CLOSING -> CLOSED: close_completed() [Normal close completion]
CLOSING -> RECOVERING: close_recovery_needed() [Close recovery needed]

RECOVERING -> ESTABLISHED: recovery_success() [Recovery successful]
RECOVERING -> CLOSED: recovery_failed() [Recovery failed after attempts]
RECOVERING -> ERROR: recovery_critical_failure() [Critical recovery failure]

ERROR -> CLOSED: cleanup() [Immediate cleanup]

// Recovery sub-state transitions (within main states)
NORMAL -> RESYNC: time_drift_detected() [Time synchronization needed]
NORMAL -> REKEY: key_rotation_needed() [Session key rotation needed]
NORMAL -> REPAIR: sequence_mismatch() [Sequence number repair needed]
NORMAL -> EMERGENCY: critical_failure() [Emergency recovery needed]

RESYNC -> NORMAL: time_sync_completed() [Time sync successful]
REKEY -> NORMAL: key_rotation_completed() [Key rotation successful]
REPAIR -> NORMAL: sequence_repair_completed() [Sequence repair successful]
EMERGENCY -> NORMAL: emergency_recovery_completed() [Emergency recovery successful]
```

## Invalid State Packet Handling
```pseudocode
function handle_packet_in_invalid_state(packet, current_state):
    switch current_state:
        case CLOSED:
            if packet.type == PACKET_TYPE_SYN:
                # Passive open - transition to SYN_RECEIVED
                return handle_syn_in_closed_state(packet)
            else:
                send_rst_packet(packet.session_id)
                return ERROR_STATE_INVALID
                
        case LISTENING:
            if packet.type == PACKET_TYPE_SYN:
                return handle_syn_in_listening_state(packet)
            else:
                send_rst_packet(packet.session_id)
                return ERROR_STATE_INVALID
                
        case CONNECTING:
            if packet.type == PACKET_TYPE_SYN:
                # Simultaneous open
                send_syn_ack_packet(packet.session_id)
                return SUCCESS
            elif packet.type == PACKET_TYPE_SYN_ACK:
                return handle_syn_ack_in_connecting_state(packet)
            else:
                send_rst_packet(packet.session_id)
                return ERROR_STATE_INVALID
                
        case ESTABLISHED:
            if packet.type == PACKET_TYPE_DATA:
                return handle_data_in_established_state(packet)
            elif packet.type == PACKET_TYPE_ACK:
                return handle_ack_in_established_state(packet)
            elif packet.type == PACKET_TYPE_FIN:
                return handle_fin_in_established_state(packet)
            else:
                send_error_packet(packet.session_id, ERROR_STATE_INVALID)
                return ERROR_STATE_INVALID
                
        # Handle other states similarly...
        
    return ERROR_STATE_INVALID
```