# Complete Timeout Handling and RTO Calculation Specification

## Overview

This document defines comprehensive timeout handling mechanisms and Retransmission Timeout (RTO) calculation algorithms that ensure reliable packet delivery while adapting to network conditions. The timeout system provides the foundation for detecting packet loss and triggering appropriate recovery actions.

## Purpose and Rationale

Timeout handling is crucial for protocol reliability and performance:

- **Reliability**: Detects packet loss and triggers retransmission to ensure data delivery
- **Adaptation**: Adjusts timeout values based on measured network characteristics
- **Efficiency**: Minimizes unnecessary retransmissions while ensuring timely loss detection
- **Responsiveness**: Quickly detects connectivity issues and triggers recovery mechanisms
- **Network Awareness**: Adapts to varying network conditions including latency and jitter

The RTO calculation algorithm balances quick loss detection with avoiding spurious retransmissions, using proven statistical methods to estimate appropriate timeout values.

## Key Concepts

- **Retransmission Timeout (RTO)**: Calculated timeout for retransmitting unacknowledged packets
- **Round-Trip Time (RTT)**: Measured time for packet to reach destination and return acknowledgment
- **RTT Variation (RTTVAR)**: Statistical measure of RTT consistency used for timeout calculation
- **Exponential Backoff**: Progressive timeout increase for repeated retransmissions
- **Adaptive Timeouts**: Dynamic adjustment based on network performance measurements

## Timeout Constants
```pseudocode
// Time-related constants
HOP_INTERVAL_MS = 250                    // Port hop interval in milliseconds (250ms time windows)
TIME_SYNC_TOLERANCE_MS = 50              // Maximum allowed clock drift
HEARTBEAT_INTERVAL_MS = 30000            // Heartbeat interval (30 seconds)
HEARTBEAT_TIMEOUT_MS = 90000             // Heartbeat timeout (90 seconds)
MAX_PACKET_LIFETIME_MS = 60000           // Maximum packet age (60 seconds)
TIMESTAMP_WINDOW_MS = 30000              // Anti-replay timestamp window
SAFETY_MARGIN_MS = 100                   // Safety margin for delay calculations
BASE_TRANSMISSION_DELAY_ALLOWANCE_MS = 1000 // Base allowance for network transmission delay

// Sequence and negotiation timeouts
SEQUENCE_NEGOTIATION_TIMEOUT_MS = 10000  // Sequence number negotiation timeout

// Retransmission and timeout constants
MIN_RETRANSMISSION_TIMEOUT_MS = 200      // Minimum RTO
MAX_RETRANSMISSION_TIMEOUT_MS = 60000    // Maximum RTO
ACK_DELAY_MS = 50                        // ACK delay for batching
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

// Discovery and fragment timeouts
DISCOVERY_TIMEOUT_MS = 10000            // Discovery process timeout (10 seconds)
FRAGMENT_TIMEOUT_MS = 30000             // Fragment reassembly timeout (30 seconds)

// Recovery timeout constants
RECOVERY_TIMEOUT_MS = 15000             // Recovery process timeout (15 seconds)
TIME_RESYNC_TIMEOUT_MS = 5000           // Time resynchronization timeout
SEQUENCE_REPAIR_TIMEOUT_MS = 8000       // Sequence repair timeout
EMERGENCY_RECOVERY_TIMEOUT_MS = 30000   // Emergency recovery timeout
REKEY_TIMEOUT_MS = 10000                // Session rekey timeout

// Flow control timeouts
ZERO_WINDOW_PROBE_INTERVAL_MS = 5000    // Zero window probe interval
WINDOW_TIMEOUT_MS = 60000               // Window timeout for flow control
```

## RTO Calculation Specification (RFC 6298)

### Complete RTO Calculation Algorithm
```pseudocode
// RTO state variables
rtt_srtt = RTT_INITIAL_MS        // Smoothed RTT
rtt_rttvar = RTT_INITIAL_MS / 2  // RTT variation
rtt_rto = RTT_INITIAL_MS         // Retransmission timeout

function calculate_rtt(send_time, ack_time):
    # Calculate RTT from send time to acknowledgment time
    rtt_sample = ack_time - send_time
    
    # Ensure RTT is within valid range
    if rtt_sample < RTT_MIN_MS:
        rtt_sample = RTT_MIN_MS
    elif rtt_sample > RTT_MAX_MS:
        rtt_sample = RTT_MAX_MS
    
    return rtt_sample

function update_rto(rtt_sample):
    # Update RTO using RFC 6298 algorithm
    
    if rtt_srtt == RTT_INITIAL_MS:
        # First RTT measurement
        rtt_srtt = rtt_sample
        rtt_rttvar = rtt_sample / 2
    else:
        # Update smoothed RTT
        rtt_rttvar = (1 - RTT_BETA) * rtt_rttvar + RTT_BETA * abs(rtt_sample - rtt_srtt)
        rtt_srtt = (1 - RTT_ALPHA) * rtt_srtt + RTT_ALPHA * rtt_sample
    
    # Calculate RTO
    rtt_rto = rtt_srtt + RTT_K * rtt_rttvar
    
    # Ensure RTO is within bounds
    if rtt_rto < MIN_RETRANSMISSION_TIMEOUT_MS:
        rtt_rto = MIN_RETRANSMISSION_TIMEOUT_MS
    elif rtt_rto > MAX_RETRANSMISSION_TIMEOUT_MS:
        rtt_rto = MAX_RETRANSMISSION_TIMEOUT_MS
    
    return rtt_rto

function handle_retransmission_timeout():
    # Handle RTO expiration - exponential backoff
    rtt_rto = min(rtt_rto * 2, MAX_RETRANSMISSION_TIMEOUT_MS)
    
    # Reset RTT measurement on timeout
    rtt_srtt = RTT_INITIAL_MS
    rtt_rttvar = RTT_INITIAL_MS / 2
    
    return rtt_rto

function get_current_rto():
    # Get current RTO value
    return rtt_rto

function reset_rto():
    # Reset RTO to initial values
    rtt_srtt = RTT_INITIAL_MS
    rtt_rttvar = RTT_INITIAL_MS / 2
    rtt_rto = RTT_INITIAL_MS
```

## Additional Timeout Specifications

```pseudocode
# Connection establishment timeouts
CONNECTION_TIMEOUT_MS = 30000           // Maximum time for connection establishment
HANDSHAKE_TIMEOUT_MS = 15000            // Handshake completion timeout
PEER_RESPONSE_TIMEOUT_MS = 10000        // Generic peer response timeout

# Session management timeouts
SESSION_IDLE_TIMEOUT_MS = 300000        // Session idle timeout (5 minutes)
SESSION_CLEANUP_INTERVAL_MS = 60000     // Session cleanup check interval
SESSION_GRACE_PERIOD_MS = 30000         // Grace period before session cleanup

# Data transmission timeouts
DATA_TRANSMISSION_TIMEOUT_MS = 5000     // Data packet transmission timeout
ACK_TIMEOUT_MS = 1000                   // ACK generation timeout
REORDER_TIMEOUT_MS = 3000               // Out-of-order packet timeout
RETRANSMIT_TIMEOUT_MS = 2000            // Base retransmission timeout

# Protocol-specific timeouts
PORT_HOP_TRANSITION_MS = 50             // Port hop transition window
TIME_WINDOW_TOLERANCE_MS = 100          // Time window boundary tolerance
CRYPTO_OPERATION_TIMEOUT_MS = 1000      // Cryptographic operation timeout

# System resource timeouts
MEMORY_CLEANUP_INTERVAL_MS = 120000     // Memory cleanup interval (2 minutes)
STATS_COLLECTION_INTERVAL_MS = 60000    // Statistics collection interval
HEALTH_CHECK_INTERVAL_MS = 30000        // Health check interval


function handle_connection_timeout(context):
    session_id = context.session_id
    
    # Log timeout event
    log_timeout_event("Connection establishment timeout", session_id)
    
    # Clean up connection state
    cleanup_connection_state(session_id)
    
    # Notify application of connection failure
    notify_application(CONNECTION_FAILED, session_id)

function handle_session_idle_timeout(context):
    session_id = context.session_id
    last_activity = context.last_activity_time
    current_time = get_current_time_ms()
    
    if (current_time - last_activity) > SESSION_IDLE_TIMEOUT_MS:
        # Send session termination notice
        send_session_termination(session_id, "Idle timeout")
        
        # Clean up session
        cleanup_session(session_id)
        
        log_session_event("Session terminated due to idle timeout", session_id)

function schedule_timeout(timeout_type, delay_ms, context):
    timeout_event = {
        'type': timeout_type,
        'expiry_time': get_current_time_ms() + delay_ms,
        'context': context
    }
    
    add_to_timeout_queue(timeout_event)

function process_timeout_queue():
    current_time = get_current_time_ms()
    expired_timeouts = []
    
    for timeout_event in timeout_queue:
        if current_time >= timeout_event.expiry_time:
            expired_timeouts.append(timeout_event)
    
    for timeout_event in expired_timeouts:
        handle_timeout_event(timeout_event.type, timeout_event.context)
        remove_from_timeout_queue(timeout_event)
```

## Timeout Error Handling

```pseudocode
function handle_timeout_error(error_details):
    # Handle timeout errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Implement exponential backoff
        backoff_time = calculate_backoff_time(error_recovery_state['retry_count'])
        schedule_retry(backoff_time)
        error_recovery_state['retry_count'] += 1
    else:
        # Maximum retries exceeded
        log_critical_error("Maximum timeout retries exceeded", error_details)
        transition_to(ERROR)

function calculate_backoff_time(retry_count):
    # Exponential backoff with jitter
    base_time = 1000 * (2 ** retry_count)  # Base exponential backoff
    jitter = random(0, base_time * 0.1)    # Add 10% jitter
    return min(base_time + jitter, MAX_RETRANSMISSION_TIMEOUT_MS)

function calculate_discovery_backoff(retry_count):
    # Discovery-specific backoff
    base_time = 5000 * (2 ** retry_count)
    return min(base_time, DISCOVERY_TIMEOUT_MS)
```

## Specialized Timeout Handling

### Sequence Negotiation Timeout
```pseudocode
function handle_sequence_negotiation_timeout():
    # Cleanup negotiation state
    clear_negotiation_buffers()
    secure_zero_sequence_material()
    
    # Retry with exponential backoff
    if negotiation_attempts < MAX_NEGOTIATION_ATTEMPTS:
        negotiation_attempts += 1
        backoff_time = SEQUENCE_NEGOTIATION_TIMEOUT_MS * (2 ** negotiation_attempts)
        
        schedule_timeout(SEQUENCE_NEGOTIATION_RETRY, backoff_time, session_context)
    else:
        log_error("Sequence negotiation failed after maximum attempts")
        return ERROR_SEQUENCE_NEGOTIATION_TIMEOUT
```

### Fragment Timeout Handling
```pseudocode
function handle_fragment_packet(fragment_packet):
    fragment_id = fragment_packet.fragment_id
    current_time = get_current_time_ms()
    
    if fragment_id not in fragment_buffers:
        fragment_buffers[fragment_id] = {
            'fragments': [None] * total_fragments,
            'total_fragments': total_fragments,
            'received_count': 0,
            'timer': current_time + FRAGMENT_TIMEOUT_MS
        }
    
    buffer = fragment_buffers[fragment_id]
    
    # Store fragment and update timeout
    if buffer['fragments'][fragment_index] == None:
        buffer['fragments'][fragment_index] = fragment_packet
        buffer['received_count'] += 1
        
        if buffer['received_count'] == buffer['total_fragments']:
            # Complete reassembly
            reassembled_data = reassemble_fragments(buffer['fragments'])
            deliver_to_application(reassembled_data)
            del fragment_buffers[fragment_id]
        else:
            # Extend timer
            buffer['timer'] = current_time + FRAGMENT_TIMEOUT_MS

function cleanup_expired_fragments():
    current_time = get_current_time_ms()
    expired_buffers = []
    
    for fragment_id, buffer in session_state.reassembly_buffers.items():
        if current_time > buffer.timeout:
            expired_buffers.append(fragment_id)
    
    for fragment_id in expired_buffers:
        buffer = session_state.reassembly_buffers[fragment_id]
        log_fragment_timeout(fragment_id, buffer.received_count, buffer.total_fragments)
        
        # Request retransmission if we have some fragments
        if buffer.received_count > 0:
            request_fragment_retransmission(fragment_id, buffer)
        
        # Clean up expired buffer
        del session_state.reassembly_buffers[fragment_id]

function send_fragmented_packet(packet_data):
    fragments = create_fragments(packet_data)
    
    for fragment in fragments:
        send_packet(fragment)
        
        # Add inter-fragment delay for pacing
        if fragment != fragments[-1]:  # Don't delay after last fragment
            wait(fragment_interval)
    
    # Set fragment reassembly timeout
    fragment_timeout = get_current_time_ms() + FRAGMENT_TIMEOUT_MS
    track_fragment_transmission(fragments[0].fragment_id, fragment_timeout)
```

### Window Timeout Handling
```pseudocode
function handle_window_timeout():
    # Handle case where no window updates received
    current_time = get_current_time_ms()
    
    if current_time - flow_control_state.last_window_update > WINDOW_TIMEOUT_MS:
        # Window timeout - probe peer
        send_window_probe()
        
        # Reduce congestion window to prevent overwhelming peer
        session_state.congestion_window = max(
            session_state.congestion_window / 2,
            MIN_CONGESTION_WINDOW
        )
```