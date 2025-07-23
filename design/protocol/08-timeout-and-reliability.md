# Timeout Handling and Reliability Mechanisms

This document defines comprehensive timeout handling and Retransmission Timeout (RTO) calculation algorithms that ensure reliable packet delivery while adapting to varying network conditions and maintaining protocol responsiveness.

## Overview

The timeout and reliability framework provides the foundation for detecting packet loss, triggering retransmissions, and maintaining connection health through adaptive timeout calculations and robust error recovery mechanisms.

## Purpose and Rationale

Timeout handling is crucial for protocol reliability and performance:

- **Reliability**: Detects packet loss and triggers retransmission to ensure guaranteed data delivery
- **Network Adaptation**: Adjusts timeout values based on measured network characteristics and performance
- **Efficiency**: Minimizes unnecessary retransmissions while ensuring timely loss detection and recovery
- **Responsiveness**: Quickly detects connectivity issues and triggers appropriate recovery mechanisms  
- **Network Awareness**: Adapts to varying network conditions including latency, jitter, and packet loss
- **Resource Management**: Prevents resource exhaustion through intelligent timeout management and cleanup

The RTO calculation algorithm balances quick loss detection with avoiding spurious retransmissions, using proven statistical methods to estimate appropriate timeout values based on RFC 6298.

## Key Concepts

- **Retransmission Timeout (RTO)**: Calculated timeout for retransmitting unacknowledged packets based on network measurements
- **Round-Trip Time (RTT)**: Measured time for packet to reach destination and return acknowledgment
- **RTT Variation (RTTVAR)**: Statistical measure of RTT consistency used for adaptive timeout calculation
- **Exponential Backoff**: Progressive timeout increase for repeated retransmissions to prevent congestion
- **Adaptive Timeouts**: Dynamic adjustment based on real-time network performance measurements
- **Timeout Hierarchies**: Different timeout categories for various protocol operations with appropriate escalation

## RTT Measurement and RTO Calculation (RFC 6298)

### RTT Measurement Infrastructure

```pseudocode
// RTO state variables for adaptive timeout calculation
rto_state = {
    'rtt_srtt': RTT_INITIAL_MS,           // Smoothed RTT estimate
    'rtt_rttvar': RTT_INITIAL_MS / 2,     // RTT variation estimate  
    'rtt_rto': RTT_INITIAL_MS,            // Current retransmission timeout
    'first_measurement': true,             // Flag for first RTT measurement
    'last_measurement_time': 0,            // Timestamp of last measurement
    'measurement_count': 0                 // Total number of measurements
}

function measure_rtt(send_time, ack_time):
    # Calculate RTT sample from send time to acknowledgment time
    rtt_sample = ack_time - send_time
    
    # Validate RTT sample within reasonable bounds
    if rtt_sample < RTT_MIN_MS:
        rtt_sample = RTT_MIN_MS
    elif rtt_sample > RTT_MAX_MS:
        rtt_sample = RTT_MAX_MS
    
    # Update measurement statistics
    rto_state.last_measurement_time = ack_time
    rto_state.measurement_count += 1
    
    return rtt_sample

function update_rto_with_measurement(rtt_sample):
    # Update RTO using RFC 6298 algorithm with measured RTT
    
    if rto_state.first_measurement:
        # First RTT measurement - initialize estimates
        rto_state.rtt_srtt = rtt_sample
        rto_state.rtt_rttvar = rtt_sample / 2
        rto_state.first_measurement = false
    else:
        # Update smoothed RTT and variation using exponential averaging
        # RTTVAR = (1 - β) * RTTVAR + β * |SRTT - R'|
        rtt_variation = abs(rtt_sample - rto_state.rtt_srtt)
        rto_state.rtt_rttvar = (1 - RTT_BETA) * rto_state.rtt_rttvar + RTT_BETA * rtt_variation
        
        # SRTT = (1 - α) * SRTT + α * R'
        rto_state.rtt_srtt = (1 - RTT_ALPHA) * rto_state.rtt_srtt + RTT_ALPHA * rtt_sample
    
    # Calculate RTO: RTO = SRTT + max(G, K * RTTVAR)
    rto_value = rto_state.rtt_srtt + max(RTT_G, RTT_K * rto_state.rtt_rttvar)
    
    # Ensure RTO is within acceptable bounds
    rto_state.rtt_rto = max(MIN_RETRANSMISSION_TIMEOUT_MS, 
                           min(rto_value, MAX_RETRANSMISSION_TIMEOUT_MS))
    
    return rto_state.rtt_rto

function handle_retransmission_timeout():
    # Handle RTO expiration with exponential backoff
    # Double the RTO for next retransmission attempt
    rto_state.rtt_rto = min(rto_state.rtt_rto * 2, MAX_RETRANSMISSION_TIMEOUT_MS)
    
    # Do not update SRTT/RTTVAR until a valid ACK is received
    # This prevents retransmitted packets from corrupting RTT estimates
    
    return rto_state.rtt_rto

function get_current_rto():
    # Get current RTO value for setting retransmission timers
    return rto_state.rtt_rto

function reset_rto_estimates():
    # Reset RTO to initial values (used after connection establishment)
    rto_state.rtt_srtt = RTT_INITIAL_MS
    rto_state.rtt_rttvar = RTT_INITIAL_MS / 2
    rto_state.rtt_rto = RTT_INITIAL_MS
    rto_state.first_measurement = true
    rto_state.measurement_count = 0
```

### Packet Timing and Retransmission Management

```pseudocode
// Packet timing tracking for RTT measurement
packet_timing_state = {
    'pending_packets': {},     // Packets awaiting acknowledgment
    'retransmission_timers': {},  // Active retransmission timers
    'retransmission_counts': {}   // Retry counts per packet
}

function send_packet_with_timing(packet):
    send_time = get_current_time_ms()
    packet_key = generate_packet_key(packet)
    
    # Track packet for RTT measurement
    packet_timing_state.pending_packets[packet_key] = {
        'packet': packet,
        'send_time': send_time,
        'sequence_number': packet.sequence_number,
        'retransmitted': false
    }
    
    # Set retransmission timer
    timeout_value = get_current_rto()
    set_retransmission_timer(packet_key, timeout_value)
    
    # Send the packet
    transmit_packet(packet)
    
    return SUCCESS

function handle_ack_packet(ack_packet):
    ack_sequence = ack_packet.acknowledgment_number
    ack_time = get_current_time_ms()
    
    # Find corresponding sent packet for RTT measurement
    acked_packets = find_acked_packets(ack_sequence)
    
    for packet_key in acked_packets:
        if packet_key in packet_timing_state.pending_packets:
            packet_info = packet_timing_state.pending_packets[packet_key]
            
            # Only measure RTT for non-retransmitted packets
            if not packet_info.retransmitted:
                rtt_sample = measure_rtt(packet_info.send_time, ack_time)
                update_rto_with_measurement(rtt_sample)
            
            # Clean up tracking
            cancel_retransmission_timer(packet_key)
            del packet_timing_state.pending_packets[packet_key]
            if packet_key in packet_timing_state.retransmission_counts:
                del packet_timing_state.retransmission_counts[packet_key]

function handle_retransmission_timer_expiry(packet_key):
    if packet_key not in packet_timing_state.pending_packets:
        return  # Packet already acknowledged
    
    packet_info = packet_timing_state.pending_packets[packet_key]
    
    # Increment retransmission count
    retry_count = packet_timing_state.retransmission_counts.get(packet_key, 0) + 1
    packet_timing_state.retransmission_counts[packet_key] = retry_count
    
    if retry_count >= MAX_RETRANSMISSION_ATTEMPTS:
        # Maximum retries exceeded - declare connection failed
        handle_connection_failure(packet_info.packet)
        return
    
    # Handle RTO timeout (exponential backoff)
    new_rto = handle_retransmission_timeout()
    
    # Mark packet as retransmitted (exclude from RTT measurement)
    packet_info.retransmitted = true
    packet_info.send_time = get_current_time_ms()
    
    # Retransmit the packet
    transmit_packet(packet_info.packet)
    
    # Set new retransmission timer
    set_retransmission_timer(packet_key, new_rto)

function set_retransmission_timer(packet_key, timeout_ms):
    # Set or update retransmission timer for packet
    expiry_time = get_current_time_ms() + timeout_ms
    packet_timing_state.retransmission_timers[packet_key] = expiry_time
    
    # Schedule timer callback
    schedule_timer_callback(expiry_time, handle_retransmission_timer_expiry, packet_key)

function cancel_retransmission_timer(packet_key):
    # Cancel retransmission timer for acknowledged packet
    if packet_key in packet_timing_state.retransmission_timers:
        del packet_timing_state.retransmission_timers[packet_key]
        cancel_timer_callback(packet_key)
```

## Specialized Timeout Management

### Connection and Session Timeouts

```pseudocode
function manage_connection_timeouts():
    # Comprehensive connection timeout management
    
    # Connection establishment timeout
    if session_state.state == CONNECTION_STATE_CONNECTING:
        time_since_start = get_current_time_ms() - session_state.connection_start_time
        if time_since_start > CONNECTION_TIMEOUT_MS:
            handle_connection_establishment_timeout()
    
    # Heartbeat timeout detection
    if session_state.state == CONNECTION_STATE_ESTABLISHED:
        time_since_heartbeat = get_current_time_ms() - session_state.last_heartbeat_time
        if time_since_heartbeat > HEARTBEAT_TIMEOUT_MS:
            handle_heartbeat_timeout()
    
    # Session idle timeout
    time_since_activity = get_current_time_ms() - session_state.last_packet_time
    if time_since_activity > SESSION_IDLE_TIMEOUT_MS:
        handle_session_idle_timeout()

function handle_connection_establishment_timeout():
    # Connection establishment took too long
    log_timeout_event("Connection establishment timeout", session_state.session_id)
    
    # Clean up connection state
    cleanup_connection_state()
    
    # Notify application layer
    notify_application_layer(CONNECTION_FAILED, "Connection timeout")
    
    # Transition to closed state
    transition_to_state(CONNECTION_STATE_CLOSED)

function handle_heartbeat_timeout():
    # No heartbeat received - connection may be dead
    log_warning("Heartbeat timeout detected", session_state.session_id)
    
    # Attempt connection recovery
    if session_state.consecutive_heartbeat_failures < MAX_HEARTBEAT_FAILURES:
        session_state.consecutive_heartbeat_failures += 1
        initiate_heartbeat_recovery()
    else:
        # Connection appears to be dead
        handle_connection_failure("Heartbeat timeout")

function handle_session_idle_timeout():
    # Session has been idle too long
    log_info("Session idle timeout", session_state.session_id)
    
    # Send graceful close
    initiate_graceful_close("Session idle timeout")
```

### Fragment Reassembly Timeouts

```pseudocode
function manage_fragment_timeouts():
    # Clean up expired fragment reassembly buffers
    current_time = get_current_time_ms()
    expired_buffers = []
    
    for fragment_id, buffer in session_state.reassembly_buffers.items():
        if current_time > buffer.timeout:
            expired_buffers.append(fragment_id)
    
    for fragment_id in expired_buffers:
        handle_fragment_timeout(fragment_id)

function handle_fragment_timeout(fragment_id):
    buffer = session_state.reassembly_buffers[fragment_id]
    
    log_fragment_timeout(fragment_id, buffer.received_count, buffer.total_fragments)
    
    # Request retransmission of missing fragments if we have partial data
    if buffer.received_count > 0 and buffer.received_count < buffer.total_fragments:
        request_fragment_retransmission(fragment_id, buffer)
    
    # Clean up expired buffer
    cleanup_reassembly_buffer(buffer)
    del session_state.reassembly_buffers[fragment_id]

function request_fragment_retransmission(fragment_id, buffer):
    # Identify missing fragments
    missing_fragments = []
    for i in range(buffer.total_fragments):
        if buffer.fragments[i] == null:
            missing_fragments.append(i)
    
    # Send retransmission request
    retrans_request = create_fragment_retrans_request(
        fragment_id = fragment_id,
        missing_fragment_indices = missing_fragments
    )
    
    send_packet(retrans_request)
    
    # Reset fragment timeout for another attempt
    buffer.timeout = get_current_time_ms() + FRAGMENT_TIMEOUT_MS

function set_fragment_reassembly_timeout(fragment_id):
    # Set timeout for fragment reassembly
    buffer = session_state.reassembly_buffers[fragment_id]
    buffer.timeout = get_current_time_ms() + FRAGMENT_TIMEOUT_MS
    
    # Schedule cleanup callback
    schedule_fragment_cleanup(fragment_id, buffer.timeout)
```

### Flow Control and Window Timeouts

```pseudocode
function manage_flow_control_timeouts():
    current_time = get_current_time_ms()
    
    # Zero window probe timeout
    if flow_control_state.send_window == 0:
        if current_time - flow_control_state.last_window_update > ZERO_WINDOW_PROBE_INTERVAL_MS:
            send_zero_window_probe()
    
    # General window timeout
    if current_time - flow_control_state.last_window_update > WINDOW_TIMEOUT_MS:
        handle_window_timeout()

function send_zero_window_probe():
    # Send minimal probe packet to test if window has opened
    probe_data = get_next_byte_to_send()
    if probe_data != null:
        probe_packet = create_data_packet(
            sequence_number = flow_control_state.send_next,
            data = probe_data,
            window_size = flow_control_state.advertised_window
        )
        
        send_packet(probe_packet)
        
        # Update probe timing with exponential backoff
        probe_interval = min(
            ZERO_WINDOW_PROBE_INTERVAL_MS * 2,
            MAX_ZERO_WINDOW_PROBE_INTERVAL_MS
        )
        schedule_next_zero_window_probe(probe_interval)

function handle_window_timeout():
    # Window timeout - peer may have failed to send updates
    log_warning("Window timeout detected", session_state.session_id)
    
    # Send window probe to elicit response
    send_window_probe()
    
    # Reduce congestion window as precaution
    congestion_control_state.congestion_window = max(
        congestion_control_state.congestion_window / 2,
        MIN_CONGESTION_WINDOW
    )
    
    # Reset window update timing
    flow_control_state.last_window_update = get_current_time_ms()
```

## Discovery and Recovery Timeouts

### PSK Discovery Timeouts

```pseudocode
function manage_discovery_timeouts():
    if session_state.discovery_state != DISCOVERY_SUB_STATE_IDLE:
        current_time = get_current_time_ms()
        discovery_duration = current_time - session_state.discovery_start_time
        
        if discovery_duration > DISCOVERY_TIMEOUT_MS:
            handle_discovery_timeout()

function handle_discovery_timeout():
    log_warning("PSK discovery timeout", session_state.discovery_id)
    
    # Check if we can retry discovery
    if session_state.discovery_retry_count < DISCOVERY_RETRY_COUNT:
        session_state.discovery_retry_count += 1
        
        # Calculate backoff time
        backoff_time = calculate_discovery_backoff(session_state.discovery_retry_count)
        
        # Schedule discovery retry
        schedule_discovery_retry(backoff_time)
    else:
        # Discovery failed after all retries
        handle_discovery_failure("Discovery timeout after maximum retries")

function calculate_discovery_backoff(retry_count):
    # Discovery-specific exponential backoff
    base_time = DISCOVERY_TIMEOUT_MS * (2 ** (retry_count - 1))
    jitter = random_uniform(0, base_time * 0.1)  # 10% jitter
    return min(base_time + jitter, MAX_DISCOVERY_TIMEOUT_MS)

function schedule_discovery_retry(delay_ms):
    # Schedule PSK discovery retry after delay
    retry_time = get_current_time_ms() + delay_ms
    schedule_timer_callback(retry_time, initiate_discovery_retry, session_state.session_id)
```

### Recovery Operation Timeouts

```pseudocode
function manage_recovery_timeouts():
    if session_state.sub_state != RECOVERY_SUB_STATE_NORMAL:
        current_time = get_current_time_ms()
        recovery_duration = current_time - session_state.last_recovery_time
        
        # Check specific recovery timeout
        timeout_limit = get_recovery_timeout_limit(session_state.sub_state)
        if recovery_duration > timeout_limit:
            handle_recovery_timeout(session_state.sub_state)

function get_recovery_timeout_limit(recovery_type):
    switch recovery_type:
        case RECOVERY_SUB_STATE_RESYNC:
            return TIME_RESYNC_TIMEOUT_MS
        case RECOVERY_SUB_STATE_REKEY:
            return REKEY_TIMEOUT_MS
        case RECOVERY_SUB_STATE_REPAIR:
            return SEQUENCE_REPAIR_TIMEOUT_MS
        case RECOVERY_SUB_STATE_EMERGENCY:
            return EMERGENCY_RECOVERY_TIMEOUT_MS
        default:
            return RECOVERY_TIMEOUT_MS

function handle_recovery_timeout(recovery_type):
    log_warning(f"Recovery timeout: {recovery_type}", session_state.session_id)
    
    # Check if we can escalate recovery
    if session_state.recovery_attempts < MAX_RECOVERY_ATTEMPTS:
        session_state.recovery_attempts += 1
        escalate_recovery_mechanism(recovery_type)
    else:
        # Recovery failed - transition to error state
        handle_recovery_failure(f"Recovery timeout after {MAX_RECOVERY_ATTEMPTS} attempts")

function escalate_recovery_mechanism(current_recovery_type):
    # Escalate to more aggressive recovery mechanism
    switch current_recovery_type:
        case RECOVERY_SUB_STATE_RESYNC:
            # Escalate time sync to rekey
            transition_to_recovery_sub_state(RECOVERY_SUB_STATE_REKEY)
            
        case RECOVERY_SUB_STATE_REKEY:
            # Escalate rekey to repair
            transition_to_recovery_sub_state(RECOVERY_SUB_STATE_REPAIR)
            
        case RECOVERY_SUB_STATE_REPAIR:
            # Escalate repair to emergency
            transition_to_recovery_sub_state(RECOVERY_SUB_STATE_EMERGENCY)
            
        case RECOVERY_SUB_STATE_EMERGENCY:
            # Emergency recovery failed - connection failure
            handle_connection_failure("Emergency recovery timeout")
```

## Timeout Error Handling and Backoff Strategies

### Exponential Backoff Implementation

```pseudocode
function calculate_exponential_backoff(retry_count, base_timeout, max_timeout):
    # Calculate exponential backoff with jitter
    exponential_component = base_timeout * (2 ** retry_count)
    jitter_range = exponential_component * 0.1  # 10% jitter
    jitter = random_uniform(-jitter_range, jitter_range)
    
    backoff_time = exponential_component + jitter
    return min(backoff_time, max_timeout)

function implement_timeout_backoff(error_context):
    retry_count = error_context.retry_count
    error_type = error_context.error_type
    
    # Different backoff strategies for different error types
    switch error_type:
        case ERROR_TYPE_CONNECTION:
            backoff_time = calculate_exponential_backoff(
                retry_count, 
                CONNECTION_TIMEOUT_MS, 
                MAX_CONNECTION_TIMEOUT_MS
            )
            
        case ERROR_TYPE_DISCOVERY:
            backoff_time = calculate_exponential_backoff(
                retry_count,
                DISCOVERY_TIMEOUT_MS,
                MAX_DISCOVERY_TIMEOUT_MS
            )
            
        case ERROR_TYPE_FRAGMENT:
            backoff_time = calculate_exponential_backoff(
                retry_count,
                FRAGMENT_TIMEOUT_MS,
                MAX_FRAGMENT_TIMEOUT_MS
            )
            
        default:
            backoff_time = calculate_exponential_backoff(
                retry_count,
                BASE_TIMEOUT_MS,
                MAX_GENERIC_TIMEOUT_MS
            )
    
    return backoff_time

function handle_timeout_error_with_backoff(error_details):
    # Handle timeout errors with intelligent backoff
    retry_count = error_details.retry_count
    
    if retry_count < MAX_RETRY_ATTEMPTS:
        # Calculate backoff time
        backoff_time = implement_timeout_backoff(error_details)
        
        # Schedule retry
        schedule_retry_operation(error_details.operation, backoff_time)
        
        # Update retry count
        error_details.retry_count += 1
        
        log_retry_attempt(error_details, backoff_time)
    else:
        # Maximum retries exceeded
        handle_permanent_timeout_failure(error_details)
```

## Timeout Monitoring and Statistics

### Timeout Performance Tracking

```pseudocode
timeout_statistics = {
    'rto_measurements': [],
    'timeout_events': {},
    'recovery_success_rates': {},
    'backoff_effectiveness': {}
}

function track_timeout_performance(timeout_type, outcome, duration):
    # Track timeout performance for optimization
    current_time = get_current_time_ms()
    
    event_record = {
        'type': timeout_type,
        'outcome': outcome,  # SUCCESS, TIMEOUT, RETRY, FAILURE
        'duration': duration,
        'timestamp': current_time,
        'rto_value': rto_state.rtt_rto,
        'network_conditions': capture_network_conditions()
    }
    
    # Store in appropriate statistics bucket
    if timeout_type not in timeout_statistics.timeout_events:
        timeout_statistics.timeout_events[timeout_type] = []
    
    timeout_statistics.timeout_events[timeout_type].append(event_record)
    
    # Maintain sliding window of recent events
    cleanup_old_statistics(current_time)

function analyze_timeout_patterns():
    # Analyze timeout patterns for optimization opportunities
    for timeout_type, events in timeout_statistics.timeout_events.items():
        if len(events) > 10:  # Sufficient data for analysis
            success_rate = calculate_success_rate(events)
            average_duration = calculate_average_duration(events)
            timeout_variance = calculate_timeout_variance(events)
            
            # Suggest optimizations
            if success_rate < 0.8:  # Less than 80% success rate
                suggest_timeout_adjustment(timeout_type, "increase")
            elif success_rate > 0.95 and average_duration < optimal_duration(timeout_type) * 0.5:
                suggest_timeout_adjustment(timeout_type, "decrease")

function optimize_timeout_parameters():
    # Continuously optimize timeout parameters based on performance
    analysis_results = analyze_timeout_patterns()
    
    for optimization in analysis_results:
        if optimization.confidence > 0.8:  # High confidence in suggestion
            apply_timeout_optimization(optimization)
            log_timeout_optimization(optimization)
```