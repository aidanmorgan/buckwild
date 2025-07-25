# Data Transmission: Flow Control and Fragmentation

This document specifies the comprehensive data transmission mechanisms including flow control, congestion control, and fragmentation that ensure reliable, efficient data delivery while preventing buffer overflow and adapting to network conditions.

## Overview

The data transmission framework provides robust mechanisms for managing data flow between peers, controlling transmission rates based on network feedback, and handling large payloads through intelligent fragmentation and reassembly.

## Purpose and Rationale

Data transmission control serves essential communication functions:

- **Flow Control**: Prevents sender from overwhelming receiver's buffer capacity, ensuring data reliability
- **Congestion Control**: Adapts transmission rate to network capacity, preventing network congestion collapse  
- **Fragmentation Support**: Enables transmission of large data payloads across networks with varying MTU constraints
- **Fairness**: Ensures equitable bandwidth sharing among multiple connections
- **Efficiency**: Maximizes network utilization while maintaining stability and preventing packet loss
- **Reliability**: Ensures all data is delivered correctly through acknowledgment and reassembly mechanisms

The design combines proven algorithms (TCP-inspired congestion control) with protocol-specific optimizations for port-hopping networks and cryptographically derived parameters.

## Key Concepts

- **Send/Receive Windows**: Buffer management that controls data flow between peers with dynamic sizing
- **Congestion Window**: Dynamic limit on outstanding data based on network feedback and RTT measurements
- **Slow Start/Congestion Avoidance**: Algorithms for probing and adapting to network capacity changes
- **Fast Recovery**: Rapid response to detected packet loss without full connection slowdown
- **Fragmentation and Reassembly**: Breaking large payloads into MTU-sized fragments with reliable reconstruction
- **Selective Acknowledgment (SACK)**: Efficient acknowledgment of out-of-order packets for faster recovery

## Flow Control Algorithm

### Flow Control State Management

```pseudocode
// Flow control state variables
flow_control_state = {
    'send_window': INITIAL_SEND_WINDOW,
    'receive_window': INITIAL_RECEIVE_WINDOW,
    'send_buffer': [],
    'receive_buffer': [],
    'reorder_buffer': [],
    'send_next': 0,
    'send_unacked': 0,
    'receive_next': 0,
    'advertised_window': INITIAL_RECEIVE_WINDOW,
    'last_window_update': 0,
    'zero_window_probe_timer': 0
}

function initialize_flow_control(initial_client_seq, initial_server_seq):
    flow_control_state.send_window = min(INITIAL_SEND_WINDOW, peer_advertised_window)
    flow_control_state.receive_window = INITIAL_RECEIVE_WINDOW
    flow_control_state.send_next = initial_client_seq
    flow_control_state.send_unacked = initial_client_seq
    flow_control_state.receive_next = initial_server_seq
    flow_control_state.advertised_window = INITIAL_RECEIVE_WINDOW
```

### Send Window Management

```pseudocode
function can_send_data(data_length):
    # Check if we can send data within current window
    bytes_in_flight = flow_control_state.send_next - flow_control_state.send_unacked
    effective_window = calculate_effective_window()
    available_window = effective_window - bytes_in_flight
    
    return data_length <= available_window and data_length <= MSS

function calculate_effective_window():
    # Effective window is minimum of congestion window and flow control window
    congestion_window = session_state.congestion_window
    flow_control_window = flow_control_state.send_window
    
    return min(congestion_window, flow_control_window)

function send_data_with_flow_control(data):
    if not can_send_data(len(data)):
        # Buffer data for later transmission
        add_to_send_buffer(data)
        return SUCCESS
    
    # Fragment data if necessary
    if len(data) > FRAGMENTATION_THRESHOLD:
        return send_fragmented_data(data)
    
    # Create data packet
    data_packet = create_data_packet(
        sequence_number = flow_control_state.send_next,
        data = data,
        window_size = flow_control_state.advertised_window
    )
    
    # Update send state
    flow_control_state.send_next += len(data)
    
    # Send packet
    send_packet(data_packet)
    
    # Set retransmission timer
    set_retransmission_timer(data_packet)
    
    # Try to send more buffered data
    attempt_send_buffered_data()
    
    return SUCCESS

function update_send_window(ack_packet):
    # Update based on acknowledgment
    acked_bytes = ack_packet.acknowledgment_number - flow_control_state.send_unacked
    
    if acked_bytes > 0:
        flow_control_state.send_unacked = ack_packet.acknowledgment_number
        
        # Remove acknowledged data from send buffer
        remove_acknowledged_data(acked_bytes)
        
        # Update congestion control
        update_congestion_window(ack_packet)
        
        # Send any buffered data that now fits in window
        attempt_send_buffered_data()
    
    # Update window size from peer advertisement
    flow_control_state.send_window = ack_packet.window_size
    
    # Handle zero window condition
    if flow_control_state.send_window == 0:
        start_zero_window_probing()
    else:
        stop_zero_window_probing()

function attempt_send_buffered_data():
    # Try to send buffered data that now fits in window
    while len(flow_control_state.send_buffer) > 0:
        next_data = flow_control_state.send_buffer[0]
        
        if can_send_data(len(next_data)):
            # Remove from buffer and send
            flow_control_state.send_buffer.pop(0)
            send_data_with_flow_control(next_data)
        else:
            break  # Can't send more data
```

### Receive Window Management

```pseudocode
function process_received_data(data_packet):
    sequence_number = data_packet.sequence_number
    data_length = len(data_packet.data)
    
    # Check if packet is within receive window
    if not is_within_receive_window(sequence_number, data_length):
        # Send duplicate ACK for out-of-window packets
        send_duplicate_ack()
        return SUCCESS
    
    # Handle in-order data
    if sequence_number == flow_control_state.receive_next:
        # Deliver data to application
        deliver_to_application(data_packet.data)
        flow_control_state.receive_next += data_length
        
        # Process any buffered in-order data
        process_buffered_in_order_data()
        
        # Update receive window
        update_receive_window(data_length)
        
        # Send acknowledgment
        send_acknowledgment()
        
    else:
        # Out-of-order data - buffer it
        buffer_out_of_order_data(data_packet)
        
        # Send selective acknowledgment
        send_selective_acknowledgment()
    
    return SUCCESS

function is_within_receive_window(sequence_number, data_length):
    window_start = flow_control_state.receive_next
    window_end = window_start + flow_control_state.receive_window
    
    return (sequence_number >= window_start and 
            sequence_number + data_length <= window_end)

function process_buffered_in_order_data():
    # Process out-of-order buffer for any newly in-order data
    while len(flow_control_state.reorder_buffer) > 0:
        next_packet = find_packet_with_sequence(
            flow_control_state.reorder_buffer, 
            flow_control_state.receive_next
        )
        
        if next_packet:
            # Found next in-order packet
            deliver_to_application(next_packet.data)
            flow_control_state.receive_next += len(next_packet.data)
            remove_from_buffer(flow_control_state.reorder_buffer, next_packet)
        else:
            break  # No more in-order data

function update_receive_window(consumed_bytes):
    # Calculate new available window space
    buffer_space_used = calculate_buffer_space_used()
    max_buffer_space = MAX_RECEIVE_BUFFER_SIZE
    available_space = max_buffer_space - buffer_space_used
    
    # Update advertised window
    new_window = min(available_space, MAX_RECEIVE_WINDOW)
    
    # Send window update if significant change
    window_change_threshold = flow_control_state.receive_window * WINDOW_UPDATE_THRESHOLD
    if abs(new_window - flow_control_state.advertised_window) > window_change_threshold:
        flow_control_state.advertised_window = new_window
        send_window_update()

function send_window_update():
    # Send window update using ACK packet
    ack_packet = create_ack_packet(
        acknowledgment_number = flow_control_state.receive_next,
        window_size = flow_control_state.advertised_window
    )
    send_packet(ack_packet)
    flow_control_state.last_window_update = get_current_time_ms()
```

## Congestion Control Algorithm

### Congestion Control State

```pseudocode
// Congestion control state variables
congestion_control_state = {
    'congestion_window': INITIAL_CONGESTION_WINDOW,
    'slow_start_threshold': SLOW_START_THRESHOLD,
    'congestion_state': SLOW_START,
    'duplicate_ack_count': 0,
    'fast_recovery_sequence': 0,
    'bytes_acked': 0
}

function update_congestion_window(ack_packet):
    # Update congestion window based on current state
    acked_bytes = ack_packet.acknowledgment_number - flow_control_state.send_unacked
    
    if acked_bytes <= 0:
        # Duplicate ACK
        handle_duplicate_ack(ack_packet)
        return
    
    # New data acknowledged
    congestion_control_state.duplicate_ack_count = 0
    
    switch congestion_control_state.congestion_state:
        case SLOW_START:
            # Slow start: exponential growth
            congestion_control_state.congestion_window = min(
                congestion_control_state.congestion_window + min(acked_bytes, MSS),
                MAX_CONGESTION_WINDOW
            )
            
            if congestion_control_state.congestion_window >= congestion_control_state.slow_start_threshold:
                congestion_control_state.congestion_state = CONGESTION_AVOIDANCE
                
        case CONGESTION_AVOIDANCE:
            # Congestion avoidance: linear growth
            congestion_control_state.bytes_acked += acked_bytes
            if congestion_control_state.bytes_acked >= congestion_control_state.congestion_window:
                congestion_control_state.congestion_window = min(
                    congestion_control_state.congestion_window + MSS,
                    MAX_CONGESTION_WINDOW
                )
                congestion_control_state.bytes_acked = 0
                
        case FAST_RECOVERY:
            # Fast recovery: maintain window size until recovery complete
            if ack_packet.acknowledgment_number >= congestion_control_state.fast_recovery_sequence:
                # Recovery complete
                congestion_control_state.congestion_window = congestion_control_state.slow_start_threshold
                congestion_control_state.congestion_state = CONGESTION_AVOIDANCE
                congestion_control_state.bytes_acked = 0

function handle_duplicate_ack(ack_packet):
    congestion_control_state.duplicate_ack_count += 1
    
    if congestion_control_state.duplicate_ack_count == 3:
        # Three duplicate ACKs - enter fast recovery
        enter_fast_recovery(ack_packet)
    elif congestion_control_state.congestion_state == FAST_RECOVERY:
        # Inflate congestion window during fast recovery
        congestion_control_state.congestion_window += MSS

function enter_fast_recovery(ack_packet):
    # Enter fast recovery mode
    congestion_control_state.slow_start_threshold = max(
        congestion_control_state.congestion_window / 2,
        MIN_CONGESTION_WINDOW
    )
    congestion_control_state.congestion_window = congestion_control_state.slow_start_threshold + 3 * MSS
    congestion_control_state.congestion_state = FAST_RECOVERY
    congestion_control_state.fast_recovery_sequence = flow_control_state.send_next
    
    # Retransmit lost packet
    retransmit_lost_packet(ack_packet.acknowledgment_number)

function handle_congestion_timeout():
    # Timeout indicates severe congestion
    congestion_control_state.slow_start_threshold = max(
        congestion_control_state.congestion_window / 2,
        MIN_CONGESTION_WINDOW
    )
    congestion_control_state.congestion_window = MIN_CONGESTION_WINDOW
    congestion_control_state.congestion_state = SLOW_START
    congestion_control_state.duplicate_ack_count = 0
    congestion_control_state.bytes_acked = 0
```

## Zero Window Handling

### Zero Window Probing

```pseudocode
function start_zero_window_probing():
    if flow_control_state.zero_window_probe_timer == 0:
        flow_control_state.zero_window_probe_timer = get_current_time_ms() + ZERO_WINDOW_PROBE_INTERVAL_MS
        schedule_zero_window_probe()

function send_zero_window_probe():
    # Send 1-byte probe packet to test if window has opened
    probe_data = get_next_byte_to_send()
    if probe_data != null:
        probe_packet = create_data_packet(
            sequence_number = flow_control_state.send_next,
            data = probe_data,
            window_size = flow_control_state.advertised_window
        )
        
        send_packet(probe_packet)
        
        # Schedule next probe with exponential backoff
        probe_interval = min(
            ZERO_WINDOW_PROBE_INTERVAL_MS * 2,
            MAX_ZERO_WINDOW_PROBE_INTERVAL_MS
        )
        flow_control_state.zero_window_probe_timer = get_current_time_ms() + probe_interval
        schedule_zero_window_probe()

function stop_zero_window_probing():
    flow_control_state.zero_window_probe_timer = 0
    cancel_zero_window_probe()

function handle_window_timeout():
    # Handle case where no window updates received
    current_time = get_current_time_ms()
    
    if current_time - flow_control_state.last_window_update > WINDOW_UPDATE_TIMEOUT_MS:
        # Window timeout - probe peer and reduce congestion window
        send_window_probe()
        
        # Reduce congestion window to prevent overwhelming peer
        congestion_control_state.congestion_window = max(
            congestion_control_state.congestion_window / 2,
            MIN_CONGESTION_WINDOW
        )
```

## Selective Acknowledgment (SACK)

### SACK Implementation

```pseudocode
function send_selective_acknowledgment():
    # Build SACK bitmap for out-of-order received data
    sack_bitmap = build_sack_bitmap()
    sack_ranges = build_sack_ranges()
    
    ack_packet = create_ack_packet(
        acknowledgment_number = flow_control_state.receive_next,
        window_size = flow_control_state.advertised_window,
        sack_flag = true,
        sack_bitmap = sack_bitmap,
        sack_ranges = sack_ranges
    )
    
    send_packet(ack_packet)

function build_sack_bitmap():
    bitmap = 0
    bitmap_size = 32  # 32-bit bitmap
    
    for i in range(bitmap_size):
        sequence_to_check = flow_control_state.receive_next + i + 1
        if is_sequence_received(sequence_to_check):
            bitmap |= (1 << i)
    
    return bitmap

function build_sack_ranges():
    # Build extended SACK ranges for complex loss patterns
    sack_ranges = []
    current_range_start = None
    current_range_end = None
    
    for packet in flow_control_state.reorder_buffer:
        if current_range_start == None:
            current_range_start = packet.sequence_number
            current_range_end = packet.sequence_number + len(packet.data)
        elif packet.sequence_number == current_range_end:
            # Extend current range
            current_range_end = packet.sequence_number + len(packet.data)
        else:
            # New range
            sack_ranges.append({
                'start': current_range_start,
                'end': current_range_end
            })
            current_range_start = packet.sequence_number
            current_range_end = packet.sequence_number + len(packet.data)
    
    # Add final range
    if current_range_start != None:
        sack_ranges.append({
            'start': current_range_start,
            'end': current_range_end
        })
    
    return sack_ranges

function process_selective_acknowledgment(ack_packet):
    sack_bitmap = ack_packet.sack_bitmap
    sack_ranges = ack_packet.sack_ranges
    base_sequence = ack_packet.acknowledgment_number
    
    # Process SACK bitmap
    for i in range(32):
        if sack_bitmap & (1 << i):
            acked_sequence = base_sequence + i + 1
            mark_sequence_acknowledged(acked_sequence)
    
    # Process extended SACK ranges
    for range_info in sack_ranges:
        mark_range_acknowledged(range_info.start, range_info.end)
    
    # Retransmit missing segments
    retransmit_missing_segments(base_sequence, sack_bitmap, sack_ranges)
```

## Fragmentation and Reassembly

### Fragmentation Decision and Process

```pseudocode
function send_fragmented_data(data):
    # Calculate fragment parameters
    fragment_params = calculate_fragment_parameters(len(data), current_mtu)
    if fragment_params == ERROR_PACKET_TOO_LARGE:
        return ERROR_PAYLOAD_TOO_LARGE
    
    # Create fragments
    fragments = fragment_large_data(data, fragment_params)
    
    # Transmit fragments with pacing
    return transmit_fragments_with_pacing(fragments)

function calculate_fragment_parameters(data_length, mtu):
    # Calculate usable payload size per fragment
    header_overhead = OPTIMIZED_COMMON_HEADER_SIZE + FLOW_CONTROL_HEADER_SIZE + FRAGMENTATION_HEADER_SIZE
    max_fragment_payload = min(MAX_FRAGMENT_SIZE, mtu - header_overhead)
    
    # Calculate number of fragments needed
    fragment_count = (data_length + max_fragment_payload - 1) // max_fragment_payload
    
    if fragment_count > MAX_FRAGMENTS:
        return ERROR_PACKET_TOO_LARGE
    
    return {
        'fragment_count': fragment_count,
        'fragment_payload_size': max_fragment_payload,
        'last_fragment_size': data_length % max_fragment_payload if data_length % max_fragment_payload != 0 else max_fragment_payload
    }

function fragment_large_data(data, fragment_params):
    fragment_id = generate_unique_fragment_id()
    fragments = []
    data_offset = 0
    
    for fragment_index in range(fragment_params.fragment_count):
        # Determine fragment payload size
        if fragment_index == fragment_params.fragment_count - 1:
            payload_size = fragment_params.last_fragment_size
        else:
            payload_size = fragment_params.fragment_payload_size
        
        # Extract fragment payload
        fragment_payload = data[data_offset:data_offset + payload_size]
        
        # Create DATA packet with fragmentation fields
        fragment_packet = create_data_packet(
            sequence_number = flow_control_state.send_next + fragment_index,
            window_size = flow_control_state.advertised_window,
            fragment_flag = true,
            fragment_id = fragment_id,
            fragment_index = fragment_index,
            total_fragments = fragment_params.fragment_count,
            payload = fragment_payload
        )
        
        fragments.append(fragment_packet)
        data_offset += payload_size
    
    # Update send sequence for all fragments
    flow_control_state.send_next += fragment_params.fragment_count
    
    return fragments

function transmit_fragments_with_pacing(fragments):
    # Calculate inter-fragment delay for pacing
    fragment_interval = calculate_fragment_pacing_interval(len(fragments))
    
    for i, fragment in enumerate(fragments):
        send_packet(fragment)
        
        # Set retransmission timer for each fragment
        set_retransmission_timer(fragment)
        
        # Add inter-fragment delay (except for last fragment)
        if i < len(fragments) - 1:
            sleep(fragment_interval)
    
    # Track fragment transmission for timeout handling
    track_fragment_transmission(fragments[0].fragment_id, fragments)
    
    return SUCCESS

function calculate_fragment_pacing_interval(fragment_count):
    # Calculate optimal inter-fragment delay based on network conditions
    base_interval = max(1, HOP_INTERVAL_MS // 20)  # Small fraction of hop interval
    congestion_factor = congestion_control_state.congestion_window / INITIAL_CONGESTION_WINDOW
    rtt_factor = session_state.rtt_srtt / RTT_INITIAL_MS
    
    # Adjust interval based on network conditions
    adjusted_interval = base_interval / (congestion_factor * rtt_factor)
    
    return max(1, min(adjusted_interval, 50))  # 1-50ms range
```

### Fragment Reassembly

```pseudocode
function handle_fragmented_data_packet(data_packet):
    # SECURITY: Session binding - only process fragments for valid sessions
    if not validate_session_binding(data_packet):
        log_security_event("Fragment without valid session binding", data_packet.session_id)
        return ERROR_SESSION_NOT_FOUND
    
    # Check if packet has fragmentation flag
    if not data_packet.fragment_flag:
        # Regular data packet - process normally
        return process_received_data(data_packet)
    
    # SECURITY: Enforce fragment arrival rate limits per session
    if not check_fragment_rate_limit(data_packet.session_id):
        log_security_event("Fragment rate limit exceeded", data_packet.session_id)
        return ERROR_RATE_LIMITED

    # Extract fragmentation information
    fragment_id = data_packet.fragment_id
    fragment_index = data_packet.fragment_index
    total_fragments = data_packet.total_fragments
    
    # SECURITY: Comprehensive fragment validation with security checks
    if not validate_fragment_packet_security(data_packet):
        return ERROR_FRAGMENT_INVALID
    
    # SECURITY: Check global and per-session reassembly limits
    if not check_reassembly_resource_limits(data_packet.session_id):
        log_security_event("Reassembly resource limits exceeded", data_packet.session_id)
        return ERROR_MEMORY_EXHAUSTED

    # Get or create reassembly buffer with session binding
    reassembly_buffer = get_or_create_reassembly_buffer(fragment_id, total_fragments, data_packet.session_id)
    
    # SECURITY: Check for duplicate fragment with overlap detection
    if reassembly_buffer.fragments[fragment_index] != null:
        return handle_duplicate_fragment(reassembly_buffer, fragment_index, data_packet)
    
    # SECURITY: Validate fragment does not create overlaps
    if detect_fragment_overlap(reassembly_buffer, fragment_index, data_packet):
        log_security_event("Fragment overlap attack detected", data_packet.session_id, fragment_id)
        cleanup_reassembly_buffer(fragment_id)
        return ERROR_FRAGMENT_OVERLAP

    # Store fragment with memory accounting
    store_fragment_with_accounting(reassembly_buffer, fragment_index, data_packet)
    
    # Check if reassembly is complete
    if reassembly_buffer.received_count == total_fragments:
        return complete_fragment_reassembly(reassembly_buffer)
    
    return SUCCESS

function complete_fragment_reassembly(reassembly_buffer):
    # Reassemble data from fragments
    reassembled_data = b''
    original_sequence = reassembly_buffer.fragments[0].sequence_number
    
    for i in range(reassembly_buffer.total_fragments):
        fragment = reassembly_buffer.fragments[i]
        if fragment == null:
            return ERROR_FRAGMENT_MISSING
        
        reassembled_data += fragment.payload
    
    # Create original data packet
    original_packet = create_data_packet(
        sequence_number = original_sequence,
        window_size = reassembly_buffer.fragments[0].window_size,
        fragment_flag = false,
        payload = reassembled_data
    )
    
    # Clean up reassembly buffer
    cleanup_reassembly_buffer(reassembly_buffer)
    
    # Process reassembled packet
    return process_received_data(original_packet)

function cleanup_expired_fragments():
    # Clean up expired fragment reassembly buffers
    current_time = get_current_time_ms()
    expired_buffers = []
    
    for fragment_id, buffer in session_state.reassembly_buffers.items():
        if current_time > buffer.timeout:
            expired_buffers.append(fragment_id)
    
    for fragment_id in expired_buffers:
        buffer = session_state.reassembly_buffers[fragment_id]
        
        # Log fragment timeout
        log_fragment_timeout(fragment_id, buffer.received_count, buffer.total_fragments)
        
        # Request retransmission of missing fragments
        if buffer.received_count > 0:
            request_fragment_retransmission(fragment_id, buffer)
        
        # Clean up buffer
        cleanup_reassembly_buffer(buffer)
        del session_state.reassembly_buffers[fragment_id]
```

## Integration and Performance Optimization

### Adaptive Transmission Control

```pseudocode
function adjust_transmission_parameters():
    # Dynamically adjust transmission parameters based on network conditions
    effective_window = calculate_effective_window()
    bytes_in_flight = flow_control_state.send_next - flow_control_state.send_unacked
    
    # Calculate transmission rate
    current_rtt = session_state.rtt_srtt
    bandwidth_delay_product = effective_window * current_rtt / 1000  # Convert to bytes
    
    # Adjust fragmentation threshold based on network conditions
    if current_rtt > 2 * RTT_INITIAL_MS:
        # High latency - use larger fragments
        adjusted_threshold = min(FRAGMENTATION_THRESHOLD * 1.5, MAX_FRAGMENT_SIZE)
    else:
        # Normal latency - use standard threshold
        adjusted_threshold = FRAGMENTATION_THRESHOLD
    
    # Update session parameters
    session_state.dynamic_fragmentation_threshold = adjusted_threshold
    session_state.bandwidth_delay_product = bandwidth_delay_product

function optimize_transmission_strategy():
    # Choose optimal transmission strategy based on current conditions
    if congestion_control_state.congestion_window < INITIAL_CONGESTION_WINDOW:
        # Conservative strategy during congestion
        return TRANSMISSION_STRATEGY_CONSERVATIVE
    elif flow_control_state.send_window == 0:
        # Zero window - use probing strategy
        return TRANSMISSION_STRATEGY_PROBE
    elif session_state.rtt_srtt > 500:
        # High latency - use bulk strategy
        return TRANSMISSION_STRATEGY_BULK
    else:
        # Normal conditions - use standard strategy
        return TRANSMISSION_STRATEGY_STANDARD
```

## Error Handling and Recovery

### Flow Control Error Recovery

```pseudocode
function handle_flow_control_error(error_type, error_data):
    switch error_type:
        case ERROR_WINDOW_OVERFLOW:
            # Reduce transmission rate and buffer data
            reduce_transmission_rate()
            buffer_overflow_data(error_data)
            
        case ERROR_FRAGMENT_TIMEOUT:
            # Request retransmission of missing fragments
            request_fragment_retransmission(error_data.fragment_id, error_data.missing_fragments)
            
        case ERROR_ZERO_WINDOW_DEADLOCK:
            # Force window probe and reset timers
            force_zero_window_probe()
            reset_window_timers()
            
        case ERROR_CONGESTION_COLLAPSE:
            # Emergency congestion recovery
            emergency_congestion_recovery()

function emergency_congestion_recovery():
    # Emergency recovery from severe congestion
    congestion_control_state.congestion_window = MIN_CONGESTION_WINDOW
    congestion_control_state.slow_start_threshold = MIN_CONGESTION_WINDOW * 2
    congestion_control_state.congestion_state = SLOW_START
    
    # Clear send buffers and restart transmission
    clear_send_buffers()
    restart_transmission_with_reduced_rate()
```

## Detailed Fragmentation Specification

### Fragment Header Structure

The fragment header provides all necessary information for reliable reassembly of fragmented messages. Each fragment carries an 8-byte header immediately following the flow control header in DATA packets.

```pseudocode
// Fragment header constants (from 02-core-definitions.md)
FRAGMENT_HEADER_SIZE = 8                 // Fragment header size in bytes
MAX_FRAGMENTS = 255                      // Maximum fragments per packet
MAX_FRAGMENT_SIZE = 1400                // Maximum fragment payload size (bytes)
FRAGMENT_REASSEMBLY_BUFFER_SIZE = 64    // Maximum fragments in reassembly buffer
FRAGMENT_ID_SPACE = 0xFFFF              // Fragment ID space (16-bit)
FRAGMENT_DUPLICATE_WINDOW = 100         // Window for detecting duplicate fragments
FRAGMENT_TIMEOUT_MS = 30000             // Fragment reassembly timeout (30 seconds)

// Fragment header structure (8 bytes total)
// For complete field layout and packet integration, see the "Fragmentation Fields" 
// section in 03-packet-architecture.md
struct FragmentHeader {
    uint16_t fragment_id;      // Unique identifier for fragmented message
    uint16_t fragment_index;   // Zero-based index of this fragment
    uint16_t total_fragments;  // Total number of fragments in message
    uint16_t reserved;         // Reserved for future use (must be 0x0000)
}
```

### Fragment ID Generation and Management

```pseudocode
// Fragment ID state management
fragment_id_state = {
    'next_fragment_id': 0,
    'recent_fragment_ids': CircularBuffer(FRAGMENT_DUPLICATE_WINDOW),
    'id_generation_counter': 0
}

function generate_unique_fragment_id():
    # Generate cryptographically random fragment ID
    # Ensures unpredictability to prevent fragment prediction attacks
    
    max_attempts = 100
    for attempt in range(max_attempts):
        # Generate random 16-bit value
        candidate_id = secure_random_uint16()
        
        # Ensure ID is not recently used
        if candidate_id not in fragment_id_state.recent_fragment_ids:
            # Add to recent IDs list
            fragment_id_state.recent_fragment_ids.add(candidate_id)
            fragment_id_state.id_generation_counter += 1
            
            # Periodic cleanup of old IDs
            if fragment_id_state.id_generation_counter % 1000 == 0:
                cleanup_expired_fragment_ids()
            
            return candidate_id
    
    # Fallback: use counter-based ID if random generation fails
    fallback_id = (fragment_id_state.next_fragment_id + 1) % FRAGMENT_ID_SPACE
    fragment_id_state.next_fragment_id = fallback_id
    fragment_id_state.recent_fragment_ids.add(fallback_id)
    return fallback_id

function cleanup_expired_fragment_ids():
    # Remove fragment IDs older than timeout window
    current_time = get_current_time_ms()
    fragment_id_state.recent_fragment_ids.remove_older_than(
        current_time - FRAGMENT_TIMEOUT_MS
    )
```

### Fragment Validation

```pseudocode
function validate_fragment_packet(fragment_packet):
    # Comprehensive fragment validation
    
    # Check fragment flag is set
    if not (fragment_packet.flags & FRAGMENT_FLAG):
        return ERROR_FRAGMENT_INVALID
    
    # Extract fragment header
    fragment_header = fragment_packet.fragment_header
    
    # Validate fragment index
    if fragment_header.fragment_index >= fragment_header.total_fragments:
        return ERROR_FRAGMENT_INVALID
    
    # Validate total fragments count
    if fragment_header.total_fragments == 0 or fragment_header.total_fragments > MAX_FRAGMENTS:
        return ERROR_FRAGMENT_INVALID
    
    # Validate reserved field
    if fragment_header.reserved != 0x0000:
        return ERROR_FRAGMENT_INVALID
    
    # Check for fragment bomb attack (excessive fragments)
    if fragment_header.total_fragments > calculate_max_fragments_for_size(MAX_PACKET_SIZE):
        return ERROR_FRAGMENT_BOMB
    
    # Validate payload size
    expected_size = calculate_expected_fragment_size(
        fragment_header.fragment_index,
        fragment_header.total_fragments,
        fragment_packet.payload_length
    )
    if fragment_packet.payload_length > expected_size:
        return ERROR_FRAGMENT_INVALID
    
    return SUCCESS

function calculate_max_fragments_for_size(max_total_size):
    # Calculate maximum reasonable fragments for a given total size
    # Prevents fragment bomb attacks
    header_overhead = OPTIMIZED_COMMON_HEADER_SIZE + FLOW_CONTROL_HEADER_SIZE + FRAGMENT_HEADER_SIZE
    min_fragment_payload = 64  # Minimum reasonable fragment payload
    max_reasonable_fragments = max_total_size // (header_overhead + min_fragment_payload)
    return min(max_reasonable_fragments, MAX_FRAGMENTS)
```

### Reassembly Buffer Management

```pseudocode
// Fragment reassembly buffer structure
struct ReassemblyBuffer {
    uint16_t fragment_id;
    uint16_t total_fragments;
    uint16_t received_count;
    uint32_t first_fragment_time;
    uint32_t timeout;
    FragmentPacket* fragments[MAX_FRAGMENTS];  // Array of fragment pointers
    uint32_t total_reassembled_size;
    uint8_t reassembly_state;  // PENDING, COMPLETE, FAILED
}

// Reassembly state management
reassembly_state = {
    'active_buffers': HashMap<fragment_id, ReassemblyBuffer>,
    'buffer_count': 0,
    'last_cleanup_time': 0
}

function get_or_create_reassembly_buffer(fragment_id, total_fragments):
    # Get existing or create new reassembly buffer
    
    if fragment_id in reassembly_state.active_buffers:
        return reassembly_state.active_buffers[fragment_id]
    
    # Check buffer limit
    if reassembly_state.buffer_count >= FRAGMENT_REASSEMBLY_BUFFER_SIZE:
        # Evict oldest incomplete buffer
        evict_oldest_reassembly_buffer()
    
    # Create new buffer
    new_buffer = ReassemblyBuffer {
        fragment_id: fragment_id,
        total_fragments: total_fragments,
        received_count: 0,
        first_fragment_time: get_current_time_ms(),
        timeout: get_current_time_ms() + FRAGMENT_TIMEOUT_MS,
        fragments: [null] * total_fragments,
        total_reassembled_size: 0,
        reassembly_state: REASSEMBLY_PENDING
    }
    
    reassembly_state.active_buffers[fragment_id] = new_buffer
    reassembly_state.buffer_count += 1
    
    return new_buffer

function evict_oldest_reassembly_buffer():
    # Find and remove oldest incomplete reassembly buffer
    oldest_time = MAX_UINT32
    oldest_id = null
    
    for fragment_id, buffer in reassembly_state.active_buffers.items():
        if buffer.first_fragment_time < oldest_time:
            oldest_time = buffer.first_fragment_time
            oldest_id = fragment_id
    
    if oldest_id != null:
        cleanup_reassembly_buffer(reassembly_state.active_buffers[oldest_id])
        del reassembly_state.active_buffers[oldest_id]
        reassembly_state.buffer_count -= 1
```

### Fragment Reassembly Process

```pseudocode
function reassemble_complete_message(reassembly_buffer):
    # Reassemble all fragments into complete message
    
    # Verify all fragments are present
    for i in range(reassembly_buffer.total_fragments):
        if reassembly_buffer.fragments[i] == null:
            return ERROR_FRAGMENT_MISSING
    
    # Calculate total message size
    total_size = 0
    for fragment in reassembly_buffer.fragments:
        total_size += len(fragment.payload)
    
    # Allocate buffer for complete message
    complete_message = allocate_buffer(total_size)
    if complete_message == null:
        return ERROR_MEMORY_EXHAUSTED
    
    # Copy fragment payloads in order
    offset = 0
    for i in range(reassembly_buffer.total_fragments):
        fragment = reassembly_buffer.fragments[i]
        copy_memory(
            complete_message + offset,
            fragment.payload,
            len(fragment.payload)
        )
        offset += len(fragment.payload)
    
    # Verify reassembly
    if offset != total_size:
        free_buffer(complete_message)
        return ERROR_FRAGMENT_REASSEMBLY_FAILED
    
    reassembly_buffer.reassembly_state = REASSEMBLY_COMPLETE
    
    return complete_message

function handle_fragment_overlap_attack(reassembly_buffer, fragment_packet):
    # Detect and handle fragment overlap attacks
    
    fragment_index = fragment_packet.fragment_header.fragment_index
    
    # Check if fragment already received
    if reassembly_buffer.fragments[fragment_index] != null:
        existing_fragment = reassembly_buffer.fragments[fragment_index]
        
        # Compare payloads
        if not compare_fragment_payloads(existing_fragment, fragment_packet):
            # Fragment overlap attack detected
            log_security_event(FRAGMENT_OVERLAP_ATTACK, fragment_packet)
            
            # Mark entire reassembly as failed
            reassembly_buffer.reassembly_state = REASSEMBLY_FAILED
            
            return ERROR_FRAGMENT_OVERLAP
    
    return SUCCESS
```

### Fragment Timeout and Cleanup

```pseudocode
function fragment_timeout_handler():
    # Periodic handler for fragment timeout management
    current_time = get_current_time_ms()
    
    # Check cleanup interval
    if current_time - reassembly_state.last_cleanup_time < FRAGMENT_CLEANUP_INTERVAL_MS:
        return
    
    expired_buffers = []
    
    # Find expired reassembly buffers
    for fragment_id, buffer in reassembly_state.active_buffers.items():
        if current_time > buffer.timeout:
            expired_buffers.append(fragment_id)
    
    # Process expired buffers
    for fragment_id in expired_buffers:
        buffer = reassembly_state.active_buffers[fragment_id]
        
        # Log timeout event
        log_fragment_timeout(
            fragment_id,
            buffer.received_count,
            buffer.total_fragments
        )
        
        # Request retransmission if significant progress made
        if buffer.received_count >= buffer.total_fragments * 0.5:
            request_selective_fragment_retransmission(buffer)
        
        # Cleanup buffer
        cleanup_reassembly_buffer(buffer)
        del reassembly_state.active_buffers[fragment_id]
        reassembly_state.buffer_count -= 1
    
    reassembly_state.last_cleanup_time = current_time

function request_selective_fragment_retransmission(reassembly_buffer):
    # Request retransmission of missing fragments only
    missing_fragments = []
    
    for i in range(reassembly_buffer.total_fragments):
        if reassembly_buffer.fragments[i] == null:
            missing_fragments.append(i)
    
    # Send NACK for missing fragments
    send_fragment_nack(
        reassembly_buffer.fragment_id,
        missing_fragments
    )

## Fragment Security Functions

### Session Binding and Rate Limiting

```pseudocode
function validate_session_binding(data_packet):
    # SECURITY: Ensure fragment belongs to valid, authenticated session
    session_id = data_packet.session_id
    
    # Check if session exists and is in valid state
    session = get_session(session_id)
    if session == null:
        return false
    
    # Verify session is in data transmission state (not handshaking)
    if session.state != SESSION_ESTABLISHED:
        return false
    
    # Verify packet authentication (HMAC already validated at this point)
    # Additional check: ensure fragment is within session's allowed sequence space
    if not is_sequence_valid_for_session(session, data_packet.sequence_number):
        return false
    
    return true

function check_fragment_rate_limit(session_id):
    # SECURITY: Enforce per-session fragment arrival rate limits
    current_time = get_current_time_ms()
    session = get_session(session_id)
    
    # Update fragment rate tracking
    if session.fragment_rate_window_start == 0:
        session.fragment_rate_window_start = current_time
        session.fragment_count_in_window = 0
    
    # Check if we need to reset the rate window (1-second window)
    if current_time - session.fragment_rate_window_start >= 1000:
        session.fragment_rate_window_start = current_time
        session.fragment_count_in_window = 0
    
    # Check rate limit
    if session.fragment_count_in_window >= FRAGMENT_ARRIVAL_RATE_LIMIT:
        return false
    
    # Increment counter
    session.fragment_count_in_window += 1
    return true

function check_reassembly_resource_limits(session_id):
    # SECURITY: Enforce memory and CPU limits for reassembly operations
    session = get_session(session_id)
    
    # Check per-session limits
    if session.active_reassemblies >= MAX_CONCURRENT_REASSEMBLIES_PER_SESSION:
        return false
    
    # Check per-session memory usage
    if session.reassembly_memory_usage >= MAX_REASSEMBLY_MEMORY_PER_SESSION:
        return false
    
    # Check global limits
    if reassembly_state.buffer_count >= MAX_CONCURRENT_REASSEMBLIES_GLOBAL:
        return false
    
    # Check global memory usage
    if get_total_reassembly_memory() >= get_max_system_reassembly_memory():
        return false
    
    return true

### Duplicate Detection and Overlap Validation

function handle_duplicate_fragment(reassembly_buffer, fragment_index, new_fragment):
    # SECURITY: Handle duplicate fragments with overlap detection
    existing_fragment = reassembly_buffer.fragments[fragment_index]
    
    # Check if payloads are identical (legitimate duplicate)
    if compare_fragment_payloads(existing_fragment, new_fragment):
        # Legitimate duplicate - update timestamp but don't change data
        log_debug("Legitimate duplicate fragment received", 
                 new_fragment.session_id, reassembly_buffer.fragment_id, fragment_index)
        return SUCCESS
    
    # Payloads differ - this is a fragment overlap attack
    log_security_event("Fragment overlap attack: different payloads for same index",
                      new_fragment.session_id, reassembly_buffer.fragment_id, fragment_index)
    
    # Cleanup compromised reassembly
    cleanup_reassembly_buffer(reassembly_buffer.fragment_id)
    
    # Block further fragments from this source for a short period
    add_fragment_source_to_temporary_blocklist(new_fragment.source_ip, 300000)  # 5 minutes
    
    return ERROR_FRAGMENT_OVERLAP

function detect_fragment_overlap(reassembly_buffer, fragment_index, new_fragment):
    # SECURITY: Detect overlapping fragment boundaries
    
    # For this protocol, fragments should not overlap
    # Each fragment_index should have exactly one corresponding fragment
    # This function serves as additional validation
    
    # Check if fragment size exceeds expected boundaries
    expected_offset = fragment_index * MAX_FRAGMENT_SIZE
    fragment_payload_size = len(new_fragment.payload)
    
    # Validate fragment doesn't exceed packet boundaries
    if fragment_index == reassembly_buffer.total_fragments - 1:
        # Last fragment - check it doesn't exceed total expected size
        max_allowed_size = MAX_TOTAL_REASSEMBLED_SIZE - expected_offset
        if fragment_payload_size > max_allowed_size:
            return true  # Overlap detected
    else:
        # Non-final fragment - should not exceed MAX_FRAGMENT_SIZE
        if fragment_payload_size > MAX_FRAGMENT_SIZE:
            return true  # Overlap detected
    
    # Check minimum fragment size (prevents tiny fragment attacks)
    if fragment_payload_size < MIN_FRAGMENT_SIZE and fragment_index < reassembly_buffer.total_fragments - 1:
        return true  # Invalid tiny fragment
    
    return false

function compare_fragment_payloads(fragment1, fragment2):
    # Compare fragment payloads for exact match
    if len(fragment1.payload) != len(fragment2.payload):
        return false
    
    # Constant-time comparison to prevent timing attacks
    result = 0
    for i in range(len(fragment1.payload)):
        result |= fragment1.payload[i] ^ fragment2.payload[i]
    
    return result == 0

### Enhanced Fragment Validation

function validate_fragment_packet_security(data_packet):
    # SECURITY: Comprehensive fragment validation with security focus
    
    # Call original validation
    if not validate_fragment_packet(data_packet):
        return false
    
    # Additional security checks
    fragment_header = data_packet.fragment_header
    
    # SECURITY: Enforce maximum fragments limit (prevents fragment bombs)
    if fragment_header.total_fragments > MAX_FRAGMENTS_PER_PACKET:
        log_security_event("Fragment bomb attempt: too many fragments",
                          data_packet.session_id, fragment_header.total_fragments)
        return false
    
    # SECURITY: Enforce minimum fragment size (prevents tiny fragment attacks)
    payload_size = len(data_packet.payload)
    if payload_size < MIN_FRAGMENT_SIZE and fragment_header.fragment_index < fragment_header.total_fragments - 1:
        log_security_event("Tiny fragment attack detected",
                          data_packet.session_id, payload_size)
        return false
    
    # SECURITY: Check total reassembled size doesn't exceed limits
    estimated_total_size = fragment_header.total_fragments * MAX_FRAGMENT_SIZE
    if estimated_total_size > MAX_TOTAL_REASSEMBLED_SIZE:
        log_security_event("Fragment bomb attempt: total size too large",
                          data_packet.session_id, estimated_total_size)
        return false
    
    # SECURITY: Validate fragment timing (prevent slow-drip attacks)
    current_time = get_current_time_ms()
    if data_packet.timestamp < current_time - FRAGMENT_TIMEOUT_MS:
        log_security_event("Stale fragment received",
                          data_packet.session_id, fragment_header.fragment_id)
        return false
    
    return true

### Memory Accounting and Resource Management

function store_fragment_with_accounting(reassembly_buffer, fragment_index, data_packet):
    # Store fragment with proper memory accounting
    session = get_session(data_packet.session_id)
    fragment_size = len(data_packet.payload) + FRAGMENT_METADATA_SIZE
    
    # Update memory accounting
    session.reassembly_memory_usage += fragment_size
    reassembly_buffer.memory_usage += fragment_size
    
    # Store the fragment
    reassembly_buffer.fragments[fragment_index] = data_packet
    reassembly_buffer.received_count += 1
    reassembly_buffer.timeout = get_current_time_ms() + FRAGMENT_TIMEOUT_MS
    
    # Update last activity
    reassembly_buffer.last_fragment_time = get_current_time_ms()

function cleanup_reassembly_buffer(fragment_id):
    # Clean up reassembly buffer with proper resource deallocation
    if fragment_id not in reassembly_state.active_buffers:
        return
    
    buffer = reassembly_state.active_buffers[fragment_id]
    session = get_session(buffer.session_id)
    
    # Update memory accounting
    session.reassembly_memory_usage -= buffer.memory_usage
    session.active_reassemblies -= 1
    
    # Clear fragment data
    for i in range(buffer.total_fragments):
        if buffer.fragments[i] != null:
            secure_zero_memory(buffer.fragments[i].payload)
            buffer.fragments[i] = null
    
    # Remove from active buffers
    del reassembly_state.active_buffers[fragment_id]
    reassembly_state.buffer_count -= 1

function add_fragment_source_to_temporary_blocklist(source_ip, duration_ms):
    # Temporarily block sources sending malicious fragments
    current_time = get_current_time_ms()
    expiry_time = current_time + duration_ms
    
    fragment_security_state.blocked_sources[source_ip] = expiry_time
    
    # Schedule cleanup
    schedule_timer_callback(duration_ms, remove_blocked_source, source_ip)

# Security state tracking
fragment_security_state = {
    'blocked_sources': {},  # IP -> expiry_time mapping
    'attack_counters': {},  # IP -> attack count mapping
    'global_fragment_rate': 0,  # Global fragment processing rate
    'last_rate_reset': 0   # Last time global rate was reset
}

# Constants for fragment security
FRAGMENT_METADATA_SIZE = 64  # Estimated overhead per fragment in memory
```