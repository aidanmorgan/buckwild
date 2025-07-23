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
    
    if current_time - flow_control_state.last_window_update > WINDOW_TIMEOUT_MS:
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
    # Check if packet has fragmentation flag
    if not data_packet.fragment_flag:
        # Regular data packet - process normally
        return process_received_data(data_packet)
    
    # Extract fragmentation information
    fragment_id = data_packet.fragment_id
    fragment_index = data_packet.fragment_index
    total_fragments = data_packet.total_fragments
    
    # Validate fragment
    if not validate_fragment_packet(data_packet):
        return ERROR_FRAGMENT_INVALID
    
    # Get or create reassembly buffer
    reassembly_buffer = get_or_create_reassembly_buffer(fragment_id, total_fragments)
    
    # Check for duplicate fragment
    if reassembly_buffer.fragments[fragment_index] != null:
        # Duplicate fragment - ignore
        return SUCCESS
    
    # Store fragment
    reassembly_buffer.fragments[fragment_index] = data_packet
    reassembly_buffer.received_count += 1
    reassembly_buffer.timeout = get_current_time_ms() + FRAGMENT_TIMEOUT_MS
    
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