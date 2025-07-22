# Flow Control and Congestion Control Specifications

## Overview

This document specifies the flow control and congestion control mechanisms that regulate data transmission rates, prevent buffer overflow, and optimize network utilization. These algorithms ensure reliable data delivery while maximizing throughput and minimizing latency under varying network conditions.

## Purpose and Rationale

Flow control and congestion control serve complementary but distinct functions:

- **Flow Control**: Prevents sender from overwhelming receiver's buffer capacity, ensuring data reliability
- **Congestion Control**: Adapts transmission rate to network capacity, preventing network congestion collapse
- **Fairness**: Ensures equitable bandwidth sharing among multiple connections
- **Efficiency**: Maximizes network utilization while maintaining stability
- **Responsiveness**: Quickly adapts to changing network conditions and congestion signals

The design combines proven algorithms (TCP-inspired congestion control) with protocol-specific optimizations for port-hopping networks, providing both reliability and performance.

## Key Concepts

- **Send/Receive Windows**: Buffer management that controls data flow between peers
- **Congestion Window**: Dynamic limit on outstanding data based on network feedback
- **Slow Start/Congestion Avoidance**: Algorithms for probing and adapting to network capacity
- **Fast Recovery**: Rapid response to detected packet loss without full connection slowdown
- **Window Scaling**: Mechanisms to handle high-bandwidth, high-latency networks

## Flow Control Algorithm
```pseudocode
// Flow control state variables
send_window = INITIAL_CONGESTION_WINDOW    // Send window size
receive_window = INITIAL_RECEIVE_WINDOW    // Receive window size
send_unacked = 0                          // Unacknowledged data
send_next = 0                             // Next sequence to send
receive_next = 0                          // Next expected sequence
receive_buffer = []                       // Out-of-order receive buffer

function update_send_window(ack_packet):
    # Update send window based on acknowledgment
    acked_bytes = ack_packet.acknowledgment_number - session_state.send_unacked
    
    if acked_bytes > 0:
        session_state.send_unacked = ack_packet.acknowledgment_number
        session_state.send_window = min(session_state.send_window + acked_bytes, MAX_CONGESTION_WINDOW)
    
    # Update based on window advertisement
    if ack_packet.window_size < session_state.receive_window:
        session_state.receive_window = ack_packet.window_size

function can_send_data():
    # Check if we can send more data
    available_window = min(session_state.send_window, session_state.receive_window)
    unacked_data = session_state.send_next - session_state.send_unacked
    
    return (unacked_data + MSS) <= available_window

function send_data(data):
    # Send data if window allows
    if not can_send_data():
        return ERROR_WINDOW_OVERFLOW
    
    # Create data packet
    data_packet = create_data_packet(
        sequence_number = session_state.send_next,
        data = data
    )
    
    # Update send state
    session_state.send_next += len(data)
    session_state.send_window -= len(data)
    
    # Send packet
    send_packet(data_packet)
    return SUCCESS

function receive_data(data_packet):
    # Handle incoming data with flow control
    sequence_number = data_packet.sequence_number
    data_length = len(data_packet.data)
    
    # Check if packet is within receive window
    if sequence_number < session_state.receive_next:
        # Duplicate packet - send ACK
        send_ack(session_state.receive_next)
        return SUCCESS
    
    if sequence_number > session_state.receive_next + session_state.receive_window:
        # Packet beyond window - drop
        return ERROR_WINDOW_OVERFLOW
    
    # Handle in-order packet
    if sequence_number == session_state.receive_next:
        deliver_to_application(data_packet.data)
        session_state.receive_next += data_length
        
        # Process out-of-order buffer
        while len(session_state.receive_buffer) > 0:
            next_packet = find_next_in_order(session_state.receive_buffer, session_state.receive_next)
            if next_packet:
                deliver_to_application(next_packet.data)
                session_state.receive_next += len(next_packet.data)
                remove_from_buffer(session_state.receive_buffer, next_packet)
            else:
                break
        
        # Update receive window
        session_state.receive_window = max(session_state.receive_window - data_length, MIN_CONGESTION_WINDOW)
        
        # Send ACK
        send_ack(session_state.receive_next)
        
    else:
        # Out-of-order packet
        if sequence_number < session_state.receive_next + session_state.receive_window:
            add_to_buffer(session_state.receive_buffer, data_packet)
            send_ack(session_state.receive_next)  # Send duplicate ACK
    
    return SUCCESS

function send_window_update():
    # Send window update using ACK packet when receive buffer is freed
    new_window_size = calculate_available_window()
    
    if new_window_size > session_state.receive_window:
        ack_packet = create_ack_packet(
            ack_number = session_state.receive_next,
            window_size = new_window_size
        )
        send_packet(ack_packet)
        session_state.receive_window = new_window_size

function calculate_available_window():
    # Calculate available receive window
    used_buffer = len(session_state.receive_buffer) + (session_state.receive_next - session_state.send_sequence)
    return MAX_RECEIVE_WINDOW - used_buffer

function handle_zero_window():
    # Handle zero window probe
    if session_state.receive_window == 0:
        # Send zero window probe
        probe_packet = create_zero_window_probe()
        send_packet(probe_packet)
        set_zero_window_timer()
```

## Congestion Control Algorithm
```pseudocode
function update_congestion_window(ack_packet):
    if session_state.congestion_state == SLOW_START:
        # Slow start: exponential growth
        session_state.congestion_window = min(session_state.congestion_window + MSS, MAX_CONGESTION_WINDOW)
        
        if session_state.congestion_window >= session_state.slow_start_threshold:
            session_state.congestion_state = CONGESTION_AVOIDANCE
            
    elif session_state.congestion_state == CONGESTION_AVOIDANCE:
        # Congestion avoidance: linear growth
        session_state.congestion_window = min(session_state.congestion_window + (MSS * MSS / session_state.congestion_window), MAX_CONGESTION_WINDOW)
        
    elif session_state.congestion_state == FAST_RECOVERY:
        # Fast recovery: maintain window size
        session_state.congestion_window = session_state.slow_start_threshold
        session_state.congestion_state = CONGESTION_AVOIDANCE

function handle_congestion_event():
    # Reduce window size on congestion
    session_state.slow_start_threshold = max(session_state.congestion_window / 2, MIN_CONGESTION_WINDOW)
    session_state.congestion_window = MIN_CONGESTION_WINDOW
    session_state.congestion_state = SLOW_START

function handle_fast_recovery():
    # Fast recovery with SACK
    session_state.slow_start_threshold = max(session_state.congestion_window / 2, MIN_CONGESTION_WINDOW)
    session_state.congestion_window = session_state.slow_start_threshold
    session_state.congestion_state = FAST_RECOVERY
```

## Flow Control State Management

```pseudocode
# Flow control state variables
flow_control_state = {
    'send_window': INITIAL_SEND_WINDOW,
    'receive_window': INITIAL_RECEIVE_WINDOW,
    'send_buffer': [],
    'receive_buffer': [],
    'send_next': 0,
    'send_unacked': 0,
    'receive_next': 0,
    'advertised_window': INITIAL_RECEIVE_WINDOW,
    'last_window_update': 0,
    'zero_window_probe_timer': 0
}

function initialize_flow_control():
    flow_control_state.send_window = min(INITIAL_SEND_WINDOW, peer_advertised_window)
    flow_control_state.receive_window = INITIAL_RECEIVE_WINDOW
    flow_control_state.send_next = session_state.local_sequence
    flow_control_state.send_unacked = session_state.local_sequence
    flow_control_state.receive_next = session_state.peer_sequence
```

## Send Window Management

```pseudocode
function can_send_data(data_length):
    # Check if we can send data within current window
    bytes_in_flight = flow_control_state.send_next - flow_control_state.send_unacked
    available_window = flow_control_state.send_window - bytes_in_flight
    
    return data_length <= available_window

function send_data_with_flow_control(data):
    if not can_send_data(len(data)):
        # Buffer data for later transmission
        add_to_send_buffer(data)
        return SUCCESS
    
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
    
    return SUCCESS

function update_send_window(ack_packet):
    # Update based on acknowledgment
    acked_bytes = ack_packet.acknowledgment_number - flow_control_state.send_unacked
    
    if acked_bytes > 0:
        flow_control_state.send_unacked = ack_packet.acknowledgment_number
        
        # Remove acknowledged data from send buffer
        remove_acknowledged_data(acked_bytes)
        
        # Send any buffered data that now fits in window
        attempt_send_buffered_data()
    
    # Update window size from peer advertisement
    flow_control_state.send_window = ack_packet.window_size
    
    # Handle zero window condition
    if flow_control_state.send_window == 0:
        start_zero_window_probing()
    else:
        stop_zero_window_probing()
```

## Receive Window Management

```pseudocode
function process_received_data(data_packet):
    sequence_number = data_packet.sequence_number
    data_length = len(data_packet.data)
    
    # Check if packet is within receive window
    if not is_within_receive_window(sequence_number, data_length):
        # Send duplicate ACK
        send_duplicate_ack()
        return SUCCESS
    
    # Handle in-order data
    if sequence_number == flow_control_state.receive_next:
        # Deliver data to application
        deliver_to_application(data_packet.data)
        flow_control_state.receive_next += data_length
        
        # Process any buffered in-order data
        process_buffered_data()
        
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

function update_receive_window(consumed_bytes):
    # Calculate new available window space
    buffer_space_used = calculate_buffer_space_used()
    max_buffer_space = MAX_RECEIVE_BUFFER_SIZE
    available_space = max_buffer_space - buffer_space_used
    
    # Update advertised window
    flow_control_state.advertised_window = min(available_space, MAX_RECEIVE_WINDOW)
    
    # Send window update if significant change
    window_change_threshold = flow_control_state.receive_window * WINDOW_UPDATE_THRESHOLD
    if abs(flow_control_state.advertised_window - flow_control_state.last_advertised_window) > window_change_threshold:
        send_window_update()
        flow_control_state.last_advertised_window = flow_control_state.advertised_window
```

## Zero Window Handling

```pseudocode
function start_zero_window_probing():
    if flow_control_state.zero_window_probe_timer == 0:
        flow_control_state.zero_window_probe_timer = get_current_time_ms() + ZERO_WINDOW_PROBE_INTERVAL_MS
        schedule_zero_window_probe()

function send_zero_window_probe():
    # Send 1-byte probe packet
    probe_data = get_next_byte_to_send()
    if probe_data != null:
        probe_packet = create_data_packet(
            sequence_number = flow_control_state.send_next,
            data = probe_data,
            window_size = flow_control_state.advertised_window
        )
        
        send_packet(probe_packet)
        
        # Schedule next probe
        flow_control_state.zero_window_probe_timer = get_current_time_ms() + ZERO_WINDOW_PROBE_INTERVAL_MS
        schedule_zero_window_probe()

function stop_zero_window_probing():
    flow_control_state.zero_window_probe_timer = 0
    cancel_zero_window_probe()
```

## Selective Acknowledgment (SACK)

```pseudocode
function send_selective_acknowledgment():
    # Build SACK bitmap for out-of-order received data
    sack_bitmap = build_sack_bitmap()
    
    ack_packet = create_ack_packet(
        acknowledgment_number = flow_control_state.receive_next,
        window_size = flow_control_state.advertised_window,
        selective_ack_bitmap = sack_bitmap
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

function process_selective_acknowledgment(ack_packet):
    sack_bitmap = ack_packet.selective_ack_bitmap
    base_sequence = ack_packet.acknowledgment_number
    
    # Process SACK information
    for i in range(32):
        if sack_bitmap & (1 << i):
            acked_sequence = base_sequence + i + 1
            mark_sequence_acknowledged(acked_sequence)
    
    # Retransmit missing segments
    retransmit_missing_segments(base_sequence, sack_bitmap)
```

## Flow Control Integration with Congestion Control

```pseudocode
function calculate_effective_window():
    # Effective window is minimum of congestion window and flow control window
    congestion_window = session_state.congestion_window
    flow_control_window = flow_control_state.send_window
    
    return min(congestion_window, flow_control_window)

function adjust_transmission_rate():
    effective_window = calculate_effective_window()
    bytes_in_flight = flow_control_state.send_next - flow_control_state.send_unacked
    
    if bytes_in_flight >= effective_window:
        # Stop sending until window opens
        pause_transmission()
    else:
        # Calculate how much we can send
        can_send = effective_window - bytes_in_flight
        resume_transmission(can_send)

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
