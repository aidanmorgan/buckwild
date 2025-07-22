# Adaptive Delay and Measurement Specification

## Overview

This document specifies the adaptive delay measurement and tuning mechanisms that optimize port hopping timing based on real-time network conditions. The adaptive system dynamically adjusts delay allowances to balance security (minimal port exposure) with reliability (sufficient tolerance for network variations).

## Purpose and Rationale

Adaptive delay tuning serves critical performance and security optimization functions:

- **Network Adaptation**: Automatically adjusts to varying network conditions including latency, jitter, and packet loss
- **Security Optimization**: Minimizes port exposure time while maintaining sufficient tolerance for legitimate packet delays
- **Performance Efficiency**: Reduces unnecessary port listening overhead while preventing packet loss due to timing mismatches
- **Dynamic Response**: Continuously measures and adapts to changing network characteristics without manual configuration
- **Peer Coordination**: Negotiates optimal delay parameters between peers to ensure synchronized timing expectations

The adaptive approach eliminates the need for static delay configurations while providing optimal performance across diverse network environments and conditions.

## Key Concepts

- **Delay Window**: The number of time windows (port positions) kept open to accommodate network transmission delays
- **Adaptive Measurement**: Continuous collection and analysis of packet arrival timing statistics
- **Delay Negotiation**: Peer-to-peer coordination of delay parameters using HEARTBEAT packet extensions
- **Statistical Analysis**: Use of percentile-based calculations (95th percentile) to determine appropriate delay allowances
- **Network Jitter**: Measurement and compensation for network timing variations and inconsistencies

## Adaptive Transmission Delay Handling

```pseudocode
# Adaptive delay allowance strategy:
# The protocol dynamically determines the number of ports to keep open based on 
# measured network characteristics rather than using fixed values. This provides
# optimal balance between security (fewer open ports) and reliability (sufficient
# delay tolerance). Delay parameters are periodically negotiated between hosts
# using existing HEARTBEAT packets with extended payload.
#
# Adaptive strategy:
# 1. Continuously measure packet delays and network jitter
# 2. Calculate required delay window using statistical analysis (95th percentile)
# 3. Periodically negotiate delay parameters with peer using HEARTBEAT packets
# 4. Adjust port listening window based on negotiated parameters
# 5. Fallback to conservative defaults if negotiation fails

// Adaptive delay state management
adaptive_delay_state = {
    'current_delay_window': ADAPTIVE_DELAY_WINDOW_MIN,
    'negotiated_delay_window': ADAPTIVE_DELAY_WINDOW_MIN,
    'delay_measurements': [],
    'last_negotiation_time': 0,
    'peer_delay_window': ADAPTIVE_DELAY_WINDOW_MIN,
    'network_jitter': 0,
    'packet_loss_rate': 0.0,
    'adaptation_enabled': true
}

function initialize_adaptive_delay():
    adaptive_delay_state.current_delay_window = ADAPTIVE_DELAY_WINDOW_MIN
    adaptive_delay_state.negotiated_delay_window = ADAPTIVE_DELAY_WINDOW_MIN
    adaptive_delay_state.delay_measurements = []
    adaptive_delay_state.last_negotiation_time = get_current_time_ms()
    adaptive_delay_state.peer_delay_window = ADAPTIVE_DELAY_WINDOW_MIN
    adaptive_delay_state.network_jitter = 0
    adaptive_delay_state.packet_loss_rate = 0.0
    adaptive_delay_state.adaptation_enabled = true

function get_current_port_with_adaptive_delay_allowance(daily_key, session_id, src_endpoint, dst_endpoint, connection_id):
    # Calculate current port with adaptive allowance for transmission delay
    # Uses dynamically determined delay window based on network characteristics
    
    # Get current effective delay window
    effective_delay_window = get_effective_delay_window()
    
    # Get current time window
    current_time_window = get_current_time_window()
    
    # Calculate ports for adaptive delay window
    ports = []
    
    # Calculate symmetric window around current time
    half_window = effective_delay_window // 2
    start_offset = -half_window
    end_offset = half_window + (effective_delay_window % 2)  # Handle odd window sizes
    
    for offset in range(start_offset, end_offset + 1):
        time_window = current_time_window + offset
        port = calculate_port_with_offset(daily_key, session_id, time_window, src_endpoint, dst_endpoint, connection_id)
        ports.append(port)
    
    return ports

function get_effective_delay_window():
    # Get current effective delay window size
    if not adaptive_delay_state.adaptation_enabled:
        return ADAPTIVE_DELAY_WINDOW_MIN
    
    # Use negotiated value if available and recent
    current_time = get_current_time_ms()
    negotiation_age = current_time - adaptive_delay_state.last_negotiation_time
    
    if negotiation_age < DELAY_NEGOTIATION_INTERVAL_MS * 2:
        return adaptive_delay_state.negotiated_delay_window
    
    # Fall back to locally calculated value
    return adaptive_delay_state.current_delay_window
```

## Network Delay Measurement and Analysis

```pseudocode
function measure_packet_delay(packet):
    # Measure packet delay for adaptive delay window calculation
    if not packet.contains_timestamp():
        return
    
    current_time = get_current_time_ms()
    packet_timestamp = packet.get_timestamp()
    
    # Calculate packet delay (time difference between expected and actual arrival)
    expected_time_window = calculate_time_window_from_timestamp(packet_timestamp)
    actual_time_window = get_current_time_window()
    
    # Convert time window difference to milliseconds
    delay_ms = (actual_time_window - expected_time_window) * HOP_INTERVAL_MS
    
    # Only record positive delays (packets arriving late)
    if delay_ms >= 0:
        record_delay_measurement(delay_ms)

function record_delay_measurement(delay_ms):
    # Record delay measurement for statistical analysis
    current_time = get_current_time_ms()
    
    measurement = {
        'delay_ms': delay_ms,
        'timestamp': current_time,
        'sequence': get_next_measurement_sequence()
    }
    
    # Add to measurements buffer
    adaptive_delay_state.delay_measurements.append(measurement)
    
    # Maintain buffer size
    if len(adaptive_delay_state.delay_measurements) > DELAY_MEASUREMENT_SAMPLES * 2:
        # Remove oldest measurements
        adaptive_delay_state.delay_measurements = adaptive_delay_state.delay_measurements[-DELAY_MEASUREMENT_SAMPLES:]
    
    # Update delay window if we have enough samples
    if len(adaptive_delay_state.delay_measurements) >= DELAY_MEASUREMENT_SAMPLES:
        update_adaptive_delay_window()

function update_adaptive_delay_window():
    # Update adaptive delay window based on statistical analysis
    recent_measurements = get_recent_delay_measurements()
    
    if len(recent_measurements) < DELAY_MEASUREMENT_SAMPLES // 2:
        return  # Insufficient data
    
    # Calculate statistical metrics
    delays = [m.delay_ms for m in recent_measurements]
    
    # Calculate 95th percentile delay
    delays.sort()
    percentile_index = int(len(delays) * DELAY_PERCENTILE_TARGET / 100)
    percentile_delay = delays[min(percentile_index, len(delays) - 1)]
    
    # Calculate network jitter (standard deviation)
    mean_delay = sum(delays) / len(delays)
    variance = sum((d - mean_delay) ** 2 for d in delays) / len(delays)
    jitter = math.sqrt(variance)
    
    # Update network statistics
    adaptive_delay_state.network_jitter = jitter
    
    # Calculate required delay window
    # Convert delay to time windows, add safety margin
    safety_margin = max(SAFETY_MARGIN_MS, jitter)
    total_delay_allowance = percentile_delay + safety_margin
    required_windows = math.ceil(total_delay_allowance / HOP_INTERVAL_MS)
    
    # Apply bounds
    new_delay_window = max(ADAPTIVE_DELAY_WINDOW_MIN, 
                          min(required_windows, ADAPTIVE_DELAY_WINDOW_MAX))
    
    # Update current delay window with smoothing
    if adaptive_delay_state.current_delay_window == 0:
        adaptive_delay_state.current_delay_window = new_delay_window
    else:
        # Apply exponential smoothing to prevent rapid changes
        smoothing_factor = 0.3
        adaptive_delay_state.current_delay_window = int(
            (1 - smoothing_factor) * adaptive_delay_state.current_delay_window +
            smoothing_factor * new_delay_window
        )

function get_recent_delay_measurements():
    # Get recent delay measurements for analysis
    current_time = get_current_time_ms()
    cutoff_time = current_time - DELAY_NEGOTIATION_INTERVAL_MS
    
    recent_measurements = []
    for measurement in adaptive_delay_state.delay_measurements:
        if measurement.timestamp >= cutoff_time:
            recent_measurements.append(measurement)
    
    return recent_measurements

function calculate_packet_loss_rate():
    # Calculate packet loss rate for delay window adjustment
    if len(adaptive_delay_state.delay_measurements) < DELAY_MEASUREMENT_SAMPLES:
        return 0.0
    
    # Use sequence numbers to detect missing packets
    recent_measurements = get_recent_delay_measurements()
    if len(recent_measurements) < 2:
        return 0.0
    
    # Calculate expected vs received packets
    min_seq = min(m.sequence for m in recent_measurements)
    max_seq = max(m.sequence for m in recent_measurements)
    expected_packets = max_seq - min_seq + 1
    received_packets = len(recent_measurements)
    
    if expected_packets <= 0:
        return 0.0
    
    loss_rate = (expected_packets - received_packets) / expected_packets
    adaptive_delay_state.packet_loss_rate = max(0.0, min(1.0, loss_rate))
    
    return adaptive_delay_state.packet_loss_rate
```

## Delay Parameter Negotiation Using HEARTBEAT Packets

```pseudocode
function create_enhanced_heartbeat_packet():
    # Create HEARTBEAT packet with delay negotiation parameters
    base_heartbeat = create_heartbeat_packet()
    
    # Add delay negotiation payload
    delay_payload = {
        'current_delay_window': adaptive_delay_state.current_delay_window,
        'network_jitter': int(adaptive_delay_state.network_jitter),
        'packet_loss_rate': int(adaptive_delay_state.packet_loss_rate * 1000),  # Encode as per-mille
        'measurement_count': len(adaptive_delay_state.delay_measurements),
        'adaptation_enabled': adaptive_delay_state.adaptation_enabled,
        'negotiation_sequence': get_negotiation_sequence()
    }
    
    # Serialize delay payload (compact encoding)
    serialized_payload = serialize_delay_payload(delay_payload)
    
    # Append to heartbeat packet payload
    enhanced_payload = base_heartbeat.payload + serialized_payload
    base_heartbeat.payload = enhanced_payload
    base_heartbeat.payload_length = len(enhanced_payload)
    
    return base_heartbeat

function process_enhanced_heartbeat_packet(heartbeat_packet):
    # Process HEARTBEAT packet with delay negotiation parameters
    base_result = process_base_heartbeat(heartbeat_packet)
    
    if base_result != SUCCESS:
        return base_result
    
    # Extract delay negotiation payload
    if len(heartbeat_packet.payload) <= BASE_HEARTBEAT_PAYLOAD_SIZE:
        return SUCCESS  # No delay negotiation data
    
    delay_payload_data = heartbeat_packet.payload[BASE_HEARTBEAT_PAYLOAD_SIZE:]
    delay_payload = deserialize_delay_payload(delay_payload_data)
    
    if delay_payload == null:
        return SUCCESS  # Invalid delay data, ignore
    
    # Process peer's delay parameters
    return process_peer_delay_parameters(delay_payload)

function process_peer_delay_parameters(peer_delay_payload):
    # Process peer's delay parameters and negotiate optimal window
    peer_window = peer_delay_payload.current_delay_window
    peer_jitter = peer_delay_payload.network_jitter
    peer_loss_rate = peer_delay_payload.packet_loss_rate / 1000.0  # Convert from per-mille
    
    # Store peer parameters
    adaptive_delay_state.peer_delay_window = peer_window
    
    # Calculate negotiated delay window
    # Use maximum of local and peer requirements, with loss rate adjustment
    local_window = adaptive_delay_state.current_delay_window
    
    # Adjust for packet loss (increase window if high loss rate)
    loss_adjustment = 0
    if peer_loss_rate > 0.05:  # > 5% loss rate
        loss_adjustment = max(1, int(peer_loss_rate * 10))
    
    negotiated_window = max(local_window, peer_window) + loss_adjustment
    
    # Apply bounds
    negotiated_window = max(ADAPTIVE_DELAY_WINDOW_MIN,
                           min(negotiated_window, ADAPTIVE_DELAY_WINDOW_MAX))
    
    # Update negotiated parameters
    adaptive_delay_state.negotiated_delay_window = negotiated_window
    adaptive_delay_state.last_negotiation_time = get_current_time_ms()
    
    # Log negotiation result
    log_delay_negotiation(local_window, peer_window, negotiated_window)
    
    return SUCCESS

function serialize_delay_payload(delay_payload):
    # Compact serialization of delay negotiation payload
    # Total size: 8 bytes for efficient transmission
    
    # Pack into 64-bit structure:
    # Bits 0-7: current_delay_window (8 bits, max 255)
    # Bits 8-19: network_jitter (12 bits, max 4095ms)
    # Bits 20-29: packet_loss_rate (10 bits, 0-1023 per-mille)
    # Bits 30-37: measurement_count (8 bits, max 255)
    # Bits 38-47: negotiation_sequence (10 bits, rolling counter)
    # Bit 48: adaptation_enabled (1 bit)
    # Bits 49-63: reserved (15 bits)
    
    packed_data = 0
    packed_data |= (delay_payload.current_delay_window & 0xFF)
    packed_data |= ((delay_payload.network_jitter & 0xFFF) << 8)
    packed_data |= ((delay_payload.packet_loss_rate & 0x3FF) << 20)
    packed_data |= ((delay_payload.measurement_count & 0xFF) << 30)
    packed_data |= ((delay_payload.negotiation_sequence & 0x3FF) << 38)
    packed_data |= ((1 if delay_payload.adaptation_enabled else 0) << 48)
    
    return packed_data.to_bytes(8, 'big')

function deserialize_delay_payload(payload_data):
    # Deserialize compact delay negotiation payload
    if len(payload_data) < 8:
        return null
    
    packed_data = int.from_bytes(payload_data[0:8], 'big')
    
    return {
        'current_delay_window': packed_data & 0xFF,
        'network_jitter': (packed_data >> 8) & 0xFFF,
        'packet_loss_rate': (packed_data >> 20) & 0x3FF,
        'measurement_count': (packed_data >> 30) & 0xFF,
        'negotiation_sequence': (packed_data >> 38) & 0x3FF,
        'adaptation_enabled': bool((packed_data >> 48) & 0x1)
    }

function should_trigger_delay_negotiation():
    # Determine if delay negotiation should be triggered
    current_time = get_current_time_ms()
    time_since_last = current_time - adaptive_delay_state.last_negotiation_time
    
    # Periodic negotiation
    if time_since_last >= DELAY_NEGOTIATION_INTERVAL_MS:
        return true
    
    # Significant change in network conditions
    if adaptive_delay_state.current_delay_window != adaptive_delay_state.negotiated_delay_window:
        change_magnitude = abs(adaptive_delay_state.current_delay_window - 
                              adaptive_delay_state.negotiated_delay_window)
        if change_magnitude >= 2:  # Significant change
            return true
    
    # High packet loss detected
    if adaptive_delay_state.packet_loss_rate > 0.1:  # > 10% loss
        return true
    
    return false

function handle_adaptive_delay_on_packet_receive(packet):
    # Handle adaptive delay processing on packet reception
    
    # Measure packet delay
    measure_packet_delay(packet)
    
    # Update packet loss statistics
    calculate_packet_loss_rate()
    
    # Check if negotiation should be triggered
    if should_trigger_delay_negotiation():
        schedule_delay_negotiation()

function schedule_delay_negotiation():
    # Schedule delay parameter negotiation in next heartbeat
    session_state.pending_delay_negotiation = true
```

## Delay Tuning Constants

```pseudocode
// Adaptive delay constants
ADAPTIVE_DELAY_WINDOW_MIN = 1            // Minimum delay window size (time windows)
ADAPTIVE_DELAY_WINDOW_MAX = 16           // Maximum delay window size (time windows)
DELAY_MEASUREMENT_SAMPLES = 10           // Number of samples for delay measurement
DELAY_NEGOTIATION_INTERVAL_MS = 60000    // Delay parameters negotiation interval (1 minute)
DELAY_PERCENTILE_TARGET = 95             // Target percentile for delay allowance (95th percentile)
BASE_HEARTBEAT_PAYLOAD_SIZE = 8          // Size of base heartbeat payload (bytes)
SAFETY_MARGIN_MS = 100                   // Safety margin for delay calculations
BASE_TRANSMISSION_DELAY_ALLOWANCE_MS = 1000 // Base allowance for network transmission delay
```