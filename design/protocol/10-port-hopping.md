# Port Hopping Specification

## Overview

This document defines the port hopping mechanism that enables the protocol to dynamically change communication ports in a synchronized, predictable manner. Port hopping provides enhanced security through obscurity while maintaining seamless connectivity between authenticated peers.

## Purpose and Rationale

Port hopping serves several critical security and operational functions:

- **Traffic Obfuscation**: Makes protocol traffic harder to identify and target by network monitors
- **DPI Evasion**: Complicates Deep Packet Inspection by distributing traffic across multiple ports
- **Attack Surface Reduction**: Limits exposure by constantly changing the network access point
- **Load Distribution**: Spreads network load across multiple ports for better performance
- **Network Resilience**: Provides redundancy if specific ports become blocked or filtered

The port hopping algorithm uses cryptographic techniques to ensure that only authenticated peers can predict port sequences, while maintaining perfect synchronization across all participants.

## Key Concepts

- **Time Windows**: Fixed 250ms intervals that synchronize port changes across all peers
- **Cryptographic Port Derivation**: HMAC-based calculation ensuring unpredictable but deterministic port selection
- **Session-Specific Sequences**: Each session uses unique port sequences derived from session keys
- **Clock Synchronization**: Precise time alignment ensures all peers hop to the same ports simultaneously
- **Connection Offset**: Mechanisms to prevent port collisions between multiple parallel connections

## Port Calculation Specification

### Time Window Calculation
```pseudocode
# Time windows are 250ms wide and based on UTC time from start of current day
# This ensures synchronized port hopping across all peers regardless of timezone
# 
# Time window calculation:
# 1. Get current UTC time in milliseconds since epoch
# 2. Calculate milliseconds since start of current UTC day
# 3. Divide by 250ms to get current time window number
# 4. Use time window number for port calculation
#
# Example: If current UTC time is 14:30:25.123, then:
# - Milliseconds since start of day = (14*3600 + 30*60 + 25)*1000 + 123 = 52225123ms
# - Time window = 52225123 // 250 = 208900 (window number)
# - Port will be calculated using this window number
```

### Connection Offset Derivation for Multiple Parallel Connections

```pseudocode
function derive_connection_offset(daily_key, src_endpoint, dst_endpoint, connection_id):
    # Derive unique port offset for each connection between same endpoints
    # This prevents port collisions when multiple connections exist between same hosts
    # The offset is derived cryptographically and never transmitted
    
    # Create connection-specific context for HKDF domain separation
    src_bytes = endpoint_to_bytes(src_endpoint)  # IP:port as bytes
    dst_bytes = endpoint_to_bytes(dst_endpoint)  # IP:port as bytes
    conn_id_bytes = uint64_to_bytes(connection_id)
    
    # HKDF domain separation using connection-specific info
    # This ensures different connections get different offsets
    connection_context = src_bytes || dst_bytes || conn_id_bytes
    
    # Use HKDF-Extract with daily key as input key material
    salt = b"connection_offset_salt"
    prk = HMAC_SHA256_128(salt, daily_key)
    
    # Use HKDF-Expand with connection context for domain separation
    info = b"port_offset" || connection_context
    offset_material = hkdf_expand_sha256(prk, info, 4)  # 4 bytes for offset
    
    # Extract 12-bit offset value (0-4095)
    offset_value = (offset_material[0] << 4) | (offset_material[1] >> 4)
    connection_offset = offset_value & 0x0FFF  # Mask to 12 bits
    
    return connection_offset

function endpoint_to_bytes(endpoint):
    # Convert IP:port endpoint to canonical byte representation
    # For IPv4: 4 bytes IP + 2 bytes port = 6 bytes
    # For IPv6: 16 bytes IP + 2 bytes port = 18 bytes
    ip_bytes = ip_address_to_bytes(endpoint.ip)
    port_bytes = uint16_to_bytes(endpoint.port)
    return ip_bytes || port_bytes
```

### Enhanced Port Calculation Algorithm with Connection Offsets

```pseudocode
function calculate_port_with_offset(daily_key, session_id, time_window, src_endpoint, dst_endpoint, connection_id):
    # Calculate port with connection-specific offset to prevent collisions
    # between multiple parallel connections
    
    # Derive connection-specific offset (never transmitted)
    connection_offset = derive_connection_offset(daily_key, src_endpoint, dst_endpoint, connection_id)
    
    # Calculate base port using existing algorithm
    session_id_bytes = uint64_to_bytes(session_id)
    time_window_bytes = uint64_to_bytes(time_window)
    offset_bytes = uint32_to_bytes(connection_offset)
    
    # Include connection offset in HMAC calculation
    hmac_input = time_window_bytes || session_id_bytes || offset_bytes
    hmac_result = HMAC_SHA256_128(daily_key, hmac_input)
    
    # Extract port value and apply offset
    base_port_value = (hmac_result[0] << 8) | hmac_result[1]
    
    # Apply connection offset to create separated port ranges
    offset_port_range = PORT_RANGE - PORT_OFFSET_RANGE
    base_port = MIN_PORT + (base_port_value % offset_port_range)
    
    # Add connection-specific offset
    final_port = base_port + (connection_offset * (PORT_OFFSET_RANGE / MAX_CONNECTION_OFFSET))
    
    # Ensure port stays within valid range
    if final_port > MAX_PORT:
        final_port = MIN_PORT + ((final_port - MIN_PORT) % PORT_RANGE)
    
    return final_port
```

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

## Port Collision Avoidance for Multiple Parallel Connections

### Design Overview

When multiple connections exist between the same two hosts, each connection must use different ports at any given time to prevent datagram delivery conflicts. The solution uses **cryptographic derivation** of connection-specific port offsets without exposing these offsets during connection establishment.

### Key Security Properties

1. **Zero Exposure**: Connection offsets are never transmitted or exposed during handshake
2. **Cryptographic Randomness**: Each connection gets a unique, unpredictable offset derived from HKDF
3. **Domain Separation**: HKDF ensures different connections produce independent offsets
4. **Collision Resistance**: 12-bit offset space (4096 values) provides sufficient separation
5. **Deterministic**: Both endpoints derive the same offset from the same connection parameters

### Collision Avoidance Mechanism

```pseudocode
# Example: Two parallel connections between Host A and Host B

Connection 1:
- connection_id = 0x1234567890ABCDEF
- Derived offset = 0x042 (66 decimal)
- Port calculation includes offset 66

Connection 2:
- connection_id = 0xFEDCBA0987654321  
- Derived offset = 0x7A1 (1953 decimal)
- Port calculation includes offset 1953

# At any time window, these connections use different port ranges:
# Connection 1: ports in range [base_port + 66*offset_multiplier]
# Connection 2: ports in range [base_port + 1953*offset_multiplier]
# No collision possible between the two connections
```

### Connection ID Generation for Collision Avoidance

```pseudocode
function generate_connection_id(local_endpoint, remote_endpoint, local_random):
    # Generate unique connection ID that ensures different connections
    # get different offsets even if endpoints are the same
    
    # Use local random entropy to ensure uniqueness
    local_bytes = endpoint_to_bytes(local_endpoint)
    remote_bytes = endpoint_to_bytes(remote_endpoint)
    timestamp_bytes = uint64_to_bytes(get_current_time_ms())
    random_bytes = get_secure_random_bytes(16)  # 128-bit random
    
    # Combine all sources for unique connection ID
    id_material = local_bytes || remote_bytes || timestamp_bytes || random_bytes
    
    # Hash to create 64-bit connection ID
    hash_result = SHA256(id_material)
    connection_id = bytes_to_uint64(hash_result[0:8])
    
    return connection_id
```

### Port Range Management

The 64,512 available ports (1024-65535) are divided into offset ranges:

- **Base Range**: 48,384 ports for base port calculation
- **Offset Range**: 16,128 ports for connection offsets  
- **Maximum Connections**: 4,096 parallel connections supported
- **Per-Connection Range**: ~4 ports per connection offset

This design ensures sufficient port space while maintaining security and collision avoidance.