# Synchronized Port Hopping for Network Security

This document defines the synchronized port hopping mechanism that enables the protocol to dynamically change communication ports in a coordinated, predictable manner while maintaining security through cryptographically derived sequences.

## Overview

The port hopping system provides enhanced security through traffic obfuscation by continuously changing communication ports in synchronized 500ms intervals. All port sequences are cryptographically derived from ECDH shared secrets, ensuring only authenticated peers can predict and follow port transitions.

**Maximum Port Range Usage (1024-65535):**
The protocol uses the maximum realistic port range (all non-privileged ports) for hopping operations, providing several advantages:
- **Maximum Security**: 64,512 available ports provide maximum obfuscation and unpredictability
- **Enhanced Performance**: Larger port space reduces predictability and improves security

## Purpose and Rationale

Port hopping serves several critical security and operational functions:

- **Traffic Obfuscation**: Makes protocol traffic harder to identify and target by network monitors and attackers
- **DPI Evasion**: Complicates Deep Packet Inspection by distributing traffic across multiple ports dynamically
- **Attack Surface Reduction**: Limits exposure by constantly changing the network access point and communication vectors
- **Load Distribution**: Spreads network load across multiple ports for better performance and bandwidth utilization
- **Network Resilience**: Provides redundancy if specific ports become blocked, filtered, or unavailable
- **Collision Avoidance**: Ensures multiple parallel connections between peers use different ports to prevent conflicts

The port hopping algorithm uses PBKDF2 derivation from ECDH shared secrets to ensure that only authenticated peers can predict port sequences, while maintaining perfect synchronization across all participants.

## Key Concepts

- **Time Windows**: Fixed 500ms intervals that synchronize port changes across all peers using UTC time
- **PBKDF2-Based Port Derivation**: Port offsets derived from ECDH shared secret using PBKDF2 key derivation functions
- **Session-Specific Sequences**: Each session uses unique port sequences derived from ephemeral DH key exchange
- **16-bit Chunk Derivation**: Port parameters extracted from PBKDF2 output as 16-bit chunks per protocol specification
- **Clock Synchronization**: Precise time alignment ensures all peers hop to the same ports simultaneously
- **Connection Offset**: Cryptographic mechanisms to prevent port collisions between multiple parallel connections
- **Adaptive Windows**: Dynamic port ranges that accommodate network delay variations

## Time Window Calculation

### UTC-Based Time Windows

```pseudocode
# Time windows are 500ms wide and based on UTC time from start of current day
# This ensures synchronized port hopping across all peers regardless of timezone
# 
# Time window calculation:
# 1. Get current UTC time in milliseconds since epoch
# 2. Calculate milliseconds since start of current UTC day
# 3. Divide by 500ms to get current time window number
# 4. Use time window number for port calculation
#
# Example: If current UTC time is 14:30:25.123, then:
# - Milliseconds since start of day = (14*3600 + 30*60 + 25)*1000 + 123 = 52225123ms
# - Time window = 52225123 // 500 = 104450 (window number)
# - Port will be calculated using this window number

function calculate_time_window(current_time_ms):
    # Calculate time window number from UTC time
    ms_per_day = 24 * 60 * 60 * 1000  # 86400000 ms
    ms_since_day_start = current_time_ms % ms_per_day
    
    time_window = ms_since_day_start // HOP_INTERVAL_MS
    return time_window

function get_current_time_window():
    # Get current time window for port calculation
    current_utc_ms = get_current_utc_time_ms()
    return calculate_time_window(current_utc_ms)

function get_synchronized_time_window():
    # Get time window using synchronized time from time sync module
    synchronized_time = get_synchronized_time()  # From time sync module
    return calculate_time_window(synchronized_time)

function calculate_next_hop_time():
    # Calculate exact time of next port hop
    current_window = get_synchronized_time_window()
    next_window = current_window + 1
    
    synchronized_time = get_synchronized_time()
    ms_since_day_start = synchronized_time % MILLISECONDS_PER_DAY
    
    next_hop_ms = next_window * HOP_INTERVAL_MS
    current_utc_day_start = synchronized_time - ms_since_day_start
    
    return current_utc_day_start + next_hop_ms

function time_until_next_hop():
    # Calculate time remaining until next port hop
    next_hop_time = calculate_next_hop_time()
    current_time = get_synchronized_time()
    
    return max(0, next_hop_time - current_time)
```

## Connection Offset Derivation

### ECDH-Based Port Parameter Derivation

```pseudocode
function derive_session_port_parameters(ecdh_shared_secret, client_pubkey, server_pubkey, session_id):
    # Derive simplified port hopping parameters from ECDH shared secret
    # No collision avoidance needed - packets routed by session ID
    
    # Create session-specific salt combining public keys and session ID
    salt = SHA256(client_pubkey || server_pubkey || session_id.to_bytes(8, 'big') || b"port_derivation_v3")
    
    # Use PBKDF2 to derive port material from ECDH shared secret
    port_material = PBKDF2_HMAC_SHA256(
        password = ecdh_shared_secret,
        salt = salt,
        iterations = PBKDF2_ITERATIONS_PORT,
        key_length = 12     # 96 bits = 6 chunks of 16 bits each (simplified)
    )
    
    # Extract as 16-bit chunks as per protocol specification
    chunks = []
    for i in range(0, 12, 2):  # 6 chunks total
        chunk = bytes_to_uint16(port_material[i:i+2])
        chunks.append(chunk)
    
    # Derive simplified port parameters (no collision avoidance)
    port_seed = chunks[0] << 16 | chunks[1]              # 32-bit primary port seed
    hop_sequence_seed = chunks[2] << 16 | chunks[3]      # 32-bit hop sequence seed  
    time_variance = chunks[4] % 100                      # Up to 100ms time variance
    hop_pattern_seed = chunks[5]                         # 16-bit pattern seed
    
    return {
        'port_seed': port_seed,
        'hop_sequence_seed': hop_sequence_seed,
        'time_variance': time_variance,
        'hop_pattern_seed': hop_pattern_seed
    }

function derive_connection_offset_from_ecdh(shared_secret, client_pubkey, server_pubkey, session_id):
    # Simplified version for existing connections - derive just the offset
    port_params = derive_session_port_parameters(shared_secret, client_pubkey, server_pubkey, session_id)
    return port_params.connection_offset
```

### Port Calculation Algorithm

```pseudocode
function calculate_base_port_for_time_window(time_window):
    # Calculate the base port for any given time window
    # This algorithm is shared across all connections and provides the base sequence
    
    # Use deterministic but unpredictable function based on time window
    time_bytes = time_window.to_bytes(8, 'big')
    hash_result = SHA256(time_bytes || b"base_port_sequence_v2")
    
    # Extract port value from hash (use multiple hash outputs for better distribution)
    port_value = bytes_to_uint32(hash_result[0:4])
    port_range = MAX_PORT - MIN_PORT + 1
    base_port = MIN_PORT + (port_value % port_range)
    
    return base_port

function calculate_port_for_time_window(port_params, time_window):
    # Calculate port using simplified algorithm - full port range available
    # Combines time window with session-specific port seed for maximum distribution
    
    # Combine time window and port seed for this hop
    combined_seed = (time_window * 0x9E3779B9) ^ port_params.port_seed  # Golden ratio multiplier
    
    # Apply hop sequence modification
    hop_modifier = (port_params.hop_sequence_seed >> (time_window % 16)) & 0xFFFF
    final_seed = combined_seed ^ hop_modifier
    
    # Calculate port within full available range
    port_value = final_seed % PORT_RANGE
    final_port = MIN_PORT + port_value
    
    # Ensure port is within valid range (should always be true with proper modulo)
    return max(MIN_PORT, min(final_port, MAX_PORT))

function get_current_session_port(port_params):
    # Get the current port using simplified calculation
    current_time_window = get_synchronized_time_window()
    return calculate_port_for_time_window(port_params, current_time_window)

function get_next_session_port(port_params):
    # Get the next port using simplified calculation
    current_time_window = get_synchronized_time_window()
    next_time_window = current_time_window + 1
    return calculate_port_for_time_window(port_params, next_time_window)

function get_port_for_time_window(port_params, time_window):
    # Get port for any specific time window using simplified calculation
    return calculate_port_for_time_window(port_params, time_window)
```

## Adaptive Port Windows

### Dynamic Port Range Calculation

```pseudocode
function calculate_ports_for_delay_window(port_params, delay_window):
    # Calculate all valid ports for current delay window using simplified algorithm
    # With full port range and session ID routing, duplicates are much less likely
    
    current_time_window = get_synchronized_time_window()
    ports = []
    
    # Calculate symmetric window around current time
    half_window = delay_window // 2
    start_offset = -half_window
    end_offset = half_window + (delay_window % 2)  # Handle odd window sizes
    
    for offset in range(start_offset, end_offset + 1):
        time_window = current_time_window + offset
        port = calculate_port_for_time_window(port_params, time_window)
        ports.append(port)
    
    # With 64K port range, duplicates are extremely rare, but handle them anyway
    unique_ports = list(dict.fromkeys(ports))  # Preserves order, removes duplicates
    
    return unique_ports

function get_current_port_with_adaptive_delay_allowance(port_params):
    # Get ports for current delay window from adaptive delay system
    effective_delay_window = get_effective_delay_window()  # From adaptive delay module
    
    return calculate_ports_for_delay_window(port_params, effective_delay_window)

function should_listen_on_port(port, port_params, max_delay_window):
    # Determine if we should listen on a specific port given delay tolerances
    current_ports = calculate_ports_for_delay_window(port_params, max_delay_window)
    return port in current_ports

function get_future_ports(port_params, num_windows):
    # Get ports for next N time windows for preemptive listening
    current_time_window = get_synchronized_time_window()
    future_ports = []
    
    for i in range(1, num_windows + 1):
        future_window = current_time_window + i
        port = calculate_port_for_time_window(port_params, future_window)
        future_ports.append(port)
    
    return future_ports
```

## Session ID-Based Packet Routing

```pseudocode  
function generate_unique_session_id():
    # Generate cryptographically unique session ID for packet routing
    timestamp_ms = get_current_time_ms()
    random_entropy = get_secure_random_bytes(16)  # 128-bit random
    local_endpoint = get_local_endpoint_bytes()
    remote_endpoint = get_remote_endpoint_bytes()
    
    # Combine sources for unique session ID
    id_material = (
        timestamp_ms.to_bytes(8, 'big') ||
        random_entropy ||
        local_endpoint ||
        remote_endpoint ||
        b"session_id_v3"
    )
    
    # Hash to create 64-bit session ID
    hash_result = SHA256(id_material)
    session_id = bytes_to_uint64(hash_result[0:8])
    
    return session_id

function route_packet_by_session_id(packet):
    # Route incoming packet to correct session based on session ID
    # No port collision concerns - packet destination determined by session ID
    
    session_id = packet.session_id
    target_session = lookup_session_by_id(session_id)
    
    if target_session == null:
        # Unknown session ID - may be expired or invalid
        log_unknown_session_packet(session_id, packet.source_port)
        return ERROR_SESSION_NOT_FOUND
    
    # Forward packet to appropriate session handler
    return target_session.process_packet(packet)

function is_valid_session_port(session_id, source_port, time_window):
    # Verify that packet arrived on expected port for this session and time window
    session = lookup_session_by_id(session_id)
    
    if session == null:
        return false
    
    expected_port = calculate_port_for_time_window(session.port_params, time_window)
    return source_port == expected_port
```

## Port Transition Management

### Synchronized Port Hopping

```pseudocode
function schedule_port_hop(port_params):
    # Schedule next port hop with precise timing
    next_hop_time = calculate_next_hop_time()
    current_time = get_synchronized_time()
    
    delay_until_hop = next_hop_time - current_time
    
    if delay_until_hop > 0:
        schedule_timer_callback(delay_until_hop, execute_port_hop, port_params)
    else:
        # Time has already passed - hop immediately
        execute_port_hop(port_params)

function execute_port_hop(port_params):
    # Execute synchronized port hop
    old_port = get_current_session_port(port_params)
    
    # Calculate new port for current time window
    new_port = get_current_session_port(port_params)
    
    if old_port != new_port:
        # Perform port transition
        transition_to_new_port(old_port, new_port, port_params)
    
    # Schedule next hop
    schedule_port_hop(port_params)

function transition_to_new_port(old_port, new_port, port_params):
    # Gracefully transition from old port to new port
    
    # 1. Start listening on new port
    bind_to_port(new_port)
    
    # 2. Continue listening on old port briefly for delayed packets
    delay_window = get_port_transition_delay_window()
    schedule_timer_callback(delay_window, unbind_from_port, old_port)
    
    # 3. Update current port state
    session_state.current_port = new_port
    session_state.port_history.append({
        'port': old_port,
        'end_time': get_current_time_ms(),
        'window': get_synchronized_time_window() - 1
    })
    
    # 4. Trim port history
    if len(session_state.port_history) > PORT_HISTORY_SIZE:
        session_state.port_history.pop(0)
    
    log_port_hop(old_port, new_port, get_synchronized_time_window())

function get_port_transition_delay_window():
    # Calculate delay window for port transition overlap
    # Accounts for network delay and clock synchronization tolerances
    
    base_delay = TIME_SYNC_TOLERANCE_MS * 2  # Double the sync tolerance
    network_delay = get_estimated_network_delay()  # From RTT measurements
    safety_margin = SAFETY_MARGIN_MS
    
    total_delay = base_delay + network_delay + safety_margin
    
    # Ensure reasonable bounds
    return max(50, min(total_delay, 500))  # 50ms to 500ms range

function preemptive_port_binding(port_params, lookahead_windows):
    # Preemptively bind to future ports for seamless transitions
    future_ports = get_future_ports(port_params, lookahead_windows)
    
    for port in future_ports:
        if not is_port_bound(port):
            try:
                bind_to_port(port)
                log_preemptive_binding(port)
            except PortBindingException:
                log_port_binding_failure(port)

function cleanup_old_port_bindings():
    # Clean up old port bindings that are no longer needed
    current_window = get_synchronized_time_window()
    
    for port_info in session_state.port_history:
        window_age = current_window - port_info.window
        
        if window_age > MAX_PORT_HISTORY_RETENTION:
            if is_port_bound(port_info.port):
                unbind_from_port(port_info.port)
                log_port_cleanup(port_info.port)
```

## Port Range Management

### Port Space Allocation

```pseudocode
# Port range constants and management (maximum range with session ID routing)
PORT_SPACE_TOTAL = MAX_PORT - MIN_PORT + 1      # 64,512 total non-privileged ports (1024-65535)
MAX_PARALLEL_CONNECTIONS = 65536               # Theoretical maximum (limited by session ID space)
PRACTICAL_CONNECTION_LIMIT = 10000             # Practical limit for most deployments

function validate_port_range_parameters():
    # Validate port range configuration is consistent
    assert MIN_PORT >= 1024, "Minimum port must be 1024 or higher (non-privileged)"
    assert MAX_PORT <= 65535, "Maximum port must be 65535 or lower"
    assert PORT_SPACE_TOTAL > 0, "Port space must be positive"
    
    log_port_range_info("Using maximum port range", PORT_SPACE_TOTAL, "ports available")
    
    return true

function calculate_port_utilization():
    # Calculate current port space utilization with simplified metrics
    active_connections = get_active_connection_count()
    practical_max = PRACTICAL_CONNECTION_LIMIT
    
    utilization_percentage = (active_connections / practical_max) * 100
    
    if utilization_percentage > 90:  # 90% threshold for practical limit
        log_high_connection_count_warning(active_connections, utilization_percentage)
    
    return utilization_percentage

function get_available_port_range():
    # Get the full available port range (simplified - no per-connection restrictions)
    return {
        'min_port': MIN_PORT,
        'max_port': MAX_PORT,
        'range_size': PORT_SPACE_TOTAL,
        'note': 'Full range available - packets routed by session ID'
    }
```

## Integration with Network Adaptation

### Adaptive Delay Window Integration

```pseudocode
function integrate_with_adaptive_delay_system(port_params):
    # Integration point with adaptive delay tuning system
    # Simplified with session ID routing - no port collision concerns
    
    # Get current network conditions
    network_conditions = get_current_network_conditions()
    
    # Calculate optimal delay window based on network performance
    optimal_delay_window = calculate_optimal_delay_window(network_conditions)
    
    # Get ports for optimal delay window using simplified calculation
    current_ports = calculate_ports_for_delay_window(port_params, optimal_delay_window)
    
    # Update port listening strategy (simplified)
    update_port_listening_strategy(current_ports, optimal_delay_window)
    
    return current_ports

function update_port_listening_strategy(required_ports, delay_window):
    # Update which ports we're listening on based on delay requirements
    currently_bound_ports = get_currently_bound_ports()
    
    # Bind to new required ports
    for port in required_ports:
        if port not in currently_bound_ports:
            bind_to_port(port)
    
    # Unbind from unnecessary ports (with safety margin)
    safety_ports = calculate_ports_for_delay_window(session_state.port_params, delay_window + 2)
    for port in currently_bound_ports:
        if port not in safety_ports:
            unbind_from_port(port)

function optimize_port_hopping_for_network_conditions():
    # Optimize port hopping strategy based on current network conditions
    network_stats = get_network_performance_stats()
    
    # Adjust parameters based on network performance
    if network_stats.packet_loss_rate > 0.02:  # > 2% loss
        # Increase delay window for lossy networks
        increase_delay_window_tolerance()
    
    if network_stats.average_latency > 200:  # > 200ms latency
        # Extend port transition overlap for high latency
        extend_port_transition_overlap()
    
    if network_stats.jitter > 100:  # > 100ms jitter
        # Use more conservative port timing
        enable_conservative_port_timing()
```
