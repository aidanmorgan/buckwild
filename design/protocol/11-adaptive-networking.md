# Adaptive Networking and Dynamic Delay Tuning

This document specifies the adaptive delay measurement and tuning mechanisms that optimize port hopping timing based on real-time network conditions, providing balance between security and reliability.

## Overview

The adaptive networking system monitors network performance and adjusts protocol parameters to optimize the balance between security (minimal port exposure) and reliability (tolerance for network variations). This eliminates static configurations while ensuring optimal performance across network environments.

## Purpose and Rationale

Adaptive networking serves critical performance and security optimization functions:

- **Network Adaptation**: Adjusts to varying network conditions including latency, jitter, and packet loss
- **Security Optimization**: Minimizes port exposure time while maintaining tolerance for legitimate packet delays
- **Performance Efficiency**: Reduces port listening overhead while preventing packet loss due to timing mismatches
- **Dynamic Response**: Measures and adapts to changing network characteristics without manual configuration
- **Peer Coordination**: Negotiates optimal delay parameters between peers for synchronized timing expectations
- **Resilience**: Maintains connectivity and performance during network condition changes and degradation


## Key Concepts

- **Delay Window**: The number of time windows (port positions) kept open to accommodate network transmission delays
- **Adaptive Measurement**: Continuous collection and analysis of packet arrival timing statistics and network performance
- **Delay Negotiation**: Peer-to-peer coordination of delay parameters using HEARTBEAT packet extensions
- **Statistical Analysis**: Use of percentile-based calculations (95th percentile) to determine appropriate delay allowances
- **Network Jitter**: Measurement and compensation for network timing variations and inconsistencies
- **Loss Rate Adaptation**: Adjustment of parameters based on measured packet loss rates

## Adaptive Delay State Management

### Core Adaptive Delay State

```pseudocode
// Adaptive delay state management with asymmetric window support
adaptive_delay_state = {
    'current_delay_window': ADAPTIVE_DELAY_WINDOW_MIN,     // Current locally calculated window (legacy/total)
    'past_window_size': ADAPTIVE_DELAY_WINDOW_MIN // 2,    // Windows for past packets (late arrivals)
    'future_window_size': ADAPTIVE_DELAY_WINDOW_MIN // 2,  // Windows for future packets (early arrivals)
    'negotiated_delay_window': ADAPTIVE_DELAY_WINDOW_MIN,  // Negotiated with peer
    'delay_measurements': [],                              // Historical delay measurements
    'last_negotiation_time': 0,                            // Last negotiation timestamp
    'peer_delay_window': ADAPTIVE_DELAY_WINDOW_MIN,        // Peer's reported window
    'network_jitter': 0,                                   // Measured network jitter (ms)
    'packet_loss_rate': 0.0,                              // Measured packet loss rate (0.0-1.0)
    'is_adaptation_enabled': true,                         // Adaptation system enabled
    'measurement_sequence': 0,                             // Sequence counter for measurements
    'negotiation_sequence': 0,                             // Sequence counter for negotiations
    'network_conditions': {},                             // Current network condition summary
    'performance_history': [],                            // Historical performance data
    'early_packet_ratio': 0.0,                           // Ratio of early vs late packets
    'late_packet_ratio': 0.0,                            // Ratio of late vs early packets
    'asymmetric_adaptation_enabled': true                 // Enable asymmetric window adaptation
}

// Adaptive delay constants are defined in 02-core-definitions.md:
// - ADAPTIVE_DELAY_WINDOW_MIN = 1
// - ADAPTIVE_DELAY_WINDOW_MAX = 16  
// - DELAY_MEASUREMENT_SAMPLES = 10
// - DELAY_NEGOTIATION_INTERVAL_MS = 60000
// - DELAY_PERCENTILE_TARGET = 95
// - BASE_HEARTBEAT_PAYLOAD_SIZE = 8
// - SAFETY_MARGIN_MS = 100
// - BASE_TRANSMISSION_DELAY_ALLOWANCE_MS = 1000
NETWORK_CONDITION_HISTORY_SIZE = 50      // Number of historical condition snapshots
PERFORMANCE_ADAPTATION_THRESHOLD = 0.05   // 5% threshold for performance changes

function initialize_adaptive_networking():
    adaptive_delay_state.current_delay_window = ADAPTIVE_DELAY_WINDOW_MIN
    adaptive_delay_state.negotiated_delay_window = ADAPTIVE_DELAY_WINDOW_MIN
    adaptive_delay_state.delay_measurements = []
    adaptive_delay_state.last_negotiation_time = get_current_time_ms()
    adaptive_delay_state.peer_delay_window = ADAPTIVE_DELAY_WINDOW_MIN
    adaptive_delay_state.network_jitter = 0
    adaptive_delay_state.packet_loss_rate = 0.0
    adaptive_delay_state.is_adaptation_enabled = true
    adaptive_delay_state.measurement_sequence = 0
    adaptive_delay_state.negotiation_sequence = 0
    adaptive_delay_state.network_conditions = initialize_network_conditions()
    adaptive_delay_state.performance_history = []
```

## Dynamic Port Window Calculation

### Adaptive Port Range Management

```pseudocode
function get_current_port_with_adaptive_delay_allowance(port_params):
    # Calculate current ports with adaptive allowance for transmission delay
    # Uses dynamically determined delay window based on network characteristics
    
    # Get current effective delay window
    effective_delay_window = get_effective_delay_window()
    
    # Calculate ports for adaptive delay window
    return calculate_ports_for_delay_window(port_params, effective_delay_window)

function get_effective_delay_window():
    # Get current effective delay window size
    if not adaptive_delay_state.is_adaptation_enabled:
        return ADAPTIVE_DELAY_WINDOW_MIN
    
    # Use negotiated value if available and recent
    current_time = get_current_time_ms()
    negotiation_age = current_time - adaptive_delay_state.last_negotiation_time
    
    if negotiation_age < DELAY_NEGOTIATION_INTERVAL_MS * 2:
        return adaptive_delay_state.negotiated_delay_window
    
    # Fall back to locally calculated value
    return adaptive_delay_state.current_delay_window

function calculate_adaptive_port_window(port_params, network_conditions):
    # Calculate optimal port window based on current network conditions
    base_window = get_effective_delay_window()
    
    # Adjust for specific network conditions
    if network_conditions.high_latency:
        base_window += 2  # Extra windows for high latency
    
    if network_conditions.high_jitter:
        base_window += 1  # Extra window for jitter
    
    if network_conditions.packet_loss_rate > 0.02:  # >2% loss
        loss_adjustment = min(3, int(network_conditions.packet_loss_rate * 50))
        base_window += loss_adjustment
    
    # Apply bounds
    final_window = max(ADAPTIVE_DELAY_WINDOW_MIN, 
                      min(base_window, ADAPTIVE_DELAY_WINDOW_MAX))
    
    return final_window

function update_port_listening_strategy(port_params):
    # Update port listening strategy based on current network conditions
    current_conditions = assess_network_conditions()
    optimal_window = calculate_adaptive_port_window(port_params, current_conditions)
    
    # Get required ports for optimal window
    required_ports = calculate_ports_for_delay_window(port_params, optimal_window)
    
    # Update which ports we're listening on
    update_active_port_bindings(required_ports, optimal_window)
    
    return required_ports

function update_active_port_bindings(required_ports, delay_window):
    # Update which ports we're listening on based on requirements
    currently_bound_ports = get_currently_bound_ports()
    
    # Bind to new required ports
    for port in required_ports:
        if port not in currently_bound_ports:
            bind_to_port(port)
            log_adaptive_port_binding(port, "required")
    
    # Calculate safety ports (slightly larger window for transitions)
    safety_window = min(delay_window + 2, ADAPTIVE_DELAY_WINDOW_MAX)
    safety_ports = calculate_ports_for_delay_window(session_state.port_params, safety_window)
    
    # Unbind from unnecessary ports
    for port in currently_bound_ports:
        if port not in safety_ports:
            unbind_from_port(port)
            log_adaptive_port_unbinding(port, "unnecessary")
```

## Network Performance Measurement

### Packet Delay Analysis

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
    
    # Record both positive and negative delays to understand timing variations
    # Positive = late packets, Negative = early packets (clock skew, fast routing)
    record_delay_measurement(abs(delay_ms), packet, delay_ms < 0)

function record_delay_measurement(delay_ms, packet, is_early_packet):
    # Record delay measurement for statistical analysis
    current_time = get_current_time_ms()
    
    measurement = {
        'delay_ms': delay_ms,
        'timestamp': current_time,
        'sequence': adaptive_delay_state.measurement_sequence,
        'packet_type': packet.type,
        'packet_size': len(packet.serialize()),
        'rtt_estimate': session_state.rtt_srtt,  # From RTO calculation
        'is_early': is_early_packet  # Track early vs late arrivals
    }
    
    adaptive_delay_state.measurement_sequence += 1
    
    # Add to measurements buffer
    adaptive_delay_state.delay_measurements.append(measurement)
    
    # Maintain buffer size
    if len(adaptive_delay_state.delay_measurements) > DELAY_MEASUREMENT_SAMPLES * 2:
        # Remove oldest measurements
        adaptive_delay_state.delay_measurements = adaptive_delay_state.delay_measurements[-DELAY_MEASUREMENT_SAMPLES:]
    
    # Update delay window if we have enough samples
    if len(adaptive_delay_state.delay_measurements) >= DELAY_MEASUREMENT_SAMPLES:
        update_adaptive_delay_window()
        
        # Evaluate any ongoing window optimization test
        evaluate_window_optimization_test()
        
        # Periodically attempt to optimize (shrink) windows
        periodic_window_optimization()

function update_adaptive_delay_window():
    # Update adaptive delay window based on statistical analysis with asymmetric support
    recent_measurements = get_recent_delay_measurements()
    
    if len(recent_measurements) < DELAY_MEASUREMENT_SAMPLES // 2:
        return  # Insufficient data
    
    # Separate early and late packets for asymmetric analysis
    early_packets = [m for m in recent_measurements if m.is_early]
    late_packets = [m for m in recent_measurements if not m.is_early]
    
    # Calculate packet timing ratios
    total_packets = len(recent_measurements)
    early_ratio = len(early_packets) / total_packets if total_packets > 0 else 0.0
    late_ratio = len(late_packets) / total_packets if total_packets > 0 else 0.0
    
    # Update timing statistics
    adaptive_delay_state.early_packet_ratio = early_ratio
    adaptive_delay_state.late_packet_ratio = late_ratio
    
    if adaptive_delay_state.asymmetric_adaptation_enabled:
        # Asymmetric window calculation based on actual packet patterns
        update_asymmetric_window(early_packets, late_packets, early_ratio, late_ratio)
    else:
        # Fallback to symmetric window calculation
        update_symmetric_window(recent_measurements)

function update_asymmetric_window(early_packets, late_packets, early_ratio, late_ratio):
    # Calculate asymmetric window sizes based on actual timing patterns
    
    # Calculate 95th percentile delays for each direction
    early_delays = [m.delay_ms for m in early_packets] if early_packets else [0]
    late_delays = [m.delay_ms for m in late_packets] if late_packets else [0]
    
    early_delays.sort()
    late_delays.sort()
    
    # Calculate percentile delays for each direction
    early_p95 = calculate_percentile(early_delays, DELAY_PERCENTILE_TARGET)
    late_p95 = calculate_percentile(late_delays, DELAY_PERCENTILE_TARGET)
    
    # Calculate jitter for each direction
    early_jitter = calculate_jitter(early_delays) if len(early_delays) > 1 else 0
    late_jitter = calculate_jitter(late_delays) if len(late_delays) > 1 else 0
    
    # Calculate required windows for each direction
    early_safety = max(SAFETY_MARGIN_MS, early_jitter)
    late_safety = max(SAFETY_MARGIN_MS, late_jitter)
    
    required_future_windows = math.ceil((early_p95 + early_safety) / HOP_INTERVAL_MS)
    required_past_windows = math.ceil((late_p95 + late_safety) / HOP_INTERVAL_MS)
    
    # Apply adaptive bias based on packet ratios
    # If more packets arrive early, increase future window
    # If more packets arrive late, increase past window
    bias_factor = 1.5  # Amplification factor for adaptation
    
    if early_ratio > late_ratio + 0.1:  # 10% threshold to avoid oscillation
        # More early packets - bias toward future windows
        future_bias = 1 + (early_ratio - late_ratio) * bias_factor
        required_future_windows = int(required_future_windows * future_bias)
    elif late_ratio > early_ratio + 0.1:
        # More late packets - bias toward past windows  
        past_bias = 1 + (late_ratio - early_ratio) * bias_factor
        required_past_windows = int(required_past_windows * past_bias)
    
    # Apply bounds to individual window sizes
    max_individual_windows = ADAPTIVE_DELAY_WINDOW_MAX - 1  # Reserve 1 for current window
    bounded_future = max(0, min(required_future_windows, max_individual_windows))
    bounded_past = max(0, min(required_past_windows, max_individual_windows))
    
    # Ensure total window doesn't exceed maximum
    total_windows = bounded_past + 1 + bounded_future  # past + current + future
    if total_windows > ADAPTIVE_DELAY_WINDOW_MAX:
        # Proportionally reduce both sides
        scale_factor = (ADAPTIVE_DELAY_WINDOW_MAX - 1) / (bounded_past + bounded_future)
        bounded_past = int(bounded_past * scale_factor)
        bounded_future = int(bounded_future * scale_factor)
    
    # Apply adaptive smoothing with bias toward smaller windows
    # Use different smoothing factors for increases vs decreases to keep windows small
    past_smoothing = calculate_adaptive_smoothing_factor(adaptive_delay_state.past_window_size, bounded_past)
    future_smoothing = calculate_adaptive_smoothing_factor(adaptive_delay_state.future_window_size, bounded_future)
    
    new_past = int((1 - past_smoothing) * adaptive_delay_state.past_window_size + 
                   past_smoothing * bounded_past)
    new_future = int((1 - future_smoothing) * adaptive_delay_state.future_window_size + 
                     future_smoothing * bounded_future)
    
    # Ensure minimum window sizes are respected
    new_past = max(0, new_past)
    new_future = max(0, new_future)
    
    # Ensure at least minimum total window size
    total_new_window = new_past + 1 + new_future
    if total_new_window < ADAPTIVE_DELAY_WINDOW_MIN:
        # Distribute minimum window size evenly
        extra_needed = ADAPTIVE_DELAY_WINDOW_MIN - total_new_window
        past_share = extra_needed // 2
        future_share = extra_needed - past_share
        new_past += past_share
        new_future += future_share
    
    # Update state
    adaptive_delay_state.past_window_size = new_past
    adaptive_delay_state.future_window_size = new_future
    adaptive_delay_state.current_delay_window = new_past + 1 + new_future  # Total window for compatibility
    
    # Log asymmetric window changes
    log_asymmetric_window_change(new_past, new_future, early_ratio, late_ratio, 
                                early_p95, late_p95)

function update_symmetric_window(recent_measurements):
    # Fallback symmetric window calculation (original logic)
    delays = [m.delay_ms for m in recent_measurements]
    delays.sort()
    
    percentile_index = int(len(delays) * DELAY_PERCENTILE_TARGET / 100)
    percentile_delay = delays[min(percentile_index, len(delays) - 1)]
    
    mean_delay = sum(delays) / len(delays)
    variance = sum((d - mean_delay) ** 2 for d in delays) / len(delays)
    jitter = math.sqrt(variance)
    
    adaptive_delay_state.network_jitter = jitter
    
    safety_margin = max(SAFETY_MARGIN_MS, jitter)
    total_delay_allowance = percentile_delay + safety_margin
    required_half_windows = math.ceil(total_delay_allowance / HOP_INTERVAL_MS)
    required_total_windows = (required_half_windows * 2) + 1
    
    bounded_windows = max(ADAPTIVE_DELAY_WINDOW_MIN, 
                         min(required_total_windows, ADAPTIVE_DELAY_WINDOW_MAX))
    if bounded_windows % 2 == 0:
        bounded_windows += 1
    
    # Update symmetric window state
    half_window = (bounded_windows - 1) // 2
    adaptive_delay_state.past_window_size = half_window
    adaptive_delay_state.future_window_size = half_window
    adaptive_delay_state.current_delay_window = bounded_windows

function calculate_percentile(sorted_values, percentile):
    # Calculate percentile from sorted array
    if not sorted_values:
        return 0
    index = int(len(sorted_values) * percentile / 100)
    return sorted_values[min(index, len(sorted_values) - 1)]

function calculate_jitter(delays):
    # Calculate jitter (standard deviation) for delay array
    if len(delays) < 2:
        return 0
    mean = sum(delays) / len(delays)
    variance = sum((d - mean) ** 2 for d in delays) / len(delays)
    return math.sqrt(variance)

function calculate_adaptive_smoothing_factor(current_size, target_size):
    # Calculate smoothing factor with bias toward smaller windows
    # Fast shrinking, slow growing to keep windows as small as possible
    
    if target_size < current_size:
        # Shrinking window - use aggressive smoothing for fast reduction
        shrink_factor = 0.6  # 60% toward target for shrinking
        return shrink_factor
    elif target_size > current_size:
        # Growing window - use conservative smoothing for slow increases
        grow_factor = 0.2   # 20% toward target for growing
        return grow_factor
    else:
        # No change - minimal smoothing to maintain stability
        return 0.1

function periodic_window_optimization():
    # Periodically attempt to shrink windows if network conditions improve
    # Called every few measurement cycles to probe for smaller window opportunities
    
    if not adaptive_delay_state.asymmetric_adaptation_enabled:
        return
    
    current_time = get_current_time_ms()
    last_optimization = adaptive_delay_state.get('last_window_optimization', 0)
    
    # Only optimize every 30 seconds to avoid excessive probing
    optimization_interval = 30000  # 30 seconds
    if current_time - last_optimization < optimization_interval:
        return
    
    adaptive_delay_state.last_window_optimization = current_time
    
    # Try temporarily smaller windows to test if they still work
    original_past = adaptive_delay_state.past_window_size
    original_future = adaptive_delay_state.future_window_size
    
    # Attempt 20% reduction in each direction (minimum 1 window reduction)
    test_past = max(0, original_past - max(1, int(original_past * 0.2)))
    test_future = max(0, original_future - max(1, int(original_future * 0.2)))
    
    # Ensure minimum total window requirement
    test_total = test_past + 1 + test_future
    if test_total >= ADAPTIVE_DELAY_WINDOW_MIN:
        # Record that we're testing smaller windows
        adaptive_delay_state.window_optimization_test = {
            'start_time': current_time,
            'test_past': test_past,
            'test_future': test_future,
            'original_past': original_past,
            'original_future': original_future,
            'packet_loss_baseline': adaptive_delay_state.packet_loss_rate
        }
        
        # Temporarily use smaller windows
        adaptive_delay_state.past_window_size = test_past
        adaptive_delay_state.future_window_size = test_future
        adaptive_delay_state.current_delay_window = test_total
        
        log_window_optimization_test(test_past, test_future, original_past, original_future)

function evaluate_window_optimization_test():
    # Evaluate if the window size optimization test was successful
    optimization_test = adaptive_delay_state.get('window_optimization_test')
    if not optimization_test:
        return
    
    current_time = get_current_time_ms()
    test_duration = current_time - optimization_test['start_time']
    
    # Test for at least 5 minutes before evaluation
    test_period = 300000  # 5 minutes
    if test_duration < test_period:
        return
    
    # Check if packet loss increased significantly during test
    current_loss_rate = adaptive_delay_state.packet_loss_rate
    baseline_loss_rate = optimization_test['packet_loss_baseline']
    loss_increase = current_loss_rate - baseline_loss_rate
    
    # If packet loss increased by more than 2%, revert to original window size
    loss_threshold = 0.02  # 2% increase threshold
    if loss_increase > loss_threshold:
        # Revert to original window sizes
        adaptive_delay_state.past_window_size = optimization_test['original_past']
        adaptive_delay_state.future_window_size = optimization_test['original_future']
        adaptive_delay_state.current_delay_window = (optimization_test['original_past'] + 1 + 
                                                    optimization_test['original_future'])
        
        log_window_optimization_reverted(loss_increase, loss_threshold)
    else:
        # Test successful - keep smaller windows
        log_window_optimization_successful(optimization_test['test_past'], 
                                         optimization_test['test_future'])
    
    # Clear test state
    del adaptive_delay_state.window_optimization_test

function get_recent_delay_measurements():
    # Get recent delay measurements for analysis
    current_time = get_current_time_ms()
    cutoff_time = current_time - DELAY_NEGOTIATION_INTERVAL_MS
    
    recent_measurements = []
    for measurement in adaptive_delay_state.delay_measurements:
        if measurement.timestamp >= cutoff_time:
            recent_measurements.append(measurement)
    
    return recent_measurements
```

### Network Condition Assessment

```pseudocode
function assess_network_conditions():
    # Assess current network conditions for adaptive optimization
    current_time = get_current_time_ms()
    
    # Calculate packet loss rate
    loss_rate = calculate_packet_loss_rate()
    
    # Assess latency characteristics
    rtt_stats = calculate_rtt_statistics()
    
    # Assess jitter characteristics  
    jitter_stats = calculate_jitter_statistics()
    
    # Determine condition flags
    conditions = {
        'timestamp': current_time,
        'packet_loss_rate': loss_rate,
        'average_rtt': rtt_stats.average,
        'rtt_variance': rtt_stats.variance,
        'network_jitter': adaptive_delay_state.network_jitter,
        'high_latency': rtt_stats.average > 200,  # >200ms
        'high_jitter': adaptive_delay_state.network_jitter > 100,  # >100ms
        'high_loss': loss_rate > 0.02,  # >2%
        'unstable_network': rtt_stats.variance > 50,  # High RTT variance
        'congested_network': detect_congestion_indicators()
    }
    
    # Store current conditions
    adaptive_delay_state.network_conditions = conditions
    
    # Add to history
    adaptive_delay_state.performance_history.append(conditions)
    if len(adaptive_delay_state.performance_history) > NETWORK_CONDITION_HISTORY_SIZE:
        adaptive_delay_state.performance_history.pop(0)
    
    return conditions

function calculate_packet_loss_rate():
    # Calculate packet loss rate for delay window adjustment
    if len(adaptive_delay_state.delay_measurements) < DELAY_MEASUREMENT_SAMPLES:
        return 0.0
    
    # Use sequence numbers to detect missing packets
    recent_measurements = get_recent_delay_measurements()
    if len(recent_measurements) < 2:
        return 0.0
    
    # Calculate expected vs received packets based on sequence gaps
    sequences = [m.sequence for m in recent_measurements]
    sequences.sort()
    
    expected_packets = sequences[-1] - sequences[0] + 1
    received_packets = len(sequences)
    
    if expected_packets <= 0:
        return 0.0
    
    loss_rate = (expected_packets - received_packets) / expected_packets
    adaptive_delay_state.packet_loss_rate = max(0.0, min(1.0, loss_rate))
    
    return adaptive_delay_state.packet_loss_rate

function calculate_rtt_statistics():
    # Calculate RTT statistics from recent measurements
    recent_measurements = get_recent_delay_measurements()
    
    if len(recent_measurements) == 0:
        return {
            'average': session_state.rtt_srtt,
            'variance': session_state.rtt_rttvar,
            'minimum': session_state.rtt_srtt,
            'maximum': session_state.rtt_srtt
        }
    
    rtt_values = [m.rtt_estimate for m in recent_measurements if m.rtt_estimate > 0]
    
    if len(rtt_values) == 0:
        return {
            'average': session_state.rtt_srtt,
            'variance': session_state.rtt_rttvar,
            'minimum': session_state.rtt_srtt,
            'maximum': session_state.rtt_srtt
        }
    
    average = sum(rtt_values) / len(rtt_values)
    variance = sum((rtt - average) ** 2 for rtt in rtt_values) / len(rtt_values)
    
    return {
        'average': average,
        'variance': variance,
        'minimum': min(rtt_values),
        'maximum': max(rtt_values)
    }

function calculate_jitter_statistics():
    # Calculate jitter statistics from delay measurements
    recent_measurements = get_recent_delay_measurements()
    
    if len(recent_measurements) < 2:
        return {
            'average_jitter': adaptive_delay_state.network_jitter,
            'peak_jitter': adaptive_delay_state.network_jitter
        }
    
    delays = [m.delay_ms for m in recent_measurements]
    mean_delay = sum(delays) / len(delays)
    
    # Calculate jitter as average deviation from mean
    deviations = [abs(delay - mean_delay) for delay in delays]
    average_jitter = sum(deviations) / len(deviations)
    peak_jitter = max(deviations)
    
    return {
        'average_jitter': average_jitter,
        'peak_jitter': peak_jitter
    }

function detect_congestion_indicators():
    # Detect network congestion based on multiple indicators
    conditions = adaptive_delay_state.network_conditions
    
    # Check multiple congestion indicators
    indicators = []
    
    # High packet loss
    if conditions.get('packet_loss_rate', 0) > 0.01:  # >1%
        indicators.append('packet_loss')
    
    # Increasing RTT trend
    if detect_rtt_trend_increase():
        indicators.append('rtt_increase')
    
    # High jitter
    if conditions.get('network_jitter', 0) > 150:  # >150ms jitter
        indicators.append('high_jitter')
    
    # Congestion window events from flow control
    if session_state.congestion_state == FAST_RECOVERY:
        indicators.append('congestion_control')
    
    return len(indicators) >= 2  # Multiple indicators suggest congestion
```

## Delay Parameter Negotiation

### HEARTBEAT-Based Negotiation

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
        'is_adaptation_enabled': adaptive_delay_state.is_adaptation_enabled,
        'negotiation_sequence': adaptive_delay_state.negotiation_sequence
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
    peer_measurement_count = peer_delay_payload.measurement_count
    
    # Store peer parameters
    adaptive_delay_state.peer_delay_window = peer_window
    
    # Calculate negotiated delay window using sophisticated algorithm
    local_window = adaptive_delay_state.current_delay_window
    
    # Weight peer and local requirements based on measurement confidence
    local_confidence = min(1.0, len(adaptive_delay_state.delay_measurements) / DELAY_MEASUREMENT_SAMPLES)
    peer_confidence = min(1.0, peer_measurement_count / DELAY_MEASUREMENT_SAMPLES)
    
    # Calculate weighted average
    if local_confidence + peer_confidence > 0:
        weighted_window = (local_window * local_confidence + peer_window * peer_confidence) / (local_confidence + peer_confidence)
    else:
        weighted_window = max(local_window, peer_window)
    
    # Adjust for packet loss (increase window if high loss rate)
    loss_adjustment = 0
    max_loss_rate = max(adaptive_delay_state.packet_loss_rate, peer_loss_rate)
    if max_loss_rate > 0.02:  # >2% loss rate
        loss_adjustment = min(4, int(max_loss_rate * 50))
    
    # Adjust for jitter asymmetry
    jitter_adjustment = 0
    max_jitter = max(adaptive_delay_state.network_jitter, peer_jitter)
    if max_jitter > 100:  # >100ms jitter
        jitter_adjustment = min(2, int(max_jitter / 100))
    
    negotiated_window = int(weighted_window) + loss_adjustment + jitter_adjustment
    
    # Apply bounds
    negotiated_window = max(ADAPTIVE_DELAY_WINDOW_MIN,
                           min(negotiated_window, ADAPTIVE_DELAY_WINDOW_MAX))
    
    # Update negotiated parameters
    adaptive_delay_state.negotiated_delay_window = negotiated_window
    adaptive_delay_state.last_negotiation_time = get_current_time_ms()
    adaptive_delay_state.negotiation_sequence += 1
    
    # Log negotiation result
    log_delay_negotiation(local_window, peer_window, negotiated_window, 
                         local_confidence, peer_confidence, loss_adjustment, jitter_adjustment)
    
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
    # Bit 48: is_adaptation_enabled (1 bit)
    # Bits 49-63: reserved (15 bits)
    
    packed_data = 0
    packed_data |= (delay_payload.current_delay_window & 0xFF)
    packed_data |= ((delay_payload.network_jitter & 0xFFF) << 8)
    packed_data |= ((delay_payload.packet_loss_rate & 0x3FF) << 20)
    packed_data |= ((delay_payload.measurement_count & 0xFF) << 30)
    packed_data |= ((delay_payload.negotiation_sequence & 0x3FF) << 38)
    packed_data |= ((1 if delay_payload.is_adaptation_enabled else 0) << 48)
    
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
        'is_adaptation_enabled': bool((packed_data >> 48) & 0x1)
    }
```

## Adaptive Optimization Strategies

### Performance-Based Adaptation

```pseudocode
function optimize_network_performance():
    # Continuously optimize network performance based on measurements
    current_conditions = assess_network_conditions()
    
    # Apply unified optimization strategy to prevent accumulation
    apply_network_condition_optimizations(current_conditions)
    
    # Update port listening strategy
    update_port_listening_strategy(session_state.port_params)

function apply_network_condition_optimizations(current_conditions):
    # Apply network optimizations based on current conditions
    # Calculate optimizations but don't accumulate - use maximum needed
    
    base_window = adaptive_delay_state.current_delay_window
    optimization_adjustments = []
    
    if current_conditions.high_congestion:
        # Increase delay window to reduce port switching overhead
        congestion_adjustment = min(2, ADAPTIVE_DELAY_WINDOW_MAX - base_window)
        optimization_adjustments.append(("congestion", congestion_adjustment))
        increase_heartbeat_interval()
        enable_conservative_timing_mode()
    
    if current_conditions.high_latency:
        # Increase delay window to accommodate longer round trips  
        latency_adjustment = min(4, ADAPTIVE_DELAY_WINDOW_MAX - base_window)
        optimization_adjustments.append(("latency", latency_adjustment))
        extend_port_transition_overlap()
        increase_timeout_tolerances()
    
    if current_conditions.high_jitter:
        # Increase delay window to handle timing variations
        jitter_windows = min(3, int(adaptive_delay_state.network_jitter / 200))  # 1 window per 200ms jitter
        optimization_adjustments.append(("jitter", jitter_windows))
        enable_jitter_compensation()
    
    if current_conditions.high_loss:
        # Increase delay window for retransmissions
        loss_windows = min(4, int(adaptive_delay_state.packet_loss_rate * 25))
        optimization_adjustments.append(("loss", loss_windows))
    
    # Apply the maximum adjustment needed (don't accumulate)
    if optimization_adjustments:
        max_adjustment = max(adj[1] for adj in optimization_adjustments)
        optimized_window = min(base_window + max_adjustment, ADAPTIVE_DELAY_WINDOW_MAX)
        
        # Ensure odd number for symmetric operation
        if optimized_window % 2 == 0:
            optimized_window += 1
            
        adaptive_delay_state.current_delay_window = optimized_window
        
        # Log applied optimizations
        active_optimizations = [adj[0] for adj in optimization_adjustments if adj[1] > 0]
        log_optimizations_applied(active_optimizations, max_adjustment, optimized_window)

function detect_rtt_trend_increase():
    # Detect if RTT is trending upward (congestion indicator)
    if len(adaptive_delay_state.performance_history) < 5:
        return false
    
    recent_rtts = [h.average_rtt for h in adaptive_delay_state.performance_history[-5:]]
    
    # Simple trend detection: compare first half to second half
    first_half = recent_rtts[:len(recent_rtts)//2]
    second_half = recent_rtts[len(recent_rtts)//2:]
    
    if len(first_half) == 0 or len(second_half) == 0:
        return false
    
    first_avg = sum(first_half) / len(first_half)
    second_avg = sum(second_half) / len(second_half)
    
    # Consider trending up if second half is 20% higher than first half
    return second_avg > first_avg * 1.2

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
    
    # Network condition changes
    current_conditions = adaptive_delay_state.network_conditions
    
    # High packet loss detected
    if current_conditions.get('packet_loss_rate', 0) > 0.05:  # >5% loss
        return true
    
    # Sudden jitter increase
    if current_conditions.get('network_jitter', 0) > adaptive_delay_state.network_jitter * 2:
        return true
    
    # Network instability
    if current_conditions.get('unstable_network', false):
        return true
    
    return false

function handle_adaptive_networking_on_packet_receive(packet):
    # Handle adaptive networking processing on packet reception
    
    # Measure packet delay and network performance
    measure_packet_delay(packet)
    
    # Update packet loss statistics
    calculate_packet_loss_rate()
    
    # Assess current network conditions
    current_conditions = assess_network_conditions()
    
    # Apply performance optimizations if needed
    if should_apply_optimizations(current_conditions):
        optimize_network_performance()
    
    # Check if negotiation should be triggered
    if should_trigger_delay_negotiation():
        schedule_delay_negotiation()

function should_apply_optimizations(current_conditions):
    # Determine if performance optimizations should be applied
    
    # Apply if conditions have changed significantly
    if not adaptive_delay_state.performance_history:
        return false
    
    previous_conditions = adaptive_delay_state.performance_history[-1]
    
    # Check for significant performance degradation
    performance_changes = [
        abs(current_conditions.packet_loss_rate - previous_conditions.packet_loss_rate) > PERFORMANCE_ADAPTATION_THRESHOLD,
        abs(current_conditions.network_jitter - previous_conditions.network_jitter) > 50,  # >50ms jitter change
        abs(current_conditions.average_rtt - previous_conditions.average_rtt) > 50,  # >50ms RTT change
        current_conditions.congested_network != previous_conditions.congested_network
    ]
    
    return any(performance_changes)

function schedule_delay_negotiation():
    # Schedule delay parameter negotiation in next heartbeat
    session_state.pending_delay_negotiation = true
    log_delay_negotiation_scheduled()
```

## Integration Points

### Protocol Integration

```pseudocode
function integrate_adaptive_networking():
    # Integration points with other protocol components
    
    # Port hopping integration
    current_ports = get_current_port_with_adaptive_delay_allowance(session_state.port_params)
    update_port_hopping_strategy(current_ports)
    
    # Flow control integration
    adjust_flow_control_for_network_conditions(adaptive_delay_state.network_conditions)
    
    # Timeout management integration
    adjust_timeouts_for_network_conditions(adaptive_delay_state.network_conditions)
    
    # Recovery mechanism integration
    update_recovery_parameters_for_conditions(adaptive_delay_state.network_conditions)

function adjust_flow_control_for_network_conditions(conditions):
    # Adjust flow control parameters based on network conditions
    if conditions.high_loss:
        # Reduce congestion window more aggressively for lossy networks
        session_state.congestion_window = max(
            MIN_CONGESTION_WINDOW,
            session_state.congestion_window * 0.8
        )
    
    if conditions.high_latency:
        # Increase initial window for high latency networks
        session_state.slow_start_threshold = min(
            session_state.slow_start_threshold * 1.2,
            MAX_CONGESTION_WINDOW
        )

function adjust_timeouts_for_network_conditions(conditions):
    # Adjust timeout values based on network conditions
    if conditions.high_jitter:
        # Increase RTO bounds for jittery networks
        session_state.rtt_rto = min(
            session_state.rtt_rto * 1.2,
            MAX_RETRANSMISSION_TIMEOUT_MS
        )
    
    if conditions.unstable_network:
        # Use more conservative timeout calculations
        session_state.rtt_alpha = 0.9  # More smoothing
        session_state.rtt_beta = 0.1   # Less weight on new measurements

function update_recovery_parameters_for_conditions(conditions):
    # Update recovery mechanism parameters for current conditions
    if conditions.high_loss:
        # Reduce recovery attempt intervals for lossy networks
        session_state.recovery_retry_interval = max(
            RECOVERY_RETRY_INTERVAL_MS // 2,
            500  # Minimum 500ms
        )
    
    if conditions.congested_network:
        # Use longer backoff for congested networks
        session_state.recovery_backoff_multiplier = 2.5
```
