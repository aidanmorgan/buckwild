# Time Synchronization Specification

## Overview

This document defines the time synchronization mechanisms that enable precise coordination between peers for synchronized port hopping. The time synchronization system ensures all peers maintain accurate time alignment, enabling coordinated port changes and preventing timing-based security vulnerabilities.

## Purpose and Rationale

Time synchronization serves critical coordination and security functions:

- **Port Hopping Coordination**: Ensures all peers change ports at exactly the same time to maintain connectivity
- **Timing Attack Prevention**: Prevents attackers from exploiting timing inconsistencies to predict port sequences
- **Network Resilience**: Maintains synchronization despite network delays, clock drift, and varying latencies
- **Security Enforcement**: Ensures time-based security windows (like anti-replay protection) work correctly across peers
- **Precision Management**: Provides sub-second accuracy required for 250ms port hopping intervals

The synchronization system uses challenge-response protocols with cryptographic validation to ensure timing information cannot be spoofed or manipulated by attackers.

## Key Concepts

- **Time Windows**: 250ms intervals synchronized across all peers for coordinated port hopping
- **Time Offset Management**: Calculation and maintenance of offset corrections between peer clocks
- **Drift Detection**: Monitoring and correction of gradual time drift between peers
- **Challenge-Response Sync**: Cryptographically secured time synchronization exchanges
- **UTC Coordination**: Use of UTC time to eliminate timezone dependencies in synchronization

## Time Window Calculation
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

## Time Offset Calculation
```pseudocode
function calculate_time_offset(client_time, server_time):
    # Calculate time offset between client and server
    return server_time - client_time

function apply_time_offset(local_time, time_offset):
    # Apply time offset to local time
    return local_time + time_offset

function get_synchronized_time():
    # Get current time with offset applied
    return apply_time_offset(get_current_time(), time_offset)

function detect_time_drift(peer_time, local_time):
    # Detect time drift between peers
    time_difference = abs(peer_time - local_time)
    return time_difference > TIME_SYNC_TOLERANCE_MS

function adjust_time_offset(new_offset):
    # Adjust time offset based on drift detection
    time_offset = (time_offset + new_offset) / 2
    return time_offset
```

## Time Resynchronization Recovery

```pseudocode
function execute_time_resync_recovery():
    # Step 1: Send time sync request
    challenge_nonce = generate_secure_random_32bit()
    local_timestamp = get_current_time_ms()
    
    sync_request = create_time_sync_request(
        challenge_nonce = challenge_nonce,
        local_timestamp = local_timestamp
    )
    
    send_time = get_current_time_ms()
    send_packet(sync_request)
    
    # Step 2: Receive time sync response
    sync_response = receive_packet_timeout(TIME_RESYNC_TIMEOUT_MS)
    receive_time = get_current_time_ms()
    
    if sync_response == null or sync_response.type != PACKET_TYPE_CONTROL or sync_response.sub_type != CONTROL_SUB_TIME_SYNC_RESPONSE:
        return ERROR_TIME_RESYNC_TIMEOUT
    
    if sync_response.challenge_nonce != challenge_nonce:
        return ERROR_TIME_RESYNC_INVALID_CHALLENGE
    
    # Step 3: Calculate time offset
    round_trip_time = receive_time - send_time
    estimated_peer_time = sync_response.peer_timestamp + (round_trip_time / 2)
    time_offset = estimated_peer_time - receive_time
    
    # Step 4: Validate and apply offset
    if abs(time_offset) > MAX_TIME_OFFSET_MS:
        return ERROR_TIME_RESYNC_OFFSET_TOO_LARGE
    
    # Apply gradual adjustment to prevent port hopping disruption
    apply_gradual_time_adjustment(time_offset)
    
    # Step 5: Verify synchronization
    if verify_time_synchronization():
        log_recovery_success("Time resynchronization completed")
        return SUCCESS
    else:
        return ERROR_TIME_RESYNC_VERIFICATION_FAILED

function apply_gradual_time_adjustment(offset):
    # Apply offset gradually over multiple hop intervals to avoid disruption
    adjustment_steps = max(1, abs(offset) / HOP_INTERVAL_MS)
    step_size = offset / adjustment_steps
    
    for step in range(adjustment_steps):
        session_state.time_offset += step_size
        wait(HOP_INTERVAL_MS)
```

## Complete Time Synchronization Specification

### Time Synchronization Overview

The protocol requires precise time synchronization between peers to maintain synchronized port hopping. The time synchronization system handles clock drift, leap seconds, network delay, and provides gradual adjustment mechanisms to prevent port hopping disruption.

### Time Synchronization Constants

```pseudocode
// Time synchronization constants
TIME_SYNC_PRECISION_MS = 10              // Required synchronization precision
TIME_SYNC_SAMPLE_COUNT = 8               // Number of samples for drift calculation
TIME_SYNC_ADJUSTMENT_RATE = 0.1          // Gradual adjustment rate (10% per hop)
MAX_TIME_ADJUSTMENT_PER_HOP = 25         // Maximum adjustment per hop interval (25ms)
LEAP_SECOND_WINDOW_MS = 2000             // Window around leap second events
CLOCK_SKEW_DETECTION_THRESHOLD = 100     // Clock skew detection threshold (100ms)
TIME_SYNC_HISTORY_SIZE = 16              // Number of historical sync measurements
DRIFT_CALCULATION_WINDOW = 300000        // Drift calculation window (5 minutes)
MAX_ACCEPTABLE_DRIFT_PPM = 100           // Maximum acceptable drift (100 ppm)
TIME_SYNC_EMERGENCY_THRESHOLD = 1000     // Emergency sync threshold (1 second)

// Time synchronization states
TIME_SYNC_STATE_SYNCHRONIZED = 0         // Clocks are synchronized
TIME_SYNC_STATE_ADJUSTING = 1            // Gradual adjustment in progress
TIME_SYNC_STATE_EMERGENCY = 2            // Emergency synchronization needed
TIME_SYNC_STATE_FAILED = 3               // Synchronization failed
```

### Time Synchronization State Management

```pseudocode
// Time synchronization state
time_sync_state = {
    'current_state': TIME_SYNC_STATE_SYNCHRONIZED,
    'local_offset': 0,                   // Local time offset in milliseconds
    'peer_offset': 0,                    // Peer time offset in milliseconds
    'drift_rate': 0.0,                   // Clock drift rate (ppm)
    'last_sync_time': 0,                 // Last successful synchronization
    'sync_samples': [],                  // Historical sync measurements
    'adjustment_queue': [],              // Pending time adjustments
    'emergency_sync_attempts': 0,        // Emergency sync attempt counter
    'leap_second_pending': false,        // Leap second event pending
    'sync_quality': 100                  // Synchronization quality (0-100)
}

function initialize_time_synchronization():
    time_sync_state.current_state = TIME_SYNC_STATE_SYNCHRONIZED
    time_sync_state.local_offset = 0
    time_sync_state.peer_offset = 0
    time_sync_state.drift_rate = 0.0
    time_sync_state.last_sync_time = get_current_time_ms()
    time_sync_state.sync_samples = []
    time_sync_state.adjustment_queue = []
    time_sync_state.emergency_sync_attempts = 0
    time_sync_state.sync_quality = 100
```

## Precision Time Synchronization Algorithm

```pseudocode
function execute_precision_time_sync():
    # Multi-sample time synchronization with network delay compensation
    sync_samples = []
    
    for sample_index in range(TIME_SYNC_SAMPLE_COUNT):
        sample = perform_single_time_sync()
        if sample != null:
            sync_samples.append(sample)
        
        # Wait between samples to get varied network conditions
        wait(HOP_INTERVAL_MS / TIME_SYNC_SAMPLE_COUNT)
    
    if len(sync_samples) < TIME_SYNC_SAMPLE_COUNT / 2:
        return ERROR_TIME_SYNC_INSUFFICIENT_SAMPLES
    
    # Calculate best time offset estimate
    time_offset = calculate_optimal_time_offset(sync_samples)
    network_delay = calculate_network_delay(sync_samples)
    sync_quality = calculate_sync_quality(sync_samples)
    
    # Validate synchronization quality
    if sync_quality < 50:  # Quality threshold
        return ERROR_TIME_SYNC_POOR_QUALITY
    
    # Apply gradual time adjustment
    if abs(time_offset) > TIME_SYNC_EMERGENCY_THRESHOLD:
        return initiate_emergency_time_sync(time_offset)
    else:
        return apply_gradual_time_adjustment(time_offset, sync_quality)

function perform_single_time_sync():
    # High-precision single time sync measurement
    challenge_nonce = generate_secure_random_32bit()
    
    # Record precise send time
    t1 = get_high_precision_time_us()  # Microsecond precision
    
    sync_request = create_time_sync_request(
        challenge_nonce = challenge_nonce,
        local_timestamp = t1 / 1000,  # Convert to milliseconds
        precision_timestamp = t1      # Keep microsecond precision
    )
    
    send_packet(sync_request)
    
    # Receive response with timeout
    sync_response = receive_packet_timeout(TIME_RESYNC_TIMEOUT_MS)
    t4 = get_high_precision_time_us()
    
    if sync_response == null or sync_response.challenge_nonce != challenge_nonce:
        return null
    
    # Extract peer timestamps
    t2 = sync_response.peer_receive_timestamp * 1000  # Peer receive time (us)
    t3 = sync_response.peer_send_timestamp * 1000     # Peer send time (us)
    
    # Calculate network delay and time offset using NTP algorithm
    network_delay = ((t4 - t1) - (t3 - t2)) / 2
    time_offset = ((t2 - t1) + (t3 - t4)) / 2
    
    return {
        'time_offset': time_offset / 1000,  # Convert back to milliseconds
        'network_delay': network_delay / 1000,
        'round_trip_time': (t4 - t1) / 1000,
        'timestamp': t1 / 1000,
        'quality': calculate_sample_quality(network_delay, t4 - t1)
    }

function calculate_optimal_time_offset(sync_samples):
    # Use weighted average based on sample quality and network delay
    total_weight = 0
    weighted_offset = 0
    
    for sample in sync_samples:
        # Weight based on quality and inverse of network delay
        weight = sample.quality / (1 + sample.network_delay)
        weighted_offset += sample.time_offset * weight
        total_weight += weight
    
    if total_weight == 0:
        return 0
    
    return weighted_offset / total_weight

function calculate_sync_quality(sync_samples):
    # Calculate synchronization quality based on sample consistency
    if len(sync_samples) < 2:
        return 0
    
    offsets = [sample.time_offset for sample in sync_samples]
    mean_offset = sum(offsets) / len(offsets)
    variance = sum((offset - mean_offset) ** 2 for offset in offsets) / len(offsets)
    standard_deviation = math.sqrt(variance)
    
    # Quality decreases with variance and network delay
    base_quality = max(0, 100 - (standard_deviation * 10))
    avg_delay = sum(sample.network_delay for sample in sync_samples) / len(sync_samples)
    delay_penalty = min(50, avg_delay)
    
    return max(0, base_quality - delay_penalty)
```

## Gradual Time Adjustment System

```pseudocode
function apply_gradual_time_adjustment(total_offset, sync_quality):
    # Apply time adjustment gradually to prevent port hopping disruption
    if abs(total_offset) < TIME_SYNC_PRECISION_MS:
        # Already synchronized
        update_sync_state(total_offset, sync_quality)
        return SUCCESS
    
    # Calculate adjustment schedule
    adjustment_steps = calculate_adjustment_steps(total_offset)
    step_size = total_offset / adjustment_steps
    
    # Queue gradual adjustments
    for step in range(adjustment_steps):
        adjustment = {
            'offset': step_size,
            'apply_time': get_current_time_ms() + (step * HOP_INTERVAL_MS),
            'step_number': step + 1,
            'total_steps': adjustment_steps
        }
        time_sync_state.adjustment_queue.append(adjustment)
    
    time_sync_state.current_state = TIME_SYNC_STATE_ADJUSTING
    return SUCCESS

function calculate_adjustment_steps(total_offset):
    # Calculate number of steps needed for gradual adjustment
    max_step_size = min(MAX_TIME_ADJUSTMENT_PER_HOP, abs(total_offset) * TIME_SYNC_ADJUSTMENT_RATE)
    steps = max(1, math.ceil(abs(total_offset) / max_step_size))
    
    # Ensure adjustment completes within reasonable time
    max_steps = DRIFT_CALCULATION_WINDOW / HOP_INTERVAL_MS / 4  # Complete within 1/4 of drift window
    return min(steps, max_steps)

function process_time_adjustments():
    # Process pending time adjustments on each hop interval
    current_time = get_current_time_ms()
    applied_adjustments = []
    
    for adjustment in time_sync_state.adjustment_queue:
        if current_time >= adjustment.apply_time:
            # Apply time adjustment
            time_sync_state.local_offset += adjustment.offset
            applied_adjustments.append(adjustment)
            
            # Log adjustment progress
            log_time_adjustment(adjustment.step_number, adjustment.total_steps, adjustment.offset)
    
    # Remove applied adjustments
    for adjustment in applied_adjustments:
        time_sync_state.adjustment_queue.remove(adjustment)
    
    # Check if adjustment is complete
    if len(time_sync_state.adjustment_queue) == 0 and time_sync_state.current_state == TIME_SYNC_STATE_ADJUSTING:
        time_sync_state.current_state = TIME_SYNC_STATE_SYNCHRONIZED
        validate_time_synchronization()

function get_synchronized_time():
    # Get current time with synchronization offset applied
    local_time = get_current_time_ms()
    return local_time + time_sync_state.local_offset
```

## Clock Drift Detection and Compensation

```pseudocode
function detect_clock_drift():
    # Detect systematic clock drift over time
    if len(time_sync_state.sync_samples) < 3:
        return 0.0  # Insufficient data for drift calculation
    
    # Calculate drift rate using linear regression
    recent_samples = time_sync_state.sync_samples[-TIME_SYNC_HISTORY_SIZE:]
    
    # Extract time and offset pairs
    time_points = [sample.timestamp for sample in recent_samples]
    offset_points = [sample.time_offset for sample in recent_samples]
    
    # Calculate drift rate (milliseconds per millisecond = ppm)
    drift_rate = calculate_linear_regression_slope(time_points, offset_points)
    
    # Convert to parts per million
    drift_ppm = drift_rate * 1000000
    
    # Update drift state
    time_sync_state.drift_rate = drift_ppm
    
    return drift_ppm

function compensate_clock_drift():
    # Apply drift compensation to time calculations
    if abs(time_sync_state.drift_rate) < 1.0:  # Ignore very small drift
        return
    
    current_time = get_current_time_ms()
    time_since_last_sync = current_time - time_sync_state.last_sync_time
    
    # Calculate accumulated drift
    drift_ms = (time_since_last_sync * time_sync_state.drift_rate) / 1000000
    
    # Apply drift compensation
    if abs(drift_ms) > TIME_SYNC_PRECISION_MS:
        time_sync_state.local_offset -= drift_ms
        time_sync_state.last_sync_time = current_time

function calculate_linear_regression_slope(x_values, y_values):
    # Calculate slope of linear regression line
    n = len(x_values)
    if n < 2:
        return 0.0
    
    sum_x = sum(x_values)
    sum_y = sum(y_values)
    sum_xy = sum(x * y for x, y in zip(x_values, y_values))
    sum_x2 = sum(x * x for x in x_values)
    
    denominator = n * sum_x2 - sum_x * sum_x
    if denominator == 0:
        return 0.0
    
    slope = (n * sum_xy - sum_x * sum_y) / denominator
    return slope
```

## Leap Second Handling

```pseudocode
function handle_leap_second_event():
    # Handle leap second insertion/deletion
    leap_second_info = get_leap_second_schedule()
    
    if leap_second_info == null:
        return SUCCESS
    
    current_time = get_current_time_ms()
    leap_second_time = leap_second_info.event_time
    
    # Check if leap second is imminent
    if abs(current_time - leap_second_time) < LEAP_SECOND_WINDOW_MS:
        time_sync_state.leap_second_pending = true
        
        # Pause time adjustments during leap second window
        pause_time_adjustments()
        
        # Increase synchronization frequency
        schedule_frequent_time_sync()
        
        return SUCCESS
    
    # Check if leap second has occurred
    if time_sync_state.leap_second_pending and current_time > leap_second_time + LEAP_SECOND_WINDOW_MS:
        time_sync_state.leap_second_pending = false
        
        # Resume normal time synchronization
        resume_normal_time_sync()
        
        # Force immediate resynchronization
        return execute_precision_time_sync()
    
    return SUCCESS

function pause_time_adjustments():
    # Temporarily pause time adjustments during leap second
    for adjustment in time_sync_state.adjustment_queue:
        adjustment.paused = true

function resume_normal_time_sync():
    # Resume normal time synchronization after leap second
    for adjustment in time_sync_state.adjustment_queue:
        if hasattr(adjustment, 'paused'):
            delattr(adjustment, 'paused')
```

## Emergency Time Synchronization

```pseudocode
function initiate_emergency_time_sync(large_offset):
    # Handle large time discrepancies that require immediate correction
    time_sync_state.current_state = TIME_SYNC_STATE_EMERGENCY
    time_sync_state.emergency_sync_attempts += 1
    
    if time_sync_state.emergency_sync_attempts > MAX_EMERGENCY_SYNC_ATTEMPTS:
        return ERROR_TIME_SYNC_EMERGENCY_FAILED
    
    # Perform multiple high-precision measurements
    emergency_samples = []
    for i in range(TIME_SYNC_SAMPLE_COUNT * 2):  # Double sample count for emergency
        sample = perform_single_time_sync()
        if sample != null:
            emergency_samples.append(sample)
        wait(HOP_INTERVAL_MS / 4)  # Faster sampling
    
    if len(emergency_samples) < TIME_SYNC_SAMPLE_COUNT:
        return ERROR_TIME_SYNC_EMERGENCY_INSUFFICIENT_SAMPLES
    
    # Calculate emergency offset with high confidence
    emergency_offset = calculate_optimal_time_offset(emergency_samples)
    sync_quality = calculate_sync_quality(emergency_samples)
    
    if sync_quality < 75:  # Higher threshold for emergency sync
        return ERROR_TIME_SYNC_EMERGENCY_POOR_QUALITY
    
    # Apply immediate offset correction
    if abs(emergency_offset) > TIME_SYNC_EMERGENCY_THRESHOLD:
        # Offset still too large - session may be compromised
        log_emergency_sync_failure(emergency_offset)
        return ERROR_TIME_SYNC_EMERGENCY_OFFSET_TOO_LARGE
    
    # Apply emergency offset immediately
    time_sync_state.local_offset += emergency_offset
    time_sync_state.current_state = TIME_SYNC_STATE_SYNCHRONIZED
    time_sync_state.emergency_sync_attempts = 0
    
    # Verify emergency synchronization
    return verify_emergency_synchronization()

function verify_emergency_synchronization():
    # Verify emergency synchronization was successful
    verification_sample = perform_single_time_sync()
    
    if verification_sample == null:
        return ERROR_TIME_SYNC_VERIFICATION_FAILED
    
    if abs(verification_sample.time_offset) > TIME_SYNC_PRECISION_MS:
        return ERROR_TIME_SYNC_VERIFICATION_OFFSET_TOO_LARGE
    
    log_emergency_sync_success(verification_sample.time_offset)
    return SUCCESS
```