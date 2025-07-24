# Replay Protection Mechanisms

This document specifies the comprehensive replay protection mechanisms that prevent attackers from capturing and retransmitting packets to disrupt communication or gain unauthorized access.

## Overview

The replay protection system uses a multi-layered approach combining timestamp validation, sequence number tracking, and cryptographic nonces to ensure that captured packets cannot be successfully replayed by attackers.

## Purpose and Rationale

Replay protection serves critical security functions:

- **Attack Prevention**: Prevents attackers from capturing and replaying valid packets to disrupt service
- **Session Integrity**: Ensures that each packet is processed exactly once in the correct order
- **Time-Based Security**: Uses synchronized timestamps to limit packet validity windows
- **Sequence Tracking**: Maintains sliding windows of valid sequence numbers to detect replays
- **Cryptographic Freshness**: Incorporates nonces and timestamps into HMAC calculations for packet uniqueness
- **Defense in Depth**: Multiple overlapping mechanisms ensure robustness against sophisticated attacks

The system is designed to handle legitimate network conditions (reordering, delay) while maintaining strong security guarantees against replay attacks.

## Key Concepts

- **Timestamp Windows**: Time-based validity periods for packet acceptance
- **Sequence Windows**: Sliding windows for tracking valid sequence numbers
- **Duplicate Detection**: Caches for identifying recently seen packets
- **Nonce Management**: Cryptographic nonces for ensuring packet uniqueness
- **HMAC Integration**: Timestamp and sequence binding in authentication
- **Clock Synchronization**: Coordinated time for consistent validation across peers

## Timestamp-Based Replay Protection

### Timestamp Validation Window

The TIMESTAMP_WINDOW_MS defines a 30-second sliding window for timestamp-based replay protection. This mechanism works with sequence number validation to provide protection against replay attacks while handling network conditions.

**Core Principles:**
- Packets with timestamps older than 30 seconds are rejected
- Packets with timestamps more than 50ms in the future are rejected (clock skew tolerance)
- Duplicate timestamps within the window are detected and blocked
- Out-of-order packets within the window are accepted if not duplicates

```pseudocode
// Timestamp validation constants (from 02-core-definitions.md)
TIMESTAMP_WINDOW_MS = 30000              // Anti-replay timestamp window (30 seconds)
MAX_PACKET_LIFETIME_MS = 60000           // Maximum packet age (60 seconds)
TIME_SYNC_TOLERANCE_MS = 50              // Maximum allowed clock drift
RECENT_TIMESTAMPS_SIZE = 1000            // Recent timestamp cache for replay detection

// Timestamp validation state
timestamp_validation_state = {
    'recent_timestamps': CircularBuffer(RECENT_TIMESTAMPS_SIZE),
    'timestamp_cache': LRUCache(RECENT_TIMESTAMPS_SIZE),
    'last_cleanup_time': 0,
    'replay_counter': 0,
    'window_violations': 0
}

function validate_packet_timestamp(packet):
    # Extract timestamp from packet header
    packet_timestamp = packet.header.timestamp
    current_time = get_synchronized_time()
    
    # Calculate time since month start for both timestamps
    month_start_utc = get_current_month_start_utc()
    packet_ms_since_month = packet_timestamp
    current_ms_since_month = current_time - month_start_utc
    
    # Handle month boundary crossing
    time_difference = calculate_time_difference_with_month_wraparound(
        packet_ms_since_month,
        current_ms_since_month
    )
    
    # Use stricter window for handshake packets
    timestamp_window = TIMESTAMP_WINDOW_MS
    if is_handshake_packet(packet):
        timestamp_window = HANDSHAKE_TIMESTAMP_WINDOW_MS
    
    # TIMESTAMP_WINDOW_MS Validation: Core Anti-Replay Mechanism
    # Phase 1: Age-based validation (30-second or 10-second sliding window)
    if time_difference > timestamp_window:
        # Packet timestamp is older than allowed window - replay attack
        timestamp_validation_state.window_violations += 1
        log_replay_attempt("timestamp_too_old", packet, time_difference)
        return ERROR_TIMESTAMP_INVALID
    
    # Phase 2: Future timestamp validation (clock skew tolerance)
    if time_difference < -TIME_SYNC_TOLERANCE_MS:
        # Packet claims to be from more than 50ms in the future
        if time_difference < -TIMESTAMP_WINDOW_MS:
            # Far future timestamp (>30s) - invalid
            timestamp_validation_state.window_violations += 1
            log_replay_attempt("timestamp_far_future", packet, time_difference)
            return ERROR_TIMESTAMP_INVALID
        else:
            # Near future timestamp (50ms-30s) - clock skew
            log_clock_skew_warning(packet, time_difference)
    
    # Phase 3: Duplicate timestamp detection within window
    timestamp_key = generate_timestamp_key(packet)
    if timestamp_key in timestamp_validation_state.timestamp_cache:
        # This exact timestamp+session+sequence combination was recently seen
        timestamp_validation_state.replay_counter += 1
        log_replay_attempt("duplicate_timestamp", packet, time_difference)
        return ERROR_REPLAY_ATTACK
    
    # Phase 4: Out-of-order acceptance within window
    # Packet timestamp is within valid window and not a duplicate
    # Accept the packet even if it arrives out of chronological order
    # The sequence number validation handles ordering requirements
    
    # Add to recent timestamp cache with expiration
    cache_entry = {
        'timestamp_key': timestamp_key,
        'packet_timestamp': packet_timestamp,
        'received_time': current_time,
        'session_id': packet.header.session_id,
        'sequence_number': packet.header.sequence_number
    }
    timestamp_validation_state.timestamp_cache.add(timestamp_key, cache_entry)
    timestamp_validation_state.recent_timestamps.add(packet_timestamp)
    
    # Phase 5: Periodic cleanup of expired entries
    if current_time - timestamp_validation_state.last_cleanup_time > TIMESTAMP_WINDOW_MS // 2:
        cleanup_old_timestamps(current_time)
    
    return SUCCESS

function calculate_time_difference_with_month_wraparound(packet_time, current_time):
    # Handle timestamp wraparound at month boundary
    if packet_time > current_time:
        # Future timestamp (clock skew) - should be rare with month epochs
        return -(packet_time - current_time)
    else:
        # Normal case - packet from earlier in month
        return current_time - packet_time

function generate_timestamp_key(packet):
    # Generate unique key for timestamp cache
    # Combines timestamp with packet-specific data to prevent collision attacks
    key_data = concat(
        packet.header.timestamp,
        packet.header.session_id,
        packet.header.sequence_number,
        packet.header.type
    )
    return hash_64bit(key_data)

function cleanup_old_timestamps(current_time):
    # Remove timestamps older than replay window
    cutoff_time = current_time - TIMESTAMP_WINDOW_MS
    
    # Remove expired entries from timestamp cache
    expired_count = 0
    for key, entry in timestamp_validation_state.timestamp_cache.items():
        if entry.received_time < cutoff_time:
            timestamp_validation_state.timestamp_cache.remove(key)
            expired_count += 1
    
    # Remove old timestamps from recent buffer
    timestamp_validation_state.recent_timestamps.remove_older_than(cutoff_time)
    timestamp_validation_state.last_cleanup_time = current_time
    
    # Log cleanup statistics
    if expired_count > 0:
        log_timestamp_cache_cleanup(expired_count, cutoff_time)

### Duplicate Detection Mechanism

The timestamp-based duplicate detection mechanism creates unique keys for each packet combining multiple packet attributes. This prevents replay attacks while allowing legitimate retransmissions.

```pseudocode
function generate_timestamp_key(packet):
    # Generate unique key for timestamp cache to prevent replay attacks
    # Combines multiple packet attributes to create collision-resistant identifier
    
    # Primary components for uniqueness
    primary_data = concat(
        packet.header.timestamp,           # When packet claims to be sent
        packet.header.session_id,          # Which session/connection
        packet.header.sequence_number,     # Position in data stream
        packet.header.type                 # Type of packet
    )
    
    # Secondary components for collision resistance
    secondary_data = concat(
        packet.header.sub_type,            # Packet sub-type if applicable
        packet.header.payload_length,      # Size of payload
        packet.payload[0:8] if len(packet.payload) >= 8 else packet.payload  # First 8 bytes of payload
    )
    
    # Generate collision-resistant hash
    full_key_data = primary_data + secondary_data
    return hash_64bit(full_key_data)

function detect_duplicate_packet(packet, session_state):
    # Multi-layer duplicate detection combining timestamp and sequence validation
    
    # Layer 1: Timestamp-based duplicate detection (handles replay attacks)
    timestamp_key = generate_timestamp_key(packet)
    if timestamp_key in timestamp_validation_state.timestamp_cache:
        cached_entry = timestamp_validation_state.timestamp_cache.get(timestamp_key)
        
        # Verify this is truly a duplicate (not just hash collision)
        if (cached_entry.session_id == packet.header.session_id and
            cached_entry.sequence_number == packet.header.sequence_number and
            cached_entry.packet_timestamp == packet.header.timestamp):
            
            # Confirmed duplicate - log and reject
            log_duplicate_detection("timestamp_duplicate", packet, cached_entry)
            return ERROR_REPLAY_ATTACK
    
    # Layer 2: Sequence-based duplicate detection (handles retransmissions)
    sequence_result = validate_packet_sequence(packet, session_state)
    if sequence_result == ERROR_REPLAY_ATTACK:
        log_duplicate_detection("sequence_duplicate", packet)
        return ERROR_REPLAY_ATTACK
    
    return SUCCESS

### Out-of-Order Packet Handling

The protocol handles out-of-order packets within the timestamp window while maintaining security against replay attacks.

```pseudocode
function handle_out_of_order_packet(packet, session_state):
    # Handle packets that arrive out of chronological order but within valid windows
    
    current_time = get_current_time_ms()
    packet_timestamp = packet.header.timestamp
    
    # Calculate how far out of order this packet is
    month_start = get_current_month_start_utc()
    packet_age = current_time - (month_start + packet_timestamp)
    
    # Accept out-of-order packets within timestamp window
    if packet_age <= TIMESTAMP_WINDOW_MS and packet_age >= 0:
        # Packet is within acceptable age range
        
        # Check if this is legitimate out-of-order arrival
        if is_legitimate_out_of_order(packet, session_state):
            # Update out-of-order statistics
            session_state.out_of_order_count += 1
            session_state.last_out_of_order_time = current_time
            
            # Add to reorder buffer for proper sequencing
            add_to_reorder_buffer(packet, session_state)
            
            log_out_of_order_acceptance(packet, packet_age)
            return SUCCESS
        else:
            # Suspicious out-of-order pattern - attack
            log_suspicious_out_of_order(packet, packet_age)
            return ERROR_REPLAY_ATTACK
    else:
        # Packet too old or invalid timestamp
        return ERROR_TIMESTAMP_INVALID

function is_legitimate_out_of_order(packet, session_state):
    # Determine if out-of-order packet is legitimate network reordering
    
    # Check 1: Sequence number within acceptable reorder window
    sequence_gap = abs(packet.header.sequence_number - session_state.expected_sequence)
    if sequence_gap > SEQUENCE_WINDOW_SIZE:
        return false  # Too far out of sequence
    
    # Check 2: Not too many out-of-order packets recently
    if session_state.out_of_order_count > MAX_OUT_OF_ORDER_RATE:
        recent_time_window = 60000  # 1 minute
        if current_time - session_state.last_out_of_order_time < recent_time_window:
            return false  # Too many out-of-order packets recently
    
    # Check 3: Reasonable timestamp relationship
    expected_timestamp_range = calculate_expected_timestamp_range(session_state)
    if packet.header.timestamp not in expected_timestamp_range:
        return false  # Timestamp doesn't match expected pattern
    
    return true

function add_to_reorder_buffer(packet, session_state):
    # Add out-of-order packet to reorder buffer for proper sequencing
    
    # Create reorder buffer entry
    reorder_entry = {
        'packet': packet,
        'sequence_number': packet.header.sequence_number,
        'timestamp': packet.header.timestamp,
        'received_time': get_current_time_ms(),
        'reorder_timeout': get_current_time_ms() + REORDER_TIMEOUT_MS
    }
    
    # Insert in sequence order
    insert_position = find_sequence_position(session_state.reorder_buffer, packet.header.sequence_number)
    session_state.reorder_buffer.insert(insert_position, reorder_entry)
    
    # Limit reorder buffer size
    if len(session_state.reorder_buffer) > REORDER_BUFFER_SIZE:
        # Remove oldest entry
        oldest_entry = min(session_state.reorder_buffer, key=lambda x: x.received_time)
        session_state.reorder_buffer.remove(oldest_entry)
        log_reorder_buffer_overflow(oldest_entry.sequence_number)
    
    # Try to deliver consecutive packets from buffer
    deliver_consecutive_packets(session_state)

function deliver_consecutive_packets(session_state):
    # Deliver any consecutive packets from reorder buffer
    
    delivered_count = 0
    while (len(session_state.reorder_buffer) > 0 and
           session_state.reorder_buffer[0].sequence_number == session_state.expected_sequence):
        
        # Remove from reorder buffer and deliver
        packet_entry = session_state.reorder_buffer.pop(0)
        deliver_packet_to_application(packet_entry.packet)
        
        session_state.expected_sequence += 1
        delivered_count += 1
    
    if delivered_count > 0:
        log_reorder_delivery(delivered_count, session_state.expected_sequence)
```

## Sequence Number Replay Protection

### Sequence Number Window Tracking

```pseudocode
// Sequence number validation constants are defined in 02-core-definitions.md:
// - SEQUENCE_WINDOW_SIZE = 1000 (Sequence number acceptance window)
// - RECENT_SEQUENCES_SIZE = 100 (Recent sequence number cache)
// - SEQUENCE_WRAP_THRESHOLD = 0x80000000 (Threshold for sequence wraparound)

// Sequence validation state per session
sequence_validation_state = {
    'expected_sequence': 0,              // Next expected sequence number
    'highest_received': 0,               // Highest sequence number received
    'sequence_bitmap': BitMap(SEQUENCE_WINDOW_SIZE),  // Received sequence tracking
    'recent_sequences': CircularBuffer(RECENT_SEQUENCES_SIZE),
    'out_of_order_count': 0,
    'duplicate_count': 0,
    'replay_attempts': 0
}

function validate_packet_sequence(packet, session_state):
    sequence_number = packet.header.sequence_number
    expected_sequence = sequence_validation_state.expected_sequence
    
    # Handle sequence number wraparound
    if is_sequence_wraparound(sequence_number, expected_sequence):
        return handle_sequence_wraparound(sequence_number)
    
    # Check if sequence number is too old (replay attack)
    if sequence_number < expected_sequence - SEQUENCE_WINDOW_SIZE:
        sequence_validation_state.replay_attempts += 1
        return ERROR_REPLAY_ATTACK
    
    # Check if sequence number is within acceptable window
    if sequence_number < expected_sequence:
        # Out-of-order packet - check if already received
        window_offset = expected_sequence - sequence_number - 1
        
        if sequence_validation_state.sequence_bitmap.is_set(window_offset):
            # Duplicate packet (replay attempt)
            sequence_validation_state.duplicate_count += 1
            sequence_validation_state.replay_attempts += 1
            return ERROR_REPLAY_ATTACK
        
        # Mark as received
        sequence_validation_state.sequence_bitmap.set(window_offset)
        sequence_validation_state.out_of_order_count += 1
        
    elif sequence_number == expected_sequence:
        # Expected sequence number
        sequence_validation_state.expected_sequence += 1
        
        # Advance window and clear old entries
        advance_sequence_window()
        
    else:  # sequence_number > expected_sequence
        # Future sequence number - advance window
        gap = sequence_number - expected_sequence
        
        if gap > SEQUENCE_WINDOW_SIZE:
            # Too far in future - possible attack
            return ERROR_SEQUENCE_INVALID
        
        # Advance expected sequence and window
        for i in range(gap):
            advance_sequence_window()
        
        sequence_validation_state.expected_sequence = sequence_number + 1
        sequence_validation_state.highest_received = sequence_number
    
    # Add to recent sequences cache
    sequence_validation_state.recent_sequences.add(sequence_number)
    
    return SUCCESS

function is_sequence_wraparound(sequence_number, expected_sequence):
    # Detect 32-bit sequence number wraparound
    if expected_sequence > SEQUENCE_WRAP_THRESHOLD and sequence_number < SEQUENCE_WINDOW_SIZE:
        return true
    return false

function handle_sequence_wraparound(sequence_number):
    # Handle sequence number wraparound at 32-bit boundary
    # Reset tracking structures while maintaining security
    
    # Verify this is legitimate wraparound
    if sequence_validation_state.highest_received < SEQUENCE_WRAP_THRESHOLD:
        # Not near wraparound boundary - likely attack
        return ERROR_SEQUENCE_INVALID
    
    # Reset sequence tracking
    sequence_validation_state.expected_sequence = sequence_number + 1
    sequence_validation_state.highest_received = sequence_number
    sequence_validation_state.sequence_bitmap.clear()
    
    # Log wraparound event
    log_sequence_wraparound_event()
    
    return SUCCESS

function advance_sequence_window():
    # Advance the sequence number window by one
    sequence_validation_state.sequence_bitmap.shift_left(1)
    sequence_validation_state.sequence_bitmap.clear_bit(SEQUENCE_WINDOW_SIZE - 1)
```

## Combined Replay Protection

### Integrated Validation Pipeline

```pseudocode
function validate_packet_replay_protection(packet, session_state):
    # Complete replay protection validation pipeline
    
    # Step 1: Validate timestamp
    timestamp_result = validate_packet_timestamp(packet)
    if timestamp_result != SUCCESS:
        log_replay_attempt(REPLAY_TYPE_TIMESTAMP, packet)
        return timestamp_result
    
    # Step 2: Validate sequence number
    sequence_result = validate_packet_sequence(packet, session_state)
    if sequence_result != SUCCESS:
        log_replay_attempt(REPLAY_TYPE_SEQUENCE, packet)
        return sequence_result
    
    # Step 3: Check packet-specific replay protection
    packet_result = validate_packet_specific_replay(packet, session_state)
    if packet_result != SUCCESS:
        log_replay_attempt(REPLAY_TYPE_PACKET_SPECIFIC, packet)
        return packet_result
    
    # Step 4: Update replay detection metrics
    update_replay_detection_metrics(packet)
    
    return SUCCESS

function validate_packet_specific_replay(packet, session_state):
    # Additional replay protection for specific packet types
    
    switch packet.header.type:
        case PACKET_TYPE_SYN:
            return validate_syn_replay(packet)
            
        case PACKET_TYPE_SYN_ACK:
            return validate_syn_ack_replay(packet)
            
        case PACKET_TYPE_DISCOVERY:
            return validate_discovery_replay(packet)
            
        case PACKET_TYPE_CONTROL:
            if packet.header.sub_type == CONTROL_SUB_TIME_SYNC_REQUEST:
                return validate_time_sync_replay(packet)
            
        case PACKET_TYPE_MANAGEMENT:
            if packet.header.sub_type == MANAGEMENT_SUB_REKEY_REQUEST:
                return validate_rekey_replay(packet)
    
    return SUCCESS
```

### Connection Establishment Replay Protection

```pseudocode
// Handshake replay protection with server-side cache
handshake_replay_state = {
    'recent_handshakes': LRUCache(10000),    // Larger cache for handshake attempts
    'syn_flood_counter': 0,
    'last_cleanup': 0,
    'cleanup_interval': HANDSHAKE_TIMESTAMP_WINDOW_MS  // Cleanup after 10 seconds
}

// Server-side handshake cache for comprehensive replay detection
server_handshake_cache = LRUCache(50000)  // Track recent handshake attempts

function is_handshake_packet(packet):
    # Check if packet is part of handshake sequence
    if packet.header.type in [PACKET_TYPE_SYN, PACKET_TYPE_SYN_ACK]:
        return true
    # ACK packets with challenge response are also handshake packets
    if packet.header.type == PACKET_TYPE_ACK and hasattr(packet, 'challenge_response'):
        return true
    return false

function validate_syn_replay(syn_packet):
    # Enforce stricter timestamp window for handshakes
    current_time = get_current_time_ms()
    packet_age = current_time - syn_packet.header.timestamp
    
    if packet_age > HANDSHAKE_TIMESTAMP_WINDOW_MS:
        return ERROR_TIMESTAMP_INVALID
    
    # Generate comprehensive cache key
    cache_key = generate_handshake_cache_key(syn_packet)
    
    # Check server-side handshake cache
    if cache_key in server_handshake_cache:
        handshake_replay_state.syn_flood_counter += 1
        
        # Check for SYN flood attack
        if handshake_replay_state.syn_flood_counter > SYN_FLOOD_THRESHOLD:
            return ERROR_RATE_LIMITED
        
        return ERROR_REPLAY_ATTACK
    
    # Add to server cache with timestamp
    server_handshake_cache.add(cache_key, current_time)
    
    # Cleanup old entries more frequently for handshakes
    if current_time - handshake_replay_state.last_cleanup > handshake_replay_state.cleanup_interval:
        cleanup_old_handshake_entries(current_time)
    
    return SUCCESS

function generate_handshake_cache_key(packet):
    # Create comprehensive cache key including all security-critical fields
    # This prevents any form of packet manipulation or replay
    key_data = concat(
        packet.header.type,
        packet.header.timestamp,
        packet.header.sequence_number,
        packet.client_public_key if hasattr(packet, 'client_public_key') else b'',
        packet.server_public_key if hasattr(packet, 'server_public_key') else b'',
        packet.client_nonce if hasattr(packet, 'client_nonce') else b'',
        packet.server_nonce if hasattr(packet, 'server_nonce') else b'',
        packet.key_exchange_id if hasattr(packet, 'key_exchange_id') else 0,
        packet.source_address  # Include source to prevent cross-source replay
    )
    return hash_256bit(key_data)

function generate_syn_identifier(syn_packet):
    # Delegate to comprehensive cache key generation
    return generate_handshake_cache_key(syn_packet)

function validate_syn_ack_replay(syn_ack_packet):
    # Enforce stricter timestamp window for handshakes
    current_time = get_current_time_ms()
    packet_age = current_time - syn_ack_packet.header.timestamp
    
    if packet_age > HANDSHAKE_TIMESTAMP_WINDOW_MS:
        return ERROR_TIMESTAMP_INVALID
    
    # Verify both client and server nonces
    if syn_ack_packet.client_nonce_echo != session_state.client_nonce:
        return ERROR_REPLAY_ATTACK
    
    # Generate comprehensive cache key
    cache_key = generate_handshake_cache_key(syn_ack_packet)
    
    # Check if SYN-ACK was recently seen
    if cache_key in handshake_replay_state.recent_handshakes:
        return ERROR_REPLAY_ATTACK
    
    # Add to cache
    handshake_replay_state.recent_handshakes.add(cache_key, current_time)
    
    return SUCCESS

function generate_syn_ack_identifier(syn_ack_packet):
    # Create unique identifier for SYN-ACK packet
    id_data = concat(
        syn_ack_packet.server_public_key,
        syn_ack_packet.server_nonce,        # Server nonce for uniqueness
        syn_ack_packet.client_nonce_echo,   # Echoed client nonce
        syn_ack_packet.key_exchange_id,
        syn_ack_packet.header.timestamp
    )
    return hash_256bit(id_data)
```

### Time Synchronization Replay Protection

```pseudocode
// Time sync replay protection
time_sync_replay_state = {
    'pending_challenges': HashMap(),     // Outstanding time sync challenges
    'recent_challenges': LRUCache(100),  // Recently used challenges
    'challenge_timeout_ms': 5000         // Challenge validity period
}

function validate_time_sync_replay(sync_packet):
    challenge_nonce = sync_packet.challenge_nonce
    
    if sync_packet.header.sub_type == CONTROL_SUB_TIME_SYNC_REQUEST:
        # Check if challenge was recently used
        if challenge_nonce in time_sync_replay_state.recent_challenges:
            return ERROR_REPLAY_ATTACK
        
        # Add to recent challenges
        time_sync_replay_state.recent_challenges.add(
            challenge_nonce,
            get_current_time_ms()
        )
        
    elif sync_packet.header.sub_type == CONTROL_SUB_TIME_SYNC_RESPONSE:
        # Verify challenge is pending
        if challenge_nonce not in time_sync_replay_state.pending_challenges:
            return ERROR_REPLAY_ATTACK
        
        # Verify challenge hasn't expired
        challenge_data = time_sync_replay_state.pending_challenges[challenge_nonce]
        if get_current_time_ms() - challenge_data.timestamp > challenge_timeout_ms:
            return ERROR_REPLAY_ATTACK
        
        # Remove used challenge
        del time_sync_replay_state.pending_challenges[challenge_nonce]
    
    return SUCCESS
```

### HMAC Binding for Replay Prevention

```pseudocode
function calculate_packet_hmac_with_replay_protection(packet, session_key):
    # Include replay-prevention fields in HMAC calculation
    # This cryptographically binds timestamp and sequence to packet
    
    # Prepare data for HMAC
    hmac_data = concat(
        packet.header.version,
        packet.header.type,
        packet.header.sub_type,
        packet.header.flags,
        packet.header.session_id,
        packet.header.sequence_number,      # Sequence binding
        packet.header.acknowledgment_number,
        packet.header.timestamp,             # Timestamp binding
        packet.header.payload_length,
        packet.payload
    )
    
    # For specific packet types, include additional nonces
    if packet.header.type == PACKET_TYPE_SYN:
        hmac_data = concat(hmac_data, packet.key_exchange_id, packet.client_nonce)
    elif packet.header.type == PACKET_TYPE_SYN_ACK:
        hmac_data = concat(hmac_data, packet.key_exchange_id, packet.server_nonce, packet.client_nonce_echo)
    elif packet.header.type == PACKET_TYPE_CONTROL:
        if packet.header.sub_type == CONTROL_SUB_TIME_SYNC_REQUEST:
            hmac_data = concat(hmac_data, packet.challenge_nonce)
    
    # Calculate HMAC
    return hmac_sha256(session_key, hmac_data)
```

## Replay Attack Detection and Response

### Attack Pattern Detection

```pseudocode
// Replay attack detection thresholds
REPLAY_DETECTION_WINDOW_MS = 60000       // 1 minute detection window
REPLAY_THRESHOLD_PER_WINDOW = 10         // Threshold for declaring attack
REPLAY_BLOCK_DURATION_MS = 300000        // 5 minute block duration

// Attack detection state
replay_attack_detection = {
    'detection_windows': HashMap(),       // Per-source detection windows
    'blocked_sources': HashMap(),         // Blocked source addresses
    'global_replay_counter': 0,
    'detection_enabled': true
}

function detect_replay_attack_pattern(source_address, packet):
    # Detect systematic replay attack attempts
    
    current_time = get_current_time_ms()
    window_key = generate_detection_window_key(source_address, current_time)
    
    # Update detection window counter
    if window_key not in replay_attack_detection.detection_windows:
        replay_attack_detection.detection_windows[window_key] = 0
    
    replay_attack_detection.detection_windows[window_key] += 1
    replay_attack_detection.global_replay_counter += 1
    
    # Check if threshold exceeded
    if replay_attack_detection.detection_windows[window_key] > REPLAY_THRESHOLD_PER_WINDOW:
        # Replay attack detected - block source
        block_replay_attacker(source_address, current_time)
        return ERROR_REPLAY_ATTACK_DETECTED
    
    # Cleanup old detection windows
    cleanup_detection_windows(current_time)
    
    return SUCCESS

function block_replay_attacker(source_address, current_time):
    # Block source address due to replay attack
    replay_attack_detection.blocked_sources[source_address] = {
        'block_time': current_time,
        'expiry_time': current_time + REPLAY_BLOCK_DURATION_MS,
        'attack_count': 1
    }
    
    log_security_event(
        SECURITY_EVENT_REPLAY_ATTACK_BLOCKED,
        source_address
    )

function is_source_blocked_for_replay(source_address):
    # Check if source is currently blocked
    if source_address not in replay_attack_detection.blocked_sources:
        return false
    
    block_info = replay_attack_detection.blocked_sources[source_address]
    current_time = get_current_time_ms()
    
    if current_time > block_info.expiry_time:
        # Block expired - remove
        del replay_attack_detection.blocked_sources[source_address]
        return false
    
    return true
```

## Performance Optimization

### Efficient Cache Management

```pseudocode
function optimize_replay_caches():
    # Periodic optimization of replay protection caches
    
    # Optimize timestamp cache
    if timestamp_validation_state.timestamp_cache.size() > RECENT_TIMESTAMPS_SIZE * 0.9:
        # Cache nearly full - aggressive cleanup
        aggressive_timestamp_cleanup()
    
    # Optimize sequence bitmap
    if sequence_validation_state.out_of_order_count > SEQUENCE_WINDOW_SIZE * 0.5:
        # High out-of-order rate - consider increasing window
        consider_sequence_window_adjustment()
    
    # Optimize detection windows
    if len(replay_attack_detection.detection_windows) > 1000:
        # Too many detection windows - cleanup
        force_detection_window_cleanup()

function aggressive_timestamp_cleanup():
    # Remove oldest 25% of timestamp cache entries
    cutoff_size = timestamp_validation_state.timestamp_cache.size() * 0.75
    timestamp_validation_state.timestamp_cache.resize(cutoff_size)

function consider_sequence_window_adjustment():
    # Dynamically adjust sequence window based on network conditions
    # Log recommendation for administrator
    log_performance_recommendation(
        "High out-of-order packet rate detected. " +
        "Consider increasing SEQUENCE_WINDOW_SIZE"
    )
```

## Integration with Protocol Components

### Packet Processing Pipeline Integration

```pseudocode
function process_incoming_packet_with_replay_protection(packet, source_address):
    # Complete packet processing with replay protection
    
    # Check if source is blocked
    if is_source_blocked_for_replay(source_address):
        return ERROR_SOURCE_BLOCKED
    
    # Perform replay protection validation
    replay_result = validate_packet_replay_protection(packet, session_state)
    
    if replay_result != SUCCESS:
        # Replay attempt detected
        detect_replay_attack_pattern(source_address, packet)
        return replay_result
    
    # Continue with normal packet processing
    return process_validated_packet(packet)
```

## Configuration and Tuning

### Replay Protection Parameters

```pseudocode
// Configurable replay protection parameters
replay_protection_config = {
    'timestamp_window_ms': TIMESTAMP_WINDOW_MS,
    'sequence_window_size': SEQUENCE_WINDOW_SIZE,
    'cache_sizes': {
        'timestamp': RECENT_TIMESTAMPS_SIZE,
        'sequence': RECENT_SEQUENCES_SIZE,
        'syn': 1000
    },
    'detection_thresholds': {
        'replay_per_window': REPLAY_THRESHOLD_PER_WINDOW,
        'syn_flood': 100,
        'block_duration_ms': REPLAY_BLOCK_DURATION_MS
    },
    'performance_tuning': {
        'cleanup_interval_ms': 30000,
        'cache_optimization_interval_ms': 60000,
        'detection_window_size_ms': REPLAY_DETECTION_WINDOW_MS
    }
}

function adjust_replay_protection_parameters(new_config):
    # Dynamically adjust replay protection parameters
    # Validate new configuration
    if validate_replay_config(new_config):
        apply_replay_config(new_config)
        log_configuration_change("Replay protection parameters updated")
        return SUCCESS
    
    return ERROR_INVALID_CONFIGURATION
```