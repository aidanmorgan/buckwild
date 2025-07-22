# Complete Fragmentation Specification

## Overview

This document specifies the packet fragmentation and reassembly mechanisms that enable transmission of large data payloads across networks with varying Maximum Transmission Unit (MTU) constraints. The fragmentation system ensures reliable delivery of oversized packets while maintaining efficiency and security.

## Purpose and Rationale

Fragmentation serves critical functions in heterogeneous network environments:

- **MTU Adaptation**: Enables transmission across networks with different MTU limits
- **Large Data Handling**: Supports application data larger than network packet size limits
- **Path MTU Discovery**: Adapts to the smallest MTU along the network path
- **Reliability**: Ensures all fragments are delivered and correctly reassembled
- **Security**: Maintains authentication and integrity across fragmented data

The fragmentation design integrates with the optimized DATA packet format, using header fields efficiently and providing robust reassembly with timeout handling for missing fragments.

## Key Concepts

- **Fragment Identification**: Unique identifiers that group related fragments
- **Fragment Ordering**: Sequence information enabling correct reassembly
- **Fragment Timeout**: Time limits for completing reassembly operations
- **MTU Discovery**: Dynamic detection of maximum safe packet sizes
- **Reassembly Buffers**: Memory management for partial packet reconstruction

## Constants and Configuration

```pseudocode
// Network constants
DEFAULT_MTU = 1500                       // Default MTU size
FRAGMENTATION_THRESHOLD = 1400           // Size threshold for fragmentation
MAX_FRAGMENTS = 255                      // Maximum fragments per packet

// Fragmentation constants
MAX_FRAGMENT_SIZE = 1400                // Maximum fragment payload size (bytes)
FRAGMENT_REASSEMBLY_BUFFER_SIZE = 64    // Maximum fragments in reassembly buffer
FRAGMENT_ID_SPACE = 0xFFFF              // Fragment ID space (16-bit)
FRAGMENT_DUPLICATE_WINDOW = 100         // Window for detecting duplicate fragments
FRAGMENT_TIMEOUT_MS = 30000             // Fragment reassembly timeout (30 seconds)
```

## Packet Type Definition

```pseudocode
// Fragmentation now integrated into DATA packets (Type 0x04) using header fields
```

## Common Header Fragment Fields

```pseudocode
Common Header Structure (Big-Endian):
+-----------------------------------+
|      Timestamp (32-bit)          |
+-----------------------------------+
|    Window Size     | Fragment ID |
+-------------------+---------------+
|  Fragment Index   | Total Frags  |
+-------------------+---------------+

Field Definitions:
- Window Size (16-bit): Available receive window size (big-endian)
- Fragment ID (16-bit): Unique fragment identifier (big-endian)
- Fragment Index (16-bit): Fragment position (0-based, big-endian)
- Total Frags (16-bit): Total number of fragments (big-endian)
```

## FRAGMENT Packet Structure

```pseudocode
FRAGMENT Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
| Fragment ID      |Fragment Index |
+-------------------+---------------+
|   Total Fragments                |
+-----------------------------------+
|        Fragment Data              |
|        (Variable Length)          |
|                                 |
|                                 |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with PSH flag set
- Fragment ID (16-bit): Unique fragment identifier
- Fragment Index (16-bit): Fragment position (0-based)
- Total Fragments (16-bit): Total number of fragments
- Fragment Data (Variable Length): Fragment payload

Total FRAGMENT Packet Size: 50 + 6 + fragment_data_length bytes
```

## Fragment Reassembly Algorithm

```pseudocode
function handle_fragment_packet(fragment_packet):
    fragment_id = fragment_packet.fragment_id
    fragment_index = fragment_packet.fragment_index
    total_fragments = fragment_packet.total_fragments
    
    # Initialize fragment buffer if needed
    if fragment_id not in fragment_buffers:
        fragment_buffers[fragment_id] = {
            'fragments': [None] * total_fragments,
            'total_fragments': total_fragments,
            'received_count': 0,
            'timer': current_time + FRAGMENT_TIMEOUT_MS
        }
    
    buffer = fragment_buffers[fragment_id]
    
    # Store fragment
    if fragment_index < total_fragments and buffer['fragments'][fragment_index] is None:
        buffer['fragments'][fragment_index] = fragment_packet.fragment_data
        buffer['received_count'] += 1
        
        # Check if all fragments received
        if buffer['received_count'] == total_fragments:
            reassembled_data = reassemble_fragments(buffer['fragments'])
            deliver_to_application(reassembled_data)
            del fragment_buffers[fragment_id]
        else:
            # Extend timer
            buffer['timer'] = current_time + FRAGMENT_TIMEOUT_MS

function reassemble_fragments(fragments):
    # Reassemble fragments in order
    reassembled_data = b''
    for fragment in fragments:
        if fragment is not None:
            reassembled_data += fragment
        else:
            raise FragmentReassemblyError("Missing fragment")
    
    return reassembled_data

function cleanup_expired_fragments():
    # Clean up expired fragment buffers
    current_time = get_current_time()
    expired_fragments = []
    
    for fragment_id, buffer in fragment_buffers.items():
        if current_time > buffer['timer']:
            expired_fragments.append(fragment_id)
    
    for fragment_id in expired_fragments:
        del fragment_buffers[fragment_id]
```

## Fragmentation Overview

The protocol implements application-layer fragmentation to handle packets that exceed the network MTU while maintaining security and reliability properties across fragments.

## Fragmentation Triggers and Policies

```pseudocode
function should_fragment_packet(packet, mtu):
    packet_size = calculate_total_packet_size(packet)
    return packet_size > (mtu - IP_HEADER_SIZE - UDP_HEADER_SIZE)

function calculate_fragment_parameters(data_length, mtu):
    # Calculate usable payload size per fragment
    header_overhead = OPTIMIZED_COMMON_HEADER_SIZE + FRAGMENT_HEADER_SIZE
    max_fragment_payload = min(MAX_FRAGMENT_SIZE, mtu - header_overhead)
    
    # Calculate number of fragments needed
    fragment_count = (data_length + max_fragment_payload - 1) / max_fragment_payload
    
    if fragment_count > MAX_FRAGMENTS:
        return ERROR_PACKET_TOO_LARGE
    
    return {
        'fragment_count': fragment_count,
        'fragment_payload_size': max_fragment_payload,
        'last_fragment_size': data_length % max_fragment_payload
    }
```

## Fragmentation Process

```pseudocode
function fragment_packet(original_packet, fragment_params):
    fragment_id = generate_fragment_id()
    fragments = []
    data_offset = 0
    
    for fragment_index in range(fragment_params.fragment_count):
        # Determine fragment payload size
        if fragment_index == fragment_params.fragment_count - 1:
            payload_size = fragment_params.last_fragment_size
        else:
            payload_size = fragment_params.fragment_payload_size
        
        # Extract fragment payload
        fragment_payload = original_packet.payload[data_offset:data_offset + payload_size]
        
        # Create fragment header
        fragment_header = create_fragment_header(
            fragment_id = fragment_id,
            fragment_index = fragment_index,
            total_fragments = fragment_params.fragment_count,
            fragment_payload_size = payload_size
        )
        
        # Create complete fragment packet using DATA type with fragment fields
        fragment_packet = create_packet(
            type = PACKET_TYPE_DATA,
            session_id = original_packet.session_id,
            sequence_number = original_packet.sequence_number + fragment_index,
            fragment_flag = true,
            fragment_id = fragment_params.fragment_id,
            fragment_index = fragment_index,
            total_fragments = fragment_params.fragment_count,
            payload = fragment_payload
        )
        
        fragments.append(fragment_packet)
        data_offset += payload_size
    
    return fragments

function generate_fragment_id():
    # Generate unique fragment ID for this session
    current_time = get_current_time_ms()
    session_fragment_counter = session_state.fragment_counter
    session_state.fragment_counter = (session_state.fragment_counter + 1) % FRAGMENT_ID_SPACE
    
    # Combine timestamp and counter for uniqueness
    fragment_id = (current_time & 0xFFFF0000) | session_fragment_counter
    return fragment_id
```

## Fragment Transmission and Pacing

```pseudocode
function transmit_fragments(fragments):
    # Apply transmission pacing to avoid network congestion
    fragment_interval = calculate_fragment_interval(len(fragments))
    
    for fragment in fragments:
        send_packet(fragment)
        
        # Add inter-fragment delay for pacing
        if fragment != fragments[-1]:  # Don't delay after last fragment
            wait(fragment_interval)
    
    # Set fragment reassembly timeout
    fragment_timeout = get_current_time_ms() + FRAGMENT_TIMEOUT_MS
    track_fragment_transmission(fragments[0].fragment_id, fragment_timeout)

function calculate_fragment_interval(fragment_count):
    # Calculate optimal inter-fragment delay based on network conditions
    base_interval = max(1, HOP_INTERVAL_MS / 10)  # Fraction of hop interval
    congestion_factor = session_state.congestion_window / INITIAL_CONGESTION_WINDOW
    
    return base_interval / congestion_factor
```

## Fragment Reception and Reassembly

```pseudocode
function handle_fragment_reception(fragment_packet):
    fragment_header = parse_fragment_header(fragment_packet)
    fragment_id = fragment_header.fragment_id
    
    # Validate fragment
    if not validate_fragment(fragment_packet, fragment_header):
        return ERROR_FRAGMENT_INVALID
    
    # Check for duplicate fragment
    if is_duplicate_fragment(fragment_id, fragment_header.fragment_index):
        log_duplicate_fragment(fragment_id, fragment_header.fragment_index)
        return SUCCESS  # Ignore duplicate
    
    # Get or create reassembly buffer
    reassembly_buffer = get_reassembly_buffer(fragment_id)
    if reassembly_buffer == null:
        reassembly_buffer = create_reassembly_buffer(
            fragment_id = fragment_id,
            total_fragments = fragment_header.total_fragments,
            timeout = get_current_time_ms() + FRAGMENT_TIMEOUT_MS
        )
    
    # Store fragment in reassembly buffer
    reassembly_buffer.fragments[fragment_header.fragment_index] = fragment_packet
    reassembly_buffer.received_count += 1
    
    # Update reassembly timeout
    reassembly_buffer.timeout = get_current_time_ms() + FRAGMENT_TIMEOUT_MS
    
    # Check if reassembly is complete
    if reassembly_buffer.received_count == fragment_header.total_fragments:
        return complete_fragment_reassembly(reassembly_buffer)
    
    return SUCCESS

function validate_fragment(fragment_packet, fragment_header):
    # Validate fragment index
    if fragment_header.fragment_index >= fragment_header.total_fragments:
        return false
    
    # Validate total fragments count
    if fragment_header.total_fragments == 0 or fragment_header.total_fragments > MAX_FRAGMENTS:
        return false
    
    # Validate fragment payload size
    if fragment_header.fragment_payload_size == 0 or fragment_header.fragment_payload_size > MAX_FRAGMENT_SIZE:
        return false
    
    # Additional security validation
    if not validate_fragment_security(fragment_packet, fragment_header):
        return false
    
    return true

function complete_fragment_reassembly(reassembly_buffer):
    # Validate all fragments are present
    for i in range(reassembly_buffer.total_fragments):
        if reassembly_buffer.fragments[i] == null:
            return ERROR_FRAGMENT_MISSING
    
    # Reassemble original packet
    reassembled_payload = b''
    for i in range(reassembly_buffer.total_fragments):
        fragment = reassembly_buffer.fragments[i]
        fragment_header = parse_fragment_header(fragment)
        fragment_payload = extract_fragment_payload(fragment, fragment_header)
        reassembled_payload += fragment_payload
    
    # Create reassembled packet
    original_packet = create_packet(
        type = determine_original_packet_type(reassembly_buffer),
        session_id = reassembly_buffer.fragments[0].session_id,
        sequence_number = reassembly_buffer.fragments[0].sequence_number,
        payload = reassembled_payload
    )
    
    # Validate reassembled packet
    if not validate_reassembled_packet(original_packet):
        cleanup_reassembly_buffer(reassembly_buffer)
        return ERROR_FRAGMENT_REASSEMBLY_INVALID
    
    # Cleanup reassembly buffer
    cleanup_reassembly_buffer(reassembly_buffer)
    
    # Process reassembled packet
    return process_packet(original_packet)
```

## Fragment Timeout and Cleanup

```pseudocode
function cleanup_expired_fragments():
    current_time = get_current_time_ms()
    expired_buffers = []
    
    for fragment_id, buffer in session_state.reassembly_buffers.items():
        if current_time > buffer.timeout:
            expired_buffers.append(fragment_id)
    
    for fragment_id in expired_buffers:
        buffer = session_state.reassembly_buffers[fragment_id]
        log_fragment_timeout(fragment_id, buffer.received_count, buffer.total_fragments)
        
        # Request retransmission if we have some fragments
        if buffer.received_count > 0:
            request_fragment_retransmission(fragment_id, buffer)
        
        cleanup_reassembly_buffer(buffer)
        del session_state.reassembly_buffers[fragment_id]

function request_fragment_retransmission(fragment_id, buffer):
    # Create bitmap of missing fragments
    missing_fragments = []
    for i in range(buffer.total_fragments):
        if buffer.fragments[i] == null:
            missing_fragments.append(i)
    
    # Send retransmission request
    retrans_request = create_fragment_retrans_request(
        fragment_id = fragment_id,
        missing_fragments = missing_fragments
    )
    
    send_packet(retrans_request)

function cleanup_reassembly_buffer(buffer):
    # Secure cleanup of fragment data
    for fragment in buffer.fragments:
        if fragment != null:
            secure_zero_packet_data(fragment)
    
    secure_zero_memory(buffer)
```

## Fragment Security Considerations

```pseudocode
function validate_fragment_security(fragment_packet, fragment_header):
    # Prevent fragment overlap attacks
    if detect_fragment_overlap(fragment_header):
        log_security_event("Fragment overlap attack detected")
        return false
    
    # Prevent fragment bomb attacks
    if fragment_header.total_fragments > MAX_FRAGMENTS:
        log_security_event("Fragment bomb attack detected")
        return false
    
    # Validate fragment ordering
    if not validate_fragment_ordering(fragment_header):
        log_security_event("Fragment ordering attack detected")
        return false
    
    return true

function detect_fragment_overlap(fragment_header):
    # Check if fragment overlaps with existing fragments in buffer
    reassembly_buffer = get_reassembly_buffer(fragment_header.fragment_id)
    if reassembly_buffer == null:
        return false
    
    # Fragment overlap detection logic
    existing_fragment = reassembly_buffer.fragments[fragment_header.fragment_index]
    if existing_fragment != null:
        # Same index already exists - potential overlap
        return true
    
    return false
```

## Fragment Error Handling

```pseudocode
function handle_fragment_error(error_details):
    # Handle fragment processing errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Request fragment retransmission
        request_fragment_retransmission(error_details)
    else:
        # Clean up fragment buffer
        cleanup_fragment_buffer()

function handle_fragment_reassembly_error(error_details):
    # Handle fragment reassembly failures
    cleanup_fragment_buffer()
    
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Request complete retransmission
        request_complete_retransmission()
    else:
        transition_to(ERROR)
```