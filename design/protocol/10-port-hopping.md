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

- **Time Windows**: Fixed 500ms intervals that synchronize port changes across all peers
- **PBKDF2-Based Port Derivation**: Port offsets derived from ECDH shared secret using PBKDF2 key derivation
- **Session-Specific Sequences**: Each session uses unique port sequences derived from ephemeral DH key exchange
- **16-bit Chunk Derivation**: Port parameters extracted from PBKDF2 output as 16-bit chunks per specification
- **Clock Synchronization**: Precise time alignment ensures all peers hop to the same ports simultaneously
- **Connection Offset**: Mechanisms to prevent port collisions between multiple parallel connections

## Port Calculation Specification

### Time Window Calculation
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
```

### Connection Offset Derivation for Multiple Parallel Connections

```pseudocode
function derive_connection_offset_from_ecdh(shared_secret, client_pubkey, server_pubkey, session_id):
    # Derive unique port offset for this connection from ECDH shared secret
    # Uses PBKDF2 to extract port parameters as 16-bit chunks
    
    # Create session-specific salt combining public keys and session ID
    salt = SHA256(client_pubkey || server_pubkey || session_id.to_bytes(8, 'big') || b"port_offset_v2")
    
    # Use PBKDF2 to derive port material from ECDH shared secret
    port_material = PBKDF2_HMAC_SHA256(
        password = shared_secret,
        salt = salt,
        iterations = PBKDF2_ITERATIONS_PORT,
        key_length = 12     # 96 bits = 6 chunks of 16 bits each
    )
    
    # Extract as 16-bit chunks as per specification
    chunks = []
    for i in range(0, 12, 2):  # 6 chunks total
        chunk = bytes_to_uint16(port_material[i:i+2])
        chunks.append(chunk)
    
    # Derive port parameters from chunks
    base_offset = chunks[0] % PORT_RANGE         # Primary port offset (16-bit)
    hop_interval = 500 + (chunks[1] % 500)       # 500-1000ms interval variance
    sequence_seed = chunks[2] << 16 | chunks[3]  # 32-bit sequence seed from chunks 2-3
    collision_offset = chunks[4] % 1024          # Secondary collision avoidance
    time_variance = chunks[5] % 100              # Up to 100ms time variance
    
    return {
        'base_offset': base_offset,
        'hop_interval': hop_interval,
        'sequence_seed': sequence_seed,
        'collision_offset': collision_offset,
        'time_variance': time_variance
    }

function calculate_dynamic_hop_interval(session_keys, time_window):
    # Calculate dynamic hop interval using ECDH-derived parameters
    base_interval = HOP_INTERVAL_MS  # Standard 500ms
    variance = session_keys.time_sync_offset % 200  # Up to 200ms variance
    seed_factor = (session_keys.hop_sequence_seed >> 16) % 100  # 0-99ms additional variance
    
    # Vary interval based on derived parameters to make timing less predictable
    dynamic_interval = base_interval + variance + seed_factor
    
    # Ensure interval stays within reasonable bounds
    return max(200, min(dynamic_interval, 1000))  # 200ms to 1000ms range
```

### Optimized Port Calculation Algorithm

```pseudocode
function calculate_port_with_connection_offset(connection_offset, time_window):
    # OPTIMIZED: Simple arithmetic using pre-calculated offset from ECDH derivation
    # This eliminates expensive cryptographic operations on every hop
    
    # Calculate base port for this time window (shared algorithm, no per-connection crypto)
    base_port = calculate_base_port_for_time_window(time_window)
    
    # Apply connection-specific offset (derived once from ECDH during connection setup)
    port_range = MAX_PORT - MIN_PORT + 1
    final_port = MIN_PORT + ((base_port - MIN_PORT + connection_offset) % port_range)
    
    return final_port

function calculate_base_port_for_time_window(time_window):
    # Calculate the base port for any given time window
    # This algorithm is shared across all connections and doesn't require session keys
    
    # Use a simple but unpredictable function based on time window
    # This provides port hopping behavior without per-connection crypto overhead
    
    # Simple hash-based calculation for base port sequence
    time_bytes = time_window.to_bytes(8, 'big')
    hash_result = SHA256(time_bytes || b"base_port_v1")
    
    # Extract port value from hash
    port_value = bytes_to_uint32(hash_result[0:4])
    port_range = MAX_PORT - MIN_PORT + 1
    base_port = MIN_PORT + (port_value % port_range)
    
    return base_port

function get_current_session_port(connection_offset):
    # OPTIMIZED: Get the current port using pre-calculated connection offset
    current_time = get_current_time_ms()
    current_time_window = calculate_time_window(current_time)
    
    return calculate_port_with_connection_offset(connection_offset, current_time_window)

function get_next_session_port(connection_offset):
    # OPTIMIZED: Get the next port using pre-calculated connection offset
    current_time = get_current_time_ms()
    next_time = current_time + HOP_INTERVAL_MS  # Use standard interval
    next_time_window = calculate_time_window(next_time)
    
    return calculate_port_with_connection_offset(connection_offset, next_time_window)
```

## Adaptive Transmission Delay Handling

The port hopping mechanism integrates with the adaptive delay system to provide optimal balance between security and reliability. For complete implementation details of the adaptive delay algorithms, measurements, and negotiation protocols, see **13-delay-tuning.md**.

```pseudocode
function get_current_port_with_adaptive_delay_allowance(connection_offset):
    # Uses delay window determined by adaptive delay tuning (see 13-delay-tuning.md)
    
    # Get current effective delay window from adaptive delay system (see 13-delay-tuning.md)
    effective_delay_window = get_effective_delay_window()
    
    # Calculate ports for the delay window using optimized approach
    return calculate_ports_for_delay_window(connection_offset, effective_delay_window)

function calculate_ports_for_delay_window(connection_offset, delay_window):
    current_time = get_current_time_ms()
    current_time_window = calculate_time_window(current_time)
    
    ports = []
    
    # Calculate symmetric window around current time
    half_window = delay_window // 2
    start_offset = -half_window
    end_offset = half_window + (delay_window % 2)  # Handle odd window sizes
    
    for offset in range(start_offset, end_offset + 1):
        time_window = current_time_window + offset
        port = calculate_port_with_connection_offset(connection_offset, time_window)
        ports.append(port)
    
    return ports
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