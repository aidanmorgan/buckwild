# Connection Lifecycle and State Management

This document defines the complete connection lifecycle, state machine, and session management that governs protocol operations from connection establishment through termination.

## Overview

The connection lifecycle provides a deterministic framework for managing protocol sessions, ensuring proper sequencing of operations, resource allocation, and graceful error handling throughout the entire connection lifetime.

## Purpose and Rationale

The connection lifecycle serves essential protocol management functions:

- **Connection Lifecycle Management**: Defines clear phases from connection establishment to termination with proper resource management
- **Error Recovery Coordination**: Manages state transitions during various recovery scenarios with automatic fallback mechanisms
- **Security State Tracking**: Maintains cryptographic and authentication state throughout the session lifecycle
- **Resource Management**: Controls when resources are allocated, used, and cleaned up to prevent memory leaks
- **Concurrency Control**: Ensures thread-safe state transitions in multi-threaded implementations
- **Deterministic Behavior**: Prevents invalid state transitions and ensures operations occur in correct sequence

The state machine design maintains both security and reliability by enforcing proper protocol sequencing and providing comprehensive recovery mechanisms.

## Key Concepts

- **Connection States**: Discrete phases of connection lifecycle (CLOSED, CONNECTING, ESTABLISHED, etc.)
- **State Transitions**: Controlled changes between states triggered by events, timeouts, or conditions
- **Session Variables**: Persistent data that influences state behavior and tracks connection parameters
- **Event Handling**: Processing of packets, timeouts, and user actions that drive state changes
- **Recovery States**: Special states for handling various failure and recovery scenarios
- **Sub-States**: Fine-grained states within main states for specific recovery operations

## Session State Variables

### Core Session State Structure

```pseudocode
// Complete session state variables for connection management
session_state = {
    // Connection state
    'state': CLOSED,
    'sub_state': NORMAL,
    'session_id': 0,
    'session_key': None,
    'daily_key': None,
    
    // ECDH key exchange state
    'ecdh_keypair': None,
    'ecdh_shared_secret': None,
    'peer_public_key': None,
    'key_exchange_id': 0,
    
    // Sequence numbers
    'send_sequence': 0,
    'receive_sequence': 0,
    'send_unacked': 0,
    'send_next': 0,
    'receive_next': 0,
    'last_ack_sent': 0,
    'last_ack_received': 0,
    
    // Flow control
    'send_window': INITIAL_SEND_WINDOW,
    'receive_window': INITIAL_RECEIVE_WINDOW,
    'congestion_window': INITIAL_CONGESTION_WINDOW,
    'slow_start_threshold': SLOW_START_THRESHOLD,
    'congestion_state': SLOW_START,
    
    // Buffers
    'send_buffer': [],
    'receive_buffer': [],
    'reorder_buffer': [],
    'reassembly_buffers': {},
    
    // Timing and RTT
    'rtt_srtt': RTT_INITIAL_MS,
    'rtt_rttvar': RTT_INITIAL_MS / 2,
    'rtt_rto': RTT_INITIAL_MS,
    'last_ack_time': 0,
    'last_packet_time': 0,
    'connection_start_time': 0,
    
    // Port hopping
    'current_port': 0,
    'peer_port': 0,
    'port_history': [],
    'port_hop_seed': 0,
    'time_offset': 0,
    'next_hop_time': 0,
    
    // Discovery state
    'discovery_state': DISCOVERY_IDLE,
    'discovered_psk': None,
    'discovery_id': 0,
    'psi_session_salt': 0,
    'bloom_filter': None,
    
    // Recovery state
    'recovery_attempts': 0,
    'recovery_state': RECOVERY_IDLE,
    'last_recovery_time': 0,
    'recovery_sequence': 0,
    
    // Error tracking
    'retry_count': 0,
    'last_error': None,
    'consecutive_failures': 0,
    'last_heartbeat_time': 0,
    
    // Fragmentation
    'fragment_id_counter': 0,
    'pending_fragments': {},
    'fragment_timeouts': {},
    
    // Timeouts
    'connection_timeout': CONNECTION_TIMEOUT_MS,
    'heartbeat_timeout': HEARTBEAT_TIMEOUT_MS,
    'fragment_timeout': FRAGMENT_TIMEOUT_MS
}
```

## Connection States

### Primary Connection States

```pseudocode
// Primary connection states
CONNECTION_STATE_CLOSED = 0        // No session exists, resources cleaned up
CONNECTION_STATE_CONNECTING = 1    // Client attempting connection (includes discovery)
CONNECTION_STATE_LISTENING = 2     // Server waiting for connection requests
CONNECTION_STATE_ESTABLISHED = 3   // Connection active, data flowing normally
CONNECTION_STATE_CLOSING = 4       // Connection termination in progress
CONNECTION_STATE_RECOVERING = 5    // Connection recovery operations in progress
CONNECTION_STATE_ERROR = 6         // Error state, connection should be terminated

// Recovery sub-states (used within ESTABLISHED and RECOVERING states)
RECOVERY_SUB_STATE_NORMAL = 0      // Normal operation, no recovery needed
RECOVERY_SUB_STATE_RESYNC = 1      // Time synchronization recovery
RECOVERY_SUB_STATE_REKEY = 2       // Session key rotation/recovery
RECOVERY_SUB_STATE_REPAIR = 3      // Connection repair (sequence number recovery)
RECOVERY_SUB_STATE_EMERGENCY = 4   // Emergency recovery mode

// Discovery sub-states (used within CONNECTING state)
DISCOVERY_SUB_STATE_IDLE = 0       // No discovery in progress
DISCOVERY_SUB_STATE_REQUEST = 1    // PSK discovery request sent
DISCOVERY_SUB_STATE_RESPONSE = 2   // PSK discovery response received
DISCOVERY_SUB_STATE_CONFIRM = 3    // PSK discovery confirmation sent
DISCOVERY_SUB_STATE_COMPLETED = 4  // PSK discovery completed successfully
DISCOVERY_SUB_STATE_FAILED = 5     // PSK discovery failed
```

## State Transitions

### Core State Transition Rules

```pseudocode
// Primary state transitions with integrated recovery
function process_state_transition(current_state, event, packet_data):
    switch current_state:
        case CONNECTION_STATE_CLOSED:
            if event == EVENT_CONNECT_REQUEST:
                return transition_to_connecting()
            elif event == EVENT_BIND_LISTEN:
                return transition_to_listening()
            elif event == EVENT_PACKET_RECEIVED and packet_data.type == PACKET_TYPE_SYN:
                return transition_to_connecting_passive(packet_data)
            else:
                return ERROR_INVALID_TRANSITION
                
        case CONNECTION_STATE_CONNECTING:
            if event == EVENT_CONNECTION_ESTABLISHED:
                return transition_to_established()
            elif event == EVENT_CONNECTION_FAILED:
                return transition_to_closed_with_cleanup()
            elif event == EVENT_RECOVERY_NEEDED:
                return transition_to_recovering()
            elif event == EVENT_TIMEOUT:
                return handle_connecting_timeout()
            else:
                return ERROR_INVALID_TRANSITION
                
        case CONNECTION_STATE_LISTENING:
            if event == EVENT_CONNECTION_ESTABLISHED:
                return transition_to_established()
            elif event == EVENT_LISTEN_TIMEOUT:
                return transition_to_closed_with_cleanup()
            elif event == EVENT_PACKET_RECEIVED and packet_data.type == PACKET_TYPE_SYN:
                return handle_syn_in_listening_state(packet_data)
            else:
                return ERROR_INVALID_TRANSITION
                
        case CONNECTION_STATE_ESTABLISHED:
            if event == EVENT_CLOSE_REQUESTED:
                return transition_to_closing()
            elif event == EVENT_RECOVERY_TRIGGERED:
                return transition_to_recovering()
            elif event == EVENT_CRITICAL_ERROR:
                return transition_to_error_state()
            elif event == EVENT_PACKET_RECEIVED:
                return handle_packet_in_established_state(packet_data)
            else:
                return process_established_state_event(event, packet_data)
                
        case CONNECTION_STATE_CLOSING:
            if event == EVENT_CLOSE_COMPLETED:
                return transition_to_closed_with_cleanup()
            elif event == EVENT_CLOSE_RECOVERY_NEEDED:
                return transition_to_recovering()
            elif event == EVENT_TIMEOUT:
                return force_close_connection()
            else:
                return ERROR_INVALID_TRANSITION
                
        case CONNECTION_STATE_RECOVERING:
            if event == EVENT_RECOVERY_SUCCESS:
                return transition_to_established()
            elif event == EVENT_RECOVERY_FAILED:
                return transition_to_closed_with_cleanup()
            elif event == EVENT_RECOVERY_CRITICAL_FAILURE:
                return transition_to_error_state()
            else:
                return process_recovery_state_event(event, packet_data)
                
        case CONNECTION_STATE_ERROR:
            if event == EVENT_CLEANUP_REQUESTED:
                return transition_to_closed_with_cleanup()
            else:
                return force_close_connection()
    
    return ERROR_INVALID_TRANSITION
```

### Recovery Sub-State Transitions

```pseudocode
// Recovery sub-state transitions (within ESTABLISHED or RECOVERING states)
function process_recovery_sub_state_transition(current_sub_state, event, data):
    switch current_sub_state:
        case RECOVERY_SUB_STATE_NORMAL:
            if event == EVENT_TIME_DRIFT_DETECTED:
                return transition_to_resync_recovery()
            elif event == EVENT_KEY_ROTATION_NEEDED:
                return transition_to_rekey_recovery()
            elif event == EVENT_SEQUENCE_MISMATCH:
                return transition_to_repair_recovery()
            elif event == EVENT_CRITICAL_FAILURE:
                return transition_to_emergency_recovery()
            else:
                return RECOVERY_SUB_STATE_NORMAL
                
        case RECOVERY_SUB_STATE_RESYNC:
            if event == EVENT_TIME_SYNC_COMPLETED:
                return transition_to_normal_operation()
            elif event == EVENT_TIME_SYNC_FAILED:
                return transition_to_emergency_recovery()
            else:
                return RECOVERY_SUB_STATE_RESYNC
                
        case RECOVERY_SUB_STATE_REKEY:
            if event == EVENT_KEY_ROTATION_COMPLETED:
                return transition_to_normal_operation()
            elif event == EVENT_KEY_ROTATION_FAILED:
                return transition_to_emergency_recovery()
            else:
                return RECOVERY_SUB_STATE_REKEY
                
        case RECOVERY_SUB_STATE_REPAIR:
            if event == EVENT_SEQUENCE_REPAIR_COMPLETED:
                return transition_to_normal_operation()
            elif event == EVENT_SEQUENCE_REPAIR_FAILED:
                return transition_to_emergency_recovery()
            else:
                return RECOVERY_SUB_STATE_REPAIR
                
        case RECOVERY_SUB_STATE_EMERGENCY:
            if event == EVENT_EMERGENCY_RECOVERY_COMPLETED:
                return transition_to_normal_operation()
            elif event == EVENT_EMERGENCY_RECOVERY_FAILED:
                return RECOVERY_SUB_STATE_EMERGENCY  # Stay in emergency mode
            else:
                return RECOVERY_SUB_STATE_EMERGENCY
    
    return current_sub_state
```

## Connection Establishment

### Multi-Port SYN/ACK Process

The session initialization process is designed to handle connection establishment across multiple ports within the adaptive delay window, ensuring reliable connection establishment even with network timing variations.

**Key Design Principles:**

1. **Base Port Algorithm for Initial Connection**: The SYN/ACK handshake always uses the base port hopping algorithm (shared by all connections) rather than per-session port offsets, ensuring both peers can predictably locate each other for connection establishment.

2. **Adaptive Multi-Port Listening**: Both SYN and SYN-ACK packets may be transmitted and received across multiple ports within the current adaptive delay window, accommodating network timing variations and ensuring connection reliability.

3. **Per-Session Port Seed Generation**: Once the ECDH key exchange is complete, the shared secret is used to derive a unique per-session port hopping seed (via PBKDF2 chunks 22-23) that provides cryptographically secure randomness for subsequent port hopping during the session.

4. **Transition to Session-Specific Hopping**: After connection establishment completes, all subsequent communication uses the per-session derived port parameters, providing unique port sequences for each connection to prevent collisions.

### Client-Side Connection Establishment

```pseudocode
function establish_client_connection(remote_endpoint, local_psk_fingerprints):
    # Initialize session state
    session_state.state = CONNECTION_STATE_CONNECTING
    session_state.sub_state = RECOVERY_SUB_STATE_NORMAL
    session_state.connection_start_time = get_current_time()
    
    # Phase 1: PSK discovery (if multiple PSKs available)
    if len(local_psk_fingerprints) > 1:
        session_state.discovery_state = DISCOVERY_SUB_STATE_REQUEST
        discovered_psk = perform_psi_discovery(remote_endpoint, local_psk_fingerprints)
        if discovered_psk == null:
            return transition_to_error_state(ERROR_PSK_NOT_FOUND)
        session_state.discovered_psk = discovered_psk
        session_state.discovery_state = DISCOVERY_SUB_STATE_COMPLETED
    else:
        session_state.discovered_psk = local_psk_fingerprints[0]
    
    # Phase 2: ECDH key exchange
    ecdh_result = perform_ecdh_key_exchange(remote_endpoint, session_state.discovered_psk)
    if ecdh_result == null:
        return transition_to_error_state(ERROR_ECDH_KEY_EXCHANGE_FAILED)
    
    # Phase 3: Initialize session parameters from ECDH shared secret
    # This generates the per-session random seed for port hopping from PBKDF2 derivation
    session_parameters = derive_session_keys_from_dh(
        ecdh_result.shared_secret,
        ecdh_result.client_public_key,
        ecdh_result.server_public_key,
        ecdh_result.key_exchange_id
    )
    
    # Update session state with derived parameters
    session_state.session_id = generate_new_session_id()
    session_state.session_key = session_parameters.session_key
    session_state.send_sequence = session_parameters.client_sequence
    session_state.receive_sequence = session_parameters.server_sequence
    # CRITICAL: This port_hop_seed provides the cryptographic randomness for per-hop port calculation
    # It is a 32-bit seed derived from PBKDF2(ECDH_shared_secret) chunks 22-23
    session_state.port_hop_seed = session_parameters.port_hop_seed
    session_state.time_offset = session_parameters.time_sync_offset
    
    # Phase 4: Complete three-way handshake
    if send_final_ack():
        return transition_to_established()
    else:
        return transition_to_error_state(ERROR_CONNECTION_FAILED)

function perform_ecdh_key_exchange(remote_endpoint, psk):
    # Generate ephemeral ECDH key pair
    client_keypair = generate_ecdh_keypair()
    session_state.ecdh_keypair = client_keypair
    session_state.key_exchange_id = generate_secure_random_16bit()
    
    # Send SYN with ECDH public key and PSK authentication
    # NOTE: Initial connection establishment MUST use base port hopping algorithm
    # (no per-session offset) to ensure predictable connection establishment
    psk_auth = HMAC_SHA256_128(psk, client_keypair.public || b"ecdh_syn_auth_v1")
    syn_packet = create_syn_packet(
        client_public_key = client_keypair.public,
        psk_authentication = psk_auth,
        key_exchange_id = session_state.key_exchange_id,
        initial_congestion_window = INITIAL_CONGESTION_WINDOW,
        initial_receive_window = INITIAL_RECEIVE_WINDOW,
        time_offset = calculate_time_offset()
    )
    
    # Send SYN packet using base port algorithm (no session-specific offset yet)
    # The SYN/ACK handshake may occur across multiple ports within the adaptive delay window
    if not send_syn_packet_using_base_ports(syn_packet, remote_endpoint):
        return null
    
    # Receive SYN-ACK with server's ECDH public key
    # Listen across adaptive delay window using base port algorithm
    syn_ack = receive_syn_ack_across_base_ports(CONNECTION_TIMEOUT_MS)
    if syn_ack == null or syn_ack.type != PACKET_TYPE_SYN_ACK:
        return null
    
    # Verify key exchange ID
    if syn_ack.key_exchange_id != session_state.key_exchange_id:
        return null
    
    # Perform ECDH computation
    shared_secret = perform_ecdh(client_keypair.private, syn_ack.server_public_key)
    if shared_secret == ERROR_INVALID_PUBLIC_KEY:
        return null
    
    # Verify shared secret hash
    if not verify_ecdh_shared_secret_hash(shared_secret, syn_ack.shared_secret_hash):
        return null
    
    # Store peer's public key and clear our private key for forward secrecy
    session_state.peer_public_key = syn_ack.server_public_key
    secure_zero_memory(client_keypair.private)
    
    return {
        'shared_secret': shared_secret,
        'client_public_key': client_keypair.public,
        'server_public_key': syn_ack.server_public_key,
        'key_exchange_id': session_state.key_exchange_id
    }

function send_syn_packet_using_base_ports(syn_packet, remote_endpoint):
    # Send SYN packet using base port hopping algorithm across adaptive delay window
    # This ensures the initial connection can be established without prior session context
    
    # Get current base ports for adaptive delay window
    current_time_window = get_synchronized_time_window()
    delay_window = get_effective_delay_window()  # From adaptive networking
    
    # Calculate all possible ports for connection establishment
    base_ports = []
    for window_offset in range(-delay_window//2, delay_window//2 + 1):
        window = current_time_window + window_offset
        base_port = calculate_base_port_for_time_window(window)
        base_ports.append(base_port)
    
    # Remove duplicates while preserving order
    unique_base_ports = list(dict.fromkeys(base_ports))
    
    # Send SYN to all possible base ports for connection establishment
    syn_sent = false
    for port in unique_base_ports:
        syn_packet.destination_port = port
        if send_packet_to_port(syn_packet, remote_endpoint, port):
            syn_sent = true
            log_syn_sent_to_base_port(port, current_time_window)
    
    return syn_sent

function receive_syn_ack_across_base_ports(timeout_ms):
    # Listen for SYN-ACK across all base ports in adaptive delay window
    
    start_time = get_current_time_ms()
    
    while (get_current_time_ms() - start_time) < timeout_ms:
        # Update current base ports (as time windows change)
        current_time_window = get_synchronized_time_window()
        delay_window = get_effective_delay_window()
        
        # Calculate current listening ports
        listening_ports = []
        for window_offset in range(-delay_window//2, delay_window//2 + 1):
            window = current_time_window + window_offset
            base_port = calculate_base_port_for_time_window(window)
            listening_ports.append(base_port)
        
        # Listen on all current base ports
        for port in listening_ports:
            packet = receive_packet_from_port_nonblocking(port)
            if packet != null and packet.type == PACKET_TYPE_SYN_ACK:
                log_syn_ack_received_on_base_port(port, current_time_window)
                return packet
        
        # Brief sleep to prevent busy waiting
        sleep_ms(10)
    
    return null  # Timeout
```

### Server-Side Connection Handling

```pseudocode
function handle_server_connection_request(syn_packet):
    # NOTE: Server receives SYN packets on base ports (no session-specific offset)
    # SYN packets may arrive on any port within the adaptive delay window using base port algorithm
    
    # Validate SYN packet
    if not validate_syn_packet(syn_packet):
        return send_error(ERROR_INVALID_PACKET)
    
    # Initialize session state for incoming connection
    session_state.state = CONNECTION_STATE_CONNECTING
    session_state.sub_state = RECOVERY_SUB_STATE_NORMAL
    session_state.connection_start_time = get_current_time()
    
    # Verify PSK authentication
    discovered_psk = verify_psk_authentication(syn_packet.psk_authentication, syn_packet.client_public_key)
    if discovered_psk == null:
        return send_error(ERROR_AUTHENTICATION_FAILED)
    session_state.discovered_psk = discovered_psk
    
    # Generate server ECDH key pair
    server_keypair = generate_ecdh_keypair()
    session_state.ecdh_keypair = server_keypair
    session_state.key_exchange_id = syn_packet.key_exchange_id
    
    # Perform ECDH computation
    shared_secret = perform_ecdh(server_keypair.private, syn_packet.client_public_key)
    if shared_secret == ERROR_INVALID_PUBLIC_KEY:
        return send_error(ERROR_INVALID_CLIENT_KEY)
    
    # Derive session parameters from ECDH shared secret
    # This generates the per-session random seed for port hopping from PBKDF2 derivation
    session_parameters = derive_session_keys_from_dh(
        shared_secret,
        syn_packet.client_public_key,
        server_keypair.public,
        syn_packet.key_exchange_id
    )
    
    # Update session state
    session_state.session_id = generate_new_session_id()
    session_state.session_key = session_parameters.session_key
    session_state.send_sequence = session_parameters.server_sequence
    session_state.receive_sequence = session_parameters.client_sequence
    session_state.peer_public_key = syn_packet.client_public_key
    
    # Send SYN-ACK with server's ECDH public key and verification
    secret_hash = create_ecdh_verification_hash(shared_secret)
    syn_ack = create_syn_ack_packet(
        server_public_key = server_keypair.public,
        shared_secret_hash = secret_hash,
        key_exchange_id = syn_packet.key_exchange_id,
        initial_congestion_window = INITIAL_CONGESTION_WINDOW,
        initial_receive_window = INITIAL_RECEIVE_WINDOW,
        time_offset = calculate_time_offset()
    )
    
    if not send_packet(syn_ack):
        return ERROR_CONNECTION_FAILED
    
    # Clear server private key for forward secrecy
    secure_zero_memory(server_keypair.private)
    
    # Wait for final ACK
    ack_packet = receive_packet_timeout(CONNECTION_TIMEOUT_MS)
    if ack_packet != null and ack_packet.type == PACKET_TYPE_ACK:
        return transition_to_established()
    else:
        return transition_to_error_state(ERROR_CONNECTION_TIMEOUT)
```

## Connection Termination

### Graceful Connection Termination

```pseudocode
function initiate_graceful_close():
    # Transition to closing state
    session_state.state = CONNECTION_STATE_CLOSING
    session_state.last_ack_sent = session_state.send_sequence
    
    # Send FIN packet
    fin_packet = create_fin_packet(
        final_sequence_number = session_state.send_sequence
    )
    
    if send_packet(fin_packet):
        session_state.send_sequence = increment_sequence_number(session_state.send_sequence)
        return wait_for_close_completion()
    else:
        return force_close_connection()

function handle_fin_packet(fin_packet):
    # Acknowledge the FIN
    ack_packet = create_ack_packet(
        acknowledgment_number = fin_packet.final_sequence_number + 1
    )
    send_packet(ack_packet)
    
    # Send our own FIN
    our_fin = create_fin_packet(
        final_sequence_number = session_state.send_sequence
    )
    send_packet(our_fin)
    
    # Transition to closing state
    session_state.state = CONNECTION_STATE_CLOSING
    
    # Wait for final ACK or timeout
    return wait_for_close_completion()

function wait_for_close_completion():
    # Wait for final ACK or timeout
    final_ack = receive_packet_timeout(TIME_WAIT_TIMEOUT_MS)
    
    if final_ack != null and final_ack.type == PACKET_TYPE_ACK:
        return transition_to_closed_with_cleanup()
    else:
        # Timeout - force close
        return force_close_connection()

function force_close_connection():
    # Send RST packet
    rst_packet = create_rst_packet(
        reset_reason = RESET_REASON_FORCED_CLOSE
    )
    send_packet(rst_packet)
    
    return transition_to_closed_with_cleanup()
```

## Invalid State Handling

### Packet Processing in Invalid States

```pseudocode
function handle_packet_in_invalid_state(packet, current_state):
    switch current_state:
        case CONNECTION_STATE_CLOSED:
            if packet.type == PACKET_TYPE_SYN:
                # Passive open - handle incoming connection
                return handle_server_connection_request(packet)
            else:
                # Send RST for any other packet type
                send_rst_packet(packet.session_id, RESET_REASON_CONNECTION_CLOSED)
                return ERROR_STATE_INVALID
                
        case CONNECTION_STATE_LISTENING:
            if packet.type == PACKET_TYPE_SYN:
                return handle_server_connection_request(packet)
            else:
                send_rst_packet(packet.session_id, RESET_REASON_NOT_LISTENING)
                return ERROR_STATE_INVALID
                
        case CONNECTION_STATE_CONNECTING:
            if packet.type == PACKET_TYPE_SYN:
                # Simultaneous open scenario
                return handle_simultaneous_open(packet)
            elif packet.type == PACKET_TYPE_SYN_ACK:
                return continue_client_handshake(packet)
            elif packet.type == PACKET_TYPE_RST:
                return handle_connection_reset(packet)
            else:
                send_rst_packet(packet.session_id, RESET_REASON_INVALID_STATE)
                return ERROR_STATE_INVALID
                
        case CONNECTION_STATE_ESTABLISHED:
            # All packet types are potentially valid in established state
            return process_established_packet(packet)
                
        case CONNECTION_STATE_CLOSING:
            if packet.type == PACKET_TYPE_FIN:
                return handle_fin_in_closing_state(packet)
            elif packet.type == PACKET_TYPE_ACK:
                return handle_ack_in_closing_state(packet)
            elif packet.type == PACKET_TYPE_RST:
                return handle_connection_reset(packet)
            else:
                # Ignore other packet types during closing
                return SUCCESS
                
        case CONNECTION_STATE_RECOVERING:
            # Recovery state can handle most packet types for recovery purposes
            return process_recovery_packet(packet)
            
        case CONNECTION_STATE_ERROR:
            # Send RST and ignore all packets in error state
            send_rst_packet(packet.session_id, RESET_REASON_ERROR_STATE)
            return ERROR_STATE_INVALID
    
    return ERROR_STATE_INVALID
```

## Resource Management

### Session Cleanup and Resource Deallocation

```pseudocode
function transition_to_closed_with_cleanup():
    # Clean up all session resources
    cleanup_session_buffers()
    cleanup_cryptographic_state()
    cleanup_timers_and_timeouts()
    cleanup_recovery_state()
    
    # Reset session state to initial values
    reset_session_state()
    
    # Transition to closed state
    session_state.state = CONNECTION_STATE_CLOSED
    session_state.sub_state = RECOVERY_SUB_STATE_NORMAL
    
    return SUCCESS

function cleanup_session_buffers():
    # Clear all buffers and free memory
    session_state.send_buffer.clear()
    session_state.receive_buffer.clear()
    session_state.reorder_buffer.clear()
    session_state.reassembly_buffers.clear()
    session_state.port_history.clear()

function cleanup_cryptographic_state():
    # Securely clear all cryptographic material
    if session_state.session_key:
        secure_zero_memory(session_state.session_key)
    if session_state.daily_key:
        secure_zero_memory(session_state.daily_key)
    if session_state.ecdh_shared_secret:
        secure_zero_memory(session_state.ecdh_shared_secret)
    if session_state.discovered_psk:
        secure_zero_memory(session_state.discovered_psk)
    
    # Clear key material references
    session_state.session_key = None
    session_state.daily_key = None
    session_state.ecdh_shared_secret = None
    session_state.discovered_psk = None
    session_state.ecdh_keypair = None
    session_state.peer_public_key = None

function cleanup_timers_and_timeouts():
    # Cancel all active timers
    cancel_heartbeat_timer()
    cancel_fragment_timers()
    cancel_recovery_timers()
    cancel_connection_timeout()

function cleanup_recovery_state():
    # Reset recovery state
    session_state.recovery_attempts = 0
    session_state.recovery_state = RECOVERY_IDLE
    session_state.last_recovery_time = 0
    session_state.recovery_sequence = 0

function reset_session_state():
    # Reset all session variables to initial state
    session_state.session_id = 0
    session_state.send_sequence = 0
    session_state.receive_sequence = 0
    session_state.send_unacked = 0
    session_state.send_next = 0
    session_state.receive_next = 0
    session_state.current_port = 0
    session_state.peer_port = 0
    session_state.retry_count = 0
    session_state.last_error = None
    session_state.consecutive_failures = 0
    
    # Reset flow control
    session_state.send_window = INITIAL_SEND_WINDOW
    session_state.receive_window = INITIAL_RECEIVE_WINDOW
    session_state.congestion_window = INITIAL_CONGESTION_WINDOW
    session_state.slow_start_threshold = SLOW_START_THRESHOLD
    session_state.congestion_state = SLOW_START
    
    # Reset RTT measurements
    session_state.rtt_srtt = RTT_INITIAL_MS
    session_state.rtt_rttvar = RTT_INITIAL_MS / 2
    session_state.rtt_rto = RTT_INITIAL_MS
```

## State Machine Integration

The connection lifecycle integrates with all other protocol components:

1. **Cryptographic Operations**: ECDH key exchange and parameter derivation during connection establishment
2. **PSK Discovery**: Privacy-preserving set intersection during connection setup
3. **Flow Control**: Window management throughout the established state
4. **Recovery Mechanisms**: Multi-layer recovery within the recovery state and sub-states
5. **Port Hopping**: Synchronized port transitions during established state
6. **Time Synchronization**: Coordinated time management across all states
7. **Fragmentation**: Packet reassembly buffer management during established state
