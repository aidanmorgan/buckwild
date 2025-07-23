# Sequence Number Derivation Specification

## Overview

This document defines the sequence number derivation mechanisms that establish secure, unpredictable initial sequence numbers for new connections. Sequence numbers are cryptographically derived from ephemeral Diffie-Hellman shared secrets using PBKDF2, ensuring both peers compute identical starting values without explicit negotiation.

## Purpose and Rationale

Sequence number derivation serves critical security and reliability functions:

- **Attack Prevention**: Prevents sequence number prediction attacks through cryptographic derivation from ephemeral secrets
- **Deterministic Agreement**: Both peers derive identical sequence numbers from shared ECDH secret without negotiation
- **Replay Protection**: Ephemeral key exchange ensures unique sequences for each connection session
- **Forward Secrecy**: Sequence numbers cannot be recovered even if long-term keys are compromised
- **Cryptographic Security**: Uses ECDH + PBKDF2 for provable security with perfect forward secrecy

The ECDH-based approach eliminates the need for interactive sequence negotiation while providing stronger security guarantees through ephemeral key exchange.

## Key Concepts

- **ECDH Key Exchange**: Ephemeral Diffie-Hellman key exchange provides shared secret for derivation
- **PBKDF2 Derivation**: Password-Based Key Derivation Function 2 extracts sequence numbers from shared secret
- **16-bit Chunking**: PBKDF2 output is processed as 16-bit chunks per specification requirements
- **Deterministic Generation**: Both peers derive identical sequences without interaction
- **Forward Secrecy**: Ephemeral keys provide perfect forward secrecy for sequence numbers
- **Wraparound Handling**: Mechanisms to handle sequence number overflow and wraparound scenarios

## Sequence Number Management

### Sequence Number Wraparound Handling
```pseudocode
function is_sequence_valid(sequence_number, expected_sequence):
    # Handle sequence number wraparound
    if expected_sequence > SEQUENCE_WRAP_THRESHOLD and sequence_number < SEQUENCE_WRAP_THRESHOLD:
        # Wraparound occurred
        return sequence_number >= 0 and sequence_number < (expected_sequence - SEQUENCE_WRAP_THRESHOLD)
    elif expected_sequence < SEQUENCE_WRAP_THRESHOLD and sequence_number > SEQUENCE_WRAP_THRESHOLD:
        # Wraparound occurred in reverse
        return sequence_number >= (expected_sequence + SEQUENCE_WRAP_THRESHOLD)
    else:
        # Normal case
        return sequence_number >= expected_sequence and sequence_number < (expected_sequence + SEQUENCE_WRAP_THRESHOLD)

function increment_sequence_number(sequence_number):
    if sequence_number == MAX_SEQUENCE_NUMBER:
        return 0
    else:
        return sequence_number + 1

function sequence_difference(seq1, seq2):
    # Calculate the difference between two sequence numbers, handling wraparound
    if seq1 >= seq2:
        return seq1 - seq2
    else:
        return (MAX_SEQUENCE_NUMBER - seq2 + 1) + seq1
```

## ECDH-Based Sequence Number Derivation

The protocol derives initial sequence numbers deterministically from ephemeral Diffie-Hellman shared secrets using PBKDF2, eliminating the need for interactive negotiation while providing stronger security guarantees through perfect forward secrecy.

### ECDH Sequence Derivation Protocol

Sequence numbers are derived as part of the ECDH connection establishment process:

1. **ECDH Key Exchange**: Peers perform ephemeral P-256 Diffie-Hellman key exchange during SYN/SYN-ACK
2. **Shared Secret Computation**: Both peers compute identical ECDH shared secret from exchanged public keys
3. **PBKDF2 Derivation**: Shared secret used as password for PBKDF2 to generate master key material (128 bytes)
4. **16-bit Chunking**: Master key material processed as 16-bit chunks per specification
5. **Parameter Assignment**: Sequence numbers extracted from specific chunks with deterministic mapping

## ECDH Sequence Derivation Implementation

```pseudocode
# ECDH-based parameter derivation (performed during SYN/SYN-ACK handshake)
function derive_session_parameters_from_ecdh(ecdh_shared_secret, client_pubkey, server_pubkey, session_context):
    # All session parameters derived from ECDH shared secret using PBKDF2
    # This happens automatically during connection establishment
    
    # Create salt from public keys and session context for key diversity
    salt = SHA256(client_pubkey || server_pubkey || session_context || b"ecdh_derivation_v1")
    
    # Derive master key material using PBKDF2 (4096 iterations for security)
    master_key_material = PBKDF2_HMAC_SHA256(
        password = ecdh_shared_secret,
        salt = salt,
        iterations = PBKDF2_ITERATIONS_SESSION,
        key_length = 128  # 1024 bits of key material
    )
    
    # Break master key material into 16-bit chunks as specified
    chunks = []
    for i in range(0, len(master_key_material), 2):
        chunk = bytes_to_uint16(master_key_material[i:i+2])
        chunks.append(chunk)
    
    # Derive specific session parameters from chunks (deterministic)
    session_parameters = {
        'client_sequence': (chunks[0] << 16 | chunks[1]) % MAX_SEQUENCE_NUMBER,  # 32-bit from chunks 0-1
        'server_sequence': (chunks[2] << 16 | chunks[3]) % MAX_SEQUENCE_NUMBER,  # 32-bit from chunks 2-3
        'client_port_offset': chunks[4] % PORT_RANGE,                           # 16-bit port offset
        'server_port_offset': chunks[5] % PORT_RANGE,                           # 16-bit port offset
        'session_key': master_key_material[12:44],                              # 32 bytes for HMAC keys
        'port_hop_seed': chunks[22] << 16 | chunks[23],                         # 32-bit hopping seed
        'time_sync_offset': chunks[24] % 1000,                                  # 16-bit time adjustment
        'congestion_seed': chunks[25] % 65536                                   # 16-bit congestion seed
    }
    
    # Clear shared secret from memory for forward secrecy
    secure_zero_memory(ecdh_shared_secret)
    
    return session_parameters

# This replaces the interactive negotiation - both peers derive identical values
function get_derived_sequence_numbers(session_parameters):
    return {
        'local_initial_sequence': session_parameters.client_sequence,
        'peer_initial_sequence': session_parameters.server_sequence
    }

# No verification functions needed - ECDH provides inherent mutual authentication
# through shared secret computation. Both peers must have correct private keys
# to compute the same shared secret and derive identical parameters.

function verify_ecdh_parameter_derivation(derived_params, shared_secret_hash):
    # Verify that both peers derived the same parameters from ECDH
    # This is done during SYN-ACK by including shared secret verification hash
    expected_hash = SHA256(derive_verification_material(derived_params))
    return constant_time_compare(shared_secret_hash, expected_hash)

function derive_verification_material(session_parameters):
    # Create material for verifying successful parameter derivation
    verification_data = (
        session_parameters.client_sequence.to_bytes(4, 'big') ||
        session_parameters.server_sequence.to_bytes(4, 'big') ||
        session_parameters.session_key[0:8]  # First 8 bytes of session key
    )
    return verification_data
```

## Sequence Number Security Properties

```pseudocode
# Security requirements for sequence negotiation
function validate_sequence_negotiation_security():
    # 1. Commitment hiding: commitment does not reveal sequence number
    assert commitment_reveals_no_information_about_sequence()
    
    # 2. Commitment binding: peer cannot change sequence after commitment
    assert peer_cannot_change_sequence_after_commitment()
    
    # 3. Proof soundness: invalid sequences cannot produce valid proofs
    assert invalid_sequences_produce_invalid_proofs()
    
    # 4. Proof zero-knowledge: proofs reveal no information about sequences
    assert proofs_reveal_no_sequence_information()
    
    # 5. Negotiation fairness: neither peer can bias the other's choice
    assert negotiation_is_fair_and_unbiased()

function handle_sequence_negotiation_timeout():
    # Cleanup negotiation state
    clear_negotiation_buffers()
    secure_zero_sequence_material()
    
    # Retry with exponential backoff
    if negotiation_attempts < MAX_SEQUENCE_NEGOTIATION_ATTEMPTS:
        backoff_time = SEQUENCE_NEGOTIATION_TIMEOUT_MS * (2 ** negotiation_attempts)
        schedule_retry(backoff_time)
        negotiation_attempts += 1
    else:
        # Negotiation failed permanently
        transition_to_state(SEQUENCE_NEGOTIATION_FAILED)
        return ERROR_SEQUENCE_NEGOTIATION_TIMEOUT
```

## ECDH-Based Connection Parameters

With ECDH-based sequence derivation, there are no separate sequence negotiation packets needed. All sequence numbers and session parameters are deterministically derived during the SYN/SYN-ACK handshake from the ECDH shared secret using PBKDF2, eliminating the need for interactive negotiation.

## SYN Packet ECDH Fields

```pseudocode
Field Definitions:
- Common Header (50 bytes): Standard header with SYN flag set
- Client ECDH Public Key (64 bytes): P-256 public key for key exchange (64 bytes)
- PSK Authentication (16 bytes): HMAC of public key with PSK (16 bytes)
- Key Exchange ID (16-bit): Unique identifier for this key exchange (2 bytes)
- Initial Congestion Window (16-bit): Initial congestion window size (2 bytes)
- Initial Receive Window (16-bit): Initial receive window size (2 bytes)
- Time Offset (32-bit): Client's time offset from epoch (4 bytes)
- Supported Features (16-bit): Bitmap of supported features (2 bytes)
- Reserved (16-bit): Always 0x0000 (2 bytes)

Total SYN Packet Size: 50 + 108 = 158 bytes
```

## SYN-ACK Packet ECDH Fields

```pseudocode
Field Definitions:
- Common Header (50 bytes): Standard header with SYN and ACK flags set
- Server ECDH Public Key (64 bytes): P-256 public key for key exchange (64 bytes)
- Shared Secret Verification Hash (32 bytes): SHA256 hash of computed shared secret (32 bytes)
- Key Exchange ID Echo (16-bit): Echo of client's key exchange ID (2 bytes)
- Initial Congestion Window (16-bit): Initial congestion window size (2 bytes)
- Initial Receive Window (16-bit): Initial receive window size (2 bytes)
- Time Offset (32-bit): Server's time offset from epoch (4 bytes)
- Negotiated Features (16-bit): Final feature bitmap (2 bytes)
- Reserved (16-bit): Always 0x0000 (2 bytes)

Total SYN-ACK Packet Size: 50 + 124 = 174 bytes
```

## PSK Discovery with Privacy-Preserving Set Intersection

### DISCOVERY Packet (Type 0x0E)
```pseudocode
DISCOVERY Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (50 bytes)             |
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|        PSK Hint (32-bit)         |
+-----------------------------------+
|      Challenge Nonce (64-bit)    |
+-----------------------------------+
|    Initiator Features (16-bit)   |
+-----------------------------------+
|        Reserved (16-bit)         |
+-----------------------------------+
|        Commitment (128-bit)      |
+-----------------------------------+

Field Definitions:
- Common Header (50 bytes): Standard header
- Discovery ID (64-bit): Unique identifier for this discovery session
- PSK Hint (32-bit): Hint about which PSK to use (may be obfuscated)
- Challenge Nonce (64-bit): Random challenge for commitment
- Initiator Features (16-bit): Bitmap of supported features
- Reserved (16-bit): Always 0x0000
- Bloom Filter (128 bytes): Privacy-preserving set intersection filter (128 bytes)

Total DISCOVERY Packet Size: 50 + 20 + 128 = 198 bytes
```

### DISCOVERY Packet with RESPONSE Sub-Type (Type 0x0E, Sub-Type 0x02)
```pseudocode
DISCOVERY_RESPONSE Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (50 bytes)             |
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|        PSK Hint (32-bit)         |
+-----------------------------------+
|      Response Nonce (64-bit)     |
+-----------------------------------+
|     Challenge Echo (64-bit)      |
+-----------------------------------+
|      PSK Commitment (64-bit)     |
+-----------------------------------+
|    Responder Features (16-bit)   |
+-----------------------------------+
|        Reserved (16-bit)         |
+-----------------------------------+
|        Commitment (128-bit)      |
+-----------------------------------+

Field Definitions:
- Common Header (50 bytes): Standard header
- Discovery ID (64-bit): Matching discovery session identifier
- PSK Hint (32-bit): Hint about which PSK to use
- Response Nonce (64-bit): Random nonce for response
- Challenge Echo (64-bit): Echo of received challenge nonce
- PSK Commitment (64-bit): PSK range commitment
- Responder Features (16-bit): Bitmap of supported features
- Reserved (16-bit): Always 0x0000
- Candidate Hashes (Variable): Hash values of intersection candidates (variable length)

Total DISCOVERY_RESPONSE Packet Size: 50 + 36 + Variable = Variable bytes
```

### DISCOVERY Packet with CONFIRM Sub-Type (Type 0x0E, Sub-Type 0x03)
```pseudocode
DISCOVERY_CONFIRM Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (50 bytes)             |
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|         PSK ID (32-bit)          |
+-----------------------------------+
|     Confirmation Nonce (64-bit)  |
+-----------------------------------+
|    Challenge Proof (64-bit)      |
+-----------------------------------+
|  PSK Selection Commitment (64-bit)|
+-----------------------------------+
|        Session ID (64-bit)       |
+-----------------------------------+
|        Reserved (16-bit)         |
+-----------------------------------+
|        Commitment (128-bit)      |
+-----------------------------------+

Field Definitions:
- Common Header (50 bytes): Standard header
- Discovery ID (64-bit): Matching discovery session identifier
- PSK ID (32-bit): Selected PSK identifier
- Confirmation Nonce (64-bit): Final confirmation nonce
- Challenge Proof (64-bit): Proof of challenge response
- PSK Selection Commitment (64-bit): PSK selection commitment
- Session ID (64-bit): New session identifier for communication
- Reserved (16-bit): Always 0x0000
- PSK Confirmation Hash (32 bytes): SHA256 confirmation of selected PSK (32 bytes)

Total DISCOVERY_CONFIRM Packet Size: 50 + 36 + 32 = 118 bytes
```

## Privacy-Preserving PSK Discovery Protocol

### Overview
The PSK discovery protocol uses privacy-preserving hash-based set intersection to identify shared PSKs between peers without revealing their complete PSK fingerprint collections. Each host maintains a list of PSK fingerprints, and the protocol enables them to find common PSKs while protecting the privacy of non-shared keys.

### Hash-Based Set Intersection Approach
The protocol implements a secure multi-party computation technique that allows two parties to find the intersection of their sets (PSK fingerprints) without revealing elements that are not in the intersection. This prevents PSK enumeration attacks while enabling efficient key discovery.

### Privacy-Preserving Set Intersection Flow

```pseudocode
function initiate_psi_psk_discovery(remote_endpoint, local_psk_fingerprints):
    # Phase 1: Generate discovery session parameters
    discovery_id = generate_secure_random_64bit()
    session_salt = generate_secure_random_32bit()
    
    # Create privacy-preserving representation of our PSK fingerprints
    # Using hash-based approach with blinding factors
    blinded_fingerprint_set = create_blinded_fingerprint_set(
        local_psk_fingerprints, 
        discovery_id, 
        session_salt
    )
    
    # Generate Bloom filter for efficient set intersection
    bloom_filter = create_psk_bloom_filter(
        blinded_fingerprint_set,
        BLOOM_FILTER_SIZE_BITS,
        BLOOM_FILTER_HASH_FUNCTIONS
    )
    
    # Send DISCOVERY_REQUEST with Bloom filter
    discovery_request = create_discovery_packet(
        sub_type = DISCOVERY_SUB_REQUEST,
        discovery_id = discovery_id,
        session_salt = session_salt,
        bloom_filter = bloom_filter,
        fingerprint_count = len(local_psk_fingerprints)
    )
    send_packet(discovery_request)
    
    # Phase 2: Receive response with candidate intersections
    response = receive_packet_timeout(DISCOVERY_TIMEOUT_MS)
    if response == null or response.sub_type != DISCOVERY_SUB_RESPONSE:
        return ERROR_DISCOVERY_TIMEOUT
    
    # Find actual intersections from candidates
    intersection_results = verify_psi_candidates(
        response.candidate_hashes,
        local_psk_fingerprints,
        discovery_id,
        session_salt
    )
    
    if len(intersection_results) == 0:
        return ERROR_PSK_NOT_FOUND
    
    # Select best PSK from intersection (highest priority/most recent)
    selected_psk_fingerprint = select_optimal_psk(intersection_results)
    
    # Phase 3: Confirm selection with peer
    confirmation_hash = calculate_psk_confirmation_hash(
        selected_psk_fingerprint,
        discovery_id,
        session_salt
    )
    
    confirmation = create_discovery_packet(
        sub_type = DISCOVERY_SUB_CONFIRM,
        discovery_id = discovery_id,
        confirmation_hash = confirmation_hash
    )
    send_packet(confirmation)
    
    # Wait for final confirmation
    final_response = receive_packet_timeout(DISCOVERY_TIMEOUT_MS)
    if final_response == null or final_response.confirmation_status != CONFIRMED:
        return ERROR_PSK_CONFIRMATION_FAILED
    
    return resolve_psk_from_fingerprint(selected_psk_fingerprint)

function handle_psi_discovery_request(request_packet, local_psk_fingerprints):
    # Extract discovery parameters
    discovery_id = request_packet.discovery_id
    session_salt = request_packet.session_salt
    peer_bloom_filter = request_packet.bloom_filter
    peer_fingerprint_count = request_packet.fingerprint_count
    
    # Create our blinded fingerprint set using same parameters
    local_blinded_fingerprints = create_blinded_fingerprint_set(
        local_psk_fingerprints,
        discovery_id,
        session_salt
    )
    
    # Test our fingerprints against peer's Bloom filter to find candidates
    candidate_intersections = []
    for blinded_fp in local_blinded_fingerprints:
        if bloom_filter_test(peer_bloom_filter, blinded_fp):
            # Potential intersection - add to candidates
            candidate_hash = SHA256(blinded_fp || b"candidate_v1")
            candidate_intersections.append(candidate_hash)
    
    if len(candidate_intersections) == 0:
        return send_discovery_response(discovery_id, [], PSI_NO_INTERSECTION)
    
    # Send response with candidate intersection hashes
    # Note: These are hashed again so peer cannot directly learn our fingerprints
    discovery_response = create_discovery_packet(
        sub_type = DISCOVERY_SUB_RESPONSE,
        discovery_id = discovery_id,
        candidate_hashes = candidate_intersections,
        intersection_status = PSI_CANDIDATES_FOUND
    )
    send_packet(discovery_response)
    
    # Wait for peer's confirmation
    confirmation = receive_packet_timeout(DISCOVERY_TIMEOUT_MS)
    if confirmation == null or confirmation.sub_type != DISCOVERY_SUB_CONFIRM:
        return ERROR_DISCOVERY_TIMEOUT
    
    # Verify the confirmed PSK is actually in our intersection
    selected_psk_fingerprint = verify_psk_confirmation(
        confirmation.confirmation_hash,
        local_psk_fingerprints,
        discovery_id,
        session_salt
    )
    
    if selected_psk_fingerprint == null:
        return send_error(ERROR_PSK_CONFIRMATION_INVALID)
    
    # Send final confirmation
    final_confirmation = create_discovery_packet(
        sub_type = DISCOVERY_SUB_CONFIRM,
        discovery_id = discovery_id,
        confirmation_status = CONFIRMED
    )
    send_packet(final_confirmation)
    
    return resolve_psk_from_fingerprint(selected_psk_fingerprint)

### Privacy-Preserving Set Intersection Functions

```pseudocode
function create_blinded_fingerprint_set(psk_fingerprints, discovery_id, session_salt):
    # Create blinded version of PSK fingerprints for privacy-preserving comparison
    # Uses HMAC with session parameters to create unlinkable blinded fingerprints
    blinded_set = []
    
    discovery_context = discovery_id.to_bytes(8, 'big') || session_salt.to_bytes(4, 'big')
    
    for fingerprint in psk_fingerprints:
        # Create blinded fingerprint using HMAC with discovery context
        blinded_fp = HMAC_SHA256_128(
            key = fingerprint,  # Original PSK fingerprint as key
            data = discovery_context || b"psi_blinding_v1"
        )
        blinded_set.append(blinded_fp)
    
    return blinded_set

function create_psk_bloom_filter(blinded_fingerprints, filter_size_bits, num_hash_functions):
    # Create Bloom filter for efficient set intersection testing
    # Multiple hash functions reduce false positive rate
    
    bloom_filter = create_empty_bit_array(filter_size_bits)
    
    for blinded_fp in blinded_fingerprints:
        # Apply multiple hash functions to each fingerprint
        for i in range(num_hash_functions):
            # Create hash function variant using index
            hash_input = blinded_fp || i.to_bytes(1, 'big') || b"bloom_hash_v1"
            hash_output = SHA256(hash_input)
            
            # Map hash to bit position in filter
            bit_position = bytes_to_uint32(hash_output[0:4]) % filter_size_bits
            bloom_filter[bit_position] = 1
    
    return bloom_filter

function bloom_filter_test(bloom_filter, blinded_fingerprint):
    # Test if blinded fingerprint might be in the set represented by Bloom filter
    # Returns True if possibly in set, False if definitely not in set
    
    filter_size_bits = len(bloom_filter)
    num_hash_functions = BLOOM_FILTER_HASH_FUNCTIONS
    
    for i in range(num_hash_functions):
        hash_input = blinded_fingerprint || i.to_bytes(1, 'big') || b"bloom_hash_v1"
        hash_output = SHA256(hash_input)
        bit_position = bytes_to_uint32(hash_output[0:4]) % filter_size_bits
        
        if bloom_filter[bit_position] == 0:
            return False  # Definitely not in set
    
    return True  # Possibly in set (could be false positive)

function verify_psi_candidates(candidate_hashes, local_psk_fingerprints, discovery_id, session_salt):
    # Verify which candidates are actual intersections
    verified_intersections = []
    
    # Recreate our blinded fingerprints
    local_blinded_fps = create_blinded_fingerprint_set(
        local_psk_fingerprints,
        discovery_id,
        session_salt
    )
    
    # Check each candidate against our actual fingerprints
    for i, blinded_fp in enumerate(local_blinded_fps):
        expected_candidate_hash = SHA256(blinded_fp || b"candidate_v1")
        
        if expected_candidate_hash in candidate_hashes:
            # This is a real intersection
            verified_intersections.append({
                'original_fingerprint': local_psk_fingerprints[i],
                'blinded_fingerprint': blinded_fp,
                'candidate_hash': expected_candidate_hash
            })
    
    return verified_intersections

function select_optimal_psk(intersection_results):
    # Select the best PSK from intersection results
    # Priority: most recent > highest security level > lexicographic order
    
    if len(intersection_results) == 0:
        return null
    
    if len(intersection_results) == 1:
        return intersection_results[0]['original_fingerprint']
    
    # Sort by priority (implementation-specific)
    sorted_results = sort_by_psk_priority(intersection_results)
    return sorted_results[0]['original_fingerprint']

function calculate_psk_confirmation_hash(psk_fingerprint, discovery_id, session_salt):
    # Create confirmation hash for selected PSK
    confirmation_context = discovery_id.to_bytes(8, 'big') || session_salt.to_bytes(4, 'big')
    return SHA256(psk_fingerprint || confirmation_context || b"psk_confirmation_v1")

function verify_psk_confirmation(confirmation_hash, local_psk_fingerprints, discovery_id, session_salt):
    # Verify that confirmation hash corresponds to one of our PSKs
    confirmation_context = discovery_id.to_bytes(8, 'big') || session_salt.to_bytes(4, 'big')
    
    for fingerprint in local_psk_fingerprints:
        expected_hash = SHA256(fingerprint || confirmation_context || b"psk_confirmation_v1")
        if constant_time_compare(confirmation_hash, expected_hash):
            return fingerprint
    
    return null  # No matching fingerprint found

function resolve_psk_from_fingerprint(psk_fingerprint):
    # Look up the actual PSK from our local storage using the fingerprint
    # This function accesses secure PSK storage (implementation-specific)
    return lookup_psk_by_fingerprint(psk_fingerprint)

### Bloom Filter Optimization

```pseudocode
function calculate_optimal_bloom_parameters(expected_items, desired_false_positive_rate):
    # Calculate optimal Bloom filter parameters for given requirements
    # Returns: (filter_size_bits, num_hash_functions)
    
    import math
    
    # Optimal filter size: m = -(n * ln(p)) / (ln(2)^2)
    # where n = expected items, p = false positive rate
    filter_size_bits = int(-expected_items * math.log(desired_false_positive_rate) / (math.log(2) ** 2))
    
    # Optimal number of hash functions: k = (m/n) * ln(2)
    num_hash_functions = int((filter_size_bits / expected_items) * math.log(2))
    
    # Ensure reasonable bounds
    filter_size_bits = max(BLOOM_FILTER_SIZE_BITS_DEFAULT, min(filter_size_bits, BLOOM_FILTER_SIZE_BITS_MAX))
    num_hash_functions = max(1, min(num_hash_functions, 8))   # 1 to 8 hash functions
    
    return (filter_size_bits, num_hash_functions)

function create_adaptive_bloom_filter(psk_fingerprints, discovery_id, session_salt):
    # Create Bloom filter with adaptive parameters based on PSK count
    psk_count = len(psk_fingerprints)
    desired_fp_rate = BLOOM_FILTER_FALSE_POSITIVE_RATE
    
    filter_size, num_hashes = calculate_optimal_bloom_parameters(psk_count, desired_fp_rate)
    
    # Create blinded fingerprints
    blinded_fps = create_blinded_fingerprint_set(psk_fingerprints, discovery_id, session_salt)
    
    return {
        'bloom_filter': create_psk_bloom_filter(blinded_fps, filter_size, num_hashes),
        'filter_size': filter_size,
        'num_hash_functions': num_hashes
    }
```

### Integration with ECDH Connection Establishment

```pseudocode
function integrated_psi_ecdh_connection(remote_endpoint, local_psk_fingerprints):
    # Complete connection establishment with PSI discovery + ECDH key exchange
    
    # Phase 1: Privacy-preserving PSK discovery
    discovered_psk = initiate_psi_psk_discovery(remote_endpoint, local_psk_fingerprints)
    if discovered_psk == null:
        return ERROR_NO_SHARED_PSK
    
    # Phase 2: ECDH key exchange with PSK authentication
    session_keys = establish_ecdh_connection_with_psk_auth(remote_endpoint, discovered_psk)
    if session_keys == null:
        return ERROR_ECDH_FAILED
    
    # Phase 3: Verify PSK-authenticated ECDH shared secret
    if not verify_psk_authenticated_ecdh(session_keys, discovered_psk):
        return ERROR_PSK_AUTH_FAILED
    
    return session_keys

function establish_ecdh_connection_with_psk_auth(remote_endpoint, psk):
    # ECDH connection establishment with PSK-based authentication
    client_keypair = generate_ecdh_keypair()
    
    # Create PSK-authenticated SYN
    psk_auth = HMAC_SHA256_128(psk, client_keypair.public || b"ecdh_syn_auth_v1")
    
    syn_packet = create_syn_packet(
        client_public_key = client_keypair.public,
        psk_authentication = psk_auth,
        # ... other ECDH fields
    )
    send_packet(syn_packet)
    
    # Continue with authenticated ECDH handshake
    return perform_psk_authenticated_ecdh_handshake(client_keypair, psk)
```


## Zero-Knowledge Constants

```pseudocode
// Discovery and zero-knowledge proof constants
MAX_PSK_COUNT = 256                     // Maximum number of PSKs per peer
// Discovery and ECDH timeout constants are defined in 02-constants.md
DISCOVERY_RETRY_COUNT = 3               // Maximum discovery retry attempts
PEDERSEN_COMMITMENT_SIZE = 64           // Size of Pedersen commitment in bytes
DISCOVERY_CHALLENGE_SIZE = 32           // Size of challenge nonce in bytes
PSK_ID_LENGTH = 32                      // Length of PSK identifier

// ECDH connection establishment constants
ECDH_PUBLIC_KEY_SIZE = 64                // P-256 uncompressed public key size
ECDH_SHARED_SECRET_SIZE = 32             // P-256 shared secret size
ECDH_VERIFICATION_HASH_SIZE = 32         // SHA256 verification hash size

// Elliptic curve constants (P-256)
CURVE_P256_FIELD_SIZE = 32               // Field element size in bytes
CURVE_P256_SCALAR_SIZE = 32              // Scalar size in bytes

// All error codes are defined in 03-error-codes.md
```