# PSK Discovery with Privacy-Preserving Set Intersection

This document defines the privacy-preserving PSK discovery mechanism that enables peers to find shared pre-shared keys without revealing their complete PSK collections using hash-based set intersection and Bloom filters.

## Overview

The PSK discovery protocol uses privacy-preserving hash-based set intersection to identify shared PSKs between peers without revealing their complete PSK fingerprint collections. Each host maintains a list of PSK fingerprints, and the protocol enables them to find common PSKs while protecting the privacy of non-shared keys.

## Purpose and Rationale

Privacy-preserving PSK discovery serves critical security and privacy functions:

- **Privacy Protection**: Prevents PSK enumeration attacks by hiding non-shared keys from discovery
- **Secure Multi-Party Computation**: Uses hash-based set intersection to find common PSKs without revealing full sets
- **Bloom Filter Efficiency**: Enables efficient discovery through probabilistic data structures with tunable false positive rates
- **Zero Knowledge Leakage**: Only intersection results are revealed, protecting individual PSK fingerprint collections
- **Attack Resistance**: Cryptographic blinding and hash-based representations prevent PSK enumeration
- **Scalable Discovery**: Supports environments where peers maintain large collections of PSK fingerprints

The hash-based set intersection approach eliminates the need to reveal non-shared PSKs while providing strong privacy guarantees through cryptographic blinding and probabilistic data structures.

## Key Concepts

- **Privacy-Preserving Set Intersection**: Secure multi-party computation technique for finding set intersections without revealing non-shared elements
- **Blinded Fingerprints**: Cryptographically blinded PSK fingerprints using HMAC with session-specific context
- **Bloom Filters**: Probabilistic data structures that enable efficient set membership testing with tunable false positive rates
- **Discovery Sessions**: Unique session identifiers and salts that provide context separation for blinding operations
- **Candidate Verification**: Two-phase approach where Bloom filter identifies candidates, then cryptographic verification confirms intersections
- **PSK Fingerprints**: Hash-based identifiers that represent PSKs without revealing the actual key material

## Privacy-Preserving Set Intersection Protocol

### Discovery Request Phase

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
```

### Discovery Response Phase

```pseudocode
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
```

## Cryptographic Blinding and Set Operations

### Blinded Fingerprint Generation

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
```

### Bloom Filter Operations

```pseudocode
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
```

### Candidate Verification

```pseudocode
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
```

## Bloom Filter Optimization

### Adaptive Parameter Calculation

```pseudocode
function calculate_optimal_bloom_parameters(expected_items, desired_false_positive_rate):
    # Calculate optimal Bloom filter parameters for given requirements
    # Returns: (filter_size_bits, num_hash_functions)
        
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

## DISCOVERY Packet Specifications

### DISCOVERY_REQUEST Packet (Sub-Type 0x01)

```pseudocode
DISCOVERY_REQUEST Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|       Session Salt (32-bit)      |
+-----------------------------------+
| Fingerprint Count|Bloom Filter   |
|     (16-bit)     | Size (16-bit) |
+-------------------+---------------+
| Initiator Features|   Reserved   |
|    (16-bit)      |   (16-bit)   |
+-------------------+---------------+
|     Bloom Filter Data            |
|     (Variable Length)            |
|    (512 bytes maximum)           |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with DISCOVERY type and REQUEST sub-type
- Discovery ID (64-bit): Unique identifier for this discovery session
- Session Salt (32-bit): Salt for blinding fingerprints in this session
- Fingerprint Count (16-bit): Number of PSK fingerprints in local set
- Bloom Filter Size (16-bit): Size of Bloom filter in bytes
- Initiator Features (16-bit): Bitmap of supported discovery features
- Reserved (16-bit): Always 0x0000
- Bloom Filter Data (Variable): Probabilistic set representation (max 512 bytes)

Total Size: 50 + 20 + bloom_filter_size bytes (max 582 bytes)
```

### DISCOVERY_RESPONSE Packet (Sub-Type 0x02)

```pseudocode
DISCOVERY_RESPONSE Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|   Candidate Count (16-bit)       |
+-----------------------------------+
|  Intersection Status (16-bit)    |
+-----------------------------------+
| Responder Features|   Reserved   |
|    (16-bit)      |   (16-bit)   |
+-------------------+---------------+
|    Candidate Intersection        |
|         Hashes                   |
|   (32 bytes per candidate)       |
|   (Variable Length)              |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with DISCOVERY type and RESPONSE sub-type
- Discovery ID (64-bit): Matching discovery session identifier
- Candidate Count (16-bit): Number of intersection candidates found
- Intersection Status (16-bit): Status of intersection operation
- Responder Features (16-bit): Bitmap of supported discovery features
- Reserved (16-bit): Always 0x0000
- Candidate Intersection Hashes (Variable): Hash values of potential intersections (32 bytes each)

Total Size: 50 + 12 + (32 * candidate_count) bytes
```

### DISCOVERY_CONFIRM Packet (Sub-Type 0x03)

```pseudocode
DISCOVERY_CONFIRM Packet Structure (Big-Endian):
+-----------------------------------+
|      Optimized Common Header      |
|           (50 bytes)             |
+-----------------------------------+
|        Discovery ID (64-bit)     |
+-----------------------------------+
|    Confirmation Hash (256-bit)   |
|   (Selected PSK fingerprint      |
|    confirmation hash)            |
|                                 |
+-----------------------------------+
|  Confirmation Status (16-bit)    |
+-----------------------------------+
|        Reserved (16-bit)         |
+-----------------------------------+
|        Session ID (64-bit)       |
+-----------------------------------+
|      Reserved (16-bit)           |
+-----------------------------------+
|        Commitment (128-bit)      |
|                                 |
+-----------------------------------+

Field Definitions:
- Optimized Common Header (50 bytes): Standard header with DISCOVERY type and CONFIRM sub-type
- Discovery ID (64-bit): Matching discovery session identifier
- Confirmation Hash (256-bit): SHA256 confirmation of selected PSK fingerprint
- Confirmation Status (16-bit): Status of PSK confirmation (CONFIRMED, REJECTED, etc.)
- Reserved (16-bit): Always 0x0000
- Session ID (64-bit): New session identifier for subsequent communication
- Reserved (16-bit): Always 0x0000
- Commitment (128-bit): Cryptographic commitment for session establishment

Total Size: 50 + 52 = 102 bytes
```

## Integration with ECDH Connection Establishment

### Complete Discovery and Connection Flow

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

## Privacy and Security Properties

### Security Guarantees

1. **Privacy Protection**: Non-shared PSK fingerprints are never revealed to peers
2. **Unlinkability**: Blinded fingerprints cannot be linked across different discovery sessions  
3. **Forward Secrecy**: Discovery session context prevents replay across sessions
4. **Attack Resistance**: Cryptographic blinding prevents PSK enumeration attacks
5. **Efficiency**: Bloom filters provide efficient discovery with tunable false positive rates
6. **Zero Knowledge**: Only intersection results are revealed, not full PSK sets

### Privacy-Preserving Set Intersection Constants

```pseudocode
// Privacy-preserving set intersection constants
BLOOM_FILTER_SIZE_BITS_DEFAULT = 2048   // Default Bloom filter size in bits (256 bytes)
BLOOM_FILTER_SIZE_BITS_MAX = 4096       // Maximum Bloom filter size in bits (512 bytes)
BLOOM_FILTER_HASH_FUNCTIONS = 3         // Number of hash functions for Bloom filter
BLOOM_FILTER_FALSE_POSITIVE_RATE = 0.01 // Target false positive rate (1%)
PSI_CANDIDATE_HASH_SIZE = 32            // Size of candidate intersection hash (256-bit)
PSI_MAX_CANDIDATES_PER_RESPONSE = 16    // Maximum candidates in response packet
PSI_BLINDED_FINGERPRINT_SIZE = 16       // Size of blinded PSK fingerprint (128-bit)
PSI_SESSION_SALT_SIZE = 4               // Size of PSI session salt (32-bit)

// Discovery process constants
MAX_PSK_COUNT = 256                     // Maximum number of PSKs per peer
MAX_PSK_PROOFS_PER_DISCOVERY = 8        // Maximum PSK proofs per discovery request
PSK_PROOF_SIZE = 16                     // Size of PSK knowledge proof in bytes
DISCOVERY_TIMEOUT_MS = 10000            // Discovery process timeout (10 seconds)
DISCOVERY_RETRY_COUNT = 3               // Maximum discovery retry attempts
DISCOVERY_CACHE_TTL_MS = 3600000        // Discovery cache time-to-live (1 hour)
DISCOVERY_CHALLENGE_SIZE = 32           // Size of challenge nonce in bytes
PSK_ID_LENGTH = 32                      // Length of PSK identifier
```
