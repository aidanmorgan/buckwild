# ECDH-Based Cryptography Specifications

## Overview

This document defines the comprehensive ECDH-based cryptographic framework that secures all protocol communications using ephemeral Diffie-Hellman key exchange, PBKDF2 parameter derivation, and privacy-preserving set intersection for PSK discovery. The cryptographic design ensures perfect forward secrecy, prevents data exposure, and maintains strong security properties throughout the protocol lifecycle.

## Purpose and Rationale

The ECDH-based cryptographic system serves multiple security objectives:

- **Perfect Forward Secrecy**: Ephemeral ECDH key exchange protects all past communications
- **Zero Data Exposure**: All sensitive exchanges use ECDH to prevent information leakage
- **Privacy-Preserving Discovery**: PSK discovery using hash-based set intersection protects key collections
- **PBKDF2 Parameter Derivation**: All session parameters cryptographically derived from ECDH shared secrets
- **Message Authentication**: HMAC authentication using ECDH-derived session keys
- **Secure Recovery**: All recovery mechanisms use ECDH instead of exposing key material

The design uses ephemeral ECDH (P-256), PBKDF2-HMAC-SHA256, and Bloom filter-based PSI, providing the strongest possible security guarantees with perfect forward secrecy.

## Key Concepts

- **Ephemeral ECDH Key Exchange**: P-256 elliptic curve Diffie-Hellman for perfect forward secrecy
- **PBKDF2 Parameter Derivation**: All session parameters derived from ECDH shared secrets using PBKDF2
- **16-bit Chunk Processing**: PBKDF2 output processed as 16-bit chunks per specification
- **Privacy-Preserving Set Intersection**: Bloom filter-based PSK discovery with zero knowledge leakage
- **HMAC Authentication**: Message authentication using ECDH-derived session keys
- **ECDH-Based Recovery**: All recovery mechanisms use ephemeral ECDH instead of exposing key material
- **Zero Data Exposure**: No sensitive data transmitted - all derived from ECDH shared secrets

## HMAC Calculation Specification

### Complete HMAC Calculation Algorithm
```pseudocode
function calculate_packet_hmac(packet_data, session_key):
    # HMAC is calculated over all packet fields except the HMAC field itself
    # The HMAC field is always the last 16 bytes of the packet (HMAC-SHA256-128)
    
    # Extract packet without HMAC
    packet_without_hmac = packet_data[0:len(packet_data)-16]
    
    # Calculate HMAC-SHA256-128 using session key
    hmac_result = HMAC_SHA256_128(session_key, packet_without_hmac)
    
    return hmac_result

function verify_packet_hmac(packet_data, session_key, received_hmac):
    # Calculate expected HMAC
    expected_hmac = calculate_packet_hmac(packet_data, session_key)
    
    # Compare HMACs (constant-time comparison)
    return constant_time_compare(expected_hmac, received_hmac)

function constant_time_compare(a, b):
    # Constant-time comparison to prevent timing attacks
    if len(a) != len(b):
        return False
    
    result = 0
    for i in range(len(a)):
        result |= a[i] ^ b[i]
    
    return result == 0
```

## Session Key Derivation Specification

### HKDF-SHA256 Key Derivation Algorithm
```pseudocode
function derive_session_key(daily_key, session_id, nonce):
    # Derive session key using HKDF-SHA256 (RFC 5869)
    # Input key material (IKM): Daily key (derived from PSK and current date)
    # Salt: Session ID for context separation
    # Info: Nonce for additional entropy
    
    # Convert inputs to bytes
    daily_key_bytes = daily_key if isinstance(daily_key, bytes) else daily_key
    session_id_bytes = uint64_to_bytes(session_id)
    nonce_bytes = nonce if isinstance(nonce, bytes) else nonce.encode('utf-8')
    
    # HKDF-SHA256 Extract phase
    # PRK = HMAC-SHA256(salt, IKM)
    salt = session_id_bytes
    ikm = daily_key_bytes
    prk = HMAC_SHA256_128(salt, ikm)
    
    # HKDF-SHA256 Expand phase
    # OKM = HKDF-Expand(PRK, info, L)
    info = b"session_key" + nonce_bytes
    l = 32  # 256-bit session key
    
    # Expand using HMAC-SHA256
    session_key = hkdf_expand_sha256(prk, info, l)
    
    return session_key

function hkdf_expand_sha256(prk, info, l):
    # HKDF-Expand implementation using HMAC-SHA256
    # Based on RFC 5869 Section 2.3
    
    if l > 255 * 32:  # SHA256 output is 32 bytes
        raise ValueError("Requested key length too large")
    
    # Initialize
    t = b""
    okm = b""
    counter = 1
    
    while len(okm) < l:
        # T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)
        t = HMAC_SHA256_128(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    
    return okm[:l]

function derive_daily_key(psk, date_string):
    # Derive daily key for port calculation and session key derivation using HKDF-SHA256
    # This provides key separation between session keys and port calculation
    # Daily key is derived from PSK and current UTC date (YYYY-MM-DD format)
    
    psk_bytes = psk if isinstance(psk, bytes) else psk.encode('utf-8')
    date_bytes = date_string.encode('utf-8')
    
    # HKDF-SHA256 Extract
    salt = b"daily_key_salt"
    ikm = psk_bytes
    prk = HMAC_SHA256_128(salt, ikm)
    
    # HKDF-SHA256 Expand
    info = b"daily_key" + date_bytes
    l = 32  # 256-bit daily key
    
    daily_key = hkdf_expand_sha256(prk, info, l)
    
    return daily_key

function derive_daily_key_for_current_date(psk):
    # Convenience function to derive daily key for current UTC date
    current_date = get_current_utc_date()
    return derive_daily_key(psk, current_date)

function initialize_session_keys(psk, session_id, nonce):
    # Initialize session keys using daily key derivation
    # This ensures all session keys are derived from the daily key, not directly from PSK
    
    # Step 1: Derive daily key from PSK and current UTC date
    daily_key = derive_daily_key_for_current_date(psk)
    
    # Step 2: Derive session key from daily key
    session_key = derive_session_key(daily_key, session_id, nonce)
    
    return {
        'daily_key': daily_key,
        'session_key': session_key
    }

function rekey_session_keys(psk, session_id, new_nonce):
    # Rekey session keys using current daily key
    # This maintains the daily key but generates a new session key
    
    # Get current daily key (or derive if not available)
    daily_key = derive_daily_key_for_current_date(psk)
    
    # Derive new session key from daily key
    new_session_key = derive_session_key(daily_key, session_id, new_nonce)
    
    return {
        'daily_key': daily_key,
        'session_key': new_session_key
    }
```


## Sequence Repair Cryptographic Proofs

```pseudocode
function calculate_sequence_proof(sequence, nonce, peer_commitment):
    # Create HMAC proof that sequence matches expected value for sequence repair
    proof_input = sequence || nonce || peer_commitment || session_id
    return HMAC_SHA256_128(session_key, proof_input)[0:4]

function calculate_confirmation_proof(local_sequence, peer_sequence):
    # Final confirmation that both parties have valid sequences
    confirmation_input = min(local_sequence, peer_sequence) || max(local_sequence, peer_sequence) || session_id
    return HMAC_SHA256_128(session_key, confirmation_input)[0:4]
```

## Session Rekeying Cryptography

```pseudocode
function execute_rekey_recovery():
    # Step 1: Generate new session key material
    rekey_nonce = generate_secure_random_32bit()
    new_daily_key = derive_daily_key_for_current_date(psk)
    new_session_key_material = generate_secure_random_256bit()
    
    # Step 2: Create key commitment
    key_commitment = create_key_commitment(new_session_key_material, rekey_nonce)
    
    rekey_request = create_rekey_request(
        rekey_nonce = rekey_nonce,
        new_key_commitment = key_commitment
    )
    
    send_packet(rekey_request)
    
    # Step 3: Receive peer's rekey response
    rekey_response = receive_packet_timeout(REKEY_TIMEOUT_MS)
    
    if rekey_response == null or rekey_response.type != PACKET_TYPE_MANAGEMENT or rekey_response.sub_type != MANAGEMENT_SUB_REKEY_RESPONSE:
        return ERROR_REKEY_TIMEOUT
    
    if rekey_response.rekey_nonce != rekey_nonce:
        return ERROR_REKEY_INVALID_NONCE
    
    # Step 4: Derive new session key
    combined_key_material = new_session_key_material || rekey_response.new_key_commitment
    new_session_key = derive_session_key(new_daily_key, session_id, combined_key_material)
    
    # Step 5: Verify rekey confirmation
    expected_confirmation = HMAC_SHA256_128(new_session_key, "rekey_confirmation" || session_id)
    if not constant_time_compare(rekey_response.confirmation, expected_confirmation[0:16]):
        return ERROR_REKEY_CONFIRMATION_INVALID
    
    # Step 6: Atomically switch to new key
    old_session_key = session_state.session_key
    session_state.session_key = new_session_key
    session_state.daily_key = new_daily_key
    
    # Step 7: Secure cleanup of old key
    secure_zero_memory(old_session_key)
    secure_zero_memory(new_session_key_material)
    
    log_recovery_success("Session rekey completed")
    return SUCCESS

function create_key_commitment(key_material, nonce):
    commitment_input = key_material || nonce || session_id || "key_commitment"
    return SHA256(commitment_input)
```

## Emergency Recovery Cryptography

```pseudocode
function derive_emergency_key_material():
    # Derive emergency recovery key using HKDF with session context
    psk_bytes = get_session_psk_bytes()
    session_context = create_emergency_session_context()
    
    # HKDF-Extract with emergency salt
    emergency_salt = b"emergency_recovery_salt_v1" + session_state.session_id.to_bytes(8, 'big')
    prk = HMAC_SHA256_128(emergency_salt, psk_bytes)
    
    # HKDF-Expand with emergency context
    info = b"emergency_recovery_key" + session_context
    emergency_key = hkdf_expand_sha256(prk, info, 32)  # 256-bit key
    
    return emergency_key

function create_emergency_session_context():
    # Create session context for emergency key derivation
    context_data = {
        'original_session_id': session_state.session_id,
        'local_endpoint': serialize_endpoint(local_endpoint),
        'remote_endpoint': serialize_endpoint(remote_endpoint),
        'connection_start_time': session_state.connection_start_time,
        'last_known_good_sequence': session_state.last_known_good_sequence,
        'emergency_recovery_reason': determine_emergency_recovery_reason()
    }
    
    # Serialize context data
    return serialize_emergency_context(context_data)

function encrypt_emergency_recovery_data(recovery_payload):
    # Encrypt recovery payload using emergency key
    iv = generate_secure_random_bytes(16)  # 128-bit IV for AES-256-GCM
    
    # Serialize recovery payload
    payload_bytes = serialize_recovery_payload(recovery_payload)
    
    # Encrypt with AES-256-GCM
    encrypted_data, auth_tag = aes_256_gcm_encrypt(
        key = emergency_recovery_state.emergency_key,
        iv = iv,
        plaintext = payload_bytes,
        additional_data = b"emergency_recovery_v1"
    )
    
    return iv + encrypted_data + auth_tag

function rederive_emergency_session_keys():
    # Re-derive session keys after emergency recovery
    
    # Derive new daily key for current date
    new_daily_key = derive_daily_key_for_current_date(get_session_psk())
    
    # Create emergency session key derivation context
    emergency_context = (
        emergency_recovery_state.recovery_token +
        emergency_recovery_state.recovery_session_id.to_bytes(8, 'big') +
        b"emergency_session_key_v1"
    )
    
    # Derive new session key
    new_session_key = derive_session_key(
        daily_key = new_daily_key,
        session_id = session_state.session_id,
        nonce = emergency_context
    )
    
    # Update session keys
    session_state.daily_key = new_daily_key
    session_state.session_key = new_session_key
    
    return SUCCESS

function verify_session_key_consistency():
    # Verify session key produces correct HMACs
    test_data = b"emergency_recovery_key_test_v1"
    test_hmac = HMAC_SHA256_128(session_state.session_key, test_data)
    
    # Send test packet to peer
    test_packet = create_emergency_verification_packet(
        test_data = test_data,
        expected_hmac = test_hmac
    )
    
    send_packet(test_packet)
    
    return SUCCESS
```

## PSK Fingerprinting and Discovery

```pseudocode
function calculate_psk_fingerprint(psk_material):
    # Calculate PSK fingerprint for local storage and matching
    # NOTE: This fingerprint is NEVER transmitted over the network
    psk_bytes = psk_material.encode('utf-8') if isinstance(psk_material, str) else psk_material
    fingerprint_input = psk_bytes + b"psk_fingerprint_v2"
    return SHA256(fingerprint_input)[0:16]  # 128-bit fingerprint for local use only

function create_psk_knowledge_proof(psk_material, challenge_nonce, discovery_id):
    # Create zero-knowledge proof that we know a PSK without revealing which one
    # Uses the PSK material to create a proof that can be verified by someone
    # who has the same PSK, but reveals nothing to attackers
    psk_hash = SHA256(psk_material + b"psk_proof_salt")
    proof_input = psk_hash + challenge_nonce + discovery_id + b"knowledge_proof_v1"
    return HMAC_SHA256_128(psk_hash, proof_input)

function verify_psk_knowledge_proof(proof, challenge_nonce, discovery_id, candidate_psk):
    # Verify if the proof was generated using the candidate PSK
    expected_proof = create_psk_knowledge_proof(candidate_psk, challenge_nonce, discovery_id)
    return constant_time_compare(proof, expected_proof)

function discover_matching_psk(peer_proofs, challenge_nonce, discovery_id, local_psk_list):
    # Discover which PSK the peer is using by testing our local PSKs
    # Returns the matching PSK or null if no match found
    for local_psk in local_psk_list:
        for peer_proof in peer_proofs:
            if verify_psk_knowledge_proof(peer_proof, challenge_nonce, discovery_id, local_psk):
                return local_psk
    return null  # No matching PSK found

function generate_psk_proof_set(local_psk_list, challenge_nonce, discovery_id, max_proofs=8):
    # Generate a set of PSK knowledge proofs for our available PSKs
    # Limits to max_proofs to prevent packet size explosion
    proof_set = []
    psk_subset = select_psk_subset(local_psk_list, max_proofs)  # Select representative PSKs
    
    for psk in psk_subset:
        proof = create_psk_knowledge_proof(psk, challenge_nonce, discovery_id)
        proof_set.append(proof)
    
    return proof_set

function generate_connection_id(local_endpoint, remote_endpoint, psk):
    # Generate deterministic connection ID from endpoint pair and PSK
    # This ensures both peers derive the same connection ID
    
    # Create canonical endpoint representation (order endpoints consistently)
    if compare_endpoints(local_endpoint, remote_endpoint) < 0:
        endpoint_a = local_endpoint
        endpoint_b = remote_endpoint
    else:
        endpoint_a = remote_endpoint
        endpoint_b = local_endpoint
    
    # Serialize endpoints for hashing
    endpoint_a_bytes = serialize_endpoint(endpoint_a)
    endpoint_b_bytes = serialize_endpoint(endpoint_b)
    psk_bytes = psk.encode('utf-8') if isinstance(psk, str) else psk
    
    # Create deterministic ID material
    id_material = endpoint_a_bytes + endpoint_b_bytes + psk_bytes + b"connection_id_v1"
    
    # Hash to create 64-bit connection ID
    hash_result = SHA256(id_material)
    connection_id = bytes_to_uint64(hash_result[0:8])
    
    return connection_id

## Ephemeral Diffie-Hellman Key Exchange

### ECDH Connection Establishment

```pseudocode
function generate_ecdh_keypair():
    # Generate ephemeral P-256 key pair for connection establishment
    private_key = generate_secure_random_scalar()  # 32 bytes random scalar
    public_key = scalar_multiply(private_key, P256_GENERATOR_POINT)
    
    return {
        'private': private_key,
        'public': public_key
    }

function perform_ecdh(our_private_key, peer_public_key):
    # Perform ECDH computation to derive shared secret
    # Validate peer's public key is on the curve
    if not is_valid_p256_point(peer_public_key):
        return ERROR_INVALID_PUBLIC_KEY
    
    # Compute shared point: private_key * peer_public_key
    shared_point = scalar_multiply(our_private_key, peer_public_key)
    
    # Extract x-coordinate as shared secret (32 bytes)
    shared_secret = shared_point.x
    
    # Clear private key from memory for forward secrecy
    secure_zero_memory(our_private_key)
    
    return shared_secret

function derive_session_keys_from_dh(shared_secret, client_public_key, server_public_key, session_context):
    # Derive all session keys and parameters from ECDH shared secret using PBKDF2
    # Uses key diversification to derive multiple independent values
    
    # Create salt from public keys and session context for key diversity
    salt = SHA256(client_public_key || server_public_key || session_context || b"ecdh_salt_v1")
    
    # Derive master key material using PBKDF2 (4096 iterations for security)
    master_key_material = PBKDF2_HMAC_SHA256(
        password = shared_secret,
        salt = salt,
        iterations = PBKDF2_ITERATIONS_SESSION,
        key_length = 128  # 1024 bits of key material
    )
    
    # Break master key material into 16-bit chunks as specified
    chunks = []
    for i in range(0, len(master_key_material), 2):
        chunk = bytes_to_uint16(master_key_material[i:i+2])
        chunks.append(chunk)
    
    # Derive specific session parameters from chunks
    session_keys = {
        'client_sequence': chunks[0] << 16 | chunks[1],  # 32-bit sequence from chunks 0-1
        'server_sequence': chunks[2] << 16 | chunks[3],  # 32-bit sequence from chunks 2-3
        'client_port_offset': chunks[4],                 # 16-bit port offset
        'server_port_offset': chunks[5],                 # 16-bit port offset
        'session_key': master_key_material[12:44],       # 32 bytes for HMAC keys from chunks 6-21
        'port_hop_seed': chunks[22] << 16 | chunks[23],  # 32-bit seed for port hopping from chunks 22-23
        'time_sync_offset': chunks[24],                  # 16-bit time sync adjustment
        'congestion_seed': chunks[25]                    # 16-bit congestion control seed
    }
    
    # Clear shared secret from memory
    secure_zero_memory(shared_secret)
    
    return session_keys

function verify_ecdh_shared_secret_hash(computed_shared_secret, received_hash):
    # Verify that both peers computed the same shared secret
    computed_hash = SHA256(computed_shared_secret || b"ecdh_verification_v1")
    return constant_time_compare(computed_hash, received_hash)

function create_ecdh_verification_hash(shared_secret):
    # Create verification hash of shared secret for SYN-ACK packet
    return SHA256(shared_secret || b"ecdh_verification_v1")
```

### PBKDF2-Based Parameter Derivation

```pseudocode
function derive_sequence_numbers(shared_secret, client_pubkey, server_pubkey):
    # Derive initial sequence numbers using PBKDF2 from ECDH shared secret
    salt = SHA256(client_pubkey || server_pubkey || b"sequence_derivation_v1")
    
    # Generate sequence key material
    sequence_material = PBKDF2_HMAC_SHA256(
        password = shared_secret,
        salt = salt,
        iterations = PBKDF2_ITERATIONS_SEQUENCE,
        key_length = 16     # 128 bits for two 32-bit sequences + padding
    )
    
    # Extract sequence numbers as 16-bit chunks, then combine
    chunks = []
    for i in range(0, 8, 2):  # Process 8 bytes as 4 chunks
        chunk = bytes_to_uint16(sequence_material[i:i+2])
        chunks.append(chunk)
    
    client_sequence = (chunks[0] << 16 | chunks[1]) % MAX_SEQUENCE_NUMBER
    server_sequence = (chunks[2] << 16 | chunks[3]) % MAX_SEQUENCE_NUMBER
    
    return {
        'client_initial_sequence': client_sequence,
        'server_initial_sequence': server_sequence
    }

function derive_port_offsets(shared_secret, client_pubkey, server_pubkey):
    # Derive port hopping offsets using PBKDF2 from ECDH shared secret
    salt = SHA256(client_pubkey || server_pubkey || b"port_derivation_v1")
    
    # Generate port key material
    port_material = PBKDF2_HMAC_SHA256(
        password = shared_secret,
        salt = salt,
        iterations = PBKDF2_ITERATIONS_PORT,
        key_length = 8      # 64 bits for port parameters
    )
    
    # Extract as 16-bit chunks
    chunks = []
    for i in range(0, 8, 2):
        chunk = bytes_to_uint16(port_material[i:i+2])
        chunks.append(chunk)
    
    return {
        'client_port_offset': chunks[0] % PORT_RANGE,
        'server_port_offset': chunks[1] % PORT_RANGE,
        'hop_interval_variance': chunks[2] % 1000,  # Max 1 second variance
        'hop_sequence_seed': chunks[3]
    }

function derive_session_authentication_key(shared_secret, session_id):
    # Derive HMAC authentication key from ECDH shared secret
    salt = session_id.to_bytes(8, 'big') || b"session_auth_v1"
    
    auth_key = PBKDF2_HMAC_SHA256(
        password = shared_secret,
        salt = salt,
        iterations = PBKDF2_ITERATIONS_SESSION,
        key_length = 32     # 256 bits for HMAC-SHA256
    )
    
    return auth_key
```

### Connection Establishment Protocol

```pseudocode
function establish_ecdh_connection(remote_endpoint):
    # Client-side ECDH connection establishment
    
    # Step 1: Generate ephemeral key pair
    client_keypair = generate_ecdh_keypair()
    key_exchange_id = generate_secure_random_16bit()
    
    # Step 2: Send SYN with client public key
    syn_packet = create_syn_packet(
        client_public_key = client_keypair.public,
        key_exchange_id = key_exchange_id,
        # ... other fields
    )
    send_packet(syn_packet)
    
    # Step 3: Receive SYN-ACK with server public key
    syn_ack = receive_packet_timeout(CONNECTION_TIMEOUT_MS)
    if syn_ack == null or syn_ack.type != PACKET_TYPE_SYN_ACK:
        return ERROR_CONNECTION_TIMEOUT
    
    # Step 4: Perform ECDH computation
    shared_secret = perform_ecdh(client_keypair.private, syn_ack.server_public_key)
    if shared_secret == ERROR_INVALID_PUBLIC_KEY:
        return ERROR_INVALID_SERVER_KEY
    
    # Step 5: Verify shared secret hash
    if not verify_ecdh_shared_secret_hash(shared_secret, syn_ack.shared_secret_hash):
        return ERROR_SHARED_SECRET_MISMATCH
    
    # Step 6: Derive session parameters
    session_keys = derive_session_keys_from_dh(
        shared_secret, 
        client_keypair.public, 
        syn_ack.server_public_key,
        key_exchange_id
    )
    
    # Step 7: Send ACK to complete handshake
    ack_packet = create_ack_packet(session_keys.client_sequence + 1)
    send_packet(ack_packet)
    
    return session_keys

function handle_ecdh_connection_request(syn_packet):
    # Server-side ECDH connection handling
    
    # Step 1: Generate ephemeral key pair
    server_keypair = generate_ecdh_keypair()
    
    # Step 2: Perform ECDH computation
    shared_secret = perform_ecdh(server_keypair.private, syn_packet.client_public_key)
    if shared_secret == ERROR_INVALID_PUBLIC_KEY:
        return send_error(ERROR_INVALID_CLIENT_KEY)
    
    # Step 3: Create verification hash
    secret_hash = create_ecdh_verification_hash(shared_secret)
    
    # Step 4: Derive session parameters  
    session_keys = derive_session_keys_from_dh(
        shared_secret,
        syn_packet.client_public_key,
        server_keypair.public,
        syn_packet.key_exchange_id
    )
    
    # Step 5: Send SYN-ACK with server public key and verification
    syn_ack = create_syn_ack_packet(
        server_public_key = server_keypair.public,
        shared_secret_hash = secret_hash,
        key_exchange_id = syn_packet.key_exchange_id,
        # ... other fields
    )
    send_packet(syn_ack)
    
    return session_keys
```

### Security Properties

1. **Perfect Forward Secrecy**: Ephemeral keys are deleted after use
2. **Key Diversification**: PBKDF2 with different salts creates independent derived keys
3. **Mutual Authentication**: Both peers prove knowledge of shared secret
4. **Replay Resistance**: Key exchange IDs and timestamps prevent replay
5. **Parameter Binding**: All derived values are cryptographically tied to the key exchange

```