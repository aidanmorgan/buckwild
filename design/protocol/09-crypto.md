# Cryptography Specifications

## Overview

This document defines the comprehensive cryptographic framework that secures all protocol communications, including message authentication, key derivation, and emergency recovery procedures. The cryptographic design ensures confidentiality, integrity, authenticity, and forward secrecy throughout the protocol lifecycle.

## Purpose and Rationale

The cryptographic system serves multiple security objectives:

- **Message Authentication**: Ensures all packets are authentic and unmodified using HMAC
- **Key Management**: Provides secure key derivation and rotation mechanisms
- **Forward Secrecy**: Protects past communications even if long-term keys are compromised
- **Emergency Recovery**: Enables secure session recovery while maintaining security properties
- **Anti-Replay Protection**: Prevents replay attacks through timestamp validation and sequence numbers

The design uses proven cryptographic primitives (HMAC-SHA256, HKDF) and follows security best practices, providing strong security guarantees while maintaining performance efficiency.

## Key Concepts

- **Session Key Derivation**: HKDF-based key generation from pre-shared keys and session context
- **Daily Key Rotation**: Automatic key rotation based on UTC date for enhanced security
- **HMAC Authentication**: Message authentication codes that verify packet integrity and authenticity
- **Emergency Key Material**: Special key derivation for secure recovery operations
- **Connection Separation**: Cryptographic isolation between multiple parallel connections

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
    # Create zero-knowledge proof that sequence matches commitment without revealing sequence
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

## Cryptographic Utilities and PSK Fingerprinting

```pseudocode
function calculate_psk_fingerprint():
    # Calculate PSK fingerprint for authentication verification
    psk_bytes = get_session_psk_bytes()
    fingerprint_input = psk_bytes + b"psk_fingerprint_v1"
    return SHA256(fingerprint_input)[0:16]  # 128-bit fingerprint

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
```