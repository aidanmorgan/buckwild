# Sequence Number Negotiation Specification

## Overview

This document defines the sequence number negotiation mechanisms that establish secure, unpredictable initial sequence numbers for new connections. The negotiation process uses zero-knowledge proofs to prevent sequence prediction attacks while ensuring both peers can agree on starting sequence values.

## Purpose and Rationale

Sequence number negotiation serves critical security and reliability functions:

- **Attack Prevention**: Prevents sequence number prediction attacks that could enable packet injection or hijacking
- **Fair Negotiation**: Ensures neither peer can manipulate the other's sequence number choice through zero-knowledge commitments
- **Replay Protection**: Establishes unpredictable starting points that prevent replay attacks across sessions
- **Synchronization**: Ensures both peers agree on the initial sequence numbers before data transmission begins
- **Security Proofs**: Uses cryptographic commitments and proofs to validate sequence number choices without early revelation

The zero-knowledge approach ensures that sequence numbers remain secret during negotiation, preventing prediction while allowing both peers to verify the integrity of the negotiation process.

## Key Concepts

- **Zero-Knowledge Commitments**: Cryptographic commitments that hide sequence numbers during negotiation
- **Commitment-Reveal Protocol**: Two-phase process where peers commit to values before revealing them
- **Sequence Validation**: Cryptographic proofs that verify sequence numbers match their commitments
- **Wraparound Handling**: Mechanisms to handle sequence number overflow and wraparound scenarios
- **Negotiation Phases**: Structured phases (commit, reveal, confirm) that ensure secure and fair negotiation

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

## Zero-Knowledge Sequence Number Exchange

The protocol uses zero-knowledge proofs to negotiate initial sequence numbers without revealing the actual values until both peers have committed to their choices. This prevents sequence number prediction attacks and ensures fair negotiation.

## Sequence Negotiation Protocol

```pseudocode
# Sequence number negotiation phases
SEQ_NEG_PHASE_COMMIT = 1     # Commitment phase
SEQ_NEG_PHASE_REVEAL = 2     # Reveal phase  
SEQ_NEG_PHASE_CONFIRM = 3    # Confirmation phase

function negotiate_sequence_numbers(peer_connection):
    # Phase 1: Commitment
    local_sequence = generate_secure_random_32bit()
    local_nonce = generate_secure_random_16bit()
    
    # Create commitment using secure hash
    commitment_input = local_sequence || local_nonce || session_id
    local_commitment = SHA256(commitment_input)[0:4]  # First 32 bits
    
    # Send commitment
    commit_packet = create_sequence_neg_packet(
        phase = SEQ_NEG_PHASE_COMMIT,
        commitment = local_commitment,
        nonce = local_nonce,
        proof = 0
    )
    send_packet(commit_packet)
    
    # Receive peer commitment
    peer_commit_packet = receive_packet_timeout(SEQUENCE_NEGOTIATION_TIMEOUT_MS)
    if peer_commit_packet == null or peer_commit_packet.phase != SEQ_NEG_PHASE_COMMIT:
        return ERROR_SEQUENCE_NEGOTIATION_FAILED
    
    # Phase 2: Reveal
    reveal_packet = create_sequence_neg_packet(
        phase = SEQ_NEG_PHASE_REVEAL,
        commitment = local_sequence,  # Reveal actual sequence
        nonce = local_nonce,
        proof = calculate_sequence_proof(local_sequence, local_nonce, peer_commit_packet.commitment)
    )
    send_packet(reveal_packet)
    
    # Receive peer reveal
    peer_reveal_packet = receive_packet_timeout(SEQUENCE_NEGOTIATION_TIMEOUT_MS)
    if peer_reveal_packet == null or peer_reveal_packet.phase != SEQ_NEG_PHASE_REVEAL:
        return ERROR_SEQUENCE_NEGOTIATION_FAILED
    
    # Verify peer's commitment
    peer_commitment_check = SHA256(peer_reveal_packet.commitment || peer_reveal_packet.nonce || session_id)[0:4]
    if peer_commitment_check != peer_commit_packet.commitment:
        return ERROR_SEQUENCE_PROOF_INVALID
    
    # Phase 3: Confirmation
    confirmation_proof = calculate_confirmation_proof(local_sequence, peer_reveal_packet.commitment)
    confirm_packet = create_sequence_neg_packet(
        phase = SEQ_NEG_PHASE_CONFIRM,
        commitment = local_commitment,
        nonce = local_nonce,
        proof = confirmation_proof
    )
    send_packet(confirm_packet)
    
    # Receive peer confirmation
    peer_confirm_packet = receive_packet_timeout(SEQUENCE_NEGOTIATION_TIMEOUT_MS)
    if peer_confirm_packet == null or peer_confirm_packet.phase != SEQ_NEG_PHASE_CONFIRM:
        return ERROR_SEQUENCE_NEGOTIATION_FAILED
    
    # Verify final proof
    if not verify_confirmation_proof(peer_confirm_packet.proof, peer_reveal_packet.commitment, local_sequence):
        return ERROR_SEQUENCE_PROOF_INVALID
    
    # Negotiation successful
    session_state.local_sequence = local_sequence
    session_state.peer_sequence = peer_reveal_packet.commitment
    
    return SUCCESS

function calculate_sequence_proof(sequence, nonce, peer_commitment):
    # Create zero-knowledge proof that sequence matches commitment without revealing sequence
    proof_input = sequence || nonce || peer_commitment || session_id
    return HMAC_SHA256_128(session_key, proof_input)[0:4]

function calculate_confirmation_proof(local_sequence, peer_sequence):
    # Final confirmation that both parties have valid sequences
    confirmation_input = min(local_sequence, peer_sequence) || max(local_sequence, peer_sequence) || session_id
    return HMAC_SHA256_128(session_key, confirmation_input)[0:4]

function verify_confirmation_proof(proof, peer_sequence, local_sequence):
    expected_proof = calculate_confirmation_proof(local_sequence, peer_sequence)
    return constant_time_compare(proof, expected_proof)
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

## SEQUENCE_NEG Packet Structure

```pseudocode
SEQUENCE_NEG Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
+-----------------------------------+
|    Negotiation Phase (8-bit)     |
+-----------------------------------+
|    Sequence Commitment (32-bit)  |
+-----------------------------------+
|      Sequence Proof (32-bit)     |
+-----------------------------------+
|      Challenge Nonce (32-bit)    |
+-----------------------------------+
|        Reserved (24-bit)         |
+-----------------------------------+

Field Definitions:
- Common Header (64 bytes): Standard header with SYN flag set
- Negotiation Phase (8-bit): Phase of sequence negotiation (COMMIT=1, REVEAL=2, CONFIRM=3)
- Sequence Commitment (32-bit): Zero-knowledge commitment to sequence number (4 bytes)
- Sequence Proof (32-bit): Zero-knowledge proof for sequence validation (4 bytes)
- Challenge Nonce (32-bit): Challenge nonce for commitment verification (4 bytes)
- Reserved (24-bit): Always 0x000000 (3 bytes)

Total SEQUENCE_NEG Packet Size: 64 + 16 = 80 bytes
```

## SYN Packet Zero-Knowledge Fields

```pseudocode
Field Definitions:
- Common Header (64 bytes): Standard header with SYN flag set
- Sequence Commitment (32-bit): Zero-knowledge commitment to initial sequence number (4 bytes)
- Initial Congestion Window (16-bit): Initial congestion window size (2 bytes)
- Initial Receive Window (16-bit): Initial receive window size (2 bytes)
- Time Offset (32-bit): Client's time offset from epoch (4 bytes)
- Supported Features (16-bit): Bitmap of supported features (2 bytes)
- Sequence Nonce (16-bit): Nonce for sequence number commitment (2 bytes)
```

## SYN-ACK Packet Zero-Knowledge Fields

```pseudocode
Field Definitions:
- Common Header (64 bytes): Standard header with SYN and ACK flags set
- Sequence Commitment (32-bit): Zero-knowledge commitment to server's initial sequence number (4 bytes)
- Sequence Proof (32-bit): Zero-knowledge proof validating client's sequence commitment (4 bytes)
- Initial Congestion Window (16-bit): Initial congestion window size (2 bytes)
- Initial Receive Window (16-bit): Initial receive window size (2 bytes)
- Time Offset (32-bit): Server's time offset from epoch (4 bytes)
- Negotiated Features (16-bit): Final feature bitmap (2 bytes)
- Sequence Nonce (16-bit): Nonce for server's sequence number commitment (2 bytes)
```

## PSK Discovery with Zero-Knowledge Proofs

### DISCOVERY Packet (Type 0x0E)
```pseudocode
DISCOVERY Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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
- Common Header (64 bytes): Standard header
- Discovery ID (64-bit): Unique identifier for this discovery session
- PSK Hint (32-bit): Hint about which PSK to use (may be obfuscated)
- Challenge Nonce (64-bit): Random challenge for commitment
- Initiator Features (16-bit): Bitmap of supported features
- Reserved (16-bit): Always 0x0000
- Commitment (128-bit): Cryptographic commitment (using challenge nonce)

Total DISCOVERY Packet Size: 64 + 20 + 16 = 100 bytes
```

### DISCOVERY Packet with RESPONSE Sub-Type (Type 0x0E, Sub-Type 0x02)
```pseudocode
DISCOVERY_RESPONSE Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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
- Common Header (64 bytes): Standard header
- Discovery ID (64-bit): Matching discovery session identifier
- PSK Hint (32-bit): Hint about which PSK to use
- Response Nonce (64-bit): Random nonce for response
- Challenge Echo (64-bit): Echo of received challenge nonce
- PSK Commitment (64-bit): PSK range commitment
- Responder Features (16-bit): Bitmap of supported features
- Reserved (16-bit): Always 0x0000
- Commitment (128-bit): Cryptographic commitment (using response nonce)

Total DISCOVERY_RESPONSE Packet Size: 64 + 36 + 16 = 116 bytes
```

### DISCOVERY Packet with CONFIRM Sub-Type (Type 0x0E, Sub-Type 0x03)
```pseudocode
DISCOVERY_CONFIRM Packet Structure (Big-Endian):
+-----------------------------------+
|         Common Header             |
|           (64 bytes)             |
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
- Common Header (64 bytes): Standard header
- Discovery ID (64-bit): Matching discovery session identifier
- PSK ID (32-bit): Selected PSK identifier
- Confirmation Nonce (64-bit): Final confirmation nonce
- Challenge Proof (64-bit): Proof of challenge response
- PSK Selection Commitment (64-bit): PSK selection commitment
- Session ID (64-bit): New session identifier for communication
- Reserved (16-bit): Always 0x0000
- Commitment (128-bit): Cryptographic commitment (using both nonces)

Total DISCOVERY_CONFIRM Packet Size: 64 + 36 + 16 = 116 bytes
```

## Key Commitment Functions

```pseudocode
function create_key_commitment(key_material, nonce):
    commitment_input = key_material || nonce || session_id || "key_commitment"
    return SHA256(commitment_input)
```

## Zero-Knowledge Proof Error Handling

```pseudocode
function handle_zkp_error(error_details):
    # Handle zero-knowledge proof errors
    if error_recovery_state['retry_count'] < MAX_RETRY_ATTEMPTS:
        # Retry with new challenge
        retry_zero_knowledge_proof()
    else:
        transition_to(ERROR)
```

## Zero-Knowledge Constants

```pseudocode
// Discovery and zero-knowledge proof constants
MAX_PSK_COUNT = 256                     // Maximum number of PSKs per peer
DISCOVERY_TIMEOUT_MS = 10000            // Discovery process timeout (10 seconds)
DISCOVERY_RETRY_COUNT = 3               // Maximum discovery retry attempts
PEDERSEN_COMMITMENT_SIZE = 64           // Size of Pedersen commitment in bytes
DISCOVERY_CHALLENGE_SIZE = 32           // Size of challenge nonce in bytes
PSK_ID_LENGTH = 32                      // Length of PSK identifier

// Sequence negotiation constants
SEQUENCE_NEGOTIATION_TIMEOUT_MS = 10000  // Sequence number negotiation timeout
SEQUENCE_COMMITMENT_SIZE = 32            // Size of sequence number commitment in bytes
SEQUENCE_NONCE_SIZE = 16                 // Size of sequence negotiation nonce in bytes

// Error codes
ERROR_ZERO_KNOWLEDGE_PROOF_FAILED = 0x14
```