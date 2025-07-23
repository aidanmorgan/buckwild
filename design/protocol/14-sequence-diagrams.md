# Protocol Sequence Diagrams and Flows

This document provides comprehensive sequence diagrams illustrating all critical protocol flows and interactions, showing message exchanges, state transitions, and timing relationships between peers during various protocol operations.

## Overview

The sequence diagrams demonstrate the dynamic behavior of the protocol by visualizing the message flows, timing dependencies, and state coordination that occur during connection establishment, data transmission, recovery scenarios, and connection termination. These diagrams serve as essential implementation guides and debugging aids.

## Purpose and Rationale

Sequence diagrams serve essential documentation and implementation functions:

- **Flow Visualization**: Provides clear visual representation of complex protocol interactions and message sequences
- **Implementation Guidance**: Helps developers understand the correct order and timing of protocol operations
- **Debugging Aid**: Enables troubleshooting by showing expected message flows versus actual behavior
- **Protocol Validation**: Allows verification that implementations follow the correct sequence of operations
- **Edge Case Documentation**: Illustrates how the protocol handles various error conditions and recovery scenarios
- **Integration Testing**: Provides test scenarios for validating protocol implementation correctness

The diagrams complement the technical specifications by showing the dynamic behavior and interactions that emerge from the static protocol definitions.

## 1. Connection Establishment Flows

### 1.1 Basic Connection Establishment (No PSK Discovery)

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Phase 1: Initial Handshake
    Client->>Server: SYN (Type 0x01)
    Note right of Client: - Sequence commitment<br/>- Initial windows<br/>- Time offset<br/>- Supported features
    
    Server->>Client: SYN-ACK (Type 0x02)
    Note left of Server: - Server sequence commitment<br/>- Sequence proof (validates client)<br/>- Negotiated features<br/>- Server time offset
    
    Client->>Server: ACK (Type 0x03)
    Note right of Client: - Acknowledges SYN-ACK<br/>- Completes three-way handshake<br/>- Connection established
    
    Note over Client,Server: Connection Ready for Data Transfer
```

### 1.2 Connection Establishment with PSK Discovery

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Phase 1: PSK Discovery
    Client->>Server: DISCOVERY_REQUEST (Type 0x0E, Sub 0x01)
    Note right of Client: - Discovery ID<br/>- PSK count hint<br/>- Challenge nonce<br/>- Cryptographic commitment
    
    Server->>Client: DISCOVERY_RESPONSE (Type 0x0E, Sub 0x02)
    Note left of Server: - Same discovery ID<br/>- PSK commitments<br/>- Response nonce<br/>- Server features
    
    Client->>Server: DISCOVERY_CONFIRM (Type 0x0E, Sub 0x03)
    Note right of Client: - Selected PSK index<br/>- PSK selection proof<br/>- New session ID<br/>- Final commitment
    
    Note over Client,Server: Phase 2: Standard Handshake
    Client->>Server: SYN (Type 0x01)
    Server->>Client: SYN-ACK (Type 0x02)
    Client->>Server: ACK (Type 0x03)
    
    Note over Client,Server: Connection Established with Negotiated PSK
```

### 1.3 Connection Establishment with ECDH Key Exchange

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Phase 1: ECDH Handshake with PSK Authentication
    Client->>Server: SYN (Type 0x01)
    Note right of Client: - Client ECDH Public Key<br/>- PSK Authentication<br/>- Key Exchange ID
    
    Server->>Client: SYN-ACK (Type 0x02)
    Note left of Server: - Server ECDH Public Key<br/>- Shared Secret Verification Hash<br/>- Echo Key Exchange ID
    
    Client->>Server: ACK (Type 0x03)
    Note right of Client: - Connection Complete<br/>- Both peers derive identical:<br/>  • Sequence numbers (PBKDF2)<br/>  • Port offsets (PBKDF2)<br/>  • Session keys (PBKDF2)
    
    Note over Client,Server: Connection with ECDH-Derived Parameters
```

### 1.4 Privacy-Preserving PSK Discovery

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Phase 1: PSI Discovery Request
    Client->>Server: DISCOVERY (Type 0x0E, Sub REQUEST 0x01)
    Note right of Client: - Discovery ID + Session Salt<br/>- Bloom Filter (blinded PSK fingerprints)<br/>- Fingerprint count
    
    Note over Client,Server: Phase 2: Intersection Response
    Server->>Client: DISCOVERY (Type 0x0E, Sub RESPONSE 0x02)
    Note left of Server: - Candidate intersection hashes<br/>- Intersection status<br/>- (Server tests PSKs against Bloom filter)
    
    Note over Client,Server: Phase 3: PSK Selection Confirmation
    Client->>Server: DISCOVERY (Type 0x0E, Sub CONFIRM 0x03)
    Note right of Client: - Selected PSK confirmation hash<br/>- (Client verifies candidates)
    
    Server->>Client: DISCOVERY (Type 0x0E, Sub CONFIRM 0x03)
    Note left of Server: - Final confirmation status<br/>- PSK discovery complete
    
    Note over Client,Server: Proceed to ECDH Connection Establishment
```

## 2. Data Transmission Flows

### 2.1 Normal Data Transmission with Flow Control

```mermaid
sequenceDiagram
    participant Sender
    participant Receiver
    
    Note over Sender,Receiver: Data Transmission Window
    Sender->>Receiver: DATA (Type 0x04, Seq 100)
    Note right of Sender: - Application data<br/>- Flow control info<br/>- Window advertisement
    
    Sender->>Receiver: DATA (Type 0x04, Seq 101)
    Sender->>Receiver: DATA (Type 0x04, Seq 102)
    
    Receiver->>Sender: ACK (Type 0x03, Ack 103)
    Note left of Receiver: - Acknowledges up to 102<br/>- Window update<br/>- Flow control feedback
    
    Sender->>Receiver: DATA (Type 0x04, Seq 103)
    Sender->>Receiver: DATA (Type 0x04, Seq 104)
    
    Note over Sender,Receiver: Continuous data flow with periodic ACKs
```

### 2.2 Data Transmission with Packet Loss and SACK

```mermaid
sequenceDiagram
    participant Sender
    participant Receiver
    
    Sender->>Receiver: DATA (Type 0x04, Seq 100)
    Sender->>X: DATA (Type 0x04, Seq 101)
    Note over Sender,Receiver: Packet 101 lost
    Sender->>Receiver: DATA (Type 0x04, Seq 102)
    Sender->>Receiver: DATA (Type 0x04, Seq 103)
    
    Receiver->>Sender: ACK (Type 0x03, Ack 101, SACK flag set)
    Note left of Receiver: - ACK up to 100<br/>- SACK: received 102-103<br/>- Indicates gap at 101
    
    Note over Sender: Detects loss, retransmits
    Sender->>Receiver: DATA (Type 0x04, Seq 101)
    Note right of Sender: Retransmission of lost packet
    
    Receiver->>Sender: ACK (Type 0x03, Ack 104)
    Note left of Receiver: - Acknowledges all data<br/>- Gap filled, sequence complete
```

### 2.3 Large Data with Fragmentation

```mermaid
sequenceDiagram
    participant Sender
    participant Receiver
    
    Note over Sender: Large data exceeds MTU
    Sender->>Receiver: DATA (Type 0x04, Fragment flag, Frag 0/3)
    Note right of Sender: - Fragment ID: 1234<br/>- Fragment 0 of 3<br/>- First fragment
    
    Sender->>Receiver: DATA (Type 0x04, Fragment flag, Frag 1/3)
    Note right of Sender: - Same Fragment ID<br/>- Fragment 1 of 3<br/>- Middle fragment
    
    Sender->>Receiver: DATA (Type 0x04, Fragment flag, Frag 2/3)
    Note right of Sender: - Same Fragment ID<br/>- Fragment 2 of 3<br/>- Final fragment
    
    Note over Receiver: Reassembles fragments
    Receiver->>Sender: ACK (Type 0x03)
    Note left of Receiver: - Acknowledges complete message<br/>- Fragments successfully reassembled
```

## 3. Port Hopping and Time Synchronization

### 3.1 Normal Port Hopping Operation

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A,Peer B: Time Window N (Port 52432)
    Peer A->>Peer B: DATA (via port 52432)
    Peer B->>Peer A: ACK (via port 52432)
    
    Note over Peer A,Peer B: 500ms Time Window Boundary
    Note over Peer A,Peer B: Both peers calculate new port
    Note over Peer A,Peer B: Time Window N+1 (Port 57891)
    
    Peer A->>Peer B: DATA (via port 57891)
    Peer B->>Peer A: ACK (via port 57891)
    
    Note over Peer A,Peer B: Synchronized port hopping continues
```

### 3.2 Time Synchronization Exchange

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client: Detects time drift
    Client->>Server: CONTROL (Type 0x0C, Sub TIME_SYNC_REQUEST 0x01)
    Note right of Client: - Challenge nonce<br/>- Local timestamp<br/>- Sync request
    
    Note over Server: Records request time
    Server->>Client: CONTROL (Type 0x0C, Sub TIME_SYNC_RESPONSE 0x02)
    Note left of Server: - Same challenge nonce<br/>- Server timestamp<br/>- Peer timestamp echo
    
    Note over Client: Calculates time offset and RTT
    Note over Client,Server: Time synchronization complete
    Note over Client,Server: Port hopping resynchronized
```

## 4. Recovery Scenarios

### 4.1 Time Resynchronization Recovery

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A,Peer B: Time drift detected
    Note over Peer A: Ports out of sync
    
    Peer A->>Peer B: CONTROL (Type 0x0C, Sub TIME_SYNC_REQUEST 0x01)
    Note right of Peer A: - Multiple ports listening<br/>- Emergency sync request
    
    Peer B->>Peer A: CONTROL (Type 0x0C, Sub TIME_SYNC_RESPONSE 0x02)
    Note left of Peer B: - Time sync response<br/>- Accurate timestamps
    
    Note over Peer A: Recalculates time offset
    Note over Peer A,Peer B: Port synchronization restored
    
    Peer A->>Peer B: ACK (Type 0x03)
    Note right of Peer A: Confirms sync successful
```

### 4.2 Sequence Repair Recovery

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Sequence number mismatch detected
    
    Client->>Server: MANAGEMENT (Type 0x0D, Sub REPAIR_REQUEST 0x03)
    Note right of Client: - Repair nonce<br/>- Last known sequence<br/>- Repair window size
    
    Server->>Client: MANAGEMENT (Type 0x0D, Sub REPAIR_RESPONSE 0x04)
    Note left of Server: - Same repair nonce<br/>- Current sequence<br/>- Repair confirmation
    
    Note over Client: Validates sequence repair
    Note over Client,Server: Sequence synchronization restored
    
    Client->>Server: DATA (Type 0x04)
    Note right of Client: Resume normal data flow
```

### 4.3 ECDH-Based Session Rekeying

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A: Authentication failures trigger rekey
    
    Peer A->>Peer B: MANAGEMENT (Type 0x0D, Sub REKEY_REQUEST 0x01)
    Note right of Peer A: - Rekey nonce<br/>- ECDH Public Key<br/>- Cryptographic proof
    
    Peer B->>Peer A: MANAGEMENT (Type 0x0D, Sub REKEY_RESPONSE 0x02)
    Note left of Peer B: - Same rekey nonce<br/>- ECDH Public Key<br/>- Shared secret hash
    
    Note over Peer A,Peer B: Both derive new session keys from ECDH
    Note over Peer A,Peer B: Atomic key switch with forward secrecy
    
    Peer A->>Peer B: DATA (Type 0x04)
    Note right of Peer A: First packet with ECDH-derived key
    
    Peer B->>Peer A: ACK (Type 0x03)
    Note left of Peer B: Confirms new ECDH key works
```

### 4.4 Connection Termination on Recovery Failure

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A,Peer B: Multiple recovery attempts failed
    Note over Peer A: Initiates connection termination
    
    Peer A->>Peer B: RST (Type 0x0B)
    Note right of Peer A: - Termination reason<br/>- Final sequence number
    
    Note over Peer B: Acknowledges termination
    Peer B->>Peer A: RST (Type 0x0B)
    Note left of Peer B: - Confirms termination<br/>- Connection closed
    
    Note over Peer A,Peer B: Connection terminated<br/>Must re-establish to continue
```

## 5. Connection Termination

### 5.1 Graceful Connection Termination

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client: Application closes connection
    Client->>Server: FIN (Type 0x05)
    Note right of Client: - Final sequence number<br/>- Graceful shutdown request
    
    Server->>Client: ACK (Type 0x03)
    Note left of Server: - Acknowledges FIN<br/>- Confirms receipt
    
    Note over Server: Server closes its side
    Server->>Client: FIN (Type 0x05)
    Note left of Server: - Server final sequence<br/>- Bidirectional shutdown
    
    Client->>Server: ACK (Type 0x03)
    Note right of Client: - Final acknowledgment<br/>- Connection fully closed
    
    Note over Client,Server: Both sides in CLOSED state
```

### 5.2 Forceful Connection Reset

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A: Unrecoverable error detected
    Peer A->>Peer B: RST (Type 0x0B)
    Note right of Peer A: - Reset reason code<br/>- Immediate termination<br/>- No further communication
    
    Note over Peer B: Receives RST
    Note over Peer B: Immediately closes connection
    Note over Peer A,Peer B: Connection terminated
    Note over Peer A,Peer B: No acknowledgment required
```

## 6. Error Handling Flows

### 6.1 Authentication Error Recovery

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Peer A->>Peer B: DATA (Type 0x04)
    Note right of Peer A: Packet with invalid HMAC
    
    Note over Peer B: HMAC validation fails
    Peer B->>Peer A: ERROR (Type 0x09)
    Note left of Peer B: - Error code: AUTH_FAILURE<br/>- Error details<br/>- Human readable message
    
    Note over Peer A: Receives auth error
    Peer A->>Peer B: MANAGEMENT (Type 0x0D, Sub REKEY_REQUEST 0x01)
    Note right of Peer A: Attempts ECDH key recovery
    
    Peer B->>Peer A: MANAGEMENT (Type 0x0D, Sub REKEY_RESPONSE 0x02)
    Note left of Peer B: Participates in ECDH rekey
    
    Note over Peer A,Peer B: Authentication restored with new ECDH keys
```

### 6.2 Protocol Error with Recovery

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Peer A->>Peer B: DATA (Type 0x04, Invalid sequence)
    Note right of Peer A: Sequence number out of window
    
    Peer B->>Peer A: ERROR (Type 0x09)
    Note left of Peer B: - Error code: SEQUENCE_ERROR<br/>- Expected sequence range<br/>- Diagnostic information
    
    Note over Peer A: Analyzes error
    Peer A->>Peer B: MANAGEMENT (Type 0x0D, Sub REPAIR_REQUEST 0x03)
    Note right of Peer A: Requests sequence repair
    
    Peer B->>Peer A: MANAGEMENT (Type 0x0D, Sub REPAIR_RESPONSE 0x04)
    Note left of Peer B: Provides current sequence
    
    Peer A->>Peer B: DATA (Type 0x04, Corrected sequence)
    Note right of Peer A: Retransmits with correct sequence
    
    Peer B->>Peer A: ACK (Type 0x03)
    Note left of Peer B: Normal operation resumed
```

## 7. Heartbeat and Keep-Alive

### 7.1 Normal Heartbeat Exchange with Adaptive Networking

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A,Peer B: 30 seconds of idle time
    
    Peer A->>Peer B: HEARTBEAT (Type 0x06)
    Note right of Peer A: - Current time<br/>- Window advertisement<br/>- Delay negotiation data<br/>- Network statistics
    
    Peer B->>Peer A: HEARTBEAT (Type 0x06)
    Note left of Peer B: - Response heartbeat<br/>- Peer network metrics<br/>- Delay parameters<br/>- Connection health
    
    Note over Peer A,Peer B: Connection verified alive
    Note over Peer A,Peer B: Delay parameters negotiated
```

### 7.2 Heartbeat Timeout and Recovery

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A,Peer B: Extended idle period
    
    Peer A->>X: HEARTBEAT (Type 0x06)
    Note over Peer A,Peer B: Heartbeat lost
    
    Note over Peer A: 90 second timeout expires
    Note over Peer A: Assumes connection issues
    
    Peer A->>Peer B: CONTROL (Type 0x0C, Sub TIME_SYNC_REQUEST 0x01)
    Note right of Peer A: - Multiple ports<br/>- Connection probe<br/>- Time sync request
    
    Peer B->>Peer A: CONTROL (Type 0x0C, Sub TIME_SYNC_RESPONSE 0x02)
    Note left of Peer B: Connection still alive
    
    Note over Peer A,Peer B: Connection and timing restored
```

## 8. Recovery Escalation Framework

### 8.1 Complete Recovery Escalation Sequence

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A,Peer B: Initial problem detected
    
    Note over Peer A,Peer B: Level 1: Time Resynchronization
    Peer A->>Peer B: CONTROL (Type 0x0C, Sub TIME_SYNC_REQUEST 0x01)
    Peer B->>Peer A: CONTROL (Type 0x0C, Sub TIME_SYNC_RESPONSE 0x02)
    
    Note over Peer A: Time sync failed
    Note over Peer A: Escalate to Level 2
    
    Note over Peer A,Peer B: Level 2: Sequence Repair
    Peer A->>Peer B: MANAGEMENT (Type 0x0D, Sub REPAIR_REQUEST 0x03)
    Peer B->>Peer A: ERROR (Type 0x09)
    Note left of Peer B: Sequence repair failed
    
    Note over Peer A: Sequence repair failed
    Note over Peer A: Escalate to Level 3
    
    Note over Peer A,Peer B: Level 3: ECDH Session Rekeying
    Peer A->>Peer B: MANAGEMENT (Type 0x0D, Sub REKEY_REQUEST 0x01)
    Peer B->>Peer A: MANAGEMENT (Type 0x0D, Sub REKEY_RESPONSE 0x02)
    
    Note over Peer A,Peer B: ECDH rekey successful
    Note over Peer A,Peer B: Session fully restored with forward secrecy
    
    Peer A->>Peer B: DATA (Type 0x04)
    Peer B->>Peer A: ACK (Type 0x03)
    
    Note over Peer A,Peer B: Normal operation resumed
```

### 8.2 Recovery Attempt Exhaustion

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A: Maximum recovery attempts reached
    Note over Peer A: All recovery levels have failed
    
    Peer A->>Peer B: RST (Type 0x0B)
    Note right of Peer A: - Reset reason: RECOVERY_EXHAUSTED<br/>- Immediate termination<br/>- Session unrecoverable
    
    Note over Peer B: Receives RST
    Note over Peer B: Clears session state
    
    Note over Peer A,Peer B: Session terminated
    Note over Peer A,Peer B: New connection required
```

## 9. Advanced Fragmentation Scenarios

### 9.1 Fragment Timeout and Retransmission

```mermaid
sequenceDiagram
    participant Sender
    participant Receiver
    
    Sender->>Receiver: DATA (Fragment 0/3, ID 1234)
    Sender->>X: DATA (Fragment 1/3, ID 1234)
    Note over Sender,Receiver: Fragment 1 lost
    Sender->>Receiver: DATA (Fragment 2/3, ID 1234)
    
    Note over Receiver: 30 second timeout expires
    Note over Receiver: Fragment 1 missing
    
    Receiver->>Sender: ERROR (Type 0x09)
    Note left of Receiver: - Error: FRAGMENT_TIMEOUT<br/>- Fragment ID: 1234<br/>- Missing fragment bitmap
    
    Note over Sender: Retransmit missing fragment
    Sender->>Receiver: DATA (Fragment 1/3, ID 1234)
    Note right of Sender: Retransmission of lost fragment
    
    Note over Receiver: All fragments received
    Note over Receiver: Reassembly complete
    
    Receiver->>Sender: ACK (Type 0x03)
    Note left of Receiver: Acknowledges complete message
```

### 9.2 Fragment Overlap Attack Detection

```mermaid
sequenceDiagram
    participant Attacker
    participant Victim
    
    Attacker->>Victim: DATA (Fragment 0/3, ID 5678, Offset 0-500)
    Note right of Attacker: Normal first fragment
    
    Attacker->>Victim: DATA (Fragment 1/3, ID 5678, Offset 400-900)
    Note right of Attacker: Overlapping fragment attack
    
    Note over Victim: Detects overlap
    Note over Victim: Offset 400-500 overlap detected
    
    Victim->>Attacker: ERROR (Type 0x09)
    Note left of Victim: - Error: FRAGMENT_OVERLAP<br/>- Attack detected<br/>- Fragment discarded
    
    Note over Victim: Drops entire fragment set
    Note over Victim: Security violation logged
```

## 10. Flow Control and Congestion Management

### 10.1 Zero Window Probing

```mermaid
sequenceDiagram
    participant Sender
    participant Receiver
    
    Note over Receiver: Receive buffer full
    
    Receiver->>Sender: ACK (Type 0x03, Window=0)
    Note left of Receiver: - Zero window advertisement<br/>- Flow control stop
    
    Note over Sender: Window closed
    Note over Sender: Stop data transmission
    
    Note over Sender: 5 second probe timer expires
    Sender->>Receiver: DATA (Type 0x04, 1 byte probe)
    Note right of Sender: - Zero window probe<br/>- Single byte payload<br/>- Tests receiver readiness
    
    Receiver->>Sender: ACK (Type 0x03, Window=0)
    Note left of Receiver: Still no buffer space
    
    Note over Sender: Continue probing every 5 seconds
    
    Note over Receiver: Application reads data
    Note over Receiver: Buffer space available
    
    Receiver->>Sender: ACK (Type 0x03, Window=8192)
    Note left of Receiver: - Window opened<br/>- Buffer space available
    
    Sender->>Receiver: DATA (Type 0x04)
    Note right of Sender: Resume normal transmission
```

### 10.2 Flow Control Deadlock Resolution

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A,Peer B: Both sides have zero windows
    
    Peer A->>Peer B: ACK (Type 0x03, Window=0)
    Peer B->>Peer A: ACK (Type 0x03, Window=0)
    
    Note over Peer A,Peer B: Deadlock detected
    
    Note over Peer A: Forced window update
    Peer A->>Peer B: ACK (Type 0x03, Window=1024)
    Note right of Peer A: - Emergency window opening<br/>- Minimum viable window<br/>- Deadlock prevention
    
    Peer B->>Peer A: DATA (Type 0x04, Small payload)
    Note left of Peer B: Sends minimum data
    
    Note over Peer A: Processes data
    Note over Peer A: Frees buffer space
    
    Peer A->>Peer B: ACK (Type 0x03, Window=4096)
    Note right of Peer A: Normal window advertisement
    
    Note over Peer A,Peer B: Flow control restored
```

## 11. Multi-Connection Management

### 11.1 Parallel Connection Establishment with Collision Avoidance

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Connection 1 Establishment
    Client->>Server: SYN (Session ID: 1234, ECDH offset derived)
    Server->>Client: SYN-ACK (Session ID: 1234)
    Client->>Server: ACK (Session ID: 1234)
    
    Note over Client,Server: Connection 2 Establishment (Different offset)
    Client->>Server: SYN (Session ID: 5678, Different ECDH offset)
    Server->>Client: SYN-ACK (Session ID: 5678)
    Client->>Server: ACK (Session ID: 5678)
    
    Note over Client,Server: Both connections active
    Note over Client,Server: Different ECDH-derived port ranges prevent collisions
    
    Client->>Server: DATA (Connection 1, Port range A)
    Client->>Server: DATA (Connection 2, Port range B)
    Server->>Client: ACK (Connection 1, Port range A)
    Server->>Client: ACK (Connection 2, Port range B)
```

### 11.2 Connection Port Collision Detection and Resolution

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Connection 1 established (uses full port range 1024-65535)
    
    Note over Client: Start Connection 2
    Client->>Server: SYN (Connection 2, port 27234)
    Note right of Client: - Different session ID<br/>- Full port range available<br/>- No collision concerns
    
    Note over Server: Routes by session ID
    Server->>Client: SYN-ACK (Connection 2, port 27234)
    Note left of Server: - Session ID determines routing<br/>- Port collisions irrelevant<br/>- Simplified connection handling
    
    Client->>Server: ACK (Connection 2, port 27234)
    
    Note over Client,Server: Both connections active
    Note over Client,Server: No port collisions
```

## 12. Security Attack Scenarios

### 12.1 Authentication Failure Cascade and Auto-Rekey

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Peer A->>Peer B: DATA (Type 0x04, Invalid HMAC)
    Note right of Peer A: Authentication failure 1
    
    Note over Peer B: HMAC verification fails
    Peer B->>Peer A: ERROR (Type 0x09)
    Note left of Peer B: - Error: AUTH_FAILURE<br/>- HMAC mismatch<br/>- Failure count: 1
    
    Peer A->>Peer B: DATA (Type 0x04, Invalid HMAC)
    Note right of Peer A: Authentication failure 2
    
    Peer B->>Peer A: ERROR (Type 0x09)
    Note left of Peer B: - Error: AUTH_FAILURE<br/>- Failure count: 2<br/>- Warning threshold
    
    Peer A->>Peer B: DATA (Type 0x04, Invalid HMAC)
    Note right of Peer A: Authentication failure 3
    
    Note over Peer B: Threshold exceeded
    Note over Peer B: Trigger automatic ECDH rekey
    
    Peer B->>Peer A: MANAGEMENT (Type 0x0D, Sub REKEY_REQUEST 0x01)
    Note left of Peer B: - Automatic ECDH rekey triggered<br/>- Security threshold exceeded<br/>- Key compromise suspected
    
    Peer A->>Peer B: MANAGEMENT (Type 0x0D, Sub REKEY_RESPONSE 0x02)
    
    Note over Peer A,Peer B: New session key established with ECDH
    
    Peer A->>Peer B: DATA (Type 0x04, Valid HMAC)
    Peer B->>Peer A: ACK (Type 0x03)
    
    Note over Peer A,Peer B: Authentication restored with forward secrecy
```

### 12.2 Replay Attack Detection and Prevention

```mermaid
sequenceDiagram
    participant Attacker
    participant Victim
    
    Note over Attacker: Captures valid packet
    
    Victim->>Attacker: DATA (Type 0x04, Timestamp T1, Seq 100)
    Note left of Victim: Original valid packet
    
    Note over Attacker: Replays captured packet
    Attacker->>Victim: DATA (Type 0x04, Timestamp T1, Seq 100)
    Note right of Attacker: - Same timestamp T1<br/>- Same sequence 100<br/>- Replay attempt
    
    Note over Victim: Detects replay
    Note over Victim: - Timestamp T1 outside window<br/>- Sequence 100 already seen<br/>- Anti-replay triggered
    
    Victim->>Attacker: ERROR (Type 0x09)
    Note left of Victim: - Error: REPLAY_DETECTED<br/>- Packet discarded<br/>- Security violation logged
    
    Note over Victim: Increases replay threshold
    Note over Victim: Strengthens timestamp validation
```

## 13. PSK Discovery Failure Scenarios

### 13.1 PSK Discovery No Common Key Found

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Client->>Server: DISCOVERY_REQUEST (Type 0x0E, Sub 0x01)
    Note right of Client: - Discovery ID<br/>- Client PSK commitments<br/>- Challenge nonce
    
    Server->>Client: DISCOVERY_RESPONSE (Type 0x0E, Sub 0x02)
    Note left of Server: - Empty PSK commitment list<br/>- No matching PSKs found<br/>- Error indication
    
    Note over Client: No compatible PSKs
    Client->>Server: ERROR (Type 0x09)
    Note right of Client: - Error: NO_COMMON_PSK<br/>- Connection terminated<br/>- No further attempts
    
    Note over Client,Server: Connection establishment failed
```

### 13.2 PSK Enumeration Attack Detection

```mermaid
sequenceDiagram
    participant Attacker
    participant Server
    
    Note over Attacker: Multiple rapid discovery attempts
    
    Attacker->>Server: DISCOVERY_REQUEST (Type 0x0E, Sub 0x01)
    Note right of Attacker: Attempt 1: Invalid PSK probe
    
    Attacker->>Server: DISCOVERY_REQUEST (Type 0x0E, Sub 0x01)
    Note right of Attacker: Attempt 2: Different PSK probe
    
    Attacker->>Server: DISCOVERY_REQUEST (Type 0x0E, Sub 0x01)
    Note right of Attacker: Attempt 3: Another PSK probe
    
    Note over Server: Detects enumeration pattern
    Note over Server: Rate limiting triggered
    
    Server->>Attacker: ERROR (Type 0x09)
    Note left of Server: - Error: RATE_LIMITED<br/>- 5 minute block duration<br/>- No further responses
    
    Note over Server: IP blocked for enumeration
```

## 14. Network Adaptation and Performance Optimization

### 14.1 Delay Parameter Negotiation via Enhanced Heartbeat

```mermaid
sequenceDiagram
    participant Peer A
    participant Peer B
    
    Note over Peer A,Peer B: Network conditions changing
    
    Peer A->>Peer B: HEARTBEAT (Type 0x06)
    Note right of Peer A: - Current delay window: 4<br/>- Measured jitter: 150ms<br/>- Loss rate: 2%<br/>- Propose window: 6
    
    Peer B->>Peer A: HEARTBEAT (Type 0x06)
    Note left of Peer B: - Current delay window: 4<br/>- Measured jitter: 200ms<br/>- Loss rate: 3%<br/>- Agree window: 6
    
    Note over Peer A,Peer B: Both agree on window size 6
    Note over Peer A,Peer B: Apply new delay parameters
    
    Note over Peer A,Peer B: Continue monitoring performance
    
    Peer A->>Peer B: HEARTBEAT (Type 0x06)
    Note right of Peer A: - Window 6 performance good<br/>- Jitter reduced: 100ms<br/>- Loss rate: 1%<br/>- Maintain current settings
    
    Note over Peer A,Peer B: Optimal delay parameters achieved
```

### 14.2 MTU Discovery and Dynamic Fragmentation

```mermaid
sequenceDiagram
    participant Sender
    participant Network
    participant Receiver
    
    Note over Sender: Large message (2000 bytes)
    Note over Sender: Assume MTU 1500
    
    Sender->>Network: DATA (1400 bytes, no fragment flag)
    Note right of Sender: Single packet attempt
    
    Network->>Sender: ICMP Fragmentation Needed (MTU 1200)
    Note over Network: Path MTU smaller than expected
    
    Note over Sender: Update MTU to 1200
    Note over Sender: Enable fragmentation
    
    Sender->>Receiver: DATA (Fragment 0/2, 1100 bytes)
    Sender->>Receiver: DATA (Fragment 1/2, 900 bytes)
    
    Note over Receiver: Reassemble fragments
    Receiver->>Sender: ACK (Type 0x03)
    
    Note over Sender,Receiver: Adaptive fragmentation established
```
