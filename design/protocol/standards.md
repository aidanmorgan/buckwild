## Naming Conventions and Standards

Standardized naming conventions used throughout the protocol documentation and implementation to ensure consistency, readability, and maintainability.

### General Principles

#### 1. Clarity Over Brevity
- Use descriptive names that clearly indicate purpose
- Avoid abbreviations unless they are widely understood
- Prefer `sequence_number` over `seq_num`
- Prefer `authentication_failed` over `auth_fail`

#### 2. Consistency Across Documents
- Use identical names for the same concepts across all documents
- Maintain consistent patterns for similar operations
- Follow established prefixes and suffixes

#### 3. Type-Based Naming
- Functions use verbs indicating actions
- Variables use nouns indicating data
- Constants use descriptive names indicating values
- Boolean functions/variables use `is_`, `has_`, `can_` prefixes

### Naming Convention Rules

#### Functions
**Format**: `snake_case` with descriptive verbs

**Patterns**:
- **Calculation functions**: `calculate_*`
  - `calculate_time_offset()`
  - `calculate_port_with_offset()`
  - `calculate_sequence_proof()`

- **Derivation functions**: `derive_*`
  - `derive_session_key()`
  - `derive_daily_key()`
  - `derive_connection_offset()`

- **Generation functions**: `generate_*`
  - `generate_secure_random_32bit()`
  - `generate_new_session_id()`
  - `generate_emergency_recovery_credentials()`

- **Validation functions**: `validate_*` or `verify_*`
  - `validate_packet_hmac()`
  - `verify_time_synchronization()`
  - `validate_sequence_negotiation_security()`

- **Detection functions**: `detect_*`
  - `detect_time_drift()`
  - `detect_sequence_mismatch()`
  - `detect_authentication_failures()`

- **Processing functions**: `process_*`
  - `process_time_sync_request()`
  - `process_emergency_response_packet()`
  - `process_discovery_confirm()`

- **Boolean query functions**: `is_*`, `has_*`, `can_*`
  - `is_sequence_valid()`
  - `has_valid_timestamp()`
  - `can_perform_recovery()`

#### Variables and Parameters
**Format**: `snake_case` with descriptive nouns

**Common Patterns**:
- **Session data**: `session_*` (session_state, session_id, session_key)
- **Time data**: `*_time*` or `*_timestamp` (current_time, local_timestamp, time_offset)
- **Sequence data**: `sequence_*` or `*_sequence` (sequence_number, expected_sequence)
- **Recovery data**: `recovery_*` (recovery_state, recovery_attempts)
- **Buffer data**: Specific buffer types (reassembly_buffers, reorder_buffer, send_buffer)

#### Constants
**Format**: `UPPER_CASE` with underscores

**Common Patterns**:
- **Packet types**: `PACKET_TYPE_*` (PACKET_TYPE_SYN, PACKET_TYPE_DATA)
- **Packet sub-types**: `*_SUB_*` (CONTROL_SUB_TIME_SYNC_REQUEST)
- **Error codes**: `ERROR_*` (ERROR_SUCCESS, ERROR_AUTHENTICATION_FAILED)
- **Time constants**: `*_MS`, `*_TIMEOUT_MS` (HOP_INTERVAL_MS, HEARTBEAT_TIMEOUT_MS)
- **Size constants**: `*_SIZE`, `MAX_*`, `MIN_*` (HEADER_SIZE, MAX_FRAGMENTS)

### Implementation Guidelines

- Use consistent naming in comments matching the code
- Reference constants by their exact names
- Use the same terminology across documentation and comments
- Parameter names should match usage within functions