# Tenant PSK Management Module

## Overview

This module implements per-tenant PSK (Pre-Shared Key) management for the Buckwild multi-tenant frequency hopping network protocol. It provides cryptographic isolation between tenants through tenant-aware key derivation and secure PSK storage.

## Index

| File | Contents (WHAT) | Read When (WHEN) |
| ---- | --------------- | ---------------- |
| `mod.rs` | Module exports, public API | Understanding module structure |
| `tenant_id.rs` | TenantId newtype with timestamp+counter format | Working with tenant identifiers |
| `psk_store.rs` | Per-tenant PSK storage with DashMap, fingerprints, daily keys | Implementing PSK management |
| `key_derivation.rs` | Tenant-aware HKDF and PBKDF2 key derivation | Deriving session or daily keys |

## Key Components

### TenantId

64-bit identifier combining 48-bit timestamp (ms since epoch) and 16-bit counter for:
- Uniqueness: 65,536 tenants per millisecond capacity
- Temporal ordering: Natural chronological sorting
- Collision avoidance: Global atomic counter

### TenantPskStore

Per-tenant PSK collection providing:
- Lock-free concurrent access via DashMap
- PSK limit: 256 PSKs per tenant (protocol specification)
- Daily key derivation with caching
- PSK fingerprints for privacy-preserving discovery
- Secure memory zeroing via Drop trait

### Key Derivation

Tenant-aware cryptographic functions:
- `derive_session_keys_with_tenant_context()`: PBKDF2-HMAC-SHA256 with tenant ID in salt
- `derive_daily_key_with_tenant_context()`: HKDF-SHA256 with tenant ID in info string

## Security Properties

### Cryptographic Isolation

- **Session keys**: Tenant ID embedded in PBKDF2 salt ensures different tenants derive different session keys from same ECDH shared secret
- **Daily keys**: Tenant ID in HKDF info string ensures same PSK produces different daily keys per tenant
- **PSK fingerprints**: SHA-256 hash for privacy-preserving discovery without revealing PSK material

### Memory Security

- `SecureBytes` wrapper for PSK material with automatic zeroing
- `DailyKey` implements Drop for secure cleanup
- `TenantPsk` Drop trait ensures cleanup on removal

## Usage Example

```rust
use buckwild_common::tenant::{TenantId, TenantPskStore, TenantPsk};

// Create tenant
let tenant_id = TenantId::new()?;

// Create PSK store
let store = TenantPskStore::new(tenant_id);

// Add PSK
let psk_material = vec![0x42; 32]; // 256-bit PSK
let psk = TenantPsk::new("psk-1".to_string(), &psk_material, tenant_id)?;
store.add_psk(psk)?;

// Derive daily key
let day_epoch = DayEpoch::current();
let daily_key = store.get_daily_key("psk-1", day_epoch)?;

// Get fingerprints for discovery
let fingerprints = store.get_fingerprints();
```

## Design References

- `docs/MULTI_TENANT.md`: Complete multi-tenant architecture specification
- `design/security.md`: Cryptographic requirements and threat model
- Section 2.3 (Key Derivation per Tenant): Tenant-aware HKDF/PBKDF2 specifications

## Testing

Run all tenant tests:
```bash
cargo test --package buckwild-common --lib tenant
```

Run specific acceptance test:
```bash
cargo test --package buckwild-common tenant_psk
```

All tests verify:
- TenantId creation, parsing, and ordering
- PSK add/remove/lookup operations
- Daily key derivation with tenant isolation
- Session key derivation with tenant context
- PSK limit enforcement (256 per tenant)
- Memory zeroing on cleanup
