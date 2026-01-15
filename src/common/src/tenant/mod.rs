//! Multi-tenant PSK management and traffic isolation module
//!
//! This module implements per-tenant PSK storage, session management, and security
//! enforcement for the Buckwild frequency hopping network protocol. Each tenant
//! maintains isolated PSK collections, session namespaces, and security policies
//! with independent key derivation and secure memory management.
//!
//! # Design
//!
//! - `TenantId`: Timestamp+counter based unique tenant identifier (64-bit)
//! - `TenantPskStore`: Per-tenant PSK storage with lock-free concurrent access
//! - `TenantSessionManager`: Per-tenant session ID generation and routing
//! - `SharedPortStrategy`: Shared port allocation with tenant-aware calculation
//! - `CrossTenantSecurityEnforcer`: Security boundaries and audit logging
//! - Tenant-aware key derivation with cryptographic isolation
//! - Support for up to 256 PSKs per tenant
//! - Automatic secure memory zeroing via Drop trait

#![cfg_attr(not(test), forbid(clippy::unwrap_used, clippy::expect_used))]

pub mod key_derivation;
pub mod port_allocation;
pub mod psk_store;
pub mod security;
pub mod session_manager;
pub mod tenant_id;

#[cfg(test)]
mod multi_tenant_tests;

pub use key_derivation::{
    derive_daily_key_with_tenant_context, derive_session_keys_with_tenant_context,
};
pub use port_allocation::{PortAllocationManager, PortRange, SharedPortStrategy};
pub use psk_store::{TenantPsk, TenantPskStore};
pub use security::{CrossTenantSecurityEnforcer, SecurityEvent, SecurityEventType};
pub use session_manager::{
    SessionRoutingEntry, SessionState, TenantSessionId, TenantSessionIdGenerator,
    TenantSessionManager,
};
pub use tenant_id::TenantId;
