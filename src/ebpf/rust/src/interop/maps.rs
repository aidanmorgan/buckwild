//! eBPF map abstractions for interoperability
//!
//! This module provides high-level abstractions for eBPF maps that are shared
//! between eBPF programs and Rust userspace code.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use super::ffi::{MapType, eBpfFfi};
use super::shared::*;
use buckwild_common::error::BuckwildError;
use buckwild_common::protocol::types::*;
use std::collections::HashMap;
use std::marker::PhantomData;

/// Generic eBPF map abstraction
pub struct eBpfMap<K, V> {
    /// Map file descriptor
    fd: EbpfFileDescriptor,
    /// Map name
    name: String,
    /// Map type
    map_type: EbpfMapType,
    /// FFI interface
    ffi: eBpfFfi,
    /// Phantom data for key and value types
    _phantom: PhantomData<(K, V)>,
}

impl<K, V> eBpfMap<K, V>
where
    K: Clone + 'static,
    V: Clone + 'static,
{
    /// Create a new eBPF map abstraction
    pub fn new(name: String, map_type: EbpfMapType, ffi: eBpfFfi) -> Result<Self, BuckwildError> {
        let fd = ffi.get_map_fd(&name)?;

        Ok(Self {
            fd,
            name,
            map_type,
            ffi,
            _phantom: PhantomData,
        })
    }

    /// Update an element in the map
    pub fn update(&self, key: &K, value: &V, flags: u64) -> Result<(), BuckwildError> {
        let key_bytes = unsafe {
            std::slice::from_raw_parts(key as *const K as *const u8, std::mem::size_of::<K>())
        };

        let value_bytes = unsafe {
            std::slice::from_raw_parts(value as *const V as *const u8, std::mem::size_of::<V>())
        };

        self.ffi
            .update_map_element(self.fd, key_bytes, value_bytes, flags)
    }

    /// Lookup an element in the map
    pub fn lookup(&self, key: &K) -> Result<Option<V>, BuckwildError> {
        let key_bytes = unsafe {
            std::slice::from_raw_parts(key as *const K as *const u8, std::mem::size_of::<K>())
        };

        match self.ffi.lookup_map_element(self.fd, key_bytes) {
            Ok(value_bytes) => {
                if value_bytes.len() >= std::mem::size_of::<V>() {
                    let value = unsafe { std::ptr::read(value_bytes.as_ptr() as *const V) };
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Delete an element from the map
    pub fn delete(&self, key: &K) -> Result<(), BuckwildError> {
        let key_bytes = unsafe {
            std::slice::from_raw_parts(key as *const K as *const u8, std::mem::size_of::<K>())
        };

        self.ffi.delete_map_element(self.fd, key_bytes)
    }

    /// Get map file descriptor
    pub fn fd(&self) -> EbpfFileDescriptor {
        self.fd
    }

    /// Get map name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get map type
    pub fn map_type(&self) -> EbpfMapType {
        self.map_type
    }
}

/// Session map for storing session information
pub type SessionMap = eBpfMap<SessionMapKey, SessionInfo>;

/// Port map for storing port hopping information
pub type PortMap = eBpfMap<PortMapKey, PortHoppingState>;

/// Security map for storing security contexts
pub type SecurityMap = eBpfMap<SecurityMapKey, SecurityContext>;

/// Statistics map for storing performance statistics
pub type StatsMap = eBpfMap<u32, SharedStats>;

/// Map manager for coordinating multiple eBPF maps
pub struct MapManager {
    /// Session map
    session_map: Option<SessionMap>,
    /// Port map
    port_map: Option<PortMap>,
    /// Security map
    security_map: Option<SecurityMap>,
    /// Statistics map
    stats_map: Option<StatsMap>,
    /// FFI interface
    ffi: eBpfFfi,
}

impl MapManager {
    /// Create a new map manager
    pub fn new(ffi: eBpfFfi) -> Self {
        Self {
            session_map: None,
            port_map: None,
            security_map: None,
            stats_map: None,
            ffi,
        }
    }

    /// Initialize all maps
    pub fn initialize_maps(&mut self) -> Result<(), BuckwildError> {
        // Initialize session map
        self.session_map = Some(eBpfMap::new(
            "session_map".to_string(),
            EbpfMapType::Hash,
            eBpfFfi::new(),
        )?);

        // Initialize port map
        self.port_map = Some(eBpfMap::new(
            "port_map".to_string(),
            EbpfMapType::Hash,
            eBpfFfi::new(),
        )?);

        // Initialize security map
        self.security_map = Some(eBpfMap::new(
            "security_map".to_string(),
            EbpfMapType::Hash,
            eBpfFfi::new(),
        )?);

        // Initialize statistics map
        self.stats_map = Some(eBpfMap::new(
            "stats_map".to_string(),
            EbpfMapType::Array,
            eBpfFfi::new(),
        )?);

        Ok(())
    }

    /// Get session map
    pub fn session_map(&self) -> Option<&SessionMap> {
        self.session_map.as_ref()
    }

    /// Get port map
    pub fn port_map(&self) -> Option<&PortMap> {
        self.port_map.as_ref()
    }

    /// Get security map
    pub fn security_map(&self) -> Option<&SecurityMap> {
        self.security_map.as_ref()
    }

    /// Get statistics map
    pub fn stats_map(&self) -> Option<&StatsMap> {
        self.stats_map.as_ref()
    }

    /// Update session information
    pub fn update_session(
        &self,
        session_id: SessionId,
        session_info: &SessionInfo,
    ) -> Result<(), BuckwildError> {
        if let Some(session_map) = &self.session_map {
            let key = SessionMapKey {
                session_id: session_id.as_raw(),
            };
            session_map.update(&key, session_info, 0)
        } else {
            Err(BuckwildError::internal_error("Session map not initialized"))
        }
    }

    /// Lookup session information
    pub fn lookup_session(
        &self,
        session_id: SessionId,
    ) -> Result<Option<SessionInfo>, BuckwildError> {
        if let Some(session_map) = &self.session_map {
            let key = SessionMapKey {
                session_id: session_id.as_raw(),
            };
            session_map.lookup(&key)
        } else {
            Err(BuckwildError::internal_error("Session map not initialized"))
        }
    }

    /// Update port hopping state
    pub fn update_port_state(
        &self,
        ip_addr: IpAddress,
        port: Port,
        state: &PortHoppingState,
    ) -> Result<(), BuckwildError> {
        if let Some(port_map) = &self.port_map {
            let ip_u32 = ip_addr.try_as_u32().ok_or_else(|| {
                BuckwildError::invalid_input("IPv6 addresses not supported for port hopping")
            })?;
            let key = PortMapKey {
                ip_addr: ip_u32,
                port: port.as_raw(),
                reserved: 0,
            };
            port_map.update(&key, state, 0)
        } else {
            Err(BuckwildError::internal_error("Port map not initialized"))
        }
    }

    /// Lookup port hopping state
    pub fn lookup_port_state(
        &self,
        ip_addr: IpAddress,
        port: Port,
    ) -> Result<Option<PortHoppingState>, BuckwildError> {
        if let Some(port_map) = &self.port_map {
            let ip_u32 = ip_addr.try_as_u32().ok_or_else(|| {
                BuckwildError::invalid_input("IPv6 addresses not supported for port hopping")
            })?;
            let key = PortMapKey {
                ip_addr: ip_u32,
                port: port.as_raw(),
                reserved: 0,
            };
            port_map.lookup(&key)
        } else {
            Err(BuckwildError::internal_error("Port map not initialized"))
        }
    }

    /// Update security context
    pub fn update_security_context(
        &self,
        session_id: SessionId,
        context_type: u32,
        context: &SecurityContext,
    ) -> Result<(), BuckwildError> {
        if let Some(security_map) = &self.security_map {
            let key = SecurityMapKey {
                session_id: session_id.as_raw(),
                context_type,
                reserved: 0,
            };
            security_map.update(&key, context, 0)
        } else {
            Err(BuckwildError::internal_error(
                "Security map not initialized",
            ))
        }
    }

    /// Lookup security context
    pub fn lookup_security_context(
        &self,
        session_id: SessionId,
        context_type: u32,
    ) -> Result<Option<SecurityContext>, BuckwildError> {
        if let Some(security_map) = &self.security_map {
            let key = SecurityMapKey {
                session_id: session_id.as_raw(),
                context_type,
                reserved: 0,
            };
            security_map.lookup(&key)
        } else {
            Err(BuckwildError::internal_error(
                "Security map not initialized",
            ))
        }
    }

    /// Update statistics
    pub fn update_stats(&self, stats_id: u32, stats: &SharedStats) -> Result<(), BuckwildError> {
        if let Some(stats_map) = &self.stats_map {
            stats_map.update(&stats_id, stats, 0)
        } else {
            Err(BuckwildError::internal_error(
                "Statistics map not initialized",
            ))
        }
    }

    /// Get statistics
    pub fn get_stats(&self, stats_id: u32) -> Result<Option<SharedStats>, BuckwildError> {
        if let Some(stats_map) = &self.stats_map {
            stats_map.lookup(&stats_id)
        } else {
            Err(BuckwildError::internal_error(
                "Statistics map not initialized",
            ))
        }
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(
        &self,
        current_time: Timestamp,
        timeout: std::time::Duration,
    ) -> Result<SessionCount, BuckwildError> {
        // This is a placeholder implementation
        // In a real implementation, you would iterate through the session map
        // and remove expired sessions

        let cleaned_count = SessionCount::new(0);

        // Placeholder logic - in reality you'd iterate through the map
        // For now, just return 0 to indicate no sessions were cleaned

        Ok(cleaned_count)
    }

    /// Get map statistics
    pub fn get_map_statistics(&self) -> HashMap<String, MapStatistics> {
        let mut stats = HashMap::new();

        if self.session_map.is_some() {
            stats.insert(
                "session_map".to_string(),
                MapStatistics {
                    name: "session_map".to_string(),
                    map_type: EbpfMapType::Hash,
                    entries: EventCount::from_raw(0), // Would be populated from actual map
                    max_entries: EbpfMapSize::new(MAX_SESSIONS as u32),
                    key_size: KeySize::new(std::mem::size_of::<SessionMapKey>()),
                    value_size: ValueSize::new(std::mem::size_of::<SessionInfo>()),
                },
            );
        }

        if self.port_map.is_some() {
            stats.insert(
                "port_map".to_string(),
                MapStatistics {
                    name: "port_map".to_string(),
                    map_type: EbpfMapType::Hash,
                    entries: EventCount::from_raw(0),
                    max_entries: EbpfMapSize::new(MAX_PORTS as u32),
                    key_size: KeySize::new(std::mem::size_of::<PortMapKey>()),
                    value_size: ValueSize::new(std::mem::size_of::<PortHoppingState>()),
                },
            );
        }

        if self.security_map.is_some() {
            stats.insert(
                "security_map".to_string(),
                MapStatistics {
                    name: "security_map".to_string(),
                    map_type: EbpfMapType::Hash,
                    entries: EventCount::from_raw(0),
                    max_entries: EbpfMapSize::new(MAX_SECURITY_CONTEXTS as u32),
                    key_size: KeySize::new(std::mem::size_of::<SecurityMapKey>()),
                    value_size: ValueSize::new(std::mem::size_of::<SecurityContext>()),
                },
            );
        }

        stats
    }
}

/// Map statistics structure
#[derive(Debug, Clone)]
pub struct MapStatistics {
    /// Map name
    pub name: String,
    /// Map type
    pub map_type: EbpfMapType,
    /// Current number of entries
    pub entries: EventCount,
    /// Maximum number of entries
    pub max_entries: EbpfMapSize,
    /// Key size in bytes
    pub key_size: KeySize,
    /// Value size in bytes
    pub value_size: ValueSize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_manager_creation() {
        let ffi = eBpfFfi::new();
        let manager = MapManager::new(ffi);

        assert!(manager.session_map.is_none());
        assert!(manager.port_map.is_none());
        assert!(manager.security_map.is_none());
        assert!(manager.stats_map.is_none());
    }

    #[test]
    fn test_map_statistics() {
        let ffi = eBpfFfi::new();
        let mut manager = MapManager::new(ffi);

        // Initialize maps would normally be called here
        // let _ = manager.initialize_maps();

        let stats = manager.get_map_statistics();
        assert!(stats.is_empty()); // No maps initialized in test
    }

    #[test]
    fn test_session_map_key() {
        let key1 = SessionMapKey { session_id: 12345 };
        let key2 = SessionMapKey { session_id: 12345 };
        let key3 = SessionMapKey { session_id: 54321 };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_port_map_key() {
        let key1 = PortMapKey {
            ip_addr: 0x7f000001,
            port: 8080,
            reserved: 0,
        };
        let key2 = PortMapKey {
            ip_addr: 0x7f000001,
            port: 8080,
            reserved: 0,
        };
        let key3 = PortMapKey {
            ip_addr: 0x7f000001,
            port: 9090,
            reserved: 0,
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_security_map_key() {
        let key1 = SecurityMapKey {
            session_id: 12345,
            context_type: 1,
            reserved: 0,
        };
        let key2 = SecurityMapKey {
            session_id: 12345,
            context_type: 1,
            reserved: 0,
        };
        let key3 = SecurityMapKey {
            session_id: 12345,
            context_type: 2,
            reserved: 0,
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
