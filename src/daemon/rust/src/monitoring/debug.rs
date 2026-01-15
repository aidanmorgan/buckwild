//! Debug endpoints for eBPF introspection
//!
//! Provides HTTP endpoints for inspecting eBPF maps and programs.
//! On non-Linux platforms, returns empty responses gracefully.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Debug endpoint errors
#[derive(Error, Debug)]
pub enum DebugError {
    #[error("Platform does not support eBPF")]
    UnsupportedPlatform,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[cfg(target_os = "linux")]
    #[error("eBPF error: {0}")]
    Ebpf(#[from] anyhow::Error),
}

/// Response for /debug/ebpf/maps endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfMapsResponse {
    pub maps: Vec<MapInfo>,
}

/// Information about a single eBPF map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapInfo {
    pub name: String,
    pub map_type: String,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub current_entries: u32,
}

/// Response for /debug/ebpf/progs endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfProgsResponse {
    pub programs: Vec<ProgramInfo>,
}

/// Information about a single eBPF program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInfo {
    pub name: String,
    pub prog_type: String,
    pub run_count: u64,
    pub run_time_ns: u64,
}

/// Get eBPF maps information
#[cfg(target_os = "linux")]
pub async fn get_ebpf_maps(
    ebpf_manager: Option<&std::sync::Arc<buckwild_ebpf::EbpfManager>>,
) -> Result<EbpfMapsResponse, DebugError> {
    use buckwild_ebpf::maps::MapManager;

    let Some(manager) = ebpf_manager else {
        return Ok(EbpfMapsResponse { maps: Vec::new() });
    };

    let map_manager = manager.map_manager();
    let map_mgr = map_manager.read().await;

    if !map_mgr.is_initialized() {
        return Ok(EbpfMapsResponse { maps: Vec::new() });
    }

    let stats = map_mgr.get_map_statistics().await?;

    let mut maps = Vec::new();

    // Add session map info
    maps.push(MapInfo {
        name: "session_map".to_string(),
        map_type: "hash".to_string(),
        key_size: std::mem::size_of::<u64>() as u32,
        value_size: 128, // Approximate session state size
        max_entries: stats.session_stats.total_sessions as u32,
        current_entries: stats.session_stats.active_sessions as u32,
    });

    // Add port map info
    maps.push(MapInfo {
        name: "port_map".to_string(),
        map_type: "hash".to_string(),
        key_size: std::mem::size_of::<u16>() as u32,
        value_size: std::mem::size_of::<u32>() as u32,
        max_entries: 65536,
        current_entries: stats.port_stats.active_ports.as_u64() as u32,
    });

    // Add security map info
    maps.push(MapInfo {
        name: "security_map".to_string(),
        map_type: "hash".to_string(),
        key_size: 16,   // IP address
        value_size: 32, // Security state
        max_entries: 10000,
        current_entries: stats.security_stats.total_maps as u32,
    });

    Ok(EbpfMapsResponse { maps })
}

/// Get eBPF programs information
#[cfg(target_os = "linux")]
pub async fn get_ebpf_programs(
    ebpf_manager: Option<&std::sync::Arc<buckwild_ebpf::EbpfManager>>,
) -> Result<EbpfProgsResponse, DebugError> {
    let Some(_manager) = ebpf_manager else {
        return Ok(EbpfProgsResponse {
            programs: Vec::new(),
        });
    };

    // Note: libbpf-rs doesn't expose program statistics directly
    // This would require additional syscalls to query BPF program info
    // For now, return placeholder information indicating programs are loaded

    let programs = vec![
        ProgramInfo {
            name: "xdp_packet_filter".to_string(),
            prog_type: "XDP".to_string(),
            run_count: 0,
            run_time_ns: 0,
        },
        ProgramInfo {
            name: "tc_egress_filter".to_string(),
            prog_type: "TC".to_string(),
            run_count: 0,
            run_time_ns: 0,
        },
    ];

    Ok(EbpfProgsResponse { programs })
}

/// Get eBPF maps information (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub async fn get_ebpf_maps(_ebpf_manager: Option<&()>) -> Result<EbpfMapsResponse, DebugError> {
    Ok(EbpfMapsResponse { maps: Vec::new() })
}

/// Get eBPF programs information (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub async fn get_ebpf_programs(
    _ebpf_manager: Option<&()>,
) -> Result<EbpfProgsResponse, DebugError> {
    Ok(EbpfProgsResponse {
        programs: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(not(target_os = "linux"))]
    async fn test_ebpf_maps_non_linux() {
        let result = get_ebpf_maps(None).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.maps.len(), 0);
    }

    #[tokio::test]
    #[cfg(not(target_os = "linux"))]
    async fn test_ebpf_programs_non_linux() {
        let result = get_ebpf_programs(None).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.programs.len(), 0);
    }
}
