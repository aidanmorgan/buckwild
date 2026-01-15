//! eBPF program loader module
//! This module provides functionality for loading and managing eBPF programs.
//! It handles XDP loaders, TC loaders, and provides proper program lifecycle management.

#![cfg(target_os = "linux")]

// Import consolidated types from the authoritative source
use buckwild_common::protocol::types::*;

pub mod tc_loader;
pub mod xdp_loader;

// Re-export loaders for convenience
pub use tc_loader::TcLoader;
pub use xdp_loader::XdpLoader;

use anyhow::Result;
use std::path::Path;

/// Common eBPF loader interface
pub trait EbpfLoader {
    /// Load eBPF programs from the specified directory
    async fn load_programs(&mut self) -> Result<()>;

    /// Unload all eBPF programs
    async fn unload_programs(&mut self) -> Result<()>;

    /// Check if programs are loaded
    fn is_loaded(&self) -> bool;

    /// Get the number of loaded programs
    fn program_count(&self) -> EbpfProgramCount;
}

/// eBPF program loader manager
pub struct LoaderManager {
    xdp_loader: xdp_loader::XdpLoader,
    tc_loader: tc_loader::TcLoader,
    program_directory: Option<std::path::PathBuf>,
}

impl LoaderManager {
    /// Create a new loader manager
    pub fn new() -> Result<Self> {
        Ok(Self {
            xdp_loader: xdp_loader::XdpLoader::new()?,
            tc_loader: tc_loader::TcLoader::new()?,
            program_directory: None,
        })
    }

    /// Set the directory containing eBPF object files
    pub fn set_program_directory<P: AsRef<Path>>(&mut self, dir: P) {
        let path = dir.as_ref().to_path_buf();
        self.program_directory = Some(path.clone());
        self.xdp_loader.set_program_directory(&path);
        self.tc_loader.set_program_directory(&path);
    }

    /// Load all eBPF programs
    pub async fn load_all_programs(&mut self) -> Result<()> {
        if self.program_directory.is_none() {
            return Err(anyhow::anyhow!("Program directory not set"));
        }

        // Load XDP programs
        self.xdp_loader.load_programs().await?;
        tracing::info!(
            "Loaded {} XDP programs",
            self.xdp_loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        // Load TC programs
        self.tc_loader.load_programs().await?;
        tracing::info!(
            "Loaded {} TC programs",
            self.tc_loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        tracing::info!("All eBPF programs loaded successfully");
        Ok(())
    }

    /// Unload all eBPF programs
    pub async fn unload_all_programs(&mut self) -> Result<()> {
        // Unload TC programs first
        self.tc_loader.unload_programs().await?;
        tracing::info!("Unloaded TC programs");

        // Unload XDP programs
        self.xdp_loader.unload_programs().await?;
        tracing::info!("Unloaded XDP programs");

        tracing::info!("All eBPF programs unloaded successfully");
        Ok(())
    }

    /// Check if all programs are loaded
    pub fn is_all_loaded(&self) -> bool {
        self.xdp_loader.is_loaded() && self.tc_loader.is_loaded()
    }

    /// Get total program count
    pub fn total_program_count(&self) -> EbpfProgramCount {
        EbpfProgramCount::new(
            self.xdp_loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed)
                + self
                    .tc_loader
                    .program_count()
                    .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Get XDP loader reference
    pub fn xdp_loader(&self) -> &xdp_loader::XdpLoader {
        &self.xdp_loader
    }

    /// Get mutable XDP loader reference
    pub fn xdp_loader_mut(&mut self) -> &mut xdp_loader::XdpLoader {
        &mut self.xdp_loader
    }

    /// Get TC loader reference
    pub fn tc_loader(&self) -> &tc_loader::TcLoader {
        &self.tc_loader
    }

    /// Get mutable TC loader reference
    pub fn tc_loader_mut(&mut self) -> &mut tc_loader::TcLoader {
        &mut self.tc_loader
    }

    /// Get loader statistics
    pub fn get_statistics(&self) -> LoaderStatistics {
        LoaderStatistics {
            xdp_programs: self
                .xdp_loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            tc_programs: self
                .tc_loader
                .program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            total_programs: self
                .total_program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            xdp_loaded: self.xdp_loader.is_loaded(),
            tc_loaded: self.tc_loader.is_loaded(),
            all_loaded: self.is_all_loaded(),
        }
    }
}

// Default implementation removed - use LoaderManager::new() instead
// Default trait cannot properly handle fallible initialization

/// Loader statistics
#[derive(Debug)]
pub struct LoaderStatistics {
    pub xdp_programs: u32,
    pub tc_programs: u32,
    pub total_programs: u32,
    pub xdp_loaded: bool,
    pub tc_loaded: bool,
    pub all_loaded: bool,
}

/// Helper function to validate eBPF object file
pub fn validate_ebpf_object<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();

    // Check if file exists
    if !path.exists() {
        return Err(anyhow::anyhow!(
            "eBPF object file does not exist: {:?}",
            path
        ));
    }

    // Check file extension
    if path.extension().and_then(|s| s.to_str()) != Some("o") {
        return Err(anyhow::anyhow!(
            "Invalid eBPF object file extension: {:?}",
            path
        ));
    }

    // Check file size (should not be empty)
    let metadata = std::fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(anyhow::anyhow!("eBPF object file is empty: {:?}", path));
    }

    Ok(())
}

/// Helper function to find eBPF object files in a directory
pub fn find_ebpf_objects<P: AsRef<Path>>(dir: P) -> Result<Vec<std::path::PathBuf>> {
    let dir = dir.as_ref();
    let mut objects = Vec::new();

    if !dir.is_dir() {
        return Err(anyhow::anyhow!("Path is not a directory: {:?}", dir));
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("o") {
            objects.push(path);
        }
    }

    objects.sort();
    Ok(objects)
}

/// Helper function to get program type from filename
pub fn get_program_type_from_filename(filename: &str) -> Option<String> {
    if filename.starts_with("buckwild_xdp") || filename.contains("xdp") {
        Some("XDP".to_string())
    } else if filename.starts_with("buckwild_tc") || filename.contains("tc") {
        Some("TC".to_string())
    } else if filename.contains("socket_filter") || filename.contains("filter") {
        Some("SocketFilter".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_loader_manager_creation() {
        let manager = LoaderManager::new();
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert!(!manager.is_all_loaded());
        assert_eq!(
            manager
                .total_program_count()
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(manager.program_directory.is_none());
    }

    #[test]
    fn test_validate_ebpf_object() {
        // Test with non-existent file
        let result = validate_ebpf_object("/non/existent/file.o");
        assert!(result.is_err());

        // Create a temporary file for testing
        let temp_dir = TempDir::new().unwrap();
        let temp_file = temp_dir.path().join("test.o");
        fs::write(&temp_file, b"test content").unwrap();

        // Test with valid file
        let result = validate_ebpf_object(&temp_file);
        assert!(result.is_ok());

        // Test with wrong extension
        let wrong_ext = temp_dir.path().join("test.txt");
        fs::write(&wrong_ext, b"test content").unwrap();
        let result = validate_ebpf_object(&wrong_ext);
        assert!(result.is_err());

        // Test with empty file
        let empty_file = temp_dir.path().join("empty.o");
        fs::write(&empty_file, b"").unwrap();
        let result = validate_ebpf_object(&empty_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_ebpf_objects() {
        let temp_dir = TempDir::new().unwrap();

        // Create some test files
        fs::write(temp_dir.path().join("program1.o"), b"test").unwrap();
        fs::write(temp_dir.path().join("program2.o"), b"test").unwrap();
        fs::write(temp_dir.path().join("not_ebpf.txt"), b"test").unwrap();

        let objects = find_ebpf_objects(temp_dir.path()).unwrap();
        assert_eq!(objects.len(), 2);

        // Check that files are sorted
        assert!(
            objects[0].file_name().unwrap().to_str().unwrap()
                <= objects[1].file_name().unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn test_get_program_type_from_filename() {
        assert_eq!(
            get_program_type_from_filename("buckwild_xdp.o"),
            Some("XDP".to_string())
        );
        assert_eq!(
            get_program_type_from_filename("buckwild_tc.o"),
            Some("TC".to_string())
        );
        assert_eq!(
            get_program_type_from_filename("socket_filter.o"),
            Some("SocketFilter".to_string())
        );
        assert_eq!(get_program_type_from_filename("unknown.o"), None);
    }

    #[test]
    fn test_loader_statistics() {
        let manager = LoaderManager::new().unwrap();
        let stats = manager.get_statistics();

        assert_eq!(stats.xdp_programs, 0);
        assert_eq!(stats.tc_programs, 0);
        assert_eq!(stats.total_programs, 0);
        assert!(!stats.xdp_loaded);
        assert!(!stats.tc_loaded);
        assert!(!stats.all_loaded);
    }
}
