use super::debug;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Health check server errors
#[derive(Error, Debug)]
pub enum HealthError {
    #[error("HTTP server error: {0}")]
    Server(#[from] hyper::Error),

    #[error("Failed to bind to address: {0}")]
    Bind(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Health status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
}

/// Readiness status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub reason: Option<String>,
}

/// Detailed health status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedHealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    pub subsystems: SubsystemsStatus,
}

/// Subsystem status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemsStatus {
    pub ready: bool,
    pub ready_reason: Option<String>,
    #[cfg(target_os = "linux")]
    pub ebpf_available: bool,
    #[cfg(not(target_os = "linux"))]
    pub ebpf_available: bool,
}

/// Health state tracking
#[derive(Debug, Clone)]
pub struct HealthState {
    start_time: Instant,
    ready: bool,
    ready_reason: Option<String>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            ready: false,
            ready_reason: Some("Initializing".to_string()),
        }
    }
}

impl HealthState {
    /// Create new health state
    pub fn new() -> Self {
        Self::default()
    }

    /// Get current uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Set ready status
    pub fn set_ready(&mut self, ready: bool, reason: Option<String>) {
        self.ready = ready;
        self.ready_reason = reason;
    }

    /// Get health response
    pub fn health(&self) -> HealthResponse {
        HealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.uptime().as_secs(),
        }
    }

    /// Get ready response
    pub fn ready(&self) -> ReadyResponse {
        ReadyResponse {
            ready: self.ready,
            reason: self.ready_reason.clone(),
        }
    }

    /// Get detailed health response
    #[cfg(target_os = "linux")]
    pub fn detailed_health(&self, ebpf_available: bool) -> DetailedHealthResponse {
        DetailedHealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.uptime().as_secs(),
            subsystems: SubsystemsStatus {
                ready: self.ready,
                ready_reason: self.ready_reason.clone(),
                ebpf_available,
            },
        }
    }

    /// Get detailed health response (non-Linux)
    #[cfg(not(target_os = "linux"))]
    pub fn detailed_health(&self, _ebpf_available: bool) -> DetailedHealthResponse {
        DetailedHealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.uptime().as_secs(),
            subsystems: SubsystemsStatus {
                ready: self.ready,
                ready_reason: self.ready_reason.clone(),
                ebpf_available: false,
            },
        }
    }
}

/// Health check server
///
/// Note: EbpfManager is not stored here because it contains non-Send libbpf types
/// that cannot be safely moved to the HTTP server thread. Debug endpoints for eBPF
/// state will return "unavailable" until a channel-based approach is implemented.
pub struct HealthServer {
    state: Arc<RwLock<HealthState>>,
    addr: std::net::SocketAddr,
    /// Flag indicating if eBPF manager is available (actual manager not stored due to thread safety)
    ebpf_available: Arc<RwLock<bool>>,
}

impl HealthServer {
    /// Create new health server
    pub fn new(port: u16) -> Self {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        Self {
            state: Arc::new(RwLock::new(HealthState::new())),
            addr,
            ebpf_available: Arc::new(RwLock::new(false)),
        }
    }

    /// Mark eBPF manager as available
    ///
    /// Note: We don't store the actual EbpfManager because it contains non-Send types
    /// that can't be moved to the HTTP server thread. This just sets a flag.
    #[cfg(target_os = "linux")]
    pub async fn set_ebpf_manager(&self, _manager: Arc<buckwild_ebpf::EbpfManager>) {
        *self.ebpf_available.write().await = true;
    }

    /// Set eBPF manager for debug endpoints (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub async fn set_ebpf_manager(&self, _manager: ()) {
        *self.ebpf_available.write().await = true;
    }

    /// Set ready status
    pub async fn set_ready(&self, ready: bool, reason: Option<String>) {
        let mut state = self.state.write().await;
        state.set_ready(ready, reason);
    }

    /// Start the health check server
    ///
    /// Uses a dedicated thread with single-threaded runtime because
    /// EbpfManager contains non-Send libbpf types that can't be used with
    /// tokio::spawn across await points.
    pub fn start(self: Arc<Self>) -> Result<std::thread::JoinHandle<()>, HealthError> {
        let addr = self.addr;

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create health server runtime");

            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(&addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind health server: {}: {}", addr, e);
                        return;
                    }
                };

                info!("Health check server listening on {}", addr);

                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(conn) => conn,
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                            continue;
                        }
                    };

                    let io = TokioIo::new(stream);
                    let self_clone = Arc::clone(&self);

                    // Handle connection inline since we're in a single-threaded runtime
                    let service = service_fn(move |req| {
                        let self_clone = Arc::clone(&self_clone);
                        async move { self_clone.handle_request(req).await }
                    });

                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        error!("Error serving connection: {}", e);
                    }
                }
            });
        });

        Ok(handle)
    }

    /// Handle HTTP request
    async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let path = req.uri().path();
        let method = req.method();

        if method != Method::GET {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method not allowed")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal error")))));
        }

        match path {
            "/health" => {
                let state = self.state.read().await;
                let health = state.health();
                match serde_json::to_vec(&health) {
                    Ok(json) => Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(json)))
                        .unwrap_or_else(|_| {
                            Response::new(Full::new(Bytes::from("Internal error")))
                        })),
                    Err(e) => {
                        error!("Failed to serialize health response: {}", e);
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::new(Bytes::from("Serialization error")))
                            .unwrap_or_else(|_| {
                                Response::new(Full::new(Bytes::from("Internal error")))
                            }))
                    }
                }
            }
            "/ready" => {
                let state = self.state.read().await;
                let ready = state.ready();
                let status = if ready.ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                match serde_json::to_vec(&ready) {
                    Ok(json) => Ok(Response::builder()
                        .status(status)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(json)))
                        .unwrap_or_else(|_| {
                            Response::new(Full::new(Bytes::from("Internal error")))
                        })),
                    Err(e) => {
                        error!("Failed to serialize ready response: {}", e);
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::new(Bytes::from("Serialization error")))
                            .unwrap_or_else(|_| {
                                Response::new(Full::new(Bytes::from("Internal error")))
                            }))
                    }
                }
            }
            "/health/detail" => {
                let state = self.state.read().await;
                let ebpf_available = *self.ebpf_available.read().await;
                let detailed = state.detailed_health(ebpf_available);
                match serde_json::to_vec(&detailed) {
                    Ok(json) => Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(json)))
                        .unwrap_or_else(|_| {
                            Response::new(Full::new(Bytes::from("Internal error")))
                        })),
                    Err(e) => {
                        error!("Failed to serialize detailed health response: {}", e);
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::new(Bytes::from("Serialization error")))
                            .unwrap_or_else(|_| {
                                Response::new(Full::new(Bytes::from("Internal error")))
                            }))
                    }
                }
            }
            "/debug/ebpf/maps" | "/debug/ebpf/progs" => {
                // Note: EbpfManager is not stored in HealthServer because it contains
                // non-Send libbpf types. Debug endpoints return unavailable until a
                // channel-based approach is implemented.
                Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"eBPF debug endpoints temporarily unavailable","reason":"thread safety"}"#
                    )))
                    .unwrap_or_else(|_| {
                        Response::new(Full::new(Bytes::from("Internal error")))
                    }))
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not found")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal error"))))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_state_uptime() {
        let state = HealthState::new();
        std::thread::sleep(Duration::from_millis(100));
        assert!(state.uptime().as_millis() >= 100);
    }

    #[test]
    fn test_health_response() {
        let state = HealthState::new();
        let health = state.health();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_ready_state() {
        let mut state = HealthState::new();
        assert!(!state.ready().ready);

        state.set_ready(true, None);
        assert!(state.ready().ready);
        assert_eq!(state.ready().reason, None);

        state.set_ready(false, Some("Not ready".to_string()));
        assert!(!state.ready().ready);
        assert_eq!(state.ready().reason, Some("Not ready".to_string()));
    }

    #[test]
    fn test_detailed_health_response() {
        let state = HealthState::new();
        let detailed = state.detailed_health(true);
        assert_eq!(detailed.status, "healthy");
        assert_eq!(detailed.version, env!("CARGO_PKG_VERSION"));
        assert!(detailed.subsystems.ebpf_available || !cfg!(target_os = "linux"));
    }

    #[test]
    fn test_detailed_health_subsystems() {
        let mut state = HealthState::new();
        state.set_ready(true, None);

        let detailed = state.detailed_health(true);
        assert!(detailed.subsystems.ready);
        assert_eq!(detailed.subsystems.ready_reason, None);

        state.set_ready(false, Some("Initializing".to_string()));
        let detailed = state.detailed_health(false);
        assert!(!detailed.subsystems.ready);
        assert_eq!(
            detailed.subsystems.ready_reason,
            Some("Initializing".to_string())
        );
        assert!(!detailed.subsystems.ebpf_available);
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_200() {
        let server = Arc::new(HealthServer::new(0));
        let state = server.state.clone();

        let mut mock_state = state.write().await;
        mock_state.set_ready(true, None);
        drop(mock_state);

        let health = state.read().await.health();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn test_aggregated_health_check_fails_when_subsystem_unhealthy() {
        let server = Arc::new(HealthServer::new(0));
        let state = server.state.clone();

        let mut mock_state = state.write().await;
        mock_state.set_ready(false, Some("eBPF initialization failed".to_string()));
        drop(mock_state);

        let ready = state.read().await.ready();
        assert!(!ready.ready);
        assert_eq!(ready.reason, Some("eBPF initialization failed".to_string()));

        let detailed = state.read().await.detailed_health(false);
        assert!(!detailed.subsystems.ready);
        assert_eq!(
            detailed.subsystems.ready_reason,
            Some("eBPF initialization failed".to_string())
        );
        assert!(!detailed.subsystems.ebpf_available);
    }
}
