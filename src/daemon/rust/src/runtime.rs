use std::future::Future;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Failed to create tokio runtime: {0}")]
    TokioCreation(#[from] std::io::Error),

    #[error("Runtime already running")]
    AlreadyRunning,

    #[error("System error: {0}")]
    SystemError(String),
}

pub struct DaemonRuntime {
    tokio_runtime: Arc<tokio::runtime::Runtime>,
}

impl DaemonRuntime {
    pub fn new() -> Result<Self, RuntimeError> {
        debug!("Creating daemon runtime with multi-threaded tokio");

        let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(num_cpus::get())
            .thread_name("buckwild-worker")
            .enable_all()
            .build()
            .map_err(RuntimeError::TokioCreation)?;

        info!(
            "Created tokio runtime with {} worker threads",
            num_cpus::get()
        );

        Ok(Self {
            tokio_runtime: Arc::new(tokio_runtime),
        })
    }

    pub fn run<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.tokio_runtime.block_on(future)
    }

    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.tokio_runtime.block_on(future)
    }

    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tokio_runtime.spawn(future)
    }

    pub fn handle(&self) -> tokio::runtime::Handle {
        self.tokio_runtime.handle().clone()
    }
}

impl Default for DaemonRuntime {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            panic!("Failed to create default runtime: {}", e);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let runtime = DaemonRuntime::new();
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_runtime_block_on() {
        let runtime = DaemonRuntime::new().unwrap();
        let result = runtime.block_on(async { 42 });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_runtime_spawn() {
        let runtime = DaemonRuntime::new().unwrap();
        let handle = runtime.spawn(async { 100 });
        let result = runtime.block_on(handle).unwrap();
        assert_eq!(result, 100);
    }
}
