use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Instant;
use uuid::{self, Uuid};

/// Unique correlation identifier for request tracking
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(Uuid);

impl CorrelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_string(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Context information for correlation tracking
#[derive(Debug, Clone)]
pub struct CorrelationContext {
    pub correlation_id: CorrelationId,
    pub operation: String,
    pub created_at: Instant,
    pub events: VecDeque<super::LogEvent>,
    pub max_events: usize,
}

impl CorrelationContext {
    pub fn new(operation: String) -> Self {
        Self {
            correlation_id: CorrelationId::new(),
            operation,
            created_at: Instant::now(),
            events: VecDeque::new(),
            max_events: 100, // Limit events per correlation to prevent memory issues
        }
    }

    pub fn add_event(&mut self, event: super::LogEvent) {
        if self.events.len() >= self.max_events {
            self.events.pop_front(); // Remove oldest event
        }
        self.events.push_back(event);
    }

    pub fn get_events(&self) -> &VecDeque<super::LogEvent> {
        &self.events
    }

    pub fn duration(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

/// Correlation span for automatic correlation management
pub struct CorrelationSpan {
    correlation_id: CorrelationId,
    _span: tracing::Span,
}

impl CorrelationSpan {
    pub fn new(operation: &str) -> Self {
        let correlation_id = CorrelationId::new();
        let span = tracing::info_span!(
            "correlation",
            correlation_id = %correlation_id,
            operation = operation
        );

        Self {
            correlation_id,
            _span: span,
        }
    }

    pub fn correlation_id(&self) -> &CorrelationId {
        &self.correlation_id
    }

    pub fn enter(&self) -> tracing::span::Entered<'_> {
        self._span.enter()
    }
}
