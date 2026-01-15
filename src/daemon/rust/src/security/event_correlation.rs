use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use tracing::{debug, warn, error, info};
use uuid::Uuid;

use crate::errors::BuckwildError;

/// Security event correlation engine for attack pattern recognition
#[derive(Debug)]
pub struct SecurityEventCorrelator {
    /// Event storage with correlation IDs
    events: Arc<RwLock<VecDeque<SecurityEvent>>>,
    /// Active incidents being tracked
    incidents: Arc<RwLock<HashMap<Uuid, SecurityIncident>>>,
    /// Attack patterns and their signatures
    attack_patterns: Arc<RwLock<Vec<AttackPattern>>>,
    /// Configuration parameters
    config: CorrelationConfig,
    /// Statistics for monitoring
    stats: Arc<RwLock<CorrelationStats>>,
    /// External monitoring integrations
    external_integrations: Arc<RwLock<Vec<Box<dyn ExternalMonitoringIntegration + Send + Sync>>>>,
}

/// Configuration for event correlation
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Maximum number of events to store
    pub max_events: usize,
    /// Time window for event correlation (seconds)
    pub correlation_window_seconds: u64,
    /// Minimum events required to trigger incident
    pub min_events_for_incident: usize,
    /// Incident auto-close timeout (seconds)
    pub incident_timeout_seconds: u64,
    /// Cleanup interval (seconds)
    pub cleanup_interval_seconds: u64,
}

/// Security event with correlation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event ID
    pub event_id: Uuid,
    /// Correlation ID for related events
    pub correlation_id: Uuid,
    /// Event type
    pub event_type: SecurityEventType,
    /// Event severity
    pub severity: EventSeverity,
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    /// Target information
    pub target: Option<String>,
    /// Session ID if applicable
    pub session_id: Option<u64>,
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Event details
    pub details: HashMap<String, String>,
    /// Attack signature if detected
    pub attack_signature: Option<String>,
}

/// Types of security events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecurityEventType {
    /// Replay attack detected
    ReplayAttack,
    /// Duplicate packet detected
    DuplicatePacket,
    /// Enumeration attack detected
    EnumerationAttack,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Invalid nonce used
    InvalidNonce,
    /// Fragment bomb attempt
    FragmentBomb,
    /// Port scanning detected
    PortScanning,
    /// Session hijacking attempt
    SessionHijacking,
    /// Timing attack detected
    TimingAttack,
    /// Authentication failure
    AuthenticationFailure,
    /// Malformed packet received
    MalformedPacket,
    /// Suspicious pattern detected
    SuspiciousPattern,
}

/// Event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    /// Informational event
    Info,
    /// Low severity event
    Low,
    /// Medium severity event
    Medium,
    /// High severity event
    High,
    /// Critical security event
    Critical,
}

/// Security incident tracking
#[derive(Debug, Clone)]
pub struct SecurityIncident {
    /// Incident ID
    pub incident_id: Uuid,
    /// Incident type
    pub incident_type: IncidentType,
    /// Incident severity
    pub severity: EventSeverity,
    /// Source IP involved
    pub source_ip: Option<IpAddr>,
    /// Related events
    pub related_events: Vec<Uuid>,
    /// Incident start time
    pub start_time: SystemTime,
    /// Last update time
    pub last_update: SystemTime,
    /// Incident status
    pub status: IncidentStatus,
    /// Response actions taken
    pub response_actions: Vec<ResponseAction>,
    /// Attack pattern matched
    pub attack_pattern: Option<String>,
}

/// Types of security incidents
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentType {
    /// Coordinated attack
    CoordinatedAttack,
    /// Brute force attempt
    BruteForce,
    /// Network reconnaissance
    NetworkReconnaissance,
    /// Resource exhaustion attack
    ResourceExhaustion,
    /// Protocol violation
    ProtocolViolation,
    /// Suspicious activity
    SuspiciousActivity,
}

/// Incident status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentStatus {
    /// Incident is active
    Active,
    /// Incident is under investigation
    Investigating,
    /// Incident has been resolved
    Resolved,
    /// Incident was a false positive
    FalsePositive,
}

/// Response actions taken for incidents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    /// Action type
    pub action_type: ResponseActionType,
    /// When the action was taken
    pub timestamp: SystemTime,
    /// Action details
    pub details: String,
    /// Action result
    pub result: ActionResult,
}

/// Types of response actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseActionType {
    /// Block source IP
    BlockSource,
    /// Rate limit source
    RateLimit,
    /// Terminate session
    TerminateSession,
    /// Alert administrator
    AlertAdmin,
    /// Log to external system
    ExternalLog,
    /// Quarantine connection
    Quarantine,
}

/// Result of response action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionResult {
    /// Action succeeded
    Success,
    /// Action failed
    Failed(String),
    /// Action is pending
    Pending,
}

/// Attack pattern definition
#[derive(Debug, Clone)]
pub struct AttackPattern {
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Event types that match this pattern
    pub event_types: Vec<SecurityEventType>,
    /// Minimum events required
    pub min_events: usize,
    /// Time window for pattern matching
    pub time_window: Duration,
    /// Pattern matching function
    pub matcher: fn(&[SecurityEvent]) -> bool,
    /// Severity of incidents created by this pattern
    pub incident_severity: EventSeverity,
}

/// Statistics for correlation monitoring
#[derive(Debug, Clone, Default)]
pub struct CorrelationStats {
    /// Total events processed
    pub total_events: u64,
    /// Active incidents
    pub active_incidents: u64,
    /// Patterns matched
    pub patterns_matched: u64,
    /// Response actions taken
    pub response_actions: u64,
    /// False positives detected
    pub false_positives: u64,
}

/// External monitoring system integration
pub trait ExternalMonitoringIntegration: std::fmt::Debug {
    /// Send event to external system
    fn send_event(&self, event: &SecurityEvent) -> Result<(), BuckwildError>;
    
    /// Send incident to external system
    fn send_incident(&self, incident: &SecurityIncident) -> Result<(), BuckwildError>;
    
    /// Get integration name
    fn name(&self) -> &str;
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            max_events: 10000,
            correlation_window_seconds: 300, // 5 minutes
            min_events_for_incident: 5,
            incident_timeout_seconds: 3600, // 1 hour
            cleanup_interval_seconds: 300,  // 5 minutes
        }
    }
}

impl SecurityEventCorrelator {
    /// Create a new security event correlator
    pub fn new() -> Self {
        Self::with_config(CorrelationConfig::default())
    }

    /// Create a new correlator with custom configuration
    pub fn with_config(config: CorrelationConfig) -> Self {
        let mut correlator = Self {
            events: Arc::new(RwLock::new(VecDeque::new())),
            incidents: Arc::new(RwLock::new(HashMap::new())),
            attack_patterns: Arc::new(RwLock::new(Vec::new())),
            config,
            stats: Arc::new(RwLock::new(CorrelationStats::default())),
            external_integrations: Arc::new(RwLock::new(Vec::new())),
        };

        // Initialize default attack patterns
        correlator.initialize_default_patterns();
        correlator
    }

    /// Initialize default attack patterns
    fn initialize_default_patterns(&mut self) {
        let mut patterns = self.attack_patterns.write();
        
        // Brute force pattern
        patterns.push(AttackPattern {
            name: "brute_force".to_string(),
            description: "Multiple authentication failures from same source".to_string(),
            event_types: vec![SecurityEventType::AuthenticationFailure, SecurityEventType::InvalidNonce],
            min_events: 10,
            time_window: Duration::from_secs(60),
            matcher: Self::brute_force_matcher,
            incident_severity: EventSeverity::High,
        });

        // Port scanning pattern
        patterns.push(AttackPattern {
            name: "port_scanning".to_string(),
            description: "Sequential port access attempts".to_string(),
            event_types: vec![SecurityEventType::PortScanning, SecurityEventType::EnumerationAttack],
            min_events: 20,
            time_window: Duration::from_secs(120),
            matcher: Self::port_scanning_matcher,
            incident_severity: EventSeverity::Medium,
        });

        // Replay attack pattern
        patterns.push(AttackPattern {
            name: "replay_attack".to_string(),
            description: "Multiple replay attempts detected".to_string(),
            event_types: vec![SecurityEventType::ReplayAttack, SecurityEventType::DuplicatePacket],
            min_events: 5,
            time_window: Duration::from_secs(30),
            matcher: Self::replay_attack_matcher,
            incident_severity: EventSeverity::High,
        });

        // Resource exhaustion pattern
        patterns.push(AttackPattern {
            name: "resource_exhaustion".to_string(),
            description: "Attempts to exhaust system resources".to_string(),
            event_types: vec![SecurityEventType::FragmentBomb, SecurityEventType::RateLimitExceeded],
            min_events: 3,
            time_window: Duration::from_secs(60),
            matcher: Self::resource_exhaustion_matcher,
            incident_severity: EventSeverity::Critical,
        });
    }

    /// Record a security event
    pub fn record_event(
        &self,
        event_type: SecurityEventType,
        severity: EventSeverity,
        source_ip: Option<IpAddr>,
        target: Option<String>,
        session_id: Option<u64>,
        details: HashMap<String, String>,
    ) -> Result<Uuid, BuckwildError> {
        let event_id = Uuid::new_v4();
        let correlation_id = Uuid::new_v4(); // Will be updated during correlation
        
        let event = SecurityEvent {
            event_id,
            correlation_id,
            event_type,
            severity,
            source_ip,
            target,
            session_id,
            timestamp: SystemTime::now(),
            details,
            attack_signature: None,
        };

        // Store event
        {
            let mut events = self.events.write();
            
            // Maintain maximum event count
            if events.len() >= self.config.max_events {
                events.pop_front();
            }
            
            events.push_back(event.clone());
        }

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_events += 1;
        }

        // Perform correlation analysis
        self.correlate_events(&event)?;

        // Send to external integrations
        self.send_to_external_integrations(&event)?;

        info!("Security event recorded: type={:?}, severity={:?}, source={:?}", 
              event.event_type, event.severity, event.source_ip);

        Ok(event_id)
    }

    /// Correlate events and detect attack patterns
    fn correlate_events(&self, new_event: &SecurityEvent) -> Result<(), BuckwildError> {
        let events = self.events.read();
        let patterns = self.attack_patterns.read();
        let current_time = SystemTime::now();

        for pattern in patterns.iter() {
            // Check if new event matches pattern
            if !pattern.event_types.contains(&new_event.event_type) {
                continue;
            }

            // Get recent events within time window
            let window_start = current_time
                .checked_sub(pattern.time_window)
                .unwrap_or(current_time);

            let recent_events: Vec<SecurityEvent> = events.iter()
                .filter(|e| e.timestamp >= window_start)
                .filter(|e| pattern.event_types.contains(&e.event_type))
                .filter(|e| {
                    // Group by source IP if available
                    match (e.source_ip, new_event.source_ip) {
                        (Some(e_ip), Some(new_ip)) => e_ip == new_ip,
                        _ => true, // Include events without IP info
                    }
                })
                .cloned()
                .collect();

            // Check if pattern matches
            if recent_events.len() >= pattern.min_events && (pattern.matcher)(&recent_events) {
                self.create_incident(&pattern, &recent_events)?;
                
                let mut stats = self.stats.write();
                stats.patterns_matched += 1;
            }
        }

        Ok(())
    }

    /// Create a security incident
    fn create_incident(
        &self,
        pattern: &AttackPattern,
        related_events: &[SecurityEvent],
    ) -> Result<Uuid, BuckwildError> {
        let incident_id = Uuid::new_v4();
        let current_time = SystemTime::now();

        // Determine incident type based on pattern
        let incident_type = match pattern.name.as_str() {
            "brute_force" => IncidentType::BruteForce,
            "port_scanning" => IncidentType::NetworkReconnaissance,
            "replay_attack" => IncidentType::ProtocolViolation,
            "resource_exhaustion" => IncidentType::ResourceExhaustion,
            _ => IncidentType::SuspiciousActivity,
        };

        // Extract source IP from events
        let source_ip = related_events.iter()
            .find_map(|e| e.source_ip)
            .or_else(|| related_events.first()?.source_ip);

        let incident = SecurityIncident {
            incident_id,
            incident_type,
            severity: pattern.incident_severity.clone(),
            source_ip,
            related_events: related_events.iter().map(|e| e.event_id).collect(),
            start_time: related_events.iter()
                .map(|e| e.timestamp)
                .min()
                .unwrap_or(current_time),
            last_update: current_time,
            status: IncidentStatus::Active,
            response_actions: Vec::new(),
            attack_pattern: Some(pattern.name.clone()),
        };

        // Store incident
        {
            let mut incidents = self.incidents.write();
            incidents.insert(incident_id, incident.clone());
        }

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.active_incidents += 1;
        }

        // Trigger automatic response
        self.trigger_incident_response(&incident)?;

        // Send to external integrations
        self.send_incident_to_external(&incident)?;

        warn!("Security incident created: id={}, type={:?}, pattern={}, source={:?}", 
              incident_id, incident.incident_type, pattern.name, incident.source_ip);

        Ok(incident_id)
    }

    /// Trigger automatic incident response
    fn trigger_incident_response(&self, incident: &SecurityIncident) -> Result<(), BuckwildError> {
        let mut response_actions = Vec::new();

        match incident.incident_type {
            IncidentType::BruteForce => {
                if let Some(source_ip) = incident.source_ip {
                    response_actions.push(self.create_response_action(
                        ResponseActionType::BlockSource,
                        format!("Blocking source IP {} due to brute force attack", source_ip),
                    ));
                }
            },
            IncidentType::ResourceExhaustion => {
                if let Some(source_ip) = incident.source_ip {
                    response_actions.push(self.create_response_action(
                        ResponseActionType::RateLimit,
                        format!("Rate limiting source IP {} due to resource exhaustion", source_ip),
                    ));
                }
            },
            IncidentType::NetworkReconnaissance => {
                response_actions.push(self.create_response_action(
                    ResponseActionType::AlertAdmin,
                    "Network reconnaissance detected - manual review required".to_string(),
                ));
            },
            _ => {
                response_actions.push(self.create_response_action(
                    ResponseActionType::ExternalLog,
                    format!("Logging incident {} to external systems", incident.incident_id),
                ));
            }
        }

        // Update incident with response actions
        {
            let mut incidents = self.incidents.write();
            if let Some(stored_incident) = incidents.get_mut(&incident.incident_id) {
                stored_incident.response_actions.extend(response_actions);
                stored_incident.last_update = SystemTime::now();
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.response_actions += response_actions.len() as u64;
        }

        Ok(())
    }

    /// Create a response action
    fn create_response_action(&self, action_type: ResponseActionType, details: String) -> ResponseAction {
        ResponseAction {
            action_type,
            timestamp: SystemTime::now(),
            details,
            result: ActionResult::Pending,
        }
    }

    /// Add external monitoring integration
    pub fn add_external_integration(
        &self,
        integration: Box<dyn ExternalMonitoringIntegration + Send + Sync>,
    ) {
        let mut integrations = self.external_integrations.write();
        integrations.push(integration);
        info!("Added external monitoring integration: {}", integrations.last().unwrap().name());
    }

    /// Send event to external integrations
    fn send_to_external_integrations(&self, event: &SecurityEvent) -> Result<(), BuckwildError> {
        let integrations = self.external_integrations.read();
        
        for integration in integrations.iter() {
            if let Err(e) = integration.send_event(event) {
                warn!("Failed to send event to {}: {}", integration.name(), e);
            }
        }

        Ok(())
    }

    /// Send incident to external integrations
    fn send_incident_to_external(&self, incident: &SecurityIncident) -> Result<(), BuckwildError> {
        let integrations = self.external_integrations.read();
        
        for integration in integrations.iter() {
            if let Err(e) = integration.send_incident(incident) {
                warn!("Failed to send incident to {}: {}", integration.name(), e);
            }
        }

        Ok(())
    }

    /// Get current statistics
    pub fn get_stats(&self) -> CorrelationStats {
        let mut stats = self.stats.read().clone();
        stats.active_incidents = self.incidents.read().len() as u64;
        stats
    }

    /// Get active incidents
    pub fn get_active_incidents(&self) -> Vec<SecurityIncident> {
        self.incidents.read()
            .values()
            .filter(|i| i.status == IncidentStatus::Active)
            .cloned()
            .collect()
    }

    /// Resolve incident
    pub fn resolve_incident(&self, incident_id: Uuid, resolution: IncidentStatus) -> Result<bool, BuckwildError> {
        let mut incidents = self.incidents.write();
        
        if let Some(incident) = incidents.get_mut(&incident_id) {
            incident.status = resolution.clone();
            incident.last_update = SystemTime::now();
            
            if resolution == IncidentStatus::FalsePositive {
                let mut stats = self.stats.write();
                stats.false_positives += 1;
            }
            
            info!("Incident resolved: id={}, status={:?}", incident_id, resolution);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Clean up old events and incidents
    pub fn cleanup_old_entries(&self) -> Result<(usize, usize), BuckwildError> {
        let current_time = SystemTime::now();
        let event_retention = Duration::from_secs(self.config.correlation_window_seconds * 2);
        let incident_timeout = Duration::from_secs(self.config.incident_timeout_seconds);

        let mut events_removed = 0;
        let mut incidents_removed = 0;

        // Clean up old events
        {
            let mut events = self.events.write();
            let initial_size = events.len();
            
            events.retain(|event| {
                current_time.duration_since(event.timestamp)
                    .map(|age| age < event_retention)
                    .unwrap_or(false)
            });
            
            events_removed = initial_size - events.len();
        }

        // Clean up old incidents
        {
            let mut incidents = self.incidents.write();
            let initial_size = incidents.len();
            
            incidents.retain(|_, incident| {
                if incident.status == IncidentStatus::Active {
                    current_time.duration_since(incident.last_update)
                        .map(|age| age < incident_timeout)
                        .unwrap_or(false)
                } else {
                    // Keep resolved incidents for a while
                    current_time.duration_since(incident.last_update)
                        .map(|age| age < incident_timeout * 2)
                        .unwrap_or(false)
                }
            });
            
            incidents_removed = initial_size - incidents.len();
        }

        if events_removed > 0 || incidents_removed > 0 {
            info!("Cleanup completed: {} events, {} incidents removed", 
                  events_removed, incidents_removed);
        }

        Ok((events_removed, incidents_removed))
    }

    // Attack pattern matchers
    fn brute_force_matcher(events: &[SecurityEvent]) -> bool {
        // Check for rapid authentication failures
        events.len() >= 10 && 
        events.iter().all(|e| matches!(e.event_type, 
            SecurityEventType::AuthenticationFailure | SecurityEventType::InvalidNonce))
    }

    fn port_scanning_matcher(events: &[SecurityEvent]) -> bool {
        // Check for sequential port access
        events.len() >= 20 &&
        events.iter().any(|e| e.event_type == SecurityEventType::PortScanning)
    }

    fn replay_attack_matcher(events: &[SecurityEvent]) -> bool {
        // Check for multiple replay attempts
        events.len() >= 5 &&
        events.iter().any(|e| e.event_type == SecurityEventType::ReplayAttack)
    }

    fn resource_exhaustion_matcher(events: &[SecurityEvent]) -> bool {
        // Check for resource exhaustion attempts
        events.iter().any(|e| e.event_type == SecurityEventType::FragmentBomb) ||
        events.iter().filter(|e| e.event_type == SecurityEventType::RateLimitExceeded).count() >= 3
    }
}

impl Default for SecurityEventCorrelator {
    fn default() -> Self {
        Self::new()
    }
}
