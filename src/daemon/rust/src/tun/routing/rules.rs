use super::manager::RoutingError;
#[cfg(target_os = "linux")]
use futures_util::stream::{StreamExt, TryStreamExt};
#[cfg(target_os = "linux")]
use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage};
#[cfg(target_os = "linux")]
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
#[cfg(target_os = "linux")]
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
#[cfg(target_os = "linux")]
use rtnetlink::{Handle, new_connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

/// Routing rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub metric: u32,
    pub table: Option<u32>,
}

/// Routing table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub metric: u32,
    pub table: u32,
    pub active: bool,
}

/// Routing rule validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Dynamic routing rule manager
#[derive(Debug)]
pub struct RoutingRules {
    rules: Arc<RwLock<HashMap<String, RoutingRule>>>,
    active_routes: Arc<RwLock<HashMap<String, RouteEntry>>>,
    #[cfg(target_os = "linux")]
    netlink_handle: Handle,
    default_table: u32,
    tun_interface: String,
}

impl RoutingRules {
    /// Create a new routing rules manager
    #[instrument]
    pub async fn new(tun_interface: String, default_table: u32) -> Result<Self, RoutingError> {
        info!(
            "Creating routing rules manager for interface: {}, table: {}",
            tun_interface, default_table
        );

        #[cfg(target_os = "linux")]
        {
            // Create netlink connection
            let (connection, handle, _) = new_connection()?;

            // Spawn netlink connection task
            tokio::spawn(connection);

            Ok(RoutingRules {
                rules: Arc::new(RwLock::new(HashMap::new())),
                active_routes: Arc::new(RwLock::new(HashMap::new())),
                netlink_handle: handle,
                default_table,
                tun_interface,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(RoutingError::Unsupported)
        }
    }

    /// Add routing rule
    #[instrument(skip(self))]
    pub async fn add_rule(&self, rule_id: String, rule: RoutingRule) -> Result<(), RoutingError> {
        debug!("Adding routing rule: {} -> {:?}", rule_id, rule);

        // Validate rule
        let validation = self.validate_rule(&rule).await?;
        if !validation.valid {
            return Err(RoutingError::InvalidRouteConfig(format!(
                "Invalid routing rule: {:?}",
                validation.errors
            )));
        }

        // Log warnings
        for warning in &validation.warnings {
            warn!("Routing rule warning: {}", warning);
        }

        // Store rule
        self.rules
            .write()
            .await
            .insert(rule_id.clone(), rule.clone());

        // Apply rule to system
        self.apply_rule(&rule_id, &rule).await?;

        info!("Added routing rule: {}", rule_id);
        Ok(())
    }

    /// Remove routing rule
    #[instrument(skip(self))]
    pub async fn remove_rule(&self, rule_id: &str) -> Result<(), RoutingError> {
        debug!("Removing routing rule: {}", rule_id);

        let rule = {
            let mut rules = self.rules.write().await;
            rules.remove(rule_id)
        };

        if let Some(rule) = rule {
            // Remove from system
            self.remove_system_route(&rule).await?;

            // Remove from active routes
            self.active_routes.write().await.remove(rule_id);

            info!("Removed routing rule: {}", rule_id);
        } else {
            warn!("Attempted to remove non-existent rule: {}", rule_id);
        }

        Ok(())
    }

    /// Update routing rule
    #[instrument(skip(self))]
    pub async fn update_rule(
        &self,
        rule_id: String,
        rule: RoutingRule,
    ) -> Result<(), RoutingError> {
        debug!("Updating routing rule: {} -> {:?}", rule_id, rule);

        // Remove old rule if it exists
        if self.rules.read().await.contains_key(&rule_id) {
            self.remove_rule(&rule_id).await?;
        }

        // Add new rule
        self.add_rule(rule_id, rule).await?;

        Ok(())
    }

    /// Apply rule batch with validation
    #[instrument(skip(self, rules))]
    pub async fn apply_rule_batch(
        &self,
        rules: HashMap<String, RoutingRule>,
    ) -> Result<Vec<String>, RoutingError> {
        debug!("Applying rule batch with {} rules", rules.len());

        let mut applied_rules = Vec::new();
        let mut failed_rules = Vec::new();

        // Validate all rules first
        for (rule_id, rule) in &rules {
            let validation = self.validate_rule(rule).await?;
            if !validation.valid {
                error!(
                    "Rule {} failed validation: {:?}",
                    rule_id, validation.errors
                );
                failed_rules.push(rule_id.clone());
            }
        }

        // Apply valid rules
        for (rule_id, rule) in rules {
            if !failed_rules.contains(&rule_id) {
                match self.add_rule(rule_id.clone(), rule).await {
                    Ok(()) => applied_rules.push(rule_id),
                    Err(e) => {
                        error!("Failed to apply rule {}: {}", rule_id, e);
                        failed_rules.push(rule_id);
                    }
                }
            }
        }

        if !failed_rules.is_empty() {
            warn!(
                "Failed to apply {} rules: {:?}",
                failed_rules.len(),
                failed_rules
            );
        }

        info!("Applied {} rules successfully", applied_rules.len());
        Ok(applied_rules)
    }

    /// Get all active rules
    pub async fn get_rules(&self) -> HashMap<String, RoutingRule> {
        self.rules.read().await.clone()
    }

    /// Get active routes
    pub async fn get_active_routes(&self) -> HashMap<String, RouteEntry> {
        self.active_routes.read().await.clone()
    }

    /// Validate routing rule
    async fn validate_rule(&self, rule: &RoutingRule) -> Result<ValidationResult, RoutingError> {
        let mut result = ValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Validate destination address
        match rule.destination {
            IpAddr::V4(_) => {
                if rule.prefix_length > 32 {
                    result.valid = false;
                    result
                        .errors
                        .push("IPv4 prefix length cannot exceed 32".to_string());
                }
            }
            IpAddr::V6(_) => {
                if rule.prefix_length > 128 {
                    result.valid = false;
                    result
                        .errors
                        .push("IPv6 prefix length cannot exceed 128".to_string());
                }
            }
        }

        // Validate gateway if present
        if let Some(gateway) = &rule.gateway {
            match (&rule.destination, gateway) {
                (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
                    result.valid = false;
                    result
                        .errors
                        .push("Gateway and destination must be same IP version".to_string());
                }
                _ => {}
            }
        }

        // Validate interface
        if rule.interface.is_empty() {
            result.valid = false;
            result
                .errors
                .push("Interface name cannot be empty".to_string());
        }

        // Validate metric
        if rule.metric == 0 {
            result
                .warnings
                .push("Metric 0 may cause routing conflicts".to_string());
        }

        // Check for potential conflicts
        let existing_rules = self.rules.read().await;
        for (existing_id, existing_rule) in existing_rules.iter() {
            if existing_rule.destination == rule.destination
                && existing_rule.prefix_length == rule.prefix_length
                && existing_rule.table.unwrap_or(self.default_table)
                    == rule.table.unwrap_or(self.default_table)
            {
                result.warnings.push(format!(
                    "Rule conflicts with existing rule: {}",
                    existing_id
                ));
            }
        }

        Ok(result)
    }

    /// Apply rule to system routing table
    async fn apply_rule(&self, rule_id: &str, rule: &RoutingRule) -> Result<(), RoutingError> {
        debug!("Applying rule to system: {} -> {:?}", rule_id, rule);

        // Create route entry
        let route_entry = RouteEntry {
            destination: rule.destination,
            prefix_length: rule.prefix_length,
            gateway: rule.gateway,
            interface: rule.interface.clone(),
            metric: rule.metric,
            table: rule.table.unwrap_or(self.default_table),
            active: false,
        };

        // Add route using netlink
        match self.add_system_route(&route_entry).await {
            Ok(()) => {
                let mut active_route = route_entry;
                active_route.active = true;
                self.active_routes
                    .write()
                    .await
                    .insert(rule_id.to_string(), active_route);
                debug!("Successfully applied rule to system: {}", rule_id);
            }
            Err(e) => {
                error!("Failed to apply rule to system: {}: {}", rule_id, e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Add route to system routing table
    #[cfg(target_os = "linux")]
    async fn add_system_route(&self, route: &RouteEntry) -> Result<(), RoutingError> {
        debug!("Adding system route: {:?}", route);

        // Get interface index
        let interface_index = self.get_interface_index(&route.interface).await?;

        // Create route message
        let mut route_message = RouteMessage::default();

        // Set route header
        let mut header = RouteHeader::default();
        header.table = route.table as u8;
        header.protocol = RouteProtocol::Boot; // RTPROT_BOOT
        header.scope = RouteScope::Link; // RT_SCOPE_LINK
        header.kind = RouteType::Unicast; // RTN_UNICAST

        match route.destination {
            IpAddr::V4(_) => {
                header.address_family = AddressFamily::Inet; // AF_INET
                header.destination_prefix_length = route.prefix_length;
            }
            IpAddr::V6(_) => {
                header.address_family = AddressFamily::Inet6; // AF_INET6
                header.destination_prefix_length = route.prefix_length;
            }
        }

        route_message.header = header;

        // Add route attributes
        let mut attributes = Vec::new();

        // Destination
        match route.destination {
            IpAddr::V4(addr) => {
                attributes.push(RouteAttribute::Destination(RouteAddress::Inet(addr)));
            }
            IpAddr::V6(addr) => {
                attributes.push(RouteAttribute::Destination(RouteAddress::Inet6(addr)));
            }
        }

        // Gateway
        if let Some(gateway) = &route.gateway {
            match gateway {
                IpAddr::V4(addr) => {
                    attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(*addr)));
                }
                IpAddr::V6(addr) => {
                    attributes.push(RouteAttribute::Gateway(RouteAddress::Inet6(*addr)));
                }
            }
        }

        // Output interface
        attributes.push(RouteAttribute::Oif(interface_index));

        // Metric
        attributes.push(RouteAttribute::Priority(route.metric));

        route_message.attributes = attributes;

        // Add route via direct netlink request
        let mut req: NetlinkMessage<RouteNetlinkMessage> =
            RouteNetlinkMessage::NewRoute(route_message).into();
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;

        let mut response = self.netlink_handle.clone().request(req)?;

        // Consume the response stream
        while let Some(_msg) = response.next().await {
            // ACK received, route added successfully
        }

        debug!("Successfully added system route");
        Ok(())
    }

    /// Remove route from system routing table
    #[cfg(target_os = "linux")]
    async fn remove_system_route(&self, rule: &RoutingRule) -> Result<(), RoutingError> {
        debug!("Removing system route: {:?}", rule);

        // Get interface index
        let interface_index = self.get_interface_index(&rule.interface).await?;

        // Create route message for deletion
        let mut route_message = RouteMessage::default();

        // Set route header
        let mut header = RouteHeader::default();
        header.table = rule.table.unwrap_or(self.default_table) as u8;

        match rule.destination {
            IpAddr::V4(_) => {
                header.address_family = AddressFamily::Inet; // AF_INET
                header.destination_prefix_length = rule.prefix_length;
            }
            IpAddr::V6(_) => {
                header.address_family = AddressFamily::Inet6; // AF_INET6
                header.destination_prefix_length = rule.prefix_length;
            }
        }

        route_message.header = header;

        // Add route attributes
        let mut attributes = Vec::new();

        // Destination
        match rule.destination {
            IpAddr::V4(addr) => {
                attributes.push(RouteAttribute::Destination(RouteAddress::Inet(addr)));
            }
            IpAddr::V6(addr) => {
                attributes.push(RouteAttribute::Destination(RouteAddress::Inet6(addr)));
            }
        }

        // Gateway
        if let Some(gateway) = &rule.gateway {
            match gateway {
                IpAddr::V4(addr) => {
                    attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(*addr)));
                }
                IpAddr::V6(addr) => {
                    attributes.push(RouteAttribute::Gateway(RouteAddress::Inet6(*addr)));
                }
            }
        }

        // Output interface
        attributes.push(RouteAttribute::Oif(interface_index));

        route_message.attributes = attributes;

        // Delete route via direct netlink request
        let mut req: NetlinkMessage<RouteNetlinkMessage> =
            RouteNetlinkMessage::DelRoute(route_message).into();
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = self.netlink_handle.clone().request(req)?;

        // Consume the response stream
        while let Some(_msg) = response.next().await {
            // ACK received, route deleted successfully
        }

        debug!("Successfully removed system route");
        Ok(())
    }

    /// Get interface index by name
    #[cfg(target_os = "linux")]
    async fn get_interface_index(&self, interface_name: &str) -> Result<u32, RoutingError> {
        let links = self
            .netlink_handle
            .link()
            .get()
            .execute()
            .try_collect::<Vec<_>>()
            .await?;

        for link in links {
            for attribute in &link.attributes {
                if let netlink_packet_route::link::LinkAttribute::IfName(name) = attribute {
                    if name == interface_name {
                        return Ok(link.header.index);
                    }
                }
            }
        }

        Err(RoutingError::InvalidRouteConfig(format!(
            "Interface not found: {}",
            interface_name
        )))
    }

    /// Add route to system routing table (non-Linux - returns Unsupported)
    #[cfg(not(target_os = "linux"))]
    async fn add_system_route(&self, _route: &RouteEntry) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    /// Remove route from system routing table (non-Linux - returns Unsupported)
    #[cfg(not(target_os = "linux"))]
    async fn remove_system_route(&self, _rule: &RoutingRule) -> Result<(), RoutingError> {
        Err(RoutingError::Unsupported)
    }

    /// Get interface index by name (non-Linux - returns Unsupported)
    #[cfg(not(target_os = "linux"))]
    async fn get_interface_index(&self, _interface_name: &str) -> Result<u32, RoutingError> {
        Err(RoutingError::Unsupported)
    }

    /// Clear all rules
    #[instrument(skip(self))]
    pub async fn clear_all_rules(&self) -> Result<(), RoutingError> {
        info!("Clearing all routing rules");

        let rule_ids: Vec<String> = self.rules.read().await.keys().cloned().collect();

        for rule_id in rule_ids {
            if let Err(e) = self.remove_rule(&rule_id).await {
                error!("Failed to remove rule {}: {}", rule_id, e);
            }
        }

        info!("Cleared all routing rules");
        Ok(())
    }
}
