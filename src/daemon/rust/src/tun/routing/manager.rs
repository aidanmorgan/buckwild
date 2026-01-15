use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
#[cfg(target_os = "linux")]
use futures_util::{StreamExt, TryStreamExt};
#[cfg(target_os = "linux")]
use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage};
#[cfg(target_os = "linux")]
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
#[cfg(target_os = "linux")]
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
#[cfg(target_os = "linux")]
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
#[cfg(target_os = "linux")]
use rtnetlink::{Handle, new_connection};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::config::hosts::parser::HostsConfig;

/// Errors that can occur during routing operations
#[derive(Error, Debug)]

pub enum RoutingError {
    #[cfg(target_os = "linux")]
    #[error("Netlink error: {0}")]
    NetlinkError(#[from] rtnetlink::Error),

    #[error("Failed to parse IP address: {0}")]
    IpParseError(#[from] std::net::AddrParseError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid route configuration: {0}")]
    InvalidRouteConfig(String),

    #[error("Route already exists")]
    RouteExists,

    #[error("Route not found")]
    RouteNotFound,

    #[error("Operation not supported on this platform")]
    Unsupported,
}

/// Route entry
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    /// Destination IP address
    pub destination: IpAddr,

    /// Prefix length
    pub prefix_len: u8,

    /// Gateway IP address
    pub gateway: Option<IpAddr>,

    /// Output interface
    pub interface: String,

    /// Route metric
    pub metric: u32,
}

/// Manages routing table updates for TUN device
pub struct RoutingManager {
    /// Netlink handle
    #[cfg(target_os = "linux")]
    handle: Arc<Handle>,

    /// Current routes
    routes: Arc<RwLock<HashSet<Route>>>,

    /// Interface index cache
    interface_indices: Arc<DashMap<String, u32>>,

    /// TUN device name
    tun_device: String,
}

impl RoutingManager {
    /// Create a new routing manager
    #[cfg(target_os = "linux")]
    #[instrument(err)]
    pub async fn new(tun_device: &str) -> Result<Self, RoutingError> {
        // Create netlink connection
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);

        let manager = Self {
            handle: Arc::new(handle),
            routes: Arc::new(RwLock::new(HashSet::new())),
            interface_indices: Arc::new(DashMap::new()),
            tun_device: tun_device.to_string(),
        };

        // Initialize interface indices
        manager.refresh_interface_indices().await?;

        Ok(manager)
    }

    /// Create a new routing manager (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    #[instrument(err)]
    pub fn new(tun_device: &str) -> Result<Self, RoutingError> {
        Ok(Self {
            routes: Arc::new(RwLock::new(HashSet::new())),
            interface_indices: Arc::new(DashMap::new()),
            tun_device: tun_device.to_string(),
        })
    }

    /// Refresh interface indices
    #[instrument(skip(self), err)]
    async fn refresh_interface_indices(&self) -> Result<(), RoutingError> {
        #[cfg(target_os = "linux")]
        {
            // Clear current indices
            self.interface_indices.clear();

            // Get all links
            let mut links = self.handle.link().get().execute();

            while let Some(link) = links.try_next().await? {
                if let Some(name) = link.attributes.iter().find_map(|attr| {
                    if let LinkAttribute::IfName(name) = attr {
                        Some(name.clone())
                    } else {
                        None
                    }
                }) {
                    self.interface_indices.insert(name, link.header.index);
                }
            }

            debug!(
                "Refreshed interface indices: {} interfaces found",
                self.interface_indices.len()
            );
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!("Interface index refresh skipped on non-Linux platform");
        }

        Ok(())
    }

    /// Get interface index by name
    #[instrument(skip(self), err)]
    async fn get_interface_index(&self, name: &str) -> Result<u32, RoutingError> {
        // Check cache first
        if let Some(index) = self.interface_indices.get(name) {
            return Ok(*index);
        }

        // Refresh indices and try again
        self.refresh_interface_indices().await?;

        if let Some(index) = self.interface_indices.get(name) {
            Ok(*index)
        } else {
            Err(RoutingError::InvalidRouteConfig(format!(
                "Interface not found: {}",
                name
            )))
        }
    }

    /// Update routes based on hosts configuration
    #[cfg(target_os = "linux")]
    #[instrument(skip(self, config), err)]
    pub async fn update_from_config(&self, config: &HostsConfig) -> Result<(), RoutingError> {
        // Get current routes
        let current_routes = self.routes.read().await.clone();

        // Build new routes
        let mut new_routes = HashSet::new();

        for host in &config.hosts {
            // Get IP address
            let ip: IpAddr = host.ip.to_std();

            // Create route
            let route = Route {
                destination: ip,
                prefix_len: if ip.is_ipv4() { 32 } else { 128 },
                gateway: None,
                interface: self.tun_device.clone(),
                metric: 100,
            };

            new_routes.insert(route);
        }

        // Calculate routes to add and remove
        let routes_to_add: Vec<_> = new_routes.difference(&current_routes).cloned().collect();
        let routes_to_remove: Vec<_> = current_routes.difference(&new_routes).cloned().collect();

        // Remove old routes
        for route in &routes_to_remove {
            if let Err(e) = self.remove_route(route).await {
                warn!(
                    destination = %route.destination,
                    error = %e,
                    "Failed to remove route"
                );
            }
        }

        // Add new routes
        for route in &routes_to_add {
            if let Err(e) = self.add_route(route).await {
                warn!(
                    destination = %route.destination,
                    error = %e,
                    "Failed to add route"
                );
            }
        }

        // Update current routes
        *self.routes.write().await = new_routes;

        // Capture total before logging to avoid Sync issues with tracing
        let total_routes = self.routes.read().await.len();
        info!(
            added = routes_to_add.len(),
            removed = routes_to_remove.len(),
            total = total_routes,
            "Updated routes"
        );

        Ok(())
    }

    /// Update routes based on hosts configuration (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    #[instrument(skip(self), err)]
    pub async fn update_from_config(&self, _config: &HostsConfig) -> Result<(), RoutingError> {
        info!("Route updates not supported on non-Linux platforms");
        Ok(())
    }

    /// Add a route
    #[cfg(target_os = "linux")]
    #[instrument(skip(self), err)]
    async fn add_route(&self, route: &Route) -> Result<(), RoutingError> {
        // Get interface index
        let if_index = self.get_interface_index(&route.interface).await?;

        // Build route header
        let mut header = RouteHeader::default();
        header.table = 254; // RT_TABLE_MAIN
        header.protocol = RouteProtocol::Boot;
        header.scope = RouteScope::Universe;
        header.kind = RouteType::Unicast;

        // Set address family and destination prefix length
        match route.destination {
            IpAddr::V4(_) => {
                header.address_family = AddressFamily::Inet;
                header.destination_prefix_length = route.prefix_len;
            }
            IpAddr::V6(_) => {
                header.address_family = AddressFamily::Inet6;
                header.destination_prefix_length = route.prefix_len;
            }
        }

        // Build route attributes
        let mut attributes = Vec::new();

        // Add destination
        match route.destination {
            IpAddr::V4(addr) => {
                attributes.push(RouteAttribute::Destination(RouteAddress::Inet(addr)));
            }
            IpAddr::V6(addr) => {
                attributes.push(RouteAttribute::Destination(RouteAddress::Inet6(addr)));
            }
        }

        // Add output interface
        attributes.push(RouteAttribute::Oif(if_index));

        // Add gateway if present
        if let Some(gateway) = route.gateway {
            match gateway {
                IpAddr::V4(addr) => {
                    attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(addr)));
                }
                IpAddr::V6(addr) => {
                    attributes.push(RouteAttribute::Gateway(RouteAddress::Inet6(addr)));
                }
            }
        }

        // Add metric/priority
        attributes.push(RouteAttribute::Priority(route.metric));

        // Create route message
        let mut message = RouteMessage::default();
        message.header = header;
        message.attributes = attributes;

        // Create netlink message for adding route
        let mut req: NetlinkMessage<RouteNetlinkMessage> =
            RouteNetlinkMessage::NewRoute(message).into();
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;

        // Execute via direct request
        let mut response = self.handle.as_ref().clone().request(req)?;

        // Consume the response stream
        while let Some(_msg) = response.next().await {
            // ACK received, route added successfully
        }

        info!(
            destination = %route.destination,
            prefix_len = route.prefix_len,
            interface = %route.interface,
            "Added route"
        );

        Ok(())
    }

    /// Remove a route
    #[instrument(skip(self), err)]
    #[cfg(target_os = "linux")]
    async fn remove_route(&self, route: &Route) -> Result<(), RoutingError> {
        // Get interface index
        let if_index = self.get_interface_index(&route.interface).await?;

        // Build route header
        let mut header = RouteHeader::default();
        header.table = 254; // RT_TABLE_MAIN
        header.protocol = RouteProtocol::Boot;
        header.scope = RouteScope::Universe;
        header.kind = RouteType::Unicast;

        // Set address family and destination prefix length
        match route.destination {
            IpAddr::V4(_) => {
                header.address_family = AddressFamily::Inet;
                header.destination_prefix_length = route.prefix_len;
            }
            IpAddr::V6(_) => {
                header.address_family = AddressFamily::Inet6;
                header.destination_prefix_length = route.prefix_len;
            }
        }

        // Build route attributes
        let mut attributes = Vec::new();

        // Add destination
        match route.destination {
            IpAddr::V4(addr) => {
                attributes.push(RouteAttribute::Destination(RouteAddress::Inet(addr)));
            }
            IpAddr::V6(addr) => {
                attributes.push(RouteAttribute::Destination(RouteAddress::Inet6(addr)));
            }
        }

        // Add output interface
        attributes.push(RouteAttribute::Oif(if_index));

        // Add gateway if present
        if let Some(gateway) = route.gateway {
            match gateway {
                IpAddr::V4(addr) => {
                    attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(addr)));
                }
                IpAddr::V6(addr) => {
                    attributes.push(RouteAttribute::Gateway(RouteAddress::Inet6(addr)));
                }
            }
        }

        // Add metric/priority
        attributes.push(RouteAttribute::Priority(route.metric));

        // Create route message
        let mut message = RouteMessage::default();
        message.header = header;
        message.attributes = attributes;

        // Create netlink message for deleting route
        let mut req: NetlinkMessage<RouteNetlinkMessage> =
            RouteNetlinkMessage::DelRoute(message).into();
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        // Execute via direct request
        let mut response = self.handle.as_ref().clone().request(req)?;

        // Consume the response stream
        while let Some(_msg) = response.next().await {
            // ACK received, route deleted successfully
        }

        info!(
            destination = %route.destination,
            prefix_len = route.prefix_len,
            interface = %route.interface,
            "Removed route"
        );

        Ok(())
    }

    /// Add a route (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    #[instrument(skip(self), err)]
    async fn add_route(&self, route: &Route) -> Result<(), RoutingError> {
        warn!(
            destination = %route.destination,
            "Route addition not supported on non-Linux platforms (requires netlink)"
        );
        // Non-Linux platforms: no-op (routes are typically managed by OS)
        Ok(())
    }

    /// Remove a route (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    #[instrument(skip(self), err)]
    async fn remove_route(&self, route: &Route) -> Result<(), RoutingError> {
        warn!(
            destination = %route.destination,
            "Route removal not supported on non-Linux platforms (requires netlink)"
        );
        // Non-Linux platforms: no-op (routes are typically managed by OS)
        Ok(())
    }

    /// Get all current routes
    pub async fn get_routes(&self) -> HashSet<Route> {
        self.routes.read().await.clone()
    }

    /// Get the number of routes
    pub async fn route_count(&self) -> usize {
        self.routes.read().await.len()
    }

    /// Clear all routes
    #[instrument(skip(self), err)]
    pub async fn clear_routes(&self) -> Result<(), RoutingError> {
        let routes = self.routes.read().await.clone();

        for route in &routes {
            if let Err(e) = self.remove_route(route).await {
                warn!(
                    destination = %route.destination,
                    error = %e,
                    "Failed to remove route"
                );
            }
        }

        self.routes.write().await.clear();

        info!("Cleared all routes");

        Ok(())
    }
}
