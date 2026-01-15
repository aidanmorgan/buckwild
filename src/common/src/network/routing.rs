// Network routing functionality

#![cfg_attr(
    not(test),
    forbid(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use crate::error::{BuckwildError, BuckwildResult};
use crate::protocol::types::*;
use crate::protocol::types::{
    IpAddress, NetworkEndpoint, RouteMetric, SessionId as TypesSessionId, SizeLimit, UsageCount,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::RwLock;

/// Network routing table for managing routes to peers
#[derive(Debug)]
pub struct RoutingTable {
    /// IPv4 routes
    ipv4_routes: Arc<RwLock<HashMap<Ipv4Network, RouteEntry>>>,
    /// IPv6 routes
    ipv6_routes: Arc<RwLock<HashMap<Ipv6Network, RouteEntry>>>,
    /// Host-specific routes
    host_routes: Arc<RwLock<HashMap<IpAddress, RouteEntry>>>,
    /// Default routes
    default_routes: Arc<RwLock<Vec<RouteEntry>>>,
    /// Routing configuration
    config: RoutingConfig,
    /// Routing statistics
    stats: Arc<RwLock<RoutingStats>>,
}

/// Routing configuration
#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// Enable multi-peer routing
    pub enable_multi_peer: SecurityFlag,
    /// Maximum number of routes
    pub max_routes: SizeLimit,
    /// Route timeout for inactive routes
    pub route_timeout: std::time::Duration,
    /// Enable route metrics
    pub enable_metrics: SecurityFlag,
    /// Default route metric
    pub default_metric: RouteMetric,
}

/// Route entry in the routing table
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Destination network or host
    pub destination: RouteDestination,
    /// Next hop information
    pub next_hop: NextHop,
    /// Route metric (lower is better)
    pub metric: RouteMetric,
    /// Route state
    pub state: RouteState,
    /// Route metadata
    pub metadata: RouteMetadata,
}

/// Route destination
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RouteDestination {
    /// IPv4 network
    Ipv4Network(Ipv4Network),
    /// IPv6 network
    Ipv6Network(Ipv6Network),
    /// Specific host
    Host(IpAddress),
    /// Default route
    Default,
}

/// Next hop information
#[derive(Debug, Clone)]
pub struct NextHop {
    /// Gateway address
    pub gateway: Option<IpAddress>,
    /// Outgoing interface (TUN device or socket)
    pub interface: RouteInterface,
    /// Session ID for Buckwild protocol routing
    pub session_id: Option<TypesSessionId>,
    /// Endpoint for direct communication
    pub endpoint: Option<NetworkEndpoint>,
}

/// Route interface type
#[derive(Debug, Clone)]
pub enum RouteInterface {
    /// TUN device interface
    TunDevice(String),
    /// Socket interface
    Socket(String),
    /// Direct peer connection
    Direct,
}

// Use consolidated RouteState from protocol types
use crate::protocol::types::RouteState;

/// Route metadata
#[derive(Debug, Clone)]
pub struct RouteMetadata {
    /// When the route was created
    pub created_at: std::time::Instant,
    /// When the route was last used
    pub last_used: Option<std::time::Instant>,
    /// Route usage statistics
    pub usage_count: UsageCount,
    /// Route description
    pub description: Option<String>,
    /// Whether the route is persistent
    pub persistent: SecurityFlag,
}

/// IPv4 network representation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Network {
    /// Network address
    pub network: Ipv4Addr,
    /// Prefix length (CIDR notation)
    pub prefix_len: PrefixLength,
}

/// IPv6 network representation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6Network {
    /// Network address
    pub network: Ipv6Addr,
    /// Prefix length (CIDR notation)
    pub prefix_len: PrefixLength,
}

/// Routing statistics
#[derive(Debug, Default, Clone)]
pub struct RoutingStats {
    /// Total number of routes
    pub total_routes: SizeLimit,
    /// Active routes
    pub active_routes: SizeLimit,
    /// Failed routes
    pub failed_routes: SizeLimit,
    /// Route lookups performed
    pub lookups_performed: UsageCount,
    /// Successful route lookups
    pub successful_lookups: UsageCount,
    /// Route updates
    pub route_updates: UsageCount,
}

/// Route lookup result
#[derive(Debug, Clone)]
pub struct RouteLookupResult {
    /// Matched route entry
    pub route: RouteEntry,
    /// Lookup type that matched
    pub lookup_type: LookupType,
}

/// Type of route lookup that matched
#[derive(Debug, Clone)]
pub enum LookupType {
    /// Exact host match
    ExactHost,
    /// Network match
    Network,
    /// Default route
    Default,
}

/// Route addition request
#[derive(Debug, Clone)]
pub struct RouteAddRequest {
    /// Route destination
    pub destination: RouteDestination,
    /// Next hop information
    pub next_hop: NextHop,
    /// Route metric
    pub metric: Option<RouteMetric>,
    /// Route description
    pub description: Option<String>,
    /// Whether the route is persistent
    pub persistent: SecurityFlag,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            enable_multi_peer: SecurityFlag::new(true),
            max_routes: SizeLimit::new(10000),
            route_timeout: std::time::Duration::from_secs(3600), // 1 hour
            enable_metrics: SecurityFlag::new(true),
            default_metric: RouteMetric::new(100),
        }
    }
}

impl Ipv4Network {
    /// Create a new IPv4 network
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> BuckwildResult<Self> {
        if prefix_len > 32 {
            return Err(BuckwildError::invalid_input(
                "IPv4 prefix length cannot exceed 32",
            ));
        }

        Ok(Self {
            network,
            prefix_len: PrefixLength::new(prefix_len),
        })
    }

    /// Check if an IPv4 address is within this network
    pub fn contains(&self, addr: &Ipv4Addr) -> bool {
        let network_bits = u32::from(self.network);
        let addr_bits = u32::from(*addr);
        let mask = if self.prefix_len.as_u8() == 0 {
            0
        } else {
            !(1u32 << (32 - self.prefix_len.as_u32() - 1))
        };

        (network_bits & mask) == (addr_bits & mask)
    }

    /// Get the network mask
    pub fn netmask(&self) -> Ipv4Addr {
        let mask = if self.prefix_len.as_u8() == 0 {
            0
        } else {
            !(1u32 << (32 - self.prefix_len.as_u32() - 1))
        };
        Ipv4Addr::from(mask)
    }
}

impl Ipv6Network {
    /// Create a new IPv6 network
    pub fn new(network: Ipv6Addr, prefix_len: u8) -> BuckwildResult<Self> {
        if prefix_len > 128 {
            return Err(BuckwildError::invalid_input(
                "IPv6 prefix length cannot exceed 128",
            ));
        }

        Ok(Self {
            network,
            prefix_len: PrefixLength::new(prefix_len),
        })
    }

    /// Check if an IPv6 address is within this network
    pub fn contains(&self, addr: &Ipv6Addr) -> bool {
        let network_bits = u128::from(self.network);
        let addr_bits = u128::from(*addr);
        let mask = if self.prefix_len.as_u8() == 0 {
            0
        } else {
            !((1u128 << (128 - self.prefix_len.as_u32() as u128)) - 1)
        };

        (network_bits & mask) == (addr_bits & mask)
    }
}

impl RouteEntry {
    /// Create a new route entry
    pub fn new(destination: RouteDestination, next_hop: NextHop, metric: RouteMetric) -> Self {
        Self {
            destination,
            next_hop,
            metric,
            state: RouteState::Active,
            metadata: RouteMetadata {
                created_at: std::time::Instant::now(),
                last_used: None,
                usage_count: UsageCount::new(0),
                description: None,
                persistent: SecurityFlag::new(false),
            },
        }
    }

    /// Check if the route is usable
    pub fn is_usable(&self) -> bool {
        matches!(self.state, RouteState::Active)
    }

    /// Update route usage statistics
    pub fn update_usage(&mut self) {
        self.metadata.last_used = Some(std::time::Instant::now());
        self.metadata
            .usage_count
            .increment(std::sync::atomic::Ordering::Relaxed);
    }

    /// Check if the route has expired
    pub fn is_expired(&self, timeout: std::time::Duration) -> bool {
        if self.metadata.persistent.as_bool() {
            return false;
        }

        if let Some(last_used) = self.metadata.last_used {
            std::time::Instant::now().duration_since(last_used) > timeout
        } else {
            std::time::Instant::now().duration_since(self.metadata.created_at) > timeout
        }
    }
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new(config: RoutingConfig) -> Self {
        Self {
            ipv4_routes: Arc::new(RwLock::new(HashMap::new())),
            ipv6_routes: Arc::new(RwLock::new(HashMap::new())),
            host_routes: Arc::new(RwLock::new(HashMap::new())),
            default_routes: Arc::new(RwLock::new(Vec::new())),
            config,
            stats: Arc::new(RwLock::new(RoutingStats::default())),
        }
    }

    /// Add a route to the routing table
    pub async fn add_route(&self, request: RouteAddRequest) -> BuckwildResult<()> {
        // Check route limit
        let current_count = self.get_route_count().await;
        if current_count >= self.config.max_routes.as_usize() {
            return Err(BuckwildError::resource_exhausted(format!(
                "Maximum number of routes ({}) reached",
                self.config.max_routes.as_usize()
            )));
        }

        let metric = request.metric.unwrap_or(self.config.default_metric);
        let mut route = RouteEntry::new(request.destination.clone(), request.next_hop, metric);

        if let Some(description) = request.description {
            route.metadata.description = Some(description);
        }
        route.metadata.persistent = request.persistent;

        match request.destination {
            RouteDestination::Ipv4Network(network) => {
                let mut routes = self.ipv4_routes.write().await;
                routes.insert(network, route);
            }
            RouteDestination::Ipv6Network(network) => {
                let mut routes = self.ipv6_routes.write().await;
                routes.insert(network, route);
            }
            RouteDestination::Host(host) => {
                let mut routes = self.host_routes.write().await;
                routes.insert(host, route);
            }
            RouteDestination::Default => {
                let mut routes = self.default_routes.write().await;
                routes.push(route);
                // Sort by metric (lower is better)
                routes.sort_by_key(|r| r.metric);
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_routes = SizeLimit::new(stats.total_routes.as_usize() + 1);
            stats.active_routes = SizeLimit::new(stats.active_routes.as_usize() + 1);
            stats.route_updates = UsageCount::new(
                stats
                    .route_updates
                    .load(std::sync::atomic::Ordering::Relaxed)
                    + 1,
            );
        }

        Ok(())
    }

    /// Remove a route from the routing table
    pub async fn remove_route(&self, destination: &RouteDestination) -> BuckwildResult<()> {
        let removed = match destination {
            RouteDestination::Ipv4Network(network) => {
                let mut routes = self.ipv4_routes.write().await;
                routes.remove(network).is_some()
            }
            RouteDestination::Ipv6Network(network) => {
                let mut routes = self.ipv6_routes.write().await;
                routes.remove(network).is_some()
            }
            RouteDestination::Host(host) => {
                let mut routes = self.host_routes.write().await;
                routes.remove(host).is_some()
            }
            RouteDestination::Default => {
                let mut routes = self.default_routes.write().await;
                if !routes.is_empty() {
                    routes.remove(0);
                    true
                } else {
                    false
                }
            }
        };

        if removed {
            let mut stats = self.stats.write().await;
            stats.total_routes = SizeLimit::new(stats.total_routes.as_usize().saturating_sub(1));
            stats.active_routes = SizeLimit::new(stats.active_routes.as_usize().saturating_sub(1));
            stats.route_updates = UsageCount::new(
                stats
                    .route_updates
                    .load(std::sync::atomic::Ordering::Relaxed)
                    + 1,
            );
            Ok(())
        } else {
            Err(BuckwildError::not_found("Route not found"))
        }
    }

    /// Look up a route for the given destination
    pub async fn lookup_route(&self, destination: &IpAddress) -> Option<RouteLookupResult> {
        // Update lookup statistics
        {
            let stats = self.stats.write().await;
            stats.lookups_performed.increment(Ordering::Relaxed);
        }

        // First, check for exact host match
        {
            let mut host_routes = self.host_routes.write().await;
            if let Some(route) = host_routes.get_mut(destination) {
                if route.is_usable() {
                    route.update_usage();
                    let stats = self.stats.write().await;
                    stats.successful_lookups.increment(Ordering::Relaxed);
                    return Some(RouteLookupResult {
                        route: route.clone(),
                        lookup_type: LookupType::ExactHost,
                    });
                }
            }
        }

        // Check network routes based on IP version
        let ip_addr: std::net::IpAddr = destination.into();
        match ip_addr {
            IpAddr::V4(ipv4_addr) => {
                let mut ipv4_routes = self.ipv4_routes.write().await;

                // Find the most specific network match (longest prefix)
                let mut best_match: Option<(Ipv4Network, &mut RouteEntry)> = None;

                for (network, route) in ipv4_routes.iter_mut() {
                    if network.contains(&ipv4_addr) && route.is_usable() {
                        match best_match {
                            None => best_match = Some((network.clone(), route)),
                            Some((ref best_network, _)) => {
                                if network.prefix_len.as_u8() > best_network.prefix_len.as_u8() {
                                    best_match = Some((network.clone(), route));
                                }
                            }
                        }
                    }
                }

                if let Some((_, route)) = best_match {
                    route.update_usage();
                    let stats = self.stats.write().await;
                    stats.successful_lookups.increment(Ordering::Relaxed);
                    return Some(RouteLookupResult {
                        route: route.clone(),
                        lookup_type: LookupType::Network,
                    });
                }
            }
            IpAddr::V6(ipv6_addr) => {
                let mut ipv6_routes = self.ipv6_routes.write().await;

                // Find the most specific network match (longest prefix)
                let mut best_match: Option<(Ipv6Network, &mut RouteEntry)> = None;

                for (network, route) in ipv6_routes.iter_mut() {
                    if network.contains(&ipv6_addr) && route.is_usable() {
                        match best_match {
                            None => best_match = Some((network.clone(), route)),
                            Some((ref best_network, _)) => {
                                if network.prefix_len.as_u8() > best_network.prefix_len.as_u8() {
                                    best_match = Some((network.clone(), route));
                                }
                            }
                        }
                    }
                }

                if let Some((_, route)) = best_match {
                    route.update_usage();
                    let stats = self.stats.write().await;
                    stats.successful_lookups.increment(Ordering::Relaxed);
                    return Some(RouteLookupResult {
                        route: route.clone(),
                        lookup_type: LookupType::Network,
                    });
                }
            }
        }

        // Check default routes
        {
            let mut default_routes = self.default_routes.write().await;
            for route in default_routes.iter_mut() {
                if route.is_usable() {
                    route.update_usage();
                    let stats = self.stats.write().await;
                    stats.successful_lookups.increment(Ordering::Relaxed);
                    return Some(RouteLookupResult {
                        route: route.clone(),
                        lookup_type: LookupType::Default,
                    });
                }
            }
        }

        None
    }

    /// Get all routes in the routing table
    pub async fn get_all_routes(&self) -> Vec<RouteEntry> {
        let mut all_routes = Vec::new();

        // IPv4 routes
        {
            let ipv4_routes = self.ipv4_routes.read().await;
            all_routes.extend(ipv4_routes.values().cloned());
        }

        // IPv6 routes
        {
            let ipv6_routes = self.ipv6_routes.read().await;
            all_routes.extend(ipv6_routes.values().cloned());
        }

        // Host routes
        {
            let host_routes = self.host_routes.read().await;
            all_routes.extend(host_routes.values().cloned());
        }

        // Default routes
        {
            let default_routes = self.default_routes.read().await;
            all_routes.extend(default_routes.iter().cloned());
        }

        all_routes
    }

    /// Get routing statistics
    pub async fn get_stats(&self) -> RoutingStats {
        self.stats.read().await.clone()
    }

    /// Clean up expired routes
    pub async fn cleanup_expired_routes(&self) -> usize {
        let mut removed_count = 0;

        // Clean up IPv4 routes
        {
            let mut ipv4_routes = self.ipv4_routes.write().await;
            let expired_keys: Vec<_> = ipv4_routes
                .iter()
                .filter(|(_, route)| route.is_expired(self.config.route_timeout))
                .map(|(key, _)| key.clone())
                .collect();

            for key in expired_keys {
                ipv4_routes.remove(&key);
                removed_count += 1;
            }
        }

        // Clean up IPv6 routes
        {
            let mut ipv6_routes = self.ipv6_routes.write().await;
            let expired_keys: Vec<_> = ipv6_routes
                .iter()
                .filter(|(_, route)| route.is_expired(self.config.route_timeout))
                .map(|(key, _)| key.clone())
                .collect();

            for key in expired_keys {
                ipv6_routes.remove(&key);
                removed_count += 1;
            }
        }

        // Clean up host routes
        {
            let mut host_routes = self.host_routes.write().await;
            let expired_keys: Vec<_> = host_routes
                .iter()
                .filter(|(_, route)| route.is_expired(self.config.route_timeout))
                .map(|(key, _)| *key)
                .collect();

            for key in expired_keys {
                host_routes.remove(&key);
                removed_count += 1;
            }
        }

        // Clean up default routes
        {
            let mut default_routes = self.default_routes.write().await;
            default_routes.retain(|route| !route.is_expired(self.config.route_timeout));
        }

        // Update statistics
        if removed_count > 0 {
            let mut stats = self.stats.write().await;
            stats.total_routes =
                SizeLimit::new(stats.total_routes.as_usize().saturating_sub(removed_count));
            stats.active_routes =
                SizeLimit::new(stats.active_routes.as_usize().saturating_sub(removed_count));
        }

        removed_count
    }

    /// Get the total number of routes
    async fn get_route_count(&self) -> usize {
        let ipv4_count = self.ipv4_routes.read().await.len();
        let ipv6_count = self.ipv6_routes.read().await.len();
        let host_count = self.host_routes.read().await.len();
        let default_count = self.default_routes.read().await.len();

        ipv4_count + ipv6_count + host_count + default_count
    }

    /// Clear all routes
    pub async fn clear_all_routes(&self) {
        {
            let mut ipv4_routes = self.ipv4_routes.write().await;
            ipv4_routes.clear();
        }

        {
            let mut ipv6_routes = self.ipv6_routes.write().await;
            ipv6_routes.clear();
        }

        {
            let mut host_routes = self.host_routes.write().await;
            host_routes.clear();
        }

        {
            let mut default_routes = self.default_routes.write().await;
            default_routes.clear();
        }

        // Reset statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_routes = SizeLimit::new(0);
            stats.active_routes = SizeLimit::new(0);
        }
    }
}

/// Multi-peer routing manager for handling routes to multiple peers
#[derive(Debug)]
pub struct MultiPeerRouter {
    /// Main routing table
    routing_table: Arc<RoutingTable>,
    /// Peer-specific routing tables
    peer_tables: Arc<RwLock<HashMap<TypesSessionId, Arc<RoutingTable>>>>,
    /// Router configuration
    config: RoutingConfig,
}

impl MultiPeerRouter {
    /// Create a new multi-peer router
    pub fn new(config: RoutingConfig) -> Self {
        let routing_table = Arc::new(RoutingTable::new(config.clone()));

        Self {
            routing_table,
            peer_tables: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Add a peer-specific routing table
    pub async fn add_peer_table(&self, session_id: TypesSessionId) -> BuckwildResult<()> {
        let mut peer_tables = self.peer_tables.write().await;

        if peer_tables.contains_key(&session_id) {
            return Err(BuckwildError::invalid_input("Peer table already exists"));
        }

        let peer_table = Arc::new(RoutingTable::new(self.config.clone()));
        peer_tables.insert(session_id, peer_table);

        Ok(())
    }

    /// Remove a peer-specific routing table
    pub async fn remove_peer_table(&self, session_id: &TypesSessionId) -> BuckwildResult<()> {
        let mut peer_tables = self.peer_tables.write().await;

        if peer_tables.remove(session_id).is_some() {
            Ok(())
        } else {
            Err(BuckwildError::not_found("Peer table not found"))
        }
    }

    /// Look up a route, checking peer tables first, then main table
    pub async fn lookup_route(
        &self,
        destination: &IpAddress,
        session_id: Option<TypesSessionId>,
    ) -> Option<RouteLookupResult> {
        // First check peer-specific table if session ID is provided
        if let Some(session_id) = session_id {
            let peer_tables = self.peer_tables.read().await;
            if let Some(peer_table) = peer_tables.get(&session_id) {
                if let Some(result) = peer_table.lookup_route(destination).await {
                    return Some(result);
                }
            }
        }

        // Fall back to main routing table
        self.routing_table.lookup_route(destination).await
    }

    /// Add a route to the main routing table
    pub async fn add_route(&self, request: RouteAddRequest) -> BuckwildResult<()> {
        self.routing_table.add_route(request).await
    }

    /// Add a route to a peer-specific table
    pub async fn add_peer_route(
        &self,
        session_id: TypesSessionId,
        request: RouteAddRequest,
    ) -> BuckwildResult<()> {
        let peer_tables = self.peer_tables.read().await;

        if let Some(peer_table) = peer_tables.get(&session_id) {
            peer_table.add_route(request).await
        } else {
            Err(BuckwildError::not_found("Peer table not found"))
        }
    }

    /// Get the main routing table
    pub fn main_table(&self) -> &Arc<RoutingTable> {
        &self.routing_table
    }

    /// Get a peer-specific routing table
    pub async fn peer_table(&self, session_id: &TypesSessionId) -> Option<Arc<RoutingTable>> {
        let peer_tables = self.peer_tables.read().await;
        peer_tables.get(session_id).cloned()
    }
}
