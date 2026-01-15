/// SNMP agent implementation for Buckwild protocol monitoring
///
/// Implements SNMPv2c agent supporting GET, GET-NEXT, and GET-BULK operations
/// Listens on configurable UDP port (default 161) and responds to SNMP queries
use super::objects::{MibObjects, MibValue};
use super::pdu::{
    ErrorStatus, PduType, SnmpError, SnmpMessage, SnmpPdu, VarBind, new_counter32_varbind,
    new_counter64_varbind, new_end_of_mib_view_varbind, new_gauge32_varbind, new_integer_varbind,
    new_no_such_object_varbind, new_objectid_varbind, new_octet_string_varbind,
};
use rasn::types::ObjectIdentifier;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// SNMP agent errors
#[derive(Error, Debug)]
pub enum AgentError {
    #[error("SNMP protocol error: {0}")]
    Snmp(#[from] SnmpError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid community string")]
    InvalidCommunity,

    #[error("Socket bind error: {0}")]
    Bind(String),
}

/// SNMP agent configuration
#[derive(Debug, Clone)]
pub struct SnmpConfig {
    /// Listen address
    pub listen_addr: SocketAddr,

    /// Community string for SNMPv2c
    pub community: String,

    /// Maximum PDU size
    pub max_pdu_size: usize,
}

impl SnmpConfig {
    /// Create default SNMP configuration
    ///
    /// # Errors
    ///
    /// Returns error if default socket address is invalid (should never occur in practice)
    pub fn default_config() -> Result<Self, AgentError> {
        Ok(Self {
            listen_addr: "0.0.0.0:161"
                .parse()
                .map_err(|e| AgentError::Bind(format!("Invalid default address: {}", e)))?,
            community: "public".to_string(),
            max_pdu_size: 65535,
        })
    }
}

impl Default for SnmpConfig {
    fn default() -> Self {
        Self::default_config().unwrap_or_else(|_| Self {
            listen_addr: ([0, 0, 0, 0], 161).into(),
            community: "public".to_string(),
            max_pdu_size: 65535,
        })
    }
}

/// SNMP agent
pub struct SnmpAgent {
    config: SnmpConfig,
    mib: Arc<RwLock<MibObjects>>,
    socket: Option<Arc<UdpSocket>>,
}

impl SnmpAgent {
    /// Create new SNMP agent
    pub fn new(config: SnmpConfig) -> Self {
        Self {
            config,
            mib: Arc::new(RwLock::new(MibObjects::new())),
            socket: None,
        }
    }

    /// Get MIB objects reference
    pub fn mib(&self) -> Arc<RwLock<MibObjects>> {
        Arc::clone(&self.mib)
    }

    /// Start the SNMP agent
    pub async fn start(mut self) -> Result<(), AgentError> {
        let socket = UdpSocket::bind(&self.config.listen_addr)
            .await
            .map_err(|e| AgentError::Bind(format!("{}: {}", self.config.listen_addr, e)))?;

        info!(
            address = %self.config.listen_addr,
            community = %self.config.community,
            "SNMP agent listening"
        );

        let socket = Arc::new(socket);
        self.socket = Some(Arc::clone(&socket));

        let mut buf = vec![0u8; self.config.max_pdu_size];

        loop {
            let (len, peer_addr) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!(error = %e, "Failed to receive SNMP packet");
                    continue;
                }
            };

            debug!(
                peer = %peer_addr,
                size = len,
                "Received SNMP request"
            );

            let request_data = buf[..len].to_vec();
            let mib = Arc::clone(&self.mib);
            let config = self.config.clone();
            let socket = Arc::clone(&socket);

            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_request(&request_data, peer_addr, &config, &mib, &socket).await
                {
                    warn!(
                        peer = %peer_addr,
                        error = %e,
                        "Failed to handle SNMP request"
                    );
                }
            });
        }
    }

    /// Handle SNMP request
    async fn handle_request(
        data: &[u8],
        peer_addr: SocketAddr,
        config: &SnmpConfig,
        mib: &Arc<RwLock<MibObjects>>,
        socket: &UdpSocket,
    ) -> Result<(), AgentError> {
        let request = SnmpMessage::decode(data)?;

        let community = request.get_community()?;
        if community != config.community {
            debug!(
                peer = %peer_addr,
                community = %community,
                "Invalid community string"
            );
            return Err(AgentError::InvalidCommunity);
        }

        let (pdu_type, request_pdu) = request
            .get_pdu_type_and_pdu()
            .ok_or_else(|| SnmpError::GenErr("Missing PDU".to_string()))?;

        debug!(
            peer = %peer_addr,
            pdu_type = ?pdu_type,
            request_id = request_pdu.request_id(),
            "Processing SNMP request"
        );

        let response_pdu = match pdu_type {
            PduType::GetRequest => Self::handle_get(request_pdu, mib).await,
            PduType::GetNextRequest => Self::handle_get_next(request_pdu, mib).await,
            PduType::GetBulkRequest => Self::handle_get_bulk(request_pdu, mib).await,
            _ => {
                warn!(pdu_type = ?pdu_type, "Unsupported PDU type");
                return Ok(());
            }
        };

        let response = SnmpMessage::new_response(community, response_pdu);
        let response_data = response.encode()?;

        socket.send_to(&response_data, peer_addr).await?;

        debug!(
            peer = %peer_addr,
            size = response_data.len(),
            "Sent SNMP response"
        );

        Ok(())
    }

    /// Handle GET request
    async fn handle_get(pdu: SnmpPdu, mib: &Arc<RwLock<MibObjects>>) -> SnmpPdu {
        let mib_guard = mib.read().await;
        let mut response_pdu = SnmpPdu::new(pdu.request_id());

        for varbind in pdu.get_varbinds() {
            let response_varbind = match mib_guard.get_value(&varbind.name) {
                Some(value) => Self::mib_value_to_varbind(varbind.name.clone(), value),
                None => new_no_such_object_varbind(varbind.name.clone()),
            };
            response_pdu.add_varbind(response_varbind);
        }

        response_pdu
    }

    /// Handle GET-NEXT request
    async fn handle_get_next(pdu: SnmpPdu, mib: &Arc<RwLock<MibObjects>>) -> SnmpPdu {
        let mib_guard = mib.read().await;
        let mut response_pdu = SnmpPdu::new(pdu.request_id());

        for varbind in pdu.get_varbinds() {
            let next_oid = mib_guard.get_next_oid(&varbind.name);

            let response_varbind = match next_oid {
                Some(oid) => match mib_guard.get_value(&oid) {
                    Some(value) => Self::mib_value_to_varbind(oid, value),
                    None => new_no_such_object_varbind(oid),
                },
                None => new_end_of_mib_view_varbind(varbind.name.clone()),
            };

            response_pdu.add_varbind(response_varbind);
        }

        response_pdu
    }

    /// Handle GET-BULK request
    async fn handle_get_bulk(pdu: SnmpPdu, mib: &Arc<RwLock<MibObjects>>) -> SnmpPdu {
        let mib_guard = mib.read().await;
        let mut response_pdu = SnmpPdu::new(pdu.request_id());

        let non_repeaters = pdu.error_status() as usize;
        let max_repetitions = pdu.error_index() as usize;
        let varbinds = pdu.get_varbinds();

        if varbinds.is_empty() {
            response_pdu.set_error(ErrorStatus::GenErr, 0);
            return response_pdu;
        }

        let non_repeaters = non_repeaters.min(varbinds.len());

        for varbind in varbinds.iter().take(non_repeaters) {
            let next_oid = mib_guard.get_next_oid(&varbind.name);

            let response_varbind = match next_oid {
                Some(oid) => match mib_guard.get_value(&oid) {
                    Some(value) => Self::mib_value_to_varbind(oid, value),
                    None => new_no_such_object_varbind(oid),
                },
                None => new_end_of_mib_view_varbind(varbind.name.clone()),
            };

            response_pdu.add_varbind(response_varbind);
        }

        for varbind in varbinds.iter().skip(non_repeaters) {
            let mut current_oid = varbind.name.clone();

            for _ in 0..max_repetitions {
                let next_oid = mib_guard.get_next_oid(&current_oid);

                let response_varbind = match next_oid {
                    Some(oid) => match mib_guard.get_value(&oid) {
                        Some(value) => {
                            current_oid = oid.clone();
                            Self::mib_value_to_varbind(oid, value)
                        }
                        None => {
                            response_pdu
                                .add_varbind(new_end_of_mib_view_varbind(current_oid.clone()));
                            break;
                        }
                    },
                    None => {
                        response_pdu.add_varbind(new_end_of_mib_view_varbind(current_oid.clone()));
                        break;
                    }
                };

                response_pdu.add_varbind(response_varbind);
            }
        }

        response_pdu.set_error(ErrorStatus::NoError, 0);

        response_pdu
    }

    /// Convert MibValue to VarBind
    fn mib_value_to_varbind(oid: ObjectIdentifier, value: MibValue) -> VarBind {
        match value {
            MibValue::Integer(i) => new_integer_varbind(oid, i as i64),
            MibValue::Counter32(c) => new_counter32_varbind(oid, c),
            MibValue::Counter64(c) => new_counter64_varbind(oid, c),
            MibValue::Gauge32(g) => new_gauge32_varbind(oid, g),
            MibValue::OctetString(s) => new_octet_string_varbind(oid, s),
            MibValue::ObjectId(o) => new_objectid_varbind(oid, o),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = SnmpConfig::default();
        assert_eq!(config.community, "public");
        assert_eq!(config.max_pdu_size, 65535);
    }

    #[test]
    fn test_agent_creation() {
        let config = SnmpConfig::default();
        let agent = SnmpAgent::new(config);
        assert!(agent.socket.is_none());
    }

    #[tokio::test]
    async fn test_mib_access() {
        let config = SnmpConfig::default();
        let agent = SnmpAgent::new(config);
        let mib = agent.mib();

        {
            let mib_guard = mib.write().await;
            mib_guard.inc_packets_transmitted(100);
        }

        {
            let mib_guard = mib.read().await;
            let oid = mib_guard.get_oid("stats", 1).unwrap();
            let value = mib_guard.get_value(&oid);
            assert!(matches!(value, Some(MibValue::Counter64(100))));
        }
    }

    #[tokio::test]
    async fn test_handle_get() {
        use crate::snmp::pdu::{ObjectSyntax, VarBindValue};
        use rasn_smi::v2::{ApplicationSyntax, Counter64};

        let mib = Arc::new(RwLock::new(MibObjects::new()));

        {
            let mib_guard = mib.write().await;
            mib_guard.inc_packets_transmitted(42);
        }

        let mut request_pdu = SnmpPdu::new(1);
        let oid = {
            let mib_guard = mib.read().await;
            mib_guard.get_oid("stats", 1).unwrap()
        };
        request_pdu.add_varbind(new_no_such_object_varbind(oid.clone()));

        let response = SnmpAgent::handle_get(request_pdu, &mib).await;

        assert_eq!(response.request_id(), 1);
        assert_eq!(response.get_varbinds().len(), 1);

        let varbind = &response.get_varbinds()[0];
        match &varbind.value {
            VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(
                Counter64(v),
            ))) => {
                assert_eq!(*v, 42);
            }
            _ => {
                assert!(false, "Expected Counter64 value, got {:?}", varbind.value);
            }
        }
    }

    #[tokio::test]
    async fn test_handle_get_next() {
        use crate::snmp::pdu::{ObjectSyntax, VarBindValue};
        use rasn_smi::v2::{ApplicationSyntax, Counter64};

        let mib = Arc::new(RwLock::new(MibObjects::new()));

        {
            let mib_guard = mib.write().await;
            mib_guard.inc_packets_transmitted(20);
            mib_guard.inc_packets_received(10);
        }

        let mut request_pdu = SnmpPdu::new(2);
        let oid = {
            let mib_guard = mib.read().await;
            mib_guard.get_oid("stats", 1).unwrap()
        };
        request_pdu.add_varbind(new_no_such_object_varbind(oid.clone()));

        let response = SnmpAgent::handle_get_next(request_pdu, &mib).await;

        assert_eq!(response.request_id(), 2);
        assert_eq!(response.get_varbinds().len(), 1);

        let varbind = &response.get_varbinds()[0];
        match &varbind.value {
            VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(
                Counter64(v),
            ))) => {
                assert_eq!(*v, 10);
            }
            _ => {
                assert!(
                    false,
                    "Expected Counter64 value for next OID, got {:?}",
                    varbind.value
                );
            }
        }
    }

    #[tokio::test]
    async fn test_agent_initialization() {
        let config = SnmpConfig {
            listen_addr: "127.0.0.1:10161".parse().unwrap(),
            community: "test_community".to_string(),
            max_pdu_size: 4096,
        };

        let agent = SnmpAgent::new(config.clone());

        assert!(agent.socket.is_none());
        assert_eq!(agent.config.community, "test_community");
        assert_eq!(agent.config.max_pdu_size, 4096);

        let mib = agent.mib();
        let mib_guard = mib.read().await;
        assert!(mib_guard.get_oid("stats", 1).is_some());
    }

    #[tokio::test]
    async fn test_pdu_response_for_known_oid() {
        use crate::snmp::pdu::{ObjectSyntax, VarBindValue};
        use rasn_smi::v2::{ApplicationSyntax, Counter64};

        let mib = Arc::new(RwLock::new(MibObjects::new()));

        {
            let mib_guard = mib.write().await;
            mib_guard.inc_packets_transmitted(12345);
        }

        let mut request_pdu = SnmpPdu::new(42);
        let oid = {
            let mib_guard = mib.read().await;
            mib_guard.get_oid("stats", 1).unwrap()
        };
        request_pdu.add_varbind(new_no_such_object_varbind(oid.clone()));

        let response = SnmpAgent::handle_get(request_pdu, &mib).await;

        assert_eq!(response.request_id(), 42);
        assert_eq!(response.error_status(), 0);
        assert_eq!(response.get_varbinds().len(), 1);

        let varbind = &response.get_varbinds()[0];
        assert_eq!(varbind.name, oid);
        match &varbind.value {
            VarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(
                Counter64(v),
            ))) => {
                assert_eq!(*v, 12345);
            }
            _ => {
                assert!(false, "Expected Counter64(12345), got {:?}", varbind.value);
            }
        }
    }
}
