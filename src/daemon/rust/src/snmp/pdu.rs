/// SNMP PDU encoding and decoding using BER (Basic Encoding Rules)
///
/// Implements SNMPv2c PDU types: GET, GET-NEXT, GET-BULK, RESPONSE, TRAP
/// Uses rasn-snmp library for proper BER encoding/decoding
use rasn::types::ObjectIdentifier;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use thiserror::Error;

// Re-export rasn-snmp types for convenience
pub use rasn_snmp::v2::*;
pub use rasn_snmp::v2c;

/// SNMP error types
#[derive(Error, Debug)]
pub enum SnmpError {
    #[error("Encoding error: {0}")]
    Encoding(#[from] rasn::error::EncodeError),

    #[error("Decoding error: {0}")]
    Decoding(#[from] rasn::error::DecodeError),

    #[error("Invalid PDU type: {0}")]
    InvalidPduType(String),

    #[error("Invalid OID: {0}")]
    InvalidOid(String),

    #[error("No such object: {0}")]
    NoSuchObject(String),

    #[error("No such instance: {0}")]
    NoSuchInstance(String),

    #[error("End of MIB view: {0}")]
    EndOfMibView(String),

    #[error("Bad value: {0}")]
    BadValue(String),

    #[error("Read only")]
    ReadOnly,

    #[error("General error: {0}")]
    GenErr(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// SNMP PDU types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    GetRequest = 0,
    GetNextRequest = 1,
    GetResponse = 2,
    SetRequest = 3,
    Trap = 4,
    GetBulkRequest = 5,
    InformRequest = 6,
    Trapv2 = 7,
    Report = 8,
}

impl PduType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Result<Self, SnmpError> {
        match value {
            0 => Ok(PduType::GetRequest),
            1 => Ok(PduType::GetNextRequest),
            2 => Ok(PduType::GetResponse),
            3 => Ok(PduType::SetRequest),
            4 => Ok(PduType::Trap),
            5 => Ok(PduType::GetBulkRequest),
            6 => Ok(PduType::InformRequest),
            7 => Ok(PduType::Trapv2),
            8 => Ok(PduType::Report),
            _ => Err(SnmpError::InvalidPduType(format!(
                "Unknown PDU type: {}",
                value
            ))),
        }
    }
}

/// SNMP error status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorStatus {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
}

/// Wrapper for SNMP PDU to provide convenience methods
#[derive(Debug, Clone)]
pub struct SnmpPdu {
    inner: Pdu,
}

impl SnmpPdu {
    /// Create new PDU with request ID
    pub fn new(request_id: i32) -> Self {
        Self {
            inner: Pdu {
                request_id,
                error_status: 0,
                error_index: 0,
                variable_bindings: VarBindList::new(),
            },
        }
    }

    /// Add variable binding
    pub fn add_varbind(&mut self, varbind: VarBind) {
        self.inner.variable_bindings.push(varbind);
    }

    /// Set error status
    pub fn set_error(&mut self, status: ErrorStatus, index: i32) {
        self.inner.error_status = status as u32;
        self.inner.error_index = index as u32;
    }

    /// Get variable bindings
    pub fn get_varbinds(&self) -> Vec<VarBind> {
        self.inner.variable_bindings.clone()
    }

    /// Get request ID
    pub fn request_id(&self) -> i32 {
        self.inner.request_id
    }

    /// Get error status
    pub fn error_status(&self) -> i32 {
        self.inner.error_status as i32
    }

    /// Get error index
    pub fn error_index(&self) -> i32 {
        self.inner.error_index as i32
    }

    /// Convert to rasn-snmp PDU for encoding
    pub fn into_inner(self) -> Pdu {
        self.inner
    }

    /// Create from rasn-snmp PDU
    pub fn from_inner(pdu: Pdu) -> Self {
        Self { inner: pdu }
    }
}

/// SNMP message wrapper
#[derive(Debug, Clone)]
pub struct SnmpMessage {
    inner: v2c::Message<Pdus>,
}

impl SnmpMessage {
    /// Create new SNMPv2c message with GET request
    pub fn new_get_request(community: String, pdu: SnmpPdu) -> Self {
        use rasn::types::Integer;
        Self {
            inner: v2c::Message {
                version: Integer::from(1i32), // SNMPv2c
                community: community.into_bytes().into(),
                data: Pdus::GetRequest(GetRequest(pdu.into_inner())),
            },
        }
    }

    /// Create new SNMPv2c message with GET-NEXT request
    pub fn new_get_next_request(community: String, pdu: SnmpPdu) -> Self {
        use rasn::types::Integer;
        Self {
            inner: v2c::Message {
                version: Integer::from(1i32),
                community: community.into_bytes().into(),
                data: Pdus::GetNextRequest(GetNextRequest(pdu.into_inner())),
            },
        }
    }

    /// Create new SNMPv2c message with GET-BULK request
    pub fn new_get_bulk_request(
        community: String,
        pdu: SnmpPdu,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Self {
        use rasn::types::Integer;
        Self {
            inner: v2c::Message {
                version: Integer::from(1i32),
                community: community.into_bytes().into(),
                data: Pdus::GetBulkRequest(GetBulkRequest(BulkPdu {
                    request_id: pdu.inner.request_id,
                    non_repeaters,
                    max_repetitions,
                    variable_bindings: pdu.inner.variable_bindings,
                })),
            },
        }
    }

    /// Create new SNMPv2c response message
    pub fn new_response(community: String, pdu: SnmpPdu) -> Self {
        use rasn::types::Integer;
        Self {
            inner: v2c::Message {
                version: Integer::from(1i32),
                community: community.into_bytes().into(),
                data: Pdus::Response(Response(pdu.into_inner())),
            },
        }
    }

    /// Create new SNMPv2c trap message
    pub fn new_trap(community: String, pdu: SnmpPdu) -> Self {
        use rasn::types::Integer;
        Self {
            inner: v2c::Message {
                version: Integer::from(1i32),
                community: community.into_bytes().into(),
                data: Pdus::Trap(Trap(pdu.into_inner())),
            },
        }
    }

    /// Get PDU type and PDU
    pub fn get_pdu_type_and_pdu(&self) -> Option<(PduType, SnmpPdu)> {
        match &self.inner.data {
            Pdus::GetRequest(req) => {
                Some((PduType::GetRequest, SnmpPdu::from_inner(req.0.clone())))
            }
            Pdus::GetNextRequest(req) => {
                Some((PduType::GetNextRequest, SnmpPdu::from_inner(req.0.clone())))
            }
            Pdus::Response(resp) => {
                Some((PduType::GetResponse, SnmpPdu::from_inner(resp.0.clone())))
            }
            Pdus::SetRequest(req) => {
                Some((PduType::SetRequest, SnmpPdu::from_inner(req.0.clone())))
            }
            Pdus::GetBulkRequest(req) => {
                // Convert BulkPdu to regular Pdu for consistency
                let pdu = Pdu {
                    request_id: req.0.request_id,
                    error_status: req.0.non_repeaters,
                    error_index: req.0.max_repetitions,
                    variable_bindings: req.0.variable_bindings.clone(),
                };
                Some((PduType::GetBulkRequest, SnmpPdu::from_inner(pdu)))
            }
            Pdus::InformRequest(req) => {
                Some((PduType::InformRequest, SnmpPdu::from_inner(req.0.clone())))
            }
            Pdus::Trap(trap) => Some((PduType::Trapv2, SnmpPdu::from_inner(trap.0.clone()))),
            Pdus::Report(rep) => Some((PduType::Report, SnmpPdu::from_inner(rep.0.clone()))),
        }
    }

    /// Get community string
    pub fn get_community(&self) -> Result<String, SnmpError> {
        String::from_utf8(self.inner.community.as_ref().to_vec())
            .map_err(|_| SnmpError::BadValue("Invalid community string".to_string()))
    }

    /// Encode message to BER bytes
    pub fn encode(&self) -> Result<Vec<u8>, SnmpError> {
        Ok(rasn::ber::encode(&self.inner)?)
    }

    /// Decode message from BER bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, SnmpError> {
        let inner: v2c::Message<Pdus> = rasn::ber::decode(bytes)?;
        Ok(Self { inner })
    }
}

/// Helper functions for VarBind creation
pub fn new_integer_varbind(oid: ObjectIdentifier, value: i64) -> VarBind {
    use rasn::types::Integer;
    use rasn_smi::v2::SimpleSyntax as Syntax2;
    VarBind {
        name: oid,
        value: VarBindValue::Value(ObjectSyntax::Simple(Syntax2::Integer(Integer::from(value)))),
    }
}

pub fn new_counter32_varbind(oid: ObjectIdentifier, value: u32) -> VarBind {
    use rasn_smi::{v1::Counter, v2::ApplicationSyntax as AppSyntax2};
    VarBind {
        name: oid,
        value: VarBindValue::Value(ObjectSyntax::ApplicationWide(AppSyntax2::Counter(Counter(
            value,
        )))),
    }
}

pub fn new_counter64_varbind(oid: ObjectIdentifier, value: u64) -> VarBind {
    use rasn_smi::v2::{ApplicationSyntax as AppSyntax2, Counter64};
    VarBind {
        name: oid,
        value: VarBindValue::Value(ObjectSyntax::ApplicationWide(AppSyntax2::BigCounter(
            Counter64(value),
        ))),
    }
}

pub fn new_gauge32_varbind(oid: ObjectIdentifier, value: u32) -> VarBind {
    use rasn_smi::{v1::Gauge, v2::ApplicationSyntax as AppSyntax2};
    VarBind {
        name: oid,
        value: VarBindValue::Value(ObjectSyntax::ApplicationWide(AppSyntax2::Unsigned(Gauge(
            value,
        )))),
    }
}

pub fn new_octet_string_varbind(oid: ObjectIdentifier, value: Vec<u8>) -> VarBind {
    use rasn_smi::v2::SimpleSyntax as Syntax2;
    VarBind {
        name: oid,
        value: VarBindValue::Value(ObjectSyntax::Simple(Syntax2::String(value.into()))),
    }
}

pub fn new_no_such_object_varbind(oid: ObjectIdentifier) -> VarBind {
    VarBind {
        name: oid,
        value: VarBindValue::Unspecified,
    }
}

pub fn new_end_of_mib_view_varbind(oid: ObjectIdentifier) -> VarBind {
    VarBind {
        name: oid,
        value: VarBindValue::EndOfMibView,
    }
}

pub fn new_objectid_varbind(oid: ObjectIdentifier, value: ObjectIdentifier) -> VarBind {
    use rasn_smi::v2::SimpleSyntax as Syntax2;
    VarBind {
        name: oid,
        value: VarBindValue::Value(ObjectSyntax::Simple(Syntax2::ObjectId(value))),
    }
}

/// Request ID generator
static REQUEST_ID: AtomicU32 = AtomicU32::new(1);

/// Generate unique request ID
pub fn generate_request_id() -> i32 {
    REQUEST_ID.fetch_add(1, Ordering::Relaxed) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdu_type_conversion() {
        assert_eq!(PduType::from_u8(0).ok(), Some(PduType::GetRequest));
        assert_eq!(PduType::from_u8(1).ok(), Some(PduType::GetNextRequest));
        assert_eq!(PduType::from_u8(5).ok(), Some(PduType::GetBulkRequest));
        assert!(PduType::from_u8(255).is_err());
    }

    #[test]
    fn test_varbind_creation() {
        use rasn_smi::v2::SimpleSyntax as Syntax2;
        let oid =
            ObjectIdentifier::new_unchecked(vec![1u32.into(), 3u32.into(), 6u32.into()].into());
        let vb = new_integer_varbind(oid.clone(), 42);
        match &vb.value {
            VarBindValue::Value(ObjectSyntax::Simple(Syntax2::Integer(i))) => {
                use num_traits::ToPrimitive;
                assert_eq!(i.to_i64(), Some(42));
            }
            _ => {
                assert!(false, "Expected integer value");
            }
        }
    }

    #[test]
    fn test_pdu_creation() {
        let mut pdu = SnmpPdu::new(1);
        let oid =
            ObjectIdentifier::new_unchecked(vec![1u32.into(), 3u32.into(), 6u32.into()].into());
        pdu.add_varbind(new_counter32_varbind(oid, 100));

        assert_eq!(pdu.request_id(), 1);
        assert_eq!(pdu.get_varbinds().len(), 1);
    }

    #[test]
    fn test_request_id_generation() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();
        assert!(id2 > id1);
    }

    #[test]
    fn test_encode_decode() {
        let mut pdu = SnmpPdu::new(123);
        let oid = ObjectIdentifier::new_unchecked(
            vec![1u32.into(), 3u32.into(), 6u32.into(), 1u32.into()].into(),
        );
        pdu.add_varbind(new_counter64_varbind(oid, 42));

        let msg = SnmpMessage::new_get_request("public".to_string(), pdu);
        let encoded = msg.encode().expect("Failed to encode");

        let decoded = SnmpMessage::decode(&encoded).expect("Failed to decode");
        assert_eq!(decoded.get_community().unwrap(), "public");

        let (pdu_type, decoded_pdu) = decoded.get_pdu_type_and_pdu().expect("Failed to get PDU");
        assert_eq!(pdu_type, PduType::GetRequest);
        assert_eq!(decoded_pdu.request_id(), 123);
        assert_eq!(decoded_pdu.get_varbinds().len(), 1);
    }

    #[test]
    fn test_trap_construction() {
        let mut trap_pdu = SnmpPdu::new(999);
        let uptime_oid =
            ObjectIdentifier::new_unchecked(vec![1u32.into(), 3u32.into(), 6u32.into()].into());
        trap_pdu.add_varbind(new_counter32_varbind(uptime_oid.clone(), 12345));

        let trap_msg = SnmpMessage::new_trap("trapcom".to_string(), trap_pdu);

        assert_eq!(trap_msg.get_community().unwrap(), "trapcom");

        let (pdu_type, decoded_pdu) = trap_msg
            .get_pdu_type_and_pdu()
            .expect("Failed to get trap PDU");
        assert_eq!(pdu_type, PduType::Trapv2);
        assert_eq!(decoded_pdu.request_id(), 999);
        assert_eq!(decoded_pdu.get_varbinds().len(), 1);
    }

    #[test]
    fn test_trap_queue_overflow_handling() {
        use std::collections::VecDeque;

        const MAX_QUEUE_SIZE: usize = 100;
        let mut trap_queue: VecDeque<SnmpMessage> = VecDeque::with_capacity(MAX_QUEUE_SIZE);

        for i in 0..150 {
            let mut pdu = SnmpPdu::new(i);
            let oid =
                ObjectIdentifier::new_unchecked(vec![1u32.into(), 3u32.into(), 6u32.into()].into());
            pdu.add_varbind(new_counter32_varbind(oid, i as u32));

            let trap = SnmpMessage::new_trap("public".to_string(), pdu);

            if trap_queue.len() >= MAX_QUEUE_SIZE {
                trap_queue.pop_front();
            }
            trap_queue.push_back(trap);
        }

        assert_eq!(trap_queue.len(), MAX_QUEUE_SIZE);

        let oldest_trap = trap_queue.front().unwrap();
        let (_, oldest_pdu) = oldest_trap
            .get_pdu_type_and_pdu()
            .expect("Failed to get oldest trap");
        assert_eq!(oldest_pdu.request_id(), 50);
    }
}
