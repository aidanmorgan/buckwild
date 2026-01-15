use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use pnet::packet::{
    MutablePacket, Packet,
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    ipv6::Ipv6Packet,
    tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
    udp::{MutableUdpPacket, UdpPacket},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};

use super::flow_tracker::FlowId;
use buckwild_common::protocol::types::PacketType;

/// Packet translation result
#[derive(Debug, Clone)]
pub struct TranslationResult {
    pub flow_id: FlowId,
    pub payload: Bytes,
    pub sequence_mapping: SequenceMapping,
    pub packet_type: TunPacketType,
}

/// Sequence number mapping for TCP reliability
#[derive(Debug, Clone)]
pub struct SequenceMapping {
    pub original_seq: u32,
    pub translated_seq: u32,
    pub original_ack: u32,
    pub translated_ack: u32,
    pub window_size: u16,
}

/// TUN packet types (different from protocol PacketType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunPacketType {
    TcpData,
    TcpControl,
    UdpData,
    Other,
}

/// TCP to stateless datagram packet translator
pub struct PacketTranslator {
    sequence_mappings: DashMap<u64, Arc<RwLock<SequenceState>>>,
    flow_tracker: Arc<super::FlowTracker>,
}

/// Sequence number state for flow
#[derive(Debug, Clone)]
struct SequenceState {
    local_seq_base: u32,
    remote_seq_base: u32,
    local_seq_offset: u32,
    remote_seq_offset: u32,
    last_ack: u32,
    window_scale: u8,
}

impl PacketTranslator {
    /// Create a new packet translator
    #[instrument]
    pub fn new(flow_tracker: Arc<super::FlowTracker>) -> Self {
        debug!("Creating packet translator");

        PacketTranslator {
            sequence_mappings: DashMap::new(),
            flow_tracker,
        }
    }

    /// Translate incoming TCP/IP packet to stateless datagram
    #[instrument(skip(self, packet))]
    pub async fn translate_inbound(&self, packet: Bytes) -> Result<TranslationResult> {
        debug!("Translating inbound packet of size: {}", packet.len());

        // Parse IP header to determine version
        if packet.is_empty() {
            bail!("Empty packet received");
        }

        let ip_version = (packet[0] >> 4) & 0x0F;

        match ip_version {
            4 => self.translate_ipv4_inbound(packet).await,
            6 => self.translate_ipv6_inbound(packet).await,
            _ => bail!("Unsupported IP version: {}", ip_version),
        }
    }

    /// Convert protocol PacketType to TUN-layer packet type based on flow protocol
    fn protocol_to_tun_packet_type(packet_type: PacketType, protocol: u8) -> TunPacketType {
        if protocol == 6 {
            // TCP
            match packet_type {
                PacketType::Data => TunPacketType::TcpData,
                _ => TunPacketType::TcpControl, // Syn, SynAck, Ack, Fin, Rst, Control, etc.
            }
        } else if protocol == 17 {
            // UDP
            TunPacketType::UdpData
        } else {
            TunPacketType::Other
        }
    }

    /// Translate outbound datagram to TCP/IP packet
    #[instrument(skip(self, payload))]
    pub async fn translate_outbound(
        &self,
        flow_id: &FlowId,
        payload: Bytes,
        sequence_mapping: &SequenceMapping,
        packet_type: PacketType,
    ) -> Result<Bytes> {
        debug!("Translating outbound packet for flow: {}", flow_id);

        let tun_packet_type = Self::protocol_to_tun_packet_type(packet_type, flow_id.protocol);

        match flow_id.src_ip {
            IpAddr::V4(_) => {
                self.translate_ipv4_outbound(flow_id, payload, sequence_mapping, tun_packet_type)
                    .await
            }
            IpAddr::V6(_) => {
                self.translate_ipv6_outbound(flow_id, payload, sequence_mapping, tun_packet_type)
                    .await
            }
        }
    }

    /// Translate IPv4 packet inbound
    async fn translate_ipv4_inbound(&self, packet: Bytes) -> Result<TranslationResult> {
        let ipv4_packet = Ipv4Packet::new(&packet).context("Failed to parse IPv4 packet")?;

        let src_ip = IpAddr::V4(ipv4_packet.get_source());
        let dst_ip = IpAddr::V4(ipv4_packet.get_destination());
        let protocol = ipv4_packet.get_next_level_protocol();

        match protocol {
            IpNextHeaderProtocols::Tcp => {
                self.translate_tcp_inbound(src_ip, dst_ip, ipv4_packet.payload())
                    .await
            }
            IpNextHeaderProtocols::Udp => {
                self.translate_udp_inbound(src_ip, dst_ip, ipv4_packet.payload())
                    .await
            }
            _ => bail!("Unsupported protocol: {:?}", protocol),
        }
    }

    /// Translate IPv6 packet inbound
    async fn translate_ipv6_inbound(&self, packet: Bytes) -> Result<TranslationResult> {
        let ipv6_packet = Ipv6Packet::new(&packet).context("Failed to parse IPv6 packet")?;

        let src_ip = IpAddr::V6(ipv6_packet.get_source());
        let dst_ip = IpAddr::V6(ipv6_packet.get_destination());
        let protocol = ipv6_packet.get_next_header();

        match protocol {
            IpNextHeaderProtocols::Tcp => {
                self.translate_tcp_inbound(src_ip, dst_ip, ipv6_packet.payload())
                    .await
            }
            IpNextHeaderProtocols::Udp => {
                self.translate_udp_inbound(src_ip, dst_ip, ipv6_packet.payload())
                    .await
            }
            _ => bail!("Unsupported protocol: {:?}", protocol),
        }
    }

    /// Translate TCP packet inbound
    async fn translate_tcp_inbound(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tcp_data: &[u8],
    ) -> Result<TranslationResult> {
        let tcp_packet = TcpPacket::new(tcp_data).context("Failed to parse TCP packet")?;

        let src_port = tcp_packet.get_source();
        let dst_port = tcp_packet.get_destination();
        let seq_num = tcp_packet.get_sequence();
        let ack_num = tcp_packet.get_acknowledgement();
        let window_size = tcp_packet.get_window();
        let flags = tcp_packet.get_flags();

        let flow_id = FlowId::new(
            src_ip,
            dst_ip,
            buckwild_common::protocol::types::Port::from_u16_unchecked(src_port),
            buckwild_common::protocol::types::Port::from_u16_unchecked(dst_port),
            6,
        );

        // Update flow tracker
        let _flow_state = self
            .flow_tracker
            .create_or_update_flow(
                flow_id.clone(),
                seq_num.into(),
                ack_num.into(),
                window_size,
                flags,
            )
            .await?;

        // Get or create sequence mapping
        let sequence_mapping = self
            .get_or_create_sequence_mapping(&flow_id, seq_num.into(), ack_num)
            .await?;

        // Extract payload
        let payload = Bytes::copy_from_slice(tcp_packet.payload());

        // Determine packet type
        let packet_type = if payload.is_empty() || self.is_control_packet(flags) {
            TunPacketType::TcpControl
        } else {
            TunPacketType::TcpData
        };

        debug!(
            "Translated TCP packet: {} bytes payload, type: {:?}",
            payload.len(),
            packet_type
        );

        Ok(TranslationResult {
            flow_id,
            payload,
            sequence_mapping,
            packet_type,
        })
    }

    /// Translate UDP packet inbound
    async fn translate_udp_inbound(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        udp_data: &[u8],
    ) -> Result<TranslationResult> {
        let udp_packet = UdpPacket::new(udp_data).context("Failed to parse UDP packet")?;

        let src_port =
            buckwild_common::protocol::types::Port::from_u16_unchecked(udp_packet.get_source());
        let dst_port = buckwild_common::protocol::types::Port::from_u16_unchecked(
            udp_packet.get_destination(),
        );

        let flow_id = FlowId::new(src_ip, dst_ip, src_port, dst_port, 17);
        let payload = Bytes::copy_from_slice(udp_packet.payload());

        // UDP doesn't need sequence mapping
        let sequence_mapping = SequenceMapping {
            original_seq: 0,
            translated_seq: 0,
            original_ack: 0,
            translated_ack: 0,
            window_size: 0,
        };

        debug!("Translated UDP packet: {} bytes payload", payload.len());

        Ok(TranslationResult {
            flow_id,
            payload,
            sequence_mapping,
            packet_type: TunPacketType::UdpData,
        })
    }

    /// Translate IPv4 packet outbound
    async fn translate_ipv4_outbound(
        &self,
        flow_id: &FlowId,
        payload: Bytes,
        sequence_mapping: &SequenceMapping,
        packet_type: TunPacketType,
    ) -> Result<Bytes> {
        let src_ipv4 = match flow_id.src_ip {
            IpAddr::V4(ip) => ip,
            _ => bail!("Expected IPv4 address"),
        };
        let dst_ipv4 = match flow_id.dst_ip {
            IpAddr::V4(ip) => ip,
            _ => bail!("Expected IPv4 address"),
        };

        match packet_type {
            TunPacketType::TcpData | TunPacketType::TcpControl => {
                self.build_ipv4_tcp_packet(
                    src_ipv4,
                    dst_ipv4,
                    flow_id,
                    payload,
                    sequence_mapping,
                    packet_type,
                )
                .await
            }
            TunPacketType::UdpData => {
                self.build_ipv4_udp_packet(src_ipv4, dst_ipv4, flow_id, payload)
                    .await
            }
            _ => bail!("Unsupported packet type: {:?}", packet_type),
        }
    }

    /// Translate IPv6 packet outbound
    async fn translate_ipv6_outbound(
        &self,
        flow_id: &FlowId,
        payload: Bytes,
        sequence_mapping: &SequenceMapping,
        packet_type: TunPacketType,
    ) -> Result<Bytes> {
        let src_ipv6 = match flow_id.src_ip {
            IpAddr::V6(ip) => ip,
            _ => bail!("Expected IPv6 address"),
        };
        let dst_ipv6 = match flow_id.dst_ip {
            IpAddr::V6(ip) => ip,
            _ => bail!("Expected IPv6 address"),
        };

        match packet_type {
            TunPacketType::TcpData | TunPacketType::TcpControl => {
                self.build_ipv6_tcp_packet(
                    src_ipv6,
                    dst_ipv6,
                    flow_id,
                    payload,
                    sequence_mapping,
                    packet_type,
                )
                .await
            }
            TunPacketType::UdpData => {
                self.build_ipv6_udp_packet(src_ipv6, dst_ipv6, flow_id, payload)
                    .await
            }
            _ => bail!("Unsupported packet type: {:?}", packet_type),
        }
    }

    /// Build IPv4 TCP packet
    async fn build_ipv4_tcp_packet(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        flow_id: &FlowId,
        payload: Bytes,
        sequence_mapping: &SequenceMapping,
        packet_type: TunPacketType,
    ) -> Result<Bytes> {
        let tcp_header_len = 20; // Minimum TCP header size
        let ip_header_len = 20; // IPv4 header size
        let total_len = ip_header_len + tcp_header_len + payload.len();

        let mut packet_buf = BytesMut::with_capacity(total_len);
        packet_buf.resize(total_len, 0);

        // Build IPv4 header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut packet_buf[..ip_header_len])
                .context("Failed to create IPv4 packet")?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5); // 20 bytes
            ip_packet.set_total_length(total_len as u16);
            ip_packet.set_identification(0); // Let kernel handle
            ip_packet.set_flags(2); // Don't fragment
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(src_ip);
            ip_packet.set_destination(dst_ip);
            ip_packet.set_checksum(0); // Let kernel calculate
        }

        // Build TCP header
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut packet_buf[ip_header_len..])
                .context("Failed to create TCP packet")?;

            tcp_packet.set_source(flow_id.src_port.as_u16());
            tcp_packet.set_destination(flow_id.dst_port.as_u16());
            tcp_packet.set_sequence(sequence_mapping.translated_seq);
            tcp_packet.set_acknowledgement(sequence_mapping.translated_ack);
            tcp_packet.set_data_offset(5); // 20 bytes
            tcp_packet.set_window(sequence_mapping.window_size);
            tcp_packet.set_urgent_ptr(0);

            // Set appropriate flags based on packet type
            let flags = match packet_type {
                TunPacketType::TcpControl => TcpFlags::ACK,
                TunPacketType::TcpData => TcpFlags::ACK | TcpFlags::PSH,
                _ => TcpFlags::ACK,
            };
            tcp_packet.set_flags(flags);

            // Copy payload using tcp_packet's payload_mut to avoid double borrow
            if !payload.is_empty() {
                tcp_packet.payload_mut().copy_from_slice(&payload);
            }

            // Calculate TCP checksum
            let checksum =
                pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
            tcp_packet.set_checksum(checksum);
        }

        debug!("Built IPv4 TCP packet: {} bytes", packet_buf.len());
        Ok(packet_buf.freeze())
    }

    /// Build IPv4 UDP packet
    async fn build_ipv4_udp_packet(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        flow_id: &FlowId,
        payload: Bytes,
    ) -> Result<Bytes> {
        let udp_header_len = 8; // UDP header size
        let ip_header_len = 20; // IPv4 header size
        let total_len = ip_header_len + udp_header_len + payload.len();

        let mut packet_buf = BytesMut::with_capacity(total_len);
        packet_buf.resize(total_len, 0);

        // Build IPv4 header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut packet_buf[..ip_header_len])
                .context("Failed to create IPv4 packet")?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(total_len as u16);
            ip_packet.set_identification(0);
            ip_packet.set_flags(2);
            ip_packet.set_fragment_offset(0);
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_packet.set_source(src_ip);
            ip_packet.set_destination(dst_ip);
            ip_packet.set_checksum(0);
        }

        // Build UDP header
        {
            let mut udp_packet = MutableUdpPacket::new(&mut packet_buf[ip_header_len..])
                .context("Failed to create UDP packet")?;

            udp_packet.set_source(flow_id.src_port.as_u16());
            udp_packet.set_destination(flow_id.dst_port.as_u16());
            udp_packet.set_length((udp_header_len + payload.len()) as u16);

            // Copy payload using udp_packet's payload_mut to avoid double borrow
            if !payload.is_empty() {
                udp_packet.payload_mut().copy_from_slice(&payload);
            }

            // Calculate UDP checksum
            let checksum =
                pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
            udp_packet.set_checksum(checksum);
        }

        debug!("Built IPv4 UDP packet: {} bytes", packet_buf.len());
        Ok(packet_buf.freeze())
    }

    /// Build IPv6 TCP packet (simplified implementation)
    async fn build_ipv6_tcp_packet(
        &self,
        _src_ip: Ipv6Addr,
        _dst_ip: Ipv6Addr,
        _flow_id: &FlowId,
        _payload: Bytes,
        _sequence_mapping: &SequenceMapping,
        _packet_type: TunPacketType,
    ) -> Result<Bytes> {
        // IPv6 implementation would be similar to IPv4 but with IPv6 headers
        bail!("IPv6 TCP translation not yet implemented");
    }

    /// Build IPv6 UDP packet (simplified implementation)
    async fn build_ipv6_udp_packet(
        &self,
        _src_ip: Ipv6Addr,
        _dst_ip: Ipv6Addr,
        _flow_id: &FlowId,
        _payload: Bytes,
    ) -> Result<Bytes> {
        // IPv6 implementation would be similar to IPv4 but with IPv6 headers
        bail!("IPv6 UDP translation not yet implemented");
    }

    /// Get or create sequence mapping for flow
    async fn get_or_create_sequence_mapping(
        &self,
        flow_id: &FlowId,
        seq_num: crate::protocol::types::SequenceNumber,
        ack_num: u32,
    ) -> Result<SequenceMapping> {
        let flow_hash = self.hash_flow_id(flow_id);

        if let Some(existing) = self.sequence_mappings.get(&flow_hash) {
            let state = existing.read().await;
            Ok(SequenceMapping {
                original_seq: seq_num.as_u32(),
                translated_seq: seq_num
                    .as_u32()
                    .wrapping_sub(state.local_seq_base)
                    .wrapping_add(state.local_seq_offset),
                original_ack: ack_num,
                translated_ack: ack_num
                    .wrapping_sub(state.remote_seq_base)
                    .wrapping_add(state.remote_seq_offset),
                window_size: 8192, // Default window size
            })
        } else {
            // Create new sequence mapping
            let state = SequenceState {
                local_seq_base: seq_num.as_u32(),
                remote_seq_base: ack_num,
                local_seq_offset: 1000, // Start with offset
                remote_seq_offset: 2000,
                last_ack: ack_num,
                window_scale: 0,
            };

            let state_arc = Arc::new(RwLock::new(state));
            self.sequence_mappings.insert(flow_hash, state_arc);

            Ok(SequenceMapping {
                original_seq: seq_num.as_u32(),
                translated_seq: 1000,
                original_ack: ack_num,
                translated_ack: 2000,
                window_size: 8192,
            })
        }
    }

    /// Check if packet is a control packet
    fn is_control_packet(&self, flags: u8) -> bool {
        const TCP_SYN: u8 = 0x02;
        const TCP_FIN: u8 = 0x01;
        const TCP_RST: u8 = 0x04;

        (flags & (TCP_SYN | TCP_FIN | TCP_RST)) != 0
    }

    /// Hash flow ID for sequence mapping lookup
    fn hash_flow_id(&self, flow_id: &FlowId) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        flow_id.hash(&mut hasher);
        hasher.finish()
    }

    /// Clean up sequence mappings for closed flows
    pub async fn cleanup_sequence_mappings(&self) {
        // This would be called periodically to clean up old mappings
        // Implementation would check flow states and remove mappings for closed flows
        debug!("Cleaning up sequence mappings");
    }
}
