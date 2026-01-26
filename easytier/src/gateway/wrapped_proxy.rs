use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet as _,
};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite};
use tokio_util::io::InspectReader;

use crate::{
    common::{acl_processor::PacketInfo, error::Result},
    gateway::tcp_proxy::{NatDstConnector, TcpProxy},
    peers::{acl_filter::AclFilter, NicPacketFilter},
    proto::{
        acl::{Action, ChainType},
        api::instance::TcpProxyEntryTransportType,
    },
    tunnel::packet_def::ZCPacket,
};

#[derive(Clone)]
pub struct ProxyAclHandler {
    pub acl_filter: Arc<AclFilter>,
    pub packet_info: PacketInfo,
    pub chain_type: ChainType,
}

impl ProxyAclHandler {
    pub fn handle_packet(&self, buf: &[u8]) -> Result<()> {
        let mut packet_info = self.packet_info.clone();
        packet_info.packet_size = buf.len();
        let ret = self
            .acl_filter
            .get_processor()
            .process_packet(&packet_info, self.chain_type);
        self.acl_filter.handle_acl_result(
            &ret,
            &packet_info,
            self.chain_type,
            &self.acl_filter.get_processor(),
        );
        if !matches!(ret.action, Action::Allow) {
            return Err(anyhow::anyhow!("acl denied").into());
        }

        Ok(())
    }

    pub async fn copy_bidirection_with_acl(
        &self,
        src: impl AsyncRead + AsyncWrite + Unpin,
        mut dst: impl AsyncRead + AsyncWrite + Unpin,
    ) -> Result<()> {
        let (src_reader, src_writer) = tokio::io::split(src);
        let src_reader = InspectReader::new(src_reader, |buf| {
            let _ = self.handle_packet(buf);
        });
        let mut src = tokio::io::join(src_reader, src_writer);

        copy_bidirectional(&mut src, &mut dst).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
pub(crate) trait TcpProxyForWrappedSrcTrait: Send + Sync + 'static {
    type Connector: NatDstConnector;
    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>>;
    async fn check_dst_allow_kcp_input(&self, dst_ip: &Ipv4Addr) -> bool;
}

#[async_trait::async_trait]
impl<C: NatDstConnector, T: TcpProxyForWrappedSrcTrait<Connector = C>> NicPacketFilter for T {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        let ret = self
            .get_tcp_proxy()
            .try_process_packet_from_nic(zc_packet)
            .await;
        if ret {
            return true;
        }

        let data = zc_packet.payload();
        let ip_packet = Ipv4Packet::new(data).unwrap();
        if ip_packet.get_version() != 4
            || ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        {
            return false;
        }

        // if no connection is established, only allow SYN packet
        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();
        let is_syn = tcp_packet.get_flags() & TcpFlags::SYN != 0
            && tcp_packet.get_flags() & TcpFlags::ACK == 0;
        if is_syn {
            // only check dst feature flag when SYN packet
            if !self
                .check_dst_allow_kcp_input(&ip_packet.get_destination())
                .await
            {
                tracing::warn!(
                    "{:?} proxy src: dst {} not allow kcp input",
                    self.get_tcp_proxy().get_transport_type(),
                    ip_packet.get_destination()
                );
                return false;
            }
        } else {
            // if not syn packet, only allow established connection
            if !self
                .get_tcp_proxy()
                .is_tcp_proxy_connection(SocketAddr::new(
                    IpAddr::V4(ip_packet.get_source()),
                    tcp_packet.get_source(),
                ))
            {
                return false;
            }
        }

        if let Some(my_ipv4) = self.get_tcp_proxy().get_global_ctx().get_ipv4() {
            // this is a net-to-net packet, only allow it when smoltcp is enabled
            // because the syn-ack packet will not be through and handled by the tun device when
            // the source ip is in the local network
            if ip_packet.get_source() != my_ipv4.address()
                && !self.get_tcp_proxy().is_smoltcp_enabled()
            {
                tracing::warn!(
                    "{:?} nat 2 nat packet, src: {} dst: {} not allow kcp input",
                    self.get_tcp_proxy().get_transport_type(),
                    ip_packet.get_source(),
                    ip_packet.get_destination()
                );
                return false;
            }
        };

        let hdr = zc_packet.mut_peer_manager_header().unwrap();
        hdr.to_peer_id = self.get_tcp_proxy().get_my_peer_id().into();
        if self.get_tcp_proxy().get_transport_type() == TcpProxyEntryTransportType::Kcp {
            hdr.set_kcp_src_modified(true);
        }
        true
    }
}
