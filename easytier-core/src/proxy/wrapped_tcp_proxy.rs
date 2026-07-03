use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};

use crate::packet::{PacketType, ZCPacket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedTcpProxyTransport {
    Kcp,
    Quic,
}

#[derive(Debug, Clone, Copy)]
pub struct WrappedTcpProxyNicContext {
    pub transport: WrappedTcpProxyTransport,
    pub my_peer_id: u32,
    pub local_ipv4: Option<Ipv4Addr>,
    pub smoltcp_enabled: bool,
}

pub async fn try_process_wrapped_tcp_packet_from_nic<ConnectionLookup, AllowCheck, AllowCheckFut>(
    zc_packet: &mut ZCPacket,
    ctx: WrappedTcpProxyNicContext,
    is_tcp_proxy_connection: ConnectionLookup,
    check_dst_allowed: AllowCheck,
) -> bool
where
    ConnectionLookup: Fn(SocketAddr) -> bool,
    AllowCheck: FnOnce(Ipv4Addr) -> AllowCheckFut,
    AllowCheckFut: Future<Output = bool>,
{
    let Some(hdr) = zc_packet.peer_manager_header() else {
        return false;
    };
    if hdr.packet_type != PacketType::Data as u8 {
        return false;
    }

    let Ok(ip_packet) = Ipv4Packet::new_checked(zc_packet.payload()) else {
        return false;
    };
    if ip_packet.version() != 4 || ip_packet.next_header() != IpProtocol::Tcp {
        return false;
    }

    let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) else {
        return false;
    };
    let src_ip = ip_packet.src_addr();
    let dst_ip = ip_packet.dst_addr();
    let src_port = tcp_packet.src_port();
    let is_syn = tcp_packet.syn() && !tcp_packet.ack();

    if is_syn {
        if !check_dst_allowed(dst_ip).await {
            tracing::warn!(
                ?ctx.transport,
                dst = %dst_ip,
                "wrapped tcp proxy src dst is not allowed"
            );
            return false;
        }
    } else if !is_tcp_proxy_connection(SocketAddr::V4(SocketAddrV4::new(src_ip, src_port))) {
        return false;
    }

    if let Some(local_ipv4) = ctx.local_ipv4 {
        if src_ip != local_ipv4 && !ctx.smoltcp_enabled {
            tracing::warn!(
                ?ctx.transport,
                src = %src_ip,
                dst = %dst_ip,
                "wrapped tcp proxy net-to-net input is not allowed without smoltcp"
            );
            return false;
        }
    }

    let hdr = zc_packet
        .mut_peer_manager_header()
        .expect("peer manager header");
    hdr.to_peer_id = ctx.my_peer_id.into();
    match ctx.transport {
        WrappedTcpProxyTransport::Kcp => {
            hdr.mark_kcp_src_modified();
        }
        WrappedTcpProxyTransport::Quic => {
            hdr.mark_quic_src_modified();
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket};

    fn build_tcp_packet(src: SocketAddrV4, dst: SocketAddrV4, syn: bool, ack: bool) -> ZCPacket {
        let mut raw = vec![0; smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN];
        {
            let mut ipv4 = Ipv4Packet::new_unchecked(&mut raw);
            ipv4.set_version(4);
            ipv4.set_header_len(smoltcp::wire::IPV4_HEADER_LEN as u8);
            ipv4.set_total_len(
                (smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN) as u16,
            );
            ipv4.set_hop_limit(64);
            ipv4.set_next_header(IpProtocol::Tcp);
            ipv4.set_src_addr(*src.ip());
            ipv4.set_dst_addr(*dst.ip());
            ipv4.fill_checksum();
        }
        {
            let mut tcp = TcpPacket::new_unchecked(&mut raw[smoltcp::wire::IPV4_HEADER_LEN..]);
            tcp.set_src_port(src.port());
            tcp.set_dst_port(dst.port());
            tcp.set_header_len(smoltcp::wire::TCP_HEADER_LEN as u8);
            tcp.set_syn(syn);
            tcp.set_ack(ack);
            tcp.fill_checksum(&IpAddress::Ipv4(*src.ip()), &IpAddress::Ipv4(*dst.ip()));
        }

        let mut packet = ZCPacket::new_with_payload(&raw);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
    }

    fn context(transport: WrappedTcpProxyTransport) -> WrappedTcpProxyNicContext {
        WrappedTcpProxyNicContext {
            transport,
            my_peer_id: 42,
            local_ipv4: Some("10.144.144.204".parse().unwrap()),
            smoltcp_enabled: false,
        }
    }

    #[tokio::test]
    async fn allowed_syn_is_marked_for_kcp() {
        let src = SocketAddrV4::new("10.144.144.204".parse().unwrap(), 50000);
        let dst = SocketAddrV4::new("10.10.10.10".parse().unwrap(), 80);
        let mut packet = build_tcp_packet(src, dst, true, false);

        assert!(
            try_process_wrapped_tcp_packet_from_nic(
                &mut packet,
                context(WrappedTcpProxyTransport::Kcp),
                |_| false,
                |_| async { true },
            )
            .await
        );

        let hdr = packet.peer_manager_header().unwrap();
        assert_eq!(hdr.to_peer_id.get(), 42);
        assert!(hdr.is_kcp_src_modified());
    }

    #[tokio::test]
    async fn denied_syn_is_not_marked() {
        let src = SocketAddrV4::new("10.144.144.204".parse().unwrap(), 50000);
        let dst = SocketAddrV4::new("10.10.10.10".parse().unwrap(), 80);
        let mut packet = build_tcp_packet(src, dst, true, false);

        assert!(
            !try_process_wrapped_tcp_packet_from_nic(
                &mut packet,
                context(WrappedTcpProxyTransport::Kcp),
                |_| false,
                |_| async { false },
            )
            .await
        );

        let hdr = packet.peer_manager_header().unwrap();
        assert_eq!(hdr.packet_type, PacketType::Data as u8);
    }

    #[tokio::test]
    async fn established_non_syn_is_marked_for_quic() {
        let src = SocketAddrV4::new("10.144.144.204".parse().unwrap(), 50000);
        let dst = SocketAddrV4::new("10.10.10.10".parse().unwrap(), 80);
        let mut packet = build_tcp_packet(src, dst, false, true);

        assert!(
            try_process_wrapped_tcp_packet_from_nic(
                &mut packet,
                context(WrappedTcpProxyTransport::Quic),
                |addr| addr == SocketAddr::V4(src),
                |_| async { false },
            )
            .await
        );

        let hdr = packet.peer_manager_header().unwrap();
        assert_eq!(hdr.to_peer_id.get(), 42);
        assert!(hdr.is_quic_src_modified());
    }

    #[tokio::test]
    async fn non_syn_without_connection_is_rejected() {
        let src = SocketAddrV4::new("10.144.144.204".parse().unwrap(), 50000);
        let dst = SocketAddrV4::new("10.10.10.10".parse().unwrap(), 80);
        let mut packet = build_tcp_packet(src, dst, false, true);

        assert!(
            !try_process_wrapped_tcp_packet_from_nic(
                &mut packet,
                context(WrappedTcpProxyTransport::Quic),
                |_| false,
                |_| async { true },
            )
            .await
        );
    }

    #[tokio::test]
    async fn net_to_net_without_smoltcp_is_rejected() {
        let src = SocketAddrV4::new("10.144.144.205".parse().unwrap(), 50000);
        let dst = SocketAddrV4::new("10.10.10.10".parse().unwrap(), 80);
        let mut packet = build_tcp_packet(src, dst, true, false);

        assert!(
            !try_process_wrapped_tcp_packet_from_nic(
                &mut packet,
                context(WrappedTcpProxyTransport::Kcp),
                |_| false,
                |_| async { true },
            )
            .await
        );
    }
}
