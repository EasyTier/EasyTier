use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use easytier_proto::acl::{ChainType, Protocol};
use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};

use crate::{
    gateway::proxy::{
        cidr_table::ProxyCidrTable, proxy_acl::ProxyAclHandler,
        traits::WrappedTcpDestinationRuntime,
    },
    packet::{PacketType, ZCPacket},
    peers::{
        acl::{filter::AclFilter, processor::PacketInfo},
        route::Route,
    },
};

#[async_trait::async_trait]
pub trait WrappedTcpPeerGroupResolver: Send + Sync {
    async fn get_peer_groups_by_ip(&self, ip: &IpAddr) -> Arc<Vec<String>>;
}

#[async_trait::async_trait]
impl<T> WrappedTcpPeerGroupResolver for T
where
    T: Route + Send + Sync + ?Sized,
{
    async fn get_peer_groups_by_ip(&self, ip: &IpAddr) -> Arc<Vec<String>> {
        Route::get_peer_groups_by_ip(self, ip).await
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WrappedTcpDestinationRequest {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub initial_packet_size: usize,
}

#[derive(Clone)]
pub struct WrappedTcpDestinationPlan {
    pub socket_dst: SocketAddr,
    pub acl_handler: ProxyAclHandler,
}

pub async fn plan_wrapped_tcp_destination<GroupResolver>(
    request: WrappedTcpDestinationRequest,
    cidr_table: &ProxyCidrTable,
    runtime: &dyn WrappedTcpDestinationRuntime,
    group_resolver: &GroupResolver,
    acl_filter: Arc<AclFilter>,
) -> anyhow::Result<WrappedTcpDestinationPlan>
where
    GroupResolver: WrappedTcpPeerGroupResolver + ?Sized,
{
    let mut mapped_dst = request.dst;
    if let IpAddr::V4(dst_ip) = mapped_dst.ip()
        && let Some(real_ip) = cidr_table.lookup_v4(dst_ip)
    {
        mapped_dst.set_ip(real_ip.into());
    }

    let src_ip = request.src.ip();
    let dst_ip = mapped_dst.ip();
    let (src_groups, dst_groups) = tokio::join!(
        group_resolver.get_peer_groups_by_ip(&src_ip),
        group_resolver.get_peer_groups_by_ip(&dst_ip),
    );

    if runtime.should_deny_tcp_proxy(mapped_dst) {
        anyhow::bail!(
            "dst socket {:?} is in running listeners, ignore it",
            mapped_dst
        );
    }

    let send_to_self = runtime.is_ip_local_virtual_ip(&dst_ip);
    let socket_dst = if send_to_self && runtime.no_tun() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), mapped_dst.port())
    } else {
        mapped_dst
    };

    let acl_handler = ProxyAclHandler {
        acl_filter,
        packet_info: PacketInfo {
            src_ip,
            dst_ip,
            src_port: Some(request.src.port()),
            dst_port: Some(socket_dst.port()),
            protocol: Protocol::Tcp,
            packet_size: request.initial_packet_size,
            src_groups,
            dst_groups,
        },
        chain_type: if send_to_self {
            ChainType::Inbound
        } else {
            ChainType::Forward
        },
    };
    acl_handler.handle_packet_size(request.initial_packet_size)?;

    Ok(WrappedTcpDestinationPlan {
        socket_dst,
        acl_handler,
    })
}

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

    if let Some(local_ipv4) = ctx.local_ipv4
        && src_ip != local_ipv4
        && !ctx.smoltcp_enabled
    {
        tracing::warn!(
            ?ctx.transport,
            src = %src_ip,
            dst = %dst_ip,
            "wrapped tcp proxy net-to-net input is not allowed without smoltcp"
        );
        return false;
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
    use crate::gateway::proxy::cidr_table::{ProxyCidrRule, ProxyCidrSnapshot};
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket};

    struct TestDestinationRuntime {
        local_ip: IpAddr,
        no_tun: bool,
        denied: Option<SocketAddr>,
    }

    impl WrappedTcpDestinationRuntime for TestDestinationRuntime {
        fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
            *ip == self.local_ip
        }

        fn no_tun(&self) -> bool {
            self.no_tun
        }

        fn should_deny_tcp_proxy(&self, dst: SocketAddr) -> bool {
            self.denied == Some(dst)
        }
    }

    struct TestGroupResolver;

    #[async_trait::async_trait]
    impl WrappedTcpPeerGroupResolver for TestGroupResolver {
        async fn get_peer_groups_by_ip(&self, ip: &IpAddr) -> Arc<Vec<String>> {
            Arc::new(vec![format!("group-{ip}")])
        }
    }

    fn destination_runtime(local_ip: &str, no_tun: bool) -> TestDestinationRuntime {
        TestDestinationRuntime {
            local_ip: local_ip.parse().unwrap(),
            no_tun,
            denied: None,
        }
    }

    fn mapped_cidr_table() -> ProxyCidrTable {
        ProxyCidrTable::from_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "10.10.0.0/16".parse().unwrap(),
                mapped_cidr: Some("100.64.0.0/16".parse().unwrap()),
            }],
        })
    }

    async fn destination_plan(
        runtime: &TestDestinationRuntime,
        dst: &str,
    ) -> anyhow::Result<WrappedTcpDestinationPlan> {
        plan_wrapped_tcp_destination(
            WrappedTcpDestinationRequest {
                src: "10.20.0.2:40000".parse().unwrap(),
                dst: dst.parse().unwrap(),
                initial_packet_size: b"header".len(),
            },
            &mapped_cidr_table(),
            runtime,
            &TestGroupResolver,
            Arc::new(AclFilter::new()),
        )
        .await
    }

    #[tokio::test]
    async fn destination_plan_maps_cidr_and_builds_forward_acl_context() {
        let plan = destination_plan(&destination_runtime("10.30.0.1", false), "100.64.2.3:443")
            .await
            .unwrap();

        assert_eq!(plan.socket_dst, "10.10.2.3:443".parse().unwrap());
        assert_eq!(plan.acl_handler.chain_type, ChainType::Forward);
        assert_eq!(
            plan.acl_handler.packet_info.dst_ip,
            "10.10.2.3".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            plan.acl_handler.packet_info.dst_groups.as_ref(),
            &["group-10.10.2.3"]
        );
    }

    #[tokio::test]
    async fn destination_plan_rewrites_local_no_tun_socket_after_acl_identity() {
        let plan = destination_plan(&destination_runtime("10.10.2.3", true), "100.64.2.3:443")
            .await
            .unwrap();

        assert_eq!(plan.socket_dst, "127.0.0.1:443".parse().unwrap());
        assert_eq!(plan.acl_handler.chain_type, ChainType::Inbound);
        assert_eq!(
            plan.acl_handler.packet_info.dst_ip,
            "10.10.2.3".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn destination_plan_denies_mapped_running_listener() {
        let mut runtime = destination_runtime("10.30.0.1", false);
        runtime.denied = Some("10.10.2.3:443".parse().unwrap());

        let err = destination_plan(&runtime, "100.64.2.3:443")
            .await
            .err()
            .expect("mapped listener must be denied");
        assert!(err.to_string().contains("running listeners"));
    }

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
