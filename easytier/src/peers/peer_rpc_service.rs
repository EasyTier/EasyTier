use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::{
    common::{global_ctx::ArcGlobalCtx, network::IPCollector},
    proto::{
        common::Void,
        peer_rpc::{
            DirectConnectorRpc, GetIpListRequest, GetIpListResponse, SendUdpHolePunchPacketRequest,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::udp,
};

const MAX_UDP_HOLE_PUNCH_CONNECTOR_ADDRS: usize = 16;

fn remove_easytier_managed_ipv6s(ret: &mut GetIpListResponse, global_ctx: &ArcGlobalCtx) {
    ret.interface_ipv6s.retain(|ip| {
        let ip = std::net::Ipv6Addr::from(*ip);
        !global_ctx.is_ip_easytier_managed_ipv6(&ip)
    });

    if ret
        .public_ipv6
        .as_ref()
        .map(|ip| std::net::Ipv6Addr::from(*ip))
        .is_some_and(|ip| global_ctx.is_ip_easytier_managed_ipv6(&ip))
    {
        ret.public_ipv6 = None;
    }
}

fn is_usable_preferred_src_ipv6(ip: &Ipv6Addr, global_ctx: &ArcGlobalCtx) -> bool {
    !global_ctx.is_ip_easytier_managed_ipv6(ip)
        && !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_unique_local()
        && !ip.is_unicast_link_local()
        && !ip.is_multicast()
}

async fn local_preferred_src_ipv6(
    global_ctx: &ArcGlobalCtx,
    preferred_src_ipv6: Option<crate::proto::common::Ipv6Addr>,
) -> Option<udp::PreferredIpv6Source> {
    let preferred_src_ipv6 = preferred_src_ipv6.map(Ipv6Addr::from)?;
    if !is_usable_preferred_src_ipv6(&preferred_src_ipv6, global_ctx) {
        tracing::debug!(
            ?preferred_src_ipv6,
            "ignore unusable preferred IPv6 source for udp hole punch"
        );
        return None;
    }

    let ifaces = IPCollector::collect_interfaces(global_ctx.net_ns.clone(), false).await;
    for iface in ifaces {
        let is_local = iface.ips.iter().any(|ip| match ip.ip() {
            IpAddr::V6(v6) => v6 == preferred_src_ipv6,
            IpAddr::V4(_) => false,
        });
        if is_local {
            tracing::debug!(
                ?preferred_src_ipv6,
                ifindex = iface.index,
                "use preferred IPv6 source for udp hole punch"
            );
            return Some(udp::PreferredIpv6Source {
                ip: preferred_src_ipv6,
                ifindex: iface.index,
            });
        }
    }

    tracing::debug!(
        ?preferred_src_ipv6,
        "ignore non-local preferred IPv6 source for udp hole punch"
    );
    None
}

fn connector_addrs_from_request(
    req: SendUdpHolePunchPacketRequest,
) -> rpc_types::error::Result<(u16, Vec<SocketAddr>, Option<crate::proto::common::Ipv6Addr>)> {
    let listener_port = u16::try_from(req.listener_port)
        .map_err(|_| anyhow::anyhow!("listener_port is out of range: {}", req.listener_port))?;
    let mut connector_addrs = req
        .connector_addrs
        .into_iter()
        .map(SocketAddr::from)
        .collect::<Vec<_>>();

    if connector_addrs.is_empty() {
        connector_addrs.push(
            req.connector_addr
                .ok_or(anyhow::anyhow!("connector_addr is required"))?
                .into(),
        );
    }

    let mut deduped = Vec::with_capacity(connector_addrs.len());
    for addr in connector_addrs {
        if !deduped.contains(&addr) {
            deduped.push(addr);
        }
        if deduped.len() >= MAX_UDP_HOLE_PUNCH_CONNECTOR_ADDRS {
            break;
        }
    }

    Ok((listener_port, deduped, req.preferred_src_ipv6))
}

#[derive(Clone)]
pub struct DirectConnectorManagerRpcServer {
    // TODO: this only cache for one src peer, should make it global
    global_ctx: ArcGlobalCtx,
}

#[async_trait::async_trait]
impl DirectConnectorRpc for DirectConnectorManagerRpcServer {
    type Controller = BaseController;

    async fn get_ip_list(
        &self,
        _: BaseController,
        _: GetIpListRequest,
    ) -> rpc_types::error::Result<GetIpListResponse> {
        let mut ret = self.global_ctx.get_ip_collector().collect_ip_addrs().await;
        ret.listeners = self
            .global_ctx
            .config
            .get_mapped_listeners()
            .into_iter()
            .chain(self.global_ctx.get_running_listeners())
            .map(Into::into)
            .collect();
        remove_easytier_managed_ipv6s(&mut ret, &self.global_ctx);
        tracing::trace!(
            "get_ip_list: public_ipv4: {:?}, public_ipv6: {:?}, listeners: {:?}",
            ret.public_ipv4,
            ret.public_ipv6,
            ret.listeners
        );
        Ok(ret)
    }

    async fn send_udp_hole_punch_packet(
        &self,
        _: BaseController,
        req: SendUdpHolePunchPacketRequest,
    ) -> rpc_types::error::Result<Void> {
        let (listener_port, connector_addrs, preferred_src_ipv6) =
            connector_addrs_from_request(req)?;
        let preferred_src_ipv6 =
            local_preferred_src_ipv6(&self.global_ctx, preferred_src_ipv6).await;

        tracing::info!(
            ?connector_addrs,
            ?preferred_src_ipv6,
            listener_port,
            "Sending udp hole punch packet"
        );

        // send 3 packets to the connector
        for _ in 0..3 {
            for connector_addr in &connector_addrs {
                let ret = match connector_addr {
                    SocketAddr::V4(addr) => {
                        udp::send_v4_hole_punch_packet(listener_port, *addr).await
                    }
                    SocketAddr::V6(addr) => {
                        udp::send_v6_hole_punch_packet(listener_port, *addr, preferred_src_ipv6)
                            .await
                    }
                };
                if let Err(e) = ret {
                    tracing::debug!(
                        ?e,
                        ?connector_addr,
                        listener_port,
                        "send udp hole punch packet failed"
                    );
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        Ok(Default::default())
    }
}

impl DirectConnectorManagerRpcServer {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddr};

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        peers::peer_rpc_service::{connector_addrs_from_request, remove_easytier_managed_ipv6s},
        proto::peer_rpc::{GetIpListResponse, SendUdpHolePunchPacketRequest},
    };

    #[tokio::test]
    async fn get_ip_list_sanitizer_removes_managed_ipv6_from_all_sources() {
        let global_ctx = get_mock_global_ctx();
        let virtual_ipv6 = "fd00::1/64".parse().unwrap();
        let public_ipv6 = "2001:db8::2/128".parse().unwrap();
        let physical_ipv6: std::net::Ipv6Addr = "2001:db8::3".parse().unwrap();
        let routed_ipv6: cidr::Ipv6Inet = "2001:db8::4/128".parse().unwrap();
        global_ctx.set_ipv6(Some(virtual_ipv6));
        global_ctx.set_public_ipv6_lease(Some(public_ipv6));
        global_ctx.set_public_ipv6_routes(BTreeSet::from([routed_ipv6]));

        let mut ip_list = GetIpListResponse {
            public_ipv6: Some(public_ipv6.address().into()),
            interface_ipv6s: vec![
                virtual_ipv6.address().into(),
                public_ipv6.address().into(),
                routed_ipv6.address().into(),
                physical_ipv6.into(),
            ],
            ..Default::default()
        };

        remove_easytier_managed_ipv6s(&mut ip_list, &global_ctx);

        assert_eq!(ip_list.public_ipv6, None);
        assert_eq!(ip_list.interface_ipv6s, vec![physical_ipv6.into()]);
    }

    #[test]
    fn hole_punch_request_prefers_batch_connector_addrs() {
        let old_addr: SocketAddr = "[2001:db8::1]:10001".parse().unwrap();
        let first_batch_addr: SocketAddr = "[2001:db8::2]:10002".parse().unwrap();
        let second_batch_addr: SocketAddr = "[2001:db8::3]:10003".parse().unwrap();
        let preferred_src_ipv6: std::net::Ipv6Addr = "2001:db8::4".parse().unwrap();

        let (listener_port, connector_addrs, preferred_src) =
            connector_addrs_from_request(SendUdpHolePunchPacketRequest {
                connector_addr: Some(old_addr.into()),
                listener_port: 11010,
                preferred_src_ipv6: Some(preferred_src_ipv6.into()),
                connector_addrs: vec![
                    first_batch_addr.into(),
                    first_batch_addr.into(),
                    second_batch_addr.into(),
                ],
            })
            .unwrap();

        assert_eq!(listener_port, 11010);
        assert_eq!(connector_addrs, vec![first_batch_addr, second_batch_addr]);
        assert_eq!(preferred_src, Some(preferred_src_ipv6.into()));
    }

    #[test]
    fn hole_punch_request_falls_back_to_legacy_connector_addr() {
        let old_addr: SocketAddr = "[2001:db8::1]:10001".parse().unwrap();

        let (_, connector_addrs, _) = connector_addrs_from_request(SendUdpHolePunchPacketRequest {
            connector_addr: Some(old_addr.into()),
            listener_port: 11010,
            preferred_src_ipv6: None,
            connector_addrs: vec![],
        })
        .unwrap();

        assert_eq!(connector_addrs, vec![old_addr]);
    }

    #[test]
    fn hole_punch_request_rejects_out_of_range_listener_port() {
        let old_addr: SocketAddr = "[2001:db8::1]:10001".parse().unwrap();

        let ret = connector_addrs_from_request(SendUdpHolePunchPacketRequest {
            connector_addr: Some(old_addr.into()),
            listener_port: u16::MAX as u32 + 1,
            preferred_src_ipv6: None,
            connector_addrs: vec![],
        });

        assert!(ret.is_err());
    }
}
