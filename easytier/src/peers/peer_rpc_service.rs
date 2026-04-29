use std::net::SocketAddr;

use crate::{
    common::global_ctx::ArcGlobalCtx,
    proto::{
        common::Void,
        peer_rpc::{
            DirectConnectorRpc, GetIpListRequest, GetIpListResponse, SendUdpHolePunchPacketRequest,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::udp,
};

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
        let listener_port = req.listener_port as u16;
        let connector_addr: SocketAddr = req
            .connector_addr
            .ok_or(anyhow::anyhow!("connector_addr is required"))?
            .into();

        tracing::info!(
            "Sending udp hole punch packet to {} from listener port {}",
            connector_addr,
            listener_port
        );

        // send 3 packets to the connector
        for _ in 0..3 {
            match connector_addr {
                SocketAddr::V4(addr) => udp::send_v4_hole_punch_packet(listener_port, addr).await?,
                SocketAddr::V6(addr) => udp::send_v6_hole_punch_packet(listener_port, addr).await?,
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
    use std::collections::BTreeSet;

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        peers::peer_rpc_service::remove_easytier_managed_ipv6s, proto::peer_rpc::GetIpListResponse,
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
}
