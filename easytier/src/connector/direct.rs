use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use easytier_core::{
    connectivity::direct::{
        DirectConnectorManager as CoreDirectConnectorManager, DirectConnectorOptions,
    },
    socket::{dns::DnsResolver, tcp::TcpBindOptions, udp::UdpBindOptions},
};

use crate::{
    common::{config::ConfigLoader, dns::RuntimeDnsResolver, global_ctx::ArcGlobalCtx},
    peers::peer_manager::PeerManager,
    use_global_var,
};

#[cfg(test)]
use crate::{
    common::{PeerId, error::Error},
    proto::peer_rpc::GetIpListResponse,
};

use super::{protocol::RuntimeClientProtocolUpgrader, runtime::RuntimeConnectorHost};

static TESTING: AtomicBool = AtomicBool::new(false);

type CoreManager = CoreDirectConnectorManager<RuntimeConnectorHost>;

pub struct DirectConnectorManager {
    inner: CoreManager,
}

impl DirectConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let flags = global_ctx.config.get_flags();
        let options = DirectConnectorOptions {
            network_name: global_ctx.get_network_name(),
            default_protocol: flags.default_protocol,
            enable_ipv6: flags.enable_ipv6,
            allow_public_server: use_global_var!(DIRECT_CONNECT_TO_PUBLIC_SERVER),
            lazy_p2p: flags.lazy_p2p,
            disable_p2p: flags.disable_p2p,
            need_p2p: flags.need_p2p,
            bind_device: flags.bind_device,
            allow_interface_bind: !cfg!(any(
                target_os = "android",
                target_os = "ios",
                all(target_os = "macos", feature = "macos-ne"),
                target_env = "ohos"
            )),
            tcp_bind: TcpBindOptions::default().with_socket_mark(flags.socket_mark),
            udp_bind: UdpBindOptions::direct_connect().with_socket_mark(flags.socket_mark),
            testing: TESTING.load(Ordering::Relaxed),
        };
        let inner = CoreDirectConnectorManager::new(
            peer_manager.core(),
            Arc::new(RuntimeConnectorHost::new(global_ctx.clone())),
            Arc::new(RuntimeDnsResolver::new()) as Arc<dyn DnsResolver>,
            Arc::new(RuntimeClientProtocolUpgrader::new(global_ctx)),
            options,
        );
        Self { inner }
    }

    pub fn run(&mut self) {
        self.inner.run();
    }

    pub fn run_as_server(&mut self) {
        self.inner.run_as_server();
    }

    pub fn run_as_client(&mut self) {
        self.inner.run_as_client();
    }

    #[cfg(test)]
    pub(crate) async fn try_direct_connect_with_ip_list(
        &self,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> Result<(), Error> {
        self.inner
            .try_direct_connect_with_ip_list(dst_peer_id, ip_list)
            .await
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        connector::direct::DirectConnectorManager,
        instance::listeners::ListenerManager,
        peers::tests::{create_mock_peer_manager, wait_route_appear, wait_route_appear_with_cost},
        proto::common::TunnelInfo,
        tunnel::{Tunnel, ring::RingTunnel},
    };
    use easytier_core::tunnel::ring::create_ring_socket_pair;

    use super::TESTING;

    fn ring_tunnel_info(local: &str, remote: &str) -> TunnelInfo {
        TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: Some(local.parse::<url::Url>().unwrap().into()),
            remote_addr: Some(remote.parse::<url::Url>().unwrap().into()),
            resolved_remote_addr: Some(remote.parse::<url::Url>().unwrap().into()),
        }
    }

    async fn connect_peer_manager(
        client: std::sync::Arc<crate::peers::peer_manager::PeerManager>,
        server: std::sync::Arc<crate::peers::peer_manager::PeerManager>,
    ) {
        let (client_socket, server_socket) = create_ring_socket_pair(1024);
        let client_tunnel: Box<dyn Tunnel> = Box::new(RingTunnel::new(
            client_socket,
            Some(ring_tunnel_info("ring://client", "ring://server")),
        ));
        let server_tunnel: Box<dyn Tunnel> = Box::new(RingTunnel::new(
            server_socket,
            Some(ring_tunnel_info("ring://server", "ring://client")),
        ));
        tokio::spawn(async move {
            client
                .add_client_tunnel(client_tunnel, false)
                .await
                .unwrap();
        });
        tokio::spawn(async move {
            server
                .add_tunnel_as_server(server_tunnel, true)
                .await
                .unwrap();
        });
    }

    async fn run_direct_connector_mapped_listener_test(
        mapped_listener: &str,
        target_listener: &str,
    ) {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        let p_x = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        connect_peer_manager(p_c.clone(), p_x.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
        wait_route_appear(p_a.clone(), p_x.clone()).await.unwrap();

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.bind_device = false;
        p_a.get_global_ctx().set_flags(flags);

        p_c.get_global_ctx()
            .config
            .set_mapped_listeners(Some(vec![mapped_listener.parse().unwrap()]));

        p_x.get_global_ctx()
            .config
            .set_listeners(vec![target_listener.parse().unwrap()]);
        let mut listener_manager = ListenerManager::new(p_x.get_global_ctx(), p_x.core());
        listener_manager.prepare_listeners().await.unwrap();
        listener_manager.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut direct_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut direct_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());
        direct_a.run_as_client();
        direct_c.run_as_server();

        wait_route_appear_with_cost(p_a.clone(), p_x.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn direct_connector_mapped_listener() {
        run_direct_connector_mapped_listener_test("tcp://127.0.0.1:11334", "tcp://0.0.0.0:11334")
            .await;
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn direct_connector_basic_test(
        #[values("tcp", "udp", "wg", "faketcp")] protocol: &str,
        #[values(true, false)] ipv6: bool,
    ) {
        #[cfg(not(feature = "faketcp"))]
        if protocol == "faketcp" {
            return;
        }

        if protocol == "faketcp" {
            if ipv6 {
                return;
            }
            #[cfg(target_family = "unix")]
            if unsafe { nix::libc::geteuid() } != 0 {
                return;
            }
        }

        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
        p_c.get_global_ctx()
            .get_ip_collector()
            .collect_ip_addrs()
            .await;
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;

        let mut direct_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut direct_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());
        direct_a.run_as_client();
        direct_c.run_as_server();

        let port = match protocol {
            "wg" => 11040,
            "faketcp" => 11042,
            _ => 11041,
        };
        let listener = if ipv6 {
            format!("{protocol}://[::]:{port}")
        } else {
            format!("{protocol}://0.0.0.0:{port}")
        };
        p_c.get_global_ctx()
            .config
            .set_listeners(vec![listener.parse().unwrap()]);
        let mut flags = p_c.get_global_ctx().config.get_flags();
        flags.enable_ipv6 = ipv6;
        p_c.get_global_ctx().set_flags(flags);
        let mut listener_manager = ListenerManager::new(p_c.get_global_ctx(), p_c.core());
        listener_manager.prepare_listeners().await.unwrap();
        listener_manager.run().await.unwrap();

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
    }
}
