use std::{sync::Arc, time::Duration};

use easytier_core::{
    connectivity::{
        direct::DirectConnectorOptions,
        manual::{
            ManualConnectivityEvent, ManualConnectivityEventSink, ManualConnectorOptions,
            ManualEndpointResolver,
        },
        protocol::ClientProtocolUpgrader,
    },
    instance::{CoreInstance, CoreInstanceAdapters, CoreInstanceConfig},
    socket::{dns::DnsResolver, tcp::TcpBindOptions, udp::UdpBindOptions},
};

use crate::{
    common::{
        config::ConfigLoader as _,
        dns::RuntimeDnsResolver,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    instance::listeners::RuntimeListenerService,
    peers::peer_manager::PeerManager,
    use_global_var,
};

use super::{
    dns_connector::DnsTunnelConnector, http_connector::HttpTunnelConnector,
    protocol::RuntimeClientProtocolUpgrader, runtime::RuntimeConnectorHost,
};

pub(crate) type RuntimeCoreInstance = CoreInstance<RuntimeConnectorHost>;

struct GlobalCtxManualConnectivityEventSink {
    global_ctx: ArcGlobalCtx,
}

struct RuntimeManualEndpointResolver {
    global_ctx: ArcGlobalCtx,
}

#[async_trait::async_trait]
impl ManualEndpointResolver for RuntimeManualEndpointResolver {
    async fn resolve_endpoint(&self, url: &url::Url) -> anyhow::Result<url::Url> {
        match url.scheme() {
            "http" | "https" => {
                let mut resolver = HttpTunnelConnector::new(url.clone(), self.global_ctx.clone());
                Ok(resolver.get_redirected_url(url.as_str()).await?)
            }
            "txt" | "srv" => {
                let resolver = DnsTunnelConnector::new(url.clone(), self.global_ctx.clone());
                let host = url
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("host should not be empty in {url}"))?;
                if url.scheme() == "txt" {
                    Ok(resolver.resolve_txt_endpoint(host).await?)
                } else {
                    Ok(resolver.resolve_srv_endpoint(host).await?)
                }
            }
            scheme => anyhow::bail!("unsupported manual endpoint resolver scheme: {scheme}"),
        }
    }
}

impl ManualConnectivityEventSink for GlobalCtxManualConnectivityEventSink {
    fn emit(&self, event: ManualConnectivityEvent) {
        match event {
            ManualConnectivityEvent::Connecting { url } => {
                self.global_ctx.issue_event(GlobalCtxEvent::Connecting(url));
            }
            ManualConnectivityEvent::ConnectError {
                url,
                ip_version,
                error,
            } => {
                self.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                    url.to_string(),
                    format!("{ip_version:?}"),
                    error,
                ));
            }
        }
    }
}

pub(crate) fn runtime_manual_options(global_ctx: &ArcGlobalCtx) -> ManualConnectorOptions {
    let flags = global_ctx.config.get_flags();
    ManualConnectorOptions {
        reconnect_interval: Duration::from_millis(use_global_var!(
            MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS
        )),
        connect_timeout: Duration::from_secs(2),
        websocket_connect_timeout: Duration::from_secs(20),
        bind_device: flags.bind_device,
        allow_interface_bind: !cfg!(any(
            target_os = "android",
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne"),
            target_env = "ohos"
        )),
        tcp_bind: TcpBindOptions::default().with_socket_mark(flags.socket_mark),
        udp_bind: UdpBindOptions::direct_connect().with_socket_mark(flags.socket_mark),
    }
}

pub(crate) fn runtime_direct_options(
    global_ctx: &ArcGlobalCtx,
    testing: bool,
) -> DirectConnectorOptions {
    let flags = global_ctx.config.get_flags();
    DirectConnectorOptions {
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
        testing,
    }
}

pub(crate) fn runtime_core_instance_adapters(
    global_ctx: ArcGlobalCtx,
) -> CoreInstanceAdapters<RuntimeConnectorHost> {
    CoreInstanceAdapters {
        host: Arc::new(RuntimeConnectorHost::new(global_ctx.clone())),
        dns: Arc::new(RuntimeDnsResolver::new()) as Arc<dyn DnsResolver>,
        endpoint_resolver: Arc::new(RuntimeManualEndpointResolver {
            global_ctx: global_ctx.clone(),
        }),
        protocol: Some(
            Arc::new(RuntimeClientProtocolUpgrader::new(global_ctx.clone()))
                as Arc<dyn ClientProtocolUpgrader<_>>,
        ),
        manual_events: Some(Arc::new(GlobalCtxManualConnectivityEventSink {
            global_ctx,
        })),
        listener: None,
        udp_hole_punch: None,
    }
}

pub(crate) fn build_runtime_core_instance(
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
) -> anyhow::Result<RuntimeCoreInstance> {
    let config = CoreInstanceConfig {
        initial_peers: Vec::new(),
        manual: runtime_manual_options(&global_ctx),
        direct: runtime_direct_options(&global_ctx, false),
    };
    let mut adapters = runtime_core_instance_adapters(global_ctx.clone());
    adapters.listener = Some(Arc::new(RuntimeListenerService::new(
        global_ctx,
        peer_manager.core(),
    )));
    adapters.udp_hole_punch = Some(Arc::new(super::udp_hole_punch::UdpHolePunchConnector::new(
        peer_manager.clone(),
    )));
    CoreInstance::new(peer_manager.core(), adapters, config)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use easytier_core::instance::{CoreInstanceState, ListenerService};
    use tokio::sync::Notify;
    use tokio_util::task::AbortOnDropHandle;

    use crate::{
        common::global_ctx::{
            NetworkIdentity,
            tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
        },
        peers::{
            create_packet_recv_chan,
            peer_manager::{PeerManager, RouteAlgoType},
        },
    };

    use super::*;

    #[derive(Default)]
    struct BlockingListenerService {
        start_entered: Notify,
        stop_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ListenerService for BlockingListenerService {
        async fn start(&self) -> anyhow::Result<()> {
            self.start_entered.notify_one();
            std::future::pending().await
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn build_test_instance_with_listener(
        network_name: &str,
        listener: Arc<dyn ListenerService>,
    ) -> Arc<RuntimeCoreInstance> {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network_name.to_owned(),
            String::new(),
        )));
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let config = CoreInstanceConfig {
            initial_peers: Vec::new(),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };
        let mut adapters = runtime_core_instance_adapters(global_ctx);
        adapters.listener = Some(listener);
        Arc::new(CoreInstance::new(peer_manager.core(), adapters, config).unwrap())
    }

    #[tokio::test]
    async fn runtime_core_instance_owns_connectivity_lifecycle() {
        let global_ctx = get_mock_global_ctx();
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let instance = Arc::new(
            build_runtime_core_instance(global_ctx, peer_manager)
                .expect("runtime core composition should succeed"),
        );

        assert_eq!(instance.state(), CoreInstanceState::Created);
        instance.start_listeners().await.unwrap();
        instance.start_listeners().await.unwrap();
        instance.start().await.unwrap();
        assert_eq!(instance.state(), CoreInstanceState::Running);
        assert!(instance.start_listeners().await.is_err());
        assert!(instance.start().await.is_err());
        instance.start_udp_hole_punch().await.unwrap();
        instance.start_udp_hole_punch().await.unwrap();

        instance.stop().await;
        instance.stop().await;
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
    }

    fn build_test_instance(network_name: &str) -> Arc<RuntimeCoreInstance> {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network_name.to_owned(),
            String::new(),
        )));
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        Arc::new(build_runtime_core_instance(global_ctx, peer_manager).unwrap())
    }

    #[tokio::test]
    async fn runtime_core_instances_keep_lifecycle_and_connectors_isolated() {
        let instance_a = build_test_instance("instance-a");
        let instance_b = build_test_instance("instance-b");
        let connector_a: url::Url = "tcp://127.0.0.1:21001".parse().unwrap();
        let connector_b: url::Url = "udp://127.0.0.1:21002".parse().unwrap();

        instance_a.add_connector(connector_a.clone()).unwrap();
        instance_b.add_connector(connector_b.clone()).unwrap();
        assert_eq!(instance_a.list_connectors()[0].url, connector_a);
        assert_eq!(instance_b.list_connectors()[0].url, connector_b);
        instance_a.clear_connectors();
        instance_b.clear_connectors();

        let (start_a, start_b) = tokio::join!(instance_a.start(), instance_b.start());
        start_a.unwrap();
        start_b.unwrap();
        let (udp_a, udp_b) = tokio::join!(
            instance_a.start_udp_hole_punch(),
            instance_b.start_udp_hole_punch()
        );
        udp_a.unwrap();
        udp_b.unwrap();
        assert_eq!(instance_a.state(), CoreInstanceState::Running);
        assert_eq!(instance_b.state(), CoreInstanceState::Running);

        instance_a.stop().await;
        assert_eq!(instance_a.state(), CoreInstanceState::Stopped);
        assert_eq!(instance_b.state(), CoreInstanceState::Running);

        instance_b.stop().await;
        assert_eq!(instance_b.state(), CoreInstanceState::Stopped);
    }

    #[tokio::test]
    async fn stop_cancels_pending_listener_start() {
        let listener = Arc::new(BlockingListenerService::default());
        let instance = build_test_instance_with_listener("pending-listener", listener.clone());
        let start_instance = instance.clone();
        let start_task = AbortOnDropHandle::new(tokio::spawn(async move {
            start_instance.start_listeners().await
        }));
        let start_result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            listener.start_entered.notified().await;
            instance.stop().await;
            start_task.await.unwrap()
        })
        .await
        .expect("listener cancellation should complete promptly");

        assert!(start_result.is_err());
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(listener.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stop_from_created_cleans_listener_service() {
        let listener = Arc::new(BlockingListenerService::default());
        let instance = build_test_instance_with_listener("created-listener", listener.clone());

        instance.stop().await;

        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(listener.stop_calls.load(Ordering::Relaxed), 1);
    }
}
