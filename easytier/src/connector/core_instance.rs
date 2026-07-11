use std::{sync::Arc, time::Duration};

use easytier_core::{
    connectivity::{
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
    peers::peer_manager::PeerManager,
    use_global_var,
};

use super::{
    direct::runtime_direct_options, dns_connector::DnsTunnelConnector,
    http_connector::HttpTunnelConnector, protocol::RuntimeClientProtocolUpgrader,
    runtime::RuntimeConnectorHost,
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

pub(crate) fn runtime_core_instance_adapters(
    global_ctx: ArcGlobalCtx,
) -> CoreInstanceAdapters<RuntimeConnectorHost> {
    CoreInstanceAdapters {
        host: Arc::new(RuntimeConnectorHost::new(global_ctx.clone())),
        dns: Arc::new(RuntimeDnsResolver::new()) as Arc<dyn DnsResolver>,
        endpoint_resolver: Arc::new(RuntimeManualEndpointResolver {
            global_ctx: global_ctx.clone(),
        }),
        protocol: Arc::new(RuntimeClientProtocolUpgrader::new(global_ctx.clone()))
            as Arc<dyn ClientProtocolUpgrader<_>>,
        manual_events: Some(Arc::new(GlobalCtxManualConnectivityEventSink {
            global_ctx,
        })),
    }
}

pub(crate) fn build_runtime_core_instance(
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
) -> anyhow::Result<RuntimeCoreInstance> {
    let config = CoreInstanceConfig {
        initial_peers: Vec::new(),
        manual: runtime_manual_options(&global_ctx),
        direct: runtime_direct_options(&global_ctx),
    };
    CoreInstance::new(
        peer_manager.core(),
        runtime_core_instance_adapters(global_ctx),
        config,
    )
}
