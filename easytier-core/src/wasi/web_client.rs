use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use prost::Message;
use tokio::runtime::Builder;
use url::Url;

use crate::{
    config::{api_input::NetworkConfigExt, toml::ConfigLoader},
    connectivity::{
        connector_host::{ConnectorHost, new_connector_host},
        manual::{
            ManualConnectorOptions, ManualTunnelConnector, discovery::ManualEndpointDiscoveryConfig,
        },
        protocol::{CoreClientProtocolConfig, CoreClientProtocolUpgrader, raw::TunnelDialer},
    },
    foundation::time::{enter_domain, next_deadline_millis},
    host::{dns::HostDnsResolver, management::HostManagementClient, socket::HostSocketRuntime},
    management::{
        ConfigServerEndpoint, ManagementRpcForwarder, WebClient, WebClientBackend, WebClientConfig,
        config_source_from_rpc, register_forwarded_instance_management_rpc,
    },
    process_runtime::CoreProcessRuntime,
    proto::{
        api::manage::{
            ListNetworkInstanceRequest, NetworkConfig, NetworkingMethod, RunNetworkInstanceRequest,
            ValidateConfigRequest, ValidateConfigResponse, WebClientService,
            WebClientServiceClient, WebClientServiceDescriptor, WebClientServiceMethodDescriptor,
        },
        common::{DirectRpcRequest, HostManagementRequest, RpcResponse},
        rpc_types::{
            controller::BaseController,
            descriptor::{MethodDescriptor, ServiceDescriptor},
            error,
            handler::Handler,
        },
        web::DeviceOsInfo,
    },
    rpc::service_registry::ServiceRegistry,
    socket::IpVersion,
    tunnel::Tunnel,
    wasi::{
        adapter::{
            dns::WasiHostDnsIo, environment::WasiHostConnectorEnvironmentIo,
            management::WasiHostManagementIo, socket::backend::WasiHostSocketBackend,
        },
        runtime_driver::{RuntimeDriveOutcome, RuntimeDriver},
        schema::WasiWebClientCreateConfig,
    },
};

pub(super) const WEB_CLIENT_DOMAIN: u64 = u64::MAX;

type WasiConnectorHost = ConnectorHost<WasiHostSocketBackend, WasiHostConnectorEnvironmentIo>;

fn supports_hosted_tunnel_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "tcp" | "udp"))
}

fn hosted_network_config(config: &NetworkConfig) -> NetworkConfig {
    let public_server_url = config
        .public_server_url
        .as_ref()
        .filter(|url| supports_hosted_tunnel_url(url))
        .cloned();
    let peers = config
        .peers
        .iter()
        .filter(|peer| supports_hosted_tunnel_url(&peer.uri))
        .cloned()
        .collect::<Vec<_>>();
    let networking_method =
        match NetworkingMethod::try_from(config.networking_method.unwrap_or_default()) {
            Ok(NetworkingMethod::PublicServer)
                if public_server_url.is_none() && peers.is_empty() =>
            {
                NetworkingMethod::Standalone
            }
            Ok(method) => method,
            Err(_) => NetworkingMethod::Standalone,
        };

    NetworkConfig {
        instance_id: config.instance_id.clone(),
        dhcp: config.dhcp,
        virtual_ipv4: config.virtual_ipv4.clone(),
        network_length: config.network_length,
        hostname: config.hostname.clone(),
        network_name: config.network_name.clone(),
        network_secret: config.network_secret.clone(),
        networking_method: Some(networking_method as i32),
        public_server_url,
        peer_urls: config
            .peer_urls
            .iter()
            .filter(|url| supports_hosted_tunnel_url(url))
            .cloned()
            .collect(),
        proxy_cidrs: config.proxy_cidrs.clone(),
        listener_urls: config
            .listener_urls
            .iter()
            .filter(|url| supports_hosted_tunnel_url(url))
            .cloned()
            .collect(),
        latency_first: config.latency_first,
        disable_ipv6: config.disable_ipv6,
        disable_p2p: config.disable_p2p,
        no_tun: config.no_tun,
        relay_all_peer_rpc: config.relay_all_peer_rpc,
        enable_relay_network_whitelist: config.enable_relay_network_whitelist,
        relay_network_whitelist: config.relay_network_whitelist.clone(),
        disable_encryption: config.disable_encryption,
        disable_udp_hole_punching: config.disable_udp_hole_punching,
        mtu: config.mtu,
        enable_private_mode: config.enable_private_mode,
        disable_sym_hole_punching: config.disable_sym_hole_punching,
        p2p_only: config.p2p_only,
        disable_tcp_hole_punching: config.disable_tcp_hole_punching,
        secure_mode: config.secure_mode.clone(),
        acl: config.acl.clone(),
        port_forwards: config.port_forwards.clone(),
        lazy_p2p: config.lazy_p2p,
        need_p2p: config.need_p2p,
        instance_recv_bps_limit: config.instance_recv_bps_limit,
        disable_upnp: config.disable_upnp,
        disable_relay_data: config.disable_relay_data,
        enable_udp_broadcast_relay: config.enable_udp_broadcast_relay,
        peers,
        ..Default::default()
    }
}

struct WasiConfigServerConnector {
    url: Url,
    connector: ManualTunnelConnector<WasiConnectorHost>,
}

#[async_trait]
impl TunnelDialer for WasiConfigServerConnector {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        self.connector
            .connect(self.url.clone(), IpVersion::Both)
            .await
    }

    fn remote_url(&self) -> Url {
        self.url.clone()
    }
}

#[derive(Clone)]
struct HostManagementHandler {
    client: HostManagementClient<WasiHostManagementIo>,
}

impl HostManagementHandler {
    async fn forward(
        &self,
        full_method_name: String,
        request: Bytes,
        prepared_config: Option<String>,
        prepared_instance_id: Option<uuid::Uuid>,
    ) -> error::Result<Bytes> {
        let request = HostManagementRequest {
            rpc: Some(DirectRpcRequest {
                full_method_name,
                request: request.into(),
                timeout_ms: None,
            }),
            prepared_config,
            prepared_instance_id: prepared_instance_id.map(Into::into),
        };
        let response = self
            .client
            .call(&request.encode_to_vec())
            .await
            .map_err(|error| error::Error::ExecutionError(error.into()))?;
        let response = RpcResponse::decode(response.as_slice())?;
        if let Some(error) = response.error {
            return Err((&error).into());
        }
        Ok(response.response.into())
    }
}

#[async_trait]
impl ManagementRpcForwarder for HostManagementHandler {
    async fn forward(&self, full_method_name: String, input: Bytes) -> error::Result<Bytes> {
        HostManagementHandler::forward(self, full_method_name, input, None, None).await
    }
}

#[async_trait]
impl Handler for HostManagementHandler {
    type Descriptor = WebClientServiceDescriptor;
    type Controller = BaseController;

    async fn call(
        &self,
        _: Self::Controller,
        method: WebClientServiceMethodDescriptor,
        input: Bytes,
    ) -> error::Result<Bytes> {
        let full_method_name = format!(
            "{}.{}.{}",
            WebClientServiceDescriptor.package(),
            WebClientServiceDescriptor.proto_name(),
            method.proto_name()
        );
        match method {
            WebClientServiceMethodDescriptor::ValidateConfig => {
                let request = ValidateConfigRequest::decode(input)?;
                let network_config = request.config.unwrap_or_default();
                let config = hosted_network_config(&network_config).gen_config()?;
                Ok(ValidateConfigResponse {
                    toml_config: config.dump(),
                }
                .encode_to_vec()
                .into())
            }
            WebClientServiceMethodDescriptor::RunNetworkInstance => {
                let request = RunNetworkInstanceRequest::decode(input.clone())?;
                let network_config = request
                    .config
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("config is required"))?;
                let config = hosted_network_config(&network_config).gen_config()?;
                let instance_id = request
                    .inst_id
                    .map(Into::into)
                    .unwrap_or_else(|| config.get_id());
                config.set_id(instance_id);
                config.set_network_config_source(config_source_from_rpc(request.source));
                self.forward(
                    full_method_name,
                    input,
                    Some(config.dump()),
                    Some(instance_id),
                )
                .await
            }
            _ => self.forward(full_method_name, input, None, None).await,
        }
    }
}

struct WasiWebClientBackend {
    handler: HostManagementHandler,
}

#[async_trait]
impl WebClientBackend for WasiWebClientBackend {
    fn register(&self, registry: &ServiceRegistry) {
        registry.register(self.handler.clone(), "");
        register_forwarded_instance_management_rpc(self.handler.clone(), registry);
    }

    async fn instance_ids(&self) -> anyhow::Result<Vec<uuid::Uuid>> {
        let response = WebClientServiceClient::new(self.handler.clone())
            .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
            .await?;
        Ok(response.inst_ids.into_iter().map(Into::into).collect())
    }
}

pub(super) struct WasiWebClientRuntime {
    socket_runtime: HostSocketRuntime,
    client: WebClient<()>,
    execution: Mutex<WasiWebClientExecution>,
}

struct WasiWebClientExecution {
    runtime: tokio::runtime::Runtime,
    runtime_driver: RuntimeDriver,
    drive_again: bool,
}

impl WasiWebClientRuntime {
    pub(super) fn new(
        config: WasiWebClientCreateConfig,
        process_runtime: Arc<CoreProcessRuntime>,
    ) -> anyhow::Result<Self> {
        let endpoint = ConfigServerEndpoint::parse(&config.endpoint, |url| {
            matches!(url.scheme(), "tcp" | "udp")
        })?;
        let machine_id = uuid::Uuid::parse_str(&config.machine_id)?;
        let runtime_driver = RuntimeDriver::default();
        let park_driver = runtime_driver.clone();
        let runtime = Builder::new_current_thread()
            .enable_time()
            .on_thread_park(move || park_driver.on_thread_park())
            .build()?;
        let socket_runtime = HostSocketRuntime::new();
        let client = {
            let _domain = enter_domain(WEB_CLIENT_DOMAIN);
            let _runtime = runtime.enter();
            let host = Arc::new(new_connector_host(
                socket_runtime.clone(),
                Arc::new(WasiHostSocketBackend::default()),
                config.environment,
                Arc::new(WasiHostConnectorEnvironmentIo),
            ));
            let dns = Arc::new(HostDnsResolver::new(
                socket_runtime.clone(),
                Arc::new(WasiHostDnsIo),
            ));
            let connector = process_runtime.manual_connector(
                host,
                dns.clone(),
                dns,
                Arc::new(CoreClientProtocolUpgrader::new(
                    CoreClientProtocolConfig::default(),
                )),
                ManualEndpointDiscoveryConfig::default(),
                ManualConnectorOptions::default(),
            );
            let backend = Arc::new(WasiWebClientBackend {
                handler: HostManagementHandler {
                    client: HostManagementClient::new(
                        socket_runtime.clone(),
                        Arc::new(WasiHostManagementIo),
                    ),
                },
            });
            WebClient::with_backend(
                WasiConfigServerConnector {
                    url: endpoint.connect_url().clone(),
                    connector,
                },
                WebClientConfig {
                    token: endpoint.token().to_owned(),
                    machine_id,
                    hostname: config.hostname,
                    device_os: DeviceOsInfo {
                        os_type: config.os_type,
                        version: String::new(),
                        distribution: String::new(),
                    },
                    easytier_version: env!("CARGO_PKG_VERSION").to_owned(),
                    secure_mode: config.secure_mode,
                },
                backend,
            )
        };

        Ok(Self {
            socket_runtime,
            client,
            execution: Mutex::new(WasiWebClientExecution {
                runtime,
                runtime_driver,
                drive_again: false,
            }),
        })
    }

    pub(super) fn drive(&self) {
        let _domain = enter_domain(WEB_CLIENT_DOMAIN);
        let advance_timers = next_deadline_millis(WEB_CLIENT_DOMAIN) == Some(0);
        let mut execution = self.execution.lock().unwrap();
        execution.drive_again = execution
            .runtime_driver
            .drive(&execution.runtime, advance_timers)
            == RuntimeDriveOutcome::BudgetExhausted;
    }

    pub(super) fn notify_host_completions(&self) {
        self.socket_runtime.notify_completions();
    }

    pub(super) fn next_wait_millis(&self) -> Option<u64> {
        let execution = self.execution.lock().unwrap();
        if execution.drive_again {
            Some(0)
        } else {
            next_deadline_millis(WEB_CLIENT_DOMAIN)
        }
    }

    pub(super) fn is_connected(&self) -> bool {
        self.client.is_connected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        api::manage::NetworkPeerConfig,
        common::{CompressionAlgoPb, SecureModeConfig},
    };

    #[test]
    fn hosted_config_keeps_supported_fields_and_filters_tunnel_urls() {
        let original = NetworkConfig {
            instance_id: Some(uuid::Uuid::new_v4().to_string()),
            dhcp: Some(true),
            network_name: Some("network".to_owned()),
            network_secret: Some("secret".to_owned()),
            networking_method: Some(NetworkingMethod::Manual as i32),
            peer_urls: vec![
                "tcp://peer.example:11010".to_owned(),
                "wg://peer.example:11011".to_owned(),
            ],
            listener_urls: vec![
                "udp://0.0.0.0:11010".to_owned(),
                "wg://0.0.0.0:11011".to_owned(),
            ],
            peers: vec![
                NetworkPeerConfig {
                    uri: "tcp://peer.example:11010".to_owned(),
                    peer_public_key: Some("key".to_owned()),
                },
                NetworkPeerConfig {
                    uri: "quic://peer.example:11010".to_owned(),
                    peer_public_key: None,
                },
            ],
            secure_mode: Some(SecureModeConfig {
                enabled: true,
                ..Default::default()
            }),
            enable_private_mode: Some(true),
            disable_relay_data: Some(true),
            proxy_cidrs: vec!["10.88.0.0/24".to_owned()],
            port_forwards: vec![crate::proto::api::manage::PortForwardConfig {
                proto: "tcp".to_owned(),
                bind_ip: "127.0.0.1".to_owned(),
                bind_port: 18080,
                dst_ip: "10.88.0.2".to_owned(),
                dst_port: 80,
            }],
            enable_vpn_portal: Some(true),
            data_compress_algo: Some(CompressionAlgoPb::Zstd as i32),
            credential_file: Some("/unsupported".to_owned()),
            ..Default::default()
        };

        let hosted = hosted_network_config(&original);

        assert_eq!(
            hosted.peer_urls,
            vec!["tcp://peer.example:11010".to_owned()]
        );
        assert_eq!(hosted.listener_urls, vec!["udp://0.0.0.0:11010".to_owned()]);
        assert_eq!(hosted.peers, original.peers[..1]);
        assert_eq!(hosted.secure_mode, original.secure_mode);
        assert_eq!(hosted.enable_private_mode, Some(true));
        assert_eq!(hosted.disable_relay_data, Some(true));
        assert_eq!(hosted.proxy_cidrs, original.proxy_cidrs);
        assert_eq!(hosted.port_forwards, original.port_forwards);
        assert_eq!(hosted.enable_vpn_portal, None);
        assert_eq!(hosted.data_compress_algo, None);
        assert_eq!(hosted.credential_file, None);
        assert_eq!(original.listener_urls.len(), 2);
    }

    #[test]
    fn hosted_config_falls_back_to_standalone_without_a_supported_public_peer() {
        let hosted = hosted_network_config(&NetworkConfig {
            networking_method: Some(NetworkingMethod::PublicServer as i32),
            public_server_url: Some("wg://peer.example:11010".to_owned()),
            ..Default::default()
        });

        assert_eq!(
            hosted.networking_method,
            Some(NetworkingMethod::Standalone as i32)
        );
        assert_eq!(hosted.public_server_url, None);
    }
}
