use async_trait::async_trait;
use url::Url;

use super::*;
use crate::{
    config::toml::ConfigLoader as _,
    listener::transport::TransportListenerConfig,
    socket::{
        SocketContext, SocketListener,
        udp::{UdpSessionAcceptKind, UdpSessionProtocol},
    },
};

struct TestServerProtocol;

#[async_trait]
impl ServerProtocolUpgrader<()> for TestServerProtocol {
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "ws" | "wss" | "wg" | "quic" | "faketcp" | "unix")
    }

    async fn upgrade_tcp(
        &self,
        _socket: (),
        _local_url: Url,
    ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
        unreachable!()
    }

    async fn upgrade_udp(
        &self,
        _session: crate::socket::udp::UdpSession,
        _local_url: Url,
        _admission: Option<crate::connectivity::protocol::ServerProtocolAdmission>,
    ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
        unreachable!()
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: (),
        _local_url: Url,
        _remote_url: Option<Url>,
    ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
        unreachable!()
    }
}

struct TestExternalListenerFactory;

impl ExternalListenerFactory<()> for TestExternalListenerFactory {
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "faketcp" | "unix")
    }

    fn create(&self, _request: ExternalListenerRequest) -> Box<dyn SocketListener<Accepted = ()>> {
        unreachable!()
    }
}

#[test]
fn core_plans_transport_and_external_listener_capabilities() {
    let self_id = uuid::Uuid::new_v4();
    let config = ListenerRuntimeConfig::new(
        [
            "tcp://127.0.0.1:1",
            "udp://127.0.0.1:2",
            "ws://127.0.0.1:3",
            "wg://127.0.0.1:4",
            "quic://127.0.0.1:5",
            "faketcp://127.0.0.1:6",
            "unix:///tmp/easytier-test",
            "http://127.0.0.1:7",
        ]
        .into_iter()
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .unwrap(),
        false,
        SocketContext::default().with_socket_mark(Some(7)),
    );

    let plan = prepare_listener_plan::<(), ()>(
        Some(&config),
        self_id,
        Some(&TestServerProtocol),
        Some(&TestExternalListenerFactory),
    )
    .unwrap();

    assert_eq!(plan.transports.len(), 6);
    assert_eq!(plan.external.len(), 2);
    assert_eq!(plan.failures.len(), 1);
    assert_eq!(
        plan.transports[0].url(),
        &crate::listener::plan::ring_listener_url(self_id)
    );
    assert!(matches!(
        &plan.transports[4],
        TransportListenerConfig::Udp {
            accept_kind: UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
            ..
        }
    ));
    assert!(matches!(
        &plan.transports[5],
        TransportListenerConfig::Udp {
            accept_kind: UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
            ..
        }
    ));
    assert_eq!(plan.external[0].0.url.scheme(), "faketcp");
    assert_eq!(plan.external[0].1.socket_mark, Some(7));
}

#[test]
fn unsupported_protocol_listener_becomes_a_plan_failure() {
    let config = ListenerRuntimeConfig::new(
        vec!["wg://127.0.0.1:11011".parse().unwrap()],
        false,
        SocketContext::default(),
    );

    let plan =
        prepare_listener_plan::<(), ()>(Some(&config), uuid::Uuid::new_v4(), None, None).unwrap();

    assert_eq!(plan.transports.len(), 1);
    assert!(plan.external.is_empty());
    assert_eq!(plan.failures.len(), 1);
}

#[test]
fn raw_unix_listener_does_not_require_a_server_protocol() {
    let config = ListenerRuntimeConfig::new(
        vec!["unix:///tmp/easytier-test".parse().unwrap()],
        false,
        SocketContext::default(),
    );

    let plan = prepare_listener_plan::<(), ()>(
        Some(&config),
        uuid::Uuid::new_v4(),
        None,
        Some(&TestExternalListenerFactory),
    )
    .unwrap();

    assert_eq!(plan.transports.len(), 1);
    assert_eq!(plan.external.len(), 1);
    assert!(plan.failures.is_empty());
    assert_eq!(plan.external[0].0.url.scheme(), "unix");
}

#[test]
fn instance_config_round_trips_as_normalized_json() {
    let mut parsed = crate::config::InstanceConfigParsed::default();
    parsed.instance_name = "test-instance".to_owned();
    parsed.hostname = "test-host".to_owned();
    parsed.dhcp = true;
    let config = crate::config::InstanceConfig::from(parsed);

    let encoded = serde_json::to_value(&config).unwrap();
    let decoded: crate::config::InstanceConfig = serde_json::from_value(encoded.clone()).unwrap();

    assert_eq!(decoded.instance_name, "test-instance");
    assert_eq!(decoded.hostname, "test-host");
    assert!(decoded.dhcp);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), encoded);
}

#[test]
fn wasi_create_config_uses_shared_toml() {
    let fixture = include_bytes!("../../testdata/wasi_core_instance_create.json");
    let mut create =
        serde_json::from_slice::<crate::wasi::schema::WasiCoreInstanceCreateConfig>(fixture)
            .unwrap();
    create.validate().unwrap();
    let config = create.parse_config().unwrap();
    let normalized = config.snapshot().unwrap();

    assert_eq!(normalized.instance_id, config.get_id());
    assert!(normalized.flags.disable_p2p);
    create.version += 1;
    assert!(create.validate().is_err());
}

#[test]
fn acl_config_rejects_invalid_whitelist() {
    let config = crate::config::peers::AclRuleConfig {
        tcp_whitelist: vec!["9000-8000".to_owned()],
        ..Default::default()
    };

    let error = config.build().unwrap_err();

    assert!(error.to_string().contains("Start port must be <= end port"));
}

mod portable_runtime {
    use std::{
        net::{IpAddr, Ipv6Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio::sync::Notify;
    use tokio_util::task::AbortOnDropHandle;

    #[cfg(feature = "proxy-packet")]
    use std::sync::Mutex as StdMutex;

    use super::*;
    use crate::peers::context::PeerContext;
    use crate::{
        config::{InstanceConfig, InstanceConfigParsed},
        connectivity::manual::{ManualConnectorHost, ManualInterfaceAddrs},
        gateway::proxy::wrapped_transport::{
            WrappedTransportEngine, WrappedTransportEngineStart, WrappedTransportEngines,
            WrappedTransportRole,
        },
        host::testkit::{TestDns, TestHost, TestTcpSocket},
        listener::transport::AcceptedTransport,
        proto::peer_rpc::GetIpListResponse,
        socket::{SocketContext, udp::PreferredIpv6Source},
    };

    #[cfg(feature = "proxy-smoltcp-stack")]
    use crate::config::gateway::PortForwardConfig;
    #[cfg(feature = "proxy-packet")]
    use crate::gateway::proxy::wrapped_transport::WrappedTransportKind;

    #[async_trait]
    impl ManualConnectorHost for TestHost {
        async fn local_addr_for_remote(
            &self,
            remote_addr: SocketAddr,
            _context: SocketContext,
        ) -> anyhow::Result<SocketAddr> {
            Ok(match remote_addr {
                SocketAddr::V4(_) => "127.0.0.1:0".parse().unwrap(),
                SocketAddr::V6(_) => "[::1]:0".parse().unwrap(),
            })
        }

        async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
            Ok(ManualInterfaceAddrs {
                interface_ipv4s: vec![],
                interface_ipv6s: vec![],
                public_ipv6: None,
            })
        }
    }

    #[async_trait]
    impl DirectConnectorHost for TestHost {
        async fn collect_ip_addrs(&self, _context: &SocketContext) -> GetIpListResponse {
            GetIpListResponse::default()
        }

        fn mapped_listeners(&self) -> Vec<Url> {
            Vec::new()
        }

        fn is_local_ip(&self, _ip: &IpAddr) -> bool {
            false
        }

        async fn preferred_ipv6_source(
            &self,
            _ip: Ipv6Addr,
            _context: SocketContext,
        ) -> Option<PreferredIpv6Source> {
            None
        }
    }

    fn test_config(network_name: &str) -> InstanceConfig {
        let mut parsed = InstanceConfigParsed::default();
        parsed.instance_name = network_name.to_owned();
        parsed.network_identity =
            crate::config::NetworkIdentity::new(network_name.to_owned(), String::new());
        parsed.into()
    }

    #[cfg(feature = "vpn-portal")]
    fn portal_test_config(network_name: &str) -> InstanceConfig {
        let mut config = test_config(network_name);
        config.parsed_mut().network_identity = crate::config::NetworkIdentity::new(
            network_name.to_owned(),
            "portal-network-secret".to_owned(),
        );
        config.parsed_mut().ipv4 = Some("10.82.0.1/24".parse().unwrap());
        config.parsed_mut().vpn_portal_config = Some(crate::config::toml::VpnPortalConfig {
            wireguard_listen: "0.0.0.0:0".parse().unwrap(),
            wireguard_private_key: None,
            clients: vec![crate::config::toml::VpnPortalClientConfig {
                name: "alice".to_owned(),
                virtual_ip: "10.82.0.2/24".parse().unwrap(),
                groups: Vec::new(),
            }],
        });
        config
    }

    fn runtime_snapshot(config: &InstanceConfig) -> InstanceConfig {
        config.clone()
    }

    fn proxy_network(real: &str, mapped: Option<&str>) -> crate::config::toml::ProxyNetworkConfig {
        crate::config::toml::ProxyNetworkConfig {
            cidr: real.parse().unwrap(),
            mapped_cidr: mapped.map(|m| m.parse().unwrap()),
            allow: None,
        }
    }

    fn adapters(
        external_listener_factory: Option<
            Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
        >,
        packet_sink: Arc<dyn PacketSink>,
    ) -> CoreHostAdapters<TestHost> {
        adapters_with_process_runtime(
            external_listener_factory,
            packet_sink,
            CoreProcessRuntime::new(),
        )
    }

    fn adapters_with_process_runtime(
        external_listener_factory: Option<
            Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
        >,
        packet_sink: Arc<dyn PacketSink>,
        process_runtime: Arc<CoreProcessRuntime>,
    ) -> CoreHostAdapters<TestHost> {
        adapters_with_host_and_process_runtime(
            Arc::new(TestHost::default()),
            external_listener_factory,
            packet_sink,
            process_runtime,
        )
    }

    #[cfg(any(feature = "proxy-packet", feature = "proxy-smoltcp-stack"))]
    fn adapters_with_host(
        host: Arc<TestHost>,
        external_listener_factory: Option<
            Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
        >,
        packet_sink: Arc<dyn PacketSink>,
    ) -> CoreHostAdapters<TestHost> {
        adapters_with_host_and_process_runtime(
            host,
            external_listener_factory,
            packet_sink,
            CoreProcessRuntime::new(),
        )
    }

    fn adapters_with_host_and_process_runtime(
        host: Arc<TestHost>,
        external_listener_factory: Option<
            Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
        >,
        packet_sink: Arc<dyn PacketSink>,
        process_runtime: Arc<CoreProcessRuntime>,
    ) -> CoreHostAdapters<TestHost> {
        let dns = Arc::new(TestDns);
        let mut adapters = CoreHostAdapters::new(host, dns, packet_sink, process_runtime);
        adapters.external_listener_factory = external_listener_factory;
        adapters
    }

    fn build_with_engines(
        config: InstanceConfig,
        engines: WrappedTransportEngines,
    ) -> anyhow::Result<Arc<CoreInstance<TestHost>>> {
        build_with_engines_and_listener(config, engines, None)
    }

    fn build_with_engines_and_listener(
        config: InstanceConfig,
        engines: WrappedTransportEngines,
        external_listener_factory: Option<
            Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
        >,
    ) -> anyhow::Result<Arc<CoreInstance<TestHost>>> {
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(external_listener_factory, Arc::new(packet_sink));
        adapters.wrapped_transports = engines;
        CoreInstance::new(config, adapters)
    }

    fn build_instance(config: InstanceConfig) -> anyhow::Result<Arc<CoreInstance<TestHost>>> {
        build_with_engines(config, WrappedTransportEngines::default())
    }

    #[cfg(feature = "management")]
    struct RecordingConfigPatchPersistence {
        writes: std::sync::Mutex<Vec<String>>,
        fail: AtomicBool,
        fail_after_writes: AtomicUsize,
    }

    #[cfg(feature = "management")]
    impl RecordingConfigPatchPersistence {
        fn new(fail: bool) -> Self {
            Self {
                writes: std::sync::Mutex::new(Vec::new()),
                fail: AtomicBool::new(fail),
                fail_after_writes: AtomicUsize::new(0),
            }
        }

        fn fail_after(limit: usize) -> Self {
            Self {
                writes: std::sync::Mutex::new(Vec::new()),
                fail: AtomicBool::new(false),
                fail_after_writes: AtomicUsize::new(limit),
            }
        }
    }

    #[cfg(feature = "management")]
    #[async_trait]
    impl crate::management::ConfigPatchPersistence for RecordingConfigPatchPersistence {
        async fn persist(
            &self,
            _instance_id: uuid::Uuid,
            config: &crate::config::InstanceConfig,
        ) -> anyhow::Result<()> {
            if self.fail.load(Ordering::Relaxed) {
                anyhow::bail!("injected config persistence failure");
            }
            let fail_after = self.fail_after_writes.load(Ordering::Relaxed);
            let mut writes = self.writes.lock().unwrap();
            if fail_after > 0 && writes.len() >= fail_after {
                anyhow::bail!("injected config persistence failure after limit");
            }
            let dumped = crate::config::serialize_raw_to_toml(config.raw())?;
            writes.push(dumped);
            Ok(())
        }
    }

    #[cfg(feature = "vpn-portal")]
    struct RejectingPortalHost;

    #[cfg(feature = "vpn-portal")]
    #[async_trait]
    impl crate::gateway::vpn_portal::PortalHost for RejectingPortalHost {
        async fn start_listeners(
            &self,
        ) -> anyhow::Result<Vec<crate::gateway::vpn_portal::PortalListener>> {
            anyhow::bail!("injected portal start failure")
        }

        fn name(&self) -> String {
            "rejecting-test-portal".to_owned()
        }

        fn render_client_config(
            &self,
            _plan: &crate::gateway::vpn_portal::PortalClientConfigPlan,
        ) -> String {
            String::new()
        }

        async fn update_clients(
            &self,
            _clients: &[crate::gateway::vpn_portal::PortalClientConfig],
        ) -> anyhow::Result<()> {
            anyhow::bail!("injected portal update failure")
        }
    }

    #[cfg(feature = "vpn-portal")]
    struct SucceedingPortalHost;

    #[cfg(feature = "vpn-portal")]
    #[async_trait]
    impl crate::gateway::vpn_portal::PortalHost for SucceedingPortalHost {
        async fn start_listeners(
            &self,
        ) -> anyhow::Result<Vec<crate::gateway::vpn_portal::PortalListener>> {
            Ok(vec![])
        }

        fn name(&self) -> String {
            "succeeding-test-portal".to_owned()
        }

        fn render_client_config(
            &self,
            _plan: &crate::gateway::vpn_portal::PortalClientConfigPlan,
        ) -> String {
            String::new()
        }

        async fn update_clients(
            &self,
            _clients: &[crate::gateway::vpn_portal::PortalClientConfig],
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }
    #[cfg(feature = "vpn-portal")]
    #[tokio::test]
    async fn runtime_update_rejects_portal_client_address_conflict() {
        let instance = build_instance(portal_test_config("portal-runtime-update")).unwrap();
        let before = instance.runtime_config.snapshot();
        let mut conflicting = (*before).clone();
        conflicting.parsed_mut().ipv4 = Some("10.82.0.2/24".parse().unwrap());

        let error = instance
            .update_runtime_config(conflicting)
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("unusable virtual IP"),
            "unexpected runtime update error: {error:#}"
        );
        assert_eq!(instance.runtime_config.snapshot().ipv4, before.ipv4);
        instance.peer_manager.clear_resources().await;
    }
    #[cfg(feature = "vpn-portal")]
    #[tokio::test]
    async fn runtime_update_allows_removing_portal_client_acl_group() {
        let mut config = portal_test_config("portal-acl-group-removal");
        config
            .parsed_mut()
            .vpn_portal_config
            .as_mut()
            .unwrap()
            .clients[0]
            .groups = vec!["ops".to_owned()];
        let mut acl = easytier_proto::acl::Acl::default();
        acl.acl_v1 = Some(easytier_proto::acl::AclV1 {
            group: Some(easytier_proto::acl::GroupInfo {
                declares: vec![easytier_proto::acl::GroupIdentity {
                    group_name: "ops".to_owned(),
                    group_secret: "ops-secret".to_owned(),
                }],
                members: Vec::new(),
            }),
            ..Default::default()
        });
        config.parsed_mut().acl = Some(acl);
        let instance = build_instance(config).unwrap();
        let mut updated = (*instance.runtime_config.snapshot()).clone();
        if let Some(acl) = updated.parsed_mut().acl.as_mut() {
            if let Some(acl_v1) = acl.acl_v1.as_mut() {
                if let Some(group) = acl_v1.group.as_mut() {
                    group.declares.clear();
                }
            }
        }

        instance.update_runtime_config(updated).await.unwrap();

        let (declares, _) =
            crate::peers::context::peer_acl_groups(instance.runtime_config.snapshot().acl.as_ref());
        assert!(declares.is_empty());
        instance.peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn update_runtime_config_updates_management_snapshot() {
        let mut initial_raw = test_config("management-sync-before").into_raw();
        initial_raw.hostname = Some("management-sync-before".to_owned());
        let initial = InstanceConfig::try_from(initial_raw).unwrap();
        let instance = build_instance(initial).unwrap();
        assert_eq!(
            instance.config_store().snapshot().parsed().hostname,
            "management-sync-before"
        );

        let mut updated_raw = instance.runtime_config.snapshot().raw().clone();
        updated_raw.hostname = Some("management-sync-after".to_owned());
        let updated = InstanceConfig::try_from(updated_raw).unwrap();
        instance.update_runtime_config(updated).await.unwrap();

        assert_eq!(
            instance.config_store().snapshot().parsed().hostname,
            "management-sync-after"
        );
        instance.peer_manager.clear_resources().await;
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn config_patch_rejects_private_public_ipv6_prefix() {
        use easytier_proto::api::config::InstanceConfigPatch;

        let initial = test_config("public-ipv6-patch-reject");
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(None, Arc::new(packet_sink));
        adapters.config.public_ipv6_provider_supported = true;
        let instance = CoreInstance::new(initial, adapters).unwrap();
        instance.set_state(CoreInstanceState::Running);

        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                ipv6_public_addr_provider: Some(true),
                ipv6_public_addr_prefix: Some("fd00::/64".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("not a valid global unicast IPv6 prefix")
        );
        instance.peer_manager.clear_resources().await;
    }

    #[cfg(feature = "dhcp-ipv4")]
    #[tokio::test]
    async fn runtime_update_preserves_dhcp_owned_ipv4() {
        let mut initial = test_config("dhcp-runtime-update");
        initial.parsed_mut().dhcp = true;
        let instance = build_instance(initial).unwrap();
        let lease: cidr::Ipv4Inet = "10.126.126.7/24".parse().unwrap();
        instance.peer_manager.context().set_dhcp_ipv4(Some(lease));

        assert_eq!(instance.peer_manager.context().ipv4(), Some(lease));

        let mut replacement = test_config("dhcp-runtime-update");
        replacement.parsed_mut().dhcp = true;
        instance
            .update_runtime_config(runtime_snapshot(&replacement))
            .await
            .unwrap();

        assert_eq!(instance.peer_manager.context().ipv4(), Some(lease));
        assert_eq!(instance.runtime_config.snapshot().ipv4, None);

        let static_replacement = test_config("dhcp-runtime-update");
        instance
            .update_runtime_config(runtime_snapshot(&static_replacement))
            .await
            .unwrap();
        assert_eq!(instance.peer_manager.context().ipv4(), None);
    }

    #[tokio::test]
    async fn core_instance_is_a_direct_managed_record() {
        let instance = build_instance(test_config("managed-directly")).unwrap();

        assert_eq!(instance.instance_name(), "managed-directly");
        assert_eq!(
            instance.instance_id(),
            crate::instance::manager::ManagedInstance::instance_id(instance.as_ref())
        );
    }

    #[tokio::test]
    async fn instance_start_ignores_configured_peer_id() {
        let mut config = test_config("fresh-peer-id");
        let instance_id = uuid::Uuid::from_bytes([7; 16]);
        config.parsed_mut().instance_id = instance_id;

        let instance = build_instance(config).unwrap();
        let generated_peer_id = instance.peer_id();

        assert_eq!(instance.instance_id(), instance_id);
        assert_ne!(generated_peer_id, 0);
        assert_eq!(instance.peer_manager.my_peer_id(), generated_peer_id);
    }

    #[cfg(all(feature = "proxy-packet", feature = "management"))]
    #[tokio::test]
    async fn process_management_rpc_resolves_and_calls_core_instance_directly() {
        use crate::{
            config::toml::TomlConfig,
            instance::manager::{InstanceFactory, InstanceManager},
            management::InstanceManagementRpc,
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
        use easytier_proto::{
            api::config::{ConfigRpc, GetConfigRequest, InstanceConfigPatch, PatchConfigRequest},
            api::instance::{
                PeerManageRpc, ShowNodeInfoRequest,
                instance_identifier::{InstanceSelector, Selector},
            },
            api::manage::{ManagedCredentialConfig, ManagedCredentialSet},
            rpc_types::controller::BaseController,
        };

        struct ManagementTestFactory;

        impl InstanceFactory for ManagementTestFactory {
            type Instance = CoreInstance<TestHost>;
            type CreateContext = ();
            type Error = anyhow::Error;

            fn create(
                &self,
                config: TomlConfig,
                (): Self::CreateContext,
            ) -> Result<Arc<Self::Instance>, Self::Error> {
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                let mut adapters = adapters(None, Arc::new(packet_sink));
                adapters.config.force_exit_node = true;
                adapters.config.public_ipv6_provider_supported = true;
                adapters.config.easytier_version = "host-version".to_owned();
                CoreInstance::from_toml(config, adapters)
            }
        }

        let manager = Arc::new(InstanceManager::new(ManagementTestFactory, None));
        let config = TomlConfig::new_from_str(
            r#"
instance_name = "managed-by-name"
hostname = "core-owned-config"

[network_identity]
network_name = "managed-network"
network_secret = "network-secret"
"#,
        )
        .unwrap();
        let instance = manager.create(config, ()).unwrap();
        instance.start().await.unwrap();
        let rpc = InstanceManagementRpc::<ManagementTestFactory>::new(manager);

        let response = rpc
            .show_node_info(
                BaseController::default(),
                ShowNodeInfoRequest {
                    instance: Some(easytier_proto::api::instance::InstanceIdentifier {
                        selector: Some(Selector::InstanceSelector(InstanceSelector {
                            name: Some("managed-by-name".to_owned()),
                        })),
                    }),
                },
            )
            .await
            .unwrap();

        let node = response.node_info.unwrap();
        assert_eq!(node.hostname, "core-owned-config");
        assert!(node.config.contains("instance_name = \"managed-by-name\""));

        let selector = || easytier_proto::api::instance::InstanceIdentifier {
            selector: Some(Selector::InstanceSelector(InstanceSelector {
                name: Some("managed-by-name".to_owned()),
            })),
        };
        rpc.patch_config(
            BaseController::default(),
            PatchConfigRequest {
                patch: Some(InstanceConfigPatch {
                    hostname: Some("patched-in-core".to_owned()),
                    ..Default::default()
                }),
                instance: Some(selector()),
            },
        )
        .await
        .unwrap();
        let response = rpc
            .get_config(
                BaseController::default(),
                GetConfigRequest {
                    instance: Some(selector()),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            response.config.unwrap().hostname.as_deref(),
            Some("patched-in-core")
        );

        let secret = BASE64_STANDARD.encode([9u8; 32]);
        rpc.patch_config(
            BaseController::default(),
            PatchConfigRequest {
                patch: Some(InstanceConfigPatch {
                    managed_credentials: Some(ManagedCredentialSet {
                        entries: vec![ManagedCredentialConfig {
                            credential_id: "pathless".to_owned(),
                            credential_secret: secret.clone(),
                            expiry_unix: i64::MAX,
                            ..Default::default()
                        }],
                    }),
                    ..Default::default()
                }),
                instance: Some(selector()),
            },
        )
        .await
        .unwrap();
        let response = rpc
            .get_config(
                BaseController::default(),
                GetConfigRequest {
                    instance: Some(selector()),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            response.config.unwrap().managed_credentials,
            vec![ManagedCredentialConfig {
                credential_id: "pathless".to_owned(),
                credential_secret: secret,
                expiry_unix: i64::MAX,
                reusable: Some(true),
                ..Default::default()
            }]
        );
        assert!(instance.host_config.force_exit_node);
        assert!(instance.host_config.public_ipv6_provider_supported);
        assert_eq!(instance.host_config.easytier_version, "host-version");
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn config_patch_rejects_instance_before_host_startup_is_complete() {
        let instance = build_instance(test_config("not-ready-for-patch")).unwrap();

        let error = crate::management::apply_config_patch(
            &instance,
            easytier_proto::api::config::InstanceConfigPatch {
                hostname: Some("too-early".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("instance is not ready"));
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn managed_credential_patch_is_durable_atomic_and_does_not_restart() {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
        use easytier_proto::api::{
            config::InstanceConfigPatch,
            manage::{ManagedCredentialConfig, ManagedCredentialSet},
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let config = TomlConfig::new_from_str(
            r#"
[network_identity]
network_name = "managed-network"
network_secret = "network-secret"

[source]
source = "web"
"#,
        )
        .unwrap();
        let instance =
            CoreInstance::from_toml(config, adapters(None, Arc::new(packet_sink))).unwrap();
        instance.start().await.unwrap();
        let peer_id = instance.peer_id();
        let secret = BASE64_STANDARD.encode([7u8; 32]);
        let patch = InstanceConfigPatch {
            managed_credentials: Some(ManagedCredentialSet {
                entries: vec![ManagedCredentialConfig {
                    credential_id: "managed".to_owned(),
                    credential_secret: secret.clone(),
                    groups: vec!["ops".to_owned()],
                    allow_relay: false,
                    allowed_proxy_cidrs: Vec::new(),
                    expiry_unix: 2_000_000_000,
                    reusable: Some(true),
                }],
            }),
            ..Default::default()
        };
        let persistence = RecordingConfigPatchPersistence::new(true);

        let error =
            crate::management::apply_config_patch(&instance, patch.clone(), Some(&persistence))
                .await
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected config persistence failure")
        );
        assert!(
            instance
                .config_store()
                .snapshot()
                .parsed()
                .managed_credentials
                .is_empty()
        );
        let private_bytes: [u8; 32] = BASE64_STANDARD.decode(&secret).unwrap().try_into().unwrap();
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_bytes));
        assert!(
            !instance
                .credential_manager()
                .is_pubkey_trusted(public_key.as_bytes())
        );

        persistence.fail.store(false, Ordering::Relaxed);
        crate::management::apply_config_patch(&instance, patch, Some(&persistence))
            .await
            .unwrap();

        assert_eq!(instance.peer_id(), peer_id);
        assert_eq!(instance.state(), CoreInstanceState::Running);
        assert!(
            instance
                .credential_manager()
                .is_pubkey_trusted(public_key.as_bytes())
        );
        assert_eq!(
            instance
                .config_store()
                .snapshot()
                .parsed()
                .managed_credentials
                .len(),
            1
        );
        let persisted = persistence.writes.lock().unwrap();
        assert_eq!(persisted.len(), 1);
        assert!(persisted[0].contains(&secret));
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn ordinary_config_patch_is_durable_before_commit() {
        use easytier_proto::api::config::InstanceConfigPatch;

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let config = TomlConfig::new_from_str(
            r#"
instance_name = "durable-ordinary-patch"
hostname = "before"

[network_identity]
network_name = "durable-network"
network_secret = "network-secret"

[source]
source = "web"
"#,
        )
        .unwrap();
        let instance =
            CoreInstance::from_toml(config, adapters(None, Arc::new(packet_sink))).unwrap();
        instance.start().await.unwrap();
        let patch = InstanceConfigPatch {
            hostname: Some("after".to_owned()),
            ..Default::default()
        };
        let persistence = RecordingConfigPatchPersistence::new(true);

        let error =
            crate::management::apply_config_patch(&instance, patch.clone(), Some(&persistence))
                .await
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected config persistence failure")
        );
        assert_eq!(
            instance.config_store().snapshot().parsed().hostname,
            "before"
        );

        persistence.fail.store(false, Ordering::Relaxed);
        crate::management::apply_config_patch(&instance, patch, Some(&persistence))
            .await
            .unwrap();

        assert_eq!(
            instance.config_store().snapshot().parsed().hostname,
            "after"
        );
        {
            let persisted = persistence.writes.lock().unwrap();
            assert_eq!(persisted.len(), 1);
            assert!(persisted[0].contains("hostname = \"after\""));
        }
        instance.stop().await;
    }

    #[cfg(all(feature = "management", feature = "vpn-portal"))]
    #[tokio::test]
    async fn portal_client_patch_restores_durable_state_after_failures() {
        use easytier_proto::api::{
            config::{ConfigPatchAction, InstanceConfigPatch, VpnPortalClientPatch},
            manage::VpnPortalClientConfig,
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut host_adapters = adapters(None, Arc::new(packet_sink));
        host_adapters.vpn_portal = Some(Arc::new(RejectingPortalHost));
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "durable-portal-patch"
ipv4 = "10.82.0.1/24"

[network_identity]
network_name = "durable-portal-network"
network_secret = "network-secret"

[vpn_portal_config]
wireguard_listen = "0.0.0.0:51820"

[[vpn_portal_config.clients]]
name = "alice"
virtual_ip = "10.82.0.2/24"

[source]
source = "web"
"#,
            )
            .unwrap(),
            host_adapters,
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);
        let persistence = RecordingConfigPatchPersistence::new(true);

        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                vpn_portal_clients: vec![
                    VpnPortalClientPatch {
                        action: ConfigPatchAction::Remove as i32,
                        client: Some(VpnPortalClientConfig {
                            name: "alice".to_owned(),
                            ..Default::default()
                        }),
                    },
                    VpnPortalClientPatch {
                        action: ConfigPatchAction::Add as i32,
                        client: Some(VpnPortalClientConfig {
                            name: "bob".to_owned(),
                            virtual_ip: "10.82.0.3/24".to_owned(),
                            ..Default::default()
                        }),
                    },
                ],
                ..Default::default()
            },
            Some(&persistence),
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected config persistence failure")
        );
        let clients = instance
            .config_store()
            .snapshot()
            .parsed()
            .vpn_portal_config
            .as_ref()
            .unwrap()
            .clients
            .clone();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].name, "alice");
        assert!(persistence.writes.lock().unwrap().is_empty());

        persistence.fail.store(false, Ordering::Relaxed);
        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                vpn_portal_clients: vec![
                    VpnPortalClientPatch {
                        action: ConfigPatchAction::Remove as i32,
                        client: Some(VpnPortalClientConfig {
                            name: "alice".to_owned(),
                            ..Default::default()
                        }),
                    },
                    VpnPortalClientPatch {
                        action: ConfigPatchAction::Add as i32,
                        client: Some(VpnPortalClientConfig {
                            name: "bob".to_owned(),
                            virtual_ip: "10.82.0.3/24".to_owned(),
                            ..Default::default()
                        }),
                    },
                ],
                ..Default::default()
            },
            Some(&persistence),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("injected portal update failure"));

        crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                hostname: Some("after-rollback".to_owned()),
                ..Default::default()
            },
            Some(&persistence),
        )
        .await
        .unwrap();

        {
            let persisted = persistence.writes.lock().unwrap();
            assert_eq!(persisted.len(), 3);
            assert!(persisted[0].contains("name = \"bob\""));
            assert!(persisted[1].contains("name = \"alice\""));
            assert!(persisted[2].contains("name = \"alice\""));
            assert!(!persisted[2].contains("name = \"bob\""));
        }
        instance.peer_manager.clear_resources().await;
    }

    #[cfg(all(feature = "management", feature = "vpn-portal"))]
    #[tokio::test]
    async fn portal_client_patch_rollback_persistence_failure_preserves_original_config_in_store() {
        use easytier_proto::api::{
            config::{ConfigPatchAction, InstanceConfigPatch, VpnPortalClientPatch},
            manage::VpnPortalClientConfig,
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut host_adapters = adapters(None, Arc::new(packet_sink));
        host_adapters.vpn_portal = Some(Arc::new(RejectingPortalHost));
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "durable-portal-rollback-fail"
ipv4 = "10.82.0.1/24"

[network_identity]
network_name = "durable-portal-network"
network_secret = "network-secret"

[vpn_portal_config]
wireguard_listen = "0.0.0.0:51820"

[[vpn_portal_config.clients]]
name = "alice"
virtual_ip = "10.82.0.2/24"

[source]
source = "web"
"#,
            )
            .unwrap(),
            host_adapters,
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        // Allow 1 write (the patch candidate with "bob"), then fail the 2nd write (the rollback to "alice")
        let persistence = RecordingConfigPatchPersistence::fail_after(1);

        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                vpn_portal_clients: vec![
                    VpnPortalClientPatch {
                        action: ConfigPatchAction::Remove as i32,
                        client: Some(VpnPortalClientConfig {
                            name: "alice".to_owned(),
                            ..Default::default()
                        }),
                    },
                    VpnPortalClientPatch {
                        action: ConfigPatchAction::Add as i32,
                        client: Some(VpnPortalClientConfig {
                            name: "bob".to_owned(),
                            virtual_ip: "10.82.0.3/24".to_owned(),
                            ..Default::default()
                        }),
                    },
                ],
                ..Default::default()
            },
            Some(&persistence),
        )
        .await
        .unwrap_err();

        // Error reports both host rejection and rollback failure
        let err_msg = format!("{error:#}");
        assert!(err_msg.contains("injected portal update failure"));
        assert!(err_msg.contains("failed to restore durable configuration"));

        // Crucial invariant: Store was NOT updated with rejected "bob", it still has "alice"
        let snapshot = instance.config_store().snapshot();
        let clients = snapshot
            .parsed()
            .vpn_portal_config
            .as_ref()
            .unwrap()
            .clients
            .clone();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].name, "alice");

        instance.peer_manager.clear_resources().await;
    }

    #[cfg(all(feature = "management", not(feature = "proxy-smoltcp-stack")))]
    #[tokio::test]
    async fn unavailable_gateway_patch_does_not_commit_shared_toml() {
        use easytier_proto::{
            api::config::{ConfigPatchAction, InstanceConfigPatch, PortForwardPatch},
            common::{PortForwardConfigPb, SocketType},
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let instance = CoreInstance::from_toml(
            crate::config::toml::TomlConfig::new_from_str(
                "instance_name = \"rejected-gateway-patch\"",
            )
            .unwrap(),
            adapters(None, Arc::new(packet_sink)),
        )
        .unwrap();
        instance.start().await.unwrap();

        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                port_forwards: vec![PortForwardPatch {
                    action: ConfigPatchAction::Add as i32,
                    cfg: Some(PortForwardConfigPb {
                        bind_addr: Some(
                            "127.0.0.1:18080"
                                .parse::<std::net::SocketAddr>()
                                .unwrap()
                                .into(),
                        ),
                        dst_addr: Some(
                            "10.144.144.2:8080"
                                .parse::<std::net::SocketAddr>()
                                .unwrap()
                                .into(),
                        ),
                        socket_type: SocketType::Tcp as i32,
                    }),
                }],
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("does not include the smoltcp gateway"),
            "unexpected patch error: {error:#}"
        );
        assert!(
            instance
                .config_store()
                .snapshot()
                .parsed()
                .port_forward
                .is_empty()
        );
        assert!(instance.runtime_config.snapshot().port_forward.is_empty());
        instance.stop().await;
    }
    #[cfg(all(feature = "management", feature = "vpn-portal"))]
    #[tokio::test]
    async fn rejected_portal_address_patch_does_not_commit_shared_toml() {
        use easytier_proto::api::config::InstanceConfigPatch;

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let instance = CoreInstance::from_toml(
            crate::config::toml::TomlConfig::new_from_str(
                r#"
instance_name = "rejected-portal-address-patch"
ipv4 = "10.82.0.1/24"

[network_identity]
network_name = "rejected-portal-address-patch"
network_secret = "portal-network-secret"

[vpn_portal_config]
wireguard_listen = "0.0.0.0:51820"

[[vpn_portal_config.clients]]
name = "alice"
virtual_ip = "10.82.0.2/24"
"#,
            )
            .unwrap(),
            adapters(None, Arc::new(packet_sink)),
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                ipv4: Some("10.82.0.2/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(
            error.to_string().contains("unusable virtual IP"),
            "unexpected config patch error: {error:#}"
        );
        assert_eq!(
            instance.config_store().snapshot().parsed().ipv4.unwrap(),
            "10.82.0.1/24".parse().unwrap()
        );
        assert_eq!(
            instance
                .runtime_config
                .snapshot()
                .ipv4
                .as_ref()
                .unwrap()
                .address(),
            "10.82.0.1".parse::<IpAddr>().unwrap()
        );
        instance.peer_manager.clear_resources().await;
    }

    #[cfg(feature = "web-client")]
    #[tokio::test]
    async fn ignored_gateway_patch_remains_in_toml_config() {
        use easytier_proto::{
            api::config::{ConfigPatchAction, InstanceConfigPatch, PortForwardPatch, UrlPatch},
            common::{PortForwardConfigPb, SocketType},
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let toml_config = crate::config::toml::TomlConfig::new_from_str(
            "instance_name = \"ignored-gateway-patch\"",
        )
        .unwrap();
        let mut host_adapters = adapters(None, Arc::new(packet_sink));
        host_adapters.config.ignore_unsupported_config = true;
        host_adapters.config.gateway_enabled = false;
        host_adapters.config.endpoint_protocols = vec!["tcp".to_owned(), "udp".to_owned()];
        let instance = CoreInstance::from_toml(toml_config, host_adapters).unwrap();
        instance.start().await.unwrap();

        crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                port_forwards: vec![PortForwardPatch {
                    action: ConfigPatchAction::Add as i32,
                    cfg: Some(PortForwardConfigPb {
                        bind_addr: Some(
                            "127.0.0.1:18080"
                                .parse::<std::net::SocketAddr>()
                                .unwrap()
                                .into(),
                        ),
                        dst_addr: Some(
                            "10.144.144.2:8080"
                                .parse::<std::net::SocketAddr>()
                                .unwrap()
                                .into(),
                        ),
                        socket_type: SocketType::Tcp as i32,
                    }),
                }],
                connectors: vec![UrlPatch {
                    action: ConfigPatchAction::Add as i32,
                    url: Some("quic://127.0.0.1:11010".parse::<url::Url>().unwrap().into()),
                }],
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            instance
                .config_store()
                .snapshot()
                .raw()
                .port_forward
                .as_ref()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            crate::config::api_input::network_config_from_raw(
                instance.config_store().snapshot().raw()
            )
            .port_forwards
            .len(),
            1
        );
        assert!(instance.runtime_config.snapshot().port_forward.is_empty());
        assert!(instance.list_connectors().is_empty());
        instance.stop().await;
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn patch_only_hostname_preserves_unset_raw_fields() {
        use easytier_proto::api::config::InstanceConfigPatch;

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "test-raw-intent"
hostname = "before"
"#,
            )
            .unwrap(),
            adapters(None, Arc::new(packet_sink)),
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        let before_raw = instance.config_store().snapshot().raw().clone();
        assert_eq!(before_raw.hostname.as_deref(), Some("before"));
        assert!(before_raw.tcp_whitelist.is_none());
        assert!(before_raw.udp_whitelist.is_none());
        assert!(before_raw.routes.is_none());
        assert!(before_raw.mapped_listeners.is_none());
        assert!(before_raw.port_forward.is_none());
        assert!(before_raw.proxy_network.is_none());
        assert!(before_raw.exit_nodes.is_none());

        crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                hostname: Some("after".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

        let after_raw = instance.config_store().snapshot().raw().clone();
        assert_eq!(after_raw.hostname.as_deref(), Some("after"));
        // Crucial invariant: other unset fields remain unset!
        assert!(after_raw.tcp_whitelist.is_none());
        assert!(after_raw.udp_whitelist.is_none());
        assert!(after_raw.routes.is_none());
        assert!(after_raw.mapped_listeners.is_none());
        assert!(after_raw.port_forward.is_none());
        assert!(after_raw.proxy_network.is_none());
        assert!(after_raw.exit_nodes.is_none());
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn patch_flags_explicit_false_and_zero_preserves_unprovided() {
        use easytier_proto::api::config::InstanceConfigPatch;

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "test-flags-patch"
[flags]
enable_encryption = true
latency_first = true
"#,
            )
            .unwrap(),
            adapters(None, Arc::new(packet_sink)),
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        let before_raw = instance.config_store().snapshot().raw().clone();
        assert_eq!(before_raw.flags.enable_encryption, Some(true));
        assert_eq!(before_raw.flags.latency_first, Some(true));
        assert_eq!(before_raw.flags.disable_relay_data, None);
        assert_eq!(before_raw.flags.prefer_peer_relay, None);

        // Explicitly set disable_relay_data to false, leaving prefer_peer_relay unset
        crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                disable_relay_data: Some(false),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

        let after_raw = instance.config_store().snapshot().raw().clone();
        assert_eq!(after_raw.flags.enable_encryption, Some(true));
        assert_eq!(after_raw.flags.latency_first, Some(true));
        assert_eq!(after_raw.flags.disable_relay_data, Some(false));
        assert_eq!(after_raw.flags.prefer_peer_relay, None);
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn patch_clear_collections_follows_each_field_convention() {
        use easytier_proto::api::config::{
            ConfigPatchAction, ExitNodePatch, InstanceConfigPatch, PortForwardPatch,
            ProxyNetworkPatch, RoutePatch, UrlPatch,
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut host_adapters = adapters(None, Arc::new(packet_sink));
        host_adapters.config.ignore_unsupported_config = true;
        host_adapters.config.gateway_enabled = false;
        host_adapters.config.proxy_enabled = false;
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "test-clear-collections"
ipv4 = "10.0.0.1/24"
exit_nodes = ["10.0.0.2"]
routes = ["10.10.0.0/16"]
mapped_listeners = ["tcp://1.2.3.4:11010"]

[flags]
proxy_forward_by_system = true

[[port_forward]]
bind_addr = "0.0.0.0:11011"
dst_addr = "10.0.0.3:11011"
proto = "tcp"

[[proxy_network]]
cidr = "10.20.0.0/24"
"#,
            )
            .unwrap(),
            host_adapters,
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        let snap = instance.config_store().snapshot();
        assert!(snap.raw().routes.is_some());
        assert!(snap.raw().mapped_listeners.is_some());
        assert!(snap.raw().port_forward.is_some());
        assert!(snap.raw().exit_nodes.is_some());
        assert!(snap.raw().proxy_network.is_some());

        crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                routes: vec![RoutePatch {
                    action: ConfigPatchAction::Clear as i32,
                    cidr: None,
                }],
                mapped_listeners: vec![UrlPatch {
                    action: ConfigPatchAction::Clear as i32,
                    url: None,
                }],
                port_forwards: vec![PortForwardPatch {
                    action: ConfigPatchAction::Clear as i32,
                    cfg: None,
                }],
                exit_nodes: vec![ExitNodePatch {
                    action: ConfigPatchAction::Clear as i32,
                    node: None,
                }],
                proxy_networks: vec![ProxyNetworkPatch {
                    action: ConfigPatchAction::Clear as i32,
                    cidr: None,
                    mapped_cidr: None,
                }],
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

        let after = instance.config_store().snapshot();
        // routes and mapped_listeners become None when empty
        assert_eq!(after.raw().routes, None);
        assert_eq!(after.raw().mapped_listeners, None);
        // port_forward and exit_nodes become Some([])
        assert_eq!(after.raw().port_forward, Some(vec![]));
        assert_eq!(after.raw().exit_nodes, Some(vec![]));
        // proxy_network becomes None on clear
        assert_eq!(after.raw().proxy_network, None);
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn patch_proxy_networks_later_failure_commits_valid_prefix() {
        use easytier_proto::api::config::{
            ConfigPatchAction, InstanceConfigPatch, ProxyNetworkPatch,
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut host_adapters = adapters(None, Arc::new(packet_sink));
        host_adapters.config.ignore_unsupported_config = true;
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "test-proxy-prefix"
ipv4 = "10.0.0.1/24"

[flags]
proxy_forward_by_system = true
"#,
            )
            .unwrap(),
            host_adapters,
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                proxy_networks: vec![
                    ProxyNetworkPatch {
                        action: ConfigPatchAction::Add as i32,
                        cidr: Some("10.1.0.0/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                        mapped_cidr: None,
                    },
                    ProxyNetworkPatch {
                        action: ConfigPatchAction::Add as i32,
                        cidr: Some("10.2.0.0/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                        // Invalid: mismatched mask length /16 vs /24
                        mapped_cidr: Some("10.3.0.0/16".parse::<cidr::Ipv4Inet>().unwrap().into()),
                    },
                ],
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Mapped CIDR must have the same network length")
        );

        // Valid prefix (10.1.0.0/24) was committed!
        let snapshot = instance.config_store().snapshot();
        let proxies = snapshot.raw().proxy_network.as_ref().unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(
            proxies[0].cidr,
            "10.1.0.0/24".parse::<cidr::Ipv4Cidr>().unwrap()
        );
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn patch_acl_validation_failure_does_not_commit_partial_acl() {
        use easytier_proto::api::config::{
            AclPatch, ConfigPatchAction, InstanceConfigPatch, StringPatch,
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "test-acl-validation"
ipv4 = "10.0.0.1/24"
"#,
            )
            .unwrap(),
            adapters(None, Arc::new(packet_sink)),
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                acl: Some(AclPatch {
                    acl: None,
                    tcp_whitelist: vec![StringPatch {
                        action: ConfigPatchAction::Add as i32,
                        value: "invalid-syntax-rule-!!!".to_owned(),
                    }],
                    udp_whitelist: vec![],
                }),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(
            error.to_string().contains("Invalid port range format"),
            "unexpected error: {error:#}"
        );

        // Raw ACL fields were not modified with invalid data
        let snapshot = instance.config_store().snapshot();
        assert!(snapshot.raw().tcp_whitelist.is_none());
        assert!(snapshot.raw().udp_whitelist.is_none());
        assert!(snapshot.raw().acl.is_none());
    }

    #[cfg(all(feature = "management", feature = "vpn-portal"))]
    #[tokio::test]
    async fn patch_portal_group_failure_does_not_commit_partial_clients() {
        use easytier_proto::api::{
            config::{ConfigPatchAction, InstanceConfigPatch, VpnPortalClientPatch},
            manage::VpnPortalClientConfig,
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut host_adapters = adapters(None, Arc::new(packet_sink));
        host_adapters.vpn_portal = Some(Arc::new(SucceedingPortalHost));
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "test-portal-group"
ipv4 = "10.0.0.1/24"
[network_identity]
network_name = "test-portal-net"
network_secret = "test-portal-secret"
[vpn_portal_config]
wireguard_listen = "0.0.0.0:51820"
[[vpn_portal_config.clients]]
name = "alice"
virtual_ip = "10.0.0.2/24"
"#,
            )
            .unwrap(),
            host_adapters,
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        // Group patch: 1 valid add, 1 invalid remove (ghost does not exist)
        let error = crate::management::apply_config_patch(
            &instance,
            InstanceConfigPatch {
                vpn_portal_clients: vec![
                    VpnPortalClientPatch {
                        action: ConfigPatchAction::Add as i32,
                        client: Some(VpnPortalClientConfig {
                            name: "bob".to_owned(),
                            virtual_ip: "10.0.0.3/24".to_owned(),
                            ..Default::default()
                        }),
                    },
                    VpnPortalClientPatch {
                        action: ConfigPatchAction::Remove as i32,
                        client: Some(VpnPortalClientConfig {
                            name: "ghost".to_owned(),
                            ..Default::default()
                        }),
                    },
                ],
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("not found"));

        // Neither bob nor ghost removal was committed
        let snapshot = instance.config_store().snapshot();
        let clients = snapshot
            .parsed()
            .vpn_portal_config
            .as_ref()
            .unwrap()
            .clients
            .clone();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].name, "alice");
    }

    #[tokio::test]
    async fn dropping_core_instance_requests_host_shutdown() {
        struct DropAwareRuntimeHost(Arc<AtomicBool>);

        #[async_trait]
        impl InstanceRuntimeHost for DropAwareRuntimeHost {
            async fn prepare(
                &self,
                _packet_plane: Arc<CorePacketPlane>,
            ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
                Ok(None)
            }

            async fn shutdown(&self) {}

            fn request_shutdown(&self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(None, Arc::new(packet_sink));
        adapters.instance_runtime = Arc::new(DropAwareRuntimeHost(shutdown_requested.clone()));
        let instance = CoreInstance::new(test_config("drop-cleanup"), adapters).unwrap();

        drop(instance);

        assert!(shutdown_requested.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn host_prepare_failure_runs_unified_cleanup() {
        #[derive(Default)]
        struct FailingRuntimeHost {
            shutdown_calls: AtomicUsize,
        }

        #[async_trait]
        impl InstanceRuntimeHost for FailingRuntimeHost {
            async fn prepare(
                &self,
                _packet_plane: Arc<CorePacketPlane>,
            ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
                anyhow::bail!("host prepare failed")
            }

            async fn shutdown(&self) {
                self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
            }
        }

        let runtime_host = Arc::new(FailingRuntimeHost::default());
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(None, Arc::new(packet_sink));
        adapters.instance_runtime = runtime_host.clone();
        let instance = CoreInstance::new(test_config("host-prepare-failure"), adapters).unwrap();

        let error = instance.start().await.unwrap_err();

        assert!(error.to_string().contains("host prepare failed"));
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert!(!instance.is_ready());
        assert_eq!(runtime_host.shutdown_calls.load(Ordering::Relaxed), 1);
        assert!(
            instance
                .latest_error()
                .unwrap()
                .contains("host prepare failed")
        );
    }

    #[tokio::test]
    async fn manager_reports_only_stopped_instances_with_errors() {
        use crate::instance::manager::{InstanceFactory, InstanceManager};

        struct StateTestFactory;

        impl InstanceFactory for StateTestFactory {
            type Instance = CoreInstance<TestHost>;
            type CreateContext = ();
            type Error = anyhow::Error;

            fn create(
                &self,
                config: TomlConfig,
                (): Self::CreateContext,
            ) -> Result<Arc<Self::Instance>, Self::Error> {
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                CoreInstance::from_toml(config, adapters(None, Arc::new(packet_sink)))
            }
        }

        fn create_instance(
            manager: &InstanceManager<StateTestFactory>,
            name: &str,
        ) -> Arc<CoreInstance<TestHost>> {
            let config = TomlConfig::new_from_str(&format!("instance_name = \"{name}\"")).unwrap();
            manager.create(config, ()).unwrap()
        }

        let manager = InstanceManager::new(StateTestFactory, None);
        let running = create_instance(&manager, "running");
        running
            .latest_error
            .write()
            .replace("old startup error".to_owned());
        running.set_state(CoreInstanceState::Running);

        let starting = create_instance(&manager, "starting");
        starting
            .latest_error
            .write()
            .replace("old startup error".to_owned());
        starting.set_state(CoreInstanceState::Starting);

        let stopped_without_error = create_instance(&manager, "stopped-without-error");
        stopped_without_error.set_state(CoreInstanceState::Stopped);

        let stopped_with_blank_error = create_instance(&manager, "stopped-with-blank-error");
        stopped_with_blank_error
            .latest_error
            .write()
            .replace("  \n".to_owned());
        stopped_with_blank_error.set_state(CoreInstanceState::Stopped);

        let failed = create_instance(&manager, "failed");
        failed
            .latest_error
            .write()
            .replace("startup failed".to_owned());
        failed.set_state(CoreInstanceState::Stopped);
        let failed_id = failed.instance_id();

        assert_eq!(manager.failed_instance_ids(), vec![failed_id]);

        manager.delete_network_instances([failed_id]).await.unwrap();
        assert!(manager.failed_instance_ids().is_empty());
    }

    #[tokio::test]
    async fn aborting_host_prepare_runs_unified_cleanup() {
        #[derive(Default)]
        struct BlockingPrepareRuntimeHost {
            prepare_started: Notify,
            prepare_release: Notify,
            shutdown_calls: AtomicUsize,
        }

        #[async_trait]
        impl InstanceRuntimeHost for BlockingPrepareRuntimeHost {
            async fn prepare(
                &self,
                _packet_plane: Arc<CorePacketPlane>,
            ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
                self.prepare_started.notify_one();
                self.prepare_release.notified().await;
                Ok(None)
            }

            async fn shutdown(&self) {
                self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
            }
        }

        let runtime_host = Arc::new(BlockingPrepareRuntimeHost::default());
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(None, Arc::new(packet_sink));
        adapters.instance_runtime = runtime_host.clone();
        let instance = CoreInstance::new(test_config("aborted-host-prepare"), adapters).unwrap();
        let start = tokio::spawn({
            let instance = instance.clone();
            async move { instance.start().await }
        });
        runtime_host.prepare_started.notified().await;

        start.abort();
        assert!(start.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            while instance.state() != CoreInstanceState::Stopped {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted Host prepare should stop the instance");

        assert!(!instance.is_ready());
        assert_eq!(runtime_host.shutdown_calls.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn cancelled_delete_finishes_stop_and_keeps_wait_blocked() {
        use std::{path::Path, path::PathBuf};

        use crate::{
            config::toml::TomlConfig,
            instance::manager::InstanceFactory,
            management::{
                ConfigFileControl, ConfigFilePermission, ConfigFileStorage, InstanceManager,
                InstanceMutationHooks, ProcessManagementRpc,
            },
        };
        use easytier_proto::{
            api::manage::{DeleteNetworkInstanceRequest, WebClientService},
            rpc_types::controller::BaseController,
        };

        #[derive(Default)]
        struct BlockingRuntimeHost {
            shutdown_started: Notify,
            shutdown_release: Notify,
        }

        #[async_trait]
        impl InstanceRuntimeHost for BlockingRuntimeHost {
            async fn prepare(
                &self,
                _packet_plane: Arc<CorePacketPlane>,
            ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
                Ok(None)
            }

            async fn shutdown(&self) {
                self.shutdown_started.notify_one();
                self.shutdown_release.notified().await;
            }
        }

        struct BlockingFactory {
            runtime_host: Arc<BlockingRuntimeHost>,
            process_runtime: Arc<CoreProcessRuntime>,
        }

        impl InstanceFactory for BlockingFactory {
            type Instance = CoreInstance<TestHost>;
            type CreateContext = ();
            type Error = anyhow::Error;

            fn create(
                &self,
                config: TomlConfig,
                (): Self::CreateContext,
            ) -> Result<Arc<Self::Instance>, Self::Error> {
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                let mut adapters = adapters_with_process_runtime(
                    None,
                    Arc::new(packet_sink),
                    self.process_runtime.clone(),
                );
                adapters.instance_runtime = self.runtime_host.clone();
                CoreInstance::from_toml(config, adapters)
            }
        }

        impl crate::management::ProcessRuntimeProvider for BlockingFactory {
            fn process_runtime(&self) -> Arc<CoreProcessRuntime> {
                self.process_runtime.clone()
            }
        }

        #[derive(Default)]
        struct RecordingStorage(AtomicBool);

        #[async_trait]
        impl ConfigFileStorage for RecordingStorage {
            async fn inspect(&self, path: &Path) -> ConfigFileControl {
                ConfigFileControl::new(Some(path.to_owned()), ConfigFilePermission::default())
            }

            async fn read(&self, _path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
                Ok(None)
            }

            async fn write(&self, _path: &Path, _contents: &[u8]) -> anyhow::Result<()> {
                Ok(())
            }

            async fn remove(&self, _path: &Path) -> anyhow::Result<()> {
                self.0.store(true, Ordering::Release);
                Ok(())
            }
        }

        #[derive(Default)]
        struct RecordingHooks(AtomicBool);

        #[async_trait]
        impl InstanceMutationHooks for RecordingHooks {
            async fn post_remove_network_instances(
                &self,
                _instance_ids: &[uuid::Uuid],
            ) -> Result<(), String> {
                self.0.store(true, Ordering::Release);
                Ok(())
            }
        }

        let runtime_host = Arc::new(BlockingRuntimeHost::default());
        let process_runtime = CoreProcessRuntime::new();
        let instances = Arc::new(InstanceManager::new(
            BlockingFactory {
                runtime_host: runtime_host.clone(),
                process_runtime,
            },
            Some(tokio::runtime::Handle::current()),
        ));
        let config = TomlConfig::default();
        config.set_listeners(Vec::new());
        let instance_id = config.get_id();
        instances
            .run_network_instance(
                config,
                ConfigFileControl::new(
                    Some(PathBuf::from("cancelled-delete.toml")),
                    ConfigFilePermission::default(),
                ),
            )
            .unwrap();
        let storage = Arc::new(RecordingStorage::default());
        let hooks = Arc::new(RecordingHooks::default());
        let rpc = ProcessManagementRpc::<BlockingFactory>::new(
            instances.clone(),
            hooks.clone(),
            storage.clone(),
        );

        let deletion = tokio::spawn(async move {
            rpc.delete_network_instance(
                BaseController::default(),
                DeleteNetworkInstanceRequest {
                    inst_ids: vec![instance_id.into()],
                },
            )
            .await
        });
        runtime_host.shutdown_started.notified().await;
        deletion.abort();
        assert!(deletion.await.unwrap_err().is_cancelled());

        let mut wait = tokio::spawn({
            let instances = instances.clone();
            async move { instances.wait().await }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wait)
                .await
                .is_err()
        );

        runtime_host.shutdown_release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !storage.0.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .unwrap()
            .unwrap();
        assert!(hooks.0.load(Ordering::Acquire));
        assert!(instances.instances().is_empty());
    }

    #[cfg(feature = "web-client")]
    #[tokio::test]
    async fn process_management_rpc_owns_instance_create_list_and_delete() {
        use crate::{
            config::toml::TomlConfig,
            instance::manager::InstanceFactory,
            management::{
                InstanceManager, ProcessManagementRpc, UnsupportedConfigFileStorage,
                register_web_client_rpc,
            },
            rpc::service_registry::ServiceRegistry,
        };
        use easytier_proto::{
            api::manage::{
                DeleteNetworkInstanceRequest, ListNetworkInstanceRequest, NetworkConfig,
                NetworkingMethod, RunNetworkInstanceRequest, WebClientService,
            },
            common::RpcDescriptor,
            rpc_types::controller::BaseController,
        };

        struct ManagementTestFactory(Arc<CoreProcessRuntime>);

        impl InstanceFactory for ManagementTestFactory {
            type Instance = CoreInstance<TestHost>;
            type CreateContext = ();
            type Error = anyhow::Error;

            fn create(
                &self,
                config: TomlConfig,
                (): Self::CreateContext,
            ) -> Result<Arc<Self::Instance>, Self::Error> {
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                CoreInstance::from_toml(
                    config,
                    adapters_with_process_runtime(None, Arc::new(packet_sink), self.0.clone()),
                )
            }
        }

        impl crate::management::ProcessRuntimeProvider for ManagementTestFactory {
            fn process_runtime(&self) -> Arc<CoreProcessRuntime> {
                self.0.clone()
            }
        }

        let instances = Arc::new(InstanceManager::new(
            ManagementTestFactory(CoreProcessRuntime::new()),
            Some(tokio::runtime::Handle::current()),
        ));
        let registry = ServiceRegistry::new();
        register_web_client_rpc(
            instances.clone(),
            &registry,
            Arc::new(()),
            Arc::new(UnsupportedConfigFileStorage),
        );
        assert_eq!(
            registry.get_method_name(&RpcDescriptor {
                domain_name: String::new(),
                service_name: "ConfigRpc".to_owned(),
                proto_name: "ConfigRpc".to_owned(),
                method_index: 2,
            }),
            Some("get_config".to_owned())
        );
        assert_eq!(
            registry.get_method_name(&RpcDescriptor {
                domain_name: String::new(),
                service_name: "WebClientService".to_owned(),
                proto_name: "WebClientService".to_owned(),
                method_index: 1,
            }),
            Some("validate_config".to_owned())
        );
        let rpc = ProcessManagementRpc::<ManagementTestFactory>::new(
            instances.clone(),
            Arc::new(()),
            Arc::new(UnsupportedConfigFileStorage),
        );
        let created = rpc
            .run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    config: Some(NetworkConfig {
                        network_name: Some("managed-process-rpc".to_owned()),
                        networking_method: Some(NetworkingMethod::Standalone.into()),
                        ..Default::default()
                    }),
                    overwrite: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .inst_id
            .unwrap();

        let listed = rpc
            .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
            .await
            .unwrap();
        assert_eq!(listed.inst_ids, vec![created]);

        let deleted = rpc
            .delete_network_instance(
                BaseController::default(),
                DeleteNetworkInstanceRequest {
                    inst_ids: vec![created],
                },
            )
            .await
            .unwrap();
        assert!(deleted.remain_inst_ids.is_empty());
        assert!(instances.instances().is_empty());
    }

    #[cfg(feature = "web-client")]
    #[tokio::test]
    async fn process_management_rpc_collects_only_requested_instances() {
        use std::{collections::VecDeque, sync::Mutex as StdMutex};

        use crate::{
            config::toml::TomlConfig,
            instance::manager::InstanceFactory,
            management::{InstanceManager, ProcessManagementRpc, UnsupportedConfigFileStorage},
        };
        use easytier_proto::{
            api::manage::{CollectNetworkInfoRequest, WebClientService},
            rpc_types::controller::BaseController,
        };

        #[derive(Default)]
        struct RecordingRuntimeHost {
            collection_count: AtomicUsize,
        }

        #[async_trait]
        impl InstanceRuntimeHost for RecordingRuntimeHost {
            async fn prepare(
                &self,
                _packet_plane: Arc<CorePacketPlane>,
            ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
                Ok(None)
            }

            async fn shutdown(&self) {}

            fn management_events(&self) -> Vec<String> {
                self.collection_count.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
        }

        struct RecordingFactory {
            process_runtime: Arc<CoreProcessRuntime>,
            runtime_hosts: StdMutex<VecDeque<Arc<RecordingRuntimeHost>>>,
        }

        impl InstanceFactory for RecordingFactory {
            type Instance = CoreInstance<TestHost>;
            type CreateContext = ();
            type Error = anyhow::Error;

            fn create(
                &self,
                config: TomlConfig,
                (): Self::CreateContext,
            ) -> Result<Arc<Self::Instance>, Self::Error> {
                let runtime_host = self.runtime_hosts.lock().unwrap().pop_front().unwrap();
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                let mut adapters = adapters_with_process_runtime(
                    None,
                    Arc::new(packet_sink),
                    self.process_runtime.clone(),
                );
                adapters.instance_runtime = runtime_host;
                CoreInstance::from_toml(config, adapters)
            }
        }

        let requested_runtime = Arc::new(RecordingRuntimeHost::default());
        let unrequested_runtime = Arc::new(RecordingRuntimeHost::default());
        let instances = Arc::new(InstanceManager::new(
            RecordingFactory {
                process_runtime: CoreProcessRuntime::new(),
                runtime_hosts: StdMutex::new(VecDeque::from([
                    requested_runtime.clone(),
                    unrequested_runtime.clone(),
                ])),
            },
            Some(tokio::runtime::Handle::current()),
        ));
        let requested_id = uuid::Uuid::new_v4();
        let unrequested_id = uuid::Uuid::new_v4();
        for instance_id in [requested_id, unrequested_id] {
            let config = TomlConfig::default();
            config.set_id(instance_id);
            config.set_listeners(Vec::new());
            instances
                .create(config, ())
                .unwrap()
                .set_state(CoreInstanceState::Running);
        }
        let rpc = ProcessManagementRpc::<RecordingFactory>::new(
            instances,
            Arc::new(()),
            Arc::new(UnsupportedConfigFileStorage),
        );

        let response = rpc
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest {
                    inst_ids: vec![
                        requested_id.into(),
                        requested_id.into(),
                        uuid::Uuid::new_v4().into(),
                    ],
                },
            )
            .await
            .unwrap();
        let info = response.info.unwrap().map;
        assert_eq!(info.len(), 1);
        assert!(info.contains_key(&requested_id.to_string()));
        assert_eq!(
            requested_runtime.collection_count.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            unrequested_runtime.collection_count.load(Ordering::Relaxed),
            0
        );

        let response = rpc
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.info.unwrap().map.len(), 2);
        assert_eq!(
            requested_runtime.collection_count.load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            unrequested_runtime.collection_count.load(Ordering::Relaxed),
            1
        );
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn owned_selection_and_cleanup_share_the_canonical_transaction() {
        use crate::{
            config::toml::TomlConfig,
            instance::manager::InstanceFactory,
            management::{
                ConfigFileControl, InstanceManager, InstanceMutationHooks, ProcessManagement,
                UnsupportedConfigFileStorage,
            },
        };

        struct ManagementTestFactory(Arc<CoreProcessRuntime>);

        impl InstanceFactory for ManagementTestFactory {
            type Instance = CoreInstance<TestHost>;
            type CreateContext = ();
            type Error = anyhow::Error;

            fn create(
                &self,
                config: TomlConfig,
                (): Self::CreateContext,
            ) -> Result<Arc<Self::Instance>, Self::Error> {
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                CoreInstance::from_toml(
                    config,
                    adapters_with_process_runtime(None, Arc::new(packet_sink), self.0.clone()),
                )
            }
        }

        impl crate::management::ProcessRuntimeProvider for ManagementTestFactory {
            fn process_runtime(&self) -> Arc<CoreProcessRuntime> {
                self.0.clone()
            }
        }

        #[derive(Default)]
        struct BlockingRemovalHook {
            entered: Notify,
            release: Notify,
            removed: std::sync::Mutex<Vec<Vec<uuid::Uuid>>>,
        }

        #[async_trait]
        impl InstanceMutationHooks for BlockingRemovalHook {
            async fn post_remove_network_instances(
                &self,
                instance_ids: &[uuid::Uuid],
            ) -> Result<(), String> {
                self.removed.lock().unwrap().push(instance_ids.to_vec());
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            }
        }

        let instances = Arc::new(InstanceManager::new(
            ManagementTestFactory(CoreProcessRuntime::new()),
            Some(tokio::runtime::Handle::current()),
        ));
        let config = TomlConfig::default();
        config.set_listeners(Vec::new());
        let instance_id = config.get_id();
        instances
            .run_network_instance(config, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
        let hooks = Arc::new(BlockingRemovalHook::default());
        let management = ProcessManagement::<ManagementTestFactory>::new(
            instances.clone(),
            hooks.clone(),
            Arc::new(UnsupportedConfigFileStorage),
        );

        let deletion_management = management.clone();
        let deletion = tokio::spawn(async move {
            deletion_management
                .delete_owned_network_instances(vec![instance_id, uuid::Uuid::new_v4()])
                .await
        });
        hooks.entered.notified().await;
        assert!(instances.mutation_lock().try_lock().is_err());
        assert_eq!(
            hooks.removed.lock().unwrap().as_slice(),
            &[vec![instance_id]]
        );
        hooks.release.notify_one();

        let result = deletion.await.unwrap().unwrap();
        assert_eq!(result.removed_instance_ids, vec![instance_id]);
        assert_eq!(hooks.removed.lock().unwrap().len(), 1);

        let old_name = format!("old-{instance_id}");
        let new_name = format!("new-{instance_id}");
        let old_config = TomlConfig::default();
        old_config.set_id(instance_id);
        old_config.set_inst_name(old_name.clone());
        old_config.set_listeners(Vec::new());
        instances
            .run_network_instance(old_config, ConfigFileControl::STATIC_CONFIG)
            .unwrap();

        let mutation_guard = instances.mutation_lock().lock_owned().await;
        let deletion = management.delete_owned_network_instances_by_name(vec![old_name]);
        tokio::pin!(deletion);
        assert!(matches!(
            futures::poll!(deletion.as_mut()),
            std::task::Poll::Pending
        ));

        instances
            .delete_network_instances([instance_id])
            .await
            .unwrap();
        let new_config = TomlConfig::default();
        new_config.set_id(instance_id);
        new_config.set_inst_name(new_name.clone());
        new_config.set_listeners(Vec::new());
        instances
            .run_network_instance(new_config, ConfigFileControl::STATIC_CONFIG)
            .unwrap();

        drop(mutation_guard);
        hooks.release.notify_one();
        let result = deletion.await.unwrap();
        assert!(result.removed_instance_ids.is_empty());
        assert_eq!(
            instances
                .instance(instance_id)
                .map(|instance| instance.instance_name().to_owned())
                .as_deref(),
            Some(new_name.as_str())
        );
        assert_eq!(
            hooks.removed.lock().unwrap().as_slice(),
            &[vec![instance_id], Vec::new()]
        );
        instances
            .delete_network_instances([instance_id])
            .await
            .unwrap();

        let selection_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let selection_ran_for_call = selection_ran.clone();
        let mutation_guard = instances.mutation_lock().lock_owned().await;
        let deletion = management.delete_owned_network_instances_selected_by(move || {
            selection_ran_for_call.store(true, std::sync::atomic::Ordering::Release);
            Vec::new()
        });
        tokio::pin!(deletion);
        assert!(matches!(
            futures::poll!(deletion.as_mut()),
            std::task::Poll::Pending
        ));
        assert!(!selection_ran.load(std::sync::atomic::Ordering::Acquire));
        drop(mutation_guard);
        hooks.release.notify_one();
        deletion.await.unwrap();
        assert!(selection_ran.load(std::sync::atomic::Ordering::Acquire));
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn process_management_rpc_rolls_back_instance_and_file_on_hook_failure() {
        use std::{
            collections::HashMap,
            path::{Path, PathBuf},
            sync::Mutex as StdMutex,
        };

        use crate::{
            config::toml::TomlConfig,
            instance::manager::InstanceFactory,
            management::{
                ConfigFileControl, ConfigFilePermission, ConfigFileStorage, InstanceManager,
                InstanceMutationHooks, ProcessManagementRpc,
            },
        };
        use easytier_proto::{
            api::manage::{
                NetworkConfig, NetworkingMethod, RunNetworkInstanceRequest, WebClientService,
            },
            rpc_types::controller::BaseController,
        };

        struct ManagementTestFactory(Arc<CoreProcessRuntime>);

        impl InstanceFactory for ManagementTestFactory {
            type Instance = CoreInstance<TestHost>;
            type CreateContext = ();
            type Error = anyhow::Error;

            fn create(
                &self,
                config: TomlConfig,
                (): Self::CreateContext,
            ) -> Result<Arc<Self::Instance>, Self::Error> {
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                CoreInstance::from_toml(
                    config,
                    adapters_with_process_runtime(None, Arc::new(packet_sink), self.0.clone()),
                )
            }
        }

        impl crate::management::ProcessRuntimeProvider for ManagementTestFactory {
            fn process_runtime(&self) -> Arc<CoreProcessRuntime> {
                self.0.clone()
            }
        }

        #[derive(Default)]
        struct MemoryStorage(StdMutex<HashMap<PathBuf, Vec<u8>>>);

        #[async_trait]
        impl ConfigFileStorage for MemoryStorage {
            async fn inspect(&self, path: &Path) -> ConfigFileControl {
                ConfigFileControl::new(Some(path.to_owned()), ConfigFilePermission::default())
            }

            async fn read(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
                Ok(self.0.lock().unwrap().get(path).cloned())
            }

            async fn write(&self, path: &Path, contents: &[u8]) -> anyhow::Result<()> {
                self.0
                    .lock()
                    .unwrap()
                    .insert(path.to_owned(), contents.to_vec());
                Ok(())
            }

            async fn remove(&self, path: &Path) -> anyhow::Result<()> {
                self.0.lock().unwrap().remove(path);
                Ok(())
            }
        }

        struct RejectPostRun;

        #[async_trait]
        impl InstanceMutationHooks for RejectPostRun {
            fn manages_remote_config_instances(&self) -> bool {
                true
            }

            async fn post_run_network_instance(
                &self,
                _instance_id: &uuid::Uuid,
            ) -> Result<(), String> {
                Err("rejected for rollback test".to_owned())
            }
        }

        let instances = Arc::new(InstanceManager::new(
            ManagementTestFactory(CoreProcessRuntime::new()),
            Some(tokio::runtime::Handle::current()),
        ));
        let storage = Arc::new(MemoryStorage::default());
        let instance_id = uuid::Uuid::new_v4();
        let config_path = PathBuf::from("managed-process-rpc.toml");
        let original_file = b"original configuration".to_vec();
        storage
            .0
            .lock()
            .unwrap()
            .insert(config_path.clone(), original_file.clone());
        let original = TomlConfig::default();
        original.set_id(instance_id);
        original.set_inst_name("original-instance".to_owned());
        original.set_listeners(Vec::new());
        instances
            .run_network_instance(
                original,
                ConfigFileControl::new(Some(config_path.clone()), ConfigFilePermission::default()),
            )
            .unwrap();
        let rpc = ProcessManagementRpc::<ManagementTestFactory>::new(
            instances.clone(),
            Arc::new(RejectPostRun),
            storage.clone(),
        );

        let result = rpc
            .run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: Some(instance_id.into()),
                    config: Some(NetworkConfig {
                        network_name: Some("replacement".to_owned()),
                        networking_method: Some(NetworkingMethod::Standalone.into()),
                        ..Default::default()
                    }),
                    overwrite: true,
                    ..Default::default()
                },
            )
            .await;

        assert!(result.is_err());
        assert_eq!(
            instances
                .instance(instance_id)
                .map(|instance| instance.instance_name().to_owned())
                .as_deref(),
            Some("original-instance")
        );
        assert_eq!(
            storage.0.lock().unwrap().get(&config_path),
            Some(&original_file)
        );
        instances
            .delete_network_instances([instance_id])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn packet_plane_does_not_retain_core_instance() {
        let instance = build_instance(test_config("packet-plane-ownership")).unwrap();
        let weak = Arc::downgrade(&instance);
        let packet_plane = instance.packet_plane();

        drop(instance);

        assert!(weak.upgrade().is_none());
        drop(packet_plane);
    }

    #[derive(Default)]
    struct RecordingProxyService {
        start_calls: AtomicUsize,
        stop_calls: AtomicUsize,
        start_gate: Option<Arc<ProxyStartGate>>,
        #[cfg(feature = "proxy-packet")]
        destination_ingress: StdMutex<
            Option<crate::gateway::proxy::wrapped_transport::WrappedTransportDestinationIngress>,
        >,
    }

    #[derive(Default)]
    struct ProxyStartGate {
        entered: Notify,
        release: Notify,
    }

    impl RecordingProxyService {
        fn blocking() -> (Arc<Self>, Arc<ProxyStartGate>) {
            let gate = Arc::new(ProxyStartGate::default());
            (
                Arc::new(Self {
                    start_gate: Some(gate.clone()),
                    ..Default::default()
                }),
                gate,
            )
        }

        #[cfg(feature = "proxy-packet")]
        fn destination_ingress(
            &self,
        ) -> Option<crate::gateway::proxy::wrapped_transport::WrappedTransportDestinationIngress>
        {
            self.destination_ingress.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WrappedTransportEngine for RecordingProxyService {
        async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            self.start_calls.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "proxy-packet")]
            {
                *self.destination_ingress.lock().unwrap() = options.destination_ingress;
            }
            #[cfg(not(feature = "proxy-packet"))]
            let _ = options;
            if let Some(gate) = &self.start_gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            _role: WrappedTransportRole,
            _from_peer_id: u32,
            _payload: bytes::Bytes,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        #[cfg(feature = "proxy-packet")]
        async fn connect_source(
            &self,
            _request: crate::gateway::proxy::wrapped_transport::WrappedTransportConnect,
        ) -> anyhow::Result<Box<dyn crate::gateway::proxy::traits::TcpProxyStream>> {
            anyhow::bail!("recording engine does not open streams")
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Debug, Default)]
    struct BlockingListenerState {
        start_entered: Notify,
        drop_calls: AtomicUsize,
    }

    #[derive(Debug)]
    struct BlockingSocketListener {
        url: Url,
        state: Arc<BlockingListenerState>,
    }

    #[async_trait]
    impl SocketListener for BlockingSocketListener {
        type Accepted = AcceptedTransport<TestTcpSocket>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            self.state.start_entered.notify_one();
            std::future::pending().await
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            std::future::pending().await
        }

        fn local_url(&self) -> Url {
            self.url.clone()
        }
    }

    impl Drop for BlockingSocketListener {
        fn drop(&mut self) {
            self.state.drop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct BlockingExternalListenerFactory {
        state: Arc<BlockingListenerState>,
    }

    impl ExternalListenerFactory<AcceptedTransport<TestTcpSocket>> for BlockingExternalListenerFactory {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "unix"
        }

        fn create(
            &self,
            request: ExternalListenerRequest,
        ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<TestTcpSocket>>> {
            Box::new(BlockingSocketListener {
                url: request.url,
                state: self.state.clone(),
            })
        }
    }

    #[derive(Debug)]
    struct ReadySocketListener(Url);

    #[async_trait]
    impl SocketListener for ReadySocketListener {
        type Accepted = AcceptedTransport<TestTcpSocket>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            std::future::pending().await
        }

        fn local_url(&self) -> Url {
            self.0.clone()
        }
    }

    struct ReadyExternalListenerFactory;

    impl ExternalListenerFactory<AcceptedTransport<TestTcpSocket>> for ReadyExternalListenerFactory {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "unix"
        }

        fn create(
            &self,
            request: ExternalListenerRequest,
        ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<TestTcpSocket>>> {
            Box::new(ReadySocketListener(request.url))
        }
    }

    #[tokio::test]
    async fn runtime_updates_refresh_avoid_relay_preference() {
        let config = test_config("portable-runtime-update");
        let instance = build_instance(config.clone()).unwrap();

        assert!(
            !instance
                .node_snapshot()
                .await
                .feature_flags
                .avoid_relay_data
        );

        let mut enabled = config.clone();
        enabled.parsed_mut().flags.disable_relay_data = true;
        instance.update_runtime_config(enabled).await.unwrap();
        assert!(
            instance
                .node_snapshot()
                .await
                .feature_flags
                .avoid_relay_data
        );

        let mut disabled = config.clone();
        disabled.parsed_mut().flags.disable_relay_data = false;
        instance.update_runtime_config(disabled).await.unwrap();
        assert!(
            !instance
                .node_snapshot()
                .await
                .feature_flags
                .avoid_relay_data
        );
    }

    #[cfg(all(feature = "test-utils", feature = "dhcp-ipv4"))]
    #[cfg_attr(
        not(target_os = "wasi"),
        tokio::test(flavor = "multi_thread", worker_threads = 2)
    )]
    #[cfg_attr(target_os = "wasi", tokio::test)]
    async fn concurrent_runtime_updates_keep_snapshot_and_derived_state_coherent() {
        let config = test_config("concurrent-runtime-update");
        let instance = build_instance(config.clone()).unwrap();
        instance.start().await.unwrap();

        let original = instance.node_snapshot().await;
        let mut full = config.clone();
        full.parsed_mut().dhcp = true;
        full.parsed_mut().tcp_whitelist = vec!["80".to_owned()];
        full.parsed_mut().hostname = "full".to_owned();
        full.parsed_mut().proxy_network =
            vec![proxy_network("192.0.2.0/24", Some("198.51.100.0/24"))];
        let mut peer_update = full.clone();
        peer_update.parsed_mut().hostname = "peer".to_owned();
        peer_update.parsed_mut().proxy_network =
            vec![proxy_network("203.0.113.0/24", Some("10.20.30.0/24"))];

        let start = Arc::new(tokio::sync::Barrier::new(3));
        let full_update = tokio::spawn({
            let instance = instance.clone();
            let start = start.clone();
            async move {
                start.wait().await;
                instance.update_runtime_config(full).await
            }
        });
        let peer_update = tokio::spawn({
            let instance = instance.clone();
            let start = start.clone();
            async move {
                start.wait().await;
                instance.update_runtime_config(peer_update).await
            }
        });
        start.wait().await;
        full_update.await.unwrap().unwrap();
        peer_update.await.unwrap().unwrap();

        let final_config = instance.runtime_config.snapshot();
        assert!(final_config.dhcp);
        assert_eq!(instance.acl_whitelist_snapshot().tcp_ports, ["80"]);
        assert_eq!(instance.acl_reload_count.load(Ordering::Relaxed), 1);
        let node = instance.node_snapshot().await;
        assert_eq!(node.peer_id, original.peer_id);
        assert_eq!(node.instance_id, original.instance_id);
        assert_eq!(
            Some(final_config.hostname.as_str()),
            Some(node.hostname.as_str())
        );
        match node.hostname.as_str() {
            "full" => assert_eq!(
                instance
                    .proxy_cidr_table
                    .lookup_v4("198.51.100.42".parse().unwrap()),
                Some("192.0.2.42".parse().unwrap())
            ),
            "peer" => assert_eq!(
                instance
                    .proxy_cidr_table
                    .lookup_v4("10.20.30.42".parse().unwrap()),
                Some("203.0.113.42".parse().unwrap())
            ),
            hostname => panic!("unexpected final hostname: {hostname:?}"),
        }

        instance.stop().await;
    }

    #[cfg(all(feature = "test-utils", feature = "dhcp-ipv4"))]
    #[tokio::test]
    async fn active_runtime_update_skips_unchanged_and_rejects_invalid_acl() {
        let config = test_config("invalid-active-acl-update");
        let instance = build_instance(config.clone()).unwrap();
        instance.start().await.unwrap();

        let mut unrelated = config.clone();
        unrelated.parsed_mut().hostname = "accepted".to_owned();
        instance.update_runtime_config(unrelated).await.unwrap();
        assert_eq!(instance.acl_reload_count.load(Ordering::Relaxed), 0);
        let before = instance.node_snapshot().await;

        let mut rejected = config.clone();
        rejected.parsed_mut().dhcp = true;
        rejected.parsed_mut().tcp_whitelist = vec!["invalid".to_owned()];
        rejected.parsed_mut().hostname = "rejected".to_owned();

        let error = instance.update_runtime_config(rejected).await.unwrap_err();
        assert!(error.to_string().contains("Invalid port number"));
        assert!(!instance.runtime_config.snapshot().dhcp);
        assert!(instance.acl_whitelist_snapshot().tcp_ports.is_empty());
        assert_eq!(instance.acl_reload_count.load(Ordering::Relaxed), 0);
        assert_eq!(instance.node_snapshot().await.hostname, before.hostname);
        instance.stop().await;
    }

    #[cfg(feature = "proxy-packet")]
    #[tokio::test]
    async fn runtime_core_instance_owns_connectivity_lifecycle() {
        let mut config = test_config("connectivity-lifecycle");
        config.parsed_mut().proxy_network = vec![proxy_network("10.1.2.0/24", None)];
        let initial_peer: Url = "tcp://127.0.0.1:29999".parse().unwrap();
        config.parsed_mut().peer = vec![crate::config::toml::PeerConfig {
            uri: initial_peer.clone(),
            peer_public_key: None,
        }];
        let proxy = Arc::new(RecordingProxyService::default());
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(proxy.clone()),
                quic: None,
            },
        )
        .unwrap();

        assert_eq!(instance.state(), CoreInstanceState::Created);
        assert_eq!(instance.list_connectors().len(), 1);
        assert_eq!(instance.list_connectors()[0].url, initial_peer);
        instance.start().await.unwrap();
        assert_eq!(instance.state(), CoreInstanceState::Running);
        assert!(instance.is_ready());
        assert!(instance.start().await.is_err());
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);

        instance.stop().await;
        instance.stop().await;
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    #[tokio::test]
    async fn startup_plan_controls_gateway_for_initial_and_updated_config() {
        fn build(
            config: InstanceConfig,
            gateway_enabled: bool,
        ) -> (Arc<CoreInstance<TestHost>>, Arc<TestHost>) {
            let host = Arc::new(TestHost {
                reject_socks5_listener: true,
                ..Default::default()
            });
            let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
            let mut adapters = adapters_with_host(host.clone(), None, Arc::new(packet_sink));
            adapters.config.gateway_enabled = gateway_enabled;
            (CoreInstance::new(config, adapters).unwrap(), host)
        }

        let mut enabled_config = test_config("gateway-enabled-by-default");
        enabled_config.parsed_mut().socks5_proxy = Some("socks5://127.0.0.1:1080".parse().unwrap());
        let (enabled, _) = build(enabled_config, true);
        let error = enabled.start().await.unwrap_err();
        assert!(error.to_string().contains("rejected SOCKS5 listener"));
        assert_eq!(enabled.state(), CoreInstanceState::Stopped);

        let mut disabled_config = test_config("gateway-disabled-by-plan");
        disabled_config.parsed_mut().ipv4 = Some("10.144.0.1/24".parse().unwrap());
        let (disabled, _) = build(disabled_config.clone(), false);
        let mut updated = disabled_config.clone();
        updated.parsed_mut().socks5_proxy = Some("socks5://127.0.0.1:1080".parse().unwrap());
        disabled.update_runtime_config(updated).await.unwrap();
        disabled.start().await.unwrap();
        assert_eq!(disabled.state(), CoreInstanceState::Running);
        let socket = disabled
            .data_plane_udp_bind(0, Duration::from_secs(1))
            .await
            .expect("startup plan must not disable the data-plane runtime");
        drop(socket);
        disabled.stop().await;
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    #[tokio::test]
    async fn failed_port_forward_start_releases_started_listeners() {
        let mut config = test_config("port-forward-start-rollback");
        config.parsed_mut().port_forward = vec![
            PortForwardConfig {
                bind_addr: "127.0.0.1:18080".parse().unwrap(),
                dst_addr: "10.144.0.2:80".parse().unwrap(),
                proto: "tcp".to_owned(),
            },
            PortForwardConfig {
                bind_addr: "127.0.0.1:18081".parse().unwrap(),
                dst_addr: "10.144.0.2:81".parse().unwrap(),
                proto: "unsupported".to_owned(),
            },
        ];
        let host = Arc::new(TestHost::default());
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let adapters = adapters_with_host(host.clone(), None, Arc::new(packet_sink));
        let instance = CoreInstance::new(config, adapters).unwrap();

        let error = instance.start().await.unwrap_err();

        assert!(error.to_string().contains("unsupported protocol"));
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(host.active_tcp_listeners.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "proxy-packet")]
    #[tokio::test]
    async fn runtime_core_instance_owns_wrapped_transport_source_nat() {
        let mut config = test_config("wrapped-source");
        config.parsed_mut().flags.enable_kcp_proxy = true;
        config.parsed_mut().flags.disable_kcp_input = true;
        let engine = Arc::new(RecordingProxyService::default());
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(engine.clone()),
                quic: None,
            },
        )
        .unwrap();

        instance.start().await.unwrap();
        assert!(
            instance.wrapped_transport_is_started(
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Source,
            )
        );
        assert!(
            instance
                .wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Source,
                )
                .is_empty()
        );

        instance.stop().await;
        assert!(
            !instance.wrapped_transport_is_started(
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Source,
            )
        );
        assert_eq!(engine.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "proxy-packet")]
    #[tokio::test]
    async fn runtime_core_instance_owns_wrapped_transport_destination_sessions() {
        let mut config = test_config("wrapped-destination");
        config.parsed_mut().flags.enable_kcp_proxy = false;
        config.parsed_mut().flags.disable_kcp_input = false;
        let engine = Arc::new(RecordingProxyService::default());
        let (connections, mut connection_receiver) = tokio::sync::mpsc::unbounded_channel();
        let host = Arc::new(TestHost {
            proxy_nat_connections: Some(connections),
            ..Default::default()
        });
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters_with_host(host, None, Arc::new(packet_sink));
        adapters.wrapped_transports = WrappedTransportEngines {
            kcp: Some(engine.clone()),
            quic: None,
        };
        let instance = CoreInstance::new(config, adapters).unwrap();

        instance.start().await.unwrap();
        assert!(instance.wrapped_transport_is_started(
            WrappedTransportKind::Kcp,
            WrappedTransportRole::Destination,
        ));

        let destination: SocketAddr = "127.0.0.1:20100".parse().unwrap();
        let ingress = engine
            .destination_ingress()
            .expect("core should inject a destination ingress");
        let (core_stream, peer_stream) = tokio::io::duplex(1024);
        ingress
            .submit(
                crate::gateway::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                    src: "10.0.0.2:40000".parse().unwrap(),
                    dst: destination,
                    initial_acl_packet_size: 16,
                    stream: Box::new(core_stream),
                },
            )
            .await
            .unwrap();
        let (connected_destination, destination_stream) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connection_receiver.recv(),
        )
        .await
        .expect("core should request the destination socket")
        .unwrap();
        assert_eq!(connected_destination, destination);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let entries = instance.wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                );
                if entries.iter().any(|entry| {
                    entry.state
                        == crate::gateway::proxy::tcp_proxy_engine::TcpNatEntryState::Connected
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("core should own the connected destination entry");

        drop(peer_stream);
        drop(destination_stream);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !instance
                .wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                )
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed destination entry should be removed");

        let (core_stream, _blocked_peer_stream) = tokio::io::duplex(1024);
        ingress
            .submit(
                crate::gateway::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                    src: "10.0.0.2:40001".parse().unwrap(),
                    dst: destination,
                    initial_acl_packet_size: 16,
                    stream: Box::new(core_stream),
                },
            )
            .await
            .unwrap();
        let (connected_destination, _blocked_destination_stream) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connection_receiver.recv(),
        )
        .await
        .expect("second destination session should request a socket")
        .unwrap();
        assert_eq!(connected_destination, destination);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while instance
                .wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                )
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocked destination session should be visible");

        tokio::time::timeout(std::time::Duration::from_secs(2), instance.stop())
            .await
            .expect("stop should cancel core-owned destination sessions");
        assert!(
            instance
                .wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                )
                .is_empty()
        );
        assert!(
            ingress
                .submit(
                    crate::gateway::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                        src: "10.0.0.2:40002".parse().unwrap(),
                        dst: destination,
                        initial_acl_packet_size: 16,
                        stream: Box::new(tokio::io::duplex(64).0),
                    },
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn runtime_core_instance_owns_the_transport_proxy_cidr_table() {
        let mut config = test_config("transport-proxy-cidr");
        config.parsed_mut().flags.proxy_forward_by_system = true;
        config.parsed_mut().proxy_network =
            vec![proxy_network("192.0.2.0/24", Some("198.51.100.0/24"))];
        let mut updated = config.clone();
        let proxy = Arc::new(RecordingProxyService::default());
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(proxy.clone()),
                quic: None,
            },
        )
        .unwrap();

        assert_eq!(instance.node_snapshot().await.proxy_networks.len(), 1);
        instance.start().await.unwrap();
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);

        updated.parsed_mut().proxy_network =
            vec![proxy_network("203.0.113.0/24", Some("10.20.30.0/24"))];
        instance.update_runtime_config(updated).await.unwrap();
        let proxy_networks = instance.node_snapshot().await.proxy_networks;
        assert_eq!(proxy_networks.len(), 1);
        assert_eq!(
            proxy_networks[0].cidr.first_address(),
            "203.0.113.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            proxy_networks[0]
                .mapped_cidr
                .as_ref()
                .unwrap()
                .first_address(),
            "10.20.30.0".parse::<IpAddr>().unwrap()
        );

        instance.stop().await;
        assert!(instance.start().await.is_err());
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn runtime_core_rejects_invalid_acl_runtime_snapshot() {
        let config = test_config("explicit-acl");
        let instance = build_instance(config.clone()).unwrap();
        assert_eq!(instance.acl_whitelist_snapshot(), Default::default());

        let mut updated = config.clone();
        updated.parsed_mut().tcp_whitelist = vec!["invalid".to_owned()];
        let error = instance.update_runtime_config(updated).await.unwrap_err();
        assert!(error.to_string().contains("Invalid port number"));
        assert!(instance.acl_whitelist_snapshot().tcp_ports.is_empty());
        instance.start().await.unwrap();
        instance.stop().await;
    }

    #[cfg(feature = "dhcp-ipv4")]
    #[tokio::test]
    async fn runtime_core_accepts_explicit_dhcp_runtime_snapshot() {
        let config = test_config("explicit-dhcp");
        let instance = build_instance(config.clone()).unwrap();
        let mut updated = config.clone();
        updated.parsed_mut().dhcp = true;
        instance.update_runtime_config(updated).await.unwrap();
        let error = instance.start().await.unwrap_err();
        assert!(error.to_string().contains("no host adapter was provided"));
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
    }

    #[cfg(feature = "public-ipv6-provider")]
    #[tokio::test]
    async fn runtime_core_accepts_explicit_public_ipv6_runtime_snapshot() {
        let config = test_config("explicit-public-ipv6");
        let instance = build_instance(config.clone()).unwrap();
        let mut updated = config.clone();
        updated.parsed_mut().ipv6_public_addr_provider = true;
        updated.parsed_mut().ipv6_public_addr_prefix = Some("fd00::/64".parse().unwrap());
        instance.update_runtime_config(updated).await.unwrap();

        let error = instance.start().await.unwrap_err();
        assert!(error.to_string().contains("not a valid global unicast"));
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
    }

    #[cfg(not(feature = "proxy-packet"))]
    #[test]
    fn runtime_core_rejects_packet_proxy_requests_when_unavailable() {
        let mut config = test_config("packet-proxy-unavailable");
        config.parsed_mut().flags.enable_exit_node = true;

        let error = match build_instance(config) {
            Ok(_) => panic!("packet proxy request unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("does not include packet proxy services")
        );
    }

    #[cfg(not(feature = "proxy-smoltcp-stack"))]
    #[tokio::test]
    async fn runtime_core_rejects_unavailable_gateway_updates() {
        let config = test_config("smoltcp-gateway-update-unavailable");
        let instance = build_instance(config.clone()).unwrap();
        let mut updated = config.clone();
        updated.parsed_mut().socks5_proxy = Some("socks5://127.0.0.1:1080".parse().unwrap());

        let error = instance.update_runtime_config(updated).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("does not include the smoltcp gateway")
        );
    }

    #[tokio::test]
    async fn stopping_while_transport_proxy_starts_rolls_back_once() {
        let mut config = test_config("blocking-transport-proxy");
        config.parsed_mut().flags.proxy_forward_by_system = true;
        config.parsed_mut().proxy_network = vec![proxy_network("10.1.2.0/24", None)];
        let initial_peer: Url = "tcp://127.0.0.1:29998".parse().unwrap();
        config.parsed_mut().peer = vec![crate::config::toml::PeerConfig {
            uri: initial_peer,
            peer_public_key: None,
        }];
        let (proxy, start_gate) = RecordingProxyService::blocking();
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(proxy.clone()),
                quic: None,
            },
        )
        .unwrap();

        let start_task = tokio::spawn({
            let instance = instance.clone();
            async move { instance.start().await }
        });
        start_gate.entered.notified().await;
        let stop_task = tokio::spawn({
            let instance = instance.clone();
            async move { instance.stop().await }
        });
        while !instance.cancel.is_cancelled() {
            tokio::task::yield_now().await;
        }

        assert!(start_task.await.unwrap().is_err());
        stop_task.await.unwrap();
        assert_eq!(instance.list_connectors().len(), 1);
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert!(!instance.is_ready());
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn start_serializes_runtime_updates() {
        let mut config = test_config("serialized-start");
        config.parsed_mut().flags.proxy_forward_by_system = true;
        config.parsed_mut().proxy_network = vec![proxy_network("10.1.4.0/24", None)];
        let mut updated = config.clone();
        updated.parsed_mut().hostname = "updated-after-start".to_owned();
        let (proxy, start_gate) = RecordingProxyService::blocking();
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(proxy),
                quic: None,
            },
        )
        .unwrap();

        let start = tokio::spawn({
            let instance = instance.clone();
            async move { instance.start().await }
        });
        start_gate.entered.notified().await;

        let update = instance.update_runtime_config(updated);
        tokio::pin!(update);
        assert!(matches!(
            futures::poll!(update.as_mut()),
            std::task::Poll::Pending
        ));

        start_gate.release.notify_one();
        start.await.unwrap().unwrap();
        update.await.unwrap();
        assert_eq!(
            instance.node_snapshot().await.hostname,
            "updated-after-start"
        );
        instance.stop().await;
    }

    #[tokio::test]
    async fn aborting_start_stops_partial_runtime() {
        let mut config = test_config("aborted-start");
        config.parsed_mut().flags.proxy_forward_by_system = true;
        config.parsed_mut().proxy_network = vec![proxy_network("10.1.3.0/24", None)];
        let (proxy, start_gate) = RecordingProxyService::blocking();
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(proxy.clone()),
                quic: None,
            },
        )
        .unwrap();

        let start = tokio::spawn({
            let instance = instance.clone();
            async move { instance.start().await }
        });
        start_gate.entered.notified().await;
        start.abort();
        assert!(start.await.unwrap_err().is_cancelled());

        tokio::time::timeout(Duration::from_secs(2), async {
            while instance.state() != CoreInstanceState::Stopped {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted activation should recover the instance");
        assert!(!instance.is_ready());
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn invalid_initial_peer_fails_during_construction() {
        let mut config = test_config("invalid-initial-peer");
        config.parsed_mut().peer = vec![crate::config::toml::PeerConfig {
            uri: "unsupported://peer.example:1234".parse().unwrap(),
            peer_public_key: None,
        }];

        let error = build_instance(config)
            .err()
            .expect("invalid initial peer should fail construction");
        assert!(
            error
                .to_string()
                .contains("unsupported core manual connector URL"),
            "unexpected construction error: {error:#}"
        );
    }

    #[tokio::test]
    async fn runtime_core_instances_keep_lifecycle_and_connectors_isolated() {
        let instance_a = build_instance(test_config("instance-a")).unwrap();
        let instance_b = build_instance(test_config("instance-b")).unwrap();
        let connector_a: Url = "tcp://127.0.0.1:21001".parse().unwrap();
        let connector_b: Url = "udp://127.0.0.1:21002".parse().unwrap();

        instance_a.add_connector(connector_a.clone()).unwrap();
        instance_b.add_connector(connector_b.clone()).unwrap();
        assert_eq!(instance_a.list_connectors()[0].url, connector_a);
        assert_eq!(instance_b.list_connectors()[0].url, connector_b);
        instance_a.clear_connectors();
        instance_b.clear_connectors();

        let (start_a, start_b) = tokio::join!(instance_a.start(), instance_b.start());
        start_a.unwrap();
        start_b.unwrap();
        assert_eq!(instance_a.state(), CoreInstanceState::Running);
        assert_eq!(instance_b.state(), CoreInstanceState::Running);

        instance_a.stop().await;
        assert_eq!(instance_a.state(), CoreInstanceState::Stopped);
        assert_eq!(instance_b.state(), CoreInstanceState::Running);
        instance_b.stop().await;
        assert_eq!(instance_b.state(), CoreInstanceState::Stopped);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_cancels_pending_listener_start() {
        let state = Arc::new(BlockingListenerState::default());
        let mut config = test_config("pending-listener");
        config.parsed_mut().listeners = Some(vec![
            "unix:///tmp/easytier-pending-listener".parse().unwrap(),
        ]);
        let instance = build_with_engines_and_listener(
            config,
            WrappedTransportEngines::default(),
            Some(Arc::new(BlockingExternalListenerFactory {
                state: state.clone(),
            })),
        )
        .unwrap();
        let start_instance = instance.clone();
        let start_task =
            AbortOnDropHandle::new(tokio::spawn(async move { start_instance.start().await }));
        let start_result = tokio::time::timeout(Duration::from_secs(1), async {
            state.start_entered.notified().await;
            instance.stop().await;
            start_task.await.unwrap()
        })
        .await
        .expect("listener cancellation should complete promptly");

        assert!(start_result.is_err());
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(state.drop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn external_listener_uses_core_running_listener_registry() {
        let external_url: Url = "unix:///tmp/easytier-external-listener-test"
            .parse()
            .unwrap();
        let mut config = test_config("external-listener-registry");
        config.parsed_mut().listeners = Some(vec![external_url.clone()]);
        let instance = build_with_engines_and_listener(
            config,
            WrappedTransportEngines::default(),
            Some(Arc::new(ReadyExternalListenerFactory)),
        )
        .unwrap();

        instance.start().await.unwrap();
        let running = instance.running_listeners();
        assert_eq!(running.len(), 2);
        assert!(running.iter().any(|url| url.scheme() == "ring"));
        assert!(running.contains(&external_url));
        assert_eq!(instance.node_snapshot().await.listeners, running);

        instance.stop().await;
        assert!(instance.running_listeners().is_empty());
    }

    #[tokio::test]
    async fn inbound_only_uses_host_registered_listener_lifecycle() {
        let external_url: Url = "unix:///tmp/easytier-host-listener-test".parse().unwrap();
        let config = test_config("host-listener");
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(
            Some(Arc::new(ReadyExternalListenerFactory)),
            Arc::new(packet_sink),
        );
        adapters.config.connectivity = CoreConnectivityMode::InboundOnly;
        adapters
            .host_listener_registrations
            .push(ExternalListenerRequest {
                url: external_url.clone(),
                socket_context: SocketContext::default(),
            });
        let instance = CoreInstance::new(config, adapters).unwrap();

        assert!(
            instance
                .add_connector("tcp://127.0.0.1:11010".parse().unwrap())
                .is_err()
        );
        instance.start().await.unwrap();
        assert!(instance.running_listeners().contains(&external_url));

        instance.stop().await;
        assert!(instance.running_listeners().is_empty());
    }

    #[tokio::test]
    async fn inbound_only_rejects_initial_peers() {
        let mut config = test_config("inbound-only-peer");
        config
            .parsed_mut()
            .peer
            .push(crate::config::toml::PeerConfig {
                uri: "tcp://127.0.0.1:11010".parse().unwrap(),
                peer_public_key: None,
            });
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(None, Arc::new(packet_sink));
        adapters.config.connectivity = CoreConnectivityMode::InboundOnly;

        let Err(error) = CoreInstance::new(config, adapters) else {
            panic!("inbound-only instance accepted an outbound peer");
        };
        assert!(
            error
                .to_string()
                .contains("inbound-only connectivity does not support outbound peers"),
            "unexpected construction error: {error:#}"
        );
    }

    #[tokio::test]
    async fn outbound_only_ignores_configured_and_host_registered_listeners() {
        let configured_url: Url = "unix:///tmp/easytier-outbound-configured-listener"
            .parse()
            .unwrap();
        let host_url: Url = "unix:///tmp/easytier-outbound-host-listener"
            .parse()
            .unwrap();
        let mut config = test_config("outbound-only-listeners");
        config.parsed_mut().listeners = Some(vec![configured_url]);
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(
            Some(Arc::new(ReadyExternalListenerFactory)),
            Arc::new(packet_sink),
        );
        adapters.config.connectivity = CoreConnectivityMode::OutboundOnly;
        adapters
            .host_listener_registrations
            .push(ExternalListenerRequest {
                url: host_url,
                socket_context: SocketContext::default(),
            });
        let instance = CoreInstance::new(config, adapters).unwrap();

        instance.start().await.unwrap();
        assert!(instance.running_listeners().is_empty());

        instance.stop().await;
    }

    #[tokio::test]
    async fn compose_with_toml_should_not_follow_original_alias() {
        let original = TomlConfig::new_from_str("hostname = 'before'").unwrap();
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let host_config = CoreInstanceHostConfig::default();
        let instance = CoreInstance::compose_with_toml(&original, host_config, |_normalized| {
            Ok(adapters(None, Arc::new(packet_sink)))
        })
        .unwrap();

        original.set_hostname(Some("after".into()));
        assert_eq!(
            instance
                .config_store()
                .snapshot()
                .parsed()
                .hostname
                .as_str(),
            "before"
        );
    }

    #[tokio::test]
    async fn compose_with_toml_rejects_mismatched_host_config() {
        let original = TomlConfig::new_from_str("hostname = 'test'").unwrap();
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let host_config = CoreInstanceHostConfig::default();
        let mut mismatched_adapters = adapters(None, Arc::new(packet_sink));
        mismatched_adapters.config.gateway_enabled = !host_config.gateway_enabled;

        let result = CoreInstance::compose_with_toml(&original, host_config, |_normalized| {
            Ok(mismatched_adapters)
        });
        let Err(err) = result else {
            panic!("expected error for mismatched host config");
        };
        assert!(
            err.to_string()
                .contains("adapters host configuration does not match")
        );
    }

    #[tokio::test]
    async fn compose_with_toml_materializes_keys_in_management_config() {
        let config = TomlConfig::default();
        let template = TomlConfig::new_from_str("[secure_mode]\nenabled = true").unwrap();
        let mut secure = template.get_secure_mode().unwrap();
        secure.local_private_key = None;
        secure.local_public_key = None;
        config.set_secure_mode(Some(secure)).unwrap();

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let host_config = CoreInstanceHostConfig::default();
        let instance = CoreInstance::compose_with_toml(&config, host_config, |_normalized| {
            Ok(adapters(None, Arc::new(packet_sink)))
        })
        .unwrap();

        let saved_has_key = instance
            .config_store()
            .snapshot()
            .parsed()
            .secure_mode
            .as_ref()
            .unwrap()
            .local_private_key
            .is_some();
        assert!(saved_has_key);
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn get_config_returns_consistent_config_and_toml_from_store_snapshot() {
        use crate::{
            instance::manager::{InstanceFactory, InstanceManager},
            management::InstanceManagementRpc,
        };
        use easytier_proto::{
            api::config::{
                ConfigRpc as _, GetConfigRequest, InstanceConfigPatch, PatchConfigRequest,
            },
            api::instance::{
                InstanceIdentifier,
                instance_identifier::{InstanceSelector, Selector},
            },
            rpc_types::controller::BaseController,
        };

        struct ConsistentGetFactory;

        impl InstanceFactory for ConsistentGetFactory {
            type Instance = CoreInstance<TestHost>;
            type CreateContext = ();
            type Error = anyhow::Error;

            fn create(
                &self,
                config: TomlConfig,
                (): Self::CreateContext,
            ) -> Result<Arc<Self::Instance>, Self::Error> {
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                let adapters = adapters(None, Arc::new(packet_sink));
                CoreInstance::from_toml(config, adapters)
            }
        }

        let manager = Arc::new(InstanceManager::new(ConsistentGetFactory, None));
        let config = TomlConfig::new_from_str(
            r#"
instance_name = "test-consistent-get"
hostname = "host-initial"
ipv4 = "10.14.0.1/24"
dhcp = false

[network_identity]
network_name = "test-network"
network_secret = "test-secret"
"#,
        )
        .unwrap();
        let instance = manager.create(config, ()).unwrap();
        instance.start().await.unwrap();
        let rpc = InstanceManagementRpc::<ConsistentGetFactory>::new(manager);

        let selector = || InstanceIdentifier {
            selector: Some(Selector::InstanceSelector(InstanceSelector {
                name: Some("test-consistent-get".to_owned()),
            })),
        };

        // 1. Initial read: both config and toml_config match Store snapshot
        let res = rpc
            .get_config(
                BaseController::default(),
                GetConfigRequest {
                    instance: Some(selector()),
                },
            )
            .await
            .unwrap();

        let net_cfg = res.config.expect("config must be present");
        let toml_str = res.toml_config;

        assert_eq!(net_cfg.hostname.as_deref(), Some("host-initial"));
        assert_eq!(net_cfg.dhcp, Some(false));
        assert_eq!(net_cfg.virtual_ipv4.as_deref(), Some("10.14.0.1"));
        assert!(toml_str.contains("hostname = \"host-initial\""));
        assert!(toml_str.contains("dhcp = false"));
        assert!(toml_str.contains("ipv4 = \"10.14.0.1/24\""));

        let parsed_toml = TomlConfig::new_from_str(&toml_str).unwrap();
        assert_eq!(parsed_toml.get_hostname(), "host-initial");
        assert_eq!(parsed_toml.snapshot().unwrap().dhcp, false);

        // 2. Patch config
        rpc.patch_config(
            BaseController::default(),
            PatchConfigRequest {
                patch: Some(InstanceConfigPatch {
                    hostname: Some("host-updated".to_owned()),
                    ..Default::default()
                }),
                instance: Some(selector()),
            },
        )
        .await
        .unwrap();

        // 3. Subsequent read immediately returns updated values from Store in both representations
        let res2 = rpc
            .get_config(
                BaseController::default(),
                GetConfigRequest {
                    instance: Some(selector()),
                },
            )
            .await
            .unwrap();

        let net_cfg2 = res2.config.expect("config must be present");
        let toml_str2 = res2.toml_config;

        assert_eq!(net_cfg2.hostname.as_deref(), Some("host-updated"));
        assert!(toml_str2.contains("hostname = \"host-updated\""));

        let parsed_toml2 = TomlConfig::new_from_str(&toml_str2).unwrap();
        assert_eq!(parsed_toml2.get_hostname(), "host-updated");

        let store_snap = instance.config_store().snapshot();
        assert_eq!(store_snap.raw().hostname.as_deref(), Some("host-updated"));
    }

    #[cfg(all(feature = "management", feature = "vpn-portal"))]
    #[tokio::test]
    async fn persistence_failure_in_subsequent_step_leaves_previously_accepted_candidate_committed()
    {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
        use easytier_proto::api::{
            config::{ConfigPatchAction, InstanceConfigPatch, VpnPortalClientPatch},
            manage::{ManagedCredentialConfig, ManagedCredentialSet, VpnPortalClientConfig},
        };

        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut host_adapters = adapters(None, Arc::new(packet_sink));
        host_adapters.vpn_portal = Some(Arc::new(SucceedingPortalHost));
        let instance = CoreInstance::from_toml(
            TomlConfig::new_from_str(
                r#"
instance_name = "partial-commit-test"
ipv4 = "10.83.0.1/24"

[network_identity]
network_name = "partial-commit-network"
network_secret = "network-secret"

[vpn_portal_config]
wireguard_listen = "0.0.0.0:51821"

[source]
source = "web"
"#,
            )
            .unwrap(),
            host_adapters,
        )
        .unwrap();
        instance.set_state(CoreInstanceState::Running);

        let persistence = RecordingConfigPatchPersistence::fail_after(1);
        let secret = BASE64_STANDARD.encode([8u8; 32]);

        let patch = InstanceConfigPatch {
            vpn_portal_clients: vec![VpnPortalClientPatch {
                action: ConfigPatchAction::Add as i32,
                client: Some(VpnPortalClientConfig {
                    name: "step-1-client".to_owned(),
                    virtual_ip: "10.83.0.2/24".to_owned(),
                    ..Default::default()
                }),
            }],
            managed_credentials: Some(ManagedCredentialSet {
                entries: vec![ManagedCredentialConfig {
                    credential_id: "step-2-cred".to_owned(),
                    credential_secret: secret.clone(),
                    groups: vec!["ops".to_owned()],
                    allow_relay: false,
                    allowed_proxy_cidrs: Vec::new(),
                    expiry_unix: 2_000_000_000,
                    reusable: Some(true),
                }],
            }),
            ..Default::default()
        };

        let error = crate::management::apply_config_patch(&instance, patch, Some(&persistence))
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected config persistence failure after limit")
        );

        let snapshot = instance.config_store().snapshot();
        let portal_clients = snapshot
            .parsed()
            .vpn_portal_config
            .as_ref()
            .unwrap()
            .clients
            .clone();
        assert_eq!(portal_clients.len(), 1);
        assert_eq!(portal_clients[0].name, "step-1-client");

        assert!(snapshot.parsed().managed_credentials.is_empty());

        let private_bytes: [u8; 32] = BASE64_STANDARD.decode(&secret).unwrap().try_into().unwrap();
        let public_key =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_bytes));
        assert!(
            !instance
                .credential_manager()
                .is_pubkey_trusted(public_key.as_bytes())
        );

        let persisted = persistence.writes.lock().unwrap();
        assert_eq!(persisted.len(), 1);
        assert!(persisted[0].contains("step-1-client"));
        assert!(!persisted[0].contains("step-2-cred"));
    }
}
