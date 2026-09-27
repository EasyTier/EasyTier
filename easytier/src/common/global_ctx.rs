use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use easytier_core::connectivity::composite::ConnectorRuntime as _;
use easytier_core::peers::public_ipv6::PublicIpv6Host;
use easytier_core::socket::{NetNamespace, SocketContext};
use easytier_core::tunnel::effective_encryption_uses_xor;
use easytier_core::{
    config::{PeerId, runtime::InstanceConfigStore},
    instance::CoreInstanceHostConfig,
};

use super::{
    config::{Flags, NetworkIdentity},
    netns::NetNS,
};
#[cfg(feature = "management")]
use crate::proto::api::config::InstanceConfigPatch;
use crate::proto::api::instance::PeerConnInfo;
use crate::proto::common::PortForwardConfigPb;
use crossbeam::atomic::AtomicCell;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "management", derive(serde::Serialize, serde::Deserialize))]
pub enum GlobalCtxEvent {
    TunDeviceReady(String),
    TunDeviceError(String),

    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(PeerConnInfo),
    PeerConnRemoved(PeerConnInfo),

    ListenerAdded(url::Url),
    ListenerAddFailed(url::Url, String), // (url, error message)
    ListenerAcceptFailed(url::Url, String), // (url, error message)
    ConnectionAccepted(String, String),  // (local url, remote url)
    ConnectionError(String, String, String), // (local url, remote url, error message)
    ListenerPortMappingEstablished {
        local_listener: url::Url,
        mapped_listener: url::Url,
        backend: String,
    },

    Connecting(url::Url),
    ConnectError(String, String, String), // (dst, ip version, error message)

    VpnPortalStarted(String),                    // (portal)
    VpnPortalClientConnected(String, String),    // (portal, client ip)
    VpnPortalClientDisconnected(String, String), // (portal, client ip)

    DhcpIpv4Changed(Option<cidr::Ipv4Inet>, Option<cidr::Ipv4Inet>), // (old, new)
    DhcpIpv4Conflicted(Option<cidr::Ipv4Inet>),
    PublicIpv6Changed(Option<cidr::Ipv6Inet>, Option<cidr::Ipv6Inet>), // (old, new)
    PublicIpv6RoutesUpdated(Vec<cidr::Ipv6Inet>, Vec<cidr::Ipv6Inet>), // (added, removed)

    PortForwardAdded(PortForwardConfigPb),

    #[cfg(feature = "management")]
    ConfigPatched(InstanceConfigPatch),

    ProxyCidrsUpdated(Vec<cidr::Ipv4Cidr>, Vec<cidr::Ipv4Cidr>), // (added, removed)

    UdpBroadcastRelayStartResult {
        capture_backend: Option<String>,
        error: Option<String>,
    },

    CredentialChanged,
}

pub type EventBus = tokio::sync::broadcast::Sender<GlobalCtxEvent>;
pub type EventBusSubscriber = tokio::sync::broadcast::Receiver<GlobalCtxEvent>;

pub struct GlobalCtx {
    pub inst_name: String,
    pub id: uuid::Uuid,
    pub net_ns: NetNS,
    pub network: NetworkIdentity,

    event_bus: EventBus,

    applied_ipv4: AtomicCell<Option<cidr::Ipv4Inet>>,

    tun_device_name: Mutex<Option<String>>,

    runtime_endpoint_protocols: Option<HashSet<String>>,
    runtime_config_store: InstanceConfigStore,
}

impl std::fmt::Debug for GlobalCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalCtx")
            .field("inst_name", &self.inst_name)
            .field("id", &self.id)
            .field("net_ns", &self.net_ns.name())
            .field("event_bus", &"EventBus")
            .field("applied_ipv4", &self.applied_ipv4)
            .finish()
    }
}

pub type ArcGlobalCtx = std::sync::Arc<GlobalCtx>;

#[async_trait]
impl PublicIpv6Host for GlobalCtx {
    async fn collect_reserved_public_ipv6_addrs(
        &self,
        prefix: cidr::Ipv6Cidr,
    ) -> HashSet<Ipv6Addr> {
        let context = SocketContext::default()
            .with_socket_mark(self.get_flags().socket_mark)
            .with_netns(self.net_ns.name().map(NetNamespace::new));
        let ip_list = crate::host_runtime::native_host_runtime()
            .collect_ip_addrs(&context)
            .await;
        let mut reserved = HashSet::new();
        reserved.extend(
            ip_list
                .interface_ipv6s
                .into_iter()
                .map(Ipv6Addr::from)
                .filter(|addr| prefix.contains(addr)),
        );
        reserved.extend(
            ip_list
                .public_ipv6
                .into_iter()
                .map(Ipv6Addr::from)
                .filter(|addr| prefix.contains(addr)),
        );
        reserved
    }
}

impl GlobalCtx {
    pub fn new(store: InstanceConfigStore, host: &CoreInstanceHostConfig) -> Self {
        let snapshot = store.snapshot();
        let parsed = snapshot.parsed();
        let id = parsed.instance_id;
        let network = parsed.network_identity.clone();
        let net_ns = NetNS::new(parsed.netns.clone());
        let protocols = host.ignore_unsupported_config.then(|| {
            host.endpoint_protocols
                .iter()
                .map(|protocol| protocol.to_ascii_lowercase())
                .collect()
        });
        if parsed.flags.enable_encryption
            && effective_encryption_uses_xor(&parsed.flags.encryption_algorithm)
        {
            tracing::warn!("using insecure XOR because no AEAD encryption is configured");
        }

        let (event_bus, _) = tokio::sync::broadcast::channel(16);
        GlobalCtx {
            inst_name: parsed.instance_name.clone(),
            id,
            net_ns,
            network,

            event_bus,
            applied_ipv4: AtomicCell::new(None),

            tun_device_name: Mutex::new(None),

            runtime_endpoint_protocols: protocols,
            runtime_config_store: store,
        }
    }

    pub fn runtime_config_store(&self) -> &InstanceConfigStore {
        &self.runtime_config_store
    }

    pub fn subscribe(&self) -> EventBusSubscriber {
        self.event_bus.subscribe()
    }

    pub fn issue_event(&self, event: GlobalCtxEvent) {
        if let Err(e) = self.event_bus.send(event.clone()) {
            tracing::warn!(
                "Failed to send event: {:?}, error: {:?}, receiver count: {}",
                event,
                e,
                self.event_bus.receiver_count()
            );
        }
    }

    #[cfg(any(feature = "tun", test))]
    fn set_tun_device_name(&self, name: Option<String>) {
        *self.tun_device_name.lock().unwrap() = name;
    }

    #[cfg(any(feature = "tun", test))]
    pub(crate) fn set_tun_device_ready(&self, name: String) {
        self.set_tun_device_name(Some(name.clone()));
        self.issue_event(GlobalCtxEvent::TunDeviceReady(name));
    }

    #[cfg(any(feature = "tun", test))]
    pub(crate) fn set_tun_device_error(&self, error: String) {
        self.set_tun_device_name(None);
        self.issue_event(GlobalCtxEvent::TunDeviceError(error));
    }

    pub fn get_tun_device_name(&self) -> Option<String> {
        self.tun_device_name.lock().unwrap().clone()
    }

    pub fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        let config = self.runtime_config_store.snapshot();
        if config.dhcp {
            self.applied_ipv4.load()
        } else {
            config.ipv4
        }
    }

    pub fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        self.runtime_config_store.snapshot().ipv6
    }

    pub fn applied_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        self.applied_ipv4.load()
    }

    pub fn set_applied_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.applied_ipv4.store(addr);
    }

    pub fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.get_ipv6().map(|x| x.address() == *ip).unwrap_or(false)
    }

    pub fn get_id(&self) -> uuid::Uuid {
        self.runtime_config_store.snapshot().instance_id
    }

    pub fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.contains(v4)).unwrap_or(false),
            IpAddr::V6(v6) => self.get_ipv6().map(|x| x.contains(v6)).unwrap_or(false),
        }
    }

    pub fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.address() == *v4).unwrap_or(false),
            IpAddr::V6(v6) => self.is_ip_local_ipv6(v6),
        }
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        self.runtime_config_store
            .snapshot()
            .network_identity
            .clone()
    }

    pub fn get_network_name(&self) -> String {
        self.get_network_identity().network_name
    }

    pub fn get_hostname(&self) -> String {
        self.runtime_config_store.snapshot().hostname.clone()
    }

    pub fn get_flags(&self) -> Flags {
        self.runtime_config_store.snapshot().flags.clone()
    }

    pub fn flags_arc(&self) -> Arc<Flags> {
        Arc::new(self.get_flags())
    }

    pub fn enable_exit_node(&self) -> bool {
        self.runtime_config_store.snapshot().flags.enable_exit_node || cfg!(target_env = "ohos")
    }

    pub fn proxy_forward_by_system(&self) -> bool {
        self.runtime_config_store
            .snapshot()
            .flags
            .proxy_forward_by_system
    }

    pub fn no_tun(&self) -> bool {
        self.runtime_config_store.snapshot().flags.no_tun
    }

    pub fn runtime_mapped_listeners(&self) -> Vec<url::Url> {
        let listeners = self
            .runtime_config_store
            .snapshot()
            .mapped_listeners
            .clone();
        let Some(protocols) = &self.runtime_endpoint_protocols else {
            return listeners;
        };
        listeners
            .into_iter()
            .filter(|listener| protocols.contains(&listener.scheme().to_ascii_lowercase()))
            .collect()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::common::config::TomlConfigLoader;
    use easytier_core::config::toml::ConfigLoader as _;

    use super::*;

    #[tokio::test]
    async fn test_global_ctx() {
        let global_ctx = get_mock_global_ctx();

        let mut subscriber = global_ctx.subscribe();
        let peer_id = rand::random();
        global_ctx.issue_event(GlobalCtxEvent::PeerAdded(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerRemoved(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default()));

        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerRemoved(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default())
        );
    }

    #[tokio::test]
    async fn test_tun_device_name_tracks_explicit_runtime_state() {
        let global_ctx = get_mock_global_ctx();

        assert_eq!(global_ctx.get_tun_device_name(), None);

        global_ctx.issue_event(GlobalCtxEvent::TunDeviceReady("ignored".to_string()));
        assert_eq!(global_ctx.get_tun_device_name(), None);

        let mut subscriber = global_ctx.subscribe();

        global_ctx.set_tun_device_ready("easytier0".to_string());
        assert_eq!(
            global_ctx.get_tun_device_name(),
            Some("easytier0".to_string())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::TunDeviceReady("easytier0".to_string())
        );

        global_ctx.set_tun_device_error("closed".to_string());
        assert_eq!(global_ctx.get_tun_device_name(), None);
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::TunDeviceError("closed".to_string())
        );
    }

    #[test]
    fn host_hostname_fallback_does_not_materialize_in_toml() {
        let config = TomlConfigLoader::default();
        let global_ctx = get_mock_global_ctx_with_config(config.clone());

        assert!(!global_ctx.get_hostname().is_empty());
        assert!(!config.dump().contains("hostname"));
    }

    #[test]
    fn active_dhcp_ipv4_survives_declarative_config_replacement() {
        let config = TomlConfigLoader::default();
        config.set_dhcp(true);
        let global_ctx = get_mock_global_ctx_with_config(config);
        let lease = "10.144.144.7/24".parse().unwrap();

        global_ctx.set_applied_ipv4(Some(lease));

        assert_eq!(global_ctx.get_ipv4(), Some(lease));
    }

    #[test]
    fn runtime_state_does_not_rewrite_toml_config() {
        let config = TomlConfigLoader::default();
        config.set_dhcp(true);
        let global_ctx = get_mock_global_ctx_with_config(config);

        global_ctx.set_applied_ipv4(Some("10.144.144.7/24".parse().unwrap()));

        assert_eq!(
            global_ctx.get_ipv4(),
            Some("10.144.144.7/24".parse().unwrap())
        );
        assert_eq!(global_ctx.runtime_config_store.snapshot().ipv4, None);
    }

    #[test]
    fn compact_runtime_does_not_advertise_unsupported_mapped_listeners() {
        let config = TomlConfigLoader::default();
        config.set_mapped_listeners(Some(vec![
            "tcp://127.0.0.1:11010".parse().unwrap(),
            "quic://127.0.0.1:11011".parse().unwrap(),
        ]));
        let host = crate::instance::config::compact_runtime_core_host_config();
        let snapshot = config.snapshot().unwrap();
        let prepared = easytier_core::instance::prepare_instance_config(snapshot, &host).unwrap();
        let store = InstanceConfigStore::new(prepared);

        let global_ctx = GlobalCtx::new(store, &host);

        assert_eq!(global_ctx.runtime_mapped_listeners().len(), 1);
        assert_eq!(global_ctx.runtime_mapped_listeners()[0].scheme(), "tcp");
    }

    #[tokio::test]
    async fn global_ctx_reads_hostname_and_flags_directly_from_runtime_config_store() {
        let config = TomlConfigLoader::new_from_str(
            r#"
hostname = "before"
[network_identity]
network_name = "test"
network_secret = "secret"
"#,
        )
        .unwrap();
        let instance = crate::instance::test_instance::TestInstance::new_with_process_runtime(
            config,
            easytier_core::process_runtime::CoreProcessRuntime::new(),
        );
        let global_ctx = instance.get_global_ctx();
        let core = instance.get_core_instance();

        assert_eq!(global_ctx.get_hostname(), "before");
        assert!(!global_ctx.get_flags().disable_relay_data);

        // Store updates via update_runtime_config must be immediately visible to GlobalCtx
        let mut raw = core.config_store().snapshot().raw().clone();
        raw.hostname = Some("after".to_owned());
        raw.flags.disable_relay_data = Some(true);
        let update = easytier_core::config::InstanceConfig::try_from(raw).unwrap();
        core.update_runtime_config(update).await.unwrap();

        assert_eq!(global_ctx.get_hostname(), "after");
        assert!(global_ctx.get_flags().disable_relay_data);
    }

    #[tokio::test]
    async fn updating_static_ipv4_and_ipv6_is_consistent_between_core_and_global_ctx() {
        let config = TomlConfigLoader::new_from_str(
            r#"
hostname = "addr-sync"
ipv4 = "10.144.144.1/24"
[network_identity]
network_name = "test"
network_secret = "secret"
"#,
        )
        .unwrap();
        let instance = crate::instance::test_instance::TestInstance::new_with_process_runtime(
            config,
            easytier_core::process_runtime::CoreProcessRuntime::new(),
        );
        let global_ctx = instance.get_global_ctx();
        let core = instance.get_core_instance();

        assert_eq!(
            global_ctx.get_ipv4(),
            Some("10.144.144.1/24".parse().unwrap())
        );

        let mut raw = core.config_store().snapshot().raw().clone();
        raw.ipv4 = Some("10.144.144.2/24".parse().unwrap());
        raw.ipv6 = Some("fd00::2/64".parse().unwrap());
        let update = easytier_core::config::InstanceConfig::try_from(raw).unwrap();
        core.update_runtime_config(update).await.unwrap();

        assert_eq!(
            global_ctx.get_ipv4(),
            Some("10.144.144.2/24".parse().unwrap())
        );
        assert_eq!(global_ctx.get_ipv6(), Some("fd00::2/64".parse().unwrap()));
        assert_eq!(
            core.config_store().snapshot().ipv4,
            Some("10.144.144.2/24".parse().unwrap())
        );
        assert_eq!(
            core.config_store().snapshot().ipv6,
            Some("fd00::2/64".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn management_patch_mapped_listeners_updates_runtime_mapped_listeners() {
        let config = TomlConfigLoader::new_from_str(
            r#"
hostname = "listeners-patch"
mapped_listeners = ["tcp://127.0.0.1:11010"]
[network_identity]
network_name = "test"
network_secret = "secret"
"#,
        )
        .unwrap();
        let mut instance = crate::instance::test_instance::TestInstance::new_with_process_runtime(
            config,
            easytier_core::process_runtime::CoreProcessRuntime::new(),
        );
        let global_ctx = instance.get_global_ctx();
        assert_eq!(global_ctx.runtime_mapped_listeners().len(), 1);

        instance.run().await.unwrap();
        let patcher = instance.get_config_patcher();
        let patch = crate::proto::api::config::InstanceConfigPatch {
            mapped_listeners: vec![crate::proto::api::config::UrlPatch {
                action: crate::proto::api::config::ConfigPatchAction::Add.into(),
                url: Some("tcp://127.0.0.1:11012".parse::<url::Url>().unwrap().into()),
            }],
            ..Default::default()
        };
        patcher.apply_patch(patch).await.unwrap();

        assert_eq!(global_ctx.runtime_mapped_listeners().len(), 2);
        instance.clear_resources().await;
    }

    #[test]
    fn get_flags_is_consistent_with_convenience_getters() {
        let config = TomlConfigLoader::default();
        let mut flags = config.get_flags();
        flags.enable_exit_node = true;
        flags.proxy_forward_by_system = true;
        flags.no_tun = true;
        config.set_flags(flags);

        let global_ctx = get_mock_global_ctx_with_config(config);
        let gflags = global_ctx.get_flags();

        assert_eq!(gflags.enable_exit_node, global_ctx.enable_exit_node());
        assert_eq!(
            gflags.proxy_forward_by_system,
            global_ctx.proxy_forward_by_system()
        );
        assert_eq!(gflags.no_tun, global_ctx.no_tun());
    }

    #[test]
    fn modifying_hostname_retains_raw_fields_ignored_by_host() {
        let mut raw = easytier_core::config::InstanceConfigRaw::default();
        raw.hostname = Some("original".to_string());
        raw.network_identity = Some(NetworkIdentity::new("test".into(), "secret".into()));
        raw.proxy_network = Some(vec![easytier_core::config::toml::ProxyNetworkConfig {
            cidr: "10.1.2.0/24".parse().unwrap(),
            mapped_cidr: None,
            allow: None,
        }]);

        raw.hostname = Some("renamed".to_string());
        let candidate = easytier_core::config::InstanceConfig::try_from(raw).unwrap();

        assert_eq!(candidate.parsed().hostname, "renamed");
        assert_eq!(candidate.raw().proxy_network.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn secure_mode_default_admin_identity_preserved_across_serialization_and_reload() {
        let config = TomlConfigLoader::new_from_str(
            r#"
[secure_mode]
enabled = true
"#,
        )
        .unwrap();

        let snapshot = config.snapshot().unwrap();
        assert!(snapshot.parsed().network_identity.network_secret.is_some());
        assert_eq!(
            snapshot.parsed().network_identity.network_secret.as_deref(),
            Some("")
        );
        assert_eq!(snapshot.raw().network_identity, None);

        let mut raw = snapshot.raw().clone();
        raw.hostname = Some("new-host".to_string());
        let updated = easytier_core::config::InstanceConfig::try_from(raw).unwrap();

        assert_eq!(
            updated.parsed().network_identity.network_secret.as_deref(),
            Some("")
        );
        assert_eq!(updated.raw().network_identity, None);
    }

    #[tokio::test]
    async fn dhcp_allocated_address_not_overwritten_by_runtime_update_and_failure_returns_actual() {
        let config = TomlConfigLoader::new_from_str(
            r#"
hostname = "dhcp-node"
dhcp = true
[network_identity]
network_name = "test"
network_secret = "secret"
"#,
        )
        .unwrap();
        let instance = crate::instance::test_instance::TestInstance::new_with_process_runtime(
            config,
            easytier_core::process_runtime::CoreProcessRuntime::new(),
        );
        let global_ctx = instance.get_global_ctx();
        let core = instance.get_core_instance();

        let lease: cidr::Ipv4Inet = "10.144.144.99/24".parse().unwrap();
        global_ctx.set_applied_ipv4(Some(lease));
        assert_eq!(global_ctx.get_ipv4(), Some(lease));

        let mut raw = core.config_store().snapshot().raw().clone();
        raw.hostname = Some("renamed-dhcp-node".to_string());
        let update = easytier_core::config::InstanceConfig::try_from(raw).unwrap();
        core.update_runtime_config(update).await.unwrap();

        assert_eq!(global_ctx.get_hostname(), "renamed-dhcp-node");
        assert_eq!(global_ctx.get_ipv4(), Some(lease));
        assert_eq!(global_ctx.applied_ipv4(), Some(lease));
    }

    #[test]
    fn windows_auto_device_name_does_not_pollute_config() {
        let config = TomlConfigLoader::new_from_str(
            r#"
hostname = "win-tun-test"
[network_identity]
network_name = "test"
network_secret = "secret"
"#,
        )
        .unwrap();
        let global_ctx = get_mock_global_ctx_with_config(config);

        assert_eq!(global_ctx.get_flags().dev_name, "");
        assert_eq!(
            global_ctx.runtime_config_store.snapshot().flags.dev_name,
            ""
        );
    }

    pub fn get_mock_global_ctx_with_config(config: TomlConfigLoader) -> ArcGlobalCtx {
        let host = crate::instance::config::runtime_core_host_config();
        let snapshot = config.snapshot().unwrap();
        let prepared = easytier_core::instance::prepare_instance_config(snapshot, &host).unwrap();
        let store = InstanceConfigStore::new(prepared);
        Arc::new(GlobalCtx::new(store, &host))
    }

    pub fn get_mock_global_ctx_with_network(
        network_identy: Option<NetworkIdentity>,
    ) -> ArcGlobalCtx {
        let config_fs = TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));
        config_fs.set_network_identity(network_identy.unwrap_or_default());
        get_mock_global_ctx_with_config(config_fs)
    }

    pub fn get_mock_global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(None)
    }
}
