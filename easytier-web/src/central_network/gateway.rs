//! Applies Gateway-mode central-network intents to native runtimes.
//!
//! Runtime ownership follows the immutable central-network ID. Mesh names are
//! only a secondary lookup used by the shared config-server listener.

pub mod listener;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use base64::Engine as _;
use easytier::{
    common::config::{ConfigLoader as _, NetworkIdentity, TomlConfigLoader},
    instance::factory::{NativeCoreInstance, create_native_instance},
    tunnel::IpScheme,
};
use easytier_core::{
    config::toml::ManagedCredentialConfig,
    peers::{error::Error as PeerError, peer_manager::PeerManagerCore},
    tunnel::Tunnel,
};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::central_network::model::{CentralNetworkIntent, NetworkMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub peer_url: String,
    pub relay_data: bool,
}

impl GatewayConfig {
    pub fn validate(&self, listener_protocol: &str) -> anyhow::Result<()> {
        let peer_url: url::Url = self
            .peer_url
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid gateway peer URL: {error}"))?;
        let listener_protocol = listener_protocol.to_ascii_lowercase();
        let listener_scheme: IpScheme = listener_protocol.parse().map_err(|_| {
            anyhow::anyhow!("unsupported config server protocol: {listener_protocol}")
        })?;
        if !matches!(
            listener_scheme,
            IpScheme::Tcp | IpScheme::Udp | IpScheme::Ws
        ) {
            anyhow::bail!("unsupported config server protocol: {listener_protocol}");
        }
        let scheme_matches = match listener_scheme {
            IpScheme::Ws => matches!(peer_url.scheme(), "ws" | "wss"),
            _ => peer_url.scheme() == listener_protocol,
        };
        if !scheme_matches {
            anyhow::bail!(
                "gateway peer URL scheme ({}) does not match config server protocol ({listener_protocol})",
                peer_url.scheme()
            );
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GatewayRuntimeSpec {
    network_id: Uuid,
    user_id: i32,
    mesh_name: String,
    network_secret: String,
    secure_mode: bool,
    relay_data: bool,
    credentials: Vec<ManagedCredentialConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GatewayRuntimeKey {
    user_id: i32,
    network_id: Uuid,
}

impl GatewayRuntimeKey {
    fn from_intent(intent: &CentralNetworkIntent) -> Self {
        Self {
            user_id: intent.user_id,
            network_id: intent.id,
        }
    }
}

impl GatewayRuntimeSpec {
    fn from_intent(intent: &CentralNetworkIntent, relay_data: bool) -> Self {
        let mut credentials = intent
            .credentials
            .iter()
            .map(|credential| ManagedCredentialConfig {
                credential_id: credential.id.clone(),
                credential_secret: credential.secret.clone(),
                groups: credential.grant.acl_groups.clone(),
                allow_relay: credential.grant.allow_relay,
                allowed_proxy_cidrs: credential.grant.allowed_proxy_cidrs.clone(),
                expiry_unix: credential.expiry_unix,
                reusable: credential.grant.reusable,
            })
            .collect::<Vec<_>>();
        credentials.sort_by(|left, right| left.credential_id.cmp(&right.credential_id));
        Self {
            network_id: intent.id,
            user_id: intent.user_id,
            mesh_name: intent.network_name.clone(),
            network_secret: intent.network_secret.clone(),
            secure_mode: intent.secure_mode,
            relay_data,
            credentials,
        }
    }
}

#[async_trait]
pub(crate) trait GatewayRuntime: Send + Sync {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
    fn peer_manager(&self) -> Option<Arc<PeerManagerCore>>;

    async fn observe_network(&self) -> Option<GatewayNetworkObservation> {
        let peer_manager = self.peer_manager()?;
        Some(observe_peer_manager(&peer_manager).await)
    }
}

pub(crate) trait GatewayRuntimeFactory: Send + Sync {
    fn build(&self, spec: &GatewayRuntimeSpec) -> anyhow::Result<Arc<dyn GatewayRuntime>>;
}

struct NativeGatewayRuntime(Arc<NativeCoreInstance>);

#[async_trait]
impl GatewayRuntime for NativeGatewayRuntime {
    async fn start(&self) -> anyhow::Result<()> {
        self.0.start().await
    }

    async fn stop(&self) {
        self.0.stop().await;
    }

    fn peer_manager(&self) -> Option<Arc<PeerManagerCore>> {
        Some(self.0.peer_manager().clone())
    }
}

#[derive(Default)]
struct NativeGatewayRuntimeFactory;

impl GatewayRuntimeFactory for NativeGatewayRuntimeFactory {
    fn build(&self, spec: &GatewayRuntimeSpec) -> anyhow::Result<Arc<dyn GatewayRuntime>> {
        let config = TomlConfigLoader::default();
        config.set_inst_name(format!(
            "easytier-web-gw-{}-{}",
            spec.user_id, spec.network_id
        ));
        config.set_hostname(Some(hostname_or_default()));
        config.set_network_identity(NetworkIdentity::new(
            spec.mesh_name.clone(),
            spec.network_secret.clone(),
        ));
        config.set_dhcp(false);
        config.set_listeners(vec![]);

        let mut flags = config.get_flags();
        flags.no_tun = true;
        flags.disable_relay_data = !spec.relay_data;
        flags.bind_device = false;
        config.set_flags(flags);

        if spec.secure_mode {
            let private = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let public = x25519_dalek::PublicKey::from(&private);
            config.set_secure_mode(Some(easytier::proto::common::SecureModeConfig {
                enabled: true,
                local_private_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(private.as_bytes()),
                ),
                local_public_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
                ),
            }));
        }
        config.set_managed_credentials(spec.credentials.clone());
        Ok(Arc::new(NativeGatewayRuntime(create_native_instance(
            config,
        )?)))
    }
}

struct PublishedRuntime {
    spec: GatewayRuntimeSpec,
    runtime: Arc<dyn GatewayRuntime>,
    retiring: CancellationToken,
    admissions: Arc<RwLock<()>>,
}

#[derive(Default)]
struct State {
    by_key: HashMap<GatewayRuntimeKey, PublishedRuntime>,
    mesh_name_to_key: HashMap<String, GatewayRuntimeKey>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct GatewayNetworkObservation {
    pub connections: Vec<easytier_proto::core_peer::peer::PeerConnInfo>,
    pub routes: Vec<easytier_proto::core_peer::peer::Route>,
}

pub struct NetworkInstanceManager {
    config: GatewayConfig,
    factory: Arc<dyn GatewayRuntimeFactory>,
    state: RwLock<State>,
    lifecycle: Mutex<()>,
}

impl std::fmt::Debug for NetworkInstanceManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkInstanceManager")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl NetworkInstanceManager {
    pub fn new(config: GatewayConfig) -> Self {
        Self::with_factory(config, Arc::new(NativeGatewayRuntimeFactory))
    }

    pub(crate) fn with_factory(
        config: GatewayConfig,
        factory: Arc<dyn GatewayRuntimeFactory>,
    ) -> Self {
        Self {
            config,
            factory,
            state: RwLock::new(State::default()),
            lifecycle: Mutex::new(()),
        }
    }

    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub async fn reconcile(&self, intent: &CentralNetworkIntent) {
        let _lifecycle = self.lifecycle.lock().await;
        self.reconcile_locked(intent).await;
    }

    async fn reconcile_locked(&self, intent: &CentralNetworkIntent) {
        let key = GatewayRuntimeKey::from_intent(intent);
        if !matches!(intent.mode, NetworkMode::Gateway { .. }) {
            self.remove_locked(key).await;
            return;
        }

        let spec = GatewayRuntimeSpec::from_intent(intent, self.config.relay_data);
        {
            let state = self.state.write().await;
            if state
                .by_key
                .get(&key)
                .is_some_and(|published| published.spec == spec)
            {
                return;
            }
        }

        self.remove_locked(key).await;
        let mesh_owner = {
            let state = self.state.read().await;
            state.mesh_name_to_key.get(&spec.mesh_name).copied()
        };
        if let Some(owner) = mesh_owner {
            tracing::error!(
                user_id = key.user_id,
                network_id = %key.network_id,
                mesh_name = %spec.mesh_name,
                owner_user_id = owner.user_id,
                owner_network_id = %owner.network_id,
                "Gateway mesh name is already owned"
            );
            return;
        }

        let candidate = match self.factory.build(&spec) {
            Ok(candidate) => candidate,
            Err(error) => {
                tracing::error!(
                    user_id = key.user_id,
                    network_id = %key.network_id,
                    "failed to build Gateway runtime: {error:#}"
                );
                return;
            }
        };
        if let Err(error) = candidate.start().await {
            candidate.stop().await;
            tracing::error!(
                user_id = key.user_id,
                network_id = %key.network_id,
                "failed to start Gateway runtime: {error:#}"
            );
            return;
        }

        {
            let mut state = self.state.write().await;
            state.mesh_name_to_key.insert(spec.mesh_name.clone(), key);
            state.by_key.insert(
                key,
                PublishedRuntime {
                    spec,
                    runtime: candidate,
                    retiring: CancellationToken::new(),
                    admissions: Arc::new(RwLock::new(())),
                },
            );
        }
    }

    pub(crate) async fn network_ids(&self) -> Vec<(i32, Uuid)> {
        self.state
            .read()
            .await
            .by_key
            .keys()
            .map(|key| (key.user_id, key.network_id))
            .collect()
    }

    pub async fn remove(&self, user_id: i32, network_id: Uuid) {
        let _lifecycle = self.lifecycle.lock().await;
        self.remove_locked(GatewayRuntimeKey {
            user_id,
            network_id,
        })
        .await;
    }

    async fn remove_locked(&self, key: GatewayRuntimeKey) {
        let retired = {
            let mut state = self.state.write().await;
            let retired = state.by_key.remove(&key);
            if let Some(retired) = retired.as_ref()
                && state.mesh_name_to_key.get(&retired.spec.mesh_name) == Some(&key)
            {
                state.mesh_name_to_key.remove(&retired.spec.mesh_name);
            }
            retired
        };
        if let Some(retired) = retired {
            retired.retiring.cancel();
            // Drain cancelled handshakes before stopping the runtime so none
            // can publish a connection after shutdown.
            let _admissions = retired.admissions.write().await;
            retired.runtime.stop().await;
        }
    }

    pub async fn accept_peer_tunnel(
        &self,
        mesh_name: &str,
        tunnel: Box<dyn Tunnel>,
    ) -> Option<Result<(), PeerError>> {
        let state = self.state.read().await;
        let key = state.mesh_name_to_key.get(mesh_name)?;
        let published = state.by_key.get(key)?;
        let peer_manager = published.runtime.peer_manager()?;
        let retiring = published.retiring.clone();
        let _admission = published.admissions.clone().read_owned().await;
        drop(state);
        tokio::select! {
            biased;
            _ = retiring.cancelled() => None,
            result = peer_manager.add_tunnel_as_server(tunnel) => Some(result),
        }
    }

    /// Snapshot a Gateway runtime only when both the tenant and immutable
    /// central-network ID match the published owner.
    pub(crate) async fn observe_network(
        &self,
        user_id: i32,
        network_id: Uuid,
    ) -> Option<GatewayNetworkObservation> {
        let key = GatewayRuntimeKey {
            user_id,
            network_id,
        };
        let runtime = {
            let state = self.state.read().await;
            let published = state.by_key.get(&key)?;
            published.runtime.clone()
        };
        runtime.observe_network().await
    }

    #[cfg(test)]
    pub(crate) async fn actual_mesh_name(&self, user_id: i32, network_id: Uuid) -> Option<String> {
        let key = GatewayRuntimeKey {
            user_id,
            network_id,
        };
        self.state
            .read()
            .await
            .by_key
            .get(&key)
            .map(|runtime| runtime.spec.mesh_name.clone())
    }

    #[cfg(test)]
    async fn runtime_ids(&self) -> Vec<Uuid> {
        let mut ids = self
            .state
            .read()
            .await
            .by_key
            .keys()
            .map(|key| key.network_id)
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }

    #[cfg(test)]
    async fn network_id_for_mesh(&self, mesh_name: &str) -> Option<Uuid> {
        self.state
            .read()
            .await
            .mesh_name_to_key
            .get(mesh_name)
            .map(|key| key.network_id)
    }
}

async fn observe_peer_manager(peer_manager: &PeerManagerCore) -> GatewayNetworkObservation {
    let mut observation = GatewayNetworkObservation::default();
    for peer in peer_manager.list_peer_snapshots().await {
        observation.connections.extend(peer.conns);
    }
    observation.routes = peer_manager.list_route_snapshots().await;
    observation
}

fn hostname_or_default() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|hostname| hostname.trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "easytier-web-gateway".to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use uuid::Uuid;

    use crate::central_network::model::{
        CentralNetworkIntent, CredentialGrant, NetworkCredentialIntent, NetworkMode,
    };

    use super::*;

    #[derive(Default)]
    struct FakeFactory {
        built: Mutex<Vec<GatewayRuntimeSpec>>,
        fail_next: Mutex<bool>,
        fail_start_next: Mutex<bool>,
        stopped: Arc<Mutex<Vec<Uuid>>>,
    }

    struct FakeRuntime {
        id: Uuid,
        fail_start: bool,
        stopped: Arc<Mutex<Vec<Uuid>>>,
    }

    #[async_trait]
    impl GatewayRuntime for FakeRuntime {
        async fn start(&self) -> anyhow::Result<()> {
            if self.fail_start {
                anyhow::bail!("injected start failure");
            }
            Ok(())
        }

        async fn stop(&self) {
            self.stopped.lock().unwrap().push(self.id);
        }

        fn peer_manager(&self) -> Option<Arc<easytier_core::peers::peer_manager::PeerManagerCore>> {
            None
        }

        async fn observe_network(&self) -> Option<GatewayNetworkObservation> {
            Some(GatewayNetworkObservation::default())
        }
    }

    impl GatewayRuntimeFactory for FakeFactory {
        fn build(&self, spec: &GatewayRuntimeSpec) -> anyhow::Result<Arc<dyn GatewayRuntime>> {
            self.built.lock().unwrap().push(spec.clone());
            if std::mem::take(&mut *self.fail_next.lock().unwrap()) {
                anyhow::bail!("injected build failure");
            }
            Ok(Arc::new(FakeRuntime {
                id: spec.network_id,
                fail_start: std::mem::take(&mut *self.fail_start_next.lock().unwrap()),
                stopped: self.stopped.clone(),
            }))
        }
    }

    fn gateway_intent(id: Uuid, mesh_name: &str) -> CentralNetworkIntent {
        CentralNetworkIntent {
            id,
            user_id: 7,
            display_name: mesh_name.to_owned(),
            network_name: mesh_name.to_owned(),
            network_secret: "secret".to_owned(),
            mode: NetworkMode::Gateway {
                peer_url: "tcp://gateway.example:22020".to_owned(),
            },
            virtual_cidr: None,
            secure_mode: false,
            members: Vec::new(),
            credentials: Vec::new(),
            acl_policy: None,
        }
    }

    fn manager(factory: Arc<FakeFactory>) -> NetworkInstanceManager {
        NetworkInstanceManager::with_factory(
            GatewayConfig {
                peer_url: "tcp://gateway.example:22020".to_owned(),
                relay_data: false,
            },
            factory,
        )
    }

    #[tokio::test]
    async fn stalled_admission_does_not_block_reconcile_and_is_cancelled_on_removal() {
        use easytier_core::tunnel::ring::create_ring_tunnel_pair;
        use std::time::Duration;
        let manager = Arc::new(NetworkInstanceManager::new(GatewayConfig {
            peer_url: "tcp://localhost:22020".into(),
            relay_data: true,
        }));
        let intent = gateway_intent(Uuid::new_v4(), "stalled-admission");
        manager.reconcile(&intent).await;
        let (server, _client) = create_ring_tunnel_pair();
        let accepting = {
            let manager = manager.clone();
            tokio::spawn(async move {
                manager
                    .accept_peer_tunnel("stalled-admission", server)
                    .await
            })
        };
        // Wait until the real peer handshake holds the runtime admission lease.
        let admissions = manager
            .state
            .read()
            .await
            .by_key
            .get(&GatewayRuntimeKey::from_intent(&intent))
            .unwrap()
            .admissions
            .clone();
        tokio::time::timeout(Duration::from_secs(1), async {
            while admissions.try_write().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let other = gateway_intent(Uuid::new_v4(), "unrelated-network");
        tokio::time::timeout(Duration::from_secs(2), manager.reconcile(&other))
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            manager.remove(intent.user_id, intent.id),
        )
        .await
        .unwrap();
        assert!(accepting.await.unwrap().is_none());
        assert!(
            manager
                .actual_mesh_name(intent.user_id, intent.id)
                .await
                .is_none()
        );
        manager.remove(other.user_id, other.id).await;
    }

    #[tokio::test]
    async fn state_is_keyed_by_immutable_network_id_and_rename_replaces_index() {
        let factory = Arc::new(FakeFactory::default());
        let manager = manager(factory.clone());
        let id = Uuid::new_v4();
        let first = gateway_intent(id, "mesh-one");
        manager.reconcile(&first).await;

        let mut renamed = first;
        renamed.network_name = "mesh-two".to_owned();
        manager.reconcile(&renamed).await;

        assert_eq!(manager.runtime_ids().await, vec![id]);
        assert_eq!(manager.network_id_for_mesh("mesh-one").await, None);
        assert_eq!(manager.network_id_for_mesh("mesh-two").await, Some(id));
        assert_eq!(factory.stopped.lock().unwrap().as_slice(), &[id]);
    }

    #[tokio::test]
    async fn observation_requires_the_published_tenant_and_network_id() {
        let factory = Arc::new(FakeFactory::default());
        let manager = manager(factory);
        let id = Uuid::new_v4();
        manager.reconcile(&gateway_intent(id, "mesh")).await;

        assert!(manager.observe_network(7, id).await.is_some());
        assert!(manager.observe_network(8, id).await.is_none());
        assert!(manager.observe_network(7, Uuid::new_v4()).await.is_none());
    }

    #[tokio::test]
    async fn mode_switch_and_delete_remove_runtime_by_id() {
        let factory = Arc::new(FakeFactory::default());
        let manager = manager(factory.clone());
        let id = Uuid::new_v4();
        let mut intent = gateway_intent(id, "mesh");
        manager.reconcile(&intent).await;

        intent.mode = NetworkMode::Standalone;
        manager.reconcile(&intent).await;
        assert!(manager.runtime_ids().await.is_empty());

        manager.reconcile(&gateway_intent(id, "mesh-again")).await;
        manager.remove(7, id).await;
        assert!(manager.runtime_ids().await.is_empty());
        assert_eq!(factory.stopped.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failed_replacement_retires_old_runtime_and_records_error() {
        let factory = Arc::new(FakeFactory::default());
        let manager = manager(factory.clone());
        let id = Uuid::new_v4();
        manager.reconcile(&gateway_intent(id, "stable")).await;

        *factory.fail_next.lock().unwrap() = true;
        manager.reconcile(&gateway_intent(id, "desired")).await;

        assert_eq!(manager.network_id_for_mesh("stable").await, None);
        assert_eq!(manager.network_id_for_mesh("desired").await, None);
        assert_eq!(factory.stopped.lock().unwrap().as_slice(), &[id]);
    }

    #[tokio::test]
    async fn failed_start_retires_old_runtime() {
        let factory = Arc::new(FakeFactory::default());
        let manager = manager(factory.clone());
        let id = Uuid::new_v4();
        manager.reconcile(&gateway_intent(id, "stable")).await;

        *factory.fail_start_next.lock().unwrap() = true;
        manager.reconcile(&gateway_intent(id, "desired")).await;

        assert_eq!(manager.network_id_for_mesh("stable").await, None);
        assert_eq!(manager.network_id_for_mesh("desired").await, None);
        assert_eq!(factory.stopped.lock().unwrap().as_slice(), &[id, id]);
    }

    #[tokio::test]
    async fn mesh_name_conflict_retires_old_runtime() {
        let factory = Arc::new(FakeFactory::default());
        let manager = manager(factory.clone());
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        manager.reconcile(&gateway_intent(first_id, "stable")).await;
        manager
            .reconcile(&gateway_intent(second_id, "occupied"))
            .await;

        manager
            .reconcile(&gateway_intent(first_id, "occupied"))
            .await;

        assert_eq!(manager.network_id_for_mesh("stable").await, None);
        assert_eq!(
            manager.network_id_for_mesh("occupied").await,
            Some(second_id)
        );
        assert_eq!(factory.stopped.lock().unwrap().as_slice(), &[first_id]);
    }

    #[tokio::test]
    async fn maps_full_grants_without_filtering_expired_credentials() {
        let factory = Arc::new(FakeFactory::default());
        let manager = manager(factory.clone());
        let mut intent = gateway_intent(Uuid::new_v4(), "mesh");
        intent.credentials.push(NetworkCredentialIntent {
            id: "expired-but-core-owned".to_owned(),
            secret: "credential-secret".to_owned(),
            expiry_unix: 1,
            grant: CredentialGrant {
                acl_groups: vec!["member:one".to_owned(), "ops".to_owned()],
                allow_relay: false,
                allowed_proxy_cidrs: vec!["10.0.0.0/8".to_owned()],
                reusable: false,
            },
        });

        manager.reconcile(&intent).await;

        let built = factory.built.lock().unwrap();
        assert_eq!(built[0].credentials.len(), 1);
        let credential = &built[0].credentials[0];
        assert_eq!(credential.groups, vec!["member:one", "ops"]);
        assert!(!credential.allow_relay);
        assert_eq!(credential.allowed_proxy_cidrs, vec!["10.0.0.0/8"]);
        assert_eq!(credential.expiry_unix, 1);
        assert!(!credential.reusable);
    }

    #[test]
    fn gateway_peer_url_scheme_must_match_listener_protocol() {
        let tcp = GatewayConfig {
            peer_url: "tcp://gateway.example:22020".to_owned(),
            relay_data: false,
        };
        assert!(tcp.validate("tcp").is_ok());
        assert!(tcp.validate("udp").is_err());
        assert!(tcp.validate("unknown").is_err());

        let secure_websocket = GatewayConfig {
            peer_url: "wss://gateway.example/mesh".to_owned(),
            relay_data: false,
        };
        assert!(secure_websocket.validate("ws").is_ok());
    }
}
