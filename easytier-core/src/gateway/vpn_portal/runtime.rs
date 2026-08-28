//! Protocol-neutral portal session orchestration.
//!
//! Native adapters authenticate clients and yield sessions. This module owns
//! configured client identities, attached-peer lifetimes, per-client
//! generations, and raw IPv4 packet forwarding at the Host packet seam.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, RwLock as StdRwLock},
};

use async_trait::async_trait;
use cidr::Ipv4Inet;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, RwLock, mpsc, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::runtime::{CoreInstanceRuntimeConfig, CoreRuntimeConfigStore},
    events::{CoreEvent, CoreEventSink},
    peers::{
        attached::{AttachedPeerConfig, AttachedPeerRuntime},
        peer_manager::PeerManagerCore,
    },
    socket::SocketListener,
};

pub const MAX_VPN_PORTAL_CLIENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalClientConfig {
    pub name: String,
    pub virtual_ip: Ipv4Inet,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalRuntimeConfig {
    pub clients: Vec<PortalClientConfig>,
}

/// One authenticated protocol session produced by a native portal adapter. A
/// new value is emitted only for a new authenticated client generation;
/// ordinary reauthentication and endpoint roaming stay within that adapter.
/// The endpoint watch exposes the current authenticated endpoint and any later
/// roaming within the generation. Packet channels carry complete raw IPv4
/// packets without protocol framing.
pub struct PortalSession {
    pub client_name: String,
    pub endpoint: watch::Receiver<String>,
    pub identity_private_key: [u8; 32],
    pub from_client: mpsc::Receiver<Vec<u8>>,
    pub to_client: mpsc::Sender<Vec<u8>>,
}

impl std::fmt::Debug for PortalSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let endpoint = self.endpoint.borrow();
        formatter
            .debug_struct("PortalSession")
            .field("client_name", &self.client_name)
            .field("endpoint", &endpoint.as_str())
            .finish_non_exhaustive()
    }
}

pub type PortalListener = Box<dyn SocketListener<Accepted = PortalSession>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalClientConfigPlan {
    pub name: String,
    pub address: Ipv4Addr,
    pub allowed_ips: Vec<String>,
    pub listener_url: url::Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalClientState {
    Offline,
    Connecting,
    Online,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalClientInfoSnapshot {
    pub name: String,
    pub virtual_ip: Ipv4Addr,
    pub groups: Vec<String>,
    pub state: PortalClientState,
    pub peer_id: Option<u32>,
    pub endpoint: Option<String>,
    pub tunnel_ip: Option<Ipv4Addr>,
    pub client_config: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalInfoSnapshot {
    pub vpn_type: String,
    pub clients: Vec<PortalClientInfoSnapshot>,
    pub listener: Option<String>,
}

#[async_trait]
pub trait PortalHost: Send + Sync + 'static {
    /// Starts the shared protocol engines. Core owns accepted generations and
    /// all portable attached-peer lifecycle after this seam.
    async fn start_listeners(&self) -> anyhow::Result<Vec<PortalListener>>;

    fn name(&self) -> String;

    fn render_client_config(&self, plan: &PortalClientConfigPlan) -> String;

    /// Replaces the configured client set at runtime without restarting the
    /// listeners. Established sessions of untouched clients must stay intact;
    /// sessions of removed or changed clients are torn down through the
    /// regular channel-close cleanup path.
    async fn update_clients(&self, clients: &[PortalClientConfig]) -> anyhow::Result<()> {
        let _ = clients;
        anyhow::bail!("portal host does not support runtime client updates")
    }
}

#[derive(Debug, Clone)]
struct ClientStatus {
    state: PortalClientState,
    generation: u64,
    peer_id: Option<u32>,
    endpoint: Option<String>,
    tunnel_ip: Option<Ipv4Addr>,
    error: Option<String>,
}

impl Default for ClientStatus {
    fn default() -> Self {
        Self {
            state: PortalClientState::Offline,
            generation: 0,
            peer_id: None,
            endpoint: None,
            tunnel_ip: None,
            error: None,
        }
    }
}

struct PortalRuntime {
    cancel: CancellationToken,
    tasks: JoinSet<()>,
    listener_urls: Vec<url::Url>,
}

pub struct PortalModule {
    operation: Mutex<()>,
    peer_manager: Arc<PeerManagerCore>,
    runtime_config: CoreRuntimeConfigStore,
    config: Option<Arc<StdRwLock<PortalRuntimeConfig>>>,
    host: Option<Arc<dyn PortalHost>>,
    events: Arc<dyn CoreEventSink>,
    statuses: Arc<RwLock<BTreeMap<String, ClientStatus>>>,
    session_locks: Arc<RwLock<BTreeMap<String, Arc<Mutex<()>>>>>,
    runtime: Mutex<Option<PortalRuntime>>,
}

impl PortalModule {
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        config: Option<PortalRuntimeConfig>,
        host: Option<Arc<dyn PortalHost>>,
        events: Arc<dyn CoreEventSink>,
    ) -> anyhow::Result<Arc<Self>> {
        if let Some(config) = config.as_ref() {
            validate_clients(config, runtime_config.snapshot().as_ref())?;
        }
        Ok(Arc::new(Self {
            operation: Mutex::new(()),
            peer_manager,
            runtime_config,
            config: config.map(|config| Arc::new(StdRwLock::new(config))),
            host,
            events,
            statuses: Arc::new(RwLock::new(BTreeMap::new())),
            session_locks: Arc::new(RwLock::new(BTreeMap::new())),
            runtime: Mutex::new(None),
        }))
    }
    #[cfg(feature = "vpn-portal")]
    pub(crate) fn validate_runtime_config(
        &self,
        runtime_config: &CoreInstanceRuntimeConfig,
    ) -> anyhow::Result<()> {
        let Some(config) = self.config.as_ref() else {
            return Ok(());
        };
        let config = config.read().unwrap();
        validate_runtime_compatibility(&config, runtime_config)
    }

    /// Replaces the configured client set at runtime. Untouched clients keep
    /// their established sessions; removed and changed clients are torn down
    /// through the regular cleanup path and may re-handshake afterwards.
    ///
    /// The caller supplies the runtime snapshot the new set must be validated
    /// against, so a combined configuration patch is judged by its final
    /// state rather than the currently running one.
    pub async fn update_clients(
        &self,
        clients: Vec<PortalClientConfig>,
        runtime: &CoreInstanceRuntimeConfig,
    ) -> anyhow::Result<Vec<PortalClientConfig>> {
        let _operation = self.operation.lock().await;
        let Some(config) = self.config.as_ref() else {
            anyhow::bail!("VPN portal is not configured");
        };
        if self.host.is_none() {
            anyhow::bail!("VPN portal has no host adapter");
        }
        let candidate = PortalRuntimeConfig { clients };
        validate_clients(&candidate, runtime)?;

        self.host
            .as_ref()
            .expect("checked above")
            .update_clients(&candidate.clients)
            .await?;

        let applied: BTreeSet<String> = candidate
            .clients
            .iter()
            .map(|client| client.name.clone())
            .collect();
        let removed: Vec<String> = {
            let mut current = config.write().unwrap();
            let removed: Vec<String> = current
                .clients
                .iter()
                .map(|client| client.name.clone())
                .filter(|name| !applied.contains(name))
                .collect();
            current.clients = candidate.clients.clone();
            removed
        };
        let applied_clients = candidate.clients;

        {
            let mut statuses = self.statuses.write().await;
            statuses.retain(|name, _| applied.contains(name));
            for name in applied {
                statuses.entry(name).or_default();
            }
        }
        {
            let mut locks = self.session_locks.write().await;
            for name in removed {
                // Entries still held by a live session are left alone; the
                // session drops its reference during its regular cleanup.
                if locks
                    .get(&name)
                    .is_none_or(|lock| Arc::strong_count(lock) == 1)
                {
                    locks.remove(&name);
                }
            }
        }
        Ok(applied_clients)
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.config.is_none() {
            return Ok(());
        }
        let stale_runtime = {
            let mut runtime = self.runtime.lock().await;
            if runtime
                .as_ref()
                .is_some_and(|runtime| !runtime.cancel.is_cancelled())
            {
                return Ok(());
            }
            runtime.take()
        };
        if let Some(stale_runtime) = stale_runtime {
            self.shutdown_runtime(stale_runtime).await;
        }

        let host = self.host.as_ref().ok_or_else(|| {
            anyhow::anyhow!("VPN portal is configured but no host adapter exists")
        })?;
        let listeners = host.start_listeners().await?;
        if listeners.is_empty() {
            anyhow::bail!("VPN portal host returned no active listeners");
        }

        let mut prepared = Vec::with_capacity(listeners.len());
        for mut listener in listeners {
            listener.listen().await?;
            let listener_url = listener.local_url();
            prepared.push((listener, listener_url));
        }

        let cancel = CancellationToken::new();
        let start_signal = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let mut listener_urls = Vec::with_capacity(prepared.len());
        for (listener, listener_url) in prepared {
            listener_urls.push(listener_url.clone());
            tasks.spawn(Self::run_listener(
                listener,
                listener_url,
                self.peer_manager.clone(),
                self.runtime_config.clone(),
                self.config.clone().expect("checked above"),
                self.statuses.clone(),
                self.session_locks.clone(),
                self.events.clone(),
                cancel.clone(),
                start_signal.clone(),
            ));
        }
        *self.runtime.lock().await = Some(PortalRuntime {
            cancel,
            tasks,
            listener_urls: listener_urls.clone(),
        });
        for local_url in &listener_urls {
            self.events
                .emit(CoreEvent::VpnPortalStarted(local_url.to_string()));
        }
        start_signal.cancel();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_listener(
        mut listener: PortalListener,
        listener_url: url::Url,
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        config: Arc<StdRwLock<PortalRuntimeConfig>>,
        statuses: Arc<RwLock<BTreeMap<String, ClientStatus>>>,
        session_locks: Arc<RwLock<BTreeMap<String, Arc<Mutex<()>>>>>,
        events: Arc<dyn CoreEventSink>,
        cancel: CancellationToken,
        start_signal: CancellationToken,
    ) {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = start_signal.cancelled() => {}
        }
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    break;
                }
                accepted = listener.accept() => match accepted {
                    Ok(session) => {
                        sessions.spawn(Self::run_session(
                            session,
                            listener_url.clone(),
                            peer_manager.clone(),
                            runtime_config.clone(),
                            config.clone(),
                            statuses.clone(),
                            session_locks.clone(),
                            events.clone(),
                            cancel.clone(),
                        ));
                    }
                    Err(error) => {
                        tracing::warn!(?error, "VPN portal listener stopped accepting");
                        cancel.cancel();
                        break;
                    }
                },
                _ = sessions.join_next(), if !sessions.is_empty() => {}
            }
        }
        drop(listener);
        while sessions.join_next().await.is_some() {}
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_session(
        mut session: PortalSession,
        listener_url: url::Url,
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        config: Arc<StdRwLock<PortalRuntimeConfig>>,
        statuses: Arc<RwLock<BTreeMap<String, ClientStatus>>>,
        session_locks: Arc<RwLock<BTreeMap<String, Arc<Mutex<()>>>>>,
        events: Arc<dyn CoreEventSink>,
        cancel: CancellationToken,
    ) {
        let Some(client) = config
            .read()
            .unwrap()
            .clients
            .iter()
            .find(|client| client.name == session.client_name)
            .cloned()
        else {
            tracing::warn!(client = %session.client_name, "unknown VPN portal client session");
            return;
        };
        let session_lock = {
            let mut locks = session_locks.write().await;
            locks.entry(client.name.clone()).or_default().clone()
        };
        let _session_guard = tokio::select! {
            _ = cancel.cancelled() => return,
            guard = session_lock.lock() => guard,
        };
        let generation = {
            let mut statuses = statuses.write().await;
            let status = statuses.entry(client.name.clone()).or_default();
            status.generation = status.generation.wrapping_add(1);
            status.state = PortalClientState::Connecting;
            status.endpoint = Some(session.endpoint.borrow_and_update().clone());
            status.tunnel_ip = Some(client.virtual_ip.address());
            status.error = None;
            status.generation
        };

        let attached = match AttachedPeerRuntime::connect(
            peer_manager,
            runtime_config,
            AttachedPeerConfig {
                name: client.name.clone(),
                virtual_ip: client.virtual_ip,
                groups: client.groups.clone(),
                identity_private_key: session.identity_private_key,
            },
        )
        .await
        {
            Ok(attached) => attached,
            Err(error) => {
                Self::finish_generation(
                    &statuses,
                    &client.name,
                    generation,
                    Some(error.to_string()),
                )
                .await;
                return;
            }
        };

        {
            let mut statuses = statuses.write().await;
            let Some(status) = statuses.get_mut(&client.name) else {
                drop(statuses);
                attached.close().await;
                return;
            };
            if status.generation != generation {
                drop(statuses);
                attached.close().await;
                return;
            }
            status.state = PortalClientState::Online;
            status.peer_id = Some(attached.peer_id());
        }
        events.emit(CoreEvent::VpnPortalClientConnected {
            portal: listener_url.to_string(),
            client: client.name.clone(),
        });

        let mut client_stream = session.from_client;
        let endpoint = session.endpoint;
        let client_sink = session.to_client;
        let client_to_mesh = {
            let attached = attached.clone();
            let name = client.name.clone();
            let virtual_ip = client.virtual_ip.address();
            tokio::spawn(async move {
                while let Some(payload) = client_stream.recv().await {
                    if !has_ipv4_source(&payload, virtual_ip) {
                        tracing::warn!(client = %name, expected = ?virtual_ip, "VPN client source does not match its assigned address");
                        continue;
                    }
                    if let Err(error) = attached.send_packet(&payload).await {
                        tracing::debug!(?error, client = %name, "attached peer send failed");
                        break;
                    }
                }
            })
        };
        let mesh_to_client = {
            let attached = attached.clone();
            tokio::spawn(async move {
                while let Some(packet) = attached.recv_packet().await {
                    let payload = packet.payload().to_vec();
                    if client_sink.send(payload).await.is_err() {
                        break;
                    }
                }
            })
        };
        Self::supervise_session_io(
            endpoint,
            statuses.clone(),
            client.name.clone(),
            generation,
            cancel,
            client_to_mesh,
            mesh_to_client,
        )
        .await;

        attached.close().await;
        Self::finish_generation(&statuses, &client.name, generation, None).await;
        events.emit(CoreEvent::VpnPortalClientDisconnected {
            portal: listener_url.to_string(),
            client: client.name,
        });
    }
    #[allow(clippy::too_many_arguments)]
    async fn supervise_session_io(
        mut endpoint: watch::Receiver<String>,
        statuses: Arc<RwLock<BTreeMap<String, ClientStatus>>>,
        client_name: String,
        generation: u64,
        cancel: CancellationToken,
        mut client_to_mesh: JoinHandle<()>,
        mut mesh_to_client: JoinHandle<()>,
    ) {
        let mut client_to_mesh_finished = false;
        let mut mesh_to_client_finished = false;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = &mut client_to_mesh, if !client_to_mesh_finished => {
                    client_to_mesh_finished = true;
                    if let Err(error) = result {
                        tracing::debug!(
                            ?error,
                            client = %client_name,
                            "VPN portal client-to-mesh task failed"
                        );
                    }
                    break;
                }
                result = &mut mesh_to_client, if !mesh_to_client_finished => {
                    mesh_to_client_finished = true;
                    if let Err(error) = result {
                        tracing::debug!(
                            ?error,
                            client = %client_name,
                            "VPN portal mesh-to-client task failed"
                        );
                    }
                    break;
                }
                changed = endpoint.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let current = endpoint.borrow_and_update().clone();
                    let mut statuses = statuses.write().await;
                    if let Some(status) = statuses.get_mut(&client_name)
                        && status.generation == generation
                    {
                        status.endpoint = Some(current);
                    }
                }
            }
        }
        if !client_to_mesh_finished {
            client_to_mesh.abort();
            let _ = client_to_mesh.await;
        }
        if !mesh_to_client_finished {
            mesh_to_client.abort();
            let _ = mesh_to_client.await;
        }
    }

    async fn finish_generation(
        statuses: &RwLock<BTreeMap<String, ClientStatus>>,
        name: &str,
        generation: u64,
        error: Option<String>,
    ) {
        let mut statuses = statuses.write().await;
        let Some(status) = statuses.get_mut(name) else {
            return;
        };
        if status.generation != generation {
            return;
        }
        status.state = if error.is_some() {
            PortalClientState::Error
        } else {
            PortalClientState::Offline
        };
        status.peer_id = None;
        status.endpoint = None;
        status.tunnel_ip = None;
        status.error = error;
    }

    async fn shutdown_runtime(&self, mut runtime: PortalRuntime) {
        runtime.cancel.cancel();
        while let Some(result) = runtime.tasks.join_next().await {
            if let Err(error) = result {
                tracing::debug!(?error, "VPN portal listener task failed");
            }
        }
        for status in self.statuses.write().await.values_mut() {
            *status = ClientStatus::default();
        }
    }

    pub async fn stop(&self) {
        let _operation = self.operation.lock().await;
        let Some(runtime) = self.runtime.lock().await.take() else {
            return;
        };
        self.shutdown_runtime(runtime).await;
    }

    pub async fn info_snapshot(&self) -> PortalInfoSnapshot {
        let Some(config) = self
            .config
            .as_ref()
            .map(|config| config.read().unwrap().clone())
        else {
            return PortalInfoSnapshot {
                vpn_type: "null".to_owned(),
                clients: Vec::new(),
                listener: None,
            };
        };
        let listener_url = self
            .runtime
            .lock()
            .await
            .as_ref()
            .filter(|runtime| !runtime.cancel.is_cancelled())
            .and_then(|runtime| runtime.listener_urls.first().cloned());
        let allowed_ips = self.allowed_ips().await;
        let statuses = self.statuses.read().await;
        let clients = config
            .clients
            .iter()
            .map(|client| {
                let status = statuses.get(&client.name).cloned().unwrap_or_default();
                let client_config = match (self.host.as_ref(), listener_url.as_ref()) {
                    (Some(host), Some(listener_url)) => {
                        let mut client_allowed_ips = allowed_ips.clone();
                        client_allowed_ips.push(client.virtual_ip.network().to_string());
                        client_allowed_ips.sort();
                        client_allowed_ips.dedup();
                        host.render_client_config(&PortalClientConfigPlan {
                            name: client.name.clone(),
                            address: client.virtual_ip.address(),
                            allowed_ips: client_allowed_ips,
                            listener_url: listener_url.clone(),
                        })
                    }
                    _ => String::new(),
                };
                PortalClientInfoSnapshot {
                    name: client.name.clone(),
                    virtual_ip: client.virtual_ip.address(),
                    groups: client.groups.clone(),
                    state: status.state,
                    peer_id: status.peer_id,
                    endpoint: status.endpoint,
                    tunnel_ip: status.tunnel_ip,
                    client_config,
                    error: status.error,
                }
            })
            .collect();
        PortalInfoSnapshot {
            vpn_type: self
                .host
                .as_ref()
                .map_or_else(|| "null".to_owned(), |host| host.name()),
            clients,
            listener: listener_url.map(|url| url.to_string()),
        }
    }

    async fn allowed_ips(&self) -> Vec<String> {
        let snapshot = self.runtime_config.snapshot();
        let mut allowed = BTreeSet::new();
        for route in self.peer_manager.list_route_snapshots().await {
            allowed.extend(route.proxy_cidrs);
        }
        for proxy in &snapshot.peer.runtime.core.routes.proxy_networks {
            let mapped = proxy.mapped.as_ref().unwrap_or(&proxy.real);
            allowed.insert(format!("{}/{}", mapped.address, mapped.prefix_len));
        }
        allowed.into_iter().collect()
    }
}

/// Validates a client set. The empty set is legal in every lifecycle stage:
/// a portal with zero clients keeps listening and accepts nothing, so
/// clearing all clients never produces a configuration that fails a later
/// instance recreation.
fn validate_clients(
    config: &PortalRuntimeConfig,
    runtime_config: &CoreInstanceRuntimeConfig,
) -> anyhow::Result<()> {
    if config.clients.len() > MAX_VPN_PORTAL_CLIENTS {
        anyhow::bail!("VPN portal supports at most {MAX_VPN_PORTAL_CLIENTS} clients");
    }
    validate_runtime_compatibility(config, runtime_config)?;
    let snapshot = runtime_config;
    let declared_groups = snapshot
        .peer
        .acl_group_declarations
        .iter()
        .map(|group| group.group_name.as_str())
        .collect::<BTreeSet<_>>();
    let mut names = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for client in &config.clients {
        validate_client_name(&client.name)?;
        if !names.insert(client.name.as_str()) {
            anyhow::bail!("duplicate VPN portal client name: {}", client.name);
        }
        if !addresses.insert(client.virtual_ip.address()) {
            anyhow::bail!("duplicate VPN portal virtual IP: {}", client.virtual_ip);
        }
        for group in &client.groups {
            if !declared_groups.contains(group.as_str()) {
                anyhow::bail!(
                    "VPN portal client {} uses unknown ACL group {group}",
                    client.name
                );
            }
        }
    }
    Ok(())
}

fn validate_runtime_compatibility(
    config: &PortalRuntimeConfig,
    runtime_config: &CoreInstanceRuntimeConfig,
) -> anyhow::Result<()> {
    let snapshot = runtime_config;
    if snapshot
        .peer
        .runtime
        .network_identity
        .network_secret
        .as_deref()
        .is_none_or(str::is_empty)
    {
        anyhow::bail!("VPN portal requires an admin node with a non-empty network secret");
    }
    let host_address = snapshot
        .peer
        .runtime
        .core
        .routes
        .ipv4
        .as_ref()
        .and_then(|prefix| match prefix.address {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        });
    for client in &config.clients {
        let address = client.virtual_ip.address();
        let network = client.virtual_ip.network();
        if host_address == Some(address)
            || address == network.first_address()
            || address == network.last_address()
        {
            anyhow::bail!(
                "VPN portal client {} has an unusable virtual IP {}",
                client.name,
                address
            );
        }
    }
    Ok(())
}

fn validate_client_name(name: &str) -> anyhow::Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid {
        anyhow::bail!("invalid VPN portal client name: {name}");
    }
    Ok(())
}

fn ipv4_source(payload: &[u8]) -> Option<Ipv4Addr> {
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ))
}

fn has_ipv4_source(payload: &[u8], expected: Ipv4Addr) -> bool {
    ipv4_source(payload) == Some(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{
            IpPrefix, NetworkIdentity,
            peers::{PeerGroupIdentity, PeerRuntimeSnapshot},
            runtime::CoreRuntimeConfig,
        },
        peers::peer_manager::PeerManagerCore,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use std::{
        future::pending,
        sync::{
            Mutex as StdMutex, Weak,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use tokio::sync::{Notify, mpsc};
    use x25519_dalek::{PublicKey, StaticSecret};

    #[derive(Default)]
    struct RecordingEvents(std::sync::Mutex<Vec<CoreEvent>>);

    impl CoreEventSink for RecordingEvents {
        fn emit(&self, event: CoreEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    struct StaticPortalHost {
        listeners: StdMutex<Option<Vec<PortalListener>>>,
    }

    impl StaticPortalHost {
        fn new(listeners: Vec<PortalListener>) -> Arc<Self> {
            Arc::new(Self {
                listeners: StdMutex::new(Some(listeners)),
            })
        }
    }

    #[async_trait]
    impl PortalHost for StaticPortalHost {
        async fn start_listeners(&self) -> anyhow::Result<Vec<PortalListener>> {
            self.listeners
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| anyhow::anyhow!("test listeners already started"))
        }

        fn name(&self) -> String {
            "test".to_owned()
        }

        fn render_client_config(&self, plan: &PortalClientConfigPlan) -> String {
            format!(
                "config:{}:{}:{}",
                plan.name,
                plan.address,
                plan.allowed_ips.join(",")
            )
        }
    }

    #[derive(Debug)]
    struct PendingPortalListener {
        url: url::Url,
        accept_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SocketListener for PendingPortalListener {
        type Accepted = PortalSession;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            self.accept_calls.fetch_add(1, Ordering::SeqCst);
            pending().await
        }

        fn local_url(&self) -> url::Url {
            self.url.clone()
        }
    }

    #[derive(Debug)]
    struct FailingListenPortalListener {
        url: url::Url,
        listening: Arc<Notify>,
        fail: Arc<Notify>,
    }

    #[async_trait]
    impl SocketListener for FailingListenPortalListener {
        type Accepted = PortalSession;

        async fn listen(&mut self) -> anyhow::Result<()> {
            self.listening.notify_one();
            self.fail.notified().await;
            anyhow::bail!("listener setup failed")
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            unreachable!("failed listeners cannot accept")
        }

        fn local_url(&self) -> url::Url {
            self.url.clone()
        }
    }

    #[derive(Debug)]
    struct FailingAcceptPortalListener {
        url: url::Url,
    }

    #[async_trait]
    impl SocketListener for FailingAcceptPortalListener {
        type Accepted = PortalSession;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            anyhow::bail!("listener receive failed")
        }

        fn local_url(&self) -> url::Url {
            self.url.clone()
        }
    }

    struct RestartingPortalHost {
        starts: AtomicUsize,
        accept_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl PortalHost for RestartingPortalHost {
        async fn start_listeners(&self) -> anyhow::Result<Vec<PortalListener>> {
            let attempt = self.starts.fetch_add(1, Ordering::SeqCst);
            let url = format!("test://127.0.0.1:{}", 10000 + attempt)
                .parse()
                .unwrap();
            if attempt == 0 {
                Ok(vec![Box::new(FailingAcceptPortalListener { url })])
            } else {
                Ok(vec![Box::new(PendingPortalListener {
                    url,
                    accept_calls: self.accept_calls.clone(),
                })])
            }
        }

        fn name(&self) -> String {
            "test".to_owned()
        }

        fn render_client_config(&self, plan: &PortalClientConfigPlan) -> String {
            format!("config:{}", plan.name)
        }
    }

    #[derive(Default)]
    struct RuntimeObservingEvents {
        module: StdMutex<Weak<PortalModule>>,
        runtime_visible_on_start: AtomicBool,
    }

    impl CoreEventSink for RuntimeObservingEvents {
        fn emit(&self, event: CoreEvent) {
            if matches!(event, CoreEvent::VpnPortalStarted(_))
                && let Some(module) = self.module.lock().unwrap().upgrade()
                && let Ok(runtime) = module.runtime.try_lock()
            {
                self.runtime_visible_on_start.store(
                    runtime
                        .as_ref()
                        .is_some_and(|runtime| !runtime.cancel.is_cancelled()),
                    Ordering::SeqCst,
                );
            }
        }
    }

    struct TaskDropCounter(Arc<AtomicUsize>);

    impl Drop for TaskDropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn runtime_config() -> CoreRuntimeConfigStore {
        let mut peer = PeerRuntimeSnapshot::default();
        peer.runtime.network_identity =
            NetworkIdentity::new("portal-test".to_owned(), "shared-secret".to_owned());
        peer.runtime.core.routes.ipv4 = Some(IpPrefix {
            address: IpAddr::V4(Ipv4Addr::new(10, 82, 0, 1)),
            prefix_len: 24,
        });
        peer.acl_group_declarations = vec![PeerGroupIdentity {
            group_name: "ops".to_owned(),
            group_secret: "ops-secret".to_owned(),
        }];
        CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(peer))
    }

    fn client(name: &str, virtual_ip: Ipv4Addr, groups: &[&str]) -> PortalClientConfig {
        PortalClientConfig {
            name: name.to_owned(),
            virtual_ip: Ipv4Inet::new(virtual_ip, 24).unwrap(),
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        }
    }

    fn raw_ipv4(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20] = 8;
        packet
    }

    #[test]
    fn portal_client_packet_requires_its_assigned_source() {
        let assigned = Ipv4Addr::new(10, 82, 0, 2);

        assert!(has_ipv4_source(
            &raw_ipv4(assigned, Ipv4Addr::new(10, 82, 0, 1)),
            assigned
        ));
        assert!(!has_ipv4_source(
            &raw_ipv4(Ipv4Addr::new(10, 82, 0, 99), Ipv4Addr::new(10, 82, 0, 1)),
            assigned
        ));
        assert!(!has_ipv4_source(&[0u8; 8], assigned));
    }
    fn network_runtime() -> (Arc<PeerManagerCore>, CoreRuntimeConfigStore) {
        network_runtime_with_secure_mode(false)
    }

    fn secure_network_runtime() -> (Arc<PeerManagerCore>, CoreRuntimeConfigStore) {
        network_runtime_with_secure_mode(true)
    }

    fn network_runtime_with_secure_mode(
        secure_mode: bool,
    ) -> (Arc<PeerManagerCore>, CoreRuntimeConfigStore) {
        let store = runtime_config();
        if secure_mode {
            let private = StaticSecret::from([42; 32]);
            let public = PublicKey::from(&private);
            store.update_peer_with(|peer| {
                peer.runtime.secure_mode = Some(crate::proto::common::SecureModeConfig {
                    enabled: true,
                    local_private_key: Some(BASE64_STANDARD.encode(private.to_bytes())),
                    local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
                });
            });
        }
        let snapshot = store.snapshot();
        let runtime = snapshot.peer.runtime.clone();
        let mut portable = crate::peers::peer_manager::PortablePeerManagerConfig::new(runtime);
        portable.snapshot.acl_group_declarations = snapshot.peer.acl_group_declarations.clone();
        let (packet_sender, _packet_receiver) = crate::host::packet::host_packet_channel();
        let public_ipv6_runtime = crate::peers::public_ipv6::CorePublicIpv6Runtime::new(
            store.clone(),
            Arc::new(()),
            Arc::new(()),
        );
        let peer = Arc::new(
            PeerManagerCore::new(
                portable,
                Vec::new(),
                store.clone(),
                Arc::new(()),
                packet_sender,
                public_ipv6_runtime,
                Arc::new(()),
                None,
                Arc::new(()),
            )
            .unwrap(),
        );
        (peer, store)
    }

    #[test]
    fn portal_runtime_rejects_duplicate_names_and_virtual_ips() {
        let runtime_config = runtime_config();
        let snapshot = runtime_config.snapshot();
        let alice = client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"]);

        let duplicate_name = PortalRuntimeConfig {
            clients: vec![
                alice.clone(),
                client("alice", Ipv4Addr::new(10, 82, 0, 3), &["ops"]),
            ],
        };
        let error = validate_clients(&duplicate_name, snapshot.as_ref())
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate VPN portal client name"));

        let duplicate_ip = PortalRuntimeConfig {
            clients: vec![alice, client("bob", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
        };
        let error = validate_clients(&duplicate_ip, snapshot.as_ref())
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate VPN portal virtual IP"));
    }

    #[test]
    fn portal_runtime_rejects_unknown_acl_groups() {
        let runtime_config = runtime_config();
        let config = PortalRuntimeConfig {
            clients: vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["unknown"])],
        };
        let error = validate_clients(&config, runtime_config.snapshot().as_ref())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown ACL group"));
    }

    #[test]
    fn portal_runtime_rejects_credential_node() {
        let runtime_config = runtime_config();
        runtime_config.update_peer_with(|peer| {
            peer.runtime.network_identity.network_secret = None;
        });
        let config = PortalRuntimeConfig {
            clients: vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
        };

        let error = validate_clients(&config, runtime_config.snapshot().as_ref())
            .unwrap_err()
            .to_string();

        assert!(error.contains("VPN portal requires an admin node"));
    }

    #[test]
    fn portal_client_cidr_is_independent_of_host_addressing() {
        let runtime_config = runtime_config();
        runtime_config.update_peer_with(|peer| peer.runtime.core.routes.ipv4 = None);
        runtime_config.update_services(|services| services.dhcp_ipv4 = true);
        let config = PortalRuntimeConfig {
            clients: vec![PortalClientConfig {
                name: "alice".to_owned(),
                virtual_ip: "10.82.0.2/16".parse().unwrap(),
                groups: vec!["ops".to_owned()],
            }],
        };

        validate_clients(&config, runtime_config.snapshot().as_ref()).unwrap();
    }

    #[test]
    fn portal_session_debug_redacts_identity_private_key() {
        let identity_private_key = [173u8; 32];
        let (_to_runtime, from_client) = mpsc::channel(1);
        let (to_client, _from_runtime) = mpsc::channel(1);
        let (_endpoint_sender, endpoint) = tokio::sync::watch::channel("portal://alice".to_owned());
        let session = PortalSession {
            client_name: "alice".to_owned(),
            endpoint,
            identity_private_key,
            from_client,
            to_client,
        };

        let rendered = format!("{session:?}");
        assert!(!rendered.contains("identity_private_key"));
        assert!(!rendered.contains(&format!("{identity_private_key:?}")));
    }

    #[tokio::test]
    async fn portal_session_publishes_virtual_ip_before_first_client_packet() {
        let (peer_manager, runtime_config) = network_runtime();
        peer_manager.run().await.unwrap();
        let virtual_ip = Ipv4Addr::new(10, 82, 0, 2);
        let config = PortalRuntimeConfig {
            clients: vec![client("alice", virtual_ip, &["ops"])],
        };
        let statuses = Arc::new(RwLock::new(BTreeMap::from([(
            "alice".to_owned(),
            ClientStatus::default(),
        )])));
        let session_locks = Arc::new(RwLock::new(BTreeMap::from([(
            "alice".to_owned(),
            Arc::new(Mutex::new(())),
        )])));
        let (to_runtime, from_client) = mpsc::channel(1);
        let (to_client, mut from_runtime) = mpsc::channel(1);
        let (endpoint_sender, endpoint) = tokio::sync::watch::channel("portal://alice".to_owned());
        let session = PortalSession {
            client_name: "alice".to_owned(),
            endpoint,
            identity_private_key: [173u8; 32],
            from_client,
            to_client,
        };
        let cancel = CancellationToken::new();
        let task = tokio::spawn(PortalModule::run_session(
            session,
            "portal://listener".parse().unwrap(),
            peer_manager.clone(),
            runtime_config,
            Arc::new(StdRwLock::new(config)),
            statuses.clone(),
            session_locks,
            Arc::new(()),
            cancel,
        ));

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let status = statuses.read().await.get("alice").cloned().unwrap();
                if status.state == PortalClientState::Online && status.tunnel_ip == Some(virtual_ip)
                {
                    return;
                }
                assert_ne!(
                    status.state,
                    PortalClientState::Error,
                    "portal session failed before publishing virtual IP: {:?}",
                    status.error
                );
                assert!(
                    !task.is_finished(),
                    "portal session ended before publishing virtual IP"
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("configured virtual IP was not published before the first client packet");

        let mesh_packet = raw_ipv4(Ipv4Addr::new(10, 82, 0, 1), virtual_ip);
        let outbound = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let _ = peer_manager
                    .send_msg_by_ip(
                        crate::packet::ZCPacket::new_with_payload(&mesh_packet),
                        IpAddr::V4(virtual_ip),
                        false,
                    )
                    .await;
                if let Ok(Some(packet)) =
                    tokio::time::timeout(std::time::Duration::from_millis(20), from_runtime.recv())
                        .await
                {
                    break packet;
                }
            }
        })
        .await
        .expect("mesh packet was not delivered before the first client packet");
        assert_eq!(&outbound[16..20], virtual_ip.octets().as_slice());

        endpoint_sender.send("portal://roamed".to_owned()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let status = statuses.read().await.get("alice").cloned().unwrap();
                if status.endpoint.as_deref() == Some("portal://roamed") {
                    return;
                }
                assert!(
                    !task.is_finished(),
                    "portal session ended before publishing the roamed endpoint"
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("roamed endpoint was not published");

        drop(to_runtime);
        task.await.unwrap();
        peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn portal_session_cancellation_runs_complete_cleanup() {
        let (peer_manager, runtime_config) = secure_network_runtime();
        peer_manager.run().await.unwrap();
        let config = PortalRuntimeConfig {
            clients: vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
        };
        let statuses = Arc::new(RwLock::new(BTreeMap::from([(
            "alice".to_owned(),
            ClientStatus::default(),
        )])));
        let session_locks = Arc::new(RwLock::new(BTreeMap::from([(
            "alice".to_owned(),
            Arc::new(Mutex::new(())),
        )])));
        let (_to_runtime, from_client) = mpsc::channel(1);
        let (to_client, _from_runtime) = mpsc::channel(1);
        let (_endpoint_sender, endpoint) = tokio::sync::watch::channel("portal://alice".to_owned());
        let identity_private_key = [174u8; 32];
        let identity_public_key =
            *PublicKey::from(&StaticSecret::from(identity_private_key)).as_bytes();
        let session = PortalSession {
            client_name: "alice".to_owned(),
            endpoint,
            identity_private_key,
            from_client,
            to_client,
        };
        let cancel = CancellationToken::new();
        let events = Arc::new(RecordingEvents::default());
        let mut task = tokio::spawn(PortalModule::run_session(
            session,
            "portal://listener".parse().unwrap(),
            peer_manager.clone(),
            runtime_config,
            Arc::new(StdRwLock::new(config)),
            statuses.clone(),
            session_locks,
            events.clone(),
            cancel.clone(),
        ));

        let attached_peer_id = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let status = statuses.read().await.get("alice").cloned().unwrap();
                if status.state == PortalClientState::Online {
                    return status.peer_id.unwrap();
                }
                assert!(
                    !task.is_finished(),
                    "portal session ended before becoming online: {:?}",
                    status.error
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("portal session did not become online");
        assert!(
            peer_manager
                .credential_manager()
                .is_pubkey_trusted(&identity_public_key)
        );

        cancel.cancel();
        if tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
            peer_manager.clear_resources().await;
            panic!("portal session did not stop after cancellation");
        }

        let status = statuses.read().await.get("alice").cloned().unwrap();
        assert_eq!(status.state, PortalClientState::Offline);
        assert!(status.peer_id.is_none());
        assert!(status.tunnel_ip.is_none());
        assert!(
            !peer_manager
                .get_peer_map()
                .has_direct_attached_peer(attached_peer_id)
        );
        assert!(
            !peer_manager
                .credential_manager()
                .is_pubkey_trusted(&identity_public_key)
        );
        {
            let events = events.0.lock().unwrap();
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, CoreEvent::VpnPortalClientConnected { .. }))
                    .count(),
                1
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, CoreEvent::VpnPortalClientDisconnected { .. }))
                    .count(),
                1
            );
        }
        peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn portal_session_stops_when_outbound_packet_task_ends() {
        let (peer_manager, runtime_config) = network_runtime();
        peer_manager.run().await.unwrap();
        let virtual_ip = Ipv4Addr::new(10, 82, 0, 2);
        let config = PortalRuntimeConfig {
            clients: vec![client("alice", virtual_ip, &["ops"])],
        };
        let statuses = Arc::new(RwLock::new(BTreeMap::from([(
            "alice".to_owned(),
            ClientStatus::default(),
        )])));
        let session_locks = Arc::new(RwLock::new(BTreeMap::from([(
            "alice".to_owned(),
            Arc::new(Mutex::new(())),
        )])));
        let (to_runtime, from_client) = mpsc::channel(1);
        let (to_client, from_runtime) = mpsc::channel(1);
        let (_endpoint_sender, endpoint) = tokio::sync::watch::channel("portal://alice".to_owned());
        let session = PortalSession {
            client_name: "alice".to_owned(),
            endpoint,
            identity_private_key: [175u8; 32],
            from_client,
            to_client,
        };
        let events = Arc::new(RecordingEvents::default());
        let task = tokio::spawn(PortalModule::run_session(
            session,
            "portal://listener".parse().unwrap(),
            peer_manager.clone(),
            runtime_config,
            Arc::new(StdRwLock::new(config)),
            statuses.clone(),
            session_locks,
            events.clone(),
            CancellationToken::new(),
        ));

        to_runtime
            .send(raw_ipv4(virtual_ip, Ipv4Addr::new(10, 82, 0, 1)))
            .await
            .unwrap();
        let attached_peer_id = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let status = statuses.read().await.get("alice").cloned().unwrap();
                if status.state == PortalClientState::Online && status.tunnel_ip == Some(virtual_ip)
                {
                    return status.peer_id.unwrap();
                }
                assert!(
                    !task.is_finished(),
                    "portal session ended before publishing its virtual address: {:?}",
                    status.error
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("portal session did not publish its virtual address");

        drop(from_runtime);
        let mesh_packet = raw_ipv4(Ipv4Addr::new(10, 82, 0, 1), virtual_ip);
        if tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !task.is_finished() {
                let _ = peer_manager
                    .send_msg_by_ip(
                        crate::packet::ZCPacket::new_with_payload(&mesh_packet),
                        IpAddr::V4(virtual_ip),
                        false,
                    )
                    .await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err()
        {
            task.abort();
            let _ = task.await;
            peer_manager.clear_resources().await;
            panic!("portal session did not stop when its outbound task ended");
        }
        task.await.unwrap();

        let status = statuses.read().await.get("alice").cloned().unwrap();
        assert_eq!(status.state, PortalClientState::Offline);
        assert!(status.peer_id.is_none());
        assert!(
            !peer_manager
                .get_peer_map()
                .has_direct_attached_peer(attached_peer_id)
        );
        assert_eq!(
            events
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|event| matches!(event, CoreEvent::VpnPortalClientDisconnected { .. }))
                .count(),
            1
        );
        peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn portal_start_does_not_accept_before_all_listeners_are_ready() {
        let (peer_manager, runtime_config) = network_runtime();
        let first_accept_calls = Arc::new(AtomicUsize::new(0));
        let second_listening = Arc::new(Notify::new());
        let fail_second = Arc::new(Notify::new());
        let host = StaticPortalHost::new(vec![
            Box::new(PendingPortalListener {
                url: "test://127.0.0.1:10001".parse().unwrap(),
                accept_calls: first_accept_calls.clone(),
            }),
            Box::new(FailingListenPortalListener {
                url: "test://127.0.0.1:10002".parse().unwrap(),
                listening: second_listening.clone(),
                fail: fail_second.clone(),
            }),
        ]);
        let events = Arc::new(RecordingEvents::default());
        let module = PortalModule::new(
            peer_manager.clone(),
            runtime_config,
            Some(PortalRuntimeConfig {
                clients: vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
            }),
            Some(host),
            events.clone(),
        )
        .unwrap();
        let start = tokio::spawn({
            let module = module.clone();
            async move { module.start().await }
        });
        second_listening.notified().await;

        let accepted_before_failure =
            tokio::time::timeout(std::time::Duration::from_millis(50), async {
                while first_accept_calls.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();
        fail_second.notify_one();

        let error = start.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("listener setup failed"));
        assert!(
            !accepted_before_failure,
            "an earlier listener accepted before startup completed"
        );
        assert!(module.runtime.lock().await.is_none());
        assert!(
            events
                .0
                .lock()
                .unwrap()
                .iter()
                .all(|event| !matches!(event, CoreEvent::VpnPortalStarted(_)))
        );
        peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn portal_started_event_observes_installed_runtime() {
        let (peer_manager, runtime_config) = network_runtime();
        let events = Arc::new(RuntimeObservingEvents::default());
        let module = PortalModule::new(
            peer_manager.clone(),
            runtime_config,
            Some(PortalRuntimeConfig {
                clients: vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
            }),
            Some(StaticPortalHost::new(vec![Box::new(
                PendingPortalListener {
                    url: "test://127.0.0.1:10003".parse().unwrap(),
                    accept_calls: Arc::new(AtomicUsize::new(0)),
                },
            )])),
            events.clone(),
        )
        .unwrap();
        *events.module.lock().unwrap() = Arc::downgrade(&module);

        module.start().await.unwrap();

        assert!(
            events.runtime_visible_on_start.load(Ordering::SeqCst),
            "VpnPortalStarted was emitted before runtime installation"
        );
        module.stop().await;
        peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn portal_client_config_routes_its_own_network_not_the_host_network() {
        let (peer_manager, runtime_config) = network_runtime();
        let module = PortalModule::new(
            peer_manager.clone(),
            runtime_config,
            Some(PortalRuntimeConfig {
                clients: vec![PortalClientConfig {
                    name: "alice".to_owned(),
                    virtual_ip: "10.90.0.2/16".parse().unwrap(),
                    groups: vec!["ops".to_owned()],
                }],
            }),
            Some(StaticPortalHost::new(vec![Box::new(
                PendingPortalListener {
                    url: "test://127.0.0.1:10004".parse().unwrap(),
                    accept_calls: Arc::new(AtomicUsize::new(0)),
                },
            )])),
            Arc::new(()),
        )
        .unwrap();

        module.start().await.unwrap();
        let snapshot = module.info_snapshot().await;

        assert!(snapshot.clients[0].client_config.contains("10.90.0.2"));
        assert!(snapshot.clients[0].client_config.contains("10.90.0.0/16"));
        assert!(!snapshot.clients[0].client_config.contains("10.82.0.0/24"));
        module.stop().await;
        peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn portal_restarts_after_listener_accept_failure() {
        let (peer_manager, runtime_config) = network_runtime();
        let host = Arc::new(RestartingPortalHost {
            starts: AtomicUsize::new(0),
            accept_calls: Arc::new(AtomicUsize::new(0)),
        });
        let module = PortalModule::new(
            peer_manager.clone(),
            runtime_config,
            Some(PortalRuntimeConfig {
                clients: vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
            }),
            Some(host.clone()),
            Arc::new(()),
        )
        .unwrap();
        module.start().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if module.info_snapshot().await.listener.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed listener remained reported as active");

        module.start().await.unwrap();

        assert_eq!(host.starts.load(Ordering::SeqCst), 2);
        assert_eq!(
            module.info_snapshot().await.listener.as_deref(),
            Some("test://127.0.0.1:10001")
        );
        module.stop().await;
        peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn session_io_cancellation_aborts_blocked_packet_directions() {
        let drops = Arc::new(AtomicUsize::new(0));
        let blocked_task = |drops: Arc<AtomicUsize>| {
            tokio::spawn(async move {
                let _drop_counter = TaskDropCounter(drops);
                pending::<()>().await;
            })
        };
        let client_to_mesh = blocked_task(drops.clone());
        let mesh_to_client = blocked_task(drops.clone());
        let (_endpoint_sender, endpoint) = watch::channel("test://127.0.0.1:10004".to_owned());
        let statuses = Arc::new(RwLock::new(BTreeMap::from([(
            "alice".to_owned(),
            ClientStatus {
                generation: 1,
                ..Default::default()
            },
        )])));
        let cancel = CancellationToken::new();
        let supervisor = tokio::spawn(PortalModule::supervise_session_io(
            endpoint,
            statuses,
            "alice".to_owned(),
            1,
            cancel.clone(),
            client_to_mesh,
            mesh_to_client,
        ));
        tokio::task::yield_now().await;

        cancel.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(1), supervisor)
            .await
            .expect("session I/O supervisor ignored cancellation")
            .unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn client_names_are_dns_safe() {
        assert!(validate_client_name("laptop-1").is_ok());
        assert!(validate_client_name("-laptop").is_err());
        assert!(validate_client_name("laptop_1").is_err());
        assert!(validate_client_name("").is_err());
    }

    #[derive(Default)]
    struct RecordingPortalHost {
        updates: StdMutex<Vec<Vec<PortalClientConfig>>>,
    }

    impl RecordingPortalHost {
        fn recorded(&self) -> Vec<Vec<PortalClientConfig>> {
            self.updates.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PortalHost for RecordingPortalHost {
        async fn start_listeners(&self) -> anyhow::Result<Vec<PortalListener>> {
            anyhow::bail!("recording host never starts listeners")
        }

        fn name(&self) -> String {
            "recording".to_owned()
        }

        fn render_client_config(&self, plan: &PortalClientConfigPlan) -> String {
            format!("config:{}", plan.name)
        }

        async fn update_clients(&self, clients: &[PortalClientConfig]) -> anyhow::Result<()> {
            self.updates.lock().unwrap().push(clients.to_vec());
            Ok(())
        }
    }

    fn portal_module_with_recording_host(
        initial: PortalRuntimeConfig,
    ) -> (
        Arc<PortalModule>,
        Arc<RecordingPortalHost>,
        CoreRuntimeConfigStore,
    ) {
        let (peer_manager, runtime_config) = network_runtime();
        let host = Arc::new(RecordingPortalHost::default());
        let module = PortalModule::new(
            peer_manager,
            runtime_config.clone(),
            Some(initial),
            Some(host.clone()),
            Arc::new(()),
        )
        .unwrap();
        (module, host, runtime_config)
    }

    #[tokio::test]
    async fn portal_module_update_clients_rejects_invalid_sets() {
        let (module, _host, runtime_config) =
            portal_module_with_recording_host(PortalRuntimeConfig {
                clients: vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
            });
        let runtime = runtime_config.snapshot();

        let duplicate = module
            .update_clients(
                vec![
                    client("bob", Ipv4Addr::new(10, 82, 0, 3), &["ops"]),
                    client("bob", Ipv4Addr::new(10, 82, 0, 4), &["ops"]),
                ],
                runtime.as_ref(),
            )
            .await
            .unwrap_err();
        assert!(
            duplicate
                .to_string()
                .contains("duplicate VPN portal client name")
        );

        let unknown_group = module
            .update_clients(
                vec![client("bob", Ipv4Addr::new(10, 82, 0, 3), &["missing"])],
                runtime.as_ref(),
            )
            .await
            .unwrap_err();
        assert!(unknown_group.to_string().contains("unknown ACL group"));

        // Runtime updates may drain the portal to zero clients.
        let applied = module
            .update_clients(Vec::new(), runtime.as_ref())
            .await
            .unwrap();
        assert!(applied.is_empty());
    }

    #[tokio::test]
    async fn portal_module_update_clients_replaces_shared_state_and_notifies_host() {
        let (module, host, runtime_config) =
            portal_module_with_recording_host(PortalRuntimeConfig {
                clients: vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
            });

        let applied = module
            .update_clients(
                vec![client("bob", Ipv4Addr::new(10, 82, 0, 3), &["ops"])],
                runtime_config.snapshot().as_ref(),
            )
            .await
            .unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].name, "bob");

        let recorded = host.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].len(), 1);
        assert_eq!(recorded[0][0].name, "bob");

        let snapshot = module.info_snapshot().await;
        assert_eq!(snapshot.clients.len(), 1);
        assert_eq!(snapshot.clients[0].name, "bob");
    }

    #[tokio::test]
    async fn portal_module_update_clients_requires_configured_portal() {
        let (peer_manager, runtime_config) = network_runtime();
        let module = PortalModule::new(
            peer_manager,
            runtime_config.clone(),
            None,
            None,
            Arc::new(()),
        )
        .unwrap();
        let error = module
            .update_clients(
                vec![client("alice", Ipv4Addr::new(10, 82, 0, 2), &["ops"])],
                runtime_config.snapshot().as_ref(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not configured"));
    }
}
