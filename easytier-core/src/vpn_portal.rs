use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use async_trait::async_trait;
use cidr::{Ipv4Cidr, Ipv4Inet};
use dashmap::DashMap;
use futures::StreamExt;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    listener::SocketListener,
    packet::{PacketType, ZCPacket, ZCPacketType},
    peers::{
        PeerPacketFilter,
        peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    },
    tunnel::{Tunnel, mpsc::MpscTunnel, mpsc::MpscTunnelSender},
};

const IPV4_HEADER_LEN: usize = 20;

pub struct VpnPortalClient<V> {
    endpoint_addr: Option<url::Url>,
    value: V,
}

impl<V> VpnPortalClient<V> {
    pub fn endpoint_addr(&self) -> Option<&url::Url> {
        self.endpoint_addr.as_ref()
    }

    pub fn value(&self) -> &V {
        &self.value
    }
}

pub struct VpnPortalClientTable<V> {
    entries: DashMap<Ipv4Addr, Arc<VpnPortalClient<V>>>,
}

impl<V> Default for VpnPortalClientTable<V> {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl<V> VpnPortalClientTable<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn endpoint_addrs(&self) -> Vec<Option<url::Url>> {
        self.entries
            .iter()
            .map(|entry| entry.value().endpoint_addr.clone())
            .collect()
    }

    pub fn route_peer_packet(&self, packet: &ZCPacket) -> VpnPortalPeerPacketRoute<V> {
        let Some(header) = packet.peer_manager_header() else {
            return VpnPortalPeerPacketRoute::Pass;
        };
        if header.packet_type != PacketType::Data as u8 {
            return VpnPortalPeerPacketRoute::Pass;
        }

        let payload = packet.payload();
        if payload.len() < IPV4_HEADER_LEN {
            return VpnPortalPeerPacketRoute::Drop;
        }
        if payload[0] >> 4 != 4 {
            return VpnPortalPeerPacketRoute::Pass;
        }
        let destination = ipv4_address(&payload[16..20]);
        let Some(client) = self
            .entries
            .get(&destination)
            .map(|entry| entry.value().clone())
        else {
            return VpnPortalPeerPacketRoute::Pass;
        };

        VpnPortalPeerPacketRoute::Deliver {
            destination,
            client,
        }
    }

    fn insert(&self, address: Ipv4Addr, client: Arc<VpnPortalClient<V>>) {
        self.entries.insert(address, client);
    }

    fn remove_if_current(&self, address: &Ipv4Addr, client: &Arc<VpnPortalClient<V>>) -> bool {
        let removed = self
            .entries
            .remove_if(address, |_, current| Arc::ptr_eq(current, client))
            .is_some();
        if self.entries.capacity() - self.entries.len() > 16 {
            self.entries.shrink_to_fit();
        }
        removed
    }
}

pub enum VpnPortalPeerPacketRoute<V> {
    Pass,
    Drop,
    Deliver {
        destination: Ipv4Addr,
        client: Arc<VpnPortalClient<V>>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VpnPortalClientPacket {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpnPortalClientRemoval {
    NotRegistered,
    Removed(Ipv4Addr),
    EntryChangedOrMissing(Ipv4Addr),
}

pub struct VpnPortalClientSession<V> {
    table: Arc<VpnPortalClientTable<V>>,
    client: Arc<VpnPortalClient<V>>,
    registered_ip: Option<Ipv4Addr>,
}

pub type VpnPortalListener = Box<dyn SocketListener<Accepted = Box<dyn Tunnel>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPortalClientConfigPlan {
    pub client_cidr: Ipv4Cidr,
    pub allowed_ips: Vec<String>,
    pub listener_url: url::Url,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPortalInfoSnapshot {
    pub vpn_type: String,
    pub client_config: String,
    pub connected_clients: Vec<String>,
}

#[async_trait]
pub trait VpnPortalHost: Send + Sync + 'static {
    /// Creates already-listening protocol engines. Core owns accepting from the
    /// returned listeners and all portable session lifecycle after this seam.
    async fn start_listeners(&self) -> anyhow::Result<Vec<VpnPortalListener>>;

    fn name(&self) -> String;

    fn render_client_config(&self, plan: &VpnPortalClientConfigPlan) -> String;

    fn not_started_client_config(&self) -> String {
        "ERROR: VPN Portal Not Started".to_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnPortalEvent {
    Started(String),
    ClientConnected { portal: String, client: String },
    ClientDisconnected { portal: String, client: String },
}

pub trait VpnPortalEventSink: Send + Sync + 'static {
    fn emit(&self, event: VpnPortalEvent);
}

impl VpnPortalEventSink for () {
    fn emit(&self, _event: VpnPortalEvent) {}
}

struct VpnPortalRuntime {
    cancel: CancellationToken,
    tasks: JoinSet<()>,
    listener_urls: Vec<url::Url>,
    _pipeline: PipelineRegistrationGuard,
}

struct VpnPortalSessionEventGuard {
    events: Arc<dyn VpnPortalEventSink>,
    portal: String,
    client: String,
}

impl Drop for VpnPortalSessionEventGuard {
    fn drop(&mut self) {
        self.events.emit(VpnPortalEvent::ClientDisconnected {
            portal: self.portal.clone(),
            client: self.client.clone(),
        });
    }
}

struct VpnPortalPeerPacketFilter {
    clients: Arc<VpnPortalClientTable<MpscTunnelSender>>,
}

#[async_trait]
impl PeerPacketFilter for VpnPortalPeerPacketFilter {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let client = match self.clients.route_peer_packet(&packet) {
            VpnPortalPeerPacketRoute::Pass => return Some(packet),
            VpnPortalPeerPacketRoute::Drop => return None,
            VpnPortalPeerPacketRoute::Deliver { client, .. } => client,
        };

        let payload_offset = packet.payload_offset();
        let packet =
            ZCPacket::new_from_buf(packet.inner().split_off(payload_offset), ZCPacketType::WG);
        if let Err(error) = client.value().try_send(packet) {
            tracing::debug!(?error, "failed to send packet to VPN portal client");
        }
        None
    }
}

pub struct VpnPortalModule {
    operation: Mutex<()>,
    peer_manager: Arc<PeerManagerCore>,
    runtime_config: CoreRuntimeConfigStore,
    host: Option<Arc<dyn VpnPortalHost>>,
    events: Arc<dyn VpnPortalEventSink>,
    clients: Arc<VpnPortalClientTable<MpscTunnelSender>>,
    runtime: Mutex<Option<VpnPortalRuntime>>,
}

impl VpnPortalModule {
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        host: Option<Arc<dyn VpnPortalHost>>,
        events: Arc<dyn VpnPortalEventSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            operation: Mutex::new(()),
            peer_manager,
            runtime_config,
            host,
            events,
            clients: Arc::new(VpnPortalClientTable::new()),
            runtime: Mutex::new(None),
        })
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.runtime.lock().await.is_some() {
            return Ok(());
        }
        if self
            .runtime_config
            .snapshot()
            .peer
            .vpn_portal_cidr
            .is_none()
        {
            return Ok(());
        }
        let Some(host) = self.host.as_ref() else {
            return Ok(());
        };

        let listeners = host.start_listeners().await?;
        if listeners.is_empty() {
            anyhow::bail!("VPN portal host returned no active listeners");
        }

        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let mut listener_urls = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let local_url = listener.local_url();
            listener_urls.push(local_url);
            tasks.spawn(Self::run_listener(
                listener,
                self.peer_manager.clone(),
                self.clients.clone(),
                self.events.clone(),
                cancel.clone(),
            ));
        }
        let pipeline = self
            .peer_manager
            .add_managed_packet_process_pipeline(Box::new(VpnPortalPeerPacketFilter {
                clients: self.clients.clone(),
            }))
            .await;
        *self.runtime.lock().await = Some(VpnPortalRuntime {
            cancel,
            tasks,
            listener_urls: listener_urls.clone(),
            _pipeline: pipeline,
        });
        for local_url in listener_urls {
            self.events
                .emit(VpnPortalEvent::Started(local_url.to_string()));
        }
        Ok(())
    }

    async fn run_listener(
        mut listener: VpnPortalListener,
        peer_manager: Arc<PeerManagerCore>,
        clients: Arc<VpnPortalClientTable<MpscTunnelSender>>,
        events: Arc<dyn VpnPortalEventSink>,
        cancel: CancellationToken,
    ) {
        let mut sessions = JoinSet::new();
        let mut accepting = true;
        loop {
            while sessions.try_join_next().is_some() {}
            if !accepting && sessions.is_empty() {
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => {
                    sessions.shutdown().await;
                    return;
                },
                accepted = listener.accept(), if accepting => {
                    match accepted {
                        Ok(tunnel) => {
                            sessions.spawn(Self::run_session(
                                tunnel,
                                peer_manager.clone(),
                                clients.clone(),
                                events.clone(),
                            ));
                        }
                        Err(error) => {
                            tracing::warn!(?error, "VPN portal listener stopped accepting");
                            accepting = false;
                        }
                    }
                }
                _ = sessions.join_next(), if !sessions.is_empty() => {}
            }
        }
    }

    async fn run_session(
        tunnel: Box<dyn Tunnel>,
        peer_manager: Arc<PeerManagerCore>,
        clients: Arc<VpnPortalClientTable<MpscTunnelSender>>,
        events: Arc<dyn VpnPortalEventSink>,
    ) {
        let info = tunnel.info().unwrap_or_default();
        let portal = info.local_addr.clone().unwrap_or_default().to_string();
        let client = info.remote_addr.clone().unwrap_or_default().to_string();
        let endpoint = info.remote_addr.clone().map(Into::into);
        let mut tunnel = MpscTunnel::new(tunnel, None);
        let mut stream = tunnel.get_stream();

        events.emit(VpnPortalEvent::ClientConnected {
            portal: portal.clone(),
            client: client.clone(),
        });
        let _event_guard = VpnPortalSessionEventGuard {
            events,
            portal,
            client,
        };
        let mut session = VpnPortalClientSession::new(clients, endpoint, tunnel.get_sink());
        loop {
            let message = match stream.next().await {
                Some(Ok(message)) => message,
                Some(Err(error)) => {
                    tracing::error!(?error, "failed to receive from VPN portal client");
                    break;
                }
                None => break,
            };

            assert_eq!(message.packet_type(), ZCPacketType::WG);
            let payload = message.inner();
            let Some(packet) = session.observe_ipv4_payload(&payload) else {
                tracing::error!(?payload, "failed to parse VPN portal IPv4 packet");
                continue;
            };
            let _ = peer_manager
                .send_msg_by_ip(
                    ZCPacket::new_with_payload(&payload),
                    IpAddr::V4(packet.destination),
                    false,
                )
                .await;
        }

        match session.close() {
            VpnPortalClientRemoval::Removed(address) => {
                tracing::info!(?address, "removed VPN portal client from table")
            }
            VpnPortalClientRemoval::EntryChangedOrMissing(address) => tracing::info!(
                ?address,
                "VPN portal client endpoint changed; retaining replacement"
            ),
            VpnPortalClientRemoval::NotRegistered => {}
        }
    }

    pub async fn stop(&self) {
        let _operation = self.operation.lock().await;
        let Some(mut runtime) = self.runtime.lock().await.take() else {
            return;
        };
        runtime.cancel.cancel();
        while runtime.tasks.join_next().await.is_some() {}
        self.clients.entries.clear();
    }

    pub async fn info_snapshot(&self) -> VpnPortalInfoSnapshot {
        let Some(host) = self.host.as_ref() else {
            return VpnPortalInfoSnapshot {
                vpn_type: "null".to_owned(),
                client_config: String::new(),
                connected_clients: Vec::new(),
            };
        };
        let runtime = self.runtime.lock().await;
        let started = runtime.is_some();
        let listener_url = runtime
            .as_ref()
            .and_then(|runtime| runtime.listener_urls.first().cloned());
        drop(runtime);
        let plan = match listener_url {
            Some(listener_url) => self.client_config_plan(listener_url).await,
            None => None,
        };
        VpnPortalInfoSnapshot {
            vpn_type: host.name(),
            client_config: if started {
                plan.as_ref()
                    .map_or_else(String::new, |plan| host.render_client_config(plan))
            } else {
                host.not_started_client_config()
            },
            connected_clients: self
                .clients
                .endpoint_addrs()
                .into_iter()
                .map(|endpoint| endpoint.map(|url| url.to_string()).unwrap_or_default())
                .collect(),
        }
    }

    async fn client_config_plan(
        &self,
        listener_url: url::Url,
    ) -> Option<VpnPortalClientConfigPlan> {
        let config = self.runtime_config.snapshot();
        let client_cidr = config.peer.vpn_portal_cidr?;
        let routes = self.peer_manager.list_route_snapshots().await;
        let mut allowed_ips = routes
            .iter()
            .flat_map(|route| route.proxy_cidrs.iter().cloned())
            .collect::<Vec<_>>();
        let local_ipv4 = config
            .peer
            .runtime
            .core
            .routes
            .ipv4
            .as_ref()
            .and_then(|prefix| {
                let IpAddr::V4(address) = prefix.address else {
                    return None;
                };
                Ipv4Inet::new(address, prefix.prefix_len).ok()
            });
        if let Some(ipv4) = routes
            .iter()
            .filter_map(|route| route.ipv4_addr.clone().map(Into::into))
            .chain(local_ipv4)
            .next()
        {
            allowed_ips.push(Ipv4Inet::from(ipv4).network().to_string());
        }
        allowed_ips.push(client_cidr.to_string());
        Some(VpnPortalClientConfigPlan {
            client_cidr,
            allowed_ips,
            listener_url,
        })
    }
}

impl<V> VpnPortalClientSession<V> {
    pub fn new(
        table: Arc<VpnPortalClientTable<V>>,
        endpoint_addr: Option<url::Url>,
        value: V,
    ) -> Self {
        Self {
            table,
            client: Arc::new(VpnPortalClient {
                endpoint_addr,
                value,
            }),
            registered_ip: None,
        }
    }

    pub fn observe_ipv4_payload(&mut self, payload: &[u8]) -> Option<VpnPortalClientPacket> {
        if payload.len() < IPV4_HEADER_LEN {
            return None;
        }
        let packet = VpnPortalClientPacket {
            source: ipv4_address(&payload[12..16]),
            destination: ipv4_address(&payload[16..20]),
        };

        if self.registered_ip.is_none() {
            self.table.insert(packet.source, self.client.clone());
            self.registered_ip = Some(packet.source);
        }
        Some(packet)
    }

    pub fn registered_ip(&self) -> Option<Ipv4Addr> {
        self.registered_ip
    }

    pub fn close(&mut self) -> VpnPortalClientRemoval {
        let Some(address) = self.registered_ip.take() else {
            return VpnPortalClientRemoval::NotRegistered;
        };
        if self.table.remove_if_current(&address, &self.client) {
            VpnPortalClientRemoval::Removed(address)
        } else {
            VpnPortalClientRemoval::EntryChangedOrMissing(address)
        }
    }
}

impl<V> Drop for VpnPortalClientSession<V> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn ipv4_address(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_payload(source: [u8; 4], destination: [u8; 4], version: u8) -> Vec<u8> {
        let mut payload = vec![0u8; IPV4_HEADER_LEN];
        payload[0] = version << 4 | 5;
        payload[12..16].copy_from_slice(&source);
        payload[16..20].copy_from_slice(&destination);
        payload
    }

    fn peer_packet(payload: &[u8], packet_type: PacketType) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
        packet
    }

    #[test]
    fn session_registers_first_source_and_routes_peer_packet() {
        let table = Arc::new(VpnPortalClientTable::new());
        let endpoint = Some("wg://198.51.100.2:51820".parse().unwrap());
        let mut session = VpnPortalClientSession::new(table.clone(), endpoint, "client");

        let observed = session
            .observe_ipv4_payload(&ipv4_payload([10, 10, 0, 2], [10, 10, 0, 3], 4))
            .unwrap();
        assert_eq!(observed.source, Ipv4Addr::new(10, 10, 0, 2));
        assert_eq!(session.registered_ip(), Some(observed.source));

        let packet = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 4),
            PacketType::Data,
        );
        let VpnPortalPeerPacketRoute::Deliver {
            destination,
            client,
        } = table.route_peer_packet(&packet)
        else {
            panic!("registered destination must be delivered");
        };
        assert_eq!(destination, observed.source);
        assert_eq!(client.value(), &"client");
    }

    #[test]
    fn closing_old_endpoint_does_not_remove_replacement() {
        let table = Arc::new(VpnPortalClientTable::new());
        let payload = ipv4_payload([10, 10, 0, 2], [10, 10, 0, 3], 4);
        let mut old = VpnPortalClientSession::new(
            table.clone(),
            Some("wg://198.51.100.2:51820".parse().unwrap()),
            "old",
        );
        let mut replacement = VpnPortalClientSession::new(
            table.clone(),
            Some("wg://198.51.100.3:51820".parse().unwrap()),
            "replacement",
        );
        old.observe_ipv4_payload(&payload).unwrap();
        replacement.observe_ipv4_payload(&payload).unwrap();

        assert_eq!(
            old.close(),
            VpnPortalClientRemoval::EntryChangedOrMissing(Ipv4Addr::new(10, 10, 0, 2))
        );
        assert_eq!(table.len(), 1);

        let routed = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 4),
            PacketType::Data,
        );
        let VpnPortalPeerPacketRoute::Deliver { client, .. } = table.route_peer_packet(&routed)
        else {
            panic!("replacement must remain registered");
        };
        assert_eq!(client.value(), &"replacement");
    }

    #[test]
    fn dropping_old_session_does_not_remove_same_endpoint_replacement() {
        let table = Arc::new(VpnPortalClientTable::new());
        let endpoint = Some("wg://198.51.100.2:51820".parse().unwrap());
        let payload = ipv4_payload([10, 10, 0, 2], [10, 10, 0, 3], 4);
        let mut old = VpnPortalClientSession::new(table.clone(), endpoint.clone(), "old");
        let mut replacement = VpnPortalClientSession::new(table.clone(), endpoint, "replacement");
        old.observe_ipv4_payload(&payload).unwrap();
        replacement.observe_ipv4_payload(&payload).unwrap();

        drop(old);

        let routed = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 4),
            PacketType::Data,
        );
        let VpnPortalPeerPacketRoute::Deliver { client, .. } = table.route_peer_packet(&routed)
        else {
            panic!("same-endpoint replacement must remain registered");
        };
        assert_eq!(client.value(), &"replacement");
    }

    #[test]
    fn close_removes_matching_entry_and_non_data_packets_pass() {
        let table = Arc::new(VpnPortalClientTable::new());
        let mut session = VpnPortalClientSession::new(table.clone(), None, ());
        session
            .observe_ipv4_payload(&ipv4_payload([10, 10, 0, 2], [10, 10, 0, 3], 4))
            .unwrap();

        let non_data = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 4),
            PacketType::Ping,
        );
        assert!(matches!(
            table.route_peer_packet(&non_data),
            VpnPortalPeerPacketRoute::Pass
        ));
        assert_eq!(
            session.close(),
            VpnPortalClientRemoval::Removed(Ipv4Addr::new(10, 10, 0, 2))
        );
        assert!(table.is_empty());
    }

    #[test]
    fn dropping_session_removes_matching_entry() {
        let table = Arc::new(VpnPortalClientTable::new());
        {
            let mut session = VpnPortalClientSession::new(table.clone(), None, ());
            session
                .observe_ipv4_payload(&ipv4_payload([10, 10, 0, 2], [10, 10, 0, 3], 4))
                .unwrap();
            assert_eq!(table.len(), 1);
        }
        assert!(table.is_empty());
    }

    #[test]
    fn peer_route_rejects_non_ipv4_payload() {
        let table = VpnPortalClientTable::<()>::new();
        let packet = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 6),
            PacketType::Data,
        );
        assert!(matches!(
            table.route_peer_packet(&packet),
            VpnPortalPeerPacketRoute::Pass
        ));
    }

    #[test]
    fn peer_route_drops_short_data_payload() {
        let table = VpnPortalClientTable::<()>::new();
        let packet = peer_packet(&[0u8; IPV4_HEADER_LEN - 1], PacketType::Data);
        assert!(matches!(
            table.route_peer_packet(&packet),
            VpnPortalPeerPacketRoute::Drop
        ));
    }
}
