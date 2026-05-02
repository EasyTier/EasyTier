use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

use anyhow::Context;
use base64::{Engine, prelude::BASE64_STANDARD};
use cidr::Ipv4Inet;
use dashmap::DashMap;
use futures::StreamExt;
use pnet::packet::ipv4::Ipv4Packet;
use tokio::task::JoinSet;
use tracing::Level;

use crate::{
    common::{
        config::{NetworkIdentity, VpnPortalClientConfig},
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        join_joinset_background, shrink_dashmap,
    },
    peers::{PeerPacketFilter, peer_manager::PeerManager},
    tunnel::{
        Tunnel, TunnelListener,
        mpsc::{MpscTunnel, MpscTunnelSender},
        packet_def::{PacketType, ZCPacket, ZCPacketType},
        wireguard::{WgClientInfo, WgConfig, WgPortalServerConfig, WgTunnelListener},
    },
};

use super::VpnPortal;

type WgPeerIpTable = Arc<DashMap<Ipv4Addr, Arc<ClientEntry>>>;

pub(crate) fn get_wg_config_for_portal(nid: &NetworkIdentity) -> WgConfig {
    let key_seed = format!(
        "{}{}",
        nid.network_name,
        nid.network_secret.as_ref().unwrap_or(&"".to_string())
    );
    WgConfig::new_for_portal(&key_seed, &key_seed)
}

struct ClientEntry {
    endpoint_addr: Option<url::Url>,
    sink: MpscTunnelSender,
    name: String,
    assigned_ip: Ipv4Addr,
    virtual_peer_id: u32,
}

struct IpAllocator {
    cidr: cidr::Ipv4Cidr,
    allocated: DashMap<Ipv4Addr, String>,
}

impl IpAllocator {
    fn new(cidr: cidr::Ipv4Cidr) -> Self {
        Self {
            cidr,
            allocated: DashMap::new(),
        }
    }

    fn allocate(&self, client_name: &str, preferred: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(ip) = preferred {
            if self.cidr.contains(&ip) && !self.allocated.contains_key(&ip) {
                self.allocated.insert(ip, client_name.to_string());
                return Some(ip);
            }
        }

        for ip in self.cidr.iter() {
            let addr = ip.address();
            if addr == self.cidr.first_address() || addr == self.cidr.last_address() {
                continue;
            }
            if !self.allocated.contains_key(&addr) {
                self.allocated.insert(addr, client_name.to_string());
                return Some(addr);
            }
        }
        None
    }

    fn release(&self, ip: &Ipv4Addr) {
        self.allocated.remove(ip);
        shrink_dashmap(&self.allocated, None);
    }
}

fn virtual_peer_id_from_pubkey(pubkey: &[u8]) -> u32 {
    let mut hasher = DefaultHasher::new();
    pubkey.hash(&mut hasher);
    let hash = hasher.finish();
    (hash as u32) | 0x80000000
}

struct WireGuardImpl {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Arc<PeerManager>,
    wg_config: Option<WgConfig>,
    server_config: Option<WgPortalServerConfig>,
    listener_addr: SocketAddr,
    ip_allocator: Option<Arc<IpAllocator>>,
    client_configs: HashMap<String, VpnPortalClientConfig>,
    wg_peer_ip_table: WgPeerIpTable,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl WireGuardImpl {
    fn new(global_ctx: ArcGlobalCtx, peer_mgr: Arc<PeerManager>) -> Self {
        let vpn_cfg = global_ctx.config.get_vpn_portal_config().unwrap();
        let listener_addr = vpn_cfg.wireguard_listen;

        let mut client_configs = HashMap::new();
        for c in &vpn_cfg.clients {
            client_configs.insert(c.name.clone(), c.clone());
        }

        let (wg_config, server_config, ip_allocator) = if vpn_cfg.clients.is_empty() {
            let nid = global_ctx.get_network_identity();
            let wg_config = get_wg_config_for_portal(&nid);
            (Some(wg_config), None, None)
        } else {
            let server_secret_key = if let Some(ref key_b64) = vpn_cfg.wireguard_private_key {
                let key_bytes = BASE64_STANDARD
                    .decode(key_b64)
                    .expect("invalid wireguard private key");
                boringtun::x25519::StaticSecret::from(
                    <[u8; 32]>::try_from(key_bytes.as_slice()).expect("invalid key length"),
                )
            } else {
                let nid = global_ctx.get_network_identity();
                let key_seed = format!(
                    "{}{}",
                    nid.network_name,
                    nid.network_secret.as_ref().unwrap_or(&"".to_string())
                );
                let mut my_sec = [0u8; 32];
                crate::tunnel::generate_digest_from_str("server", &key_seed, &mut my_sec);
                boringtun::x25519::StaticSecret::from(my_sec)
            };
            let server_public_key = boringtun::x25519::PublicKey::from(&server_secret_key);

            let clients = Arc::new(DashMap::new());
            for client in &vpn_cfg.clients {
                if let Ok(pubkey_bytes) = BASE64_STANDARD.decode(&client.client_public_key) {
                    if let Ok(pubkey_arr) = <[u8; 32]>::try_from(pubkey_bytes.as_slice()) {
                        let pubkey = boringtun::x25519::PublicKey::from(pubkey_arr);
                        clients.insert(pubkey, client.name.clone());
                    }
                }
            }

            let server_config = WgPortalServerConfig {
                server_secret_key,
                server_public_key,
                clients,
                next_index: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            };

            let ip_allocator = {
                let cidr = if let Some(ipv4) = global_ctx.get_ipv4() {
                    cidr::Ipv4Cidr::new(ipv4.address(), ipv4.network_length())
                        .unwrap_or(vpn_cfg.client_cidr)
                } else {
                    vpn_cfg.client_cidr
                };
                let allocator = IpAllocator::new(cidr);
                // Reserve the server's own IP if it falls within the allocation range
                if let Some(ipv4) = global_ctx.get_ipv4() {
                    if cidr.contains(&ipv4.address()) {
                        allocator.allocated.insert(ipv4.address(), "server".to_string());
                    }
                }
                Some(Arc::new(allocator))
            };

            (None, Some(server_config), ip_allocator)
        };

        Self {
            global_ctx,
            peer_mgr,
            wg_config,
            server_config,
            listener_addr,
            ip_allocator,
            client_configs,
            wg_peer_ip_table: Arc::new(DashMap::new()),
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
        }
    }

    async fn handle_incoming_conn(
        t: Box<dyn Tunnel>,
        peer_mgr: Arc<PeerManager>,
        wg_peer_ip_table: WgPeerIpTable,
        ip_allocator: Option<Arc<IpAllocator>>,
        client_name: Option<String>,
        client_pubkey: Option<Vec<u8>>,
        client_configs: HashMap<String, VpnPortalClientConfig>,
    ) {
        let info = t.info().unwrap_or_default();
        let mut mpsc_tunnel = MpscTunnel::new(t, None);
        let mut stream = mpsc_tunnel.get_stream();
        let mut ip_registered = false;

        let remote_addr = info.remote_addr.clone();
        let endpoint_addr = remote_addr.clone().map(Into::into);

        let assigned = if let (Some(allocator), Some(name), Some(pubkey)) =
            (&ip_allocator, &client_name, &client_pubkey)
        {
            let preferred = client_configs.get(name).and_then(|c| c.assigned_ip);
            let ip = allocator
                .allocate(name, preferred)
                .unwrap_or_else(|| {
                    tracing::error!("Failed to allocate IP for client: {}", name);
                    Ipv4Addr::new(0, 0, 0, 0)
                });

            let virtual_peer_id = virtual_peer_id_from_pubkey(pubkey);
            peer_mgr.add_virtual_peer(virtual_peer_id, ip);

            peer_mgr.get_global_ctx().issue_event(
                GlobalCtxEvent::VpnPortalClientConnected(
                    info.local_addr.clone().unwrap_or_default().to_string(),
                    format!(
                        "{} ({} / {})",
                        info.remote_addr.clone().unwrap_or_default(),
                        name,
                        ip
                    ),
                ),
            );

            Some((ip, virtual_peer_id, name.clone()))
        } else {
            peer_mgr.get_global_ctx().issue_event(
                GlobalCtxEvent::VpnPortalClientConnected(
                    info.local_addr.clone().unwrap_or_default().to_string(),
                    info.remote_addr.clone().unwrap_or_default().to_string(),
                ),
            );
            None
        };

        let mut map_key = None;

        loop {
            let msg = match stream.next().await {
                Some(Ok(msg)) => msg,
                Some(Err(err)) => {
                    tracing::error!(?err, "Failed to receive from wg client");
                    break;
                }
                None => {
                    tracing::info!("Wireguard client disconnected");
                    break;
                }
            };

            assert_eq!(msg.packet_type(), ZCPacketType::WG);
            let inner = msg.inner();
            let Some(i) = Ipv4Packet::new(&inner) else {
                tracing::error!(?inner, "Failed to parse ipv4 packet");
                continue;
            };
            if !ip_registered {
                let client_entry = Arc::new(ClientEntry {
                    endpoint_addr: endpoint_addr.clone(),
                    sink: mpsc_tunnel.get_sink(),
                    name: assigned.as_ref().map(|a| a.2.clone()).unwrap_or_default(),
                    assigned_ip: assigned.as_ref().map(|a| a.0).unwrap_or_else(|| i.get_source()),
                    virtual_peer_id: assigned.as_ref().map(|a| a.1).unwrap_or(0),
                });
                map_key = Some(i.get_source());
                wg_peer_ip_table.insert(i.get_source(), client_entry.clone());
                ip_registered = true;
            }
            tracing::trace!(?i, "Received from wg client");
            let dst = i.get_destination();
            let _ = peer_mgr
                .send_msg_by_ip(
                    ZCPacket::new_with_payload(inner.as_ref()),
                    IpAddr::V4(dst),
                    false,
                )
                .await;
        }

        if let Some(map_key) = map_key {
            match wg_peer_ip_table
                .remove_if(&map_key, |_, entry| entry.endpoint_addr == endpoint_addr)
            {
                Some((_, entry)) => {
                    tracing::info!(?map_key, "Removed wg client from table");
                    if let Some((ip, virtual_peer_id, _)) = assigned {
                        if entry.assigned_ip == ip {
                            if let Some(ref allocator) = ip_allocator {
                                allocator.release(&ip);
                            }
                            peer_mgr.remove_virtual_peer(virtual_peer_id);
                        }
                    }
                }
                None => tracing::info!(
                    ?map_key,
                    "The wg client changed its endpoint address, not removing from table"
                ),
            }
            shrink_dashmap(&wg_peer_ip_table, None);
        }

        peer_mgr
            .get_global_ctx()
            .issue_event(GlobalCtxEvent::VpnPortalClientDisconnected(
                info.local_addr.unwrap_or_default().to_string(),
                info.remote_addr.unwrap_or_default().to_string(),
            ));
    }

    async fn start_pipeline_processor(&self) {
        struct PeerPacketFilterForVpnPortal {
            wg_peer_ip_table: WgPeerIpTable,
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for PeerPacketFilterForVpnPortal {
            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if hdr.packet_type != PacketType::Data as u8 {
                    return Some(packet);
                };

                let payload_bytes = packet.payload();
                let ipv4 = Ipv4Packet::new(payload_bytes)?;
                if ipv4.get_version() != 4 {
                    return Some(packet);
                }

                let Some(entry) = self
                    .wg_peer_ip_table
                    .get(&ipv4.get_destination())
                    .map(|f| f.clone())
                else {
                    return Some(packet);
                };

                tracing::trace!(?ipv4, "Packet filter for vpn portal");

                let payload_offset = packet.packet_type().get_packet_offsets().payload_offset;
                let packet = ZCPacket::new_from_buf(
                    packet.inner().split_off(payload_offset),
                    ZCPacketType::WG,
                );

                match entry.sink.try_send(packet) {
                    Ok(_) => {
                        tracing::trace!("Sent packet to wg client");
                    }
                    Err(e) => {
                        tracing::debug!(?e, "Failed to send packet to wg client");
                    }
                }

                None
            }
        }

        self.peer_mgr
            .add_packet_process_pipeline(Box::new(PeerPacketFilterForVpnPortal {
                wg_peer_ip_table: self.wg_peer_ip_table.clone(),
            }))
            .await;
    }

    async fn start_listener(&self, listener_addr: &SocketAddr) -> anyhow::Result<()> {
        let mut listener_url = url::Url::parse("wg://0.0.0.0:0").unwrap();
        listener_url.set_port(Some(listener_addr.port())).unwrap();
        listener_url.set_ip_host(listener_addr.ip()).unwrap();

        let mut l = if let Some(ref srv_cfg) = self.server_config {
            WgTunnelListener::new_for_portal(listener_url.clone(), srv_cfg.clone())
        } else {
            WgTunnelListener::new(listener_url.clone(), self.wg_config.clone().unwrap())
        };

        tracing::info!("Wireguard VPN Portal Starting");

        {
            let _g = self.global_ctx.net_ns.guard();
            l.listen()
                .await
                .with_context(|| "Failed to start wireguard listener for vpn portal")?;
        }
        let tasks = Arc::downgrade(&self.tasks.clone());
        let peer_mgr = self.peer_mgr.clone();
        let wg_peer_ip_table = self.wg_peer_ip_table.clone();
        let ip_allocator = self.ip_allocator.clone();
        let client_configs = self.client_configs.clone();
        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(t) = l.accept().await {
                let Some(tasks) = tasks.upgrade() else {
                    break;
                };

                let (client_name, client_pubkey) =
                    if let Some(data) = t.get_associate_data() {
                        if let Some(info) = data.downcast_ref::<WgClientInfo>() {
                            (Some(info.name.clone()), Some(info.pubkey.to_vec()))
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    };

                tasks.lock().unwrap().spawn(Self::handle_incoming_conn(
                    t,
                    peer_mgr.clone(),
                    wg_peer_ip_table.clone(),
                    ip_allocator.clone(),
                    client_name,
                    client_pubkey,
                    client_configs.clone(),
                ));
            }
        });

        self.global_ctx
            .issue_event(GlobalCtxEvent::VpnPortalStarted(listener_url.to_string()));

        Ok(())
    }

    async fn run_virtual_peer_refresh(
        peer_mgr: Arc<PeerManager>,
        wg_peer_ip_table: WgPeerIpTable,
    ) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            for entry in wg_peer_ip_table.iter() {
                let virtual_peer_id = entry.value().virtual_peer_id;
                if virtual_peer_id != 0 {
                    peer_mgr.refresh_virtual_peer(virtual_peer_id);
                }
            }
        }
    }

    #[tracing::instrument(skip(self), err(level = Level::WARN))]
    async fn start(&self) -> anyhow::Result<()> {
        tracing::info!("Wireguard VPN Portal Starting");

        self.start_listener(&self.listener_addr).await?;
        if let SocketAddr::V4(v4) = &self.listener_addr
            && v4.ip().is_unspecified()
        {
            let _ = self
                .start_listener(&SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    v4.port(),
                    0,
                    0,
                )))
                .await;
        };

        if self.server_config.is_some() {
            let peer_mgr = self.peer_mgr.clone();
            let wg_peer_ip_table = self.wg_peer_ip_table.clone();
            self.tasks.lock().unwrap().spawn(Self::run_virtual_peer_refresh(
                peer_mgr,
                wg_peer_ip_table,
            ));
        }

        join_joinset_background(self.tasks.clone(), "wireguard".to_string());
        self.start_pipeline_processor().await;

        Ok(())
    }
}

#[derive(Default)]
pub struct WireGuard {
    inner: Option<WireGuardImpl>,
}

#[async_trait::async_trait]
impl VpnPortal for WireGuard {
    async fn start(
        &mut self,
        global_ctx: ArcGlobalCtx,
        peer_mgr: Arc<PeerManager>,
    ) -> anyhow::Result<()> {
        assert!(self.inner.is_none());

        let vpn_cfg = global_ctx.config.get_vpn_portal_config();
        if vpn_cfg.is_none() {
            anyhow::bail!("vpn cfg is not set for wireguard vpn portal");
        }

        let inner = WireGuardImpl::new(global_ctx, peer_mgr);
        inner.start().await?;
        self.inner = Some(inner);
        Ok(())
    }

    async fn dump_client_config(&self, peer_mgr: Arc<PeerManager>) -> String {
        if self.inner.is_none() {
            return "ERROR: Wireguard VPN Portal Not Started".to_string();
        }
        let global_ctx = self.inner.as_ref().unwrap().global_ctx.clone();
        if global_ctx.config.get_vpn_portal_config().is_none() {
            return "ERROR: VPN Portal Config Not Set".to_string();
        }

        let vpn_cfg = global_ctx.config.get_vpn_portal_config().unwrap();
        let routes = peer_mgr.list_routes().await;
        let mut allow_ips = routes
            .iter()
            .flat_map(|x| x.proxy_cidrs.iter().map(String::to_string))
            .collect::<Vec<_>>();
        if let Some(ipv4) = routes
            .iter()
            .filter_map(|x| x.ipv4_addr)
            .chain(global_ctx.get_ipv4().into_iter().map(Into::into))
            .next()
        {
            let inet = Ipv4Inet::from(ipv4);
            allow_ips.push(inet.network().to_string());
        }

        allow_ips.push(vpn_cfg.client_cidr.to_string());
        let allow_ips = allow_ips.into_iter().collect::<Vec<_>>().join(",");

        let listener_addr = self.inner.as_ref().unwrap().listener_addr;

        if let Some(ref srv_cfg) = self.inner.as_ref().unwrap().server_config {
            // Multi-client mode: generate config for each registered client
            let mut output = String::new();
            for client in &vpn_cfg.clients {
                output.push_str(&format!("\n# Client: {}\n", client.name));
                let assigned_ip = client
                    .assigned_ip
                    .map(|ip| ip.to_string() + "/32")
                    .unwrap_or_else(|| "auto".to_string());
                output.push_str(&format!(
                    r#"[Interface]
PrivateKey = <your private key>
Address = {assigned_ip}

[Peer]
PublicKey = {my_public_key}
AllowedIPs = {allow_ips}
Endpoint = {listener_addr}
PersistentKeepalive = 25
"#,
                    my_public_key = BASE64_STANDARD.encode(srv_cfg.server_public_key.as_bytes()),
                ));
            }
            output
        } else {
            // Legacy single-key mode
            let cfg = self.inner.as_ref().unwrap().wg_config.clone().unwrap();
            format!(
                r#"
[Interface]
PrivateKey = {peer_secret_key}
Address = {address}

[Peer]
PublicKey = {my_public_key}
AllowedIPs = {allow_ips}
Endpoint = {listener_addr}
PersistentKeepalive = 25
"#,
                peer_secret_key = BASE64_STANDARD.encode(cfg.peer_secret_key()),
                my_public_key = BASE64_STANDARD.encode(cfg.my_public_key()),
                listener_addr = listener_addr,
                allow_ips = allow_ips,
                address = vpn_cfg.client_cidr.first_address().to_string() + "/32",
            )
        }
    }

    fn name(&self) -> String {
        "wireguard".to_string()
    }

    async fn list_clients(&self) -> Vec<String> {
        self.inner
            .as_ref()
            .map(|w| {
                w.wg_peer_ip_table
                    .iter()
                    .map(|x| {
                        let entry = x.value();
                        format!(
                            "{}: {} (ip: {})",
                            entry.name,
                            entry
                                .endpoint_addr
                                .as_ref()
                                .map(|x| x.to_string())
                                .unwrap_or_default(),
                            entry.assigned_ip
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::ConfigLoader;

    #[test]
    fn test_ip_allocator_basic() {
        let cidr = "10.14.14.0/24".parse().unwrap();
        let allocator = IpAllocator::new(cidr);

        let ip1 = allocator.allocate("client1", None).unwrap();
        assert!(cidr.contains(&ip1));
        assert_ne!(ip1, cidr.first_address());
        assert_ne!(ip1, cidr.last_address());

        let ip2 = allocator.allocate("client2", None).unwrap();
        assert_ne!(ip1, ip2);

        allocator.release(&ip1);
        let ip3 = allocator.allocate("client3", None).unwrap();
        assert_eq!(ip1, ip3); // should reuse released ip
    }

    #[test]
    fn test_ip_allocator_preferred() {
        let cidr = "10.14.14.0/24".parse().unwrap();
        let allocator = IpAllocator::new(cidr);

        let preferred = "10.14.14.100".parse().unwrap();
        let ip = allocator.allocate("client1", Some(preferred)).unwrap();
        assert_eq!(ip, preferred);
    }

    #[test]
    fn test_ip_allocator_preferred_conflict() {
        let cidr = "10.14.14.0/24".parse().unwrap();
        let allocator = IpAllocator::new(cidr);

        let preferred = "10.14.14.100".parse().unwrap();
        allocator.allocate("client1", Some(preferred)).unwrap();

        // preferred ip already taken, should allocate another one
        let ip2 = allocator.allocate("client2", Some(preferred)).unwrap();
        assert_ne!(ip2, preferred);
    }

    #[test]
    fn test_ip_allocator_reserve_server_ip() {
        let cidr = "10.14.14.0/24".parse().unwrap();
        let allocator = IpAllocator::new(cidr);
        let server_ip: Ipv4Addr = "10.14.14.1".parse().unwrap();
        allocator.allocated.insert(server_ip, "server".to_string());

        let ip = allocator.allocate("client1", None).unwrap();
        assert_ne!(ip, server_ip);
    }

    #[test]
    fn test_virtual_peer_id_deterministic() {
        let pubkey1 = [1u8; 32];
        let pubkey2 = [2u8; 32];

        let id1a = virtual_peer_id_from_pubkey(&pubkey1);
        let id1b = virtual_peer_id_from_pubkey(&pubkey1);
        let id2 = virtual_peer_id_from_pubkey(&pubkey2);

        assert_eq!(id1a, id1b);
        assert_ne!(id1a, id2);
        assert!(id1a >= 0x80000000);
    }

    #[test]
    fn test_wireguard_impl_mode_selection_legacy() {
        use crate::common::config::TomlConfigLoader;
        let cfg_str = r#"
            [network_identity]
            network_name = "test"
            network_secret = "secret"

            [vpn_portal_config]
            client_cidr = "10.14.14.0/24"
            wireguard_listen = "0.0.0.0:12345"
        "#;
        let loader = TomlConfigLoader::new_from_str(cfg_str).unwrap();
        let vpn_cfg = loader.get_vpn_portal_config().unwrap();
        assert!(vpn_cfg.clients.is_empty());
        assert_eq!(vpn_cfg.wireguard_private_key, None);
    }

    #[test]
    fn test_wireguard_impl_mode_selection_multi_client() {
        use crate::common::config::TomlConfigLoader;
        let cfg_str = r#"
            [network_identity]
            network_name = "test"
            network_secret = "secret"

            [[vpn_portal_config.clients]]
            name = "client1"
            client_public_key = "YZT/1P/7IjvKkNA3yq5+1xyn1SQT0p+2eEaL7gSFg0="

            [[vpn_portal_config.clients]]
            name = "client2"
            client_public_key = "YZT/1P/7IjvKkNA3yq5+1xyn1SQT0p+2eEaL7gSFg1="
            assigned_ip = "10.14.14.10"

            [vpn_portal_config]
            client_cidr = "10.14.14.0/24"
            wireguard_listen = "0.0.0.0:12345"
        "#;
        let loader = TomlConfigLoader::new_from_str(cfg_str).unwrap();
        let vpn_cfg = loader.get_vpn_portal_config().unwrap();
        assert_eq!(vpn_cfg.clients.len(), 2);
        assert_eq!(vpn_cfg.clients[0].name, "client1");
        assert_eq!(vpn_cfg.clients[1].assigned_ip, Some("10.14.14.10".parse().unwrap()));
    }
}
