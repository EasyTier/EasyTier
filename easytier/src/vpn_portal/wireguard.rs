use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::Context;
use base64::{Engine, prelude::BASE64_STANDARD};
use bytes::BytesMut;
use cidr::Ipv4Inet;
use dashmap::{DashMap, mapref::entry::Entry};
use futures::StreamExt;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::{
    icmp::{IcmpPacket, IcmpTypes},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    tcp::MutableTcpPacket,
    udp::MutableUdpPacket,
};
use tokio::task::JoinSet;
use tracing::Level;

use crate::{
    common::{
        config::{NetworkIdentity, VpnPortalClientConfig},
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        join_joinset_background,
        packet_checksum::{
            update_ip_packet_checksum, update_tcp_packet_checksum,
            update_udp_packet_checksum_if_present,
        },
        shrink_dashmap,
    },
    peers::{PeerPacketFilter, peer_manager::PeerManager},
    proto::common::{is_virtual_peer_id, to_virtual_peer_id},
    tunnel::{
        Tunnel, TunnelListener,
        mpsc::{MpscTunnel, MpscTunnelSender},
        packet_def::{PacketType, ZCPacket, ZCPacketType},
        wireguard::{WgClientInfo, WgConfig, WgPortalServerConfig, WgTunnelListener},
    },
};

use super::VpnPortal;

type WgPeerIpTable = Arc<DashMap<Ipv4Addr, Arc<ClientEntry>>>;
static NEXT_CLIENT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn get_wg_config_for_portal(nid: &NetworkIdentity) -> WgConfig {
    let key_seed = format!(
        "{}{}",
        nid.network_name,
        nid.network_secret.as_ref().unwrap_or(&"".to_string())
    );
    WgConfig::new_for_portal(&key_seed, &key_seed)
}

struct ClientEntry {
    connection_id: u64,
    endpoint_addr: Option<url::Url>,
    sink: MpscTunnelSender,
    name: String,
    assigned_ip: Ipv4Addr,
    tunnel_ip: Ipv4Addr,
    virtual_peer_id: u32,
}

#[derive(Debug, Clone)]
struct AssignedClient {
    assigned_ip: Ipv4Addr,
    tunnel_ip: Ipv4Addr,
    virtual_peer_id: u32,
    name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv4NatError {
    InvalidPacket,
    InvalidTransportPacket,
    UnexpectedSource {
        actual: Ipv4Addr,
        expected: Ipv4Addr,
    },
    UnexpectedDestination {
        actual: Ipv4Addr,
        expected: Ipv4Addr,
    },
    UnsupportedFragment,
    UnsupportedProtocol(IpNextHeaderProtocol),
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

    fn is_assignable(&self, ip: Ipv4Addr) -> bool {
        is_assignable_client_ip(self.cidr, ip)
    }

    fn try_claim(&self, ip: Ipv4Addr, client_name: &str) -> bool {
        match self.allocated.entry(ip) {
            Entry::Vacant(entry) => {
                entry.insert(client_name.to_string());
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    fn allocate(&self, client_name: &str, preferred: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(ip) = preferred {
            if self.try_claim(ip, client_name) {
                return Some(ip);
            }
            return None;
        }

        for ip in self.cidr.iter() {
            let addr = ip.address();
            if !self.is_assignable(addr) {
                continue;
            }
            if self.try_claim(addr, client_name) {
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
    to_virtual_peer_id(hash as u32)
}

fn is_assignable_client_ip(cidr: cidr::Ipv4Cidr, ip: Ipv4Addr) -> bool {
    cidr.contains(&ip) && ip != cidr.first_address() && ip != cidr.last_address()
}

fn ipv4_packet_total_len(packet: &[u8]) -> Result<usize, Ipv4NatError> {
    let ipv4_packet = Ipv4Packet::new(packet).ok_or(Ipv4NatError::InvalidPacket)?;
    if ipv4_packet.get_version() != 4 {
        return Err(Ipv4NatError::InvalidPacket);
    }

    let header_len = ipv4_packet.get_header_length() as usize * 4;
    let total_len = ipv4_packet.get_total_length() as usize;
    if header_len < Ipv4Packet::minimum_packet_size()
        || total_len < header_len
        || total_len > packet.len()
    {
        return Err(Ipv4NatError::InvalidPacket);
    }

    Ok(total_len)
}

fn update_transport_checksum(ipv4_packet: &mut MutableIpv4Packet) -> Result<(), Ipv4NatError> {
    let source = ipv4_packet.get_source();
    let destination = ipv4_packet.get_destination();
    let protocol = ipv4_packet.get_next_level_protocol();

    match protocol {
        IpNextHeaderProtocols::Tcp => {
            let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut())
                .ok_or(Ipv4NatError::InvalidTransportPacket)?;
            update_tcp_packet_checksum(&mut tcp_packet, &source, &destination);
        }
        IpNextHeaderProtocols::Udp => {
            let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut())
                .ok_or(Ipv4NatError::InvalidTransportPacket)?;
            update_udp_packet_checksum_if_present(&mut udp_packet, &source, &destination);
        }
        IpNextHeaderProtocols::Icmp => {
            let icmp_packet = IcmpPacket::new(ipv4_packet.payload())
                .ok_or(Ipv4NatError::InvalidTransportPacket)?;
            let icmp_type = icmp_packet.get_icmp_type();
            if icmp_type != IcmpTypes::EchoRequest && icmp_type != IcmpTypes::EchoReply {
                return Err(Ipv4NatError::UnsupportedProtocol(protocol));
            }
        }
        _ => return Err(Ipv4NatError::UnsupportedProtocol(protocol)),
    }

    Ok(())
}

fn reject_fragmented_packet(ipv4_packet: &MutableIpv4Packet) -> Result<(), Ipv4NatError> {
    if ipv4_packet.get_fragment_offset() != 0
        || ipv4_packet.get_flags() & Ipv4Flags::MoreFragments != 0
    {
        return Err(Ipv4NatError::UnsupportedFragment);
    }

    Ok(())
}

fn rewrite_ipv4_source(
    packet: &mut BytesMut,
    expected_source: Ipv4Addr,
    new_source: Ipv4Addr,
) -> Result<(), Ipv4NatError> {
    let total_len = ipv4_packet_total_len(packet.as_ref())?;
    let mut ipv4_packet =
        MutableIpv4Packet::new(&mut packet[..total_len]).ok_or(Ipv4NatError::InvalidPacket)?;
    let actual_source = ipv4_packet.get_source();
    if actual_source != expected_source {
        return Err(Ipv4NatError::UnexpectedSource {
            actual: actual_source,
            expected: expected_source,
        });
    }
    if actual_source == new_source {
        return Ok(());
    }

    reject_fragmented_packet(&ipv4_packet)?;
    ipv4_packet.set_source(new_source);
    update_transport_checksum(&mut ipv4_packet)?;
    update_ip_packet_checksum(&mut ipv4_packet);

    Ok(())
}

fn rewrite_ipv4_destination(
    packet: &mut BytesMut,
    expected_destination: Ipv4Addr,
    new_destination: Ipv4Addr,
) -> Result<(), Ipv4NatError> {
    let total_len = ipv4_packet_total_len(packet.as_ref())?;
    let mut ipv4_packet =
        MutableIpv4Packet::new(&mut packet[..total_len]).ok_or(Ipv4NatError::InvalidPacket)?;
    let actual_destination = ipv4_packet.get_destination();
    if actual_destination != expected_destination {
        return Err(Ipv4NatError::UnexpectedDestination {
            actual: actual_destination,
            expected: expected_destination,
        });
    }
    if actual_destination == new_destination {
        return Ok(());
    }

    reject_fragmented_packet(&ipv4_packet)?;
    ipv4_packet.set_destination(new_destination);
    update_transport_checksum(&mut ipv4_packet)?;
    update_ip_packet_checksum(&mut ipv4_packet);

    Ok(())
}

fn build_client_config_map(
    clients: &[VpnPortalClientConfig],
    cidr: cidr::Ipv4Cidr,
    server_ip: Option<Ipv4Addr>,
) -> HashMap<String, VpnPortalClientConfig> {
    let mut used_ips = HashSet::new();
    if let Some(server_ip) = server_ip {
        used_ips.insert(server_ip);
    }

    let mut client_configs = HashMap::new();
    for client in clients {
        let mut config = client.clone();
        if let Some(ip) = config.assigned_ip
            && !used_ips.insert(ip)
        {
            tracing::warn!(
                client = %config.name,
                %ip,
                "Configured WireGuard virtual client IP is already reserved"
            );
            config.assigned_ip = None;
        }
        client_configs.insert(config.name.clone(), config);
    }

    for client in clients {
        let Some(config) = client_configs.get_mut(&client.name) else {
            continue;
        };
        if config.assigned_ip.is_some() {
            continue;
        }

        let next_ip = cidr
            .iter()
            .map(|ip| ip.address())
            .find(|ip| is_assignable_client_ip(cidr, *ip) && !used_ips.contains(ip));
        if let Some(ip) = next_ip {
            used_ips.insert(ip);
            config.assigned_ip = Some(ip);
        } else {
            tracing::error!(
                client = %config.name,
                %cidr,
                "No assignable WireGuard client IP is available"
            );
        }
    }

    for client in clients {
        let Some(config) = client_configs.get_mut(&client.name) else {
            continue;
        };
        if config.tunnel_ip.is_none() {
            config.tunnel_ip = config.assigned_ip;
        }
    }

    client_configs
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

        let (wg_config, server_config, ip_allocator, client_configs) = if vpn_cfg.clients.is_empty()
        {
            let nid = global_ctx.get_network_identity();
            let wg_config = get_wg_config_for_portal(&nid);
            (Some(wg_config), None, None, HashMap::new())
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
                if let Ok(pubkey_bytes) = BASE64_STANDARD.decode(&client.client_public_key)
                    && let Ok(pubkey_arr) = <[u8; 32]>::try_from(pubkey_bytes.as_slice())
                {
                    let pubkey = boringtun::x25519::PublicKey::from(pubkey_arr);
                    clients.insert(pubkey, client.name.clone());
                }
            }

            let server_config = WgPortalServerConfig {
                server_secret_key,
                server_public_key,
                clients,
                next_index: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            };

            let local_ipv4 = global_ctx.get_ipv4();
            let cidr = local_ipv4
                .map(|ipv4| ipv4.network())
                .unwrap_or(vpn_cfg.client_cidr);
            let client_configs =
                build_client_config_map(&vpn_cfg.clients, cidr, local_ipv4.map(|ip| ip.address()));

            let allocator = IpAllocator::new(cidr);
            // Reserve the server's own IP if it falls within the allocation range.
            if let Some(ipv4) = local_ipv4 {
                allocator
                    .allocated
                    .insert(ipv4.address(), "server".to_string());
            }

            (
                None,
                Some(server_config),
                Some(Arc::new(allocator)),
                client_configs,
            )
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
            let Some(config) = client_configs.get(name) else {
                tracing::error!(client = %name, "No config is available for client");
                return;
            };
            let Some(preferred) = config.assigned_ip else {
                tracing::error!("No configured IP is available for client: {}", name);
                return;
            };
            let tunnel_ip = config.tunnel_ip.unwrap_or(preferred);
            let Some(ip) = allocator.allocate(name, Some(preferred)) else {
                tracing::error!(
                    client = %name,
                    %preferred,
                    "Failed to allocate configured virtual IP for WireGuard client"
                );
                return;
            };

            let virtual_peer_id = virtual_peer_id_from_pubkey(pubkey);
            peer_mgr.add_virtual_peer(virtual_peer_id, ip);

            peer_mgr
                .get_global_ctx()
                .issue_event(GlobalCtxEvent::VpnPortalClientConnected(
                    info.local_addr.clone().unwrap_or_default().to_string(),
                    format!(
                        "{} ({} / {})",
                        info.remote_addr.clone().unwrap_or_default(),
                        name,
                        ip
                    ),
                ));

            Some(AssignedClient {
                assigned_ip: ip,
                tunnel_ip,
                virtual_peer_id,
                name: name.clone(),
            })
        } else {
            peer_mgr
                .get_global_ctx()
                .issue_event(GlobalCtxEvent::VpnPortalClientConnected(
                    info.local_addr.clone().unwrap_or_default().to_string(),
                    info.remote_addr.clone().unwrap_or_default().to_string(),
                ));
            None
        };

        let mut map_key = None;
        if let Some(assigned) = &assigned {
            let connection_id = NEXT_CLIENT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
            let client_entry = Arc::new(ClientEntry {
                connection_id,
                endpoint_addr: endpoint_addr.clone(),
                sink: mpsc_tunnel.get_sink(),
                name: assigned.name.clone(),
                assigned_ip: assigned.assigned_ip,
                tunnel_ip: assigned.tunnel_ip,
                virtual_peer_id: assigned.virtual_peer_id,
            });
            map_key = Some((assigned.assigned_ip, connection_id));
            wg_peer_ip_table.insert(assigned.assigned_ip, client_entry);
            ip_registered = true;
        }

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
            let mut inner = msg.inner();
            let Some((src, dst)) = Ipv4Packet::new(&inner).and_then(|i| {
                (i.get_version() == 4).then_some((i.get_source(), i.get_destination()))
            }) else {
                tracing::error!(?inner, "Failed to parse ipv4 packet");
                continue;
            };

            if let Some(assigned) = &assigned {
                match rewrite_ipv4_source(&mut inner, assigned.tunnel_ip, assigned.assigned_ip) {
                    Ok(()) => {}
                    Err(Ipv4NatError::UnexpectedSource { actual, expected }) => {
                        tracing::warn!(
                            client = %assigned.name,
                            src = %actual,
                            expected = %expected,
                            "Rejecting WireGuard client packet with unexpected source IP"
                        );
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            client = %assigned.name,
                            ?err,
                            "Dropping WireGuard client packet unsupported by VPN portal NAT"
                        );
                        continue;
                    }
                }
            }

            if !ip_registered {
                let assigned_ip = assigned
                    .as_ref()
                    .map(|assigned| assigned.assigned_ip)
                    .unwrap_or(src);
                let tunnel_ip = assigned
                    .as_ref()
                    .map(|assigned| assigned.tunnel_ip)
                    .unwrap_or(src);
                let connection_id = NEXT_CLIENT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
                let client_entry = Arc::new(ClientEntry {
                    connection_id,
                    endpoint_addr: endpoint_addr.clone(),
                    sink: mpsc_tunnel.get_sink(),
                    name: assigned
                        .as_ref()
                        .map(|assigned| assigned.name.clone())
                        .unwrap_or_default(),
                    assigned_ip,
                    tunnel_ip,
                    virtual_peer_id: assigned
                        .as_ref()
                        .map(|assigned| assigned.virtual_peer_id)
                        .unwrap_or(0),
                });
                map_key = Some((assigned_ip, connection_id));
                wg_peer_ip_table.insert(assigned_ip, client_entry.clone());
                ip_registered = true;
            }
            tracing::trace!(?inner, "Received from wg client");
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
                .remove_if(&map_key.0, |_, entry| entry.connection_id == map_key.1)
            {
                Some((_, entry)) => {
                    tracing::info!(?map_key, "Removed wg client from table");
                    if let Some(assigned) = assigned
                        && entry.assigned_ip == assigned.assigned_ip
                    {
                        if let Some(ref allocator) = ip_allocator {
                            allocator.release(&assigned.assigned_ip);
                        }
                        peer_mgr.remove_virtual_peer(assigned.virtual_peer_id);
                    }
                }
                None => tracing::info!(
                    ?map_key,
                    "The wg client changed its endpoint address, not removing from table"
                ),
            }
            shrink_dashmap(&wg_peer_ip_table, None);
        } else if let Some(assigned) = assigned {
            if let Some(ref allocator) = ip_allocator {
                allocator.release(&assigned.assigned_ip);
            }
            peer_mgr.remove_virtual_peer(assigned.virtual_peer_id);
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
                let destination = ipv4.get_destination();

                let Some(entry) = self.wg_peer_ip_table.get(&destination).map(|f| f.clone()) else {
                    return Some(packet);
                };

                tracing::trace!(?ipv4, "Packet filter for vpn portal");

                let payload_offset = packet.packet_type().get_packet_offsets().payload_offset;
                let mut inner = packet.inner().split_off(payload_offset);
                if let Err(err) =
                    rewrite_ipv4_destination(&mut inner, entry.assigned_ip, entry.tunnel_ip)
                {
                    tracing::warn!(
                        client = %entry.name,
                        assigned_ip = %entry.assigned_ip,
                        tunnel_ip = %entry.tunnel_ip,
                        ?err,
                        "Dropping peer packet unsupported by VPN portal NAT"
                    );
                    return None;
                }

                let packet = ZCPacket::new_from_buf(inner, ZCPacketType::WG);

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

                let (client_name, client_pubkey) = if let Some(data) = t.get_associate_data() {
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

    async fn run_virtual_peer_refresh(peer_mgr: Arc<PeerManager>, wg_peer_ip_table: WgPeerIpTable) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let virtual_peer_ids: Vec<_> = wg_peer_ip_table
                .iter()
                .filter_map(|entry| {
                    let virtual_peer_id = entry.value().virtual_peer_id;
                    is_virtual_peer_id(virtual_peer_id).then_some(virtual_peer_id)
                })
                .collect();
            peer_mgr.refresh_virtual_peers(virtual_peer_ids);
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
            self.tasks
                .lock()
                .unwrap()
                .spawn(Self::run_virtual_peer_refresh(peer_mgr, wg_peer_ip_table));
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
                let config = self
                    .inner
                    .as_ref()
                    .unwrap()
                    .client_configs
                    .get(&client.name)
                    .cloned();
                let Some(config) = config else {
                    output.push_str(&format!(
                        "\n# Client: {}\n# ERROR: no available WireGuard client address\n",
                        client.name
                    ));
                    continue;
                };
                let Some(tunnel_ip) = config.tunnel_ip.or(config.assigned_ip) else {
                    output.push_str(&format!(
                        "\n# Client: {}\n# ERROR: no available WireGuard client address\n",
                        client.name
                    ));
                    continue;
                };
                let address = tunnel_ip.to_string() + "/32";
                output.push_str(&format!("\n# Client: {}\n", client.name));
                output.push_str(&format!(
                    r#"[Interface]
PrivateKey = <your private key>
Address = {address}

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
                            "{}: {} (ip: {}, tunnel_ip: {})",
                            entry.name,
                            entry
                                .endpoint_addr
                                .as_ref()
                                .map(|x| x.to_string())
                                .unwrap_or_default(),
                            entry.assigned_ip,
                            entry.tunnel_ip
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
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::{
        icmp::{self, MutableIcmpPacket},
        ipv4, tcp, udp,
    };

    fn build_tcp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> BytesMut {
        let mut packet = BytesMut::new();
        packet.resize(44, 0);
        let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(44);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(src);
        ipv4_packet.set_destination(dst);

        let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
        tcp_packet.set_source(12345);
        tcp_packet.set_destination(80);
        tcp_packet.set_data_offset(5);
        tcp_packet.payload_mut().copy_from_slice(&[1, 2, 3, 4]);
        tcp_packet.set_checksum(tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src, &dst));
        drop(tcp_packet);

        update_ip_packet_checksum(&mut ipv4_packet);
        packet
    }

    fn build_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, checksum_enabled: bool) -> BytesMut {
        let mut packet = BytesMut::new();
        packet.resize(32, 0);
        let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(32);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4_packet.set_source(src);
        ipv4_packet.set_destination(dst);

        let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut()).unwrap();
        udp_packet.set_source(12345);
        udp_packet.set_destination(53);
        udp_packet.set_length(12);
        udp_packet.payload_mut().copy_from_slice(&[1, 2, 3, 4]);
        if checksum_enabled {
            udp_packet.set_checksum(udp::ipv4_checksum(&udp_packet.to_immutable(), &src, &dst));
        }
        drop(udp_packet);

        update_ip_packet_checksum(&mut ipv4_packet);
        packet
    }

    fn build_icmp_packet(src: Ipv4Addr, dst: Ipv4Addr, icmp_type: icmp::IcmpType) -> BytesMut {
        let mut packet = BytesMut::new();
        packet.resize(32, 0);
        let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(32);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4_packet.set_source(src);
        ipv4_packet.set_destination(dst);

        let mut icmp_packet = MutableIcmpPacket::new(ipv4_packet.payload_mut()).unwrap();
        icmp_packet.set_icmp_type(icmp_type);
        icmp_packet
            .payload_mut()
            .copy_from_slice(&[0, 0, 0, 0, 1, 2, 3, 4]);
        icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));
        drop(icmp_packet);

        update_ip_packet_checksum(&mut ipv4_packet);
        packet
    }

    fn assert_ipv4_checksum(packet: &BytesMut) {
        let ipv4_packet = Ipv4Packet::new(packet).unwrap();
        assert_eq!(ipv4_packet.get_checksum(), ipv4::checksum(&ipv4_packet));
    }

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

        // preferred ip already taken, should reject the claim
        assert_eq!(allocator.allocate("client2", Some(preferred)), None);
    }

    #[test]
    fn test_ip_allocator_preferred_claim_is_atomic() {
        use std::sync::Barrier;

        let cidr = "10.14.14.0/30".parse().unwrap();
        let allocator = Arc::new(IpAllocator::new(cidr));
        let barrier = Arc::new(Barrier::new(16));
        let preferred = "10.14.14.1".parse().unwrap();

        let handles = (0..16)
            .map(|idx| {
                let allocator = allocator.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    allocator.allocate(&format!("client{idx}"), Some(preferred))
                })
            })
            .collect::<Vec<_>>();

        let allocated = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(allocated, vec![preferred]);
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
    fn test_build_client_config_map_assigns_missing_ips() {
        let cidr = "10.14.14.0/24".parse().unwrap();
        let clients = vec![
            VpnPortalClientConfig {
                name: "client1".to_string(),
                client_public_key: "key1".to_string(),
                assigned_ip: None,
                tunnel_ip: None,
            },
            VpnPortalClientConfig {
                name: "client2".to_string(),
                client_public_key: "key2".to_string(),
                assigned_ip: Some("10.14.14.10".parse().unwrap()),
                tunnel_ip: None,
            },
        ];

        let configs = build_client_config_map(&clients, cidr, Some("10.14.14.1".parse().unwrap()));

        assert_eq!(
            configs.get("client1").and_then(|c| c.assigned_ip),
            Some("10.14.14.2".parse().unwrap())
        );
        assert_eq!(
            configs.get("client2").and_then(|c| c.assigned_ip),
            Some("10.14.14.10".parse().unwrap())
        );
        assert_eq!(
            configs.get("client1").and_then(|c| c.tunnel_ip),
            Some("10.14.14.2".parse().unwrap())
        );
        assert_eq!(
            configs.get("client2").and_then(|c| c.tunnel_ip),
            Some("10.14.14.10".parse().unwrap())
        );
    }

    #[test]
    fn test_build_client_config_map_preserves_tunnel_ip() {
        let cidr = "10.14.14.0/24".parse().unwrap();
        let clients = vec![VpnPortalClientConfig {
            name: "client1".to_string(),
            client_public_key: "key1".to_string(),
            assigned_ip: Some("10.144.144.10".parse().unwrap()),
            tunnel_ip: Some("10.14.14.10".parse().unwrap()),
        }];

        let configs = build_client_config_map(&clients, cidr, Some("10.14.14.1".parse().unwrap()));

        assert_eq!(
            configs.get("client1").and_then(|c| c.assigned_ip),
            Some("10.144.144.10".parse().unwrap())
        );
        assert_eq!(
            configs.get("client1").and_then(|c| c.tunnel_ip),
            Some("10.14.14.10".parse().unwrap())
        );
    }

    #[test]
    fn test_rewrite_ipv4_source_updates_tcp_checksum() {
        let tunnel_ip = "10.14.14.10".parse().unwrap();
        let assigned_ip = "10.144.144.10".parse().unwrap();
        let destination = "10.1.1.1".parse().unwrap();
        let mut packet = build_tcp_packet(tunnel_ip, destination);

        rewrite_ipv4_source(&mut packet, tunnel_ip, assigned_ip).unwrap();

        let ipv4_packet = Ipv4Packet::new(&packet).unwrap();
        assert_eq!(ipv4_packet.get_source(), assigned_ip);
        assert_eq!(ipv4_packet.get_destination(), destination);
        assert_ipv4_checksum(&packet);
        let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(
            tcp_packet.get_checksum(),
            tcp::ipv4_checksum(&tcp_packet, &assigned_ip, &destination)
        );
    }

    #[test]
    fn test_rewrite_ipv4_destination_updates_udp_checksum() {
        let source = "10.1.1.1".parse().unwrap();
        let assigned_ip = "10.144.144.10".parse().unwrap();
        let tunnel_ip = "10.14.14.10".parse().unwrap();
        let mut packet = build_udp_packet(source, assigned_ip, true);

        rewrite_ipv4_destination(&mut packet, assigned_ip, tunnel_ip).unwrap();

        let ipv4_packet = Ipv4Packet::new(&packet).unwrap();
        assert_eq!(ipv4_packet.get_source(), source);
        assert_eq!(ipv4_packet.get_destination(), tunnel_ip);
        assert_ipv4_checksum(&packet);
        let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(
            udp_packet.get_checksum(),
            udp::ipv4_checksum(&udp_packet, &source, &tunnel_ip)
        );
    }

    #[test]
    fn test_rewrite_ipv4_destination_preserves_zero_udp_checksum() {
        let source = "10.1.1.1".parse().unwrap();
        let assigned_ip = "10.144.144.10".parse().unwrap();
        let tunnel_ip = "10.14.14.10".parse().unwrap();
        let mut packet = build_udp_packet(source, assigned_ip, false);

        rewrite_ipv4_destination(&mut packet, assigned_ip, tunnel_ip).unwrap();

        let ipv4_packet = Ipv4Packet::new(&packet).unwrap();
        let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(udp_packet.get_checksum(), 0);
    }

    #[test]
    fn test_rewrite_ipv4_source_accepts_icmp_echo() {
        let tunnel_ip = "10.14.14.10".parse().unwrap();
        let assigned_ip = "10.144.144.10".parse().unwrap();
        let destination = "10.1.1.1".parse().unwrap();
        let mut packet = build_icmp_packet(tunnel_ip, destination, IcmpTypes::EchoRequest);
        let original_icmp_checksum = IcmpPacket::new(Ipv4Packet::new(&packet).unwrap().payload())
            .unwrap()
            .get_checksum();

        rewrite_ipv4_source(&mut packet, tunnel_ip, assigned_ip).unwrap();

        let ipv4_packet = Ipv4Packet::new(&packet).unwrap();
        let icmp_packet = IcmpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(ipv4_packet.get_source(), assigned_ip);
        assert_ipv4_checksum(&packet);
        assert_eq!(icmp_packet.get_checksum(), original_icmp_checksum);
    }

    #[test]
    fn test_rewrite_ipv4_rejects_non_first_fragment() {
        let tunnel_ip = "10.14.14.10".parse().unwrap();
        let assigned_ip = "10.144.144.10".parse().unwrap();
        let destination = "10.1.1.1".parse().unwrap();
        let mut packet = build_tcp_packet(tunnel_ip, destination);
        let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
        ipv4_packet.set_fragment_offset(1);

        assert_eq!(
            rewrite_ipv4_source(&mut packet, tunnel_ip, assigned_ip),
            Err(Ipv4NatError::UnsupportedFragment)
        );
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
        assert_eq!(
            vpn_cfg.clients[1].assigned_ip,
            Some("10.14.14.10".parse().unwrap())
        );
    }
}
