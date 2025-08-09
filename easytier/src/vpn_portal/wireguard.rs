use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use base64::{prelude::BASE64_STANDARD, Engine};
use cidr::Ipv4Inet;
use dashmap::DashMap;
use futures::StreamExt;
use pnet::packet::ipv4::Ipv4Packet;
use tokio::task::JoinSet;
use tracing::Level;

use crate::{
    common::{
        config::NetworkIdentity,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        join_joinset_background,
    },
    peers::{peer_manager::PeerManager, PeerPacketFilter},
    tunnel::{
        mpsc::{MpscTunnel, MpscTunnelSender},
        packet_def::{PacketType, ZCPacket, ZCPacketType},
        wireguard::{WgConfig, WgTunnelListener},
        Tunnel, TunnelListener,
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
}

struct WireGuardImpl {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Arc<PeerManager>,
    wg_config: WgConfig,
    listenr_addr: SocketAddr,

    wg_peer_ip_table: WgPeerIpTable,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl WireGuardImpl {
    fn new(global_ctx: ArcGlobalCtx, peer_mgr: Arc<PeerManager>) -> Self {
        let nid = global_ctx.get_network_identity();
        let wg_config = get_wg_config_for_portal(&nid);

        let vpn_cfg = global_ctx.config.get_vpn_portal_config().unwrap();
        let listenr_addr = vpn_cfg.wireguard_listen;

        Self {
            global_ctx,
            peer_mgr,
            wg_config,
            listenr_addr,
            wg_peer_ip_table: Arc::new(DashMap::new()),
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
        }
    }

    async fn handle_incoming_conn(
        t: Box<dyn Tunnel>,
        peer_mgr: Arc<PeerManager>,
        wg_peer_ip_table: WgPeerIpTable,
    ) {
        let info = t.info().unwrap_or_default();
        let mut mpsc_tunnel = MpscTunnel::new(t, None);
        let mut stream = mpsc_tunnel.get_stream();
        let mut ip_registered = false;

        let remote_addr = info.remote_addr.clone();
        let endpoint_addr = remote_addr.clone().map(Into::into);
        peer_mgr
            .get_global_ctx()
            .issue_event(GlobalCtxEvent::VpnPortalClientConnected(
                info.local_addr.clone().unwrap_or_default().to_string(),
                info.remote_addr.clone().unwrap_or_default().to_string(),
            ));

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
                });
                map_key = Some(i.get_source());
                // Be careful here: we may overwrite an existing entry if the client IP is reused,
                // which is common when clients are behind NAT.
                wg_peer_ip_table.insert(i.get_source(), client_entry.clone());
                ip_registered = true;
            }
            tracing::trace!(?i, "Received from wg client");
            let dst = i.get_destination();
            let _ = peer_mgr
                .send_msg_by_ip(ZCPacket::new_with_payload(inner.as_ref()), IpAddr::V4(dst))
                .await;
        }

        if let Some(map_key) = map_key {
            // Remove the client from the wg_peer_ip_table only when its endpoint address is unchanged,
            // or we may break clients behind NAT.
            match wg_peer_ip_table
                .remove_if(&map_key, |_, entry| entry.endpoint_addr == endpoint_addr)
            {
                Some(_) => tracing::info!(?map_key, "Removed wg client from table"),
                None => tracing::info!(
                    ?map_key,
                    "The wg client changed its endpoint address, not removing from table"
                ),
            }
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

    #[tracing::instrument(skip(self), err(level = Level::WARN))]
    async fn start(&self) -> anyhow::Result<()> {
        let mut l = WgTunnelListener::new(
            format!("wg://{}", self.listenr_addr).parse().unwrap(),
            self.wg_config.clone(),
        );

        tracing::info!("Wireguard VPN Portal Starting");

        {
            let _g = self.global_ctx.net_ns.guard();
            l.listen()
                .await
                .with_context(|| "Failed to start wireguard listener for vpn portal")?;
        }

        join_joinset_background(self.tasks.clone(), "wireguard".to_string());

        let tasks = Arc::downgrade(&self.tasks.clone());
        let peer_mgr = self.peer_mgr.clone();
        let wg_peer_ip_table = self.wg_peer_ip_table.clone();
        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(t) = l.accept().await {
                let Some(tasks) = tasks.upgrade() else {
                    break;
                };
                tasks.lock().unwrap().spawn(Self::handle_incoming_conn(
                    t,
                    peer_mgr.clone(),
                    wg_peer_ip_table.clone(),
                ));
            }
        });

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

        let vpn_cfg = global_ctx.config.get_vpn_portal_config().unwrap();
        let client_cidr = vpn_cfg.client_cidr;

        allow_ips.push(client_cidr.to_string());

        let allow_ips = allow_ips
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let cfg = self.inner.as_ref().unwrap().wg_config.clone();
        let cfg_str = format!(
            r#"
[Interface]
PrivateKey = {peer_secret_key}
Address = {address} # should assign an ip from this cidr manually

[Peer]
PublicKey = {my_public_key}
AllowedIPs = {allow_ips}
Endpoint = {listenr_addr} # should be the public ip(or domain) of the vpn server
PersistentKeepalive = 25
"#,
            peer_secret_key = BASE64_STANDARD.encode(cfg.peer_secret_key()),
            my_public_key = BASE64_STANDARD.encode(cfg.my_public_key()),
            listenr_addr = self.inner.as_ref().unwrap().listenr_addr,
            allow_ips = allow_ips,
            address = client_cidr.first_address().to_string() + "/32",
        );

        cfg_str
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
                        x.value()
                            .endpoint_addr
                            .as_ref()
                            .map(|x| x.to_string())
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}
