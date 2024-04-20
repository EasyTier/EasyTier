use std::{
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

use anyhow::Context;
use base64::{prelude::BASE64_STANDARD, Engine};
use cidr::Ipv4Inet;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use pnet::packet::ipv4::Ipv4Packet;
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::bytes::Bytes;

use crate::{
    common::{
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        join_joinset_background,
    },
    peers::{
        packet::{self, ArchivedPacket},
        peer_manager::PeerManager,
        PeerPacketFilter,
    },
    tunnel::packet_def::{PacketType, ZCPacket},
    tunnels::{
        wireguard::{WgConfig, WgTunnelListener},
        DatagramSink, Tunnel, TunnelListener,
    },
};

use super::VpnPortal;

type WgPeerIpTable = Arc<DashMap<Ipv4Addr, Arc<ClientEntry>>>;

struct ClientEntry {
    endpoint_addr: Option<url::Url>,
    sink: Mutex<Pin<Box<dyn DatagramSink + 'static>>>,
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
        let key_seed = format!("{}{}", nid.network_name, nid.network_secret);
        let wg_config = WgConfig::new_for_portal(&key_seed, &key_seed);

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
        let mut s = t.pin_stream();
        let mut ip_registered = false;

        let info = t.info().unwrap_or_default();
        let remote_addr = info.remote_addr.clone();
        peer_mgr
            .get_global_ctx()
            .issue_event(GlobalCtxEvent::VpnPortalClientConnected(
                info.local_addr,
                info.remote_addr,
            ));

        while let Some(Ok(msg)) = s.next().await {
            let Some(i) = Ipv4Packet::new(&msg) else {
                tracing::error!(?msg, "Failed to parse ipv4 packet");
                continue;
            };
            if !ip_registered {
                let client_entry = Arc::new(ClientEntry {
                    endpoint_addr: remote_addr.parse().ok(),
                    sink: Mutex::new(t.pin_sink()),
                });
                wg_peer_ip_table.insert(i.get_source(), client_entry.clone());
                ip_registered = true;
            }
            tracing::trace!(?i, "Received from wg client");
            let dst = i.get_destination();
            drop(i);
            let _ = peer_mgr
                .send_msg_ipv4(ZCPacket::new_with_payload(msg), dst)
                .await;
        }

        let info = t.info().unwrap_or_default();
        peer_mgr
            .get_global_ctx()
            .issue_event(GlobalCtxEvent::VpnPortalClientDisconnected(
                info.local_addr,
                info.remote_addr,
            ));
    }

    async fn start_pipeline_processor(&self) {
        struct PeerPacketFilterForVpnPortal {
            wg_peer_ip_table: WgPeerIpTable,
        }

        impl PeerPacketFilterForVpnPortal {
            async fn try_handle_peer_packet(&self, packet: &ZCPacket) -> Option<()> {
                let hdr = packet.peer_manager_header().unwrap();
                if hdr.packet_type != PacketType::Data as u8 {
                    return None;
                };

                let payload_bytes = packet.payload();
                let ipv4 = Ipv4Packet::new(payload_bytes)?;
                if ipv4.get_version() != 4 {
                    return None;
                }

                let entry = self.wg_peer_ip_table.get(&ipv4.get_destination())?.clone();

                tracing::trace!(?ipv4, "Packet filter for vpn portal");

                let ret = entry
                    .sink
                    .lock()
                    .await
                    .send(Bytes::copy_from_slice(payload_bytes))
                    .await;

                ret.ok()
            }
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for PeerPacketFilterForVpnPortal {
            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                if let Some(_) = self.try_handle_peer_packet(&packet).await {
                    return None;
                } else {
                    return Some(packet);
                }
            }
        }

        self.peer_mgr
            .add_packet_process_pipeline(Box::new(PeerPacketFilterForVpnPortal {
                wg_peer_ip_table: self.wg_peer_ip_table.clone(),
            }))
            .await;
    }

    async fn start(&self) -> anyhow::Result<()> {
        let mut l = WgTunnelListener::new(
            format!("wg://{}", self.listenr_addr).parse().unwrap(),
            self.wg_config.clone(),
        );

        l.listen()
            .await
            .with_context(|| "Failed to start wireguard listener for vpn portal")?;

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
            .map(|x| x.proxy_cidrs.iter().map(String::to_string))
            .flatten()
            .collect::<Vec<_>>();
        for ipv4 in routes
            .iter()
            .map(|x| x.ipv4_addr.clone())
            .chain(global_ctx.get_ipv4().iter().map(|x| x.to_string()))
        {
            let Ok(ipv4) = ipv4.parse() else {
                continue;
            };
            let inet = Ipv4Inet::new(ipv4, 24).unwrap();
            allow_ips.push(inet.network().to_string());
            break;
        }

        let allow_ips = allow_ips
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let vpn_cfg = global_ctx.config.get_vpn_portal_config().unwrap();
        let client_cidr = vpn_cfg.client_cidr;

        let cfg = self.inner.as_ref().unwrap().wg_config.clone();
        let cfg_str = format!(
            r#"
[Interface]
PrivateKey = {peer_secret_key}
Address = {client_cidr} # should assign an ip from this cidr manually

[Peer]
PublicKey = {my_public_key}
AllowedIPs = {allow_ips}
Endpoint = {listenr_addr} # should be the public ip of the vpn server
"#,
            peer_secret_key = BASE64_STANDARD.encode(cfg.peer_secret_key()),
            my_public_key = BASE64_STANDARD.encode(cfg.my_public_key()),
            listenr_addr = self.inner.as_ref().unwrap().listenr_addr,
            allow_ips = allow_ips,
            client_cidr = client_cidr,
        );

        cfg_str
    }

    fn name(&self) -> String {
        "wireguard".to_string()
    }

    async fn list_clients(&self) -> Vec<String> {
        self.inner
            .as_ref()
            .unwrap()
            .wg_peer_ip_table
            .iter()
            .map(|x| {
                x.value()
                    .endpoint_addr
                    .as_ref()
                    .map(|x| x.to_string())
                    .unwrap_or_default()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    use crate::{
        common::{
            config::{NetworkIdentity, VpnPortalConfig},
            global_ctx::tests::get_mock_global_ctx_with_network,
        },
        connector::udp_hole_punch::tests::replace_stun_info_collector,
        peers::{
            peer_manager::{PeerManager, RouteAlgoType},
            tests::wait_for_condition,
        },
        rpc::NatType,
        tunnels::{tcp_tunnel::TcpTunnelConnector, TunnelConnector},
    };

    async fn portal_test() {
        let (s, _r) = tokio::sync::mpsc::channel(1000);
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            get_mock_global_ctx_with_network(Some(NetworkIdentity {
                network_name: "sijie".to_string(),
                network_secret: "1919119".to_string(),
            })),
            s,
        ));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr
            .get_global_ctx()
            .config
            .set_vpn_portal_config(VpnPortalConfig {
                wireguard_listen: "0.0.0.0:11021".parse().unwrap(),
                client_cidr: "10.14.14.0/24".parse().unwrap(),
            });
        peer_mgr.run().await.unwrap();
        let mut pmgr_conn = TcpTunnelConnector::new("tcp://127.0.0.1:11010".parse().unwrap());
        let tunnel = pmgr_conn.connect().await;
        // peer_mgr.add_client_tunnel(tunnel.unwrap()).await.unwrap();
        wait_for_condition(
            || async {
                let routes = peer_mgr.list_routes().await;
                println!("Routes: {:?}", routes);
                routes.len() != 0
            },
            std::time::Duration::from_secs(10),
        )
        .await;

        let mut wg = WireGuard::default();
        wg.start(peer_mgr.get_global_ctx(), peer_mgr.clone())
            .await
            .unwrap();
    }
}
