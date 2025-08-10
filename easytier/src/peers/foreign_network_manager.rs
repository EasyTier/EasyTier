/*
foreign_network_manager is used to forward packets of other networks.  currently
only forward packets of peers that directly connected to this node.

in future, with the help wo peer center we can forward packets of peers that
connected to any node in the local network.
*/
use std::{
    sync::{Arc, Weak},
    time::SystemTime,
};

use dashmap::{DashMap, DashSet};
use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
    task::JoinSet,
};

use crate::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent, NetworkIdentity},
        join_joinset_background,
        stats_manager::{LabelSet, LabelType, MetricName, StatsManager},
        token_bucket::TokenBucket,
        PeerId,
    },
    peer_center::instance::{PeerCenterInstance, PeerMapWithPeerRpcManager},
    peers::route_trait::{Route, RouteInterface},
    proto::{
        cli::{ForeignNetworkEntryPb, ListForeignNetworkResponse, PeerInfo},
        common::LimiterConfig,
        peer_rpc::DirectConnectorRpcServer,
    },
    tunnel::packet_def::{PacketType, ZCPacket},
    use_global_var,
};

use super::{
    create_packet_recv_chan,
    peer_conn::PeerConn,
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
    peer_rpc_service::DirectConnectorManagerRpcServer,
    recv_packet_from_chan,
    route_trait::NextHopPolicy,
    PacketRecvChan, PacketRecvChanReceiver,
};

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Box, Arc)]
pub trait GlobalForeignNetworkAccessor: Send + Sync + 'static {
    async fn list_global_foreign_peer(&self, network_identity: &NetworkIdentity) -> Vec<PeerId>;
}

struct ForeignNetworkEntry {
    my_peer_id: PeerId,

    global_ctx: ArcGlobalCtx,
    network: NetworkIdentity,
    peer_map: Arc<PeerMap>,
    relay_data: bool,
    pm_packet_sender: Mutex<Option<PacketRecvChan>>,

    peer_rpc: Arc<PeerRpcManager>,
    rpc_sender: UnboundedSender<ZCPacket>,

    packet_recv: Mutex<Option<PacketRecvChanReceiver>>,

    bps_limiter: Arc<TokenBucket>,

    peer_center: Arc<PeerCenterInstance>,

    stats_mgr: Arc<StatsManager>,

    tasks: Mutex<JoinSet<()>>,

    pub lock: Mutex<()>,
}

impl ForeignNetworkEntry {
    fn new(
        network: NetworkIdentity,
        // NOTICE: ospf route need my_peer_id be changed after restart.
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        relay_data: bool,
        pm_packet_sender: PacketRecvChan,
    ) -> Self {
        let stats_mgr = global_ctx.stats_manager().clone();
        let foreign_global_ctx = Self::build_foreign_global_ctx(&network, global_ctx.clone());

        let (packet_sender, packet_recv) = create_packet_recv_chan();

        let peer_map = Arc::new(PeerMap::new(
            packet_sender,
            foreign_global_ctx.clone(),
            my_peer_id,
        ));

        let (peer_rpc, rpc_transport_sender) = Self::build_rpc_tspt(my_peer_id, peer_map.clone());

        peer_rpc.rpc_server().registry().register(
            DirectConnectorRpcServer::new(DirectConnectorManagerRpcServer::new(
                foreign_global_ctx.clone(),
            )),
            &network.network_name,
        );

        let relay_bps_limit = global_ctx.config.get_flags().foreign_relay_bps_limit;
        let limiter_config = LimiterConfig {
            burst_rate: None,
            bps: Some(relay_bps_limit),
            fill_duration_ms: None,
        };
        let bps_limiter = global_ctx
            .token_bucket_manager()
            .get_or_create(&network.network_name, limiter_config.into());

        let peer_center = Arc::new(PeerCenterInstance::new(Arc::new(
            PeerMapWithPeerRpcManager {
                peer_map: peer_map.clone(),
                rpc_mgr: peer_rpc.clone(),
            },
        )));

        Self {
            my_peer_id,

            global_ctx: foreign_global_ctx,
            network,
            peer_map,
            relay_data,
            pm_packet_sender: Mutex::new(Some(pm_packet_sender)),

            peer_rpc,
            rpc_sender: rpc_transport_sender,

            packet_recv: Mutex::new(Some(packet_recv)),

            bps_limiter,

            stats_mgr,

            tasks: Mutex::new(JoinSet::new()),

            peer_center,

            lock: Mutex::new(()),
        }
    }

    fn build_foreign_global_ctx(
        network: &NetworkIdentity,
        global_ctx: ArcGlobalCtx,
    ) -> ArcGlobalCtx {
        let config = TomlConfigLoader::default();
        config.set_network_identity(network.clone());
        config.set_hostname(Some(format!("PublicServer_{}", global_ctx.get_hostname())));

        let mut flags = config.get_flags();
        flags.disable_relay_kcp = !global_ctx.get_flags().enable_relay_foreign_network_kcp;
        config.set_flags(flags);

        let foreign_global_ctx = Arc::new(GlobalCtx::new(config));
        foreign_global_ctx
            .replace_stun_info_collector(Box::new(global_ctx.get_stun_info_collector().clone()));

        let mut feature_flag = global_ctx.get_feature_flags();
        feature_flag.is_public_server = true;
        foreign_global_ctx.set_feature_flags(feature_flag);

        for u in global_ctx.get_running_listeners().into_iter() {
            foreign_global_ctx.add_running_listener(u);
        }

        foreign_global_ctx
    }

    fn build_rpc_tspt(
        my_peer_id: PeerId,
        peer_map: Arc<PeerMap>,
    ) -> (Arc<PeerRpcManager>, UnboundedSender<ZCPacket>) {
        struct RpcTransport {
            my_peer_id: PeerId,
            peer_map: Weak<PeerMap>,

            packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
        }

        #[async_trait::async_trait]
        impl PeerRpcManagerTransport for RpcTransport {
            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }

            async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
                tracing::debug!(
                    "foreign network manager send rpc to peer: {:?}",
                    dst_peer_id
                );
                let peer_map = self
                    .peer_map
                    .upgrade()
                    .ok_or(anyhow::anyhow!("peer map is gone"))?;

                // send to ourselves so we can handle it in forward logic.
                peer_map.send_msg_directly(msg, self.my_peer_id).await
            }

            async fn recv(&self) -> Result<ZCPacket, Error> {
                if let Some(o) = self.packet_recv.lock().await.recv().await {
                    tracing::info!("recv rpc packet in foreign network manager rpc transport");
                    Ok(o)
                } else {
                    Err(Error::Unknown)
                }
            }
        }

        impl Drop for RpcTransport {
            fn drop(&mut self) {
                tracing::debug!(
                    "drop rpc transport for foreign network manager, my_peer_id: {:?}",
                    self.my_peer_id
                );
            }
        }

        let (rpc_transport_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        let tspt = RpcTransport {
            my_peer_id,
            peer_map: Arc::downgrade(&peer_map),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
        };

        let peer_rpc = Arc::new(PeerRpcManager::new(tspt));
        (peer_rpc, rpc_transport_sender)
    }

    async fn prepare_route(&self, accessor: Box<dyn GlobalForeignNetworkAccessor>) {
        struct Interface {
            my_peer_id: PeerId,
            peer_map: Weak<PeerMap>,
            network_identity: NetworkIdentity,
            accessor: Box<dyn GlobalForeignNetworkAccessor>,
        }

        #[async_trait::async_trait]
        impl RouteInterface for Interface {
            async fn list_peers(&self) -> Vec<PeerId> {
                let Some(peer_map) = self.peer_map.upgrade() else {
                    return vec![];
                };

                let mut global = self
                    .accessor
                    .list_global_foreign_peer(&self.network_identity)
                    .await;
                let local = peer_map.list_peers_with_conn().await;
                global.extend(local.iter().cloned());
                global
                    .into_iter()
                    .filter(|x| *x != self.my_peer_id)
                    .collect()
            }

            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }
        }

        let route = PeerRoute::new(
            self.my_peer_id,
            self.global_ctx.clone(),
            self.peer_rpc.clone(),
        );
        route
            .open(Box::new(Interface {
                my_peer_id: self.my_peer_id,
                network_identity: self.network.clone(),
                peer_map: Arc::downgrade(&self.peer_map),
                accessor,
            }))
            .await
            .unwrap();

        route
            .set_route_cost_fn(self.peer_center.get_cost_calculator())
            .await;

        self.peer_map.add_route(Arc::new(Box::new(route))).await;
    }

    async fn start_packet_recv(&self) {
        let mut recv = self.packet_recv.lock().await.take().unwrap();
        let my_node_id = self.my_peer_id;
        let rpc_sender = self.rpc_sender.clone();
        let peer_map = self.peer_map.clone();
        let relay_data = self.relay_data;
        let pm_sender = self.pm_packet_sender.lock().await.take().unwrap();
        let network_name = self.network.network_name.clone();
        let bps_limiter = self.bps_limiter.clone();

        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone()));
        let forward_bytes = self
            .stats_mgr
            .get_counter(MetricName::TrafficBytesForwarded, label_set.clone());
        let forward_packets = self
            .stats_mgr
            .get_counter(MetricName::TrafficPacketsForwarded, label_set.clone());
        let rx_bytes = self
            .stats_mgr
            .get_counter(MetricName::TrafficBytesSelfRx, label_set.clone());
        let rx_packets = self
            .stats_mgr
            .get_counter(MetricName::TrafficPacketsRx, label_set.clone());

        self.tasks.lock().await.spawn(async move {
            while let Ok(zc_packet) = recv_packet_from_chan(&mut recv).await {
                let buf_len = zc_packet.buf_len();
                let Some(hdr) = zc_packet.peer_manager_header() else {
                    tracing::warn!("invalid packet, skip");
                    continue;
                };
                tracing::info!(?hdr, "recv packet in foreign network manager");
                let to_peer_id = hdr.to_peer_id.get();
                if to_peer_id == my_node_id {
                    if hdr.packet_type == PacketType::TaRpc as u8
                        || hdr.packet_type == PacketType::RpcReq as u8
                        || hdr.packet_type == PacketType::RpcResp as u8
                    {
                        rx_bytes.add(buf_len as u64);
                        rx_packets.inc();
                        rpc_sender.send(zc_packet).unwrap();
                        continue;
                    }
                    tracing::trace!(?hdr, "ignore packet in foreign network");
                } else {
                    if hdr.packet_type == PacketType::Data as u8
                        || hdr.packet_type == PacketType::KcpSrc as u8
                        || hdr.packet_type == PacketType::KcpDst as u8
                    {
                        if !relay_data {
                            continue;
                        }
                        if !bps_limiter.try_consume(hdr.len.into()) {
                            continue;
                        }
                    }

                    forward_bytes.add(buf_len as u64);
                    forward_packets.inc();

                    let gateway_peer_id = peer_map
                        .get_gateway_peer_id(to_peer_id, NextHopPolicy::LeastHop)
                        .await;

                    match gateway_peer_id {
                        Some(peer_id) if peer_map.has_peer(peer_id) => {
                            if let Err(e) = peer_map.send_msg_directly(zc_packet, peer_id).await {
                                tracing::error!(
                                    ?e,
                                    "send packet to foreign peer inside peer map failed"
                                );
                            }
                        }
                        _ => {
                            let mut foreign_packet = ZCPacket::new_for_foreign_network(
                                &network_name,
                                to_peer_id,
                                &zc_packet,
                            );
                            let via_peer = gateway_peer_id.unwrap_or(to_peer_id);
                            foreign_packet.fill_peer_manager_hdr(
                                my_node_id,
                                via_peer,
                                PacketType::ForeignNetworkPacket as u8,
                            );
                            if let Err(e) = pm_sender.send(foreign_packet).await {
                                tracing::error!("send packet to peer with pm failed: {:?}", e);
                            }
                        }
                    };
                }
            }
        });
    }

    async fn prepare(&self, accessor: Box<dyn GlobalForeignNetworkAccessor>) {
        self.prepare_route(accessor).await;
        self.start_packet_recv().await;
        self.peer_rpc.run();
        self.peer_center.init().await;
    }
}

impl Drop for ForeignNetworkEntry {
    fn drop(&mut self) {
        self.peer_rpc
            .rpc_server()
            .registry()
            .unregister_by_domain(&self.network.network_name);

        tracing::debug!(self.my_peer_id, ?self.network, "drop foreign network entry");
    }
}

struct ForeignNetworkManagerData {
    network_peer_maps: DashMap<String, Arc<ForeignNetworkEntry>>,
    peer_network_map: DashMap<PeerId, DashSet<String>>,
    network_peer_last_update: DashMap<String, SystemTime>,
    accessor: Arc<Box<dyn GlobalForeignNetworkAccessor>>,
    lock: std::sync::Mutex<()>,
}

impl ForeignNetworkManagerData {
    fn get_peer_network(&self, peer_id: PeerId) -> Option<DashSet<String>> {
        self.peer_network_map.get(&peer_id).map(|v| v.clone())
    }

    fn get_network_entry(&self, network_name: &str) -> Option<Arc<ForeignNetworkEntry>> {
        self.network_peer_maps.get(network_name).map(|v| v.clone())
    }

    fn remove_peer(&self, peer_id: PeerId, network_name: &String) {
        let _l = self.lock.lock().unwrap();
        self.peer_network_map.remove_if(&peer_id, |_, v| {
            let _ = v.remove(network_name);
            v.is_empty()
        });
        if self
            .network_peer_maps
            .remove_if(network_name, |_, v| v.peer_map.is_empty())
            .is_some()
        {
            self.network_peer_last_update.remove(network_name);
        }
    }

    async fn clear_no_conn_peer(&self, network_name: &String) {
        let Some(peer_map) = self
            .network_peer_maps
            .get(network_name)
            .map(|v| v.peer_map.clone())
        else {
            return;
        };
        peer_map.clean_peer_without_conn().await;
    }

    fn remove_network(&self, network_name: &String) {
        let _l = self.lock.lock().unwrap();
        self.peer_network_map.iter().for_each(|v| {
            v.value().remove(network_name);
        });
        self.peer_network_map.retain(|_, v| !v.is_empty());
        self.network_peer_maps.remove(network_name);
        self.network_peer_last_update.remove(network_name);
    }

    async fn get_or_insert_entry(
        &self,
        network_identity: &NetworkIdentity,
        my_peer_id: PeerId,
        dst_peer_id: PeerId,
        relay_data: bool,
        global_ctx: &ArcGlobalCtx,
        pm_packet_sender: &PacketRecvChan,
    ) -> (Arc<ForeignNetworkEntry>, bool) {
        let mut new_added = false;

        let l = self.lock.lock().unwrap();
        let entry = self
            .network_peer_maps
            .entry(network_identity.network_name.clone())
            .or_insert_with(|| {
                new_added = true;
                Arc::new(ForeignNetworkEntry::new(
                    network_identity.clone(),
                    my_peer_id,
                    global_ctx.clone(),
                    relay_data,
                    pm_packet_sender.clone(),
                ))
            })
            .clone();

        self.peer_network_map
            .entry(dst_peer_id)
            .or_default()
            .insert(network_identity.network_name.clone());

        self.network_peer_last_update
            .insert(network_identity.network_name.clone(), SystemTime::now());

        drop(l);

        if new_added {
            entry.prepare(Box::new(self.accessor.clone())).await;
        }

        (entry, new_added)
    }
}

pub const FOREIGN_NETWORK_SERVICE_ID: u32 = 1;

pub struct ForeignNetworkManager {
    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,
    packet_sender_to_mgr: PacketRecvChan,

    data: Arc<ForeignNetworkManagerData>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl ForeignNetworkManager {
    pub fn new(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        packet_sender_to_mgr: PacketRecvChan,
        accessor: Box<dyn GlobalForeignNetworkAccessor>,
    ) -> Self {
        let data = Arc::new(ForeignNetworkManagerData {
            network_peer_maps: DashMap::new(),
            peer_network_map: DashMap::new(),
            network_peer_last_update: DashMap::new(),
            accessor: Arc::new(accessor),
            lock: std::sync::Mutex::new(()),
        });

        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "ForeignNetworkManager".to_string());

        Self {
            my_peer_id,
            global_ctx,
            packet_sender_to_mgr,

            data,

            tasks,
        }
    }

    pub fn get_network_peer_id(&self, network_name: &str) -> Option<PeerId> {
        self.data
            .network_peer_maps
            .get(network_name)
            .map(|v| v.my_peer_id)
    }

    pub async fn add_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        tracing::info!(peer_conn = ?peer_conn.get_conn_info(), network = ?peer_conn.get_network_identity(), "add new peer conn in foreign network manager");

        let relay_peer_rpc = self.global_ctx.get_flags().relay_all_peer_rpc;
        let ret = self
            .global_ctx
            .check_network_in_whitelist(&peer_conn.get_network_identity().network_name)
            .map_err(Into::into);
        if ret.is_err() && !relay_peer_rpc {
            return ret;
        }

        let (entry, new_added) = self
            .data
            .get_or_insert_entry(
                &peer_conn.get_network_identity(),
                peer_conn.get_my_peer_id(),
                peer_conn.get_peer_id(),
                ret.is_ok(),
                &self.global_ctx,
                &self.packet_sender_to_mgr,
            )
            .await;

        let _g = entry.lock.lock().await;

        if entry.network != peer_conn.get_network_identity()
            || entry.my_peer_id != peer_conn.get_my_peer_id()
        {
            if new_added {
                self.data
                    .remove_network(&entry.network.network_name.clone());
            }
            let err = if entry.my_peer_id != peer_conn.get_my_peer_id() {
                anyhow::anyhow!(
                    "my peer id not match. exp: {:?} real: {:?}, need retry connect",
                    entry.my_peer_id,
                    peer_conn.get_my_peer_id()
                )
            } else {
                anyhow::anyhow!(
                    "network secret not match. exp: {:?} real: {:?}",
                    entry.network,
                    peer_conn.get_network_identity()
                )
            };
            tracing::error!(?err, "foreign network entry not match, disconnect peer");
            return Err(err.into());
        }

        if new_added {
            self.start_event_handler(&entry).await;
        } else if let Some(peer) = entry.peer_map.get_peer_by_id(peer_conn.get_peer_id()) {
            let direct_conns_len = peer.get_directly_connections().len();
            let max_count = use_global_var!(MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK);
            if direct_conns_len >= max_count as usize {
                return Err(anyhow::anyhow!(
                    "too many direct conns, cur: {}, max: {}",
                    direct_conns_len,
                    max_count
                )
                .into());
            }
        }

        entry.peer_map.add_new_peer_conn(peer_conn).await;
        Ok(())
    }

    async fn start_event_handler(&self, entry: &ForeignNetworkEntry) {
        let data = self.data.clone();
        let network_name = entry.network.network_name.clone();
        let mut s = entry.global_ctx.subscribe();
        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(e) = s.recv().await {
                match &e {
                    GlobalCtxEvent::PeerRemoved(peer_id) => {
                        tracing::info!(?e, "remove peer from foreign network manager");
                        data.remove_peer(*peer_id, &network_name);
                        data.network_peer_last_update
                            .insert(network_name.clone(), SystemTime::now());
                    }
                    GlobalCtxEvent::PeerConnRemoved(..) => {
                        tracing::info!(?e, "clear no conn peer from foreign network manager");
                        data.clear_no_conn_peer(&network_name).await;
                    }
                    GlobalCtxEvent::PeerAdded(_) => {
                        tracing::info!(?e, "add peer to foreign network manager");
                        data.network_peer_last_update
                            .insert(network_name.clone(), SystemTime::now());
                    }
                    _ => continue,
                }
            }
            // if lagged or recv done just remove the network
            tracing::error!("global event handler at foreign network manager exit");
            data.remove_network(&network_name);
        });
    }

    pub async fn list_foreign_networks(&self) -> ListForeignNetworkResponse {
        let mut ret = ListForeignNetworkResponse::default();
        let networks = self
            .data
            .network_peer_maps
            .iter()
            .map(|v| v.key().clone())
            .collect::<Vec<_>>();

        for network_name in networks {
            let Some(item) = self
                .data
                .network_peer_maps
                .get(&network_name)
                .map(|v| v.clone())
            else {
                continue;
            };

            let mut entry = ForeignNetworkEntryPb {
                network_secret_digest: item
                    .network
                    .network_secret_digest
                    .unwrap_or_default()
                    .to_vec(),
                my_peer_id_for_this_network: item.my_peer_id,
                peers: Default::default(),
            };
            for peer in item.peer_map.list_peers().await {
                let peer_info = PeerInfo {
                    peer_id: peer,
                    conns: item.peer_map.list_peer_conns(peer).await.unwrap_or(vec![]),
                    ..Default::default()
                };
                entry.peers.push(peer_info);
            }

            ret.foreign_networks.insert(network_name, entry);
        }
        ret
    }

    pub fn get_foreign_network_last_update(&self, network_name: &str) -> Option<SystemTime> {
        self.data
            .network_peer_last_update
            .get(network_name)
            .map(|v| *v)
    }

    pub async fn send_msg_to_peer(
        &self,
        network_name: &str,
        dst_peer_id: PeerId,
        msg: ZCPacket,
    ) -> Result<(), Error> {
        if let Some(entry) = self.data.get_network_entry(network_name) {
            entry
                .peer_map
                .send_msg(msg, dst_peer_id, NextHopPolicy::LeastHop)
                .await
        } else {
            Err(Error::RouteError(Some("network not found".to_string())))
        }
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &super::peer_conn::PeerConnId,
    ) -> Result<(), Error> {
        let network_names = self.data.get_peer_network(peer_id).unwrap_or_default();
        for network_name in network_names {
            if let Some(entry) = self.data.get_network_entry(&network_name) {
                let ret = entry.peer_map.close_peer_conn(peer_id, conn_id).await;
                if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
                    return ret;
                }
            }
        }
        Err(Error::NotFound)
    }
}

impl Drop for ForeignNetworkManager {
    fn drop(&mut self) {
        self.data.peer_network_map.clear();
        self.data.network_peer_maps.clear();
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx_with_network,
        connector::udp_hole_punch::tests::{
            create_mock_peer_manager_with_mock_stun, replace_stun_info_collector,
        },
        peers::{
            peer_manager::{PeerManager, RouteAlgoType},
            tests::{connect_peer_manager, wait_route_appear},
        },
        proto::common::NatType,
        set_global_var,
        tunnel::common::tests::wait_for_condition,
    };
    use std::time::Duration;

    use super::*;

    async fn create_mock_peer_manager_for_foreign_network_ext(
        network: &str,
        secret: &str,
    ) -> Arc<PeerManager> {
        let (s, _r) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                network.to_string(),
                secret.to_string(),
            ))),
            s,
        ));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.run().await.unwrap();
        peer_mgr
    }

    pub async fn create_mock_peer_manager_for_foreign_network(network: &str) -> Arc<PeerManager> {
        create_mock_peer_manager_for_foreign_network_ext(network, network).await
    }

    #[tokio::test]
    async fn foreign_network_basic() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        assert_eq!(2, pma_net1.list_routes().await.len());
        assert_eq!(2, pmb_net1.list_routes().await.len());

        println!("{:?}", pmb_net1.list_routes().await);

        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(1, rpc_resp.foreign_networks.len());
        assert_eq!(2, rpc_resp.foreign_networks["net1"].peers.len());
    }

    async fn foreign_network_whitelist_helper(name: String) {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());
        let mut flag = pm_center.get_global_ctx().get_flags();
        flag.relay_network_whitelist = ["net1".to_string(), "net2*".to_string()].join(" ");
        pm_center.get_global_ctx().config.set_flags(flag);

        let pma_net1 = create_mock_peer_manager_for_foreign_network(name.as_str()).await;

        let (a_ring, b_ring) = crate::tunnel::ring::create_ring_tunnel_pair();
        let b_mgr_copy = pm_center.clone();
        let s_ret =
            tokio::spawn(async move { b_mgr_copy.add_tunnel_as_server(b_ring, true).await });

        pma_net1.add_client_tunnel(a_ring, false).await.unwrap();

        s_ret.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn foreign_network_whitelist() {
        foreign_network_whitelist_helper("net1".to_string()).await;
        foreign_network_whitelist_helper("net2".to_string()).await;
        foreign_network_whitelist_helper("net2abc".to_string()).await;
    }

    #[tokio::test]
    async fn only_relay_peer_rpc() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let mut flag = pm_center.get_global_ctx().get_flags();
        flag.relay_network_whitelist = "".to_string();
        flag.relay_all_peer_rpc = true;
        pm_center.get_global_ctx().config.set_flags(flag);
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        assert_eq!(2, pma_net1.list_routes().await.len());
        assert_eq!(2, pmb_net1.list_routes().await.len());
    }

    #[tokio::test]
    #[should_panic]
    async fn foreign_network_whitelist_fail() {
        foreign_network_whitelist_helper("net3".to_string()).await;
    }

    #[tokio::test]
    async fn test_foreign_network_manager() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(pm_center.clone(), pm_center2.clone()).await;

        tracing::debug!(
            "pm_center: {:?}, pm_center2: {:?}",
            pm_center.my_peer_id(),
            pm_center2.my_peer_id()
        );

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;

        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );

        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        assert_eq!(
            vec![pm_center
                .get_foreign_network_manager()
                .get_network_peer_id("net1")
                .unwrap()],
            pma_net1
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .await
        );
        assert_eq!(
            vec![pm_center
                .get_foreign_network_manager()
                .get_network_peer_id("net1")
                .unwrap()],
            pmb_net1
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .await
        );

        assert_eq!(2, pma_net1.list_routes().await.len());
        assert_eq!(2, pmb_net1.list_routes().await.len());

        let pmc_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pmc_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();
        wait_route_appear(pmb_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();
        assert_eq!(3, pmc_net1.list_routes().await.len());

        tracing::debug!("pmc_net1: {:?}", pmc_net1.my_peer_id());

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        tracing::debug!(
            "pma_net2: {:?}, pmb_net2: {:?}",
            pma_net2.my_peer_id(),
            pmb_net2.my_peer_id()
        );
        connect_peer_manager(pma_net2.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
        assert_eq!(2, pma_net2.list_routes().await.len());
        assert_eq!(2, pmb_net2.list_routes().await.len());

        assert_eq!(
            5,
            pm_center
                .get_foreign_network_manager()
                .data
                .peer_network_map
                .len()
        );

        assert_eq!(
            2,
            pm_center
                .get_foreign_network_manager()
                .data
                .network_peer_maps
                .len()
        );

        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(2, rpc_resp.foreign_networks.len());
        assert_eq!(3, rpc_resp.foreign_networks["net1"].peers.len());
        assert_eq!(2, rpc_resp.foreign_networks["net2"].peers.len());

        drop(pmb_net2);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            4,
            pm_center
                .get_foreign_network_manager()
                .data
                .peer_network_map
                .len()
        );
        drop(pma_net2);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            3,
            pm_center
                .get_foreign_network_manager()
                .data
                .peer_network_map
                .len()
        );
        assert_eq!(
            1,
            pm_center
                .get_foreign_network_manager()
                .data
                .network_peer_maps
                .len()
        );
    }

    #[tokio::test]
    async fn test_disconnect_foreign_network() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());
        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        tracing::debug!("pma_net1: {:?}", pma_net1.my_peer_id(),);

        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;

        wait_for_condition(
            || async { pma_net1.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;

        drop(pm_center);
        wait_for_condition(
            || async { pma_net1.list_routes().await.is_empty() },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_simple() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center2.clone()).await;

        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        connect_peer_manager(pma_net2.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center2.clone()).await;

        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_multiple_hops() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center3 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center4 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;
        connect_peer_manager(pm_center2.clone(), pm_center3.clone()).await;
        connect_peer_manager(pm_center3.clone(), pm_center4.clone()).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center3.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        let pmc_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pmc_net1.clone(), pm_center4.clone()).await;
        wait_route_appear(pma_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        connect_peer_manager(pma_net2.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center4.clone()).await;
        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
        drop(pmb_net2);
        wait_for_condition(
            || async { pma_net2.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center3 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;
        connect_peer_manager(pm_center2.clone(), pm_center3.clone()).await;

        tracing::debug!(
            "pm_center: {:?}, pm_center2: {:?}",
            pm_center1.my_peer_id(),
            pm_center2.my_peer_id()
        );

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center2.clone()).await;

        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );

        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        assert_eq!(3, pma_net1.list_routes().await.len(),);

        let pmc_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pmc_net1.clone(), pm_center3.clone()).await;
        wait_route_appear(pma_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();
        assert_eq!(5, pma_net1.list_routes().await.len(),);

        println!(
            "pm_center1: {:?}, pm_center2: {:?}, pm_center3: {:?}",
            pm_center1.my_peer_id(),
            pm_center2.my_peer_id(),
            pm_center3.my_peer_id()
        );
        println!(
            "pma_net1: {:?}, pmb_net1: {:?}, pmc_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id(),
            pmc_net1.my_peer_id()
        );

        println!("drop pmc_net1, id: {:?}", pmc_net1.my_peer_id());

        // foreign network node disconnect
        drop(pmc_net1);
        wait_for_condition(
            || async { pma_net1.list_routes().await.len() == 3 },
            Duration::from_secs(15),
        )
        .await;

        println!("drop pm_center1, id: {:?}", pm_center1.my_peer_id());
        drop(pm_center1);
        wait_for_condition(
            || async { pma_net1.list_routes().await.is_empty() },
            Duration::from_secs(5),
        )
        .await;
        wait_for_condition(
            || async {
                let n = pmb_net1
                    .get_route()
                    .get_next_hop(pma_net1.my_peer_id())
                    .await;
                n.is_none()
            },
            Duration::from_secs(5),
        )
        .await;
        wait_for_condition(
            || async {
                // only remain pmb center
                pmb_net1.list_routes().await.len() == 1
            },
            Duration::from_secs(15),
        )
        .await;
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_multi_net() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center3 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;
        connect_peer_manager(pm_center2.clone(), pm_center3.clone()).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center2.clone()).await;

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        connect_peer_manager(pma_net2.clone(), pm_center2.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center3.clone()).await;

        let pma_net3 = create_mock_peer_manager_for_foreign_network("net3").await;
        let pmb_net3 = create_mock_peer_manager_for_foreign_network("net3").await;
        connect_peer_manager(pma_net3.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net3.clone(), pm_center3.clone()).await;

        let pma_net4 = create_mock_peer_manager_for_foreign_network("net4").await;
        let pmb_net4 = create_mock_peer_manager_for_foreign_network("net4").await;
        let pmc_net4 = create_mock_peer_manager_for_foreign_network("net4").await;
        connect_peer_manager(pma_net4.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net4.clone(), pm_center2.clone()).await;
        connect_peer_manager(pmc_net4.clone(), pm_center3.clone()).await;

        tokio::time::sleep(Duration::from_secs(5)).await;

        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
        wait_route_appear(pma_net3.clone(), pmb_net3.clone())
            .await
            .unwrap();
        wait_route_appear(pma_net4.clone(), pmb_net4.clone())
            .await
            .unwrap();
        wait_route_appear(pma_net4.clone(), pmc_net4.clone())
            .await
            .unwrap();
        wait_route_appear(pmb_net4.clone(), pmc_net4.clone())
            .await
            .unwrap();

        assert_eq!(3, pma_net1.list_routes().await.len());
        assert_eq!(3, pmb_net1.list_routes().await.len());

        assert_eq!(3, pma_net2.list_routes().await.len());
        assert_eq!(3, pmb_net2.list_routes().await.len());

        assert_eq!(3, pma_net3.list_routes().await.len());
        assert_eq!(3, pmb_net3.list_routes().await.len());

        assert_eq!(5, pma_net4.list_routes().await.len());
        assert_eq!(5, pmb_net4.list_routes().await.len());
        assert_eq!(5, pmc_net4.list_routes().await.len());

        drop(pm_center3);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(1, pma_net2.list_routes().await.len());
        assert_eq!(1, pma_net3.list_routes().await.len());
        assert_eq!(3, pma_net4.list_routes().await.len());
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_secret_mismatch() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center3 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;
        connect_peer_manager(pm_center2.clone(), pm_center3.clone()).await;

        let pma_net4 = create_mock_peer_manager_for_foreign_network_ext("net4", "1").await;
        let pmb_net4 = create_mock_peer_manager_for_foreign_network_ext("net4", "2").await;
        let pmc_net4 = create_mock_peer_manager_for_foreign_network_ext("net4", "3").await;
        connect_peer_manager(pma_net4.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net4.clone(), pm_center2.clone()).await;
        connect_peer_manager(pmc_net4.clone(), pm_center3.clone()).await;

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(1, pma_net4.list_routes().await.len());
        assert_eq!(1, pmb_net4.list_routes().await.len());
        assert_eq!(1, pmc_net4.list_routes().await.len());
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_max_direct_conns() {
        set_global_var!(MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;

        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        wait_for_condition(
            || async { pma_net1.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;

        println!("routes: {:?}", pma_net1.list_routes().await);

        let (a_ring, b_ring) = crate::tunnel::ring::create_ring_tunnel_pair();
        let a_mgr_copy = pma_net1.clone();
        tokio::spawn(async move {
            a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
        });
        let b_mgr_copy = pm_center1.clone();

        assert!(b_mgr_copy.add_tunnel_as_server(b_ring, true).await.is_err());
    }
}
