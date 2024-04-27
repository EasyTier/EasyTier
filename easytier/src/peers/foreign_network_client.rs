use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use dashmap::DashMap;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, NetworkIdentity},
        PeerId,
    },
    tunnel::packet_def::ZCPacket,
};

use super::{
    foreign_network_manager::{ForeignNetworkServiceClient, FOREIGN_NETWORK_SERVICE_ID},
    peer_map::PeerMap,
    peer_rpc::PeerRpcManager,
    zc_peer_conn::PeerConn,
    PacketRecvChan,
};

pub struct ForeignNetworkClient {
    global_ctx: ArcGlobalCtx,
    peer_rpc: Arc<PeerRpcManager>,
    my_peer_id: PeerId,

    peer_map: Arc<PeerMap>,

    next_hop: Arc<DashMap<PeerId, PeerId>>,
    tasks: Mutex<JoinSet<()>>,
}

impl ForeignNetworkClient {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        packet_sender_to_mgr: PacketRecvChan,
        peer_rpc: Arc<PeerRpcManager>,
        my_peer_id: PeerId,
    ) -> Self {
        let peer_map = Arc::new(PeerMap::new(
            packet_sender_to_mgr,
            global_ctx.clone(),
            my_peer_id,
        ));
        let next_hop = Arc::new(DashMap::new());

        Self {
            global_ctx,
            peer_rpc,
            my_peer_id,

            peer_map,

            next_hop,
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub async fn add_new_peer_conn(&self, peer_conn: PeerConn) {
        tracing::warn!(peer_conn = ?peer_conn.get_conn_info(), network = ?peer_conn.get_network_identity(), "add new peer conn in foreign network client");
        self.peer_map.add_new_peer_conn(peer_conn).await
    }

    async fn collect_next_hop_in_foreign_network_task(
        network_identity: NetworkIdentity,
        peer_map: Arc<PeerMap>,
        peer_rpc: Arc<PeerRpcManager>,
        next_hop: Arc<DashMap<PeerId, PeerId>>,
    ) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            peer_map.clean_peer_without_conn().await;

            let new_next_hop = Self::collect_next_hop_in_foreign_network(
                network_identity.clone(),
                peer_map.clone(),
                peer_rpc.clone(),
            )
            .await;

            next_hop.clear();
            for (k, v) in new_next_hop.into_iter() {
                next_hop.insert(k, v);
            }
        }
    }

    async fn collect_next_hop_in_foreign_network(
        network_identity: NetworkIdentity,
        peer_map: Arc<PeerMap>,
        peer_rpc: Arc<PeerRpcManager>,
    ) -> DashMap<PeerId, PeerId> {
        let peers = peer_map.list_peers().await;
        let mut tasks = JoinSet::new();
        if !peers.is_empty() {
            tracing::warn!(?peers, my_peer_id = ?peer_rpc.my_peer_id(), "collect next hop in foreign network");
        }
        for peer in peers {
            let peer_rpc = peer_rpc.clone();
            let network_identity = network_identity.clone();
            tasks.spawn(async move {
                let Ok(Some(peers_in_foreign)) = peer_rpc
                    .do_client_rpc_scoped(FOREIGN_NETWORK_SERVICE_ID, peer, |c| async {
                        let c =
                            ForeignNetworkServiceClient::new(tarpc::client::Config::default(), c)
                                .spawn();
                        let mut rpc_ctx = tarpc::context::current();
                        rpc_ctx.deadline = SystemTime::now() + Duration::from_secs(2);
                        let ret = c.list_network_peers(rpc_ctx, network_identity).await;
                        ret
                    })
                    .await
                else {
                    return (peer, vec![]);
                };

                (peer, peers_in_foreign)
            });
        }

        let new_next_hop = DashMap::new();
        while let Some(join_ret) = tasks.join_next().await {
            let Ok((gateway, peer_ids)) = join_ret else {
                tracing::error!(?join_ret, "collect next hop in foreign network failed");
                continue;
            };
            for ret in peer_ids {
                new_next_hop.insert(ret, gateway);
            }
        }

        new_next_hop
    }

    pub fn has_next_hop(&self, peer_id: PeerId) -> bool {
        self.get_next_hop(peer_id).is_some()
    }

    pub fn is_peer_public_node(&self, peer_id: &PeerId) -> bool {
        self.peer_map.has_peer(*peer_id)
    }

    pub fn get_next_hop(&self, peer_id: PeerId) -> Option<PeerId> {
        if self.peer_map.has_peer(peer_id) {
            return Some(peer_id.clone());
        }
        self.next_hop.get(&peer_id).map(|v| v.clone())
    }

    pub async fn send_msg(&self, msg: ZCPacket, peer_id: PeerId) -> Result<(), Error> {
        if let Some(next_hop) = self.get_next_hop(peer_id) {
            let ret = self.peer_map.send_msg_directly(msg, next_hop).await;
            if ret.is_err() {
                tracing::error!(
                    ?ret,
                    ?peer_id,
                    ?next_hop,
                    "foreign network client send msg failed"
                );
            }
            return ret;
        }
        Err(Error::RouteError(Some("no next hop".to_string())))
    }

    pub fn list_foreign_peers(&self) -> Vec<PeerId> {
        let mut peers = vec![];
        for item in self.next_hop.iter() {
            if item.key() != &self.my_peer_id {
                peers.push(item.key().clone());
            }
        }
        peers
    }

    pub async fn run(&self) {
        self.tasks
            .lock()
            .await
            .spawn(Self::collect_next_hop_in_foreign_network_task(
                self.global_ctx.get_network_identity(),
                self.peer_map.clone(),
                self.peer_rpc.clone(),
                self.next_hop.clone(),
            ));
    }

    pub fn get_next_hop_table(&self) -> DashMap<PeerId, PeerId> {
        let next_hop = DashMap::new();
        for item in self.next_hop.iter() {
            next_hop.insert(item.key().clone(), item.value().clone());
        }
        next_hop
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.peer_map.clone()
    }
}
