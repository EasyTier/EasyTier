use std::sync::{Arc, Weak};

use tokio::sync::{
    Mutex,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::{config::PeerId, packet::ZCPacket};

use super::{
    context::NetworkIdentity,
    peer_map::PeerMap,
    peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
};

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Box, Arc)]
pub trait GlobalForeignNetworkAccessor: Send + Sync + 'static {
    async fn list_global_foreign_peer(&self, network_identity: &NetworkIdentity) -> Vec<PeerId>;
}

pub fn peer_map_foreign_network_accessor(
    peer_map: Weak<PeerMap>,
) -> Box<dyn GlobalForeignNetworkAccessor> {
    struct PeerMapForeignNetworkAccessor {
        peer_map: Weak<PeerMap>,
    }

    #[async_trait::async_trait]
    impl GlobalForeignNetworkAccessor for PeerMapForeignNetworkAccessor {
        async fn list_global_foreign_peer(
            &self,
            network_identity: &NetworkIdentity,
        ) -> Vec<PeerId> {
            let Some(peer_map) = self.peer_map.upgrade() else {
                return vec![];
            };

            peer_map
                .list_peers_own_foreign_network(network_identity)
                .await
        }
    }

    Box::new(PeerMapForeignNetworkAccessor { peer_map })
}

pub struct RpcTransport {
    my_peer_id: PeerId,
    peer_map: Weak<PeerMap>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
}

impl RpcTransport {
    pub fn new(my_peer_id: PeerId, peer_map: Weak<PeerMap>) -> (Self, UnboundedSender<ZCPacket>) {
        let (rpc_transport_sender, packet_recv) = mpsc::unbounded_channel();
        (
            Self {
                my_peer_id,
                peer_map,
                packet_recv: Mutex::new(packet_recv),
            },
            rpc_transport_sender,
        )
    }
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> anyhow::Result<()> {
        tracing::debug!(
            "foreign network manager send rpc to peer: {:?}",
            dst_peer_id
        );
        let peer_map = self
            .peer_map
            .upgrade()
            .ok_or(anyhow::anyhow!("peer map is gone"))?;

        // send to ourselves so we can handle it in forward logic.
        peer_map.send_msg_directly(msg, self.my_peer_id).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<ZCPacket> {
        if let Some(packet) = self.packet_recv.lock().await.recv().await {
            tracing::trace!("recv rpc packet in foreign network manager rpc transport");
            Ok(packet)
        } else {
            Err(anyhow::anyhow!("unknown data store error"))
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

pub fn build_rpc_transport(
    my_peer_id: PeerId,
    peer_map: Weak<PeerMap>,
) -> (Arc<PeerRpcManager>, UnboundedSender<ZCPacket>) {
    let (transport, sender) = RpcTransport::new(my_peer_id, peer_map);
    (Arc::new(PeerRpcManager::new(transport)), sender)
}
