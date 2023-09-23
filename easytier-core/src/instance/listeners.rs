use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    common::{error::Error, netns::NetNS},
    peers::peer_manager::PeerManager,
    tunnels::{
        ring_tunnel::RingTunnelListener, tcp_tunnel::TcpTunnelListener,
        udp_tunnel::UdpTunnelListener, Tunnel, TunnelListener,
    },
};

#[async_trait]
pub trait TunnelHandlerForListener {
    async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error>;
}

#[async_trait]
impl TunnelHandlerForListener for PeerManager {
    #[tracing::instrument]
    async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
        self.add_tunnel_as_server(tunnel).await
    }
}

pub struct ListenerManager<H> {
    my_node_id: uuid::Uuid,
    net_ns: NetNS,
    listeners: Vec<Arc<Mutex<dyn TunnelListener>>>,
    peer_manager: Arc<H>,

    tasks: JoinSet<()>,
}

impl<H: TunnelHandlerForListener + Send + Sync + 'static + Debug> ListenerManager<H> {
    pub fn new(my_node_id: uuid::Uuid, net_ns: NetNS, peer_manager: Arc<H>) -> Self {
        Self {
            my_node_id,
            net_ns,
            listeners: Vec::new(),
            peer_manager,
            tasks: JoinSet::new(),
        }
    }

    pub async fn prepare_listeners(&mut self) -> Result<(), Error> {
        self.add_listener(UdpTunnelListener::new(
            "udp://0.0.0.0:11010".parse().unwrap(),
        ))
        .await?;
        self.add_listener(TcpTunnelListener::new(
            "tcp://0.0.0.0:11010".parse().unwrap(),
        ))
        .await?;
        self.add_listener(RingTunnelListener::new(
            format!("ring://{}", self.my_node_id).parse().unwrap(),
        ))
        .await?;
        Ok(())
    }

    pub async fn add_listener<Listener>(&mut self, listener: Listener) -> Result<(), Error>
    where
        Listener: TunnelListener + 'static,
    {
        let listener = Arc::new(Mutex::new(listener));
        self.listeners.push(listener);
        Ok(())
    }

    #[tracing::instrument]
    async fn run_listener(listener: Arc<Mutex<dyn TunnelListener>>, peer_manager: Arc<H>) {
        let mut l = listener.lock().await;
        while let Ok(ret) = l.accept().await {
            tracing::info!(ret = ?ret, "conn accepted");
            let server_ret = peer_manager.handle_tunnel(ret).await;
            if let Err(e) = &server_ret {
                tracing::error!(error = ?e, "handle conn error");
            }
        }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        for listener in &self.listeners {
            let _guard = self.net_ns.guard();
            log::warn!("run listener: {:?}", listener);
            listener.lock().await.listen().await?;
            self.tasks.spawn(Self::run_listener(
                listener.clone(),
                self.peer_manager.clone(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::time::timeout;

    use crate::tunnels::{ring_tunnel::RingTunnelConnector, TunnelConnector};

    use super::*;

    #[derive(Debug)]
    struct MockListenerHandler {}

    #[async_trait]
    impl TunnelHandlerForListener for MockListenerHandler {
        async fn handle_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
            let data = "abc";
            _tunnel.pin_sink().send(data.into()).await.unwrap();
            Err(Error::Unknown)
        }
    }

    #[tokio::test]
    async fn handle_error_in_accept() {
        let net_ns = NetNS::new(None);
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr =
            ListenerManager::new(uuid::Uuid::new_v4(), net_ns.clone(), handler.clone());

        let ring_id = format!("ring://{}", uuid::Uuid::new_v4());

        listener_mgr
            .add_listener(RingTunnelListener::new(ring_id.parse().unwrap()))
            .await
            .unwrap();
        listener_mgr.run().await.unwrap();

        let connect_once = |ring_id| async move {
            let tunnel = RingTunnelConnector::new(ring_id).connect().await.unwrap();
            assert_eq!(tunnel.pin_stream().next().await.unwrap().unwrap(), "abc");
            tunnel
        };

        timeout(std::time::Duration::from_secs(1), async move {
            connect_once(ring_id.parse().unwrap()).await;
            // handle tunnel fail should not impact the second connect
            connect_once(ring_id.parse().unwrap()).await;
        })
        .await
        .unwrap();
    }
}
