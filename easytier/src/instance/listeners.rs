use std::{fmt::Debug, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    peers::peer_manager::PeerManager,
    tunnel::{
        quic::QUICTunnelListener,
        ring::RingTunnelListener,
        tcp::TcpTunnelListener,
        udp::UdpTunnelListener,
        wireguard::{WgConfig, WgTunnelListener},
        Tunnel, TunnelListener,
    },
};

pub fn get_listener_by_url(
    l: &url::Url,
    ctx: ArcGlobalCtx,
) -> Result<Box<dyn TunnelListener>, Error> {
    Ok(match l.scheme() {
        "tcp" => Box::new(TcpTunnelListener::new(l.clone())),
        "udp" => Box::new(UdpTunnelListener::new(l.clone())),
        "wg" => {
            let nid = ctx.get_network_identity();
            let wg_config =
                WgConfig::new_from_network_identity(&nid.network_name, &nid.network_secret);
            Box::new(WgTunnelListener::new(l.clone(), wg_config))
        }
        "quic" => Box::new(QUICTunnelListener::new(l.clone())),
        _ => {
            unreachable!("unsupported listener uri");
        }
    })
}

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
    global_ctx: ArcGlobalCtx,
    net_ns: NetNS,
    listeners: Vec<Arc<Mutex<dyn TunnelListener>>>,
    peer_manager: Arc<H>,

    tasks: JoinSet<()>,
}

impl<H: TunnelHandlerForListener + Send + Sync + 'static + Debug> ListenerManager<H> {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<H>) -> Self {
        Self {
            global_ctx: global_ctx.clone(),
            net_ns: global_ctx.net_ns.clone(),
            listeners: Vec::new(),
            peer_manager,
            tasks: JoinSet::new(),
        }
    }

    pub async fn prepare_listeners(&mut self) -> Result<(), Error> {
        self.add_listener(RingTunnelListener::new(
            format!("ring://{}", self.global_ctx.get_id())
                .parse()
                .unwrap(),
        ))
        .await?;

        for l in self.global_ctx.config.get_listener_uris().iter() {
            let lis = get_listener_by_url(l, self.global_ctx.clone())?;
            self.add_listener(lis).await?;
        }

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
    async fn run_listener(
        listener: Arc<Mutex<dyn TunnelListener>>,
        peer_manager: Arc<H>,
        global_ctx: ArcGlobalCtx,
    ) {
        let mut l = listener.lock().await;
        global_ctx.add_running_listener(l.local_url());
        global_ctx.issue_event(GlobalCtxEvent::ListenerAdded(l.local_url()));
        while let Ok(ret) = l.accept().await {
            let tunnel_info = ret.info().unwrap();
            global_ctx.issue_event(GlobalCtxEvent::ConnectionAccepted(
                tunnel_info.local_addr.clone(),
                tunnel_info.remote_addr.clone(),
            ));
            tracing::info!(ret = ?ret, "conn accepted");
            let peer_manager = peer_manager.clone();
            let global_ctx = global_ctx.clone();
            tokio::spawn(async move {
                let server_ret = peer_manager.handle_tunnel(ret).await;
                if let Err(e) = &server_ret {
                    global_ctx.issue_event(GlobalCtxEvent::ConnectionError(
                        tunnel_info.local_addr,
                        tunnel_info.remote_addr,
                        e.to_string(),
                    ));
                    tracing::error!(error = ?e, "handle conn error");
                }
            });
        }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        for listener in &self.listeners {
            let _guard = self.net_ns.guard();
            let addr = listener.lock().await.local_url();
            log::warn!("run listener: {:?}", listener);
            listener
                .lock()
                .await
                .listen()
                .await
                .with_context(|| format!("failed to add listener {}", addr))?;
            self.tasks.spawn(Self::run_listener(
                listener.clone(),
                self.peer_manager.clone(),
                self.global_ctx.clone(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::time::timeout;

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{packet_def::ZCPacket, ring::RingTunnelConnector, TunnelConnector},
    };

    use super::*;

    #[derive(Debug)]
    struct MockListenerHandler {}

    #[async_trait]
    impl TunnelHandlerForListener for MockListenerHandler {
        async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
            let data = "abc";
            let (_recv, mut send) = tunnel.split();

            let zc_packet = ZCPacket::new_with_payload(data.as_bytes());
            send.send(zc_packet).await.unwrap();
            Err(Error::Unknown)
        }
    }

    #[tokio::test]
    async fn handle_error_in_accept() {
        let handler = Arc::new(MockListenerHandler {});
        let mut listener_mgr = ListenerManager::new(get_mock_global_ctx(), handler.clone());

        let ring_id = format!("ring://{}", uuid::Uuid::new_v4());

        listener_mgr
            .add_listener(RingTunnelListener::new(ring_id.parse().unwrap()))
            .await
            .unwrap();
        listener_mgr.run().await.unwrap();

        let connect_once = |ring_id| async move {
            let tunnel = RingTunnelConnector::new(ring_id).connect().await.unwrap();
            let (mut recv, _send) = tunnel.split();
            assert_eq!(
                recv.next().await.unwrap().unwrap().payload(),
                "abc".as_bytes()
            );
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
