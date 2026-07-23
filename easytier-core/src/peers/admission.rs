use std::sync::{Arc, Weak};

use async_trait::async_trait;

use crate::{
    connectivity::protocol::raw,
    listener::{
        AcceptedSocketHandler,
        transport::{
            AcceptedTransport, AcceptedTunnelEvent, AcceptedTunnelEventSink, AcceptedTunnelHandler,
        },
    },
    tunnel::Tunnel,
};

use super::peer_manager::PeerManagerCore;

pub(crate) struct PeerAcceptedTunnelHandler {
    peer_manager: Weak<PeerManagerCore>,
    events: Arc<dyn AcceptedTunnelEventSink>,
}

impl PeerAcceptedTunnelHandler {
    pub(crate) fn new(
        peer_manager: &Arc<PeerManagerCore>,
        events: Arc<dyn AcceptedTunnelEventSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            peer_manager: Arc::downgrade(peer_manager),
            events,
        })
    }
}

#[async_trait]
impl AcceptedTunnelHandler for PeerAcceptedTunnelHandler {
    async fn handle_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        let tunnel_info = tunnel
            .info()
            .ok_or_else(|| anyhow::anyhow!("accepted tunnel has no tunnel info"))?;
        let local_url = tunnel_info
            .local_addr
            .clone()
            .unwrap_or_default()
            .to_string();
        let remote_url = tunnel_info
            .remote_addr
            .clone()
            .unwrap_or_default()
            .to_string();
        self.events.emit(AcceptedTunnelEvent::Accepted {
            local_url: local_url.clone(),
            remote_url: remote_url.clone(),
        });
        tracing::info!(ret = ?tunnel, "conn accepted");

        let Some(peer_manager) = self.peer_manager.upgrade() else {
            let error = "peer manager is gone, cannot handle tunnel".to_owned();
            self.events.emit(AcceptedTunnelEvent::AdmissionFailed {
                local_url,
                remote_url,
                error: error.clone(),
            });
            tracing::error!(error = %error, "handle conn error");
            return Err(anyhow::anyhow!(error));
        };
        if let Err(error) = peer_manager.add_tunnel_as_server(tunnel, true).await {
            self.events.emit(AcceptedTunnelEvent::AdmissionFailed {
                local_url,
                remote_url,
                error: error.to_string(),
            });
            tracing::error!(?error, "handle conn error");
            return Err(error.into());
        }
        Ok(())
    }
}

pub(crate) struct RawAcceptedTransportHandler {
    peer_manager: Weak<PeerManagerCore>,
}

impl RawAcceptedTransportHandler {
    pub(crate) fn new(peer_manager: &Arc<PeerManagerCore>) -> Self {
        Self {
            peer_manager: Arc::downgrade(peer_manager),
        }
    }
}

#[async_trait]
impl<TcpSocket> AcceptedSocketHandler<AcceptedTransport<TcpSocket>> for RawAcceptedTransportHandler
where
    TcpSocket: crate::socket::tcp::VirtualTcpSocket,
{
    async fn handle_accepted_socket(
        &self,
        accepted: AcceptedTransport<TcpSocket>,
    ) -> anyhow::Result<()> {
        let peer_manager = self
            .peer_manager
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("peer manager is gone"))?;
        let tunnel = match accepted {
            AcceptedTransport::Tunnel { tunnel, .. } => tunnel,
            AcceptedTransport::Tcp {
                socket, local_url, ..
            } => {
                if local_url.scheme() != "tcp" {
                    anyhow::bail!("unsupported raw TCP listener protocol: {local_url}");
                }
                raw::upgrade_accepted_tcp_with_local_url(socket, local_url)?
            }
            AcceptedTransport::Udp {
                session, local_url, ..
            } => {
                if local_url.scheme() != "udp" {
                    anyhow::bail!("unsupported raw UDP listener protocol: {local_url}");
                }
                raw::upgrade_accepted_udp_with_local_url(session, local_url)?
            }
            AcceptedTransport::ByteStream {
                socket,
                local_url,
                remote_url,
            } => raw::upgrade_accepted_byte_stream(socket, local_url, remote_url)?,
        };
        peer_manager.add_tunnel_as_server(tunnel, true).await?;
        Ok(())
    }
}
