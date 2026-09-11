use std::sync::{Arc, Weak};

use async_trait::async_trait;

use crate::{
    connectivity::protocol::raw,
    events::{CoreEvent, CoreEventSink},
    listener::{
        AcceptedSocketHandler,
        transport::{AcceptedTransport, AcceptedTunnelHandler},
    },
    tunnel::Tunnel,
};

use super::peer_manager::PeerManagerCore;

pub(crate) struct PeerAcceptedTunnelHandler {
    peer_manager: Weak<PeerManagerCore>,
    events: Arc<dyn CoreEventSink>,
}

impl PeerAcceptedTunnelHandler {
    pub(crate) fn new(
        peer_manager: &Arc<PeerManagerCore>,
        events: Arc<dyn CoreEventSink>,
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
        self.events.emit(CoreEvent::TunnelAccepted {
            local_url: local_url.clone(),
            remote_url: remote_url.clone(),
        });
        tracing::info!(ret = ?tunnel, "conn accepted");

        let Some(peer_manager) = self.peer_manager.upgrade() else {
            let error = "peer manager is gone, cannot handle tunnel".to_owned();
            self.events.emit(CoreEvent::TunnelAdmissionFailed {
                local_url,
                remote_url,
                error: error.clone(),
            });
            tracing::error!(error = %error, "handle conn error");
            return Err(anyhow::anyhow!(error));
        };
        if let Err(error) = peer_manager.add_tunnel_as_server(tunnel, true).await {
            self.events.emit(CoreEvent::TunnelAdmissionFailed {
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
    tunnel_handler: Arc<dyn AcceptedTunnelHandler>,
}

impl RawAcceptedTransportHandler {
    pub(crate) fn new(tunnel_handler: Arc<dyn AcceptedTunnelHandler>) -> Self {
        Self { tunnel_handler }
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
        self.tunnel_handler.handle_tunnel(tunnel).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{host::testkit::TestTcpSocket, tunnel::ring::RingTunnelRegistry};

    struct RecordingTunnelHandler(AtomicUsize);

    #[async_trait]
    impl AcceptedTunnelHandler for RecordingTunnelHandler {
        async fn handle_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn raw_transport_delegates_tunnel_to_shared_admission_handler() {
        let registry = Arc::new(RingTunnelRegistry::default());
        let local_id = uuid::Uuid::new_v4();
        let mut listener = registry.bind(local_id).unwrap();
        let _client = registry.connect(local_id).unwrap();
        let tunnel = listener.accept().await.unwrap().into_tunnel();
        let recorder = Arc::new(RecordingTunnelHandler(AtomicUsize::new(0)));
        let handler = RawAcceptedTransportHandler::new(recorder.clone());

        handler
            .handle_accepted_socket(AcceptedTransport::<TestTcpSocket>::Tunnel {
                tunnel,
                local_url: format!("ring://{local_id}").parse().unwrap(),
            })
            .await
            .unwrap();

        assert_eq!(recorder.0.load(Ordering::Relaxed), 1);
    }
}
