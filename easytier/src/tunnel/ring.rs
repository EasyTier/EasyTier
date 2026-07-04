use async_trait::async_trait;
pub use easytier_core::tunnel::ring::{
    RING_TUNNEL_CAP, RingSink, RingSinkSendError, RingStream, RingTunnel, RingTunnelSocket,
    RingTunnelSocketListener, connect_ring_socket, create_ring_socket_pair,
    create_ring_tunnel_pair, split_ring_socket,
};
use uuid::Uuid;

use crate::tunnel::{FromUrl, IpVersion};

use super::{
    Tunnel, TunnelConnector, TunnelError, TunnelInfo, TunnelListener, build_url_from_socket_addr,
};

#[derive(Debug)]
pub struct RingTunnelListener {
    listener_addr: url::Url,
    listener: Option<RingTunnelSocketListener>,
}

impl RingTunnelListener {
    pub fn new(key: url::Url) -> Self {
        Self {
            listener_addr: key,
            listener: None,
        }
    }
}

fn ring_tunnel_info(local_id: Uuid, remote_id: Uuid, tunnel_type: &str) -> TunnelInfo {
    TunnelInfo {
        tunnel_type: tunnel_type.to_owned(),
        local_addr: Some(build_url_from_socket_addr(&local_id.into(), "ring").into()),
        remote_addr: Some(build_url_from_socket_addr(&remote_id.into(), "ring").into()),
        resolved_remote_addr: Some(build_url_from_socket_addr(&remote_id.into(), "ring").into()),
    }
}

fn map_registry_error(error: easytier_core::tunnel::ring::RingTunnelRegistryError) -> TunnelError {
    TunnelError::InternalError(error.to_string())
}

impl RingTunnelListener {
    async fn get_addr(&self) -> Result<Uuid, TunnelError> {
        Uuid::from_url(self.listener_addr.clone(), IpVersion::Both).await
    }
}

#[async_trait]
impl TunnelListener for RingTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        tracing::info!("listen new conn of key: {}", self.listener_addr);
        let addr = self.get_addr().await?;
        self.listener = Some(RingTunnelSocketListener::bind(addr).map_err(map_registry_error)?);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        tracing::info!("waiting accept new conn of key: {}", self.listener_addr);
        let accepted = self
            .listener
            .as_mut()
            .ok_or_else(|| TunnelError::InternalError("ring listener not started".to_owned()))?
            .accept()
            .await
            .map_err(map_registry_error)?;

        Ok(Box::new(RingTunnel::new(
            accepted.socket,
            Some(ring_tunnel_info(
                accepted.local_id,
                accepted.remote_id,
                "ring",
            )),
        )))
    }

    fn local_url(&self) -> url::Url {
        self.listener_addr.clone()
    }
}

pub struct RingTunnelConnector {
    remote_addr: url::Url,
}

impl RingTunnelConnector {
    pub fn new(remote_addr: url::Url) -> Self {
        RingTunnelConnector { remote_addr }
    }
}

#[async_trait]
impl TunnelConnector for RingTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let remote_id = Uuid::from_url(self.remote_addr.clone(), IpVersion::Both).await?;
        tracing::info!("connecting");
        let dialed = connect_ring_socket(remote_id).map_err(map_registry_error)?;

        Ok(Box::new(RingTunnel::new(
            dialed.socket,
            Some(ring_tunnel_info(dialed.local_id, dialed.remote_id, "ring")),
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.remote_addr.clone()
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio::time::timeout;

    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong};

    use super::*;

    #[tokio::test]
    async fn ring_pingpong() {
        let id: url::Url = format!("ring://{}", Uuid::new_v4()).parse().unwrap();
        let listener = RingTunnelListener::new(id.clone());
        let connector = RingTunnelConnector::new(id.clone());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ring_bench() {
        let id: url::Url = format!("ring://{}", Uuid::new_v4()).parse().unwrap();
        let listener = RingTunnelListener::new(id.clone());
        let connector = RingTunnelConnector::new(id);
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn ring_close() {
        let (stunnel, ctunnel) = create_ring_tunnel_pair();
        drop(stunnel);

        let mut stream = ctunnel.split().0;
        let ret = stream.next().await;
        assert!(ret.as_ref().is_none(), "expect none, got {:?}", ret);
    }

    #[tokio::test]
    async fn abort_ring_stream() {
        let (_stunnel, ctunnel) = create_ring_tunnel_pair();
        let mut stream = ctunnel.split().0;
        let task = tokio::spawn(async move {
            let _ = stream.next().await;
        });
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        task.abort();
        let _ = tokio::join!(task);
    }

    #[tokio::test]
    async fn ring_stream_recv_timeout() {
        let (_stunnel, ctunnel) = create_ring_tunnel_pair();
        let mut stream = ctunnel.split().0;
        let _ = timeout(tokio::time::Duration::from_millis(10), stream.next()).await;
    }
}
