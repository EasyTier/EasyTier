use std::{net::SocketAddr, sync::Arc};

use crate::{
    connectivity::transport::ConnectedUdpSession,
    socket::udp::{UdpSessionLayer, VirtualUdpSocketFactory},
};

use super::DirectConnectorHost;

pub(super) async fn connect_with_socket<H>(
    host: Arc<H>,
    socket: Arc<<H as VirtualUdpSocketFactory>::Socket>,
    remote_addr: SocketAddr,
) -> anyhow::Result<ConnectedUdpSession>
where
    H: DirectConnectorHost,
{
    let layer = Arc::new(UdpSessionLayer::new_with_stun_responder(socket, host));
    let session = layer.connect(remote_addr).await?;
    Ok(ConnectedUdpSession::new(session, layer))
}
