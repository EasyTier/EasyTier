use std::{net::SocketAddr, sync::Arc};

use crate::{
    connectivity::transport::ConnectedUdpSession,
    socket::udp::{UdpSessionControlHandler, UdpSessionLayer, VirtualUdpSocketFactory},
};

use super::DirectConnectorHost;

pub(super) async fn connect_with_socket<H>(
    host: Arc<H>,
    socket: Arc<<H as VirtualUdpSocketFactory>::Socket>,
    remote_addr: SocketAddr,
) -> anyhow::Result<ConnectedUdpSession>
where
    H: DirectConnectorHost + UdpSessionControlHandler<<H as VirtualUdpSocketFactory>::Socket>,
{
    let layer = Arc::new(
        UdpSessionLayer::new_with_control_handler_and_stun_responder(socket, host.clone(), host),
    );
    let session = layer.connect(remote_addr).await?;
    Ok(ConnectedUdpSession::new(session, layer))
}
