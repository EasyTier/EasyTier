//! Routes Gateway peers away from the ordinary Web configuration listener.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use easytier_core::{
    packet::{PacketType, ZCPacket},
    socket::{ListenerConnectionCounter, SocketListener},
    tunnel::{Tunnel, TunnelError, wrapper::TunnelWrapper},
};

use futures::{FutureExt as _, StreamExt, future::BoxFuture};
use tokio::{task::JoinSet, time::timeout};

use super::NetworkInstanceManager;

const GATEWAY_ACCEPT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PENDING_CONNECTIONS: usize = 32;

type PendingAccept<L> = BoxFuture<'static, (L, anyhow::Result<Box<dyn Tunnel>>)>;

pub struct GatewayListener<L> {
    inner: Option<L>,
    accepting: Option<PendingAccept<L>>,
    local_info: Option<(url::Url, Arc<dyn ListenerConnectionCounter>)>,
    instances: Arc<NetworkInstanceManager>,
    pending: JoinSet<Option<Box<dyn Tunnel>>>,
}

impl<L> std::fmt::Debug for GatewayListener<L> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayListener")
            .field("local_info", &self.local_info)
            .finish_non_exhaustive()
    }
}

impl<L> GatewayListener<L> {
    pub fn new(inner: L, instances: Arc<NetworkInstanceManager>) -> Self {
        Self {
            inner: Some(inner),
            accepting: None,
            local_info: None,
            instances,
            pending: JoinSet::new(),
        }
    }
}

#[async_trait]
impl<L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static> SocketListener
    for GatewayListener<L>
{
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.inner
            .as_mut()
            .expect("listen before accepting")
            .listen()
            .await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        loop {
            if self.accepting.is_none() && self.pending.len() < MAX_PENDING_CONNECTIONS {
                let mut inner = self.inner.take().expect("idle listener");
                self.local_info = Some((inner.local_url(), inner.connection_counter()));
                // WebSocket acceptance includes its HTTP upgrade. Preserve
                // this future across other completions and accept() returns.
                self.accepting = Some(
                    async move {
                        let accepted = inner.accept().await;
                        (inner, accepted)
                    }
                    .boxed(),
                );
            }
            tokio::select! {
                completed = self.pending.join_next(), if !self.pending.is_empty() => {
                    match completed {
                        Some(Ok(Some(tunnel))) => return Ok(tunnel),
                        Some(Err(error)) => tracing::warn!(%error, "Gateway connection task failed"),
                        _ => {}
                    }
                }
                (inner, accepted) = async { self.accepting.as_mut().unwrap().await }, if self.accepting.is_some() => {
                    self.accepting = None;
                    self.inner = Some(inner);
                    let tunnel = accepted?;
                    let instances = self.instances.clone();
                    self.pending.spawn(async move {
                        match accept_demux_server_tunnel(tunnel).await {
                            Ok(AcceptedTunnelRoute::Web(tunnel)) => return Some(tunnel),
                            Ok(AcceptedTunnelRoute::Peer(tunnel, mesh_name)) => {
                                match instances.accept_peer_tunnel(&mesh_name, tunnel).await {
                                    Some(Ok(())) => {}
                                    Some(Err(error)) => tracing::warn!(%error, %mesh_name, "failed to accept Gateway peer tunnel"),
                                    None => tracing::warn!(%mesh_name, "Gateway network unavailable, dropping connection"),
                                }
                            }
                            Err(error) => tracing::warn!(%error, "failed to demultiplex tunnel, dropping connection"),
                        }
                        None
                    });
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.inner.as_ref().map_or_else(
            || self.local_info.as_ref().unwrap().0.clone(),
            |inner| inner.local_url(),
        )
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        self.inner.as_ref().map_or_else(
            || self.local_info.as_ref().unwrap().1.clone(),
            |inner| inner.connection_counter(),
        )
    }
}

/// Routing decision for a connection accepted on the shared Web listener.
enum AcceptedTunnelRoute {
    Peer(Box<dyn Tunnel>, String),
    Web(Box<dyn Tunnel>),
}

fn peer_first_packet_network_name(packet: &ZCPacket) -> Result<String, TunnelError> {
    use prost::Message as _;

    let header = packet
        .peer_manager_header()
        .ok_or_else(|| TunnelError::InvalidPacket("peer handshake packet too short".to_string()))?;
    let network_name = if header.packet_type == PacketType::NoiseHandshakeMsg1 as u8 {
        const NOISE_XX_MSG1_EPHEMERAL_LEN: usize = 32;
        let payload = packet.payload();
        if payload.len() <= NOISE_XX_MSG1_EPHEMERAL_LEN {
            return Err(TunnelError::InvalidPacket(
                "noise msg1 has no handshake payload".to_string(),
            ));
        }
        easytier_proto::peer_rpc::PeerConnNoiseMsg1Pb::decode(
            &payload[NOISE_XX_MSG1_EPHEMERAL_LEN..],
        )
        .map_err(|error| {
            TunnelError::InvalidPacket(format!("invalid noise msg1 handshake payload: {error}"))
        })?
        .a_network_name
    } else if header.packet_type == PacketType::HandShake as u8 {
        easytier_proto::peer_rpc::HandshakeRequest::decode(packet.payload())
            .map_err(|error| {
                TunnelError::InvalidPacket(format!("invalid peer handshake payload: {error}"))
            })?
            .network_name
    } else {
        return Err(TunnelError::InvalidPacket(format!(
            "packet type {} is not a peer handshake",
            header.packet_type
        )));
    };
    if network_name.is_empty() {
        return Err(TunnelError::InvalidPacket(
            "peer handshake has an empty network name".to_string(),
        ));
    }
    Ok(network_name)
}

fn is_peer_handshake_first_packet(packet: &ZCPacket) -> bool {
    packet.peer_manager_header().is_some_and(|header| {
        header.packet_type == PacketType::HandShake as u8
            || header.packet_type == PacketType::NoiseHandshakeMsg1 as u8
    })
}

/// Classify a shared listener connection without upgrading its Web transport.
/// The first packet is replayed so the ordinary Web accept path performs the
/// Noise handshake exactly once. Idle connections are closed at the routing
/// timeout so they cannot block the serial Web handshake path.
async fn accept_demux_server_tunnel(
    tunnel: Box<dyn Tunnel>,
) -> Result<AcceptedTunnelRoute, TunnelError> {
    let info = tunnel.info();
    let (mut stream, sink) = tunnel.split();
    let first_packet = match timeout(GATEWAY_ACCEPT_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(packet))) => packet,
        Ok(Some(Err(error))) => return Err(error),
        Ok(None) => return Err(TunnelError::Shutdown),
        Err(_) => return Err(TunnelError::Shutdown),
    };
    if is_peer_handshake_first_packet(&first_packet) {
        let network_name = peer_first_packet_network_name(&first_packet)?;
        let stream = Box::pin(futures::stream::once(async move { Ok(first_packet) }).chain(stream));
        return Ok(AcceptedTunnelRoute::Peer(
            Box::new(TunnelWrapper::new(stream, sink, info)),
            network_name,
        ));
    }
    let stream = Box::pin(futures::stream::once(async move { Ok(first_packet) }).chain(stream));
    Ok(AcceptedTunnelRoute::Web(Box::new(TunnelWrapper::new(
        stream, sink, info,
    ))))
}

#[cfg(test)]
mod tests {
    use easytier_core::tunnel::{
        ring::create_ring_tunnel_pair,
        web_security::{
            accept_or_upgrade_server_tunnel, upgrade_client_tunnel, web_secure_tunnel_supported,
        },
    };
    use futures::SinkExt;
    use prost::Message as _;

    use super::*;

    fn pack_control_packet(payload: &[u8]) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.fill_peer_manager_hdr(0, 0, PacketType::Data as u8);
        packet
    }

    fn peer_handshake_packet(packet_type: PacketType, network_name: &str) -> ZCPacket {
        let payload = match packet_type {
            PacketType::HandShake => easytier_proto::peer_rpc::HandshakeRequest {
                network_name: network_name.to_string(),
                ..Default::default()
            }
            .encode_to_vec(),
            PacketType::NoiseHandshakeMsg1 => {
                let mut payload = vec![0; 32];
                easytier_proto::peer_rpc::PeerConnNoiseMsg1Pb {
                    a_network_name: network_name.to_string(),
                    ..Default::default()
                }
                .encode(&mut payload)
                .unwrap();
                payload
            }
            _ => panic!("not a peer handshake packet type"),
        };
        let mut packet = ZCPacket::new_with_payload(&payload);
        packet.fill_peer_manager_hdr(0, 0, packet_type as u8);
        packet
    }

    #[test]
    fn extracts_network_name_from_plain_and_noise_peer_handshakes() {
        for packet_type in [PacketType::HandShake, PacketType::NoiseHandshakeMsg1] {
            assert_eq!(
                peer_first_packet_network_name(&peer_handshake_packet(packet_type, "mesh-a"))
                    .unwrap(),
                "mesh-a"
            );
        }
    }

    #[tokio::test]
    async fn demux_replays_peer_handshake_to_selected_network() {
        for packet_type in [PacketType::HandShake, PacketType::NoiseHandshakeMsg1] {
            let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
            let server_task =
                tokio::spawn(async move { accept_demux_server_tunnel(server_tunnel).await });
            let (_stream, mut sink) = client_tunnel.split();
            sink.send(peer_handshake_packet(packet_type, "mesh-a"))
                .await
                .unwrap();

            let AcceptedTunnelRoute::Peer(peer_tunnel, network_name) =
                server_task.await.unwrap().unwrap()
            else {
                panic!("peer handshake must not be routed as Web traffic");
            };
            assert_eq!(network_name, "mesh-a");
            let (mut stream, _sink) = peer_tunnel.split();
            let replayed = stream.next().await.unwrap().unwrap();
            assert_eq!(
                replayed.peer_manager_header().unwrap().packet_type,
                packet_type as u8
            );
        }
    }

    #[test]
    fn rejects_malformed_peer_handshake_before_dispatch() {
        let mut packet = ZCPacket::new_with_payload(&[0; 32]);
        packet.fill_peer_manager_hdr(0, 0, PacketType::NoiseHandshakeMsg1 as u8);

        assert!(matches!(
            peer_first_packet_network_name(&packet),
            Err(TunnelError::InvalidPacket(message))
                if message == "noise msg1 has no handshake payload"
        ));
    }

    #[tokio::test]
    async fn demux_keeps_rpc_traffic_on_web_route() {
        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
        let server_task =
            tokio::spawn(async move { accept_demux_server_tunnel(server_tunnel).await });
        let (_stream, mut sink) = client_tunnel.split();
        let mut packet = ZCPacket::new_with_payload(b"rpc");
        packet.fill_peer_manager_hdr(0, 0, PacketType::RpcReq as u8);
        sink.send(packet).await.unwrap();

        let AcceptedTunnelRoute::Web(web_tunnel) = server_task.await.unwrap().unwrap() else {
            panic!("RPC packet must remain on the Web route");
        };
        let (web_tunnel, secure) = accept_or_upgrade_server_tunnel(web_tunnel).await.unwrap();
        assert!(!secure);
        let (mut stream, _sink) = web_tunnel.split();
        assert_eq!(
            stream
                .next()
                .await
                .unwrap()
                .unwrap()
                .peer_manager_header()
                .unwrap()
                .packet_type,
            PacketType::RpcReq as u8
        );
    }

    #[tokio::test]
    async fn demux_leaves_web_noise_upgrade_to_web_acceptance() {
        if !web_secure_tunnel_supported() {
            return;
        }

        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
        let server_task = tokio::spawn(async move {
            let AcceptedTunnelRoute::Web(tunnel) =
                accept_demux_server_tunnel(server_tunnel).await.unwrap()
            else {
                panic!("Web Noise handshake must remain on the Web route");
            };
            accept_or_upgrade_server_tunnel(tunnel).await.unwrap()
        });
        let client_tunnel = upgrade_client_tunnel(client_tunnel).await.unwrap();
        let (server_tunnel, secure) = server_task.await.unwrap();
        assert!(secure);

        let (mut server_stream, mut server_sink) = server_tunnel.split();
        let (mut client_stream, mut client_sink) = client_tunnel.split();
        client_sink
            .send(pack_control_packet(b"request"))
            .await
            .unwrap();
        let request = timeout(Duration::from_secs(1), server_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(request.payload(), b"request");
        server_sink
            .send(pack_control_packet(b"response"))
            .await
            .unwrap();
        let response = timeout(Duration::from_secs(1), client_stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.payload(), b"response");
    }

    #[tokio::test]
    async fn idle_demux_connection_is_closed_after_routing_timeout() {
        let (server_tunnel, _client_tunnel) = create_ring_tunnel_pair();
        let started = std::time::Instant::now();
        assert!(matches!(
            accept_demux_server_tunnel(server_tunnel).await,
            Err(TunnelError::Shutdown)
        ));
        assert!(started.elapsed() >= GATEWAY_ACCEPT_TIMEOUT);
    }

    #[derive(Debug)]
    struct TestListener(tokio::sync::mpsc::UnboundedReceiver<Box<dyn Tunnel>>);

    #[async_trait]
    impl SocketListener for TestListener {
        type Accepted = Box<dyn Tunnel>;
        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            self.0
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("listener closed"))
        }
        fn local_url(&self) -> url::Url {
            "ring://gateway".parse().unwrap()
        }
    }

    #[derive(Debug)]
    struct UpgradingListener {
        connections: tokio::sync::mpsc::UnboundedReceiver<Box<dyn Tunnel>>,
        upgrades: Arc<tokio::sync::Semaphore>,
        accepted: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl SocketListener for UpgradingListener {
        type Accepted = Box<dyn Tunnel>;
        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            let tunnel = self
                .connections
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("closed"))?;
            self.accepted
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.upgrades.acquire().await.unwrap().forget();
            Ok(tunnel)
        }
        fn local_url(&self) -> url::Url {
            "ring://upgrade".parse().unwrap()
        }
    }

    #[tokio::test]
    async fn pending_completion_and_web_return_preserve_inflight_transport_upgrade() {
        let instances = Arc::new(NetworkInstanceManager::new(super::super::GatewayConfig {
            peer_url: "tcp://localhost:22020".into(),
            relay_data: true,
        }));
        let (sender, connections) = tokio::sync::mpsc::unbounded_channel();
        let upgrades = Arc::new(tokio::sync::Semaphore::new(0));
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut listener = GatewayListener::new(
            UpgradingListener {
                connections,
                upgrades: upgrades.clone(),
                accepted: accepted.clone(),
            },
            instances,
        );
        let (server, client) = create_ring_tunnel_pair();
        sender.send(server).unwrap();
        // A previous Web connection finishes while the new one is upgrading.
        let (previous, _previous_client) = create_ring_tunnel_pair();
        listener.pending.spawn(async move {
            while accepted.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            Some(previous)
        });
        let _web = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        upgrades.add_permits(1);
        let (_, mut sink) = client.split();
        let mut packet = ZCPacket::new_with_payload(b"upgraded");
        packet.fill_peer_manager_hdr(0, 0, PacketType::RpcReq as u8);
        sink.send(packet).await.unwrap();
        let tunnel = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let (mut stream, _) = tunnel.split();
        assert_eq!(stream.next().await.unwrap().unwrap().payload(), b"upgraded");
    }

    #[tokio::test]
    async fn pending_connections_are_bounded_and_dropped_with_listener() {
        let instances = Arc::new(NetworkInstanceManager::new(super::super::GatewayConfig {
            peer_url: "tcp://localhost:22020".into(),
            relay_data: true,
        }));
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut listener = GatewayListener::new(TestListener(receiver), instances);
        let mut clients = Vec::new();
        for _ in 0..MAX_PENDING_CONNECTIONS + 1 {
            let (server, client) = create_ring_tunnel_pair();
            sender.send(server).unwrap();
            clients.push(client);
        }
        assert!(
            timeout(Duration::from_secs(1), listener.accept())
                .await
                .is_err()
        );
        assert_eq!(listener.pending.len(), MAX_PENDING_CONNECTIONS);
        assert_eq!(listener.inner.as_ref().unwrap().0.len(), 1);
        drop(listener);
        let (mut stream, _sink) = clients.remove(0).split();
        assert!(
            timeout(Duration::from_secs(1), stream.next())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn idle_connection_does_not_block_active_web_client() {
        let instances = Arc::new(NetworkInstanceManager::new(super::super::GatewayConfig {
            peer_url: "tcp://localhost:22020".into(),
            relay_data: true,
        }));
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut listener = GatewayListener::new(TestListener(receiver), instances);
        let (idle, _idle_client) = create_ring_tunnel_pair();
        sender.send(idle).unwrap();
        let (active, client) = create_ring_tunnel_pair();
        sender.send(active).unwrap();
        let (_, mut sink) = client.split();
        let mut packet = ZCPacket::new_with_payload(b"rpc");
        packet.fill_peer_manager_hdr(0, 0, PacketType::RpcReq as u8);
        sink.send(packet).await.unwrap();
        let tunnel = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let (mut stream, _) = tunnel.split();
        assert_eq!(stream.next().await.unwrap().unwrap().payload(), b"rpc");
        assert_eq!(listener.pending.len(), 1);
        listener.pending.abort_all();
        while listener.pending.join_next().await.is_some() {}
    }
}
