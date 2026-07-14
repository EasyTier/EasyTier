//! Core-owned UDP hole-punch socket/session runtime.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Weak},
};

use anyhow::Context as _;
use async_trait::async_trait;

use crate::{
    connectivity::direct::DirectConnectorHost,
    hole_punch::udp::{
        UdpHolePunchRuntime, UdpPortMappingLease, UdpPunchAcceptor, UdpPunchConnCounter,
        UdpPunchListener, UdpPunchSocket, UdpResolvedPublicAddr,
    },
    peers::peer_manager::PeerManagerCore,
    socket::{
        IpVersion, SocketContext,
        udp::{
            UdpBindOptions, UdpSessionControlHandler, UdpSessionLayer, UdpSessionSocket,
            UdpSessionStunResponder, VirtualUdpSocket, VirtualUdpSocketFactory,
        },
    },
    stun::StunSocketMapper,
};

#[async_trait]
pub trait UdpHolePunchPlatform: Send + Sync + 'static {
    async fn start_udp_port_mapping(
        &self,
        _local_listener: &url::Url,
    ) -> anyhow::Result<Option<Box<dyn UdpPortMappingLease>>> {
        Ok(None)
    }
}

#[async_trait]
impl UdpHolePunchPlatform for () {}

type HostUdpSocket<H> = <H as VirtualUdpSocketFactory>::Socket;
type CoreUdpSessionLayer<H> = UdpSessionLayer<HostUdpSocket<H>, H, H>;

struct CoreUdpPunchAcceptor<H>
where
    H: VirtualUdpSocketFactory,
    HostUdpSocket<H>: VirtualUdpSocket,
{
    layer: Arc<CoreUdpSessionLayer<H>>,
}

#[async_trait]
impl<H> UdpPunchAcceptor for CoreUdpPunchAcceptor<H>
where
    H: VirtualUdpSocketFactory
        + UdpSessionControlHandler<HostUdpSocket<H>>
        + UdpSessionStunResponder<HostUdpSocket<H>>
        + Send
        + Sync
        + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    async fn accept(&mut self) -> anyhow::Result<UdpPunchSocket> {
        let session = self.layer.accept().await?;
        let remote_addr = session.peer_addr()?;
        Ok(UdpPunchSocket::new(
            session,
            remote_addr,
            self.layer.clone(),
        ))
    }
}

struct CoreUdpPunchConnCounter<H>
where
    H: VirtualUdpSocketFactory,
    HostUdpSocket<H>: VirtualUdpSocket,
{
    layer: Weak<CoreUdpSessionLayer<H>>,
}

impl<H> UdpPunchConnCounter for CoreUdpPunchConnCounter<H>
where
    H: VirtualUdpSocketFactory
        + UdpSessionControlHandler<HostUdpSocket<H>>
        + UdpSessionStunResponder<HostUdpSocket<H>>
        + Send
        + Sync
        + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    fn get(&self) -> Option<u32> {
        Some(
            self.layer
                .upgrade()
                .map(|layer| layer.active_session_count() as u32)
                .unwrap_or(0),
        )
    }
}

pub struct CoreUdpHolePunchRuntime<H>
where
    H: DirectConnectorHost,
{
    host: Arc<H>,
    peer_manager: Arc<PeerManagerCore>,
    stun: Arc<dyn StunSocketMapper<HostUdpSocket<H>>>,
    platform: Arc<dyn UdpHolePunchPlatform>,
    socket_context: SocketContext,
}

impl<H> CoreUdpHolePunchRuntime<H>
where
    H: DirectConnectorHost + Send + Sync + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    pub fn new(
        host: Arc<H>,
        peer_manager: Arc<PeerManagerCore>,
        stun: Arc<dyn StunSocketMapper<HostUdpSocket<H>>>,
        platform: Arc<dyn UdpHolePunchPlatform>,
        socket_context: SocketContext,
    ) -> Self {
        Self {
            host,
            peer_manager,
            stun,
            platform,
            socket_context,
        }
    }

    fn session_layer(&self, socket: Arc<HostUdpSocket<H>>) -> Arc<CoreUdpSessionLayer<H>> {
        Arc::new(
            UdpSessionLayer::new_with_control_handler_and_stun_responder(
                socket,
                self.host.clone(),
                self.host.clone(),
            ),
        )
    }

    async fn create_listener_with_mapping(
        &self,
        resolve_public_addr: bool,
        port: Option<u16>,
    ) -> anyhow::Result<UdpPunchListener<HostUdpSocket<H>>> {
        let bind = match port {
            Some(port) => UdpBindOptions::hole_punch_candidate().with_local_addr(Some(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
            )),
            None => UdpBindOptions::hole_punch_control(),
        }
        .with_context(self.socket_context.clone().with_ip_version(IpVersion::V4));
        let socket = self.host.bind_udp(bind).await?;
        let local_port = socket.local_addr()?.port();
        let resolved = if resolve_public_addr {
            self.resolve_public_addr(socket.clone()).await?
        } else {
            UdpResolvedPublicAddr {
                mapped_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port)),
                port_mapping_lease: None,
            }
        };

        let layer = self.session_layer(socket.clone());
        let conn_counter = Arc::new(CoreUdpPunchConnCounter {
            layer: Arc::downgrade(&layer),
        });
        let acceptor = Box::new(CoreUdpPunchAcceptor { layer });

        Ok(UdpPunchListener {
            socket,
            mapped_addr: resolved.mapped_addr,
            conn_counter,
            acceptor,
            port_mapping_lease: resolved.port_mapping_lease,
        })
    }

    async fn resolve_public_addr(
        &self,
        socket: Arc<HostUdpSocket<H>>,
    ) -> anyhow::Result<UdpResolvedPublicAddr> {
        let local_port = socket.local_addr()?.port();
        let local_listener: url::Url = format!("udp://0.0.0.0:{local_port}").parse()?;
        let port_mapping_lease = if self.peer_manager.p2p_policy_flags().disable_upnp {
            None
        } else {
            match self.platform.start_udp_port_mapping(&local_listener).await {
                Ok(lease) => lease,
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        %local_listener,
                        "failed to establish udp port mapping, fallback to stun-only public addr resolution"
                    );
                    None
                }
            }
        };

        let mapped_addr = self
            .stun
            .get_udp_port_mapping_with_socket(socket)
            .await
            .map_err(anyhow::Error::from)
            .with_context(|| format!("resolve udp public addr for {local_listener}"))?;
        if let Some(lease) = &port_mapping_lease {
            lease.public_addr_resolved(mapped_addr);
        } else {
            tracing::debug!(
                %local_listener,
                stun_mapped_addr = %mapped_addr,
                "udp public addr resolved without port mapping"
            );
        }

        Ok(UdpResolvedPublicAddr {
            mapped_addr,
            port_mapping_lease,
        })
    }

    async fn validate_socket_route(
        &self,
        context: SocketContext,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let local_addr = self
            .host
            .local_addr_for_remote(remote_addr, context)
            .await?;
        match local_addr.ip() {
            IpAddr::V4(ip) if self.peer_manager.is_local_virtual_ip(&IpAddr::V4(ip)) => {
                anyhow::bail!("local address is virtual ipv4")
            }
            IpAddr::V6(ip) if self.peer_manager.is_easytier_managed_ipv6(&ip).await => {
                anyhow::bail!("local address is easytier-managed ipv6")
            }
            _ => Ok(()),
        }
    }
}

#[async_trait]
impl<H> UdpHolePunchRuntime for CoreUdpHolePunchRuntime<H>
where
    H: DirectConnectorHost + Send + Sync + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    type Socket = HostUdpSocket<H>;

    fn socket_context(&self) -> SocketContext {
        self.socket_context.clone()
    }

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        self.host.bind_udp(options).await
    }

    async fn bind_direct_connect_udp(&self) -> anyhow::Result<Arc<Self::Socket>> {
        self.host
            .bind_udp(
                UdpBindOptions::hole_punch_candidate()
                    .with_context(self.socket_context.clone().with_ip_version(IpVersion::V4)),
            )
            .await
    }

    async fn resolve_udp_public_addr(
        &self,
        socket: Arc<Self::Socket>,
    ) -> anyhow::Result<UdpResolvedPublicAddr> {
        self.resolve_public_addr(socket).await
    }

    async fn create_listener(
        &self,
        _prefer_port_mapping: bool,
    ) -> anyhow::Result<UdpPunchListener<Self::Socket>> {
        self.create_listener_with_mapping(true, None).await
    }

    async fn create_port_bound_listener(
        &self,
        port: u16,
    ) -> anyhow::Result<UdpPunchListener<Self::Socket>> {
        self.create_listener_with_mapping(false, Some(port)).await
    }

    async fn connect_with_socket(
        &self,
        socket: Arc<Self::Socket>,
        remote: SocketAddr,
    ) -> anyhow::Result<UdpPunchSocket> {
        self.validate_socket_route(socket.socket_context(), remote)
            .await?;
        let layer = self.session_layer(socket);
        let session = layer.connect(remote).await?;
        if session.peer_addr()? != remote {
            tracing::debug!(
                recv_addr = ?session.peer_addr()?,
                ?remote,
                "udp connect addr not match"
            );
        }
        Ok(UdpPunchSocket::new(session, remote, layer))
    }
}
