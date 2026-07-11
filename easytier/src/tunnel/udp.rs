use std::{
    fmt::Debug,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex as StdMutex, Weak},
};

use async_trait::async_trait;
pub use easytier_core::hole_punch::udp::new_hole_punch_packet;
use easytier_core::socket::udp::{
    PreferredIpv6Source, UdpBindOptions, UdpSession, UdpSessionConnectError,
    UdpSessionControlHandler, UdpSessionLayer, UdpSessionProtocol, UdpSessionSocket,
    UdpSocketPurpose, UdpSocketRecvMeta, UdpSocketSendMeta, VirtualUdpSocket,
    VirtualUdpSocketFactory,
};
pub(crate) use easytier_core::socket::udp::{UdpSessionAcceptKind, accept_udp_session};
use easytier_core::tunnel::udp::UdpTunnelUpgrader;
use futures::stream::FuturesUnordered;

use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender, channel},
    task::JoinSet,
};
use tracing::Instrument;

use super::{
    FromUrl, IpVersion, Tunnel, TunnelConnCounter, TunnelError, TunnelInfo, TunnelListener,
    TunnelUrl, common::wait_for_connect_futures,
};
use crate::tunnel::common::{BindDev, bind};
use crate::{
    common::{join_joinset_background, netns::NetNS},
    tunnel::{build_url_from_socket_addr, udp_src},
};

pub const UDP_DATA_MTU: usize = 2000;

pub(crate) type RuntimeUdpSessionLayer = UdpSessionLayer<
    RuntimeUdpSocket,
    RuntimeUdpSessionControlHandler,
    RuntimeUdpSessionControlHandler,
>;

pub(crate) struct RuntimeUdpSocket {
    socket: Arc<UdpSocket>,
    udp_session_layer: StdMutex<Option<Weak<RuntimeUdpSessionLayer>>>,
}

impl RuntimeUdpSocket {
    pub(crate) fn new(socket: Arc<UdpSocket>) -> Self {
        if let Err(err) = udp_src::enable_recv_pktinfo(&socket) {
            tracing::debug!(?err, "enable udp pktinfo failed");
        }
        Self {
            socket,
            udp_session_layer: StdMutex::new(None),
        }
    }

    pub(crate) fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    pub(crate) fn udp_session_layer(self: &Arc<Self>) -> Arc<RuntimeUdpSessionLayer> {
        let mut weak_layer = self.udp_session_layer.lock().unwrap();
        if let Some(layer) = weak_layer.as_ref().and_then(Weak::upgrade) {
            return layer;
        }

        let control_handler = Arc::new(RuntimeUdpSessionControlHandler);
        let layer = Arc::new(
            UdpSessionLayer::new_with_control_handler_and_stun_responder(
                self.clone(),
                control_handler.clone(),
                control_handler,
            ),
        );
        *weak_layer = Some(Arc::downgrade(&layer));
        layer
    }
}

#[async_trait]
impl VirtualUdpSocket for RuntimeUdpSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(data, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    async fn send_to_with_meta(
        &self,
        data: &[u8],
        addr: SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> std::io::Result<usize> {
        if let Some(src_ip) = meta.src_ip {
            return udp_src::send_to_with_src_ip(&self.socket, src_ip, addr, data).await;
        }
        self.send_to(data, addr).await
    }

    async fn recv_from_with_meta(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, UdpSocketRecvMeta)> {
        let (len, addr, dst_ip) = udp_src::recv_from_with_dst_ip(&self.socket, buf).await?;
        Ok((len, addr, UdpSocketRecvMeta { dst_ip }))
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeUdpSessionControlHandler;

#[async_trait]
impl UdpSessionControlHandler<RuntimeUdpSocket> for RuntimeUdpSessionControlHandler {
    async fn send_v4_hole_punch(
        &self,
        socket: Arc<RuntimeUdpSocket>,
        dst_addr: SocketAddrV4,
    ) -> std::io::Result<usize> {
        let udp_packet = new_hole_punch_packet(1, 32).into_bytes();
        socket
            .socket()
            .try_send_to(&udp_packet, SocketAddr::V4(dst_addr))
    }

    async fn send_v6_hole_punch(
        &self,
        socket: Arc<RuntimeUdpSocket>,
        dst_addr: SocketAddrV6,
        preferred_src: Option<PreferredIpv6Source>,
    ) -> std::io::Result<usize> {
        let udp_packet = new_hole_punch_packet(1, 32).into_bytes();
        let udp_socket = socket.socket();
        if let Some(src) = preferred_src {
            match udp_src::send_to_with_src_ipv6(
                &udp_socket,
                src.ip,
                src.ifindex,
                dst_addr,
                &udp_packet,
            ) {
                Ok(ret) => return Ok(ret),
                Err(err) => {
                    tracing::debug!(
                        ?src,
                        ?dst_addr,
                        ?err,
                        "udp preferred v6 source failed, falling back"
                    );
                }
            }
        }
        udp_socket.try_send_to(&udp_packet, SocketAddr::V6(dst_addr))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeUdpSocketFactory {
    net_ns: NetNS,
    socket_mark: Option<u32>,
}

impl RuntimeUdpSocketFactory {
    pub(crate) fn new(net_ns: NetNS) -> Self {
        Self {
            net_ns,
            socket_mark: None,
        }
    }

    pub(crate) fn with_socket_mark(mut self, socket_mark: Option<u32>) -> Self {
        self.socket_mark = socket_mark;
        self
    }

    fn bind_device_for(&self, options: &UdpBindOptions) -> BindDev {
        if let Some(bind_device) = &options.bind_device {
            return BindDev::from(bind_device.as_str());
        }

        if matches!(
            options.purpose,
            UdpSocketPurpose::DirectConnect | UdpSocketPurpose::PortBoundListener
        ) {
            return BindDev::Auto;
        }

        BindDev::Disabled
    }

    fn reuse_addr_for(&self, options: &UdpBindOptions) -> bool {
        options.reuse_addr
            || (matches!(
                options.purpose,
                UdpSocketPurpose::PortBoundListener | UdpSocketPurpose::ProxyNat
            ) && !cfg!(target_os = "windows"))
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for RuntimeUdpSocketFactory {
    type Socket = RuntimeUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        let bind_addr = options
            .local_addr
            .unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
        let socket = bind::<UdpSocket>()
            .addr(bind_addr)
            .dev(self.bind_device_for(&options))
            .maybe_net_ns(Some(self.net_ns.clone()))
            .only_v6(options.only_v6)
            .reuse_addr(self.reuse_addr_for(&options))
            .reuse_port(options.reuse_port)
            .maybe_socket_mark(options.socket_mark.or(self.socket_mark))
            .call()?;
        Ok(Arc::new(RuntimeUdpSocket::new(Arc::new(socket))))
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for RuntimeUdpSessionControlHandler {
    type Socket = RuntimeUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        let bind_addr = options
            .local_addr
            .unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
        let bind_device = options
            .bind_device
            .map(BindDev::from)
            .unwrap_or(BindDev::Disabled);
        let socket = bind::<UdpSocket>()
            .addr(bind_addr)
            .dev(bind_device)
            .only_v6(options.only_v6)
            .reuse_addr(options.reuse_addr)
            .reuse_port(options.reuse_port)
            .maybe_socket_mark(options.socket_mark)
            .call()?;
        Ok(Arc::new(RuntimeUdpSocket::new(Arc::new(socket))))
    }
}

fn map_udp_session_connect_error(error: UdpSessionConnectError) -> TunnelError {
    match error {
        UdpSessionConnectError::Io(error) => TunnelError::IOError(error),
        UdpSessionConnectError::Timeout => TunnelError::InvalidPacket("udp connect timeout".into()),
        UdpSessionConnectError::InvalidPacket(error) => TunnelError::InvalidPacket(error),
    }
}

async fn accept_udp_session_tunnels(
    layer: Arc<RuntimeUdpSessionLayer>,
    accept_kind: UdpSessionAcceptKind,
    conn_send: Sender<Box<dyn Tunnel>>,
    local_url: url::Url,
) {
    loop {
        let session = match accept_udp_session(&layer, accept_kind).await {
            Ok(session) => session,
            Err(err) => {
                tracing::debug!(?err, "udp session accept loop stopped");
                break;
            }
        };
        let remote_addr = match session.peer_addr() {
            Ok(addr) => addr,
            Err(err) => {
                tracing::debug!(?err, "udp accepted session has invalid peer addr");
                continue;
            }
        };
        let tunnel_info = TunnelInfo {
            tunnel_type: "udp".to_owned(),
            local_addr: Some(local_url.clone().into()),
            remote_addr: Some(build_url_from_socket_addr(&remote_addr.to_string(), "udp").into()),
            resolved_remote_addr: Some(
                build_url_from_socket_addr(&remote_addr.to_string(), "udp").into(),
            ),
        };
        let conn =
            match UdpTunnelUpgrader::with_keep_alive(tunnel_info, layer.clone()).upgrade(session) {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::debug!(?err, "udp accepted session build tunnel failed");
                    continue;
                }
            };
        tracing::info!(info = ?conn.info().unwrap().remote_addr, "udp connection accept done");

        if let Err(err) = conn_send.send(conn).await {
            tracing::warn!(?err, "udp send conn to accept channel error");
            break;
        }
    }
}

pub(crate) struct RuntimeUdpSessionListener {
    addr: url::Url,
    socket: Option<Arc<UdpSocket>>,
    runtime_socket: Option<Arc<RuntimeUdpSocket>>,
    session_layer: Option<Arc<RuntimeUdpSessionLayer>>,
    session_layer_ref: Arc<StdMutex<Option<Weak<RuntimeUdpSessionLayer>>>>,
    socket_mark: Option<u32>,
    only_v6: bool,
}

impl RuntimeUdpSessionListener {
    pub(crate) fn new(addr: url::Url) -> Self {
        Self {
            addr,
            socket: None,
            runtime_socket: None,
            session_layer: None,
            session_layer_ref: Arc::new(StdMutex::new(None)),
            socket_mark: None,
            only_v6: true,
        }
    }

    pub(crate) fn new_with_socket(addr: url::Url, socket: Arc<UdpSocket>) -> Self {
        let mut listener = Self::new(addr);
        listener.runtime_socket = Some(Arc::new(RuntimeUdpSocket::new(socket.clone())));
        listener.socket = Some(socket);
        listener
    }

    pub(crate) fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    pub(crate) fn set_only_v6(&mut self, only_v6: bool) {
        self.only_v6 = only_v6;
    }

    pub(crate) fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }

    pub(crate) fn get_runtime_socket(&self) -> Option<Arc<RuntimeUdpSocket>> {
        self.runtime_socket.clone()
    }

    pub(crate) fn session_layer(&self) -> Option<Arc<RuntimeUdpSessionLayer>> {
        self.session_layer.clone()
    }

    pub(crate) async fn listen(&mut self) -> Result<(), TunnelError> {
        if self.session_layer.is_some() {
            return Ok(());
        }

        if self.socket.is_none() {
            let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
            let tunnel_url: TunnelUrl = self.addr.clone().into();
            self.socket = Some(Arc::new(
                bind()
                    .addr(addr)
                    .only_v6(self.only_v6)
                    .maybe_dev(tunnel_url.bind_dev())
                    .maybe_socket_mark(self.socket_mark)
                    .call()?,
            ));
        }

        self.addr
            .set_port(Some(self.socket.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

        let runtime_socket = match self.runtime_socket.clone() {
            Some(socket) => socket,
            None => {
                let socket = Arc::new(RuntimeUdpSocket::new(self.socket.as_ref().unwrap().clone()));
                self.runtime_socket = Some(socket.clone());
                socket
            }
        };
        let layer = runtime_socket.udp_session_layer();
        *self.session_layer_ref.lock().unwrap() = Some(Arc::downgrade(&layer));
        self.session_layer = Some(layer);

        Ok(())
    }

    pub(crate) async fn accept(
        &self,
        accept_kind: UdpSessionAcceptKind,
    ) -> Result<UdpSession, TunnelError> {
        let layer = self
            .session_layer
            .as_ref()
            .ok_or_else(|| TunnelError::InternalError("udp listener not started".to_owned()))?;
        accept_udp_session(layer, accept_kind)
            .await
            .map_err(TunnelError::IOError)
    }

    pub(crate) fn enable_classified_accept(
        &self,
        protocol: UdpSessionProtocol,
    ) -> Result<(), TunnelError> {
        let layer = self
            .session_layer
            .as_ref()
            .ok_or_else(|| TunnelError::InternalError("udp listener not started".to_owned()))?;
        layer
            .enable_classified_accept(protocol)
            .map_err(TunnelError::IOError)
    }

    pub(crate) fn local_url(&self) -> url::Url {
        self.addr.clone()
    }

    pub(crate) fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        struct UdpTunnelConnCounter {
            session_layer: Arc<StdMutex<Option<Weak<RuntimeUdpSessionLayer>>>>,
        }

        impl TunnelConnCounter for UdpTunnelConnCounter {
            fn get(&self) -> Option<u32> {
                let session_layer = self.session_layer.lock().unwrap();
                let Some(session_layer) = session_layer.as_ref() else {
                    return Some(0);
                };
                session_layer
                    .upgrade()
                    .map(|layer| layer.active_session_count() as u32)
            }
        }

        impl Debug for UdpTunnelConnCounter {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("UdpTunnelConnCounter")
                    .field("session_count", &self.get())
                    .finish()
            }
        }

        Arc::new(Box::new(UdpTunnelConnCounter {
            session_layer: self.session_layer_ref.clone(),
        }))
    }
}

pub struct UdpTunnelListener {
    session_listener: RuntimeUdpSessionListener,
    conn_send: Sender<Box<dyn Tunnel>>,
    conn_recv: Receiver<Box<dyn Tunnel>>,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl UdpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        let (conn_send, conn_recv) = channel(100);
        Self {
            session_listener: RuntimeUdpSessionListener::new(addr),
            conn_send,
            conn_recv,
            forward_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.session_listener.set_socket_mark(socket_mark);
    }

    pub fn new_with_socket(addr: url::Url, socket: Arc<UdpSocket>) -> Self {
        let (conn_send, conn_recv) = channel(100);
        Self {
            session_listener: RuntimeUdpSessionListener::new_with_socket(addr, socket),
            conn_send,
            conn_recv,
            forward_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
        }
    }

    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.session_listener.get_socket()
    }

    pub(crate) fn get_runtime_socket(&self) -> Option<Arc<RuntimeUdpSocket>> {
        self.session_listener.get_runtime_socket()
    }
}

#[async_trait]
impl TunnelListener for UdpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let already_listening = self.session_listener.session_layer().is_some();
        self.session_listener.listen().await?;
        if already_listening {
            return Ok(());
        }
        let layer = self.session_listener.session_layer().ok_or_else(|| {
            TunnelError::InternalError("udp listener did not create session layer".to_owned())
        })?;

        self.forward_tasks.lock().unwrap().spawn(
            accept_udp_session_tunnels(
                layer,
                UdpSessionAcceptKind::EasyTierMux,
                self.conn_send.clone(),
                self.session_listener.local_url(),
            )
            .instrument(tracing::info_span!("udp session accept loop")),
        );

        join_joinset_background(self.forward_tasks.clone(), "UdpTunnelListener".to_owned());

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::info!("start udp accept: {:?}", self.session_listener.local_url());
        if let Some(conn) = self.conn_recv.recv().await {
            return Ok(conn);
        }
        return Err(super::TunnelError::InternalError(
            "udp accept error".to_owned(),
        ));
    }

    fn local_url(&self) -> url::Url {
        self.session_listener.local_url()
    }

    fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        self.session_listener.get_conn_counter()
    }
}

#[derive(Debug)]
pub struct UdpTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
}

impl UdpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        Self {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
        }
    }

    async fn connect_udp_session_with_runtime_socket(
        &self,
        runtime_socket: Arc<RuntimeUdpSocket>,
        addr: SocketAddr,
    ) -> Result<(Arc<RuntimeUdpSessionLayer>, UdpSession), super::TunnelError> {
        tracing::warn!("udp connect: {:?}", self.addr);

        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(runtime_socket.socket().as_ref())?;

        let layer = runtime_socket.udp_session_layer();
        let session = layer
            .connect(addr)
            .await
            .map_err(map_udp_session_connect_error)?;
        if session.peer_addr()? != addr {
            tracing::debug!(
                recv_addr = ?session.peer_addr()?,
                ?addr,
                "udp connect addr not match"
            );
        }

        Ok((layer, session))
    }

    fn udp_tunnel_upgrader_for_session(
        &self,
        layer: Arc<RuntimeUdpSessionLayer>,
        session: &UdpSession,
    ) -> Result<UdpTunnelUpgrader, super::TunnelError> {
        let local_addr = session.local_addr()?;
        let dst_addr = session.peer_addr()?;
        Ok(UdpTunnelUpgrader::with_keep_alive(
            TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(build_url_from_socket_addr(&local_addr.to_string(), "udp").into()),
                remote_addr: Some(self.addr.clone().into()),
                resolved_remote_addr: Some(
                    build_url_from_socket_addr(&dst_addr.to_string(), "udp").into(),
                ),
            },
            layer,
        ))
    }

    pub async fn try_connect_with_socket(
        &self,
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        self.try_connect_with_runtime_socket(Arc::new(RuntimeUdpSocket::new(socket)), addr)
            .await
    }

    pub(crate) async fn try_connect_with_runtime_socket(
        &self,
        runtime_socket: Arc<RuntimeUdpSocket>,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        let (layer, session) = self
            .connect_udp_session_with_runtime_socket(runtime_socket, addr)
            .await?;
        let upgrader = self.udp_tunnel_upgrader_for_session(layer, &session)?;
        upgrader.upgrade(session)
    }

    async fn connect_with_default_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        // Route through bind() so socket_mark is applied consistently for
        // both the None (no-op) and Some(_) paths.
        let bind_addr: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = bind::<UdpSocket>()
            .addr(bind_addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;

        return self.try_connect_with_socket(Arc::new(socket), addr).await;
    }

    async fn connect_with_custom_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind()
                .addr(*bind_addr)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()
            {
                Ok(socket) => futures.push(self.try_connect_with_socket(Arc::new(socket), addr)),
                Err(error) => {
                    tracing::error!(?error, ?bind_addr, ?addr, "bind addr fail");
                    continue;
                }
            }
        }
        wait_for_connect_futures(futures).await
    }
}

#[async_trait]
impl super::TunnelConnector for UdpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        if self.bind_addrs.is_empty() || addr.is_ipv6() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr).await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use bytes::BytesMut;
    use easytier_core::packet::ZCPacket;
    use easytier_core::socket::udp::{
        extract_v6_hole_punch_packet, new_v6_hole_punch_packet, send_v4_hole_punch_control_packet,
        send_v6_hole_punch_control_packet,
    };
    use futures::{SinkExt, StreamExt};
    use rand::Rng;
    use tokio::time::timeout;

    use super::*;
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        common::netns::NetNS,
        connector::udp_hole_punch::common::RuntimeUdpHolePunchRuntime,
        tunnel::{
            TunnelConnector,
            common::{
                get_interface_name_by_ip,
                tests::{_tunnel_bench, _tunnel_echo_server, _tunnel_pingpong, wait_for_condition},
            },
        },
    };

    #[test]
    fn runtime_udp_socket_factory_interprets_bind_defaults_by_purpose() {
        let listener_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let factory = RuntimeUdpSocketFactory::new(NetNS::new(None));

        assert!(matches!(
            factory.bind_device_for(&UdpBindOptions::port_bound_listener(listener_addr)),
            BindDev::Auto
        ));
        assert!(matches!(
            factory.bind_device_for(&UdpBindOptions::direct_connect()),
            BindDev::Auto
        ));
        assert!(matches!(
            factory.bind_device_for(&UdpBindOptions::hole_punch_control()),
            BindDev::Disabled
        ));
        assert_eq!(
            factory.reuse_addr_for(&UdpBindOptions::port_bound_listener(listener_addr)),
            !cfg!(target_os = "windows")
        );
        assert!(!factory.reuse_addr_for(&UdpBindOptions::hole_punch_control()));
        assert_eq!(
            factory.reuse_addr_for(&UdpBindOptions::proxy_nat()),
            !cfg!(target_os = "windows")
        );
    }

    #[test]
    fn runtime_udp_socket_factory_applies_listener_bind_device_option() {
        let listener_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let factory = RuntimeUdpSocketFactory::new(NetNS::new(None));
        let options = UdpBindOptions::port_bound_listener(listener_addr)
            .with_bind_device(Some("eth0".to_owned()));

        match factory.bind_device_for(&options) {
            BindDev::Custom(dev) => assert_eq!(dev, "eth0"),
            bind_device => panic!("unexpected bind device: {bind_device:?}"),
        }
        assert!(matches!(
            factory.bind_device_for(&UdpBindOptions::hole_punch_control()),
            BindDev::Disabled
        ));
    }

    #[tokio::test]
    async fn udp_pingpong() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn udp_listener_reuses_runtime_socket_session_layer() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = socket.local_addr().unwrap().port();
        let mut listener = UdpTunnelListener::new_with_socket(
            format!("udp://127.0.0.1:{port}").parse().unwrap(),
            socket,
        );

        listener.listen().await.unwrap();
        let runtime_socket = listener.get_runtime_socket().unwrap();
        let listener_layer = listener.session_listener.session_layer.as_ref().unwrap();
        let socket_layer = runtime_socket.udp_session_layer();

        assert!(Arc::ptr_eq(listener_layer, &socket_layer));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn runtime_udp_socket_reports_ipv4_destination_ip() {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let runtime_socket = RuntimeUdpSocket::new(socket.clone());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(
                b"pktinfo",
                SocketAddr::from(([127, 0, 0, 1], socket.local_addr().unwrap().port())),
            )
            .await
            .unwrap();

        let mut buf = [0; 32];
        let (len, _peer, meta) = runtime_socket.recv_from_with_meta(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], b"pktinfo");
        assert_eq!(meta.dst_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn udp_bench() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5555".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5555".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn udp_bench_with_bind() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5554".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5554".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn udp_bench_with_bind_fail() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5553".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5553".parse().unwrap());
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    async fn send_random_data_to_socket(remote_url: url::Url) {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket
            .connect(format!(
                "{}:{}",
                remote_url.host().unwrap(),
                remote_url.port().unwrap()
            ))
            .await
            .unwrap();

        // get a random 100-len buf
        loop {
            let mut buf = vec![0u8; 100];
            rand::thread_rng().fill(&mut buf[..]);
            socket.send(&buf).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn udp_multiple_conns() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5557".parse().unwrap());
        listener.listen().await.unwrap();

        let _lis = tokio::spawn(async move {
            loop {
                let ret = listener.accept().await.unwrap();
                assert_eq!(
                    ret.info()
                        .unwrap()
                        .local_addr
                        .unwrap_or_default()
                        .to_string(),
                    listener.local_url().to_string()
                );
                tokio::spawn(async move { _tunnel_echo_server(ret, false).await });
            }
        });

        let mut connector1 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());
        let mut connector2 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());

        let t1 = connector1.connect().await.unwrap();
        let t2 = connector2.connect().await.unwrap();

        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t1.info().unwrap().local_addr.unwrap().into()),
        ));
        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t1.info().unwrap().remote_addr.unwrap().into()),
        ));
        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t2.info().unwrap().remote_addr.unwrap().into()),
        ));

        let sender1 = tokio::spawn(async move {
            let (mut stream, mut sink) = t1.split();

            for i in 0..10 {
                sink.send(ZCPacket::new_with_payload("hello1".as_bytes()))
                    .await
                    .unwrap();
                let recv = stream.next().await.unwrap().unwrap();
                println!("t1 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv.payload(), "hello1".as_bytes());
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let sender2 = tokio::spawn(async move {
            let (mut stream, mut sink) = t2.split();

            for i in 0..10 {
                sink.send(ZCPacket::new_with_payload("hello2".as_bytes()))
                    .await
                    .unwrap();
                let recv = stream.next().await.unwrap().unwrap();
                println!("t2 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv.payload(), "hello2".as_bytes());
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let _ = tokio::join!(sender1, sender2);
    }

    #[tokio::test]
    async fn bind_multi_ip_to_same_dev() {
        let global_ctx = get_mock_global_ctx();
        let ips = global_ctx
            .get_ip_collector()
            .collect_ip_addrs()
            .await
            .interface_ipv4s;
        if ips.is_empty() {
            return;
        }
        let bind_dev = get_interface_name_by_ip(&IpAddr::V4(ips[0].into()));

        for ip in ips {
            println!("bind to ip: {}, {:?}", ip, bind_dev);
            let addr = SocketAddr::from_url(
                format!("udp://{}:11111", ip).parse().unwrap(),
                IpVersion::Both,
            )
            .await
            .unwrap();
            let _ = bind::<UdpSocket>()
                .addr(addr)
                .maybe_dev(bind_dev.clone())
                .only_v6(true)
                .call()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn bind_same_port() {
        println!("{}", "[::]:8888".parse::<SocketAddr>().unwrap());
        let mut listener = UdpTunnelListener::new("udp://[::]:31014".parse().unwrap());
        let mut listener2 = UdpTunnelListener::new("udp://0.0.0.0:31014".parse().unwrap());
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener = UdpTunnelListener::new("udp://[::1]:31015".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://[::1]:31015".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let listener = UdpTunnelListener::new("udp://[::1]:31016".parse().unwrap());
        let mut connector =
            UdpTunnelConnector::new("udp://test.easytier.top:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener = UdpTunnelListener::new("udp://127.0.0.1:31016".parse().unwrap());
        let mut connector =
            UdpTunnelConnector::new("udp://test.easytier.top:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = UdpTunnelListener::new("udp://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }

    #[tokio::test]
    async fn test_conn_counter() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            let _c1 = connector.connect().await.unwrap();
            let _c2 = connector.connect().await.unwrap();
        });

        let conn_counter = listener.get_conn_counter();

        listener.listen().await.unwrap();
        let c1 = listener.accept().await.unwrap();
        assert_eq!(conn_counter.get(), Some(1));
        let c2 = listener.accept().await.unwrap();
        assert_eq!(conn_counter.get(), Some(2));

        drop(c2);
        wait_for_condition(
            || async { conn_counter.get() == Some(1) },
            Duration::from_secs(1),
        )
        .await;

        drop(c1);
        wait_for_condition(
            || async { conn_counter.get().unwrap_or(0) == 0 },
            Duration::from_secs(1),
        )
        .await;
    }

    #[test]
    fn v6_hole_punch_packet_preserves_preferred_source_ifindex() {
        let dst_addr = "[2001:db8::1]:10001".parse::<SocketAddrV6>().unwrap();
        let preferred_src = PreferredIpv6Source {
            ip: "2001:db8::2".parse().unwrap(),
            ifindex: 42,
        };

        let packet = new_v6_hole_punch_packet(&dst_addr, Some(preferred_src));
        let (parsed_dst_addr, parsed_preferred_src) =
            extract_v6_hole_punch_packet(packet.udp_payload()).unwrap();

        assert_eq!(parsed_dst_addr, dst_addr);
        assert_eq!(parsed_preferred_src, Some(preferred_src));
    }

    #[tokio::test]
    async fn test_v6_hole_punch_packet() {
        let mut lis = UdpTunnelListener::new("udp://[::]:0".parse().unwrap());
        lis.listen().await.unwrap();

        // a socket to receive forwarded hole punch packets
        let socket = Arc::new(UdpSocket::bind("[::]:0").await.unwrap());
        let socket_clone = socket.clone();
        let t = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            socket_clone.recv_from(&mut buf).await.unwrap();
        });

        tracing::info!("lis local addr: {:?}", lis.local_url());
        tracing::info!("socket local addr: {:?}", socket.local_addr().unwrap());

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // a socket to send v6 hole punch packets
        let runtime = RuntimeUdpHolePunchRuntime::new(get_mock_global_ctx());
        send_v6_hole_punch_control_packet(
            &runtime,
            lis.local_url().port().unwrap(),
            match socket.local_addr().unwrap() {
                std::net::SocketAddr::V6(addr_v6) => addr_v6,
                _ => panic!("Expected an IPv6 address"),
            },
            None,
        )
        .await
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), t)
            .await
            .expect("Timeout waiting for v6 hole punch packet")
            .unwrap();
    }

    #[tokio::test]
    async fn test_v4_hole_punch_packet() {
        let mut lis = UdpTunnelListener::new("udp://0.0.0.0:0".parse().unwrap());
        lis.listen().await.unwrap();

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_clone = socket.clone();
        let t = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            socket_clone.recv_from(&mut buf).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let runtime = RuntimeUdpHolePunchRuntime::new(get_mock_global_ctx());
        send_v4_hole_punch_control_packet(
            &runtime,
            lis.local_url().port().unwrap(),
            match socket.local_addr().unwrap() {
                std::net::SocketAddr::V4(addr_v4) => addr_v4,
                _ => panic!("Expected an IPv4 address"),
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), t)
            .await
            .expect("Timeout waiting for v4 hole punch packet")
            .unwrap();
    }
}
