use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex as StdMutex, Weak},
};

use async_trait::async_trait;
use easytier_core::socket::{
    NetNamespace, SocketContext,
    udp::{
        UdpBindOptions, UdpSessionAcceptKind, UdpSessionLayer, UdpSessionListenRequest,
        UdpSessionSocketListener, UdpSocketPurpose, UdpSocketRecvMeta, UdpSocketSendMeta,
        VirtualUdpSocket, VirtualUdpSocketFactory,
    },
};
use tokio::net::UdpSocket;

use crate::{
    common::netns::NetNS,
    host_runtime::{NativeHostRuntime, native_host_runtime},
    tunnel::common::{BindDev, bind},
};

use super::udp_src;

pub(crate) type RuntimeUdpSessionLayer = UdpSessionLayer<RuntimeUdpSocket, NativeHostRuntime>;

pub(crate) type RuntimeUdpSessionSocketListener = UdpSessionSocketListener<NativeHostRuntime>;

pub(crate) fn new_runtime_udp_session_listener(
    url: url::Url,
    mut request: UdpSessionListenRequest,
    accept_kind: UdpSessionAcceptKind,
    net_ns: NetNS,
) -> RuntimeUdpSessionSocketListener {
    request.bind.context.netns = net_ns.name().map(NetNamespace::new);
    let runtime = native_host_runtime();
    UdpSessionSocketListener::new_with_request(url, request, accept_kind, runtime)
}

pub struct RuntimeUdpSocket {
    socket: Arc<UdpSocket>,
    context: SocketContext,
    udp_session_layer: StdMutex<Option<Weak<RuntimeUdpSessionLayer>>>,
}

impl RuntimeUdpSocket {
    pub(crate) fn new(socket: Arc<UdpSocket>) -> Self {
        Self::new_with_context(socket, SocketContext::default())
    }

    pub(crate) fn new_with_context(socket: Arc<UdpSocket>, context: SocketContext) -> Self {
        if let Err(err) = udp_src::enable_recv_pktinfo(&socket) {
            tracing::debug!(?err, "enable udp pktinfo failed");
        }
        Self {
            socket,
            context,
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

        let runtime = native_host_runtime();
        let layer = Arc::new(UdpSessionLayer::new_with_stun_responder(
            self.clone(),
            runtime,
        ));
        *weak_layer = Some(Arc::downgrade(&layer));
        layer
    }
}

#[async_trait]
impl VirtualUdpSocket for RuntimeUdpSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn socket_context(&self) -> SocketContext {
        self.context.clone()
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
        if let (Some(IpAddr::V6(src)), Some(ifindex), SocketAddr::V6(dst)) =
            (meta.src_ip, meta.src_ifindex, addr)
        {
            return udp_src::send_to_with_src_ipv6(&self.socket, src, ifindex, dst, data);
        }
        if let Some(src_ip) = meta.src_ip {
            return udp_src::send_to_with_src_ip(&self.socket, src_ip, addr, data).await;
        }
        self.socket.try_send_to(data, addr)
    }

    async fn recv_from_with_meta(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, UdpSocketRecvMeta)> {
        let (len, addr, dst_ip) = udp_src::recv_from_with_dst_ip(&self.socket, buf).await?;
        Ok((len, addr, UdpSocketRecvMeta { dst_ip }))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RuntimeUdpSocketFactory;

#[derive(Clone, Copy)]
enum UdpBindPolicy {
    PurposeDefaults,
    ExplicitOptions,
}

impl RuntimeUdpSocketFactory {
    pub(crate) fn new() -> Self {
        Self
    }

    fn bind_device_for(&self, options: &UdpBindOptions) -> BindDev {
        if let Some(bind_device) = &options.bind_device {
            return BindDev::from(bind_device.as_str());
        }

        if matches!(
            options.purpose,
            UdpSocketPurpose::DirectConnect
                | UdpSocketPurpose::PortBoundListener
                | UdpSocketPurpose::PortForward
        ) {
            return BindDev::Auto;
        }

        BindDev::Disabled
    }

    fn reuse_addr_for(&self, options: &UdpBindOptions) -> bool {
        options.reuse_addr
            || (matches!(
                options.purpose,
                UdpSocketPurpose::PortBoundListener
                    | UdpSocketPurpose::ProxyNat
                    | UdpSocketPurpose::PortForward
            ) && !cfg!(target_os = "windows"))
    }

    fn bind_udp_with_policy(
        &self,
        options: UdpBindOptions,
        policy: UdpBindPolicy,
    ) -> anyhow::Result<Arc<RuntimeUdpSocket>> {
        let context = options.context.clone();
        let bind_addr = options
            .local_addr
            .unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
        let bind_device = if matches!(policy, UdpBindPolicy::PurposeDefaults) {
            self.bind_device_for(&options)
        } else {
            options
                .bind_device
                .as_deref()
                .map(BindDev::from)
                .unwrap_or(BindDev::Disabled)
        };
        let reuse_addr = if matches!(policy, UdpBindPolicy::PurposeDefaults) {
            self.reuse_addr_for(&options)
        } else {
            options.reuse_addr
        };
        let socket = bind::<UdpSocket>()
            .addr(bind_addr)
            .dev(bind_device)
            .maybe_net_ns(Some(NetNS::from_socket_context(&context)))
            .only_v6(options.only_v6)
            .reuse_addr(reuse_addr)
            .reuse_port(options.reuse_port)
            .maybe_socket_mark(context.socket_mark)
            .call()?;
        Ok(Arc::new(RuntimeUdpSocket::new_with_context(
            Arc::new(socket),
            context,
        )))
    }

    pub(crate) fn bind_udp_with_explicit_options(
        &self,
        options: UdpBindOptions,
    ) -> anyhow::Result<Arc<RuntimeUdpSocket>> {
        self.bind_udp_with_policy(options, UdpBindPolicy::ExplicitOptions)
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for RuntimeUdpSocketFactory {
    type Socket = RuntimeUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        self.bind_udp_with_policy(options, UdpBindPolicy::PurposeDefaults)
    }
}

#[cfg(test)]
mod tests {
    use easytier_core::{
        listener::SocketListener,
        socket::udp::{
            UdpSessionListenRequest, send_v4_hole_punch_control_packet,
            send_v6_hole_punch_control_packet,
        },
    };

    use crate::host_runtime::native_host_runtime;

    use super::*;

    #[tokio::test]
    async fn runtime_udp_socket_reuses_session_layer() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let runtime_socket = Arc::new(RuntimeUdpSocket::new(socket));

        let first = runtime_socket.udp_session_layer();
        let second = runtime_socket.udp_session_layer();

        assert!(Arc::ptr_eq(&first, &second));
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
        assert_eq!(meta.dst_ip, Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn runtime_v4_hole_punch_control_packet_is_forwarded() {
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut listener = new_runtime_udp_session_listener(
            "udp://0.0.0.0:0".parse().unwrap(),
            UdpSessionListenRequest::new(UdpBindOptions::port_bound_listener(local_addr)),
            UdpSessionAcceptKind::EasyTierMux,
            NetNS::new(None),
        );
        listener.listen().await.unwrap();

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let runtime = native_host_runtime();
        send_v4_hole_punch_control_packet(
            runtime.as_ref(),
            SocketContext::default(),
            listener.local_url().port().unwrap(),
            match receiver.local_addr().unwrap() {
                SocketAddr::V4(addr) => addr,
                SocketAddr::V6(_) => unreachable!(),
            },
        )
        .await
        .unwrap();

        let mut buf = [0; 128];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("timeout waiting for v4 hole-punch packet")
        .unwrap();
    }

    #[tokio::test]
    async fn runtime_v6_hole_punch_control_packet_is_forwarded() {
        let local_addr = "[::]:0".parse().unwrap();
        let mut listener = new_runtime_udp_session_listener(
            "udp://[::]:0".parse().unwrap(),
            UdpSessionListenRequest::new(UdpBindOptions::port_bound_listener(local_addr)),
            UdpSessionAcceptKind::EasyTierMux,
            NetNS::new(None),
        );
        listener.listen().await.unwrap();

        let receiver = UdpSocket::bind("[::]:0").await.unwrap();
        let runtime = native_host_runtime();
        send_v6_hole_punch_control_packet(
            runtime.as_ref(),
            SocketContext::default(),
            listener.local_url().port().unwrap(),
            match receiver.local_addr().unwrap() {
                SocketAddr::V6(addr) => addr,
                SocketAddr::V4(_) => unreachable!(),
            },
            None,
        )
        .await
        .unwrap();

        let mut buf = [0; 128];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("timeout waiting for v6 hole-punch packet")
        .unwrap();
    }

    #[test]
    fn factory_interprets_bind_defaults_by_purpose() {
        let listener_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let factory = RuntimeUdpSocketFactory::new();

        assert!(matches!(
            factory.bind_device_for(&UdpBindOptions::port_bound_listener(listener_addr)),
            BindDev::Auto
        ));
        assert!(matches!(
            factory.bind_device_for(&UdpBindOptions::direct_connect()),
            BindDev::Auto
        ));
        assert!(matches!(
            factory.bind_device_for(&UdpBindOptions::port_forward(listener_addr)),
            BindDev::Auto
        ));
        assert!(matches!(
            factory.bind_device_for(&UdpBindOptions::port_lease(listener_addr)),
            BindDev::Disabled
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
        assert_eq!(
            factory.reuse_addr_for(&UdpBindOptions::port_forward(listener_addr)),
            !cfg!(target_os = "windows")
        );
        assert!(!factory.reuse_addr_for(&UdpBindOptions::port_lease(listener_addr)));
    }

    #[test]
    fn factory_applies_listener_bind_device_option() {
        let listener_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let factory = RuntimeUdpSocketFactory::new();
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
}
