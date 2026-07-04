use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;

#[async_trait]
pub trait VirtualUdpSocket: Send + Sync + 'static {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSocketPurpose {
    HolePunchControl,
    HolePunchCandidate,
    DirectConnect,
    PortBoundListener,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpBindOptions {
    pub local_addr: Option<SocketAddr>,
    pub purpose: UdpSocketPurpose,
}

impl UdpBindOptions {
    pub fn hole_punch_control() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::HolePunchControl,
        }
    }

    pub fn hole_punch_candidate() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::HolePunchCandidate,
        }
    }

    pub fn direct_connect() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::DirectConnect,
        }
    }

    pub fn port_bound_listener(local_addr: SocketAddr) -> Self {
        Self {
            local_addr: Some(local_addr),
            purpose: UdpSocketPurpose::PortBoundListener,
        }
    }
}

impl Default for UdpBindOptions {
    fn default() -> Self {
        Self::hole_punch_control()
    }
}

#[async_trait]
pub trait VirtualUdpSocketFactory: Send + Sync + 'static {
    type Socket: VirtualUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionKind {
    Direct,
    EasyTierMux,
}

#[async_trait]
pub trait UdpSessionSocket: Send + Sync + 'static {
    fn kind(&self) -> UdpSessionKind;

    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    fn peer_addr(&self) -> std::io::Result<SocketAddr>;

    async fn send(&self, data: &[u8]) -> std::io::Result<usize>;

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionConnectRequest {
    pub remote_addr: SocketAddr,
    pub bind: UdpBindOptions,
}

impl UdpSessionConnectRequest {
    pub fn direct(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            bind: UdpBindOptions::direct_connect(),
        }
    }

    pub fn with_bind(mut self, bind: UdpBindOptions) -> Self {
        self.bind = bind;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionListenRequest {
    pub bind: UdpBindOptions,
}

impl UdpSessionListenRequest {
    pub fn new(bind: UdpBindOptions) -> Self {
        Self { bind }
    }
}

#[async_trait]
pub trait UdpSessionConnector: Send {
    type Session: UdpSessionSocket;

    async fn connect(&mut self, request: UdpSessionConnectRequest)
    -> anyhow::Result<Self::Session>;
}

#[async_trait]
pub trait UdpSessionListener: Send {
    type Session: UdpSessionSocket;

    async fn listen(&mut self, request: UdpSessionListenRequest) -> anyhow::Result<()>;

    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn accept(&mut self) -> anyhow::Result<Self::Session>;
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn bind_options_constructors_describe_socket_purpose() {
        let listener_addr = SocketAddr::from(([0, 0, 0, 0], 12345));

        assert_eq!(
            UdpBindOptions::hole_punch_control(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::HolePunchControl,
            }
        );
        assert_eq!(
            UdpBindOptions::hole_punch_candidate(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::HolePunchCandidate,
            }
        );
        assert_eq!(
            UdpBindOptions::direct_connect(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::DirectConnect,
            }
        );
        assert_eq!(
            UdpBindOptions::port_bound_listener(listener_addr),
            UdpBindOptions {
                local_addr: Some(listener_addr),
                purpose: UdpSocketPurpose::PortBoundListener,
            }
        );
        assert_eq!(
            UdpBindOptions::default(),
            UdpBindOptions::hole_punch_control()
        );
    }

    #[test]
    fn session_connect_request_keeps_peer_scoped_udp_shape() {
        let remote_addr = SocketAddr::from(([192, 0, 2, 1], 11010));
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 22020));

        let request = UdpSessionConnectRequest::direct(remote_addr)
            .with_bind(UdpBindOptions::port_bound_listener(bind_addr));

        assert_eq!(request.remote_addr, remote_addr);
        assert_eq!(
            request.bind,
            UdpBindOptions {
                local_addr: Some(bind_addr),
                purpose: UdpSocketPurpose::PortBoundListener,
            }
        );
    }

    #[test]
    fn session_listen_request_keeps_bind_options() {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let bind = UdpBindOptions::port_bound_listener(bind_addr);

        assert_eq!(UdpSessionListenRequest::new(bind).bind, bind);
    }

    struct MockUdpSessionSocket {
        kind: UdpSessionKind,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        incoming: Mutex<Vec<u8>>,
        sent: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl UdpSessionSocket for MockUdpSessionSocket {
        fn kind(&self) -> UdpSessionKind {
            self.kind
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }

        async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
            self.sent.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let incoming = self.incoming.lock().unwrap();
            let len = incoming.len().min(buf.len());
            buf[..len].copy_from_slice(&incoming[..len]);
            Ok(len)
        }
    }

    #[tokio::test]
    async fn udp_session_socket_is_peer_scoped() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 10000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 10001));
        let socket = MockUdpSessionSocket {
            kind: UdpSessionKind::Direct,
            local_addr,
            peer_addr,
            incoming: Mutex::new(b"pong".to_vec()),
            sent: Mutex::new(Vec::new()),
        };

        assert_eq!(socket.kind(), UdpSessionKind::Direct);
        assert_eq!(socket.local_addr().unwrap(), local_addr);
        assert_eq!(socket.peer_addr().unwrap(), peer_addr);
        assert_eq!(socket.send(b"ping").await.unwrap(), 4);

        let mut buf = [0; 8];
        let len = socket.recv(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], b"pong");
        assert_eq!(&*socket.sent.lock().unwrap(), b"ping");
    }

    struct MockUdpSessionListener {
        local_addr: SocketAddr,
        accepted: Option<MockUdpSessionSocket>,
    }

    #[async_trait]
    impl UdpSessionListener for MockUdpSessionListener {
        type Session = MockUdpSessionSocket;

        async fn listen(&mut self, request: UdpSessionListenRequest) -> anyhow::Result<()> {
            if let Some(local_addr) = request.bind.local_addr {
                self.local_addr = local_addr;
            }
            Ok(())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Session> {
            self.accepted
                .take()
                .ok_or_else(|| anyhow::anyhow!("no accepted session"))
        }
    }

    #[tokio::test]
    async fn udp_session_listener_reports_bound_local_addr_before_accept() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 10000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 10001));
        let mut listener = MockUdpSessionListener {
            local_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            accepted: Some(MockUdpSessionSocket {
                kind: UdpSessionKind::EasyTierMux,
                local_addr,
                peer_addr,
                incoming: Mutex::new(Vec::new()),
                sent: Mutex::new(Vec::new()),
            }),
        };

        listener
            .listen(UdpSessionListenRequest::new(
                UdpBindOptions::port_bound_listener(local_addr),
            ))
            .await
            .unwrap();

        assert_eq!(listener.local_addr().unwrap(), local_addr);
        assert_eq!(
            listener.accept().await.unwrap().peer_addr().unwrap(),
            peer_addr
        );
    }
}
