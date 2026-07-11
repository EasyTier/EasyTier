use std::{fmt, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use url::Url;

use crate::{
    listener::{
        AcceptedSocketHandler, ListenerConnectionCounter, ListenerEventSink, ListenerManager,
        SocketListener,
    },
    socket::{
        tcp::{TcpListenOptions, TcpSocketListener, VirtualTcpListener, VirtualTcpListenerFactory},
        udp::{
            UdpSession, UdpSessionAcceptKind, UdpSessionControlHandler, UdpSessionListenRequest,
            UdpSessionSocketListener, VirtualUdpSocketFactory,
        },
    },
};

pub type HostAcceptedTcpSocket<H> =
    <<H as VirtualTcpListenerFactory>::Listener as VirtualTcpListener>::Socket;

/// The transport boundary of a core listener.
///
/// Socket creation and binding belong to the host factory. Protocol handling
/// consumes this value and may turn it into one or more EasyTier tunnels.
pub enum AcceptedTransport<TcpSocket> {
    Tcp { socket: TcpSocket, local_url: Url },
    Udp { session: UdpSession, local_url: Url },
}

impl<TcpSocket> AcceptedTransport<TcpSocket> {
    pub fn local_url(&self) -> &Url {
        match self {
            Self::Tcp { local_url, .. } | Self::Udp { local_url, .. } => local_url,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransportListenerConfig {
    Tcp {
        url: Url,
        options: TcpListenOptions,
        must_succeed: bool,
    },
    Udp {
        url: Url,
        request: UdpSessionListenRequest,
        accept_kind: UdpSessionAcceptKind,
        must_succeed: bool,
    },
}

impl TransportListenerConfig {
    pub fn must_succeed(&self) -> bool {
        match self {
            Self::Tcp { must_succeed, .. } | Self::Udp { must_succeed, .. } => *must_succeed,
        }
    }
}

struct TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    inner: TcpSocketListener<H>,
}

impl<H> TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    fn new(url: Url, options: TcpListenOptions, host: Arc<H>) -> Self {
        Self {
            inner: TcpSocketListener::new_with_options(url, options, host),
        }
    }
}

impl<H> fmt::Debug for TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpTransportListener")
            .field("inner", &self.inner)
            .finish()
    }
}

#[async_trait]
impl<H> SocketListener for TcpTransportListener<H>
where
    H: VirtualTcpListenerFactory,
{
    type Accepted = AcceptedTransport<HostAcceptedTcpSocket<H>>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.inner.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let socket = self.inner.accept().await?;
        Ok(AcceptedTransport::Tcp {
            socket,
            local_url: self.inner.local_url(),
        })
    }

    fn local_url(&self) -> Url {
        self.inner.local_url()
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        self.inner.connection_counter()
    }
}

struct UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<H::Socket>,
{
    inner: UdpSessionSocketListener<H, H>,
    tcp_socket: PhantomData<fn() -> TcpSocket>,
}

impl<H, TcpSocket> UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<H::Socket>,
{
    fn new(
        url: Url,
        request: UdpSessionListenRequest,
        accept_kind: UdpSessionAcceptKind,
        host: Arc<H>,
    ) -> Self {
        Self {
            inner: UdpSessionSocketListener::new_with_request(
                url,
                request,
                accept_kind,
                host.clone(),
                host,
            ),
            tcp_socket: PhantomData,
        }
    }
}

impl<H, TcpSocket> fmt::Debug for UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<H::Socket>,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpTransportListener")
            .field("inner", &self.inner)
            .finish()
    }
}

#[async_trait]
impl<H, TcpSocket> SocketListener for UdpTransportListener<H, TcpSocket>
where
    H: VirtualUdpSocketFactory + UdpSessionControlHandler<H::Socket>,
    TcpSocket: Send + 'static,
{
    type Accepted = AcceptedTransport<TcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.inner.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let session = self.inner.accept().await?;
        Ok(AcceptedTransport::Udp {
            session,
            local_url: self.inner.local_url(),
        })
    }

    fn local_url(&self) -> Url {
        self.inner.local_url()
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        self.inner.connection_counter()
    }
}

struct ErasedAcceptedTransportHandler<TcpSocket> {
    inner: Arc<dyn AcceptedSocketHandler<AcceptedTransport<TcpSocket>>>,
}

#[async_trait]
impl<TcpSocket> AcceptedSocketHandler<AcceptedTransport<TcpSocket>>
    for ErasedAcceptedTransportHandler<TcpSocket>
where
    TcpSocket: Send + 'static,
{
    async fn handle_accepted_socket(
        &self,
        accepted: AcceptedTransport<TcpSocket>,
    ) -> anyhow::Result<()> {
        self.inner.handle_accepted_socket(accepted).await
    }
}

type HostTransportListenerManager<H> = ListenerManager<
    AcceptedTransport<HostAcceptedTcpSocket<H>>,
    ErasedAcceptedTransportHandler<HostAcceptedTcpSocket<H>>,
>;

/// Owns TCP and UDP transport listeners built entirely from host factories.
pub struct TransportListenerService<H>
where
    H: VirtualTcpListenerFactory
        + VirtualUdpSocketFactory
        + UdpSessionControlHandler<<H as VirtualUdpSocketFactory>::Socket>,
{
    manager: HostTransportListenerManager<H>,
}

impl<H> TransportListenerService<H>
where
    H: VirtualTcpListenerFactory
        + VirtualUdpSocketFactory
        + UdpSessionControlHandler<<H as VirtualUdpSocketFactory>::Socket>,
{
    pub fn new(
        host: Arc<H>,
        configs: Vec<TransportListenerConfig>,
        handler: Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>,
    ) -> Self {
        Self::build(host, configs, handler, None)
    }

    pub fn new_with_events(
        host: Arc<H>,
        configs: Vec<TransportListenerConfig>,
        handler: Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>,
        events: Arc<dyn ListenerEventSink>,
    ) -> Self {
        Self::build(host, configs, handler, Some(events))
    }

    fn build(
        host: Arc<H>,
        configs: Vec<TransportListenerConfig>,
        handler: Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>,
        events: Option<Arc<dyn ListenerEventSink>>,
    ) -> Self {
        let handler = Arc::new(ErasedAcceptedTransportHandler { inner: handler });
        let mut manager = match events {
            Some(events) => ListenerManager::new_with_events(handler, events),
            None => ListenerManager::new(handler),
        };

        for config in configs {
            let must_succeed = config.must_succeed();
            match config {
                TransportListenerConfig::Tcp { url, options, .. } => {
                    let host = host.clone();
                    manager.add_listener(
                        move || {
                            Box::new(TcpTransportListener::new(
                                url.clone(),
                                options.clone(),
                                host.clone(),
                            ))
                        },
                        must_succeed,
                    );
                }
                TransportListenerConfig::Udp {
                    url,
                    request,
                    accept_kind,
                    ..
                } => {
                    let host = host.clone();
                    manager.add_listener(
                        move || {
                            Box::new(UdpTransportListener::new(
                                url.clone(),
                                request.clone(),
                                accept_kind,
                                host.clone(),
                            ))
                        },
                        must_succeed,
                    );
                }
            }
        }

        Self { manager }
    }

    pub fn listener_count(&self) -> usize {
        self.manager.listener_count()
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        self.manager.run().await
    }

    pub async fn stop(&self) {
        self.manager.stop().await;
    }
}
