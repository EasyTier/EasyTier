use std::{
    fmt, io,
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex, Weak},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::listener::{ListenerConnectionCounter, SocketListener};

use super::{
    NoopUdpSessionControlHandler, UdpBindOptions, UdpSession, UdpSessionControlHandler,
    UdpSessionLayer, UdpSessionListenRequest, UdpSessionProtocol, UdpSessionStunResponder,
    VirtualUdpSocket, VirtualUdpSocketFactory,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpSessionAcceptKind {
    EasyTierMux,
    Classified(UdpSessionProtocol),
}

pub async fn accept_udp_session<S, H, R>(
    layer: &Arc<UdpSessionLayer<S, H, R>>,
    accept_kind: UdpSessionAcceptKind,
) -> io::Result<UdpSession>
where
    S: VirtualUdpSocket,
    H: UdpSessionControlHandler<S>,
    R: UdpSessionStunResponder<S>,
{
    match accept_kind {
        UdpSessionAcceptKind::EasyTierMux => layer.accept().await,
        UdpSessionAcceptKind::Classified(protocol) => {
            layer.accept_classified_session(protocol).await
        }
    }
}

type Layer<F, H> = UdpSessionLayer<<F as VirtualUdpSocketFactory>::Socket, H, F>;

pub struct UdpSessionSocketListener<F, H = NoopUdpSessionControlHandler>
where
    F: VirtualUdpSocketFactory,
    H: UdpSessionControlHandler<F::Socket>,
{
    url: Url,
    request: UdpSessionListenRequest,
    accept_kind: UdpSessionAcceptKind,
    factory: Arc<F>,
    control_handler: Arc<H>,
    layer: Option<Arc<Layer<F, H>>>,
    layer_ref: Arc<StdMutex<Option<Weak<Layer<F, H>>>>>,
}

impl<F> UdpSessionSocketListener<F, NoopUdpSessionControlHandler>
where
    F: VirtualUdpSocketFactory,
{
    pub fn new(url: Url, local_addr: SocketAddr, factory: Arc<F>) -> Self {
        Self::new_with_control_handler(
            url,
            local_addr,
            UdpSessionAcceptKind::EasyTierMux,
            factory,
            Arc::new(NoopUdpSessionControlHandler),
        )
    }
}

impl<F, H> UdpSessionSocketListener<F, H>
where
    F: VirtualUdpSocketFactory,
    H: UdpSessionControlHandler<F::Socket>,
{
    pub fn new_with_control_handler(
        url: Url,
        local_addr: SocketAddr,
        accept_kind: UdpSessionAcceptKind,
        factory: Arc<F>,
        control_handler: Arc<H>,
    ) -> Self {
        let request = UdpSessionListenRequest::new(
            UdpBindOptions::port_bound_listener(local_addr).with_only_v6(true),
        );
        Self::new_with_request(url, request, accept_kind, factory, control_handler)
    }

    pub fn new_with_request(
        url: Url,
        request: UdpSessionListenRequest,
        accept_kind: UdpSessionAcceptKind,
        factory: Arc<F>,
        control_handler: Arc<H>,
    ) -> Self {
        Self {
            url,
            request,
            accept_kind,
            factory,
            control_handler,
            layer: None,
            layer_ref: Arc::new(StdMutex::new(None)),
        }
    }

    fn layer(&self) -> anyhow::Result<Arc<Layer<F, H>>> {
        self.layer
            .clone()
            .ok_or_else(|| anyhow::anyhow!("udp session listener is not started"))
    }
}

impl<F, H> fmt::Debug for UdpSessionSocketListener<F, H>
where
    F: VirtualUdpSocketFactory,
    H: UdpSessionControlHandler<F::Socket>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSessionSocketListener")
            .field("url", &self.url)
            .field("request", &self.request)
            .field("accept_kind", &self.accept_kind)
            .field("listening", &self.layer.is_some())
            .finish()
    }
}

#[async_trait]
impl<F, H> SocketListener for UdpSessionSocketListener<F, H>
where
    F: VirtualUdpSocketFactory,
    H: UdpSessionControlHandler<F::Socket>,
{
    type Accepted = UdpSession;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.layer.is_some() {
            return Ok(());
        }

        let socket = self.factory.bind_udp(self.request.bind.clone()).await?;
        let local_addr = socket.local_addr()?;
        self.url
            .set_port(Some(local_addr.port()))
            .map_err(|_| anyhow::anyhow!("failed to update udp listener port for {}", self.url))?;

        let layer = Arc::new(
            UdpSessionLayer::new_with_control_handler_and_stun_responder(
                socket,
                self.control_handler.clone(),
                self.factory.clone(),
            ),
        );
        if let UdpSessionAcceptKind::Classified(protocol) = self.accept_kind {
            layer.enable_classified_accept(protocol)?;
        }

        *self.layer_ref.lock().unwrap() = Some(Arc::downgrade(&layer));
        self.layer = Some(layer);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let layer = self.layer()?;
        let mut session = accept_udp_session(&layer, self.accept_kind).await?;
        session.keep_layer_alive(layer);
        Ok(session)
    }

    fn local_url(&self) -> Url {
        self.url.clone()
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        Arc::new(UdpSessionConnectionCounter {
            layer: self.layer_ref.clone(),
        })
    }
}

struct UdpSessionConnectionCounter<F, H>
where
    F: VirtualUdpSocketFactory,
    H: UdpSessionControlHandler<F::Socket>,
{
    layer: Arc<StdMutex<Option<Weak<Layer<F, H>>>>>,
}

impl<F, H> fmt::Debug for UdpSessionConnectionCounter<F, H>
where
    F: VirtualUdpSocketFactory,
    H: UdpSessionControlHandler<F::Socket>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSessionConnectionCounter")
            .field("active", &self.get())
            .finish()
    }
}

impl<F, H> ListenerConnectionCounter for UdpSessionConnectionCounter<F, H>
where
    F: VirtualUdpSocketFactory,
    H: UdpSessionControlHandler<F::Socket>,
{
    fn get(&self) -> Option<u32> {
        let layer = self.layer.lock().unwrap();
        let Some(layer) = layer.as_ref().and_then(Weak::upgrade) else {
            return Some(0);
        };
        let active = layer.active_session_count() + layer.active_classified_session_count();
        Some(active as u32)
    }
}
