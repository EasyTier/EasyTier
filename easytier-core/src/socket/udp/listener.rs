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
    UdpBindOptions, UdpSession, UdpSessionLayer, UdpSessionListenRequest, UdpSessionProtocol,
    UdpSessionStunResponder, VirtualUdpSocket, VirtualUdpSocketFactory,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpSessionAcceptKind {
    EasyTierMux,
    Classified(UdpSessionProtocol),
}

pub async fn accept_udp_session<S, R>(
    layer: &Arc<UdpSessionLayer<S, R>>,
    accept_kind: UdpSessionAcceptKind,
) -> io::Result<UdpSession>
where
    S: VirtualUdpSocket,
    R: UdpSessionStunResponder<S>,
{
    match accept_kind {
        UdpSessionAcceptKind::EasyTierMux => layer.accept().await,
        UdpSessionAcceptKind::Classified(protocol) => {
            layer.accept_classified_session(protocol).await
        }
    }
}

type Layer<F> = UdpSessionLayer<<F as VirtualUdpSocketFactory>::Socket, F>;

pub struct UdpSessionSocketListener<F>
where
    F: VirtualUdpSocketFactory,
{
    url: Url,
    request: UdpSessionListenRequest,
    accept_kind: UdpSessionAcceptKind,
    factory: Arc<F>,
    socket: Option<Arc<F::Socket>>,
    layer: Option<Arc<Layer<F>>>,
    layer_ref: Arc<StdMutex<Option<Weak<Layer<F>>>>>,
}

impl<F> UdpSessionSocketListener<F>
where
    F: VirtualUdpSocketFactory,
{
    pub fn new(url: Url, local_addr: SocketAddr, factory: Arc<F>) -> Self {
        let request = UdpSessionListenRequest::new(
            UdpBindOptions::port_bound_listener(local_addr).with_only_v6(true),
        );
        Self::new_with_request(url, request, UdpSessionAcceptKind::EasyTierMux, factory)
    }

    pub fn new_with_request(
        url: Url,
        request: UdpSessionListenRequest,
        accept_kind: UdpSessionAcceptKind,
        factory: Arc<F>,
    ) -> Self {
        Self {
            url,
            request,
            accept_kind,
            factory,
            socket: None,
            layer: None,
            layer_ref: Arc::new(StdMutex::new(None)),
        }
    }

    fn layer(&self) -> anyhow::Result<Arc<Layer<F>>> {
        self.layer
            .clone()
            .ok_or_else(|| anyhow::anyhow!("udp session listener is not started"))
    }

    pub fn bound_socket(&self) -> anyhow::Result<Arc<F::Socket>> {
        self.socket
            .clone()
            .ok_or_else(|| anyhow::anyhow!("udp session listener is not started"))
    }

    pub async fn accept_session(&self) -> anyhow::Result<UdpSession> {
        let layer = self.layer()?;
        let mut session = accept_udp_session(&layer, self.accept_kind).await?;
        session.keep_layer_alive(layer);
        Ok(session)
    }
}

impl<F> fmt::Debug for UdpSessionSocketListener<F>
where
    F: VirtualUdpSocketFactory,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSessionSocketListener")
            .field("url", &self.url)
            .field("request", &self.request)
            .field("accept_kind", &self.accept_kind)
            .field("listening", &self.socket.is_some())
            .finish()
    }
}

#[async_trait]
impl<F> SocketListener for UdpSessionSocketListener<F>
where
    F: VirtualUdpSocketFactory,
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

        let layer = Arc::new(UdpSessionLayer::new_with_stun_responder(
            socket.clone(),
            self.factory.clone(),
        ));
        if let UdpSessionAcceptKind::Classified(protocol) = self.accept_kind {
            layer.enable_classified_accept(protocol)?;
        }

        *self.layer_ref.lock().unwrap() = Some(Arc::downgrade(&layer));
        self.socket = Some(socket);
        self.layer = Some(layer);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        self.accept_session().await
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

struct UdpSessionConnectionCounter<F>
where
    F: VirtualUdpSocketFactory,
{
    layer: Arc<StdMutex<Option<Weak<Layer<F>>>>>,
}

impl<F> fmt::Debug for UdpSessionConnectionCounter<F>
where
    F: VirtualUdpSocketFactory,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSessionConnectionCounter")
            .field("active", &self.get())
            .finish()
    }
}

impl<F> ListenerConnectionCounter for UdpSessionConnectionCounter<F>
where
    F: VirtualUdpSocketFactory,
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
