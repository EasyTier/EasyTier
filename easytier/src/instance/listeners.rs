use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use easytier_core::{
    instance::{ExternalListenerFactory, ExternalListenerRequest},
    listener::{
        self as core_listener,
        transport::{AcceptedTransport, AcceptedTunnelEvent, AcceptedTunnelEventSink},
    },
};

#[cfg(feature = "faketcp")]
use crate::common::netns::NetNS;
use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    socket::tcp::RuntimeTcpSocket,
};

pub(crate) struct RuntimeExternalListenerFactory;

impl RuntimeExternalListenerFactory {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl ExternalListenerFactory<AcceptedTransport<RuntimeTcpSocket>>
    for RuntimeExternalListenerFactory
{
    fn supports_scheme(&self, scheme: &str) -> bool {
        match scheme {
            "faketcp" => cfg!(feature = "faketcp"),
            "unix" => cfg!(unix),
            _ => false,
        }
    }

    fn create(
        &self,
        request: ExternalListenerRequest,
    ) -> Box<dyn core_listener::SocketListener<Accepted = AcceptedTransport<RuntimeTcpSocket>>>
    {
        match request.url.scheme() {
            #[cfg(feature = "faketcp")]
            "faketcp" => Box::new(RuntimeFakeTcpSocketListener::new(
                request.url,
                NetNS::from_socket_context(&request.socket_context),
            )),
            #[cfg(unix)]
            "unix" => Box::new(RuntimeUnixStreamListener::new(request.url)),
            scheme => unreachable!("core requested unsupported external listener: {scheme}"),
        }
    }
}

#[cfg(unix)]
struct RuntimeUnixStreamListener {
    url: url::Url,
    inner: Option<tokio::net::UnixListener>,
}

#[cfg(unix)]
impl RuntimeUnixStreamListener {
    fn new(url: url::Url) -> Self {
        Self { url, inner: None }
    }
}

#[cfg(unix)]
fn unix_stream_remote_url(remote_addr: tokio::net::unix::SocketAddr) -> url::Url {
    crate::tunnel::unix::url_from_unix_socket_addr(remote_addr).unwrap_or_else(|| {
        format!("unix://anonymous/{}", uuid::Uuid::new_v4())
            .parse()
            .expect("synthetic Unix stream URL should be valid")
    })
}

#[cfg(unix)]
impl Debug for RuntimeUnixStreamListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeUnixStreamListener")
            .field("url", &self.url)
            .field("listening", &self.inner.is_some())
            .finish()
    }
}

#[cfg(unix)]
#[async_trait]
impl core_listener::SocketListener for RuntimeUnixStreamListener {
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.inner.is_none() {
            self.inner = Some(tokio::net::UnixListener::bind(self.url.path())?);
        }
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let (stream, remote_addr) = self
            .inner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Unix stream listener is not started"))?
            .accept()
            .await?;
        Ok(AcceptedTransport::ByteStream {
            socket: RuntimeTcpSocket::from_unix(stream),
            local_url: self.url.clone(),
            remote_url: Some(unix_stream_remote_url(remote_addr)),
        })
    }

    fn local_url(&self) -> url::Url {
        self.url.clone()
    }
}

#[cfg(unix)]
impl Drop for RuntimeUnixStreamListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.url.path());
    }
}

#[cfg(feature = "faketcp")]
struct RuntimeFakeTcpSocketListener {
    net_ns: NetNS,
    inner: crate::tunnel::fake_tcp::FakeTcpTunnelListener,
}

#[cfg(feature = "faketcp")]
impl RuntimeFakeTcpSocketListener {
    fn new(url: url::Url, net_ns: NetNS) -> Self {
        Self {
            net_ns,
            inner: crate::tunnel::fake_tcp::FakeTcpTunnelListener::new(url),
        }
    }
}

#[cfg(feature = "faketcp")]
impl Debug for RuntimeFakeTcpSocketListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeFakeTcpSocketListener")
            .field(
                "url",
                &core_listener::SocketListener::local_url(&self.inner),
            )
            .finish()
    }
}

#[cfg(feature = "faketcp")]
#[async_trait]
impl core_listener::SocketListener for RuntimeFakeTcpSocketListener {
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        let _guard = self.net_ns.guard();
        core_listener::SocketListener::listen(&mut self.inner).await?;
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let local_url = core_listener::SocketListener::local_url(&self.inner);
        let socket = self.inner.accept_socket().await?;
        Ok(AcceptedTransport::Tcp {
            socket: RuntimeTcpSocket::from_fake_tcp(socket),
            local_url,
            upgrade_permit: None,
        })
    }

    fn local_url(&self) -> url::Url {
        core_listener::SocketListener::local_url(&self.inner)
    }
}

#[derive(Debug)]
pub(crate) struct GlobalCtxListenerEventSink {
    global_ctx: ArcGlobalCtx,
}

pub(crate) fn runtime_listener_event_sink(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn core_listener::ListenerEventSink> {
    Arc::new(GlobalCtxListenerEventSink { global_ctx })
}

impl core_listener::ListenerEventSink for GlobalCtxListenerEventSink {
    fn emit(&self, event: core_listener::ListenerEvent) {
        match event {
            core_listener::ListenerEvent::ListenerPlanFailed { url, error } => {
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAddFailed(url, error));
            }
            core_listener::ListenerEvent::ListenerAdded { url, .. } => {
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAdded(url));
            }
            core_listener::ListenerEvent::ListenerRemoved { .. } => {}
            core_listener::ListenerEvent::ListenerAddFailed {
                url,
                error,
                will_retry,
                ..
            } => {
                let message = if will_retry {
                    format!("error: {error}, retry listen later...")
                } else {
                    format!("error: {error}")
                };
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAddFailed(url, message));
            }
            core_listener::ListenerEvent::ListenerAcceptFailed { url, error } => {
                self.global_ctx
                    .issue_event(GlobalCtxEvent::ListenerAcceptFailed(
                        url,
                        format!("error: {error}, retry listen later..."),
                    ));
            }
            core_listener::ListenerEvent::SocketAccepted { .. } => {}
            core_listener::ListenerEvent::AcceptedSocketHandleFailed { url, error } => {
                tracing::error!(%url, %error, "accepted socket handler failed");
            }
        }
    }
}

#[derive(Debug)]
struct GlobalCtxAcceptedTunnelEventSink {
    global_ctx: ArcGlobalCtx,
}

pub(crate) fn runtime_accepted_tunnel_event_sink(
    global_ctx: ArcGlobalCtx,
) -> Arc<dyn AcceptedTunnelEventSink> {
    Arc::new(GlobalCtxAcceptedTunnelEventSink { global_ctx })
}

impl AcceptedTunnelEventSink for GlobalCtxAcceptedTunnelEventSink {
    fn emit(&self, event: AcceptedTunnelEvent) {
        let event = match event {
            AcceptedTunnelEvent::Accepted {
                local_url,
                remote_url,
            } => GlobalCtxEvent::ConnectionAccepted(local_url, remote_url),
            AcceptedTunnelEvent::AdmissionFailed {
                local_url,
                remote_url,
                error,
            } => GlobalCtxEvent::ConnectionError(local_url, remote_url, error),
        };
        self.global_ctx.issue_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_listener_capabilities_follow_native_build() {
        let factory = RuntimeExternalListenerFactory;

        assert_eq!(
            factory.supports_scheme("faketcp"),
            cfg!(feature = "faketcp")
        );
        assert_eq!(factory.supports_scheme("unix"), cfg!(unix));
        assert!(!factory.supports_scheme("tcp"));
    }
}
