use std::fmt::Debug;

use async_trait::async_trait;
use easytier_core::listener::{
    self as core_listener, ExternalListenerFactory, ExternalListenerRequest,
    transport::{AcceptedTransport, AcceptedTunnelEvent, AcceptedTunnelEventSink},
};
use easytier_core::socket::SocketListener;

#[cfg(feature = "faketcp")]
use crate::common::netns::NetNS;
use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    socket::tcp::RuntimeTcpSocket,
};

pub(crate) struct RuntimeExternalListenerFactory;

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
    ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<RuntimeTcpSocket>>> {
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
    crate::socket::tcp::url_from_unix_socket_addr(remote_addr).unwrap_or_else(|| {
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
impl SocketListener for RuntimeUnixStreamListener {
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
    inner: crate::socket::fake_tcp::FakeTcpSocketListener,
}

#[cfg(feature = "faketcp")]
impl RuntimeFakeTcpSocketListener {
    fn new(url: url::Url, net_ns: NetNS) -> Self {
        Self {
            net_ns,
            inner: crate::socket::fake_tcp::FakeTcpSocketListener::new(url),
        }
    }
}

#[cfg(feature = "faketcp")]
impl Debug for RuntimeFakeTcpSocketListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeFakeTcpSocketListener")
            .field("url", &SocketListener::local_url(&self.inner))
            .finish()
    }
}

#[cfg(feature = "faketcp")]
#[async_trait]
impl SocketListener for RuntimeFakeTcpSocketListener {
    type Accepted = AcceptedTransport<RuntimeTcpSocket>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        let _guard = self.net_ns.guard();
        SocketListener::listen(&mut self.inner).await?;
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let local_url = SocketListener::local_url(&self.inner);
        let socket = self.inner.accept_socket().await?;
        Ok(AcceptedTransport::Tcp {
            socket: RuntimeTcpSocket::from_fake_tcp(socket),
            local_url,
            upgrade_permit: None,
        })
    }

    fn local_url(&self) -> url::Url {
        SocketListener::local_url(&self.inner)
    }
}

#[derive(Debug)]
pub(crate) struct GlobalCtxListenerEvents {
    global_ctx: ArcGlobalCtx,
}

impl GlobalCtxListenerEvents {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}

impl core_listener::ListenerEventSink for GlobalCtxListenerEvents {
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

impl AcceptedTunnelEventSink for GlobalCtxListenerEvents {
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

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_adapters_exchange_bytes_and_unlink_listener() {
        use easytier_core::connectivity::composite::ConnectorRuntime;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("easytier.sock");
        let url: url::Url = format!("unix://{}", path.display()).parse().unwrap();
        let mut listener = RuntimeUnixStreamListener::new(url.clone());
        SocketListener::listen(&mut listener).await.unwrap();

        let runtime = crate::host_runtime::native_host_runtime();
        let (accepted, connected) = tokio::join!(
            SocketListener::accept(&mut listener),
            runtime.connect_byte_stream(&url),
        );
        let AcceptedTransport::ByteStream {
            socket: mut server,
            local_url,
            ..
        } = accepted.unwrap()
        else {
            panic!("Unix listener returned a non-byte-stream transport");
        };
        let (mut client, _, _, _) = connected.unwrap().into_parts();
        assert_eq!(local_url, url);

        client.write_all(b"ping").await.unwrap();
        let mut request = [0; 4];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");

        server.write_all(b"pong").await.unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        drop(listener);
        assert!(!path.exists());
    }
}
