use std::future::Future;

use futures::{StreamExt, stream::FuturesUnordered};
use url::Url;

mod tcp;
mod udp;

pub(crate) use tcp::connect_tcp;
pub use udp::{ConnectedUdpSession, UdpSessionMode, connect_udp};

/// A host-created non-IP byte stream with host-provided endpoint metadata.
///
/// Unix and in-process transports use the same stream framing boundary as TCP,
/// but their endpoints cannot be represented by `SocketAddr`.
pub struct ConnectedByteStream<S> {
    socket: S,
    local_url: Option<Url>,
    remote_url: Url,
    resolved_remote_url: Option<Url>,
}

impl<S> ConnectedByteStream<S> {
    pub fn new(
        socket: S,
        local_url: Option<Url>,
        remote_url: Url,
        resolved_remote_url: Option<Url>,
    ) -> Self {
        Self {
            socket,
            local_url,
            remote_url,
            resolved_remote_url,
        }
    }

    pub fn into_parts(self) -> (S, Option<Url>, Url, Option<Url>) {
        (
            self.socket,
            self.local_url,
            self.remote_url,
            self.resolved_remote_url,
        )
    }
}

/// A transport endpoint established by a connectivity strategy.
///
/// Manual, direct, and hole-punch strategies stop at this boundary. Protocol
/// code consumes the endpoint and upgrades it into an EasyTier tunnel.
pub enum ConnectedTransport<TcpSocket> {
    Tcp(TcpSocket),
    Udp(ConnectedUdpSession),
    ByteStream(ConnectedByteStream<TcpSocket>),
}

async fn first_success<F, T>(mut futures: FuturesUnordered<F>) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>> + Send,
{
    let mut last_error = None;
    while let Some(result) = futures.next().await {
        match result {
            Ok(value) => return Ok(value),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no transport candidates")))
}
