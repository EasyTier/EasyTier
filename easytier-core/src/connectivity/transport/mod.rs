use std::future::Future;

use futures::{StreamExt, stream::FuturesUnordered};

mod tcp;
mod udp;

pub use tcp::connect_tcp;
pub use udp::{ConnectedUdpSession, UdpSessionMode, connect_udp};

/// A transport endpoint established by a connectivity strategy.
///
/// Manual, direct, and hole-punch strategies stop at this boundary. Protocol
/// code consumes the endpoint and upgrades it into an EasyTier tunnel.
pub enum ConnectedTransport<TcpSocket> {
    Tcp(TcpSocket),
    Udp(ConnectedUdpSession),
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
