use std::{net::SocketAddr, sync::Arc};

use futures::stream::FuturesUnordered;

use crate::socket::tcp::{TcpBindOptions, TcpConnectOptions, VirtualTcpSocketFactory};

use super::first_success;

pub async fn connect_tcp<H>(
    host: Arc<H>,
    remote_addr: SocketAddr,
    bind_addrs: Vec<SocketAddr>,
    default_bind: TcpBindOptions,
) -> anyhow::Result<H::Socket>
where
    H: VirtualTcpSocketFactory,
{
    let futures = FuturesUnordered::new();
    if bind_addrs.is_empty() {
        futures.push(
            host.connect_tcp(
                TcpConnectOptions::direct_connect(remote_addr).with_bind(default_bind),
            ),
        );
    } else {
        for bind_addr in bind_addrs {
            let bind = default_bind
                .clone()
                .with_local_addr(Some(bind_addr))
                .with_only_v6(true);
            futures.push(
                host.connect_tcp(TcpConnectOptions::direct_connect(remote_addr).with_bind(bind)),
            );
        }
    }
    first_success(futures).await
}
