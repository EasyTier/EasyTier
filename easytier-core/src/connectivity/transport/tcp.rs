use std::{net::SocketAddr, sync::Arc};

use futures::stream::FuturesUnordered;

use crate::socket::{
    IpVersion,
    tcp::{TcpBindOptions, TcpConnectOptions, TcpSocketPurpose, VirtualTcpSocketFactory},
};

use super::first_success;

pub async fn connect_tcp<H>(
    host: Arc<H>,
    remote_addr: SocketAddr,
    bind_addrs: Vec<SocketAddr>,
    default_bind: TcpBindOptions,
    purpose: TcpSocketPurpose,
) -> anyhow::Result<H::Socket>
where
    H: VirtualTcpSocketFactory,
{
    let ip_version = if remote_addr.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    };
    let default_bind = default_bind.with_ip_version(ip_version);
    let futures = FuturesUnordered::new();
    if bind_addrs.is_empty() {
        futures.push(
            host.connect_tcp(
                TcpConnectOptions::direct_connect(remote_addr)
                    .with_purpose(purpose)
                    .with_bind(default_bind),
            ),
        );
    } else {
        for bind_addr in bind_addrs {
            let bind = default_bind
                .clone()
                .with_local_addr(Some(bind_addr))
                .with_only_v6(true);
            futures.push(
                host.connect_tcp(
                    TcpConnectOptions::direct_connect(remote_addr)
                        .with_purpose(purpose)
                        .with_bind(bind),
                ),
            );
        }
    }
    first_success(futures).await
}
