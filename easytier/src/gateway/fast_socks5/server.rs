use std::{io, net::SocketAddr};

use anyhow::Context;
use tokio::net::{TcpStream, UdpSocket};

pub use easytier_core::proxy::socks5_protocol::server::*;
use easytier_core::proxy::socks5_protocol::{
    Result, TargetAddr, new_udp_header, parse_udp_request,
};

use super::util::{stream::tcp_connect_with_timeout, target_addr::resolve_dns};

pub struct DefaultTcpConnector;

#[async_trait::async_trait]
impl AsyncTcpConnector for DefaultTcpConnector {
    type S = TcpStream;

    async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<TcpStream> {
        tcp_connect_with_timeout(addr, timeout_s).await
    }
}

pub struct RuntimeSocks5Server;

#[async_trait::async_trait]
impl Socks5ServerRuntime for RuntimeSocks5Server {
    async fn resolve_dns(&self, target_addr: TargetAddr) -> Result<TargetAddr> {
        resolve_dns(target_addr).await.map_err(Into::into)
    }

    async fn bind_udp_association(&self) -> Result<Box<dyn Socks5UdpAssociation>> {
        Ok(Box::new(RuntimeSocks5UdpAssociation {
            inbound: UdpSocket::bind("[::]:0").await?,
        }))
    }
}

struct RuntimeSocks5UdpAssociation {
    inbound: UdpSocket,
}

#[async_trait::async_trait]
impl Socks5UdpAssociation for RuntimeSocks5UdpAssociation {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inbound.local_addr()
    }

    async fn transfer(self: Box<Self>) -> Result<()> {
        transfer_udp(self.inbound).await
    }
}

async fn handle_udp_request(inbound: &UdpSocket, outbound: &UdpSocket) -> Result<()> {
    let mut buf = vec![0u8; 0x10000];
    loop {
        let (size, client_addr) = inbound.recv_from(&mut buf).await?;
        tracing::debug!("Server recieve udp from {}", client_addr);
        inbound.connect(client_addr).await?;

        let (frag, target_addr, data) = parse_udp_request(&buf[..size]).await?;
        if frag != 0 {
            tracing::debug!("Discard UDP frag packets sliently.");
            return Ok(());
        }

        tracing::debug!("Server forward to packet to {}", target_addr);
        let mut target_addr = std::net::ToSocketAddrs::to_socket_addrs(&target_addr)?
            .next()
            .context("unreachable")?;
        target_addr.set_ip(match target_addr.ip() {
            std::net::IpAddr::V4(v4) => std::net::IpAddr::V6(v4.to_ipv6_mapped()),
            v6 @ std::net::IpAddr::V6(_) => v6,
        });
        outbound.send_to(data, target_addr).await?;
    }
}

async fn handle_udp_response(inbound: &UdpSocket, outbound: &UdpSocket) -> Result<()> {
    let mut buf = vec![0u8; 0x10000];
    loop {
        let (size, remote_addr) = outbound.recv_from(&mut buf).await?;
        tracing::debug!("Recieve packet from {}", remote_addr);

        let mut data = new_udp_header(remote_addr)?;
        data.extend_from_slice(&buf[..size]);
        inbound.send(&data).await?;
    }
}

async fn transfer_udp(inbound: UdpSocket) -> Result<()> {
    let outbound = UdpSocket::bind("[::]:0").await?;
    tokio::try_join!(
        handle_udp_request(&inbound, &outbound),
        handle_udp_response(&inbound, &outbound)
    )?;
    Ok(())
}
