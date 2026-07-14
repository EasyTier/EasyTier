use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
};

use crate::socket::{
    IpVersion, SocketContext,
    dns::{DnsQuery, DnsResolver},
    udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
};

use super::{
    AddrError, Result, SocksError, TargetAddr, new_udp_header, parse_udp_request,
    server::{Socks5ServerRuntime, Socks5UdpAssociation},
};

/// Portable SOCKS command runtime backed exclusively by host capabilities.
pub struct HostSocks5ServerRuntime<H>
where
    H: VirtualUdpSocketFactory,
{
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    socket_context: SocketContext,
}

impl<H> HostSocks5ServerRuntime<H>
where
    H: VirtualUdpSocketFactory,
{
    pub fn new(host: Arc<H>, dns: Arc<dyn DnsResolver>, socket_context: SocketContext) -> Self {
        Self {
            host,
            dns,
            socket_context,
        }
    }

    async fn resolve_target(&self, target: TargetAddr) -> Result<SocketAddr> {
        match target {
            TargetAddr::Ip(address) => Ok(address),
            TargetAddr::Domain(domain, port) => {
                tracing::debug!(%domain, "attempting SOCKS DNS resolution");
                let address = self
                    .dns
                    .resolve(DnsQuery::new(domain.clone(), self.socket_context.clone()))
                    .await
                    .map_err(|error| {
                        SocksError::Other(error.context(AddrError::DNSResolutionFailed))
                    })?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        SocksError::Other(anyhow::Error::new(AddrError::Custom(format!(
                            "cannot resolve SOCKS domain {domain}"
                        ))))
                    })?;
                let address = SocketAddr::new(address, port);
                tracing::debug!(%address, "SOCKS domain resolved");
                Ok(address)
            }
        }
    }

    fn udp_bind_options(&self) -> UdpBindOptions {
        UdpBindOptions::socks5()
            .with_context(self.socket_context.clone().with_ip_version(IpVersion::V6))
            .with_local_addr(Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                0,
                0,
            ))))
    }
}

#[async_trait::async_trait]
impl<H> Socks5ServerRuntime for HostSocks5ServerRuntime<H>
where
    H: VirtualUdpSocketFactory,
{
    async fn resolve_dns(&self, target_addr: TargetAddr) -> Result<TargetAddr> {
        self.resolve_target(target_addr).await.map(TargetAddr::Ip)
    }

    async fn bind_udp_association(&self) -> Result<Box<dyn Socks5UdpAssociation>> {
        let inbound = self
            .host
            .bind_udp(self.udp_bind_options())
            .await
            .map_err(SocksError::Other)?;
        Ok(Box::new(HostSocks5UdpAssociation {
            inbound,
            host: self.host.clone(),
            dns: self.dns.clone(),
            socket_context: self.socket_context.clone(),
            client: Mutex::new(None),
        }))
    }
}

struct HostSocks5UdpAssociation<H>
where
    H: VirtualUdpSocketFactory,
{
    inbound: Arc<H::Socket>,
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    socket_context: SocketContext,
    client: Mutex<Option<SocketAddr>>,
}

#[async_trait::async_trait]
impl<H> Socks5UdpAssociation for HostSocks5UdpAssociation<H>
where
    H: VirtualUdpSocketFactory,
{
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inbound.local_addr()
    }

    async fn transfer(self: Box<Self>) -> Result<()> {
        let runtime = HostSocks5ServerRuntime::new(
            self.host.clone(),
            self.dns.clone(),
            self.socket_context.clone(),
        );
        let outbound = self
            .host
            .bind_udp(runtime.udp_bind_options())
            .await
            .map_err(SocksError::Other)?;
        tokio::try_join!(
            transfer_requests(self.as_ref(), outbound.as_ref(), &runtime),
            transfer_responses(self.as_ref(), outbound.as_ref()),
        )?;
        Ok(())
    }
}

async fn transfer_requests<H>(
    association: &HostSocks5UdpAssociation<H>,
    outbound: &H::Socket,
    runtime: &HostSocks5ServerRuntime<H>,
) -> Result<()>
where
    H: VirtualUdpSocketFactory,
{
    let mut buffer = vec![0u8; 0x10000];
    loop {
        let (size, client) = association.inbound.recv_from(&mut buffer).await?;
        {
            let mut pinned = association.client.lock().unwrap();
            match *pinned {
                None => *pinned = Some(client),
                Some(current) if current == client => {}
                Some(_) => continue,
            }
        }

        let (fragment, target, data) = parse_udp_request(&buffer[..size]).await?;
        if fragment != 0 {
            tracing::debug!(fragment, "discarding fragmented SOCKS UDP request");
            return Ok(());
        }

        let mut target = runtime.resolve_target(target).await?;
        if let IpAddr::V4(ipv4) = target.ip() {
            target.set_ip(IpAddr::V6(ipv4.to_ipv6_mapped()));
        }
        outbound.send_to(data, target).await?;
    }
}

async fn transfer_responses<H>(
    association: &HostSocks5UdpAssociation<H>,
    outbound: &H::Socket,
) -> Result<()>
where
    H: VirtualUdpSocketFactory,
{
    let mut buffer = vec![0u8; 0x10000];
    loop {
        let (size, remote) = outbound.recv_from(&mut buffer).await?;
        let client = *association.client.lock().unwrap();
        let Some(client) = client else {
            continue;
        };
        let mut data = new_udp_header(remote)?;
        data.extend_from_slice(&buffer[..size]);
        association.inbound.send_to(&data, client).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StaticDns;

    #[async_trait::async_trait]
    impl DnsResolver for StaticDns {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            assert_eq!(query.host, "peer.example");
            Ok(vec!["192.0.2.8".parse().unwrap()])
        }
    }

    struct MockSocket;

    #[async_trait::async_trait]
    impl VirtualUdpSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("[::]:42000".parse().unwrap())
        }

        async fn send_to(&self, _data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            unreachable!()
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct MockHost {
        binds: AtomicUsize,
        options: Mutex<Vec<UdpBindOptions>>,
    }

    #[async_trait::async_trait]
    impl VirtualUdpSocketFactory for MockHost {
        type Socket = MockSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.binds.fetch_add(1, Ordering::Relaxed);
            self.options.lock().unwrap().push(options);
            Ok(Arc::new(MockSocket))
        }
    }

    #[tokio::test]
    async fn resolves_and_binds_only_through_host_capabilities() {
        let host = Arc::new(MockHost::default());
        let context = SocketContext::default().with_socket_mark(Some(7));
        let runtime =
            HostSocks5ServerRuntime::new(host.clone(), Arc::new(StaticDns), context.clone());

        assert_eq!(
            runtime
                .resolve_dns(TargetAddr::Domain("peer.example".into(), 443))
                .await
                .unwrap(),
            TargetAddr::Ip("192.0.2.8:443".parse().unwrap())
        );
        let association = runtime.bind_udp_association().await.unwrap();
        assert_eq!(association.local_addr().unwrap().port(), 42000);
        assert_eq!(host.binds.load(Ordering::Relaxed), 1);
        let options = host.options.lock().unwrap();
        assert_eq!(
            options[0].purpose,
            crate::socket::udp::UdpSocketPurpose::Socks5
        );
        assert_eq!(options[0].context.socket_mark, context.socket_mark);
        assert_eq!(options[0].context.ip_version, IpVersion::V6);
    }
}
