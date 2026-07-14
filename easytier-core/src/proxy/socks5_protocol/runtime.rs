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
        let outbound = self
            .host
            .bind_udp(
                UdpBindOptions::socks5()
                    .with_context(self.socket_context.clone().with_ip_version(IpVersion::V6))
                    .with_local_addr(Some(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::UNSPECIFIED,
                        0,
                        0,
                        0,
                    )))),
            )
            .await
            .map_err(SocksError::Other)?;
        tokio::try_join!(
            transfer_requests(self.as_ref(), outbound.as_ref()),
            transfer_responses(self.as_ref(), outbound.as_ref()),
        )?;
        Ok(())
    }
}

async fn transfer_requests<H>(
    association: &HostSocks5UdpAssociation<H>,
    outbound: &H::Socket,
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

        let target = match target {
            TargetAddr::Ip(address) => address,
            TargetAddr::Domain(_, _) => {
                return Err(io::Error::other(
                    "SOCKS UDP domain targets must be explicitly resolved by the client",
                )
                .into());
            }
        };
        outbound.send_to(data, ipv4_mapped_addr(target)).await?;
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
        let mut data = new_udp_header(ipv4_mapped_addr(remote))?;
        data.extend_from_slice(&buffer[..size]);
        association.inbound.send_to(&data, client).await?;
    }
}

fn ipv4_mapped_addr(mut address: SocketAddr) -> SocketAddr {
    if let IpAddr::V4(ipv4) = address.ip() {
        address.set_ip(IpAddr::V6(ipv4.to_ipv6_mapped()));
    }
    address
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StaticDns;

    #[async_trait::async_trait]
    impl DnsResolver for StaticDns {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            assert_eq!(query.host, "peer.example");
            Ok(vec!["192.0.2.8".parse().unwrap()])
        }
    }

    #[derive(Default)]
    struct MockSocket {
        receives: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        sends: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    #[async_trait::async_trait]
    impl VirtualUdpSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("[::]:42000".parse().unwrap())
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sends.lock().unwrap().push((data.to_vec(), addr));
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let (data, addr) = self.receives.lock().unwrap().pop_front().unwrap();
            buf[..data.len()].copy_from_slice(&data);
            Ok((data.len(), addr))
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
            Ok(Arc::new(MockSocket::default()))
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

    #[tokio::test]
    async fn udp_requests_pin_the_first_client_and_map_ipv4_targets() {
        let client: SocketAddr = "192.0.2.1:1000".parse().unwrap();
        let other_client: SocketAddr = "192.0.2.2:1000".parse().unwrap();
        let target: SocketAddr = "198.51.100.3:53".parse().unwrap();
        let inbound = Arc::new(MockSocket::default());
        let outbound = MockSocket::default();

        let mut request = new_udp_header(target).unwrap();
        request.extend_from_slice(b"first");
        let mut ignored = new_udp_header(target).unwrap();
        ignored.extend_from_slice(b"ignored");
        let mut fragmented = new_udp_header(target).unwrap();
        fragmented[2] = 1;
        inbound.receives.lock().unwrap().extend([
            (request, client),
            (ignored, other_client),
            (fragmented, client),
        ]);

        let association = HostSocks5UdpAssociation {
            inbound,
            host: Arc::new(MockHost::default()),
            socket_context: SocketContext::default(),
            client: Mutex::new(None),
        };
        transfer_requests(&association, &outbound).await.unwrap();

        assert_eq!(*association.client.lock().unwrap(), Some(client));
        let sends = outbound.sends.lock().unwrap();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, b"first");
        assert_eq!(sends[0].1, "[::ffff:198.51.100.3]:53".parse().unwrap());
    }

    #[tokio::test]
    async fn udp_requests_reject_domain_targets_without_dns() {
        let client: SocketAddr = "192.0.2.1:1000".parse().unwrap();
        let inbound = Arc::new(MockSocket::default());
        let outbound = MockSocket::default();
        let mut request = new_udp_header(("peer.example", 53)).unwrap();
        request.extend_from_slice(b"query");
        inbound
            .receives
            .lock()
            .unwrap()
            .push_back((request, client));

        let association = HostSocks5UdpAssociation {
            inbound,
            host: Arc::new(MockHost::default()),
            socket_context: SocketContext::default(),
            client: Mutex::new(None),
        };
        let error = transfer_requests(&association, &outbound)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("must be explicitly resolved"));
        assert!(outbound.sends.lock().unwrap().is_empty());
    }

    #[test]
    fn udp_response_preserves_ipv6_wire_family_for_mapped_ipv4() {
        let remote = ipv4_mapped_addr("198.51.100.3:53".parse().unwrap());
        let header = new_udp_header(remote).unwrap();

        assert_eq!(header[3], super::super::consts::SOCKS5_ADDR_TYPE_IPV6);
    }
}
