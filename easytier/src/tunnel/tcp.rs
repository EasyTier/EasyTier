use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use easytier_core::{
    socket::{
        SocketContext,
        dial::{
            BindEndpoint, RemoteEndpoint, SocketAttemptBuilder, SocketDialError, SocketDialRequest,
            SocketKind,
        },
        dns::{DnsQuery, DnsResolveError, global_dns_resolver},
        tcp::{VirtualTcpListener, VirtualTcpSocket},
    },
    tunnel::tcp::TcpTunnelUpgrader,
};
use futures::stream::FuturesUnordered;
use rand::seq::SliceRandom;

use super::{
    IpScheme, IpVersion, Tunnel, TunnelError, TunnelInfo, TunnelListener,
    common::wait_for_connect_futures,
};
use crate::{common::dns::register_core_dns_resolver, tunnel::tcp_socket};

#[derive(Debug)]
pub struct TcpTunnelListener {
    addr: url::Url,
    listener: Option<tcp_socket::RuntimeTcpListener>,
    socket_mark: Option<u32>,
}

impl TcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelListener {
            addr,
            listener: None,
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    async fn do_accept(&self) -> Result<Box<dyn Tunnel>, std::io::Error> {
        let listener = self.listener.as_ref().unwrap();
        let (socket, _) = listener.accept().await?;
        let peer_addr = socket.peer_addr()?;
        let remote_url = super::build_url_from_socket_addr(&peer_addr.to_string(), "tcp");

        let info = TunnelInfo {
            tunnel_type: "tcp".to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(remote_url.clone().into()),
            resolved_remote_addr: Some(remote_url.into()),
        };

        TcpTunnelUpgrader::new(info)
            .upgrade(socket)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))
    }
}

#[async_trait]
impl TunnelListener for TcpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        self.listener = None;

        let addr = resolve_tcp_bind_url_addr(&self.addr, IpVersion::Both, self.socket_mark).await?;
        let context = tcp_socket_context(IpVersion::Both, self.socket_mark);
        let listener = tcp_socket::bind_tcp_listener(addr, &context)?;

        self.addr
            .set_port(Some(listener.local_addr()?.port()))
            .unwrap();
        self.listener = Some(listener);

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        loop {
            match self.do_accept().await {
                Ok(ret) => return Ok(ret),
                Err(e) => {
                    use std::io::ErrorKind::*;
                    if matches!(
                        e.kind(),
                        NotConnected | ConnectionAborted | ConnectionRefused | ConnectionReset
                    ) {
                        tracing::warn!(?e, "accept fail with retryable error: {:?}", e);
                        continue;
                    }
                    tracing::warn!(?e, "accept fail");
                    return Err(e.into());
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

fn tcp_socket_context(ip_version: IpVersion, socket_mark: Option<u32>) -> SocketContext {
    SocketContext {
        ip_version,
        socket_mark,
        netns: None,
    }
}

fn remote_endpoint_from_tcp_url(url: &url::Url) -> Result<RemoteEndpoint, TunnelError> {
    let host = url
        .host_str()
        .ok_or_else(|| TunnelError::InvalidAddr(url.to_string()))?;
    let port = url.port().unwrap_or(IpScheme::Tcp.default_port());
    Ok(match parse_url_host_ip_literal(host) {
        Ok(ip) => RemoteEndpoint::Addr(SocketAddr::new(ip, port)),
        Err(_) => RemoteEndpoint::Domain {
            host: host.to_owned(),
            port,
        },
    })
}

fn parse_url_host_ip_literal(host: &str) -> Result<IpAddr, std::net::AddrParseError> {
    if let Some(host) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        host.parse()
    } else {
        host.parse()
    }
}

async fn resolve_tcp_attempts(
    request: &SocketDialRequest,
) -> Result<Vec<easytier_core::socket::dial::SocketAttempt>, TunnelError> {
    let builder = SocketAttemptBuilder::new();
    match builder
        .resolve_ip_attempts(request, global_dns_resolver())
        .await
    {
        Ok(attempts) => Ok(attempts),
        Err(SocketDialError::Dns(DnsResolveError::NotRegistered)) => {
            register_core_dns_resolver();
            Ok(builder
                .resolve_ip_attempts(request, global_dns_resolver())
                .await
                .map_err(|error| TunnelError::Anyhow(error.into()))?)
        }
        Err(error) => Err(TunnelError::Anyhow(error.into())),
    }
}

fn select_one_remote_attempts(
    attempts: Vec<easytier_core::socket::dial::SocketAttempt>,
) -> Vec<easytier_core::socket::dial::SocketAttempt> {
    let mut remote_addrs = Vec::new();
    for attempt in &attempts {
        if !remote_addrs.contains(&attempt.remote_addr) {
            remote_addrs.push(attempt.remote_addr);
        }
    }
    let remote_addr = remote_addrs.choose(&mut rand::thread_rng()).copied();
    match remote_addr {
        Some(remote_addr) => attempts
            .into_iter()
            .filter(|attempt| attempt.remote_addr == remote_addr)
            .collect(),
        None => attempts,
    }
}

async fn resolve_tcp_domain_addrs(
    host: String,
    port: u16,
    context: SocketContext,
) -> Result<Vec<SocketAddr>, TunnelError> {
    let query = DnsQuery::new(host, context);
    let resolved = match global_dns_resolver().resolve(query.clone()).await {
        Ok(ips) => ips,
        Err(DnsResolveError::NotRegistered) => {
            register_core_dns_resolver();
            global_dns_resolver()
                .resolve(query)
                .await
                .map_err(|error| TunnelError::Anyhow(error.into()))?
        }
        Err(error) => return Err(TunnelError::Anyhow(error.into())),
    };
    Ok(resolved
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

async fn resolve_tcp_bind_url_addr(
    url: &url::Url,
    ip_version: IpVersion,
    socket_mark: Option<u32>,
) -> Result<SocketAddr, TunnelError> {
    let addrs = match remote_endpoint_from_tcp_url(url)? {
        RemoteEndpoint::Addr(addr) => vec![addr],
        RemoteEndpoint::Domain { host, port } => {
            resolve_tcp_domain_addrs(host, port, tcp_socket_context(ip_version, socket_mark))
                .await?
        }
        _ => unreachable!("tcp URL resolves only to IP endpoints"),
    };
    let addrs = addrs
        .into_iter()
        .filter(|addr| match ip_version {
            IpVersion::V4 => addr.is_ipv4(),
            IpVersion::V6 => addr.is_ipv6(),
            IpVersion::Both => true,
        })
        .collect::<Vec<_>>();
    addrs
        .choose(&mut rand::thread_rng())
        .copied()
        .ok_or(TunnelError::NoDnsRecordFound(ip_version))
}

#[derive(Debug)]
pub struct TcpTunnelConnector {
    addr: url::Url,

    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
}

impl TcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelConnector {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
        }
    }

    fn build_dial_request(&self) -> Result<SocketDialRequest, TunnelError> {
        let remote = self
            .resolved_addr
            .map(RemoteEndpoint::Addr)
            .map(Ok)
            .unwrap_or_else(|| remote_endpoint_from_tcp_url(&self.addr))?;
        let binds = self
            .bind_addrs
            .iter()
            .copied()
            .map(BindEndpoint::Addr)
            .collect::<Vec<_>>();
        Ok(SocketDialRequest::new(SocketKind::Tcp, remote)
            .with_context(tcp_socket_context(self.ip_version, self.socket_mark))
            .with_binds(binds))
    }

    async fn connect_attempts(
        &self,
        attempts: Vec<easytier_core::socket::dial::SocketAttempt>,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for attempt in attempts {
            tracing::info!(url = ?self.addr, ?attempt.remote_addr, ?attempt.bind, "connect tcp start");
            futures.push(tcp_socket::connect_tcp_attempt(attempt));
        }

        let socket = wait_for_connect_futures(futures).await?;
        let local_addr = socket.local_addr()?;
        let peer_addr = socket.peer_addr()?;
        tracing::info!(url = ?self.addr, ?peer_addr, "connect tcp succ");
        let info = TunnelInfo {
            tunnel_type: "tcp".to_owned(),
            local_addr: Some(
                super::build_url_from_socket_addr(&local_addr.to_string(), "tcp").into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&peer_addr.to_string(), "tcp").into(),
            ),
        };
        TcpTunnelUpgrader::new(info).upgrade(socket)
    }
}

#[async_trait]
impl super::TunnelConnector for TcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let request = self.build_dial_request()?;
        let attempts = resolve_tcp_attempts(&request).await?;
        let attempts = select_one_remote_attempts(attempts);
        self.connect_attempts(attempts).await
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc};

    use async_trait::async_trait;
    use easytier_core::socket::dns::{DnsQuery, DnsResolver, global_dns_resolver};
    use guarden::defer;

    use crate::tunnel::{
        TunnelConnector,
        common::tests::{_tunnel_bench, _tunnel_pingpong},
    };

    use super::*;

    struct StaticDnsResolver {
        ips: Vec<IpAddr>,
    }

    #[async_trait]
    impl DnsResolver for StaticDnsResolver {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            Ok(self.ips.clone())
        }
    }

    #[tokio::test]
    async fn tcp_pingpong() {
        let listener = TcpTunnelListener::new("tcp://0.0.0.0:31011".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://127.0.0.1:31011".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn tcp_bench() {
        let listener = TcpTunnelListener::new("tcp://0.0.0.0:31012".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://127.0.0.1:31012".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn tcp_bench_with_bind() {
        let listener = TcpTunnelListener::new("tcp://127.0.0.1:11013".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11013".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn tcp_bench_with_bind_fail() {
        let listener = TcpTunnelListener::new("tcp://127.0.0.1:11014".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11014".parse().unwrap());
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn bind_same_port() {
        let mut listener = TcpTunnelListener::new("tcp://[::]:31014".parse().unwrap());
        let mut listener2 = TcpTunnelListener::new("tcp://0.0.0.0:31014".parse().unwrap());
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener = TcpTunnelListener::new("tcp://[::1]:31015".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://[::1]:31015".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let previous = global_dns_resolver().register(Arc::new(StaticDnsResolver {
            ips: vec![
                IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
                IpAddr::from([127, 0, 0, 1]),
            ],
        }));
        defer!({
            if let Some(previous) = previous {
                global_dns_resolver().register(previous);
            } else {
                global_dns_resolver().unregister();
            }
        });

        let mut listener = TcpTunnelListener::new("tcp://[::1]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        let connector_url: url::Url = format!("tcp://tcp-test.easytier.invalid:{port}")
            .parse()
            .unwrap();
        let mut connector = TcpTunnelConnector::new(connector_url);
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        let connector_url: url::Url = format!("tcp://tcp-test.easytier.invalid:{port}")
            .parse()
            .unwrap();
        let mut connector = TcpTunnelConnector::new(connector_url);
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn connector_keeps_source_addr_and_reports_resolved_addr() {
        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();

        let port = listener.local_url().port().unwrap();
        let source_url: url::Url = format!("tcp://localhost:{port}").parse().unwrap();
        let mut connector = TcpTunnelConnector::new(source_url.clone());
        connector.set_ip_version(IpVersion::V4);

        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
        let tunnel = connector.connect().await.unwrap();
        let accepted_tunnel = accept_task.await.unwrap();

        let info = tunnel.info().unwrap();
        assert_eq!(info.remote_addr.unwrap().url, source_url.to_string());

        let resolved_remote_addr: url::Url = info.resolved_remote_addr.unwrap().into();
        assert_eq!(resolved_remote_addr.host_str(), Some("127.0.0.1"));
        assert_eq!(resolved_remote_addr.port(), Some(port));

        let accepted_info = accepted_tunnel.info().unwrap();
        assert_eq!(
            accepted_info.remote_addr,
            accepted_info.resolved_remote_addr,
        );
    }

    #[tokio::test]
    async fn connector_uses_pre_resolved_addr_without_resolving_url() {
        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();

        let port = listener.local_url().port().unwrap();
        let source_url: url::Url = format!("tcp://unresolvable.invalid:{port}")
            .parse()
            .unwrap();
        let resolved_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut connector = TcpTunnelConnector::new(source_url.clone());
        connector.set_resolved_addr(resolved_addr);

        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap() });
        let tunnel = connector.connect().await.unwrap();
        let _accepted_tunnel = accept_task.await.unwrap();

        let info = tunnel.info().unwrap();
        assert_eq!(info.remote_addr.unwrap().url, source_url.to_string());

        let resolved_remote_addr: url::Url = info.resolved_remote_addr.unwrap().into();
        assert_eq!(resolved_remote_addr.host_str(), Some("127.0.0.1"));
        assert_eq!(resolved_remote_addr.port(), Some(port));
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener = TcpTunnelListener::new("tcp://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = TcpTunnelListener::new("tcp://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}
