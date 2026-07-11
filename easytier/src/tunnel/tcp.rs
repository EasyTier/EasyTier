use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use easytier_core::{
    socket::{
        SocketContext,
        dns::{DnsQuery, DnsResolveError, global_dns_resolver},
        tcp::{
            TcpBindOptions, TcpConnectOptions, TcpListenOptions, VirtualTcpListener,
            VirtualTcpSocket,
        },
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcpUrlEndpoint {
    Addr(SocketAddr),
    Domain { host: String, port: u16 },
}

#[derive(Debug, Clone)]
struct TcpConnectCandidate {
    options: TcpConnectOptions,
}

impl TcpConnectCandidate {
    fn new(remote_addr: SocketAddr, bind: TcpBindOptions) -> Self {
        Self {
            options: TcpConnectOptions::direct_connect(remote_addr).with_bind(bind),
        }
    }
}

#[derive(Debug)]
struct TcpSingleSocketConnector {
    options: TcpConnectOptions,
}

impl TcpSingleSocketConnector {
    fn new(options: TcpConnectOptions) -> Self {
        Self { options }
    }

    async fn connect(self) -> Result<tcp_socket::RuntimeTcpSocket, TunnelError> {
        tcp_socket::connect_tcp(self.options).await
    }
}

#[derive(Debug)]
struct TcpCandidateDialer {
    original_url: url::Url,
    candidates: Vec<TcpConnectCandidate>,
}

impl TcpCandidateDialer {
    fn new(original_url: url::Url, candidates: Vec<TcpConnectCandidate>) -> Self {
        Self {
            original_url,
            candidates,
        }
    }

    async fn connect(self) -> Result<tcp_socket::RuntimeTcpSocket, TunnelError> {
        let futures = FuturesUnordered::new();

        for candidate in self.candidates {
            let remote_addr = candidate.options.remote_addr;
            let bind = candidate.options.bind.clone();
            tracing::info!(
                url = ?self.original_url,
                ?remote_addr,
                ?bind,
                "connect tcp start"
            );
            futures.push(TcpSingleSocketConnector::new(candidate.options).connect());
        }

        wait_for_connect_futures(futures).await
    }
}

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
        let bind = TcpBindOptions::default()
            .with_local_addr(Some(addr))
            .with_socket_mark(self.socket_mark)
            .with_only_v6(true);
        let listener =
            tcp_socket::bind_tcp_listener(TcpListenOptions::direct_connect(addr).with_bind(bind))?;

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

fn remote_endpoint_from_tcp_url(url: &url::Url) -> Result<TcpUrlEndpoint, TunnelError> {
    let host = url
        .host_str()
        .ok_or_else(|| TunnelError::InvalidAddr(url.to_string()))?;
    let scheme = url
        .scheme()
        .parse::<IpScheme>()
        .map_err(|_| TunnelError::InvalidProtocol(url.scheme().to_owned()))?;
    let port = url.port().unwrap_or(scheme.default_port());
    Ok(match parse_url_host_ip_literal(host) {
        Ok(ip) => TcpUrlEndpoint::Addr(SocketAddr::new(ip, port)),
        Err(_) => TcpUrlEndpoint::Domain {
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

fn addr_matches_ip_version(addr: SocketAddr, ip_version: IpVersion) -> bool {
    match ip_version {
        IpVersion::V4 => addr.is_ipv4(),
        IpVersion::V6 => addr.is_ipv6(),
        IpVersion::Both => true,
    }
}

fn dedup_addrs(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut deduped = Vec::new();
    for addr in addrs {
        if !deduped.contains(&addr) {
            deduped.push(addr);
        }
    }
    deduped
}

async fn resolve_tcp_remote_addrs(
    endpoint: TcpUrlEndpoint,
    ip_version: IpVersion,
    socket_mark: Option<u32>,
) -> Result<Vec<SocketAddr>, TunnelError> {
    let addrs = match endpoint {
        TcpUrlEndpoint::Addr(addr) => vec![addr],
        TcpUrlEndpoint::Domain { host, port } => {
            resolve_tcp_domain_addrs(host, port, tcp_socket_context(ip_version, socket_mark))
                .await?
        }
    };
    let addrs = dedup_addrs(
        addrs
            .into_iter()
            .filter(|addr| addr_matches_ip_version(*addr, ip_version)),
    );
    if addrs.is_empty() {
        return Err(TunnelError::NoDnsRecordFound(ip_version));
    }
    Ok(addrs)
}

fn select_one_remote_addr(
    remote_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
) -> Result<SocketAddr, TunnelError> {
    remote_addrs
        .choose(&mut rand::thread_rng())
        .copied()
        .ok_or(TunnelError::NoDnsRecordFound(ip_version))
}

fn bind_addr_matches_remote(bind_addr: SocketAddr, remote_addr: SocketAddr) -> bool {
    bind_addr.is_ipv4() == remote_addr.is_ipv4()
}

pub(crate) async fn resolve_tcp_bind_url_addr(
    url: &url::Url,
    ip_version: IpVersion,
    socket_mark: Option<u32>,
) -> Result<SocketAddr, TunnelError> {
    let addrs = match remote_endpoint_from_tcp_url(url)? {
        TcpUrlEndpoint::Addr(addr) => vec![addr],
        TcpUrlEndpoint::Domain { host, port } => {
            resolve_tcp_domain_addrs(host, port, tcp_socket_context(ip_version, socket_mark))
                .await?
        }
    };
    let addrs = addrs
        .into_iter()
        .filter(|addr| addr_matches_ip_version(*addr, ip_version))
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

    async fn resolve_remote_addrs(&self) -> Result<Vec<SocketAddr>, TunnelError> {
        let endpoint = self
            .resolved_addr
            .map(TcpUrlEndpoint::Addr)
            .map(Ok)
            .unwrap_or_else(|| remote_endpoint_from_tcp_url(&self.addr))?;
        resolve_tcp_remote_addrs(endpoint, self.ip_version, self.socket_mark).await
    }

    fn selectable_remote_addrs(&self, remote_addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        if self.bind_addrs.is_empty() {
            return remote_addrs;
        }

        remote_addrs
            .into_iter()
            .filter(|remote_addr| {
                self.bind_addrs
                    .iter()
                    .copied()
                    .any(|bind_addr| bind_addr_matches_remote(bind_addr, *remote_addr))
            })
            .collect()
    }

    fn build_candidates(&self, remote_addr: SocketAddr) -> Vec<TcpConnectCandidate> {
        if self.bind_addrs.is_empty() {
            return vec![TcpConnectCandidate::new(
                remote_addr,
                TcpBindOptions::default().with_socket_mark(self.socket_mark),
            )];
        }

        self.bind_addrs
            .iter()
            .copied()
            .filter(|bind_addr| bind_addr_matches_remote(*bind_addr, remote_addr))
            .map(|bind_addr| {
                TcpConnectCandidate::new(
                    remote_addr,
                    TcpBindOptions::default()
                        .with_local_addr(Some(bind_addr))
                        .with_socket_mark(self.socket_mark)
                        .with_only_v6(true),
                )
            })
            .collect()
    }

    async fn build_dialer(&self) -> Result<TcpCandidateDialer, TunnelError> {
        let remote_addrs = self.resolve_remote_addrs().await?;
        let remote_addrs = self.selectable_remote_addrs(remote_addrs);
        let remote_addr = select_one_remote_addr(remote_addrs, self.ip_version)?;
        Ok(TcpCandidateDialer::new(
            self.addr.clone(),
            self.build_candidates(remote_addr),
        ))
    }

    fn upgrade_socket(
        &self,
        socket: tcp_socket::RuntimeTcpSocket,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
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
        let dialer = self.build_dialer().await?;
        let socket = dialer.connect().await?;
        self.upgrade_socket(socket)
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
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

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

    #[test]
    fn connector_filters_bind_candidates_by_remote_family() {
        let remote_v4: SocketAddr = "127.0.0.1:11013".parse().unwrap();
        let remote_v6: SocketAddr = "[::1]:11013".parse().unwrap();
        let bind_v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut connector = TcpTunnelConnector::new("tcp://example.com:11013".parse().unwrap());
        connector.set_bind_addrs(vec![bind_v4]);

        assert_eq!(
            connector.selectable_remote_addrs(vec![remote_v6, remote_v4]),
            vec![remote_v4]
        );
        assert!(connector.build_candidates(remote_v6).is_empty());

        let candidates = connector.build_candidates(remote_v4);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].options.remote_addr, remote_v4);
        assert_eq!(candidates[0].options.bind.local_addr, Some(bind_v4));
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn tcp_url_endpoint_uses_protocol_default_port() {
        for (url, expected_port) in [
            ("tcp://127.0.0.1", 11010),
            ("ws://127.0.0.1", 80),
            ("wss://127.0.0.1", 443),
        ] {
            assert_eq!(
                remote_endpoint_from_tcp_url(&url.parse().unwrap()).unwrap(),
                TcpUrlEndpoint::Addr(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    expected_port
                ))
            );
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
