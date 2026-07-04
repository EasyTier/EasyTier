use std::{net::SocketAddr, path::PathBuf};

use async_trait::async_trait;

use crate::{
    socket::dns::{DnsQuery, DnsResolveError, DnsResolverRegistry},
    socket::{IpVersion, SocketContext},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Tcp,
    Udp,
    FakeTcp,
    Unix,
    Ring,
}

impl SocketKind {
    pub fn is_ip_socket(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp | Self::FakeTcp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEndpoint {
    Domain { host: String, port: u16 },
    Addr(SocketAddr),
    Ring(uuid::Uuid),
    UnixPath(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindEndpoint {
    Default,
    Addr(SocketAddr),
    Device(String),
    AddrOnDevice { addr: SocketAddr, device: String },
}

impl BindEndpoint {
    fn addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Default | Self::Device(_) => None,
            Self::Addr(addr) | Self::AddrOnDevice { addr, .. } => Some(*addr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketDialRequest {
    pub socket_kind: SocketKind,
    pub remote: RemoteEndpoint,
    pub binds: Vec<BindEndpoint>,
    pub context: SocketContext,
}

impl SocketDialRequest {
    pub fn new(socket_kind: SocketKind, remote: RemoteEndpoint) -> Self {
        Self {
            socket_kind,
            remote,
            binds: Vec::new(),
            context: SocketContext::default(),
        }
    }

    pub fn with_binds(mut self, binds: Vec<BindEndpoint>) -> Self {
        self.binds = binds;
        self
    }

    pub fn with_context(mut self, context: SocketContext) -> Self {
        self.context = context;
        self
    }
}

#[async_trait]
pub trait SocketConnector: Send {
    type ConnectedSocket: Send + 'static;

    async fn connect(
        &mut self,
        request: SocketDialRequest,
    ) -> anyhow::Result<Self::ConnectedSocket>;
}

impl RemoteEndpoint {
    fn is_ip_endpoint(&self) -> bool {
        matches!(self, Self::Domain { .. } | Self::Addr(_))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SocketAttemptBuilder;

impl SocketAttemptBuilder {
    pub fn new() -> Self {
        Self
    }

    pub async fn resolve_ip_attempts(
        &self,
        request: &SocketDialRequest,
        dns_resolver: &DnsResolverRegistry,
    ) -> Result<Vec<SocketAttempt>, SocketDialError> {
        if !request.socket_kind.is_ip_socket() {
            return Err(SocketDialError::NonIpSocketKind(request.socket_kind));
        }

        let remote_addrs = match &request.remote {
            RemoteEndpoint::Addr(addr) => vec![*addr],
            RemoteEndpoint::Domain { host, port } => dns_resolver
                .resolve(DnsQuery::new(host.clone(), request.context.clone()))
                .await?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, *port))
                .collect(),
            remote => return Err(SocketDialError::NonIpRemoteEndpoint(remote.clone())),
        };

        let attempts = self.expand_ip_attempts(request, remote_addrs)?;
        if attempts.is_empty() {
            return Err(SocketDialError::NoAttempts(request.clone()));
        }

        Ok(attempts)
    }

    pub fn expand_ip_attempts<I>(
        &self,
        request: &SocketDialRequest,
        remote_addrs: I,
    ) -> Result<Vec<SocketAttempt>, SocketDialError>
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        if !request.socket_kind.is_ip_socket() {
            return Err(SocketDialError::NonIpSocketKind(request.socket_kind));
        }
        if !request.remote.is_ip_endpoint() {
            return Err(SocketDialError::NonIpRemoteEndpoint(request.remote.clone()));
        }

        let remote_addrs = remote_addrs
            .into_iter()
            .filter(|addr| addr_matches_ip_version(*addr, request.context.ip_version))
            .collect::<Vec<_>>();
        let binds = effective_binds(request);
        let mut attempts = Vec::new();

        for bind in binds {
            for remote_addr in remote_addrs.iter().copied() {
                if bind_matches_remote(&bind, remote_addr) {
                    attempts.push(SocketAttempt {
                        socket_kind: request.socket_kind,
                        remote_addr,
                        bind: bind.clone(),
                        context: request.context.clone(),
                    });
                }
            }
        }

        if attempts.is_empty() {
            return Err(SocketDialError::NoAttempts(request.clone()));
        }

        Ok(attempts)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAttempt {
    pub socket_kind: SocketKind,
    pub remote_addr: SocketAddr,
    pub bind: BindEndpoint,
    pub context: SocketContext,
}

#[derive(Debug, thiserror::Error)]
pub enum SocketDialError {
    #[error("socket kind is not address based: {0:?}")]
    NonIpSocketKind(SocketKind),
    #[error("remote endpoint is not address based: {0:?}")]
    NonIpRemoteEndpoint(RemoteEndpoint),
    #[error("no socket attempts for request: {0:?}")]
    NoAttempts(SocketDialRequest),
    #[error(transparent)]
    Dns(#[from] DnsResolveError),
}

pub fn addr_matches_ip_version(addr: SocketAddr, ip_version: IpVersion) -> bool {
    match ip_version {
        IpVersion::V4 => addr.is_ipv4(),
        IpVersion::V6 => addr.is_ipv6(),
        IpVersion::Both => true,
    }
}

fn bind_matches_remote(bind: &BindEndpoint, remote_addr: SocketAddr) -> bool {
    bind.addr()
        .is_none_or(|bind_addr| bind_addr.is_ipv4() == remote_addr.is_ipv4())
}

fn effective_binds(request: &SocketDialRequest) -> Vec<BindEndpoint> {
    if request.binds.is_empty() {
        vec![BindEndpoint::Default]
    } else {
        request.binds.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc};

    use async_trait::async_trait;

    use crate::socket::{
        NetNamespace,
        dns::{DnsQuery, DnsResolver},
    };

    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))
    }

    struct StaticDnsResolver {
        ips: Vec<IpAddr>,
        queries: Arc<std::sync::Mutex<Vec<DnsQuery>>>,
    }

    #[async_trait]
    impl DnsResolver for StaticDnsResolver {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            self.queries.lock().unwrap().push(query);
            Ok(self.ips.clone())
        }
    }

    #[test]
    fn empty_binds_expand_to_default_bind() {
        let request = SocketDialRequest::new(SocketKind::Tcp, RemoteEndpoint::Addr(v4(11010)));

        let attempts = SocketAttemptBuilder::new()
            .expand_ip_attempts(&request, [v4(11010)])
            .unwrap();

        assert_eq!(
            attempts,
            vec![SocketAttempt {
                socket_kind: SocketKind::Tcp,
                remote_addr: v4(11010),
                bind: BindEndpoint::Default,
                context: SocketContext::default(),
            }]
        );
    }

    #[test]
    fn bind_candidates_expand_against_each_remote_addr() {
        let request = SocketDialRequest::new(
            SocketKind::Udp,
            RemoteEndpoint::Domain {
                host: "example.com".to_owned(),
                port: 11010,
            },
        )
        .with_binds(vec![
            BindEndpoint::Addr(SocketAddr::from(([0, 0, 0, 0], 0))),
            BindEndpoint::Device("eth0".to_owned()),
        ]);

        let attempts = SocketAttemptBuilder::new()
            .expand_ip_attempts(&request, [v4(11010), v4(11011)])
            .unwrap();

        assert_eq!(attempts.len(), 4);
        assert_eq!(
            attempts[0].bind,
            BindEndpoint::Addr(SocketAddr::from(([0, 0, 0, 0], 0)))
        );
        assert_eq!(attempts[0].remote_addr, v4(11010));
        assert_eq!(attempts[3].bind, BindEndpoint::Device("eth0".to_owned()));
        assert_eq!(attempts[3].remote_addr, v4(11011));
    }

    #[test]
    fn bind_addr_must_match_remote_addr_family() {
        let request = SocketDialRequest::new(SocketKind::Tcp, RemoteEndpoint::Addr(v4(11010)))
            .with_binds(vec![
                BindEndpoint::Addr(SocketAddr::from(([0, 0, 0, 0], 0))),
                BindEndpoint::Addr(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))),
            ]);

        let attempts = SocketAttemptBuilder::new()
            .expand_ip_attempts(&request, [v4(11010), v6(11010)])
            .unwrap();

        assert_eq!(attempts.len(), 2);
        assert_eq!(
            attempts[0].bind,
            BindEndpoint::Addr(SocketAddr::from(([0, 0, 0, 0], 0)))
        );
        assert_eq!(attempts[0].remote_addr, v4(11010));
        assert_eq!(
            attempts[1].bind,
            BindEndpoint::Addr(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)))
        );
        assert_eq!(attempts[1].remote_addr, v6(11010));
    }

    #[test]
    fn ip_version_filters_remote_candidates() {
        let request = SocketDialRequest::new(SocketKind::Tcp, RemoteEndpoint::Addr(v4(11010)))
            .with_context(SocketContext {
                ip_version: IpVersion::V4,
                ..SocketContext::default()
            });

        let attempts = SocketAttemptBuilder::new()
            .expand_ip_attempts(&request, [v4(11010), v6(11010)])
            .unwrap();

        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].remote_addr, v4(11010));
    }

    #[test]
    fn expand_ip_attempts_reports_no_attempts_after_filtering() {
        let request = SocketDialRequest::new(SocketKind::Tcp, RemoteEndpoint::Addr(v4(11010)))
            .with_context(SocketContext {
                ip_version: IpVersion::V6,
                ..SocketContext::default()
            });

        let error = SocketAttemptBuilder::new()
            .expand_ip_attempts(&request, [v4(11010)])
            .unwrap_err();

        assert!(matches!(error, SocketDialError::NoAttempts(_)));
    }

    #[tokio::test]
    async fn domain_resolution_uses_dns_hook_before_attempt_expansion() {
        let registry = DnsResolverRegistry::new();
        let queries = Arc::new(std::sync::Mutex::new(Vec::new()));
        registry.register(Arc::new(StaticDnsResolver {
            ips: vec![IpAddr::from([127, 0, 0, 1]), IpAddr::from([127, 0, 0, 2])],
            queries: queries.clone(),
        }));
        let context = SocketContext {
            ip_version: IpVersion::V4,
            socket_mark: Some(7),
            netns: Some(NetNamespace::new("underlay")),
        };
        let request = SocketDialRequest::new(
            SocketKind::Tcp,
            RemoteEndpoint::Domain {
                host: "example.com".to_owned(),
                port: 11010,
            },
        )
        .with_context(context.clone())
        .with_binds(vec![
            BindEndpoint::Addr(SocketAddr::from(([0, 0, 0, 0], 0))),
            BindEndpoint::Device("eth0".to_owned()),
        ]);

        let attempts = SocketAttemptBuilder::new()
            .resolve_ip_attempts(&request, &registry)
            .await
            .unwrap();

        assert_eq!(attempts.len(), 4);
        assert_eq!(attempts[0].remote_addr, v4(11010));
        assert_eq!(
            attempts[3].remote_addr,
            SocketAddr::from(([127, 0, 0, 2], 11010))
        );
        assert_eq!(queries.lock().unwrap()[0].context, context);
    }

    #[tokio::test]
    async fn non_ip_socket_kind_does_not_resolve_ip_attempts() {
        let registry = DnsResolverRegistry::new();
        let request =
            SocketDialRequest::new(SocketKind::Ring, RemoteEndpoint::Ring(uuid::Uuid::new_v4()));

        let error = SocketAttemptBuilder::new()
            .resolve_ip_attempts(&request, &registry)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            SocketDialError::NonIpSocketKind(SocketKind::Ring)
        ));
    }
}
