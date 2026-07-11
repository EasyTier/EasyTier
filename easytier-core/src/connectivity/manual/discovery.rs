use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::Context as _;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, header};
use hyper_util::rt::TokioIo;
use rand::{Rng as _, seq::SliceRandom};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::{
    connectivity::transport,
    socket::{
        IpVersion, SocketContext,
        dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
        tcp::{TcpBindOptions, TcpSocketPurpose, VirtualTcpSocketFactory},
    },
};

use super::resolve_url_addrs;

const HTTP_DEFAULT_PORT: u16 = 80;
const HTTPS_DEFAULT_PORT: u16 = 443;

#[derive(Debug, Clone)]
pub struct HttpDiscoveryRequest {
    pub url: Url,
    pub user_agent: String,
    pub network_name: String,
    pub timeout: Duration,
    pub ip_version: IpVersion,
    pub tcp_bind: TcpBindOptions,
}

pub async fn fetch_http_discovery<H>(
    host: Arc<H>,
    dns: &dyn DnsResolver,
    request: HttpDiscoveryRequest,
) -> anyhow::Result<HttpDiscoveryResponse>
where
    H: VirtualTcpSocketFactory,
{
    let timeout = request.timeout;
    tokio::time::timeout(timeout, fetch_http_discovery_inner(host, dns, request))
        .await
        .map_err(|_| anyhow::anyhow!("HTTP discovery timed out after {timeout:?}"))?
}

async fn fetch_http_discovery_inner<H>(
    host: Arc<H>,
    dns: &dyn DnsResolver,
    request: HttpDiscoveryRequest,
) -> anyhow::Result<HttpDiscoveryResponse>
where
    H: VirtualTcpSocketFactory,
{
    let default_port = match request.url.scheme() {
        "http" => HTTP_DEFAULT_PORT,
        "https" => HTTPS_DEFAULT_PORT,
        scheme => anyhow::bail!("unsupported HTTP discovery scheme: {scheme}"),
    };
    let addrs = resolve_url_addrs(
        &request.url,
        default_port,
        request.ip_version,
        request.tcp_bind.socket_mark,
        dns,
    )
    .await?;

    let mut last_error = None;
    let mut socket = None;
    for addr in addrs {
        match transport::connect_tcp(
            host.clone(),
            addr,
            Vec::new(),
            request.tcp_bind.clone(),
            TcpSocketPurpose::ManualConnect,
        )
        .await
        {
            Ok(connected) => {
                socket = Some(connected);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let socket = socket.ok_or_else(|| {
        last_error.unwrap_or_else(|| anyhow::anyhow!("no HTTP discovery address candidates"))
    })?;

    if request.url.scheme() == "https" {
        let server_name = request
            .url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("HTTP discovery URL has no host: {}", request.url))?
            .to_owned();
        let server_name = ServerName::try_from(server_name)
            .with_context(|| format!("invalid HTTPS server name in {}", request.url))?;
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let stream = TlsConnector::from(Arc::new(tls_config))
            .connect(server_name, socket)
            .await
            .with_context(|| format!("HTTPS handshake failed for {}", request.url))?;
        send_http_discovery_request(stream, request).await
    } else {
        send_http_discovery_request(socket, request).await
    }
}

async fn send_http_discovery_request<S>(
    stream: S,
    request: HttpDiscoveryRequest,
) -> anyhow::Result<HttpDiscoveryResponse>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .with_context(|| format!("starting HTTP connection failed for {}", request.url))?;
    let connection_task = AbortOnDropHandle::new(tokio::spawn(connection));

    let request_target = match request.url.query() {
        Some(query) => format!("{}?{query}", request.url.path()),
        None => request.url.path().to_owned(),
    };
    let host_header = &request.url[url::Position::BeforeHost..url::Position::AfterPort];
    let outgoing = Request::builder()
        .method("GET")
        .uri(request_target)
        .header(header::HOST, host_header)
        .header(header::USER_AGENT, request.user_agent)
        .header("X-Network-Name", request.network_name)
        .header(header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())?;
    let response = sender
        .send_request(outgoing)
        .await
        .with_context(|| format!("sending HTTP request failed for {}", request.url))?;
    let status_code = response.status().as_u16();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
    let body = response
        .into_body()
        .collect()
        .await
        .with_context(|| format!("reading HTTP response failed for {}", request.url))?
        .to_bytes();
    drop(sender);
    connection_task
        .await
        .context("HTTP connection task failed")?
        .with_context(|| format!("HTTP connection failed for {}", request.url))?;

    Ok(HttpDiscoveryResponse {
        status_code,
        location,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpEndpointSource {
    RedirectQuery,
    RedirectUrl,
    ResponseBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpDiscoveryResponse {
    pub status_code: u16,
    pub location: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHttpEndpoint {
    pub url: Url,
    pub source: HttpEndpointSource,
}

fn resolve_http_redirect(location: &str) -> anyhow::Result<ResolvedHttpEndpoint> {
    let url = Url::parse(location)
        .with_context(|| format!("parsing redirect URL failed. url: {location}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Ok(ResolvedHttpEndpoint {
            url,
            source: HttpEndpointSource::RedirectUrl,
        });
    }

    let candidates = url
        .query_pairs()
        .filter_map(|(_, value)| Url::parse(&value).ok())
        .collect::<Vec<_>>();
    if let Some(url) = candidates.choose(&mut rand::thread_rng()).cloned() {
        return Ok(ResolvedHttpEndpoint {
            url,
            source: HttpEndpointSource::RedirectQuery,
        });
    }

    if let Some(url) = location
        .strip_prefix(&format!("{}://", url.scheme()))
        .and_then(|value| Url::parse(value).ok())
    {
        return Ok(ResolvedHttpEndpoint {
            url,
            source: HttpEndpointSource::RedirectUrl,
        });
    }

    anyhow::bail!("no valid connector URL found in redirect location {location:?}")
}

fn resolve_http_body(body: &str) -> anyhow::Result<ResolvedHttpEndpoint> {
    let mut candidates = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    candidates.shuffle(&mut rand::thread_rng());
    for candidate in candidates {
        if let Ok(url) = Url::parse(candidate) {
            return Ok(ResolvedHttpEndpoint {
                url,
                source: HttpEndpointSource::ResponseBody,
            });
        }
    }
    anyhow::bail!("no valid connector URL found in response body {body:?}")
}

pub fn resolve_http_endpoint(
    response: HttpDiscoveryResponse,
) -> anyhow::Result<ResolvedHttpEndpoint> {
    match response.status_code {
        300..=399 => resolve_http_redirect(
            response
                .location
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("HTTP redirect has no Location header"))?,
        ),
        200..=299 => resolve_http_body(&response.body),
        status_code => anyhow::bail!(
            "unexpected HTTP discovery status {status_code}, body: {:?}",
            response.body
        ),
    }
}

fn choose_weighted<T>(options: &[(T, u64)]) -> Option<&T> {
    let total_weight = options.iter().map(|(_, weight)| *weight).sum();
    let mut rng = rand::thread_rng();
    let selected = rng.gen_range(0..total_weight);
    let mut accumulated = 0;

    for (item, weight) in options {
        accumulated += *weight;
        if selected < accumulated {
            return Some(item);
        }
    }
    None
}

pub async fn resolve_txt_endpoint(
    resolver: &dyn DnsRecordResolver,
    domain_name: &str,
    context: SocketContext,
) -> anyhow::Result<Url> {
    let txt_data = resolver
        .resolve_txt(DnsQuery::new(domain_name, context))
        .await
        .with_context(|| format!("resolve TXT record failed for {domain_name}"))?;
    let candidates = txt_data
        .split(' ')
        .filter_map(|candidate| Url::parse(candidate).ok())
        .collect::<Vec<_>>();
    candidates
        .choose(&mut rand::thread_rng())
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no valid URL found in TXT data {txt_data:?}; expected a space-separated URL list"
            )
        })
}

fn srv_record_url(protocol: &str, record: DnsSrvRecord) -> anyhow::Result<(Url, u64)> {
    if record.port == 0 {
        anyhow::bail!("SRV port must be non-zero");
    }
    let url = format!("{protocol}://{}:{}", record.target, record.port);
    // Preserve the existing EasyTier selection rule, which treats SRV priority
    // as the candidate weight.
    Ok((Url::parse(&url)?, u64::from(record.priority)))
}

fn deduplicate_srv_candidates(candidates: Vec<(Url, u64)>) -> Vec<(Url, u64)> {
    candidates
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

pub async fn resolve_srv_endpoint(
    resolver: &dyn DnsRecordResolver,
    domain_name: &str,
    supported_protocols: &[String],
    context: SocketContext,
) -> anyhow::Result<Url> {
    let lookups = supported_protocols.iter().map(|protocol| {
        let protocol = protocol.clone();
        let query = DnsQuery::new(
            format!("_easytier._{protocol}.{domain_name}"),
            context.clone(),
        );
        async move { (protocol, resolver.resolve_srv(query).await) }
    });

    let mut candidates = Vec::new();
    for (protocol, result) in futures::future::join_all(lookups).await {
        let Ok(records) = result else {
            continue;
        };
        candidates.extend(records.into_iter().filter_map(|record| {
            match srv_record_url(&protocol, record) {
                Ok(candidate) => Some(candidate),
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        srv_domain = %format!("_easytier._{protocol}.{domain_name}"),
                        "ignore invalid SRV endpoint record"
                    );
                    None
                }
            }
        }));
    }
    if candidates.is_empty() {
        anyhow::bail!("no SRV endpoint found for {domain_name}");
    }
    let candidates = deduplicate_srv_candidates(candidates);

    choose_weighted(&candidates)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("failed to choose an SRV endpoint for {domain_name}"))
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
    };

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, ReadBuf};

    use crate::socket::tcp::{TcpConnectOptions, VirtualTcpSocket, VirtualTcpSocketFactory};

    use super::*;

    struct HttpTestSocket {
        stream: DuplexStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    }

    impl AsyncRead for HttpTestSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for HttpTestSocket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    impl VirtualTcpSocket for HttpTestSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }
    }

    struct HttpTestHost {
        stream: Mutex<Option<DuplexStream>>,
        connects: Mutex<Vec<TcpConnectOptions>>,
    }

    #[async_trait]
    impl VirtualTcpSocketFactory for HttpTestHost {
        type Socket = HttpTestSocket;

        async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
            self.connects.lock().unwrap().push(options.clone());
            let stream = self
                .stream
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| anyhow::anyhow!("test socket already connected"))?;
            Ok(HttpTestSocket {
                stream,
                local_addr: "192.0.2.2:40000".parse().unwrap(),
                peer_addr: options.remote_addr,
            })
        }
    }

    struct HttpTestDns {
        queries: Mutex<Vec<DnsQuery>>,
    }

    #[async_trait]
    impl DnsResolver for HttpTestDns {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            self.queries.lock().unwrap().push(query);
            Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))])
        }
    }

    #[tokio::test]
    async fn http_fetch_uses_host_dns_and_socket_while_core_drives_io() {
        let (client, mut server) = tokio::io::duplex(8192);
        let host = Arc::new(HttpTestHost {
            stream: Mutex::new(Some(client)),
            connects: Mutex::new(Vec::new()),
        });
        let dns = HttpTestDns {
            queries: Mutex::new(Vec::new()),
        };
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let len = server.read(&mut chunk).await.unwrap();
                assert_ne!(len, 0, "HTTP request ended before its headers");
                request.extend_from_slice(&chunk[..len]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("get /lookup?kind=peer http/1.1\r\n"));
            assert!(request.contains("host: discovery.example:18080\r\n"));
            assert!(request.contains("user-agent: easytier/test\r\n"));
            assert!(request.contains("x-network-name: test-network\r\n"));
            assert!(request.contains("connection: close\r\n"));

            server
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: tcp://192.0.2.10:11010\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let response = fetch_http_discovery(
            host.clone(),
            &dns,
            HttpDiscoveryRequest {
                url: "http://discovery.example:18080/lookup?kind=peer"
                    .parse()
                    .unwrap(),
                user_agent: "easytier/test".to_owned(),
                network_name: "test-network".to_owned(),
                timeout: Duration::from_secs(1),
                ip_version: IpVersion::V4,
                tcp_bind: TcpBindOptions::default().with_socket_mark(Some(9)),
            },
        )
        .await
        .unwrap();
        server_task.await.unwrap();

        assert_eq!(response.status_code, 302);
        assert_eq!(response.location.as_deref(), Some("tcp://192.0.2.10:11010"));
        assert_eq!(response.body, "hello");
        assert_eq!(
            *dns.queries.lock().unwrap(),
            [DnsQuery::new(
                "discovery.example",
                SocketContext {
                    ip_version: IpVersion::V4,
                    socket_mark: Some(9),
                    netns: None,
                }
            )]
        );
        assert_eq!(host.connects.lock().unwrap().len(), 1);
        let options = &host.connects.lock().unwrap()[0];
        assert_eq!(options.remote_addr, "192.0.2.1:18080".parse().unwrap());
        assert_eq!(options.purpose, TcpSocketPurpose::ManualConnect);
        assert_eq!(options.bind.socket_mark, Some(9));
    }

    #[test]
    fn http_discovery_interprets_redirect_and_body_forms() {
        let query = resolve_http_endpoint(HttpDiscoveryResponse {
            status_code: 302,
            location: Some("https://discovery.example/?url=tcp://127.0.0.1:11010".to_owned()),
            body: String::new(),
        })
        .unwrap();
        assert_eq!(query.url.as_str(), "tcp://127.0.0.1:11010");
        assert_eq!(query.source, HttpEndpointSource::RedirectQuery);

        let nested = resolve_http_endpoint(HttpDiscoveryResponse {
            status_code: 302,
            location: Some("https://udp://127.0.0.1:11010".to_owned()),
            body: String::new(),
        })
        .unwrap();
        assert_eq!(nested.url.as_str(), "udp://127.0.0.1:11010");
        assert_eq!(nested.source, HttpEndpointSource::RedirectUrl);

        let direct = resolve_http_endpoint(HttpDiscoveryResponse {
            status_code: 307,
            location: Some("quic://127.0.0.1:11012".to_owned()),
            body: String::new(),
        })
        .unwrap();
        assert_eq!(direct.url.as_str(), "quic://127.0.0.1:11012");
        assert_eq!(direct.source, HttpEndpointSource::RedirectUrl);

        let body = resolve_http_endpoint(HttpDiscoveryResponse {
            status_code: 200,
            location: None,
            body: "invalid\nwg://127.0.0.1:11011\n".to_owned(),
        })
        .unwrap();
        assert_eq!(body.url.as_str(), "wg://127.0.0.1:11011");
        assert_eq!(body.source, HttpEndpointSource::ResponseBody);
    }

    #[test]
    fn http_discovery_reports_malformed_redirect_location() {
        let error = resolve_http_endpoint(HttpDiscoveryResponse {
            status_code: 302,
            location: Some("not a URL".to_owned()),
            body: String::new(),
        })
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("parsing redirect URL failed"));
        assert!(message.contains("not a URL"));
    }

    struct TestResolver {
        txt: String,
        srv: Vec<DnsSrvRecord>,
        queries: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsRecordResolver for TestResolver {
        async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
            self.queries.lock().unwrap().push(query.host);
            Ok(self.txt.clone())
        }

        async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
            self.queries.lock().unwrap().push(query.host);
            Ok(self.srv.clone())
        }
    }

    #[tokio::test]
    async fn txt_discovery_parses_easy_tier_url_candidates() {
        let resolver = TestResolver {
            txt: "invalid tcp://127.0.0.1:11010".to_owned(),
            srv: Vec::new(),
            queries: Mutex::new(Vec::new()),
        };

        let endpoint =
            resolve_txt_endpoint(&resolver, "discovery.example", SocketContext::default())
                .await
                .unwrap();

        assert_eq!(endpoint.as_str(), "tcp://127.0.0.1:11010");
        assert_eq!(*resolver.queries.lock().unwrap(), ["discovery.example"]);
    }

    #[tokio::test]
    async fn srv_discovery_builds_protocol_specific_endpoint() {
        let resolver = TestResolver {
            txt: String::new(),
            srv: vec![DnsSrvRecord {
                priority: 1,
                weight: 10,
                port: 11012,
                target: "peer.example.com.".to_owned(),
            }],
            queries: Mutex::new(Vec::new()),
        };

        let endpoint = resolve_srv_endpoint(
            &resolver,
            "discovery.example",
            &["quic".to_owned()],
            SocketContext::default(),
        )
        .await
        .unwrap();

        assert_eq!(endpoint.as_str(), "quic://peer.example.com.:11012");
        assert_eq!(
            *resolver.queries.lock().unwrap(),
            ["_easytier._quic.discovery.example"]
        );
    }

    #[test]
    fn srv_discovery_deduplicates_url_and_priority() {
        let endpoint: Url = "tcp://peer.example.com:11010".parse().unwrap();
        let candidates = deduplicate_srv_candidates(vec![
            (endpoint.clone(), 10),
            (endpoint.clone(), 10),
            (endpoint.clone(), 20),
        ]);

        assert_eq!(candidates.len(), 2);
        assert!(candidates.contains(&(endpoint.clone(), 10)));
        assert!(candidates.contains(&(endpoint, 20)));
    }
}
