use std::{net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use anyhow::Context as _;
use easytier_core::connectivity::manual::discovery::{
    self, HttpDiscoveryRequest, HttpDiscoveryResponse, HttpEndpointSource, ResolvedHttpEndpoint,
};
use easytier_core::tunnel::ring::RingTunnelRegistry;
use url::Url;

use crate::{
    VERSION,
    common::{dns::RuntimeDnsResolver, error::Error, global_ctx::ArcGlobalCtx},
    tunnel::{IpVersion, Tunnel, TunnelConnector, TunnelError, ZCPacketSink, ZCPacketStream},
};

use crate::proto::common::TunnelInfo;

use super::{
    core_instance::runtime_manual_options, create_connector_by_url, runtime::RuntimeConnectorHost,
};

pub struct TunnelWithInfo {
    inner: Box<dyn Tunnel>,
    info: TunnelInfo,
}

impl TunnelWithInfo {
    pub fn new(inner: Box<dyn Tunnel>, info: TunnelInfo) -> Self {
        Self { inner, info }
    }
}

impl Tunnel for TunnelWithInfo {
    fn split(&self) -> (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>) {
        self.inner.split()
    }

    fn info(&self) -> Option<TunnelInfo> {
        Some(self.info.clone())
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum HttpRedirectType {
    Unknown,
    // redirected url is in the path of new url
    RedirectToQuery,
    // redirected url is the entire new url
    RedirectToUrl,
    // redirected url is in the body of response
    BodyUrls,
}

fn interpret_http_discovery_response(
    response: HttpDiscoveryResponse,
) -> Result<ResolvedHttpEndpoint, Error> {
    discovery::resolve_http_endpoint(response).map_err(|error| Error::InvalidUrl(error.to_string()))
}

pub struct HttpTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    global_ctx: ArcGlobalCtx,
    ring_registry: Arc<RingTunnelRegistry>,
    redirect_type: HttpRedirectType,
}

impl std::fmt::Debug for HttpTunnelConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpTunnelConnector")
            .field("addr", &self.addr)
            .field("bind_addrs", &self.bind_addrs)
            .field("ip_version", &self.ip_version)
            .field("redirect_type", &self.redirect_type)
            .finish_non_exhaustive()
    }
}

impl HttpTunnelConnector {
    pub fn new(
        addr: url::Url,
        global_ctx: ArcGlobalCtx,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        Self {
            addr,
            bind_addrs: Vec::new(),
            ip_version: IpVersion::Both,
            global_ctx,
            ring_registry,
            redirect_type: HttpRedirectType::Unknown,
        }
    }

    #[tracing::instrument(ret)]
    pub async fn get_redirected_url(&mut self, original_url: &str) -> Result<Url, Error> {
        self.redirect_type = HttpRedirectType::Unknown;
        tracing::info!("get_redirected_url: {}", original_url);
        let url = Url::parse(original_url)
            .with_context(|| format!("parsing url failed. url: {original_url}"))?;
        let network_name = self.global_ctx.network.network_name.clone();
        let user_agent = format!("easytier/{}", VERSION);
        tracing::info!(%url, %network_name, "sending HTTP discovery request");
        let options = runtime_manual_options(&self.global_ctx);
        let response = discovery::fetch_http_discovery(
            Arc::new(RuntimeConnectorHost::new_with_ring_registry(
                self.global_ctx.clone(),
                self.ring_registry.clone(),
            )),
            &RuntimeDnsResolver::new(),
            HttpDiscoveryRequest {
                url,
                user_agent,
                network_name,
                timeout: Duration::from_secs(20),
                ip_version: self.ip_version.into(),
                tcp_bind: options.tcp_bind,
            },
        )
        .await
        .with_context(|| format!("sending HTTP request failed. url: {original_url}"))?;

        let endpoint = interpret_http_discovery_response(response)?;
        self.redirect_type = match endpoint.source {
            HttpEndpointSource::RedirectQuery => HttpRedirectType::RedirectToQuery,
            HttpEndpointSource::RedirectUrl => HttpRedirectType::RedirectToUrl,
            HttpEndpointSource::ResponseBody => HttpRedirectType::BodyUrls,
        };
        Ok(endpoint.url)
    }

    pub async fn get_redirected_connector(
        &mut self,
        original_url: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        let url = self.get_redirected_url(original_url).await?;
        create_connector_by_url(
            url.as_str(),
            &self.global_ctx,
            self.ip_version,
            self.ring_registry.clone(),
        )
        .await
    }
}

#[async_trait::async_trait]
impl super::TunnelConnector for HttpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let mut conn = self
            .get_redirected_connector(self.addr.to_string().as_str())
            .await
            .with_context(|| "get redirected url failed")?;
        conn.set_ip_version(self.ip_version);
        let t = conn.connect().await?;
        let info = t.info().unwrap_or_default();
        Ok(Box::new(TunnelWithInfo::new(
            t,
            TunnelInfo {
                local_addr: info.local_addr.clone(),
                remote_addr: Some(self.addr.clone().into()),
                resolved_remote_addr: info
                    .resolved_remote_addr
                    .clone()
                    .or(info.remote_addr.clone()),
                tunnel_type: format!("{}-{}", self.addr.scheme(), info.tunnel_type),
            },
        )))
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
}

#[cfg(test)]
mod tests {
    use tokio::{io::AsyncReadExt as _, io::AsyncWriteExt as _, net::TcpListener};

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx_with_network,
        tunnel::{TunnelConnector, TunnelListener, tcp::TcpTunnelListener},
    };

    use super::*;

    #[test]
    fn http_discovery_failures_remain_invalid_url_errors() {
        for response in [
            HttpDiscoveryResponse {
                status_code: 302,
                location: None,
                body: String::new(),
            },
            HttpDiscoveryResponse {
                status_code: 200,
                location: None,
                body: "not a URL".to_owned(),
            },
            HttpDiscoveryResponse {
                status_code: 500,
                location: None,
                body: "failure".to_owned(),
            },
        ] {
            assert!(matches!(
                interpret_http_discovery_response(response),
                Err(Error::InvalidUrl(_))
            ));
        }
    }

    async fn run_http_redirect_server(
        port: u16,
        test_type: HttpRedirectType,
    ) -> Result<String, Error> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
        let (mut stream, _) = listener.accept().await?;

        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        let req = String::from_utf8_lossy(&buf[..n]);

        let mut captured_network_name = String::new();
        for line in req.lines() {
            if line.to_lowercase().starts_with("x-network-name:") {
                captured_network_name = line
                    .split_once(':')
                    .map(|x| x.1)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                break;
            }
        }

        match test_type {
            HttpRedirectType::RedirectToQuery => {
                let resp = "HTTP/1.1 301 Moved Permanently\r\nLocation: http://test.com/?url=tcp://127.0.0.1:25888\r\n\r\n";
                stream.write_all(resp.as_bytes()).await?;
            }
            HttpRedirectType::RedirectToUrl => {
                let resp =
                    "HTTP/1.1 301 Moved Permanently\r\nLocation: tcp://127.0.0.1:25888\r\n\r\n";
                stream.write_all(resp.as_bytes()).await?;
            }
            HttpRedirectType::BodyUrls => {
                let resp = "HTTP/1.1 200 OK\r\n\r\ntcp://127.0.0.1:25888";
                stream.write_all(resp.as_bytes()).await?;
            }
            HttpRedirectType::Unknown => {
                panic!("unexpected test type");
            }
        }

        Ok(captured_network_name)
    }

    #[rstest::rstest]
    #[serial_test::serial(http_redirect_test)]
    #[tokio::test]
    async fn http_redirect_test(
        // 1. 301 redirect
        // 2. 200 success with valid connector urls
        #[values(
            HttpRedirectType::RedirectToQuery,
            HttpRedirectType::RedirectToUrl,
            HttpRedirectType::BodyUrls
        )]
        test_type: HttpRedirectType,
    ) {
        let network_name = format!("net_{}", rand::random::<u32>());
        let http_task = tokio::spawn(run_http_redirect_server(35888, test_type));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let test_url: url::Url = "http://127.0.0.1:35888".parse().unwrap();

        let identity = crate::common::config::NetworkIdentity {
            network_name: network_name.clone(),
            ..Default::default()
        };
        let global_ctx = get_mock_global_ctx_with_network(Some(identity));

        let mut flags = global_ctx.config.get_flags();
        flags.bind_device = false;
        global_ctx.set_flags(flags);
        let mut connector = HttpTunnelConnector::new(
            test_url.clone(),
            global_ctx.clone(),
            Arc::new(RingTunnelRegistry::default()),
        );

        let mut listener = TcpTunnelListener::new("tcp://0.0.0.0:25888".parse().unwrap());
        listener.listen().await.unwrap();

        let task = tokio::spawn(async move {
            let _conn = listener.accept().await.unwrap();
        });

        let t = connector.connect().await.unwrap();
        assert_eq!(connector.redirect_type, test_type);

        let captured_name = http_task.await.unwrap().unwrap();
        assert_eq!(captured_name, network_name);

        let info = t.info().unwrap();
        let remote_addr = info.remote_addr.unwrap();
        assert_eq!(remote_addr, test_url.into());
        let resolved_remote_addr = info.resolved_remote_addr.unwrap();
        assert_eq!(resolved_remote_addr.url, "tcp://127.0.0.1:25888");

        tokio::join!(task).0.unwrap();
    }
}
