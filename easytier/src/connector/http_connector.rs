use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
};

use anyhow::Context;
use http_req::request::{RedirectPolicy, Request};
use rand::seq::SliceRandom as _;
use url::Url;

use crate::{
    VERSION,
    common::{error::Error, global_ctx::ArcGlobalCtx},
    tunnel::{IpVersion, Tunnel, TunnelConnector, TunnelError, ZCPacketSink, ZCPacketStream},
};

use crate::proto::common::TunnelInfo;

use super::create_connector_by_url;

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

#[derive(Debug)]
pub struct HttpTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    global_ctx: ArcGlobalCtx,
    redirect_type: HttpRedirectType,
}

impl HttpTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            addr,
            bind_addrs: Vec::new(),
            ip_version: IpVersion::Both,
            global_ctx,
            redirect_type: HttpRedirectType::Unknown,
        }
    }

    #[tracing::instrument(ret)]
    async fn handle_302_redirect(
        &mut self,
        new_url: url::Url,
        url_str: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        // the url should be in following format:
        // 1: http(s)://easytier.cn/?url=tcp://10.147.22.22:11010 (scheme is http, domain is ignored, path is splitted into proto type and addr)
        // 2: http(s)://tcp://10.137.22.22:11010 (connector url is appended to the scheme)
        // 3: tcp://10.137.22.22:11010 (scheme is protocol type, the url is used to construct a connector directly)
        tracing::info!("redirect to {}", new_url);
        let url = url::Url::parse(new_url.as_str())
            .with_context(|| format!("parsing redirect url failed. url: {}", new_url))?;
        if url.scheme() == "http" || url.scheme() == "https" {
            let mut query = new_url
                .query_pairs()
                .filter_map(|x| url::Url::parse(&x.1).ok())
                .collect::<Vec<_>>();
            query.shuffle(&mut rand::thread_rng());
            if !query.is_empty() {
                tracing::info!("try to create connector by url: {}", query[0]);
                self.redirect_type = HttpRedirectType::RedirectToQuery;
                return create_connector_by_url(
                    query[0].as_ref(),
                    &self.global_ctx,
                    self.ip_version,
                )
                .await;
            } else if let Some(new_url) = url_str
                .strip_prefix(format!("{}://", url.scheme()).as_str())
                .and_then(|x| Url::parse(x).ok())
            {
                // stripe the scheme and create connector by url
                self.redirect_type = HttpRedirectType::RedirectToUrl;
                return create_connector_by_url(
                    new_url.as_str(),
                    &self.global_ctx,
                    self.ip_version,
                )
                .await;
            }
            return Err(Error::InvalidUrl(format!(
                "no valid connector url found in url: {}",
                url
            )));
        } else {
            self.redirect_type = HttpRedirectType::RedirectToUrl;
            return create_connector_by_url(new_url.as_str(), &self.global_ctx, self.ip_version)
                .await;
        }
    }

    #[tracing::instrument]
    async fn handle_200_success(
        &mut self,
        body: &String,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        // resp body should be line of connector urls, like:
        // tcp://10.1.1.1:11010
        // udp://10.1.1.1:11010
        let mut lines = body
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<&str>>();

        tracing::info!("get {} lines of connector urls", lines.len());

        // shuffle the lines for load balancing
        lines.shuffle(&mut rand::thread_rng());

        let mut valid_urls = Vec::new();
        let mut first_valid_url = None;

        for line in lines {
            let url = url::Url::parse(line);
            if url.is_err() {
                tracing::warn!("invalid url: {}, skip it", line);
                continue;
            }
            let url = url.unwrap();
            valid_urls.push(url.clone());
            
            // Keep track of the first valid URL to return as primary connector
            if first_valid_url.is_none() {
                first_valid_url = Some(url);
            }
        }

        if valid_urls.is_empty() {
            return Err(Error::InvalidUrl(format!(
                "no valid connector url found, response body: {}",
                body
            )));
        }

        self.redirect_type = HttpRedirectType::BodyUrls;

        // Add all valid URLs to the manual connector manager (except the first one which will be returned)
        if valid_urls.len() > 1 {
            if let Some(conn_manager) = self.global_ctx.get_manual_connector_manager() {
                for url in valid_urls.iter().skip(1) {
                    tracing::info!("Adding additional connector from HTTP response: {}", url);
                    if let Err(e) = conn_manager.add_connector_by_url(url.clone()).await {
                        tracing::warn!("Failed to add connector {}: {:?}", url, e);
                    }
                }
                tracing::info!(
                    "Added {} additional connectors from HTTP response",
                    valid_urls.len() - 1
                );
            } else {
                tracing::warn!("ManualConnectorManager not available, cannot add additional connectors");
            }
        }

        // Return the first valid URL as the primary connector
        let primary_url = first_valid_url.unwrap();
        tracing::info!("Using primary connector from HTTP response: {}", primary_url);
        
        // Register with global dynamic connector manager for auto-refresh
        self.register_for_auto_refresh();
        
        create_connector_by_url(primary_url.as_str(), &self.global_ctx, self.ip_version).await
    }

    /// 注册到全局动态连接器管理器进行自动刷新
    fn register_for_auto_refresh(&self) {
        use crate::connector::dynamic_connector_manager::{DynamicConnectorType, GlobalDynamicConnectorManager};
        
        let global_manager = GlobalDynamicConnectorManager::get_instance().clone();
        let source_url = self.addr.clone();
        let ip_version = self.ip_version;
        
        // 从 URL 查询参数中读取 TTL，默认 300 秒
        let ttl = self.extract_ttl_from_url();
        
        tokio::spawn(async move {
            if let Err(e) = global_manager.add_dynamic_connector(
                source_url.clone(),
                DynamicConnectorType::Http,
                ip_version,
                ttl,
            ).await {
                tracing::warn!("Failed to register HTTP connector for auto-refresh: {:?}", e);
            }
        });
    }

    /// 从 URL 中提取 TTL 值（单位：秒）
    /// 支持格式: http://example.com/nodes?ttl=120
    /// 范围: 60-6000 秒，超出范围则使用默认值 300
    fn extract_ttl_from_url(&self) -> u64 {
        const DEFAULT_TTL: u64 = 300;
        const MIN_TTL: u64 = 60;
        const MAX_TTL: u64 = 6000;
        
        // 尝试从查询参数中获取 ttl
        if let Some(ttl_param) = self.addr.query_pairs()
            .find(|(key, _)| key.to_lowercase() == "ttl")
            .map(|(_, value)| value)
        {
            match ttl_param.parse::<u64>() {
                Ok(ttl) => {
                    if ttl < MIN_TTL {
                        tracing::warn!(
                            "TTL {} is less than minimum {}, using default {}",
                            ttl, MIN_TTL, DEFAULT_TTL
                        );
                        DEFAULT_TTL
                    } else if ttl > MAX_TTL {
                        tracing::warn!(
                            "TTL {} exceeds maximum {}, using default {}",
                            ttl, MAX_TTL, DEFAULT_TTL
                        );
                        DEFAULT_TTL
                    } else {
                        tracing::info!("Using custom TTL: {} seconds", ttl);
                        ttl
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        "Invalid TTL parameter '{}', using default {}",
                        ttl_param, DEFAULT_TTL
                    );
                    DEFAULT_TTL
                }
            }
        } else {
            DEFAULT_TTL
        }
    }

    #[tracing::instrument(ret)]
    pub async fn get_redirected_connector(
        &mut self,
        original_url: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        self.redirect_type = HttpRedirectType::Unknown;
        tracing::info!("get_redirected_url: {}", original_url);
        // Container for body of a response.
        let body = Arc::new(RwLock::new(Vec::new()));

        let original_url_clone = original_url.to_string();
        let body_clone = body.clone();
        let network_name = self.global_ctx.network.network_name.clone();
        let user_agent = format!("easytier/{}", VERSION);
        let res = tokio::task::spawn_blocking(move || {
            let uri = http_req::uri::Uri::try_from(original_url_clone.as_ref())
                .with_context(|| format!("parsing url failed. url: {}", original_url_clone))?;

            tracing::info!(
                "sending http request to {}, network_name: {}",
                uri,
                network_name
            );

            Request::new(&uri)
                .header("User-Agent", &user_agent)
                .header("X-Network-Name", &network_name)
                .redirect_policy(RedirectPolicy::Limit(0))
                .timeout(std::time::Duration::from_secs(20))
                .send(&mut *body_clone.write().unwrap())
                .with_context(|| format!("sending http request failed. url: {}", uri))
        })
        .await
        .map_err(|e| Error::InvalidUrl(format!("task join error: {}", e)))??;

        let body = String::from_utf8_lossy(&body.read().unwrap()).to_string();

        if res.status_code().is_redirect() {
            let redirect_url = res
                .headers()
                .get("Location")
                .ok_or_else(|| Error::InvalidUrl("no redirect address found".to_string()))?;
            let new_url = url::Url::parse(redirect_url.as_str())
                .with_context(|| format!("parsing redirect url failed. url: {}", redirect_url))?;
            return self.handle_302_redirect(new_url, redirect_url).await;
        } else if res.status_code().is_success() {
            return self.handle_200_success(&body).await;
        } else {
            return Err(Error::InvalidUrl(format!(
                "unexpected response, resp: {:?}, body: {}",
                res, body,
            )));
        }
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

    async fn run_http_multi_node_server(port: u16) -> Result<String, Error> {
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

        // Return multiple node URLs
        let resp = "HTTP/1.1 200 OK\r\n\r\ntcp://127.0.0.1:25888\nudp://127.0.0.1:25889\ntcp://127.0.0.1:25890";
        stream.write_all(resp.as_bytes()).await?;

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
        let mut connector = HttpTunnelConnector::new(test_url.clone(), global_ctx.clone());

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

    #[tokio::test]
    async fn http_multi_node_test() {
        use crate::connector::manual::ManualConnectorManager;
        use crate::peers::peer_manager::PeerManager;
        
        let network_name = format!("net_{}", rand::random::<u32>());
        let http_task = tokio::spawn(run_http_multi_node_server(35890));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let test_url: url::Url = "http://127.0.0.1:35890".parse().unwrap();

        let identity = crate::common::config::NetworkIdentity {
            network_name: network_name.clone(),
            ..Default::default()
        };
        let global_ctx = get_mock_global_ctx_with_network(Some(identity));

        let mut flags = global_ctx.config.get_flags();
        flags.bind_device = false;
        global_ctx.set_flags(flags);
        
        // Create a mock peer manager and connector manager
        let config_fs = crate::common::config::TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));
        config_fs.set_network_identity(identity.clone());
        let peer_manager = Arc::new(PeerManager::new(config_fs, global_ctx.clone()));
        let conn_manager = Arc::new(ManualConnectorManager::new(global_ctx.clone(), peer_manager.clone()));
        
        // Set the connector manager in global ctx
        global_ctx.set_manual_connector_manager(Arc::downgrade(&conn_manager));
        
        let mut connector = HttpTunnelConnector::new(test_url.clone(), global_ctx.clone());

        // Connect should succeed and add additional connectors
        let t = connector.connect().await.unwrap();
        assert_eq!(connector.redirect_type, HttpRedirectType::BodyUrls);

        let captured_name = http_task.await.unwrap().unwrap();
        assert_eq!(captured_name, network_name);

        // Verify that additional connectors were added
        let connectors = conn_manager.list_connectors().await;
        tracing::info!("Connectors after HTTP multi-node test: {:?}", connectors);
        // Should have 2 additional connectors (udp://127.0.0.1:25889 and tcp://127.0.0.1:25890)
        assert_eq!(connectors.len(), 2, "Expected 2 additional connectors to be added");

        let info = t.info().unwrap();
        let remote_addr = info.remote_addr.unwrap();
        assert_eq!(remote_addr, test_url.into());
    }
}
