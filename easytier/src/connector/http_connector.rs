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
                    &query[0].to_string(),
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

        // shuffle the lines and pick the usable one
        lines.shuffle(&mut rand::thread_rng());

        for line in lines {
            let url = url::Url::parse(line);
            if url.is_err() {
                tracing::warn!("invalid url: {}, skip it", line);
                continue;
            }
            self.redirect_type = HttpRedirectType::BodyUrls;
            return create_connector_by_url(line, &self.global_ctx, self.ip_version).await;
        }

        Err(Error::InvalidUrl(format!(
            "no valid connector url found, response body: {}",
            body
        )))
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
        let res = tokio::task::spawn_blocking(move || {
            let uri = http_req::uri::Uri::try_from(original_url_clone.as_ref())
                .with_context(|| format!("parsing url failed. url: {}", original_url_clone))?;

            tracing::info!("sending http request to {}", uri);

            Request::new(&uri)
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
            return self.handle_302_redirect(new_url, &redirect_url).await;
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
                tunnel_type: format!(
                    "{:?}-{}",
                    self.redirect_type,
                    info.remote_addr.unwrap_or_default()
                ),
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
    use tokio::{io::AsyncWriteExt as _, net::TcpListener};

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{tcp::TcpTunnelListener, TunnelConnector, TunnelListener},
    };

    use super::*;

    async fn run_http_redirect_server(port: u16, test_type: HttpRedirectType) -> Result<(), Error> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        let (mut stream, _) = listener.accept().await?;

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

        Ok(())
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
        let http_task = tokio::spawn(run_http_redirect_server(35888, test_type));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let test_url: url::Url = "http://127.0.0.1:35888".parse().unwrap();
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.config.get_flags();
        flags.bind_device = false;
        global_ctx.config.set_flags(flags);
        let mut connector = HttpTunnelConnector::new(test_url.clone(), global_ctx.clone());

        let mut listener = TcpTunnelListener::new("tcp://0.0.0.0:25888".parse().unwrap());
        listener.listen().await.unwrap();

        let task = tokio::spawn(async move {
            let _conn = listener.accept().await.unwrap();
        });

        let t = connector.connect().await.unwrap();
        assert_eq!(connector.redirect_type, test_type);
        let info = t.info().unwrap();
        let remote_addr = info.remote_addr.unwrap();
        assert_eq!(remote_addr, test_url.into());

        tokio::join!(task).0.unwrap();
        tokio::join!(http_task).0.unwrap().unwrap();
    }
}
