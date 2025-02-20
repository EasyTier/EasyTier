use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{RwLock},
};

use anyhow::Context;
use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    tunnel::{Tunnel, TunnelConnector, TunnelError, ZCPacketSink, ZCPacketStream},
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


#[derive(Debug)]
pub struct DNSTxtTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    global_ctx: ArcGlobalCtx,
}

impl DNSTxtTunnelConnector {
    pub fn new(addr: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            addr,
            bind_addrs: Vec::new(),
            global_ctx,
        }
    }

    #[tracing::instrument(ret)]
    async fn handle_dns_txt(
        &mut self,
        new_url: url::Url,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        // the url txt record should be in pointing
        // 1: tcp://10.137.22.22:11010 (scheme is protocol type, the url is used to construct a connector directly)
        tracing::info!("txt record to {}", new_url);
        let url = url::Url::parse(new_url.as_str())
            .with_context(|| format!("parsing txt record url failed. url: {}", new_url))?;
        if url.scheme() == "http" || url.scheme() == "https" {
            let p = url
                .path_segments()
                .map(|p| p.collect::<Vec<&str>>())
                .unwrap_or_default();
            tracing::info!("path: {:?}", p);
            if p.len() != 2 {
                return Err(Error::InvalidUrl(format!(
                    "unexpected path format, path: {}",
                    url.path()
                )));
            }
            let proto = p[0];
            let addr = p[1];
            let connector_url = format!("{}://{}", proto, addr);
            tracing::info!("try to create connector by url: {}", connector_url);
            return create_connector_by_url(&connector_url, &self.global_ctx).await;
        } else {
            return create_connector_by_url(new_url.as_str(), &self.global_ctx).await;
        }
    }
    
    #[tracing::instrument(ret)]
    pub async fn get_dns_txt_connector(
        &mut self,
        original_url: &str,
    ) -> Result<Box<dyn TunnelConnector>, Error> {
        tracing::info!("get_txt_record_url: {}", original_url);

        let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).map_err(|_| Error::InvalidUrl("Failed to create an asynchronous dns resolver".to_string()))?;

        let txt_records = resolver.txt_lookup(original_url.replace("txt://", "")).await
            .map_err(|_| Error::InvalidUrl("failed to get txt records".to_string()))?;

        if let Some(txt_record) = txt_records.iter().next() {
            let txt_str = txt_record.to_string();

            let new_url = url::Url::parse(txt_str.as_str())
                .with_context(|| format!("parsing redirect url failed. url: {}", txt_str))?;
            return self.handle_dns_txt(new_url).await;
        } else {
           return  Err(Error::InvalidUrl("no txt records found".to_string()))
        }
    }
}



#[async_trait::async_trait]
impl super::TunnelConnector for DNSTxtTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let mut conn = self
            .get_dns_txt_connector(self.addr.to_string().as_str())
            .await
            .with_context(|| "get txt record url failed")?;
        let t = conn.connect().await?;
        let info = t.info().unwrap_or_default();
        Ok(Box::new(TunnelWithInfo::new(
            t,
            TunnelInfo {
                local_addr: info.local_addr.clone(),
                remote_addr: Some(self.addr.clone().into()),
                tunnel_type: format!(
                    "{}",
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
}
