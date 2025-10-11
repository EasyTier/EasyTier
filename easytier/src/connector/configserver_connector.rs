use std::{ sync::Arc};
use crate::common::global_ctx::GlobalCtx;
use crate::connector::{create_connector_by_url};
use crate::tunnel::IpVersion;
use crate as easytier;

pub struct ConfigServerConnector {
    urls: Vec<url::Url>,
    global_ctx: Arc<GlobalCtx>,
    ip_version: IpVersion,
    last_remote: std::sync::RwLock<url::Url>,
}

impl ConfigServerConnector {
    pub fn new(urls: Vec<url::Url>, global_ctx: Arc<GlobalCtx>, ip_version: IpVersion) -> Self {
        let first = urls[0].clone();
        ConfigServerConnector {
            urls,
            global_ctx,
            ip_version,
            last_remote: std::sync::RwLock::new(first),
        }
    }
}

#[async_trait::async_trait]
impl easytier::tunnel::TunnelConnector for ConfigServerConnector {
    async fn connect(&mut self) -> Result<Box<dyn easytier::tunnel::Tunnel>, easytier::tunnel::TunnelError> {
        loop {
            for config_server_url in &self.urls {
                // remember last remote for remote_url()
                {
                    let mut lr = self.last_remote.write().unwrap();
                    *lr = config_server_url.clone();
                }

                match create_connector_by_url(config_server_url.as_str(), &self.global_ctx, self.ip_version).await {
                    Ok(mut connector) => match connector.connect().await {
                        Ok(tunnel) => {
                            println!("Connected to config server: {}", config_server_url);
                            return Ok(tunnel);
                        }
                        Err(e) => {
                            println!("Failed to connect to config server {}: {}", config_server_url, e);
                            continue;
                        }
                    },
                    Err(e) => {
                        println!("Failed to build connector for config server {}: {}", config_server_url, e);
                        continue;
                    }
                }
            }

            // sleep a bit then retry all urls
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    fn remote_url(&self) -> url::Url {
        self.last_remote.read().unwrap().clone()
    }

    fn set_bind_addrs(&mut self, _addrs: Vec<std::net::SocketAddr>) {
        panic!("not implemented");
    }
    fn set_ip_version(&mut self, _ip_version: IpVersion) {
        panic!("not implemented");
    }
}