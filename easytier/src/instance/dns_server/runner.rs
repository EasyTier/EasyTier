use cidr::Ipv4Inet;
use tokio_util::sync::CancellationToken;

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use crate::{common::global_ctx::ArcGlobalCtx, instance::composition::NativeCoreInstance};

use super::{client_instance::MagicDnsClientInstance, server_instance::MagicDnsServerInstance};

static DEFAULT_ET_DNS_ZONE: &str = "et.net.";

pub struct DnsRunner {
    client: Option<MagicDnsClientInstance>,
    server: Option<MagicDnsServerInstance>,
    core_instance: Arc<NativeCoreInstance>,
    global_ctx: ArcGlobalCtx,
    tun_dev: Option<String>,
    tun_inet: Ipv4Inet,
    fake_ip: Ipv4Addr,
}

impl DnsRunner {
    pub(crate) fn new(
        core_instance: Arc<NativeCoreInstance>,
        global_ctx: ArcGlobalCtx,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Self {
        Self {
            client: None,
            server: None,
            core_instance,
            global_ctx,
            tun_dev,
            tun_inet,
            fake_ip,
        }
    }

    async fn clean_env(&mut self) {
        if let Some(server) = self.server.take() {
            server.clean_env().await;
        }
        self.client.take();
    }

    async fn run_once(&mut self) -> anyhow::Result<()> {
        // try server first
        match MagicDnsServerInstance::new(
            self.core_instance.clone(),
            self.global_ctx.clone(),
            self.tun_dev.clone(),
            self.tun_inet,
            self.fake_ip,
        )
        .await
        {
            Ok(server) => {
                self.server = Some(server);
                tracing::info!("DnsRunner::run_once: server started");
            }
            Err(e) => {
                tracing::error!("DnsRunner::run_once: {:?}", e);
            }
        }

        // every runner must run a client
        let client = MagicDnsClientInstance::new(self.core_instance.clone()).await?;
        self.client = Some(client);
        self.client.as_mut().unwrap().run_and_wait().await;

        Err(anyhow::anyhow!("Client instance exit"))
    }

    pub async fn run(&mut self, canel_token: CancellationToken) {
        loop {
            tracing::info!("DnsRunner::run: start");
            tokio::select! {
                _ = canel_token.cancelled() => {
                    self.clean_env().await;
                    tracing::info!("DnsRunner::run: cancelled");
                    return;
                }

                ret = self.run_once() => {
                    self.clean_env().await;
                    if let Err(e) = ret {
                        tracing::error!("DnsRunner::run: {:?}", e);
                    } else {
                        tracing::info!("DnsRunner::run: unexpected exit, server may be down");
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
}
