use cidr::Ipv4Inet;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "tun")]
use crate::instance::virtual_nic::NicBackend;
use crate::peers::peer_manager::PeerManager;
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use super::{client_instance::MagicDnsClientInstance, server_instance::MagicDnsServerInstance};

static DEFAULT_ET_DNS_ZONE: &str = "et.net.";

pub struct DnsRunner {
    client: Option<MagicDnsClientInstance>,
    server: Option<MagicDnsServerInstance>,
    peer_mgr: Arc<PeerManager>,
    tun_dev: Option<String>,
    netns: Option<String>,
    tun_inet: Ipv4Inet,
    fake_ip: Ipv4Addr,
    #[cfg(feature = "tun")]
    route_backend: Option<NicBackend>,
}

#[cfg(feature = "tun")]
#[derive(Clone)]
struct MagicDnsFakeIpRouteClaim {
    tun_dev_name: String,
    fake_ip: Ipv4Addr,
    netns: Option<String>,
    route_backend: NicBackend,
}

#[cfg(feature = "tun")]
impl MagicDnsFakeIpRouteClaim {
    async fn add(self) -> anyhow::Result<()> {
        let cost = if cfg!(target_os = "windows") {
            Some(4)
        } else {
            None
        };

        MagicDnsServerInstance::add_fake_ip_route(
            &self.tun_dev_name,
            self.fake_ip,
            self.netns,
            cost,
            Some(&self.route_backend),
        )
        .await
    }

    async fn remove(self) {
        MagicDnsServerInstance::remove_fake_ip_route(
            &self.tun_dev_name,
            self.fake_ip,
            self.netns,
            Some(&self.route_backend),
        )
        .await;
    }
}

impl DnsRunner {
    pub fn new(
        peer_mgr: Arc<PeerManager>,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Self {
        Self {
            client: None,
            server: None,
            peer_mgr,
            tun_dev,
            netns: None,
            tun_inet,
            fake_ip,
            #[cfg(feature = "tun")]
            route_backend: None,
        }
    }

    pub fn new_with_netns(
        peer_mgr: Arc<PeerManager>,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
        netns: Option<String>,
    ) -> Self {
        let mut runner = Self::new(peer_mgr, tun_dev, tun_inet, fake_ip);
        runner.netns = netns;
        runner
    }

    #[cfg(feature = "tun")]
    pub fn with_route_backend(mut self, route_backend: NicBackend) -> Self {
        self.route_backend = Some(route_backend);
        self
    }

    async fn clean_env(&mut self) {
        if let Some(server) = self.server.take() {
            server.clean_env().await;
        }
        self.client.take();
    }

    #[cfg(feature = "tun")]
    fn should_manage_fake_ip_route(&self) -> bool {
        self.route_backend.is_some()
            && self.tun_dev.is_some()
            && !self.tun_inet.contains(&self.fake_ip)
    }

    #[cfg(feature = "tun")]
    fn fake_ip_route_claim(&self) -> Option<MagicDnsFakeIpRouteClaim> {
        if !self.should_manage_fake_ip_route() {
            return None;
        }

        let Some(tun_dev_name) = &self.tun_dev else {
            return None;
        };
        let route_backend = self.route_backend.clone()?;
        Some(MagicDnsFakeIpRouteClaim {
            tun_dev_name: tun_dev_name.clone(),
            fake_ip: self.fake_ip,
            netns: self.netns.clone(),
            route_backend,
        })
    }

    async fn run_once(&mut self) -> anyhow::Result<()> {
        #[cfg(feature = "tun")]
        if let Some(claim) = self.fake_ip_route_claim() {
            claim
                .add()
                .await
                .map_err(|err| anyhow::anyhow!("failed to add magic dns fake-ip route: {err}"))?;
        }

        // try server first
        #[cfg(feature = "tun")]
        let server_result = if self.should_manage_fake_ip_route() {
            MagicDnsServerInstance::new_with_external_fake_ip_route(
                self.peer_mgr.clone(),
                self.tun_dev.clone(),
                self.tun_inet,
                self.fake_ip,
                self.netns.clone(),
            )
            .await
        } else {
            MagicDnsServerInstance::new_with_route_backend(
                self.peer_mgr.clone(),
                self.tun_dev.clone(),
                self.tun_inet,
                self.fake_ip,
                self.netns.clone(),
                None,
            )
            .await
        };
        #[cfg(not(feature = "tun"))]
        let server_result = MagicDnsServerInstance::new_with_netns(
            self.peer_mgr.clone(),
            self.tun_dev.clone(),
            self.tun_inet,
            self.fake_ip,
            self.netns.clone(),
        )
        .await;

        match server_result {
            Ok(server) => {
                self.server = Some(server);
                tracing::info!("DnsRunner::run_once: server started");
            }
            Err(e) => {
                tracing::error!("DnsRunner::run_once: {:?}", e);
            }
        }

        // every runner must run a client
        let client = MagicDnsClientInstance::new(self.peer_mgr.clone()).await?;
        self.client = Some(client);
        self.client.as_mut().unwrap().run_and_wait().await;

        Err(anyhow::anyhow!("Client instance exit"))
    }

    pub async fn run(&mut self, canel_token: CancellationToken) {
        #[cfg(feature = "tun")]
        let fake_ip_route_claim = self.fake_ip_route_claim();

        loop {
            tracing::info!("DnsRunner::run: start");
            tokio::select! {
                _ = canel_token.cancelled() => {
                    self.clean_env().await;
                    #[cfg(feature = "tun")]
                    if let Some(claim) = fake_ip_route_claim.clone() {
                        claim.remove().await;
                    }
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
