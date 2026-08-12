use cidr::Ipv4Inet;
use tokio_util::sync::CancellationToken;

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use easytier_core::instance::CorePacketPlane;

use crate::{
    common::{
        error::Error as EtError,
        global_ctx::ArcGlobalCtx,
        ifcfg::{IfConfiger, IfConfiguerTrait},
        netns::NetNS,
    },
    instance::virtual_nic::NicBackend,
};

use super::{client_instance::MagicDnsClientInstance, server_instance::MagicDnsServerInstance};

pub struct DnsRunner {
    client: Option<MagicDnsClientInstance>,
    server: Option<MagicDnsServerInstance>,
    packet_plane: Arc<CorePacketPlane>,
    global_ctx: ArcGlobalCtx,
    tun_dev: Option<String>,
    tun_inet: Ipv4Inet,
    fake_ip: Ipv4Addr,
    shared_route_backend: Option<NicBackend>,
}

#[derive(Clone)]
struct MagicDnsFakeIpRouteClaim {
    tun_dev: Option<String>,
    net_ns: NetNS,
    fake_ip: Ipv4Addr,
    route_backend: NicBackend,
}

impl MagicDnsFakeIpRouteClaim {
    async fn add(&self) -> anyhow::Result<()> {
        let cost = if cfg!(target_os = "windows") {
            Some(4)
        } else {
            None
        };

        match self
            .route_backend
            .add_route_with_cost(self.fake_ip, 32, cost)
            .await
        {
            Err(EtError::IOError(err))
                if err.kind() == std::io::ErrorKind::AlreadyExists && self.tun_dev.is_some() =>
            {
                let ifcfg = IfConfiger::default();
                let _guard = self.net_ns.guard();
                ifcfg
                    .remove_ipv4_route(self.tun_dev.as_deref().unwrap(), self.fake_ip, 32)
                    .await?;
                self.route_backend
                    .add_route_with_cost(self.fake_ip, 32, cost)
                    .await?;
                Ok(())
            }
            result => result.map_err(Into::into),
        }
    }

    async fn remove(&self) {
        if let Err(err) = self.route_backend.remove_route(self.fake_ip, 32).await {
            tracing::warn!(?err, fake_ip = ?self.fake_ip, "remove magic dns route failed");
        }
    }
}

impl DnsRunner {
    pub(crate) fn new(
        packet_plane: Arc<CorePacketPlane>,
        global_ctx: ArcGlobalCtx,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Self {
        Self {
            client: None,
            server: None,
            packet_plane,
            global_ctx,
            tun_dev,
            tun_inet,
            fake_ip,
            shared_route_backend: None,
        }
    }

    pub(crate) fn with_shared_route_backend(mut self, route_backend: Option<NicBackend>) -> Self {
        self.shared_route_backend = route_backend;
        self
    }

    async fn clean_env(&mut self) {
        if let Some(server) = self.server.take() {
            server.clean_env().await;
        }
        self.client.take();
    }

    fn should_manage_fake_ip_route_externally(&self) -> bool {
        self.shared_route_backend.is_some() && !self.tun_inet.contains(&self.fake_ip)
    }

    fn fake_ip_route_claim(&self) -> Option<MagicDnsFakeIpRouteClaim> {
        if !self.should_manage_fake_ip_route_externally() {
            return None;
        }

        Some(MagicDnsFakeIpRouteClaim {
            tun_dev: self.tun_dev.clone(),
            net_ns: self.global_ctx.net_ns.clone(),
            fake_ip: self.fake_ip,
            route_backend: self.shared_route_backend.clone()?,
        })
    }

    async fn run_once(&mut self) -> anyhow::Result<()> {
        if let Some(claim) = self.fake_ip_route_claim() {
            claim
                .add()
                .await
                .map_err(|err| anyhow::anyhow!("failed to add magic dns fake-ip route: {err}"))?;
        }

        // try server first
        let server_result = if self.should_manage_fake_ip_route_externally() {
            MagicDnsServerInstance::new_with_external_fake_ip_route(
                self.packet_plane.clone(),
                self.global_ctx.clone(),
                self.tun_dev.clone(),
                self.tun_inet,
                self.fake_ip,
            )
            .await
        } else {
            MagicDnsServerInstance::new(
                self.packet_plane.clone(),
                self.global_ctx.clone(),
                self.tun_dev.clone(),
                self.tun_inet,
                self.fake_ip,
            )
            .await
        };

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
        let client = MagicDnsClientInstance::new(self.packet_plane.clone()).await?;
        self.client = Some(client);
        self.client.as_mut().unwrap().run_and_wait().await;

        Err(anyhow::anyhow!("Client instance exit"))
    }

    pub async fn run(&mut self, canel_token: CancellationToken) {
        let fake_ip_route_claim = self.fake_ip_route_claim();

        loop {
            tracing::info!("DnsRunner::run: start");
            tokio::select! {
                _ = canel_token.cancelled() => {
                    self.clean_env().await;
                    if let Some(claim) = &fake_ip_route_claim {
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
