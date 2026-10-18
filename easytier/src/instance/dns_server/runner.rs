use cidr::Ipv4Inet;
use tokio_util::sync::CancellationToken;

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use easytier_core::host::route::{
    DeviceEpoch, RouteClaim, RouteDemand, RouteHandle, RouteSet, RouteSpec,
};
use easytier_core::instance::CorePacketPlane;

use crate::{common::global_ctx::ArcGlobalCtx, instance::virtual_nic::NicBackend};

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
    managed_routes: Option<(RouteHandle, DeviceEpoch)>,
    active_fake_ip_route: Option<MagicDnsFakeIpRouteClaim>,
}

enum MagicDnsFakeIpRouteClaim {
    Legacy {
        fake_ip: Ipv4Addr,
        route_backend: NicBackend,
    },
    Managed {
        claim: RouteClaim,
        device: DeviceEpoch,
    },
}

impl MagicDnsFakeIpRouteClaim {
    async fn add(&self) -> anyhow::Result<()> {
        let (fake_ip, route_backend) = match self {
            Self::Managed { claim, device } => {
                return claim.wait_ready(Some(*device)).await.map_err(Into::into);
            }
            Self::Legacy {
                fake_ip,
                route_backend,
            } => (fake_ip, route_backend),
        };
        let cost = if cfg!(target_os = "windows") {
            Some(4)
        } else {
            None
        };

        route_backend
            .add_route_with_cost(*fake_ip, 32, cost)
            .await?;
        Ok(())
    }

    async fn remove(self) {
        if let Self::Legacy {
            fake_ip,
            route_backend,
        } = self
            && let Err(err) = route_backend.remove_route(fake_ip, 32).await
        {
            tracing::warn!(?err, ?fake_ip, "remove magic dns route failed");
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
            managed_routes: None,
            active_fake_ip_route: None,
        }
    }

    pub(crate) fn with_shared_route_backend(mut self, route_backend: Option<NicBackend>) -> Self {
        self.shared_route_backend = route_backend;
        self
    }

    pub(crate) fn with_managed_routes(mut self, routes: RouteHandle, device: DeviceEpoch) -> Self {
        self.managed_routes = Some((routes, device));
        self.shared_route_backend = None;
        self
    }

    async fn clean_env(&mut self) {
        if let Some(mut server) = self.server.take() {
            server.clean_env().await;
        }
        if let Some(claim) = self.active_fake_ip_route.take() {
            claim.remove().await;
        }
        self.client.take();
    }

    fn should_manage_fake_ip_route_externally(&self) -> bool {
        (self.shared_route_backend.is_some() || self.managed_routes.is_some())
            && !self.tun_inet.contains(&self.fake_ip)
    }

    fn fake_ip_route_claim(&self) -> Option<MagicDnsFakeIpRouteClaim> {
        if !self.should_manage_fake_ip_route_externally() {
            return None;
        }

        Some(MagicDnsFakeIpRouteClaim::Legacy {
            fake_ip: self.fake_ip,
            route_backend: self.shared_route_backend.clone()?,
        })
    }

    async fn run_once(&mut self, cancel_token: &CancellationToken) -> anyhow::Result<()> {
        // try server first
        let server_result = if let Some((routes, device)) = self.managed_routes.clone() {
            let active = &mut self.active_fake_ip_route;
            let fake_ip = self.fake_ip;
            let needs_route = !self.tun_inet.contains(&fake_ip);
            let ready = async move {
                if needs_route {
                    *active = Some(MagicDnsFakeIpRouteClaim::Managed {
                        claim: routes.publish(RouteDemand::Additional(RouteSet::from([
                            RouteSpec::for_tun(cidr::Ipv4Cidr::new(fake_ip, 32).unwrap().into()),
                        ])))?,
                        device,
                    });
                    tokio::select! {
                        _ = cancel_token.cancelled() => anyhow::bail!("DNS route readiness cancelled"),
                        result = active.as_ref().unwrap().add() => result?,
                    }
                }
                Ok(())
            };
            MagicDnsServerInstance::new_with_route_ready(
                self.packet_plane.clone(),
                self.global_ctx.clone(),
                self.tun_dev.clone(),
                self.tun_inet,
                self.fake_ip,
                ready,
            )
            .await
        } else if self.should_manage_fake_ip_route_externally() {
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
                // Keep the initialized resolver owned by the runner before adding
                // its route, so route failure still reaches async server cleanup.
                if self.managed_routes.is_none() {
                    self.active_fake_ip_route = self.fake_ip_route_claim();
                    if let Some(claim) = &self.active_fake_ip_route {
                        claim.add().await.map_err(|err| {
                            anyhow::anyhow!("failed to add magic dns fake-ip route: {err}")
                        })?;
                    }
                }
                tracing::info!("DnsRunner::run_once: server started");
            }
            Err(e) => {
                if self.managed_routes.is_some()
                    && let Some(claim) = self.active_fake_ip_route.take()
                {
                    claim.remove().await;
                }
                tracing::error!("DnsRunner::run_once: {:?}", e);
            }
        }

        // Every runner must run a client. Only this phase is cancellable: server
        // initialization and route updates must finish before async cleanup.
        tokio::select! {
            _ = cancel_token.cancelled() => Ok(()),
            ret = async {
                let client = MagicDnsClientInstance::new(self.packet_plane.clone(), self.global_ctx.net_ns.clone()).await?;
                self.client = Some(client);
                self.client.as_mut().unwrap().run_and_wait().await;
                Err(anyhow::anyhow!("Client instance exit"))
            } => ret,
        }
    }

    pub async fn run(&mut self, cancel_token: CancellationToken) {
        while !cancel_token.is_cancelled() {
            tracing::info!("DnsRunner::run: start");
            let ret = self.run_once(&cancel_token).await;
            self.clean_env().await;
            if cancel_token.is_cancelled() {
                break;
            }
            if let Err(e) = ret {
                tracing::error!("DnsRunner::run: {:?}", e);
            } else {
                tracing::info!("DnsRunner::run: unexpected exit, server may be down");
            }
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
        tracing::info!("DnsRunner::run: cancelled");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::host::route::{
        ClaimRouteStatus, InstanceRouteStatus, InstanceRoutes, RouteWaitError,
    };
    use futures::FutureExt;

    #[tokio::test]
    async fn managed_dns_claim_waits_for_its_supplied_epoch_and_drop_withdraws() {
        let owner = InstanceRoutes::new(Arc::new(|| {}));
        let inputs = owner.inputs();
        let nic = uuid::Uuid::new_v4();
        owner.bind_default_nic(nic).unwrap();
        let epoch = DeviceEpoch::new();
        inputs.set_default_device(nic, Some(epoch)).unwrap();
        let claim = owner
            .handle()
            .publish(RouteDemand::Additional(RouteSet::from([
                RouteSpec::for_tun("100.100.100.100/32".parse().unwrap()),
            ])))
            .unwrap();
        let claim = MagicDnsFakeIpRouteClaim::Managed {
            claim,
            device: epoch,
        };
        assert!(claim.add().now_or_never().is_none());
        let snapshot = inputs.snapshot();
        assert!(
            inputs.publish_feedback(
                &snapshot,
                InstanceRouteStatus::Active,
                snapshot
                    .claims
                    .keys()
                    .map(|id| (*id, ClaimRouteStatus::Ready))
                    .collect()
            )
        );
        claim.add().await.unwrap();
        inputs
            .set_default_device(nic, Some(DeviceEpoch::new()))
            .unwrap();
        let error = claim.add().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<RouteWaitError>(),
            Some(RouteWaitError::DeviceChanged)
        ));
        claim.remove().await;
        assert!(inputs.snapshot().claims.is_empty());
    }
}
