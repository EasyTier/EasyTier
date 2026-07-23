//! Start/stop orchestration for `CoreInstance` components.
//!
//! The instance struct, its constructor, and the public API live in
//! `instance::mod`; this file holds the lifecycle facet: component start
//! methods, their rollback paths, and shutdown.

use std::{
    future::Future,
    sync::{Arc, Weak, atomic::Ordering},
};

use crate::gateway::dhcp::DhcpIpv4Host;

use super::{CoreInstance, CoreInstanceHost, CoreInstanceState};

struct RecoveryGuard<F>
where
    F: FnOnce(),
{
    recovery: Option<F>,
}

impl<F> RecoveryGuard<F>
where
    F: FnOnce(),
{
    fn new(recovery: F) -> Self {
        Self {
            recovery: Some(recovery),
        }
    }

    fn disarm(&mut self) {
        self.recovery.take();
    }
}

impl<F> Drop for RecoveryGuard<F>
where
    F: FnOnce(),
{
    fn drop(&mut self) {
        if let Some(recovery) = self.recovery.take() {
            recovery();
        }
    }
}

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    fn recovery_guard(self: &Arc<Self>) -> RecoveryGuard<impl FnOnce() + Send + use<H>> {
        let weak: Weak<Self> = Arc::downgrade(self);
        RecoveryGuard::new(move || {
            if let Some(instance) = weak.upgrade() {
                tokio::spawn(async move {
                    instance.stop().await;
                });
            }
        })
    }

    pub(super) async fn stop_components(&self) {
        self.vpn_portal.stop().await;
        self.public_ipv6_provider.stop().await;
        self.dhcp_ipv4.stop().await;
        self.proxy_cidr_monitor.stop().await;
        if let Some(listener) = &self.listener {
            listener.stop().await;
        }
        self.udp_hole_punch.stop().await;
        self.udp_hole_punch_started.store(false, Ordering::Release);
        self.smoltcp_gateway.stop().await;
        self.wrapped_transport.stop().await;
        self.packet_proxy.stop().await;
        self.manual.stop().await;
        self.tcp_hole_punch.stop().await;
        self.direct.stop().await;
        self.peer_center.stop().await;
        self.peer_center_started.store(false, Ordering::Release);
        self.peer_manager.clear_resources().await;
        if let Some(packet_egress) = &self.packet_egress {
            packet_egress.stop().await;
        }
    }

    pub(super) async fn start_listener(&self) -> anyhow::Result<()> {
        let Some(listener) = &self.listener else {
            return Ok(());
        };
        tokio::select! {
            _ = self.cancel.cancelled() => Err(anyhow::anyhow!("listener start cancelled")),
            result = listener.start() => result,
        }
    }

    async fn run_startup_transaction<Start, StartFuture, Rollback, RollbackFuture>(
        self: &Arc<Self>,
        cancel_message: &'static str,
        start: Start,
        rollback: Rollback,
    ) -> anyhow::Result<()>
    where
        Start: FnOnce() -> StartFuture,
        StartFuture: Future<Output = anyhow::Result<()>>,
        Rollback: FnOnce() -> RollbackFuture,
        RollbackFuture: Future<Output = ()>,
    {
        let mut recovery = self.recovery_guard();
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => Err(anyhow::anyhow!(cancel_message)),
            result = start() => result,
        };
        let error = match start_result {
            Err(error) => Some(error),
            Ok(()) if self.cancel.is_cancelled() => Some(anyhow::anyhow!(cancel_message)),
            Ok(()) => None,
        };

        if let Some(error) = error {
            rollback().await;
            recovery.disarm();
            return Err(error);
        }

        recovery.disarm();
        Ok(())
    }

    pub async fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Created {
            anyhow::bail!("core instance cannot start from state {state:?}");
        }

        self.public_ipv6_provider.validate_before_start().await?;

        self.set_state(CoreInstanceState::Starting);
        let mut recovery = self.recovery_guard();

        let start_result: anyhow::Result<()> = async {
            self.start_listener().await?;
            if let Some(packet_egress) = &self.packet_egress {
                packet_egress.start()?;
            }
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    Err(anyhow::anyhow!("core instance start cancelled"))
                }
                result = self.peer_manager.run() => result.map_err(anyhow::Error::from),
            }?;
            if self.cancel.is_cancelled() {
                anyhow::bail!("core instance start cancelled");
            }
            Ok(())
        }
        .await;
        if let Err(error) = start_result {
            self.stop_components().await;
            self.set_state(CoreInstanceState::Stopped);
            recovery.disarm();
            return Err(error);
        }

        self.direct.run();
        self.tcp_hole_punch.run();
        self.manual.start();

        self.set_state(CoreInstanceState::Running);
        self.public_ipv6_provider.start().await;
        recovery.disarm();
        Ok(())
    }

    /// Starts the portable runtime and lets the Host prepare its concrete
    /// Instance resources before network-facing services are activated.
    pub async fn start_managed(self: &Arc<Self>) -> anyhow::Result<()> {
        self.latest_error.write().take();
        let result = async {
            self.start().await?;
            let dhcp_host = self.instance_runtime.prepare(self.packet_plane()).await?;
            self.start_after_host_ready(dhcp_host).await
        }
        .await;
        if let Err(error) = &result {
            self.latest_error.write().replace(format!("{error:#}"));
            self.stop().await;
        }
        result
    }

    pub(super) async fn start_udp_hole_punch(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("UDP hole punching cannot start from core instance state {state:?}");
        }
        if self.udp_hole_punch_started.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut recovery = self.recovery_guard();
        self.udp_hole_punch_started.store(true, Ordering::Release);
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => {
                Err(anyhow::anyhow!("UDP hole punching start cancelled"))
            }
            result = self.udp_hole_punch.start() => result,
        };
        if let Err(error) = start_result {
            self.udp_hole_punch.stop().await;
            self.udp_hole_punch_started.store(false, Ordering::Release);
            recovery.disarm();
            return Err(error);
        }
        recovery.disarm();
        Ok(())
    }

    pub(super) async fn start_peer_center(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("peer center cannot start from core instance state {state:?}");
        }
        if self.peer_center_started.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("peer center start cancelled");
        }

        self.peer_center.init().await;
        self.peer_manager
            .get_route()
            .set_route_cost_fn(self.peer_center.get_cost_calculator())
            .await;
        self.peer_center_started.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) async fn start_initial_peers(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("initial peers cannot start from core instance state {state:?}");
        }
        if !self.peer_center_started.load(Ordering::Acquire) {
            anyhow::bail!("initial peers cannot start before peer center");
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("initial peer start cancelled");
        }
        if self.initial_peers_started.load(Ordering::Acquire) {
            return Ok(());
        }

        for url in &self.initial_peers {
            if self.cancel.is_cancelled() {
                anyhow::bail!("initial peer start cancelled");
            }
            self.manual.add_connector(url.clone())?;
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("initial peer start cancelled");
        }
        self.initial_peers_started.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) async fn start_transport_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("transport proxy cannot start from core instance state {state:?}");
        }
        if !self.wrapped_transport.is_available() {
            return Ok(());
        }
        self.run_startup_transaction(
            "transport proxy start cancelled",
            || self.wrapped_transport.start(),
            || self.wrapped_transport.stop(),
        )
        .await
    }

    /// Starts proxy services after the host has prepared its packet interface.
    pub(super) async fn start_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy services cannot start from core instance state {state:?}");
        }
        if self.packet_proxy.is_started() {
            return Ok(());
        }
        let config = self.runtime_config.snapshot();
        let has_proxy_networks = !config.peer.runtime.core.routes.proxy_networks.is_empty();
        if !config.services.proxy.should_start(has_proxy_networks) {
            return Ok(());
        }

        self.run_startup_transaction(
            "proxy service start cancelled",
            || self.packet_proxy.start(),
            || self.packet_proxy.stop(),
        )
        .await
    }

    /// Starts the core-owned services that run after the host has prepared its
    /// packet interface.
    pub(super) async fn start_network_services(
        self: &Arc<Self>,
        dhcp_ipv4_host: Option<Arc<dyn DhcpIpv4Host>>,
    ) -> anyhow::Result<()> {
        self.dhcp_ipv4.start(self, dhcp_ipv4_host).await?;
        self.refresh_proxy_cidr_table().await?;
        self.start_transport_proxy().await?;
        self.load_initial_acl().await?;
        self.start_proxy().await?;
        self.start_udp_hole_punch().await?;
        self.start_peer_center().await?;
        self.start_initial_peers().await?;
        self.proxy_cidr_monitor.start(self).await?;
        self.start_vpn_portal().await?;
        Ok(())
    }

    /// Completes startup after the host packet interface is ready. Core owns
    /// the service order and rolls back the whole instance on partial failure.
    pub async fn start_after_host_ready(
        self: &Arc<Self>,
        dhcp_ipv4_host: Option<Arc<dyn DhcpIpv4Host>>,
    ) -> anyhow::Result<()> {
        let result = async {
            self.start_network_services(dhcp_ipv4_host).await?;
            if self.startup_plan.gateway {
                self.start_gateway().await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            self.stop().await;
            return Err(error);
        }
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) async fn start_vpn_portal(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("VPN portal cannot start from core instance state {state:?}");
        }
        if !self.vpn_portal.is_available() {
            return Ok(());
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("VPN portal start cancelled");
        }
        self.run_startup_transaction(
            "VPN portal start cancelled",
            || self.vpn_portal.start(),
            || self.vpn_portal.stop(),
        )
        .await
    }

    pub(super) async fn start_gateway(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("gateway cannot start from core instance state {state:?}");
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("gateway start cancelled");
        }
        self.run_startup_transaction(
            "gateway start cancelled",
            || self.smoltcp_gateway.start(&self.runtime_config),
            || self.smoltcp_gateway.stop(),
        )
        .await
    }

    pub async fn stop(self: &Arc<Self>) {
        self.cancel.cancel();
        self.ready.store(false, Ordering::Release);
        let mut recovery = self.recovery_guard();
        let _operation = self.operation.lock().await;
        match self.state() {
            CoreInstanceState::Stopped => {
                self.set_state(CoreInstanceState::Stopped);
                recovery.disarm();
                return;
            }
            CoreInstanceState::Created
            | CoreInstanceState::Starting
            | CoreInstanceState::Running
            | CoreInstanceState::Stopping => {
                self.set_state(CoreInstanceState::Stopping);
            }
        }

        self.stop_components().await;
        self.instance_runtime.shutdown().await;
        self.set_state(CoreInstanceState::Stopped);
        recovery.disarm();
    }
}
