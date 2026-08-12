//! Serial start/stop orchestration for `CoreInstance`.
//!
//! Each runtime Module owns its internal resources. `CoreInstance` only
//! chooses their composition order and provides one outer cancellation and
//! cleanup path.

use std::sync::{Arc, Weak};

#[cfg(feature = "dhcp-ipv4")]
use crate::gateway::dhcp::{DhcpIpv4Host, DhcpIpv4RouteSource};

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

    async fn start_listener(&self) -> anyhow::Result<()> {
        match &self.listener {
            Some(listener) => listener.start().await,
            None => Ok(()),
        }
    }

    #[cfg(feature = "dhcp-ipv4")]
    async fn start_dhcp_ipv4(&self, host: Option<Arc<dyn DhcpIpv4Host>>) -> anyhow::Result<()> {
        if !self.runtime_config.snapshot().services.dhcp_ipv4 {
            return Ok(());
        }
        let host = host.ok_or_else(|| {
            anyhow::anyhow!("DHCP IPv4 is enabled but no host adapter was provided")
        })?;
        let route_source: Arc<dyn DhcpIpv4RouteSource> = self.peer_manager.clone();
        self.dhcp_ipv4
            .start(route_source, self.runtime_config.clone(), host)
            .await;
        Ok(())
    }

    #[cfg(feature = "proxy-packet")]
    async fn start_packet_proxy(&self) -> anyhow::Result<()> {
        let config = self.runtime_config.snapshot();
        let has_proxy_networks = !config.peer.runtime.core.routes.proxy_networks.is_empty();
        if config.services.proxy.should_start(has_proxy_networks) {
            self.packet_proxy
                .start()
                .await
                .map_err(anyhow::Error::new)?;
        }
        Ok(())
    }

    async fn start_components(&self) -> anyhow::Result<()> {
        #[cfg(feature = "public-ipv6-provider")]
        self.public_ipv6_provider.validate_before_start().await?;
        self.peer_manager
            .get_route()
            .set_route_cost_fn(self.peer_center.get_cost_calculator())
            .await;

        self.start_listener().await?;
        let packet_receiver = self
            .packet_receiver
            .lock()
            .await
            .take()
            .ok_or_else(|| anyhow::anyhow!("packet egress is one-shot and already started"))?;
        self.packet_egress.start(packet_receiver).await?;
        self.peer_manager.run().await.map_err(anyhow::Error::from)?;
        self.direct.run();
        #[cfg(feature = "tcp-hole-punch")]
        self.tcp_hole_punch.run();
        self.manual.start();
        #[cfg(feature = "public-ipv6-provider")]
        self.public_ipv6_provider.start().await;

        let dhcp_host = self.instance_runtime.prepare(self.packet_plane()).await?;
        #[cfg(feature = "dhcp-ipv4")]
        self.start_dhcp_ipv4(dhcp_host).await?;
        #[cfg(not(feature = "dhcp-ipv4"))]
        let _ = dhcp_host;
        #[cfg(feature = "wrapped-transport")]
        if let Some(wrapped_transport) = &self.wrapped_transport {
            wrapped_transport.start().await?;
        }
        #[cfg(feature = "proxy-packet")]
        self.start_packet_proxy().await?;
        self.udp_hole_punch.start().await?;
        self.peer_center.init().await;
        #[cfg(feature = "proxy-cidr-monitor")]
        self.proxy_cidr_monitor
            .start(&self.peer_manager, self.runtime_config.clone())
            .await;
        #[cfg(feature = "vpn-portal")]
        self.vpn_portal.start().await?;
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.data_plane_runtime.start_runtime().await?;
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.data_plane_session
            .start()
            .map_err(anyhow::Error::new)?;
        #[cfg(feature = "proxy-smoltcp-stack")]
        if self.startup_plan.gateway {
            self.socks5_adapter.start().await?;
            self.port_forward_adapter.start().await?;
        }
        Ok(())
    }

    async fn stop_components(&self) {
        #[cfg(feature = "vpn-portal")]
        self.vpn_portal.stop().await;
        #[cfg(feature = "public-ipv6-provider")]
        self.public_ipv6_provider.stop().await;
        #[cfg(feature = "dhcp-ipv4")]
        self.dhcp_ipv4.stop().await;
        #[cfg(feature = "proxy-cidr-monitor")]
        self.proxy_cidr_monitor.stop().await;
        if let Some(listener) = &self.listener {
            listener.stop().await;
        }
        self.udp_hole_punch.stop().await;
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.port_forward_adapter.stop().await;
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.socks5_adapter.stop().await;
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.data_plane_session.stop();
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.data_plane_runtime.stop_runtime().await;
        #[cfg(feature = "wrapped-transport")]
        if let Some(wrapped_transport) = &self.wrapped_transport {
            wrapped_transport.stop().await;
        }
        #[cfg(feature = "proxy-packet")]
        self.packet_proxy.stop().await;
        self.manual.stop().await;
        #[cfg(feature = "tcp-hole-punch")]
        self.tcp_hole_punch.stop().await;
        self.direct.stop().await;
        self.peer_center.stop().await;

        // Host packet tasks can still call the packet plane, so stop them
        // before clearing PeerManager resources.
        self.instance_runtime.shutdown().await;
        self.peer_manager.clear_resources().await;
        self.packet_egress.stop().await;
    }

    /// Starts the complete instance through one serial composition path.
    pub async fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Created {
            anyhow::bail!("core instance cannot start from state {state:?}");
        }

        self.latest_error.write().take();
        self.set_state(CoreInstanceState::Starting);
        let mut recovery = self.recovery_guard();
        let result = tokio::select! {
            _ = self.cancel.cancelled() => {
                Err(anyhow::anyhow!("core instance start cancelled"))
            }
            result = self.start_components() => result,
        };
        let result = match result {
            Ok(()) => {
                self.set_state(CoreInstanceState::Running);
                if self.cancel.is_cancelled() {
                    Err(anyhow::anyhow!("core instance start cancelled"))
                } else {
                    Ok(())
                }
            }
            Err(error) => Err(error),
        };

        if let Err(error) = result {
            self.latest_error.write().replace(format!("{error:#}"));
            self.cancel.cancel();
            self.set_state(CoreInstanceState::Stopping);
            self.stop_components().await;
            self.set_state(CoreInstanceState::Stopped);
            recovery.disarm();
            return Err(error);
        }

        recovery.disarm();
        Ok(())
    }

    pub async fn stop(self: &Arc<Self>) {
        self.cancel.cancel();
        let mut recovery = self.recovery_guard();
        let _operation = self.operation.lock().await;
        if self.state() == CoreInstanceState::Stopped {
            recovery.disarm();
            return;
        }

        self.set_state(CoreInstanceState::Stopping);
        self.stop_components().await;
        self.set_state(CoreInstanceState::Stopped);
        recovery.disarm();
    }
}
