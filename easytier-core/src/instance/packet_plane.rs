use std::{collections::BTreeSet, net::IpAddr, sync::Arc};

use async_trait::async_trait;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    foundation::stats::{LabelSet, LabelType, MetricName},
    magic_dns::{MagicDnsRouteSnapshot, MagicDnsRouteSource},
    peers::peer_manager::PeerManagerCore,
    proxy::cidr_monitor::{ProxyCidrDiff, collect_proxy_cidr_diff},
};

#[cfg(feature = "proxy-packet")]
use crate::magic_dns::{MagicDnsQueryResolver, magic_dns_packet_filter};

#[cfg(feature = "proxy-packet")]
use super::MagicDnsResolverRegistration;
use super::{UdpBroadcastRelayStats, packet_io::parse_ip_packet};

/// Stable packet- and route-plane projection for platform integrations.
pub struct CorePacketPlane {
    peer_manager: Arc<PeerManagerCore>,
    runtime_config: CoreRuntimeConfigStore,
    proxy_cidr_monitor_available: bool,
}

impl CorePacketPlane {
    pub(super) fn new(
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        proxy_cidr_monitor_available: bool,
    ) -> Self {
        Self {
            peer_manager,
            runtime_config,
            proxy_cidr_monitor_available,
        }
    }

    pub async fn send_ip_packet(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        let meta = parse_ip_packet(&packet)?;
        let source_is_local = self.peer_manager.is_local_virtual_ip(&meta.source);
        if matches!(meta.source, IpAddr::V6(ip) if ip.is_unicast_link_local()) && !source_is_local {
            return Ok(());
        }
        self.peer_manager
            .send_msg_by_ip(
                crate::packet::ZCPacket::new_with_payload(&packet),
                meta.destination,
                source_is_local,
            )
            .await
            .map_err(Into::into)
    }

    pub async fn send_local_ip_packet(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        let destination = parse_ip_packet(&packet)?.destination;
        self.peer_manager
            .send_msg_by_ip(
                crate::packet::ZCPacket::new_with_payload(&packet),
                destination,
                true,
            )
            .await
            .map_err(Into::into)
    }

    pub async fn proxy_cidr_diff(
        &self,
        previous: &BTreeSet<cidr::Ipv4Cidr>,
    ) -> Option<ProxyCidrDiff> {
        if !self.proxy_cidr_monitor_available {
            return None;
        }
        Some(
            collect_proxy_cidr_diff(self.peer_manager.as_ref(), &self.runtime_config, previous)
                .await,
        )
    }

    pub async fn public_ipv6_routes(&self) -> BTreeSet<cidr::Ipv6Inet> {
        self.peer_manager.list_public_ipv6_routes().await
    }

    pub async fn public_ipv6_addr(&self) -> Option<cidr::Ipv6Inet> {
        self.peer_manager.public_ipv6_addr().await
    }

    pub fn udp_broadcast_relay_stats(&self) -> UdpBroadcastRelayStats {
        let network_name = self
            .runtime_config
            .snapshot()
            .peer
            .runtime
            .network_identity
            .network_name
            .clone();
        let labels = LabelSet::new().with_label_type(LabelType::NetworkName(network_name));
        let stats = self.peer_manager.stats_manager();
        UdpBroadcastRelayStats {
            packets_captured: stats
                .get_counter(MetricName::UdpBroadcastRelayPacketsCaptured, labels.clone()),
            packets_ignored: stats
                .get_counter(MetricName::UdpBroadcastRelayPacketsIgnored, labels.clone()),
            packets_forwarded: stats.get_counter(
                MetricName::UdpBroadcastRelayPacketsForwarded,
                labels.clone(),
            ),
            packets_forward_failed: stats
                .get_counter(MetricName::UdpBroadcastRelayPacketsForwardFailed, labels),
        }
    }

    #[cfg(feature = "proxy-packet")]
    pub async fn register_magic_dns_resolver(
        &self,
        fake_ip: std::net::Ipv4Addr,
        resolver: Arc<dyn MagicDnsQueryResolver>,
    ) -> MagicDnsResolverRegistration {
        let runtime = tokio::runtime::Handle::current();
        let pipeline = self
            .peer_manager
            .add_managed_nic_packet_process_pipeline(magic_dns_packet_filter(
                fake_ip,
                self.peer_manager.my_peer_id(),
                resolver,
            ))
            .await;
        MagicDnsResolverRegistration {
            peer_manager: Arc::downgrade(&self.peer_manager),
            pipeline,
            runtime,
        }
    }
}

#[async_trait]
impl MagicDnsRouteSource for CorePacketPlane {
    async fn snapshot(&self) -> MagicDnsRouteSnapshot {
        MagicDnsRouteSource::snapshot(self.peer_manager.as_ref()).await
    }

    async fn revision(&self) -> quanta::Instant {
        MagicDnsRouteSource::revision(self.peer_manager.as_ref()).await
    }
}
