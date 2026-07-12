//! Host network facts and slow operations used by connector orchestration.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    connectivity::{
        host::{DirectConnectorEnvironment, ManualConnectorEnvironment},
        manual::ManualInterfaceAddrs,
    },
    hole_punch::tcp::TcpHolePunchEnvironment,
    proto::{common::NatType, peer_rpc::GetIpListResponse},
    socket::{host::udp::HostUdpSocket, udp::PreferredIpv6Source},
};

/// Host-observed facts consumed by core connector policy.
///
/// The host may replace this snapshot when interfaces, STUN results, mapped
/// listeners, or protected addresses change. Core owns all selection and
/// connection policy applied to these facts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostConnectorEnvironmentSnapshot {
    pub public_ipv4: Option<Ipv4Addr>,
    pub interface_ipv4s: Vec<Ipv4Addr>,
    pub public_ipv6: Option<Ipv6Addr>,
    pub interface_ipv6s: Vec<Ipv6Addr>,
    pub mapped_listeners: Vec<Url>,
    pub running_listeners: Vec<Url>,
    pub local_ips: Vec<IpAddr>,
    pub protected_tcp_ports: Vec<u16>,
    pub stun_public_ips: Vec<IpAddr>,
    pub managed_ipv6s: Vec<Ipv6Addr>,
    pub preferred_ipv6_sources: Vec<PreferredIpv6Source>,
    pub tcp_nat_type: NatType,
}

impl HostConnectorEnvironmentSnapshot {
    fn ip_list(&self) -> GetIpListResponse {
        GetIpListResponse {
            public_ipv4: self.public_ipv4.map(Into::into),
            interface_ipv4s: self
                .interface_ipv4s
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            public_ipv6: self.public_ipv6.map(Into::into),
            interface_ipv6s: self
                .interface_ipv6s
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            listeners: Default::default(),
        }
    }

    fn manual_interface_addrs(&self) -> ManualInterfaceAddrs {
        ManualInterfaceAddrs {
            interface_ipv4s: self.interface_ipv4s.clone(),
            interface_ipv6s: self.interface_ipv6s.clone(),
            public_ipv6: self.public_ipv6,
        }
    }
}

/// Slow or socket-specific system operations below connector policy.
#[async_trait]
pub trait HostConnectorEnvironmentServices: Send + Sync + 'static {
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr>;

    async fn udp_port_mapping(&self, socket: Arc<HostUdpSocket>) -> anyhow::Result<SocketAddr>;

    async fn tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr>;
}

/// Adapts an atomically replaceable host snapshot and slow host services to
/// the connector capability interfaces.
pub struct HostConnectorEnvironment<S> {
    snapshot: ArcSwap<HostConnectorEnvironmentSnapshot>,
    services: Arc<S>,
}

impl<S> HostConnectorEnvironment<S> {
    pub fn new(snapshot: HostConnectorEnvironmentSnapshot, services: Arc<S>) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(snapshot),
            services,
        }
    }

    pub fn update_snapshot(&self, snapshot: HostConnectorEnvironmentSnapshot) {
        self.snapshot.store(Arc::new(snapshot));
    }

    pub fn snapshot(&self) -> Arc<HostConnectorEnvironmentSnapshot> {
        self.snapshot.load_full()
    }
}

#[async_trait]
impl<S> ManualConnectorEnvironment for HostConnectorEnvironment<S>
where
    S: HostConnectorEnvironmentServices,
{
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr> {
        self.services.local_addr_for_remote(remote_addr).await
    }

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
        Ok(self.snapshot().manual_interface_addrs())
    }
}

#[async_trait]
impl<S> DirectConnectorEnvironment for HostConnectorEnvironment<S>
where
    S: HostConnectorEnvironmentServices,
{
    async fn collect_ip_addrs(&self) -> anyhow::Result<GetIpListResponse> {
        Ok(self.snapshot().ip_list())
    }

    fn mapped_listeners(&self) -> Vec<Url> {
        self.snapshot().mapped_listeners.clone()
    }

    fn running_listeners(&self) -> Vec<Url> {
        self.snapshot().running_listeners.clone()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.snapshot().local_ips.contains(ip)
    }

    fn is_protected_tcp_port(&self, port: u16) -> bool {
        self.snapshot().protected_tcp_ports.contains(&port)
    }

    fn stun_public_ips(&self) -> Vec<IpAddr> {
        self.snapshot().stun_public_ips.clone()
    }

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool {
        self.snapshot().managed_ipv6s.contains(ip)
    }

    async fn udp_port_mapping(&self, socket: Arc<HostUdpSocket>) -> anyhow::Result<SocketAddr> {
        self.services.udp_port_mapping(socket).await
    }

    async fn preferred_ipv6_source(&self, ip: Ipv6Addr) -> Option<PreferredIpv6Source> {
        self.snapshot()
            .preferred_ipv6_sources
            .iter()
            .find(|source| source.ip == ip)
            .copied()
    }
}

#[async_trait]
impl<S> TcpHolePunchEnvironment for HostConnectorEnvironment<S>
where
    S: HostConnectorEnvironmentServices,
{
    fn tcp_nat_type(&self) -> NatType {
        self.snapshot().tcp_nat_type
    }

    async fn tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
        self.services.tcp_port_mapping(local_port).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use crate::socket::udp::VirtualUdpSocket;

    use super::*;

    struct RecordingServices {
        local_requests: Mutex<Vec<SocketAddr>>,
        tcp_mapping_requests: Mutex<Vec<u16>>,
    }

    #[async_trait]
    impl HostConnectorEnvironmentServices for RecordingServices {
        async fn local_addr_for_remote(
            &self,
            remote_addr: SocketAddr,
        ) -> anyhow::Result<SocketAddr> {
            self.local_requests.lock().unwrap().push(remote_addr);
            Ok("192.0.2.1:40100".parse().unwrap())
        }

        async fn udp_port_mapping(&self, socket: Arc<HostUdpSocket>) -> anyhow::Result<SocketAddr> {
            Ok(SocketAddr::new(
                "198.51.100.1".parse().unwrap(),
                socket.local_addr()?.port(),
            ))
        }

        async fn tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
            self.tcp_mapping_requests.lock().unwrap().push(local_port);
            Ok(SocketAddr::new("198.51.100.2".parse().unwrap(), local_port))
        }
    }

    fn snapshot() -> HostConnectorEnvironmentSnapshot {
        HostConnectorEnvironmentSnapshot {
            public_ipv4: Some("198.51.100.1".parse().unwrap()),
            interface_ipv4s: vec!["192.0.2.1".parse().unwrap()],
            public_ipv6: Some("2001:db8::1".parse().unwrap()),
            interface_ipv6s: vec!["2001:db8::2".parse().unwrap()],
            mapped_listeners: vec!["tcp://198.51.100.1:11010".parse().unwrap()],
            running_listeners: vec!["udp://[::]:11010".parse().unwrap()],
            local_ips: vec!["192.0.2.1".parse().unwrap()],
            protected_tcp_ports: vec![11010],
            stun_public_ips: vec!["198.51.100.1".parse().unwrap()],
            managed_ipv6s: vec!["fd00::1".parse().unwrap()],
            preferred_ipv6_sources: vec![PreferredIpv6Source {
                ip: "2001:db8::2".parse().unwrap(),
                ifindex: 7,
            }],
            tcp_nat_type: NatType::Symmetric,
        }
    }

    #[tokio::test]
    async fn projects_snapshot_and_delegates_slow_operations() {
        let initial_snapshot = snapshot();
        assert_eq!(
            serde_json::from_slice::<HostConnectorEnvironmentSnapshot>(
                &serde_json::to_vec(&initial_snapshot).unwrap()
            )
            .unwrap(),
            initial_snapshot
        );
        let services = Arc::new(RecordingServices {
            local_requests: Mutex::new(Vec::new()),
            tcp_mapping_requests: Mutex::new(Vec::new()),
        });
        let environment = HostConnectorEnvironment::new(initial_snapshot, services.clone());

        let remote = "203.0.113.1:11010".parse().unwrap();
        assert_eq!(
            environment.local_addr_for_remote(remote).await.unwrap(),
            "192.0.2.1:40100".parse().unwrap()
        );
        assert_eq!(*services.local_requests.lock().unwrap(), vec![remote]);
        assert_eq!(
            environment.interface_addrs().await.unwrap().public_ipv6,
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            environment
                .collect_ip_addrs()
                .await
                .unwrap()
                .interface_ipv4s,
            vec![Ipv4Addr::new(192, 0, 2, 1).into()]
        );
        assert!(environment.is_local_ip(&"192.0.2.1".parse().unwrap()));
        assert!(environment.is_protected_tcp_port(11010));
        assert!(environment.is_easytier_managed_ipv6(&"fd00::1".parse().unwrap()));
        assert_eq!(environment.tcp_nat_type(), NatType::Symmetric);
        assert_eq!(
            environment
                .preferred_ipv6_source("2001:db8::2".parse().unwrap())
                .await,
            Some(PreferredIpv6Source {
                ip: "2001:db8::2".parse().unwrap(),
                ifindex: 7,
            })
        );
        assert_eq!(
            environment.tcp_port_mapping(42000).await.unwrap(),
            "198.51.100.2:42000".parse().unwrap()
        );
        assert_eq!(*services.tcp_mapping_requests.lock().unwrap(), vec![42000]);

        let mut updated = snapshot();
        updated.protected_tcp_ports = vec![22020];
        environment.update_snapshot(updated);
        assert!(!environment.is_protected_tcp_port(11010));
        assert!(environment.is_protected_tcp_port(22020));
    }
}
