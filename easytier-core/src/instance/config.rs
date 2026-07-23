//! Portable normalization from the shared TOML model into one core instance.

use std::collections::BTreeSet;

use crate::{
    config::{
        IpPrefix, NodeConfig, ProxyNetworkConfig, RouteConfig,
        gateway::{GatewayRuntimeConfig, ProxyRuntimeConfig},
        peers::{AclRuleConfig, HostRoutingPolicy, PublicIpv6ProviderConfig},
        runtime::CoreRuntimeConfig,
        toml::{ConfigLoader as _, TomlConfig},
    },
    connectivity::{
        direct::DirectConnectorOptions,
        manual::{ManualConnectorOptions, discovery::ManualEndpointDiscoveryConfig},
        stun::StunServerConfig,
    },
    listener::plan::ListenerRuntimeConfig,
    peers::{
        context::PeerRuntimeSnapshotInput,
        peer_manager::{PortablePeerManagerConfig, RouteAlgoType},
    },
    socket::{NetNamespace, SocketContext, tcp::TcpBindOptions, udp::UdpBindOptions},
};

use super::{CoreConnectivityConfig, CoreInstanceConfig};

const OSPF_UPDATE_MY_FOREIGN_NETWORK_INTERVAL_SEC: u64 = 10;
const MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK: usize = 3;

/// Host facts and policy that cannot be derived from the shared TOML model.
///
/// This input deliberately contains no routes, ACL, peer, gateway, listener,
/// or other portable configuration. Core combines it with TOML through one
/// normalization path for both initial construction and runtime patching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreInstanceHostConfig {
    pub hostname_fallback: Option<String>,
    pub host_routing: HostRoutingPolicy,
    pub force_exit_node: bool,
    pub allow_interface_bind: bool,
    pub smoltcp_available: bool,
    pub requires_smoltcp: bool,
    pub icmp_failure_is_fatal: bool,
    pub public_ipv6_provider_supported: bool,
    pub gateway_enabled: bool,
    pub easytier_version: String,
    pub endpoint_protocols: Vec<String>,
}

impl Default for CoreInstanceHostConfig {
    fn default() -> Self {
        Self {
            hostname_fallback: None,
            host_routing: HostRoutingPolicy::default(),
            force_exit_node: false,
            allow_interface_bind: true,
            smoltcp_available: false,
            requires_smoltcp: false,
            icmp_failure_is_fatal: false,
            public_ipv6_provider_supported: false,
            gateway_enabled: true,
            easytier_version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint_protocols: ManualEndpointDiscoveryConfig::default().srv_protocols,
        }
    }
}

impl CoreInstanceConfig {
    /// Normalizes the complete shared TOML model using OS-independent defaults.
    ///
    /// A Host may still project runtime facts such as a fallback hostname or
    /// platform capability after parsing, but it does not need another network
    /// configuration schema.
    pub fn from_toml(config: &TomlConfig) -> anyhow::Result<Self> {
        Self::from_toml_with_host(config, &CoreInstanceHostConfig::default())
    }

    /// Normalizes TOML with explicit Host facts and policy.
    pub fn from_toml_with_host(
        config: &TomlConfig,
        host: &CoreInstanceHostConfig,
    ) -> anyhow::Result<Self> {
        let flags = config.get_flags();
        let instance_id = config.get_id();
        let identity: crate::config::NetworkIdentity = config.get_network_identity().into();
        let network_name = identity.network_name.clone();
        let socket_context = SocketContext::default()
            .with_socket_mark(flags.socket_mark)
            .with_netns(config.get_netns().map(NetNamespace::new));
        let hostname = match config.get_hostname() {
            hostname if !hostname.is_empty() => hostname,
            _ => host.hostname_fallback.clone().unwrap_or_default(),
        };
        let acl = config.get_acl();

        let peer_snapshot =
            crate::config::peers::PeerRuntimeSnapshot::from_host_input(PeerRuntimeSnapshotInput {
                node: NodeConfig {
                    peer_id: None,
                    instance_id: Some(*instance_id.as_bytes()),
                    hostname: (!hostname.is_empty()).then_some(hostname),
                    network_name: network_name.clone(),
                },
                routes: RouteConfig {
                    ipv4: config.get_ipv4().map(|value| IpPrefix {
                        address: value.address().into(),
                        prefix_len: value.network_length(),
                    }),
                    ipv6: config.get_ipv6().map(|value| IpPrefix {
                        address: value.address().into(),
                        prefix_len: value.network_length(),
                    }),
                    proxy_networks: config
                        .get_proxy_cidrs()
                        .into_iter()
                        .map(|proxy| ProxyNetworkConfig {
                            real: IpPrefix {
                                address: proxy.cidr.first_address().into(),
                                prefix_len: proxy.cidr.network_length(),
                            },
                            mapped: proxy.mapped_cidr.map(|mapped| IpPrefix {
                                address: mapped.first_address().into(),
                                prefix_len: mapped.network_length(),
                            }),
                        })
                        .collect(),
                    ..Default::default()
                },
                network_identity: identity,
                stun_info: Default::default(),
                flags: flags.clone(),
                secure_mode: config.get_secure_mode(),
                host_routing: host.host_routing,
                acl: acl.clone(),
                easytier_version: host.easytier_version.clone(),
                vpn_portal_cidr: config
                    .get_vpn_portal_config()
                    .map(|portal| portal.client_cidr),
                pinned_peers: config
                    .get_peers()
                    .into_iter()
                    .map(|peer| (peer.uri, peer.peer_public_key))
                    .collect(),
                ospf_update_my_foreign_network_interval_sec:
                    OSPF_UPDATE_MY_FOREIGN_NETWORK_INTERVAL_SEC,
                max_direct_conns_per_peer_in_foreign_network:
                    MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK,
                hmac_secret_digest: false,
            });
        let peer = PortablePeerManagerConfig {
            snapshot: peer_snapshot,
            route_algo: RouteAlgoType::Ospf,
            exit_nodes: config.get_exit_nodes(),
            foreign_context_default_flags: TomlConfig::default().get_flags(),
        };

        let tcp_bind = TcpBindOptions::default().with_context(socket_context.clone());
        let udp_bind = UdpBindOptions::direct_connect().with_context(socket_context.clone());
        let listeners = Some(ListenerRuntimeConfig::new(
            config.get_listener_uris(),
            flags.enable_ipv6,
            socket_context.clone(),
        ));
        let socks5_bind = config
            .get_socks5_portal()
            .map(|url| {
                let host = url
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("SOCKS5 portal host is missing"))?;
                let port = url
                    .port()
                    .ok_or_else(|| anyhow::anyhow!("SOCKS5 portal port is missing"))?;
                format!("{host}:{port}")
                    .parse()
                    .map_err(|error| anyhow::anyhow!("invalid SOCKS5 portal address: {error}"))
            })
            .transpose()?;
        let runtime = CoreRuntimeConfig {
            acl: AclRuleConfig {
                acl,
                tcp_whitelist: config.get_tcp_whitelist(),
                udp_whitelist: config.get_udp_whitelist(),
                whitelist_priority: None,
            },
            dhcp_ipv4: config.get_dhcp(),
            gateway: GatewayRuntimeConfig {
                socks5_bind,
                port_forwards: config.get_port_forwards(),
            },
            manual_routes: config
                .get_routes()
                .map(|routes| routes.into_iter().collect::<BTreeSet<_>>()),
            proxy: ProxyRuntimeConfig {
                enable_exit_node: flags.enable_exit_node || host.force_exit_node,
                no_tun: flags.no_tun,
                forward_by_system: flags.proxy_forward_by_system,
                force_smoltcp: host.smoltcp_available
                    && (flags.use_smoltcp || flags.no_tun || host.requires_smoltcp),
                icmp_failure_is_fatal: host.icmp_failure_is_fatal,
                udp_response_ipv4_mtu: 1280,
            },
            public_ipv6_auto: config.get_ipv6_public_addr_auto(),
            public_ipv6_provider: PublicIpv6ProviderConfig {
                provider_enabled: config.get_ipv6_public_addr_provider(),
                configured_prefix: config.get_ipv6_public_addr_prefix(),
                provider_supported: host.public_ipv6_provider_supported,
            },
        };

        Ok(Self {
            instance_name: config.get_inst_name(),
            peer,
            connectivity: CoreConnectivityConfig {
                initial_peers: config
                    .get_peers()
                    .into_iter()
                    .map(|peer| peer.uri)
                    .collect(),
                listeners,
                runtime,
                startup_plan: super::CoreInstanceStartupPlan {
                    gateway: host.gateway_enabled,
                },
                stun: StunServerConfig {
                    udp_servers: config
                        .get_stun_servers()
                        .unwrap_or_else(|| StunServerConfig::default().udp_servers),
                    udp_v6_servers: config
                        .get_stun_servers_v6()
                        .unwrap_or_else(|| StunServerConfig::default().udp_v6_servers),
                    ..StunServerConfig::default()
                },
                endpoint_discovery: ManualEndpointDiscoveryConfig {
                    user_agent: format!("easytier/{}", host.easytier_version),
                    network_name: network_name.clone(),
                    http_tcp_bind: tcp_bind.clone(),
                    dns_record_context: socket_context,
                    srv_protocols: host.endpoint_protocols.clone(),
                    ..Default::default()
                },
                manual: ManualConnectorOptions {
                    bind_device: flags.bind_device,
                    allow_interface_bind: host.allow_interface_bind,
                    tcp_bind: tcp_bind.clone(),
                    udp_bind: udp_bind.clone(),
                    ..Default::default()
                },
                direct: DirectConnectorOptions {
                    network_name,
                    default_protocol: flags.default_protocol,
                    enable_ipv6: flags.enable_ipv6,
                    allow_public_server: true,
                    lazy_p2p: flags.lazy_p2p,
                    disable_p2p: flags.disable_p2p,
                    need_p2p: flags.need_p2p,
                    bind_device: flags.bind_device,
                    allow_interface_bind: host.allow_interface_bind,
                    tcp_bind,
                    udp_bind,
                    testing: false,
                },
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_toml_normalizes_instance_identity_and_connectivity() {
        let config = TomlConfig::new_from_str(
            r#"
instance_id = "018f4fb1-7a2c-7d1f-9d89-935b0ad7e135"
instance_name = "wasi-test"
hostname = "portable-host"
ipv4 = "10.144.0.2/24"
listeners = ["tcp://0.0.0.0:11010"]

[[peer]]
uri = "tcp://127.0.0.1:11010"

[network_identity]
network_name = "portable"
network_secret = "secret"

[flags]
disable_p2p = true
"#,
        )
        .unwrap();

        let normalized = CoreInstanceConfig::from_toml(&config).unwrap();
        assert_eq!(normalized.instance_name, "wasi-test");
        assert_eq!(
            normalized.peer.snapshot.runtime.core.node.instance_id,
            Some(*config.get_id().as_bytes())
        );
        assert_eq!(normalized.peer.snapshot.runtime.core.node.peer_id, None);
        assert_eq!(
            normalized
                .peer
                .snapshot
                .runtime
                .core
                .node
                .hostname
                .as_deref(),
            Some("portable-host")
        );
        assert_eq!(
            normalized.peer.snapshot.runtime.core.node.network_name,
            "portable"
        );
        assert_eq!(normalized.connectivity.initial_peers.len(), 1);
        assert_eq!(
            normalized
                .connectivity
                .listeners
                .as_ref()
                .unwrap()
                .urls
                .len(),
            1
        );
        assert!(normalized.connectivity.direct.disable_p2p);
    }

    #[test]
    fn host_config_supplies_only_platform_policy() {
        let config = TomlConfig::default();
        let host = CoreInstanceHostConfig {
            hostname_fallback: Some("host-fallback".to_owned()),
            host_routing: HostRoutingPolicy {
                local_exit_node_fallback: true,
            },
            force_exit_node: true,
            allow_interface_bind: false,
            smoltcp_available: true,
            requires_smoltcp: true,
            icmp_failure_is_fatal: true,
            public_ipv6_provider_supported: true,
            gateway_enabled: false,
            easytier_version: "host-version".to_owned(),
            endpoint_protocols: vec!["host-protocol".to_owned()],
        };

        let normalized = CoreInstanceConfig::from_toml_with_host(&config, &host).unwrap();

        assert_eq!(
            normalized
                .peer
                .snapshot
                .runtime
                .core
                .node
                .hostname
                .as_deref(),
            Some("host-fallback")
        );
        assert!(
            normalized
                .peer
                .snapshot
                .runtime
                .host_routing
                .local_exit_node_fallback
        );
        assert_eq!(normalized.peer.snapshot.easytier_version, "host-version");
        assert!(normalized.connectivity.runtime.proxy.enable_exit_node);
        assert!(normalized.connectivity.runtime.proxy.force_smoltcp);
        assert!(normalized.connectivity.runtime.proxy.icmp_failure_is_fatal);
        assert!(
            normalized
                .connectivity
                .runtime
                .public_ipv6_provider
                .provider_supported
        );
        assert!(!normalized.connectivity.startup_plan.gateway);
        assert!(!normalized.connectivity.manual.allow_interface_bind);
        assert!(!normalized.connectivity.direct.allow_interface_bind);
        assert_eq!(
            normalized.connectivity.endpoint_discovery.srv_protocols,
            ["host-protocol"]
        );
    }
}
