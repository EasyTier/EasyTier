//! Portable normalization from typed instance configuration values.

use crate::{
    config::{EncryptionAlgorithm, InstanceConfig, toml::Flags},
    connectivity::manual::discovery::ManualEndpointDiscoveryConfig,
    packet::CompressorAlgo,
    tunnel::encrypt::algorithm_is_available,
};
use easytier_proto::common::CompressionAlgoPb;

pub use crate::config::peers::HostRoutingPolicy;
pub use crate::instance::CoreConnectivityMode;

/// Host facts and policy that cannot be derived from the shared TOML model.
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
    pub proxy_enabled: bool,
    pub vpn_portal_enabled: bool,
    pub magic_dns_enabled: bool,
    pub kcp_enabled: bool,
    pub quic_enabled: bool,
    pub udp_broadcast_enabled: bool,
    pub upnp_enabled: bool,
    pub tcp_hole_punching_enabled: bool,
    pub ignore_unsupported_config: bool,
    pub connectivity: CoreConnectivityMode,
    pub direct_testing: bool,
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
            proxy_enabled: true,
            vpn_portal_enabled: true,
            magic_dns_enabled: true,
            kcp_enabled: true,
            quic_enabled: true,
            udp_broadcast_enabled: true,
            upnp_enabled: true,
            tcp_hole_punching_enabled: true,
            ignore_unsupported_config: false,
            connectivity: CoreConnectivityMode::Full,
            direct_testing: false,
            easytier_version: env!("CARGO_PKG_VERSION").to_owned(),
            endpoint_protocols: ManualEndpointDiscoveryConfig::default().srv_protocols,
        }
    }
}

impl CoreInstanceHostConfig {
    pub(crate) fn accepts_runtime_url(&self, url: &url::Url) -> bool {
        !self.ignore_unsupported_config
            || self
                .endpoint_protocols
                .iter()
                .any(|scheme| scheme.eq_ignore_ascii_case(url.scheme()))
    }

    pub(crate) fn runtime_flags(&self, mut flags: Flags) -> Flags {
        if !self.ignore_unsupported_config {
            return flags;
        }

        if !self.smoltcp_available {
            flags.no_tun = false;
            flags.use_smoltcp = false;
        }
        if !self.proxy_enabled {
            flags.enable_exit_node = false;
        }
        if !self.magic_dns_enabled {
            flags.accept_dns = false;
        }
        if !self.kcp_enabled {
            flags.enable_kcp_proxy = false;
            flags.disable_kcp_input = true;
            flags.disable_relay_kcp = true;
            flags.enable_relay_foreign_network_kcp = false;
        }
        if !self.quic_enabled {
            flags.enable_quic_proxy = false;
            flags.disable_quic_input = true;
            flags.disable_relay_quic = true;
            flags.enable_relay_foreign_network_quic = false;
        }
        if !self.udp_broadcast_enabled {
            flags.enable_udp_broadcast_relay = false;
        }
        if !self.upnp_enabled {
            flags.disable_upnp = true;
        }
        if !self.tcp_hole_punching_enabled {
            flags.disable_tcp_hole_punching = true;
        }
        if CompressionAlgoPb::try_from(flags.data_compress_algo)
            .ok()
            .and_then(|algorithm| CompressorAlgo::try_from(algorithm).ok())
            .is_some_and(|algorithm| !algorithm.is_available())
        {
            flags.data_compress_algo = CompressionAlgoPb::None as i32;
        }

        if flags
            .encryption_algorithm
            .parse::<EncryptionAlgorithm>()
            .is_ok_and(|algorithm| !algorithm_is_available(algorithm))
            && algorithm_is_available(EncryptionAlgorithm::AesGcm)
        {
            flags.encryption_algorithm = EncryptionAlgorithm::AesGcm.to_string();
        }

        flags
    }
}

/// Normalizes the typed configuration values with explicit Host facts and policy.
pub fn prepare_instance_config(
    config: InstanceConfig,
    host: &CoreInstanceHostConfig,
) -> anyhow::Result<InstanceConfig> {
    let raw = config.raw().clone();
    let mut parsed = config.into_parsed();

    if parsed.hostname.is_empty()
        && let Some(fallback) = &host.hostname_fallback
    {
        parsed.hostname = fallback.clone();
    }

    parsed.flags = host.runtime_flags(parsed.flags);

    if !parsed.managed_credentials.is_empty() && parsed.network_identity.network_secret.is_none() {
        anyhow::bail!("only admin nodes with a network_secret can configure managed credentials");
    }

    if let Some(listeners) = &mut parsed.listeners {
        listeners.retain(|url| host.accepts_runtime_url(url));
    }
    parsed
        .peer
        .retain(|peer| host.accepts_runtime_url(&peer.uri));

    if host.ignore_unsupported_config {
        if !host.proxy_enabled {
            parsed.proxy_network.clear();
            parsed.exit_nodes.clear();
        }
        if !host.gateway_enabled {
            parsed.port_forward.clear();
            parsed.socks5_proxy = None;
        }
        if !host.vpn_portal_enabled {
            parsed.vpn_portal_config = None;
        }
        if !host.public_ipv6_provider_supported {
            parsed.ipv6_public_addr_auto = false;
            parsed.ipv6_public_addr_provider = false;
            parsed.ipv6_public_addr_prefix = None;
        }
    }

    Ok(InstanceConfig::new(parsed, raw, ()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InstanceConfigParsed;

    #[test]
    fn host_config_normalizes_hostname_and_filters_unsupported_when_requested() {
        let mut raw = crate::config::parse_instance_config(
            "test",
            r#"
listeners = ["tcp://127.0.0.1:11010", "quic://127.0.0.1:11011"]
proxy_network = [{ cidr = "10.20.0.0/16" }]

[[peer]]
uri = "tcp://127.0.0.1:11010"

[[peer]]
uri = "quic://127.0.0.1:11011"

[flags]
enable_exit_node = true
enable_kcp_proxy = true
accept_dns = true
"#,
        )
        .unwrap()
        .into_raw();
        raw.exit_nodes = Some(vec!["10.144.144.2".parse().unwrap()]);
        raw.ipv6_public_addr_provider = Some(true);
        let config = InstanceConfig::try_from(raw).unwrap();

        let host = CoreInstanceHostConfig {
            hostname_fallback: Some("fallback-host".to_owned()),
            ignore_unsupported_config: true,
            smoltcp_available: true,
            proxy_enabled: false,
            gateway_enabled: false,
            public_ipv6_provider_supported: false,
            magic_dns_enabled: false,
            kcp_enabled: false,
            quic_enabled: false,
            endpoint_protocols: vec!["tcp".to_owned(), "udp".to_owned()],
            ..Default::default()
        };

        let prepared = prepare_instance_config(config, &host).unwrap();
        assert_eq!(prepared.hostname, "fallback-host");
        assert_eq!(prepared.listeners.as_ref().unwrap().len(), 1);
        assert_eq!(prepared.peer.len(), 1);
        assert!(prepared.proxy_network.is_empty());
        assert!(prepared.exit_nodes.is_empty());
        assert!(!prepared.flags.enable_exit_node);
        assert!(!prepared.flags.enable_kcp_proxy);
        assert!(prepared.flags.disable_kcp_input);
        assert!(!prepared.flags.accept_dns);
        assert!(!prepared.ipv6_public_addr_provider);
    }

    #[test]
    fn managed_credentials_require_network_secret() {
        let mut parsed = InstanceConfigParsed {
            network_identity: crate::config::NetworkIdentity {
                network_name: "test".to_string(),
                network_secret: None,
                network_secret_digest: None,
            },
            managed_credentials: vec![crate::config::toml::ManagedCredentialConfig {
                credential_id: "alice".to_string(),
                credential_secret: "secret".to_string(),
                groups: vec!["admin".to_string()],
                allow_relay: false,
                allowed_proxy_cidrs: Vec::new(),
                expiry_unix: 0,
                reusable: true,
            }],
            ..Default::default()
        };
        parsed.network_identity.network_secret = None;
        let config = InstanceConfig::from_parsed(parsed);

        let host = CoreInstanceHostConfig::default();
        let result = prepare_instance_config(config, &host);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only admin nodes with a network_secret")
        );
    }
}
