use easytier_core::{
    config::toml::{ConfigLoader as _, TomlConfig},
    instance::{RuntimeConfigProjection, RuntimeConfigProjector},
};
use easytier_proto::common::CompressionAlgoPb;
use url::Url;

use crate::common::config::EncryptionAlgorithm;

/// Projects full EasyTier configurations onto the compact native feature set.
#[derive(Default)]
pub struct CompactRuntimeConfigProjector;

impl CompactRuntimeConfigProjector {
    fn supports_url(url: &Url) -> bool {
        matches!(url.scheme(), "tcp" | "udp")
    }

    fn suppress(suppressions: &mut Vec<&'static str>, changed: bool, capability: &'static str) {
        if changed && !suppressions.contains(&capability) {
            suppressions.push(capability);
        }
    }
}

impl RuntimeConfigProjector for CompactRuntimeConfigProjector {
    fn project(&self, authoritative: &TomlConfig) -> anyhow::Result<RuntimeConfigProjection> {
        let effective = authoritative.detached_snapshot();
        let mut suppressions = Vec::new();

        let listeners = authoritative.get_listener_uris();
        let supported_listeners = listeners
            .iter()
            .filter(|url| Self::supports_url(url))
            .cloned()
            .collect::<Vec<_>>();
        Self::suppress(
            &mut suppressions,
            supported_listeners.len() != listeners.len(),
            "non-TCP/UDP listeners",
        );
        effective.set_listeners(supported_listeners);

        let mapped_listeners = authoritative.get_mapped_listeners();
        let supported_mapped_listeners = mapped_listeners
            .iter()
            .filter(|url| Self::supports_url(url))
            .cloned()
            .collect::<Vec<_>>();
        Self::suppress(
            &mut suppressions,
            supported_mapped_listeners.len() != mapped_listeners.len(),
            "non-TCP/UDP mapped listeners",
        );
        effective.set_mapped_listeners(
            (!supported_mapped_listeners.is_empty()).then_some(supported_mapped_listeners),
        );

        let peers = authoritative.get_peers();
        let supported_peers = peers
            .iter()
            .filter(|peer| Self::supports_url(&peer.uri))
            .cloned()
            .collect::<Vec<_>>();
        Self::suppress(
            &mut suppressions,
            supported_peers.len() != peers.len(),
            "non-TCP/UDP peers",
        );
        effective.set_peers(supported_peers);

        let gateway_requested = authoritative.get_dhcp()
            || authoritative.get_vpn_portal_config().is_some()
            || authoritative.get_socks5_portal().is_some()
            || !authoritative.get_port_forwards().is_empty()
            || !authoritative.get_proxy_cidrs().is_empty()
            || !authoritative.get_exit_nodes().is_empty();
        Self::suppress(
            &mut suppressions,
            gateway_requested,
            "gateway, proxy, and VPN services",
        );
        effective.set_dhcp(false);
        effective.clear_vpn_portal_config();
        effective.set_socks5_portal(None);
        effective.set_port_forwards(Vec::new());
        effective.clear_proxy_cidrs();
        effective.set_exit_nodes(Vec::new());

        let public_ipv6_requested = authoritative.get_ipv6_public_addr_provider()
            || authoritative.get_ipv6_public_addr_auto()
            || authoritative.get_ipv6_public_addr_prefix().is_some();
        Self::suppress(
            &mut suppressions,
            public_ipv6_requested,
            "public IPv6 provider",
        );
        effective.set_ipv6_public_addr_provider(false);
        effective.set_ipv6_public_addr_auto(false);
        effective.set_ipv6_public_addr_prefix(None);

        let mut flags = authoritative.get_flags();
        Self::suppress(
            &mut suppressions,
            flags.no_tun || flags.use_smoltcp || flags.enable_exit_node,
            "userspace gateway mode",
        );
        flags.no_tun = false;
        flags.use_smoltcp = false;
        flags.enable_exit_node = false;

        Self::suppress(&mut suppressions, flags.accept_dns, "Magic DNS");
        flags.accept_dns = false;

        let wrapped_transport_requested = flags.enable_kcp_proxy
            || !flags.disable_kcp_input
            || !flags.disable_relay_kcp
            || flags.enable_relay_foreign_network_kcp
            || flags.enable_quic_proxy
            || !flags.disable_quic_input
            || !flags.disable_relay_quic
            || flags.enable_relay_foreign_network_quic;
        Self::suppress(
            &mut suppressions,
            wrapped_transport_requested,
            "KCP and QUIC transports",
        );
        flags.enable_kcp_proxy = false;
        flags.disable_kcp_input = true;
        flags.disable_relay_kcp = true;
        flags.enable_relay_foreign_network_kcp = false;
        flags.enable_quic_proxy = false;
        flags.disable_quic_input = true;
        flags.disable_relay_quic = true;
        flags.enable_relay_foreign_network_quic = false;

        Self::suppress(
            &mut suppressions,
            flags.enable_udp_broadcast_relay,
            "UDP broadcast relay",
        );
        flags.enable_udp_broadcast_relay = false;

        Self::suppress(
            &mut suppressions,
            !flags.disable_upnp || !flags.disable_tcp_hole_punching,
            "UPnP and TCP hole punching",
        );
        flags.disable_upnp = true;
        flags.disable_tcp_hole_punching = true;

        Self::suppress(
            &mut suppressions,
            flags.socket_mark.is_some(),
            "socket mark",
        );
        flags.socket_mark = None;

        Self::suppress(
            &mut suppressions,
            flags.data_compress_algo != CompressionAlgoPb::None as i32,
            "data compression",
        );
        flags.data_compress_algo = CompressionAlgoPb::None as i32;

        if flags
            .encryption_algorithm
            .parse::<EncryptionAlgorithm>()
            .is_ok_and(|algorithm| algorithm == EncryptionAlgorithm::ChaCha20)
        {
            Self::suppress(&mut suppressions, true, "ChaCha20 encryption");
            flags.encryption_algorithm = EncryptionAlgorithm::AesGcm.to_string();
        }
        effective.set_flags(flags);

        Self::suppress(
            &mut suppressions,
            authoritative.get_credential_file().is_some(),
            "credential-file persistence",
        );
        effective.set_credential_file(None);

        Ok(RuntimeConfigProjection {
            effective_config: effective,
            suppressed_capabilities: suppressions,
        })
    }

    fn project_connector(&self, connector: &Url) -> Option<Url> {
        Self::supports_url(connector).then(|| connector.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_is_detached_and_preserves_authoritative_configuration() {
        let authoritative = TomlConfig::new_from_str(
            r#"
listeners = ["tcp://127.0.0.1:11010", "quic://127.0.0.1:11011"]
proxy_network = [{ cidr = "10.20.0.0/16" }]

[flags]
encryption_algorithm = "chacha20"
data_compress_algo = "Zstd"
"#,
        )
        .unwrap();
        let before = authoritative.dump();

        let projection = CompactRuntimeConfigProjector
            .project(&authoritative)
            .unwrap();

        assert_eq!(authoritative.dump(), before);
        assert_eq!(projection.effective_config.get_listener_uris().len(), 1);
        assert!(projection.effective_config.get_proxy_cidrs().is_empty());
        let flags = projection.effective_config.get_flags();
        assert_eq!(flags.encryption_algorithm, "aes-gcm");
        assert_eq!(flags.data_compress_algo, CompressionAlgoPb::None as i32);
        assert!(flags.disable_upnp);
        assert!(flags.disable_tcp_hole_punching);
        assert!(
            projection
                .suppressed_capabilities
                .contains(&"UPnP and TCP hole punching")
        );
    }
}
