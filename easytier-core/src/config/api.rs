//! Portable conversion between the shared TOML model and management schema.

use easytier_proto::api::manage::{
    self, NetworkConfig, NetworkingMethod, PortForwardConfig as ApiPortForwardConfig,
};

use optionize::Optionizable as _;

use super::{
    api_input::set_network_flags,
    toml::{ConfigLoader as _, TomlConfig},
};

pub fn network_config_from_toml(config: &TomlConfig) -> NetworkConfig {
    let default_config = TomlConfig::default();
    let mut result = NetworkConfig {
        instance_id: Some(config.get_id().to_string()),
        dhcp: Some(config.get_dhcp()),
        ..Default::default()
    };

    if config.get_hostname() != default_config.get_hostname() {
        result.hostname = Some(config.get_hostname());
    }

    let network_identity = config.get_network_identity();
    result.network_name = Some(network_identity.network_name);
    result.network_secret = network_identity.network_secret;

    if let Some(ipv4) = config.get_ipv4() {
        result.virtual_ipv4 = Some(ipv4.address().to_string());
        result.network_length = Some(ipv4.network_length() as i32);
    }

    if config.get_ipv6_public_addr_provider() != default_config.get_ipv6_public_addr_provider() {
        result.ipv6_public_addr_provider = Some(config.get_ipv6_public_addr_provider());
    }
    if config.get_ipv6_public_addr_auto() != default_config.get_ipv6_public_addr_auto() {
        result.ipv6_public_addr_auto = Some(config.get_ipv6_public_addr_auto());
    }
    result.ipv6_public_addr_prefix = config
        .get_ipv6_public_addr_prefix()
        .map(|prefix| prefix.to_string());

    let peers = config.get_peers();
    result.networking_method = Some(NetworkingMethod::Manual as i32);
    if !peers.is_empty() {
        result.peer_urls = peers.iter().map(|peer| peer.uri.to_string()).collect();
        result.peers = peers
            .iter()
            .map(|peer| manage::NetworkPeerConfig {
                uri: peer.uri.to_string(),
                peer_public_key: peer.peer_public_key.clone(),
            })
            .collect();
    }

    result.listener_urls = config
        .get_listeners()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect();
    result.proxy_cidrs = config
        .get_proxy_cidrs()
        .iter()
        .map(|proxy| match proxy.mapped_cidr {
            Some(mapped) => format!("{}->{}", proxy.cidr, mapped),
            None => proxy.cidr.to_string(),
        })
        .collect();

    let port_forwards = config.get_port_forwards();
    if !port_forwards.is_empty() {
        result.port_forwards = port_forwards
            .iter()
            .map(|forward| ApiPortForwardConfig {
                proto: forward.proto.clone(),
                bind_ip: forward.bind_addr.ip().to_string(),
                bind_port: forward.bind_addr.port() as u32,
                dst_ip: forward.dst_addr.ip().to_string(),
                dst_port: forward.dst_addr.port() as u32,
            })
            .collect();
    }

    if let Some(vpn_config) = config.get_vpn_portal_config() {
        result.vpn_portal_config = Some(manage::VpnPortalConfig {
            wireguard_listen: vpn_config.wireguard_listen.to_string(),
            wireguard_private_key: vpn_config.wireguard_private_key,
            clients: vpn_config
                .clients
                .into_iter()
                .map(|client| manage::VpnPortalClientConfig {
                    name: client.name,
                    virtual_ip: client.virtual_ip.to_string(),
                    groups: client.groups,
                })
                .collect(),
        });
    }

    if let Some(routes) = config.get_routes()
        && !routes.is_empty()
    {
        result.enable_manual_routes = Some(true);
        result.routes = routes.iter().map(ToString::to_string).collect();
    }
    let exit_nodes = config.get_exit_nodes();
    if !exit_nodes.is_empty() {
        result.exit_nodes = exit_nodes.iter().map(ToString::to_string).collect();
    }
    if let Some(socks5_portal) = config.get_socks5_portal() {
        result.enable_socks5 = Some(true);
        result.socks5_port = socks5_portal.port().map(|port| port as i32);
    }
    let mapped_listeners = config.get_mapped_listeners();
    if !mapped_listeners.is_empty() {
        result.mapped_listeners = mapped_listeners.iter().map(ToString::to_string).collect();
    }

    result.secure_mode = config.get_secure_mode();
    result.credential_file = config
        .get_credential_file()
        .map(|path| path.to_string_lossy().into_owned());
    result.managed_credentials = config
        .get_managed_credentials()
        .into_iter()
        .map(|credential| credential.downgrade())
        .collect();

    set_network_flags(&mut result, config.get_flags_patch());
    result.acl = config.get_acl();

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::toml::ManagedCredentialConfig;

    #[test]
    fn includes_managed_credentials() {
        let config = TomlConfig::default();
        config.set_managed_credentials(vec![ManagedCredentialConfig {
            credential_id: "managed-a".to_owned(),
            credential_secret: "credential-secret".to_owned(),
            groups: vec!["ops".to_owned()],
            allow_relay: true,
            allowed_proxy_cidrs: vec!["10.0.0.0/24".to_owned()],
            expiry_unix: 2_000_000_000,
            reusable: false,
        }]);

        let projected = network_config_from_toml(&config);

        assert_eq!(
            projected.managed_credentials,
            vec![manage::ManagedCredentialConfig {
                credential_id: "managed-a".to_owned(),
                credential_secret: "credential-secret".to_owned(),
                groups: vec!["ops".to_owned()],
                allow_relay: true,
                allowed_proxy_cidrs: vec!["10.0.0.0/24".to_owned()],
                expiry_unix: 2_000_000_000,
                reusable: Some(false),
            }]
        );
    }
}
