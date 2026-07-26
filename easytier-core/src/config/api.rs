//! Portable conversion between the shared TOML model and management schema.

use easytier_proto::api::manage::{
    self, NetworkConfig, NetworkingMethod, PortForwardConfig as ApiPortForwardConfig,
};

use super::toml::{ConfigLoader as _, TomlConfig};

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
        result.enable_vpn_portal = Some(true);
        result.vpn_portal_client_network_addr =
            Some(vpn_config.client_cidr.first_address().to_string());
        result.vpn_portal_client_network_len = Some(vpn_config.client_cidr.network_length() as i32);
        result.vpn_portal_listen_port = Some(vpn_config.wireguard_listen.port() as i32);
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

    let flags = config.get_flags();
    let default_flags = default_config.get_flags();
    result.latency_first = Some(flags.latency_first);
    result.dev_name = Some(flags.dev_name.clone());
    result.use_smoltcp = Some(flags.use_smoltcp);
    result.disable_ipv6 = Some(!flags.enable_ipv6);
    result.enable_kcp_proxy = Some(flags.enable_kcp_proxy);
    result.disable_kcp_input = Some(flags.disable_kcp_input);
    result.enable_quic_proxy = Some(flags.enable_quic_proxy);
    result.disable_quic_input = Some(flags.disable_quic_input);
    result.disable_p2p = Some(flags.disable_p2p);
    result.p2p_only = Some(flags.p2p_only);
    result.lazy_p2p = Some(flags.lazy_p2p);
    result.bind_device = Some(flags.bind_device);
    result.socket_mark = flags.socket_mark;
    result.no_tun = Some(flags.no_tun);
    result.enable_exit_node = Some(flags.enable_exit_node);
    result.relay_all_peer_rpc = Some(flags.relay_all_peer_rpc);
    result.need_p2p = Some(flags.need_p2p);
    result.multi_thread = Some(flags.multi_thread);
    result.proxy_forward_by_system = Some(flags.proxy_forward_by_system);
    result.disable_encryption = Some(!flags.enable_encryption);
    result.disable_tcp_hole_punching = Some(flags.disable_tcp_hole_punching);
    result.disable_udp_hole_punching = Some(flags.disable_udp_hole_punching);
    result.disable_upnp = Some(flags.disable_upnp);
    result.disable_relay_data = Some(flags.disable_relay_data);
    result.enable_udp_broadcast_relay = Some(flags.enable_udp_broadcast_relay);
    result.disable_sym_hole_punching = Some(flags.disable_sym_hole_punching);
    result.enable_magic_dns = Some(flags.accept_dns);
    result.mtu = Some(flags.mtu as i32);
    result.data_compress_algo = (flags.data_compress_algo != default_flags.data_compress_algo)
        .then_some(flags.data_compress_algo);
    result.encryption_algorithm = (flags.encryption_algorithm
        != default_flags.encryption_algorithm)
        .then_some(flags.encryption_algorithm);
    result.instance_recv_bps_limit =
        (flags.instance_recv_bps_limit != u64::MAX).then_some(flags.instance_recv_bps_limit);
    result.enable_private_mode = Some(flags.private_mode);
    result.acl = config.get_acl();

    if flags.relay_network_whitelist == "*" {
        result.enable_relay_network_whitelist = Some(false);
    } else {
        result.enable_relay_network_whitelist = Some(true);
        result.relay_network_whitelist = flags
            .relay_network_whitelist
            .split_whitespace()
            .map(ToOwned::to_owned)
            .collect();
    }

    result
}
