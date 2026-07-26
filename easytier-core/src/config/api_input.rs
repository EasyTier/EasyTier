//! Conversion between the management NetworkConfig schema and shared TOML.

use std::net::SocketAddr;

use anyhow::Context;
use easytier_proto::api::manage;

use crate::config::{
    MappedListenerPolicy, normalize_secure_mode_config,
    toml::{
        ConfigLoader, NetworkIdentity, PeerConfig, PortForwardConfig, TomlConfigLoader,
        VpnPortalConfig, gen_default_flags,
    },
};

fn parse_mapped_listener_urls(mapped_listeners: &[String]) -> Result<Vec<url::Url>, anyhow::Error> {
    MappedListenerPolicy::new(["tcp", "udp", "wg", "quic", "ws", "wss", "faketcp"])
        .parse_urls(mapped_listeners)
}

pub fn add_proxy_network_to_config(
    proxy_network: &str,
    cfg: &TomlConfigLoader,
) -> Result<(), anyhow::Error> {
    let parts: Vec<&str> = proxy_network.split("->").collect();
    let real_cidr = parts[0]
        .parse()
        .with_context(|| format!("failed to parse proxy network: {}", parts[0]))?;

    if parts.len() > 2 {
        return Err(anyhow::anyhow!(
                    "invalid proxy network format: {}, support format: <real_cidr> or <real_cidr>-><mapped_cidr>, example:
                    10.0.0.0/24 or 10.0.0.0/24->192.168.0.0/24",
                    proxy_network
                ));
    }

    let mapped_cidr = if parts.len() == 2 {
        Some(
            parts[1]
                .parse()
                .with_context(|| format!("failed to parse mapped network: {}", parts[1]))?,
        )
    } else {
        None
    };
    cfg.add_proxy_cidr(real_cidr, mapped_cidr)?;
    Ok(())
}

pub type NetworkingMethod = easytier_proto::api::manage::NetworkingMethod;
pub type NetworkConfig = easytier_proto::api::manage::NetworkConfig;

pub trait NetworkConfigExt {
    fn gen_config(&self) -> Result<TomlConfigLoader, anyhow::Error>;
    fn new_from_config(config: impl ConfigLoader) -> Result<NetworkConfig, anyhow::Error>;
}

fn parse_peer(peer: &manage::NetworkPeerConfig) -> Result<Option<PeerConfig>, anyhow::Error> {
    let uri = peer.uri.trim();
    if uri.is_empty() {
        return Ok(None);
    }

    Ok(Some(PeerConfig {
        uri: uri
            .parse()
            .with_context(|| format!("failed to parse peer uri: {}", uri))?,
        peer_public_key: peer.peer_public_key.clone(),
    }))
}

fn parse_peers(peers: &[manage::NetworkPeerConfig]) -> Result<Vec<PeerConfig>, anyhow::Error> {
    let mut ret = Vec::new();
    for peer in peers {
        if let Some(peer) = parse_peer(peer)? {
            ret.push(peer);
        }
    }
    Ok(ret)
}

fn parse_peer_urls(peer_urls: &[String]) -> Result<Vec<PeerConfig>, anyhow::Error> {
    let mut peers = vec![];
    for peer_url in peer_urls.iter() {
        let peer_url = peer_url.trim();
        if peer_url.is_empty() {
            continue;
        }
        peers.push(PeerConfig {
            uri: peer_url
                .parse()
                .with_context(|| format!("failed to parse peer uri: {}", peer_url))?,
            peer_public_key: None,
        });
    }
    Ok(peers)
}

impl NetworkConfigExt for NetworkConfig {
    fn gen_config(&self) -> Result<TomlConfigLoader, anyhow::Error> {
        let cfg = TomlConfigLoader::default();
        cfg.set_id(
            self.instance_id
                .clone()
                .unwrap_or(uuid::Uuid::new_v4().to_string())
                .parse()
                .with_context(|| format!("failed to parse instance id: {:?}", self.instance_id))?,
        );
        cfg.set_hostname(self.hostname.clone());
        cfg.set_dhcp(self.dhcp.unwrap_or_default());
        cfg.set_inst_name(self.network_name.clone().unwrap_or_default());

        // The web UI does not expose credential inputs directly, but imported/saved
        // NetworkConfig objects still need to preserve credential-mode instances via
        // secure_mode.local_private_key + empty network_secret.
        let credential_secret = if self.network_secret.is_some() {
            None
        } else {
            self.secure_mode
                .as_ref()
                .and_then(|mode| mode.local_private_key.clone())
                .filter(|s| !s.is_empty())
        };

        if credential_secret.is_some() {
            cfg.set_network_identity(NetworkIdentity::new_credential(
                self.network_name.clone().unwrap_or_default(),
            ));
        } else {
            cfg.set_network_identity(NetworkIdentity::new(
                self.network_name.clone().unwrap_or_default(),
                self.network_secret.clone().unwrap_or_default(),
            ));
        }

        if !cfg.get_dhcp() {
            let virtual_ipv4 = self.virtual_ipv4.clone().unwrap_or_default();
            if !virtual_ipv4.is_empty() {
                let ip = format!("{}/{}", virtual_ipv4, self.network_length.unwrap_or(24))
                    .parse()
                    .with_context(|| {
                        format!(
                            "failed to parse ipv4 inet address: {}, {:?}",
                            virtual_ipv4, self.network_length
                        )
                    })?;
                cfg.set_ipv4(Some(ip));
            }
        }

        match NetworkingMethod::try_from(self.networking_method.unwrap_or_default())
            .unwrap_or_default()
        {
            NetworkingMethod::PublicServer => {
                let peers = parse_peers(&self.peers)?;
                if peers.is_empty() {
                    let public_server_url = self.public_server_url.clone().unwrap_or_default();
                    cfg.set_peers(vec![PeerConfig {
                        uri: public_server_url.parse().with_context(|| {
                            format!("failed to parse public server uri: {}", public_server_url)
                        })?,
                        peer_public_key: None,
                    }]);
                } else {
                    cfg.set_peers(peers);
                }
            }
            NetworkingMethod::Manual => {
                let mut peers = parse_peers(&self.peers)?;
                if peers.is_empty() {
                    peers = parse_peer_urls(&self.peer_urls)?;
                }
                if !peers.is_empty() {
                    cfg.set_peers(peers);
                }
            }
            NetworkingMethod::Standalone => {}
        }

        let mut listener_urls = vec![];
        for listener_url in self.listener_urls.iter() {
            if listener_url.is_empty() {
                continue;
            }
            listener_urls.push(
                listener_url
                    .parse()
                    .with_context(|| format!("failed to parse listener uri: {}", listener_url))?,
            );
        }
        cfg.set_listeners(listener_urls);

        for n in self.proxy_cidrs.iter() {
            add_proxy_network_to_config(n, &cfg)?;
        }

        if !self.port_forwards.is_empty() {
            cfg.set_port_forwards(
                self.port_forwards
                    .iter()
                    .filter(|pf| !pf.bind_ip.is_empty() && !pf.dst_ip.is_empty())
                    .filter_map(|pf| {
                        let bind_addr =
                            format!("{}:{}", pf.bind_ip, pf.bind_port).parse::<SocketAddr>();
                        let dst_addr =
                            format!("{}:{}", pf.dst_ip, pf.dst_port).parse::<SocketAddr>();

                        match (bind_addr, dst_addr) {
                            (Ok(bind_addr), Ok(dst_addr)) => Some(PortForwardConfig {
                                bind_addr,
                                dst_addr,
                                proto: pf.proto.clone(),
                            }),
                            _ => None,
                        }
                    })
                    .collect::<Vec<_>>(),
            );
        }

        if self.enable_vpn_portal.unwrap_or_default() {
            let cidr = format!(
                "{}/{}",
                self.vpn_portal_client_network_addr
                    .clone()
                    .unwrap_or_default(),
                self.vpn_portal_client_network_len.unwrap_or(24)
            );
            cfg.set_vpn_portal_config(VpnPortalConfig {
                client_cidr: cidr
                    .parse()
                    .with_context(|| format!("failed to parse vpn portal client cidr: {}", cidr))?,
                wireguard_listen: format!(
                    "0.0.0.0:{}",
                    self.vpn_portal_listen_port.unwrap_or_default()
                )
                .parse()
                .with_context(|| {
                    format!(
                        "failed to parse vpn portal wireguard listen port. {:?}",
                        self.vpn_portal_listen_port
                    )
                })?,
            });
        }

        if self.enable_manual_routes.unwrap_or_default() {
            let mut routes = Vec::<cidr::Ipv4Cidr>::with_capacity(self.routes.len());
            for route in self.routes.iter() {
                routes.push(
                    route
                        .parse()
                        .with_context(|| format!("failed to parse route: {}", route))?,
                );
            }
            cfg.set_routes(Some(routes));
        }

        if !self.exit_nodes.is_empty() {
            let mut exit_nodes = Vec::<std::net::IpAddr>::with_capacity(self.exit_nodes.len());
            for node in self.exit_nodes.iter() {
                exit_nodes.push(
                    node.parse()
                        .with_context(|| format!("failed to parse exit node: {}", node))?,
                );
            }
            cfg.set_exit_nodes(exit_nodes);
        }

        if self.enable_socks5.unwrap_or_default()
            && let Some(socks5_port) = self.socks5_port
        {
            cfg.set_socks5_portal(Some(
                format!("socks5://0.0.0.0:{}", socks5_port).parse().unwrap(),
            ));
        }

        if !self.mapped_listeners.is_empty() {
            let mapped_listeners = parse_mapped_listener_urls(&self.mapped_listeners)?;
            cfg.set_mapped_listeners(Some(mapped_listeners));
        }

        if let Some(credential_file) = self
            .credential_file
            .as_ref()
            .filter(|path| !path.is_empty())
        {
            cfg.set_credential_file(Some(credential_file.into()));
        }

        if let Some(credential_secret) = credential_secret {
            cfg.set_secure_mode(Some(normalize_secure_mode_config(
                easytier_proto::common::SecureModeConfig {
                    enabled: true,
                    local_private_key: Some(credential_secret),
                    local_public_key: None,
                },
            )?));
        } else {
            cfg.set_secure_mode(
                self.secure_mode
                    .clone()
                    .map(normalize_secure_mode_config)
                    .transpose()?,
            );
        }

        let mut flags = gen_default_flags();
        if let Some(latency_first) = self.latency_first {
            flags.latency_first = latency_first;
        }

        if let Some(dev_name) = self.dev_name.clone() {
            flags.dev_name = dev_name;
        }

        if let Some(use_smoltcp) = self.use_smoltcp {
            flags.use_smoltcp = use_smoltcp;
        }

        if let Some(ipv6_public_addr_provider) = self.ipv6_public_addr_provider {
            cfg.set_ipv6_public_addr_provider(ipv6_public_addr_provider);
        }

        if let Some(ipv6_public_addr_auto) = self.ipv6_public_addr_auto {
            cfg.set_ipv6_public_addr_auto(ipv6_public_addr_auto);
        }

        if let Some(ipv6_public_addr_prefix) = self
            .ipv6_public_addr_prefix
            .as_ref()
            .filter(|prefix| !prefix.is_empty())
        {
            cfg.set_ipv6_public_addr_prefix(Some(ipv6_public_addr_prefix.parse().with_context(
                || format!("failed to parse ipv6 public address prefix: {ipv6_public_addr_prefix}"),
            )?));
        }

        if let Some(disable_ipv6) = self.disable_ipv6 {
            flags.enable_ipv6 = !disable_ipv6;
        }

        if let Some(enable_kcp_proxy) = self.enable_kcp_proxy {
            flags.enable_kcp_proxy = enable_kcp_proxy;
        }

        if let Some(disable_kcp_input) = self.disable_kcp_input {
            flags.disable_kcp_input = disable_kcp_input;
        }

        if let Some(enable_quic_proxy) = self.enable_quic_proxy {
            flags.enable_quic_proxy = enable_quic_proxy;
        }

        if let Some(disable_quic_input) = self.disable_quic_input {
            flags.disable_quic_input = disable_quic_input;
        }

        if let Some(disable_p2p) = self.disable_p2p {
            flags.disable_p2p = disable_p2p;
        }

        if let Some(p2p_only) = self.p2p_only {
            flags.p2p_only = p2p_only;
        }

        if let Some(lazy_p2p) = self.lazy_p2p {
            flags.lazy_p2p = lazy_p2p;
        }

        if let Some(bind_device) = self.bind_device {
            flags.bind_device = bind_device;
        }

        if self.socket_mark.is_some() {
            flags.socket_mark = self.socket_mark;
        }

        if let Some(no_tun) = self.no_tun {
            flags.no_tun = no_tun;
        }

        if let Some(enable_exit_node) = self.enable_exit_node {
            flags.enable_exit_node = enable_exit_node;
        }

        if let Some(relay_all_peer_rpc) = self.relay_all_peer_rpc {
            flags.relay_all_peer_rpc = relay_all_peer_rpc;
        }

        if let Some(need_p2p) = self.need_p2p {
            flags.need_p2p = need_p2p;
        }

        if let Some(multi_thread) = self.multi_thread {
            flags.multi_thread = multi_thread;
        }

        if let Some(proxy_forward_by_system) = self.proxy_forward_by_system {
            flags.proxy_forward_by_system = proxy_forward_by_system;
        }

        if let Some(disable_encryption) = self.disable_encryption {
            flags.enable_encryption = !disable_encryption;
        }

        if self.enable_relay_network_whitelist.unwrap_or_default() {
            if !self.relay_network_whitelist.is_empty() {
                flags.relay_network_whitelist = self.relay_network_whitelist.join(" ");
            } else {
                flags.relay_network_whitelist = "".to_string();
            }
        }

        if let Some(disable_tcp_hole_punching) = self.disable_tcp_hole_punching {
            flags.disable_tcp_hole_punching = disable_tcp_hole_punching;
        }

        if let Some(disable_udp_hole_punching) = self.disable_udp_hole_punching {
            flags.disable_udp_hole_punching = disable_udp_hole_punching;
        }

        if let Some(disable_upnp) = self.disable_upnp {
            flags.disable_upnp = disable_upnp;
        }

        if let Some(disable_relay_data) = self.disable_relay_data {
            flags.disable_relay_data = disable_relay_data;
        }

        if let Some(enable_udp_broadcast_relay) = self.enable_udp_broadcast_relay {
            flags.enable_udp_broadcast_relay = enable_udp_broadcast_relay;
        }

        if let Some(disable_sym_hole_punching) = self.disable_sym_hole_punching {
            flags.disable_sym_hole_punching = disable_sym_hole_punching;
        }

        if let Some(enable_magic_dns) = self.enable_magic_dns {
            flags.accept_dns = enable_magic_dns;
        }

        if let Some(mtu) = self.mtu {
            flags.mtu = mtu as u32;
        }

        if let Some(instance_recv_bps_limit) = self.instance_recv_bps_limit {
            flags.instance_recv_bps_limit = instance_recv_bps_limit;
        }

        if let Some(enable_private_mode) = self.enable_private_mode {
            flags.private_mode = enable_private_mode;
        }

        if let Some(encryption_algorithm) = self.encryption_algorithm.clone() {
            flags.encryption_algorithm = encryption_algorithm;
        }

        if let Some(acl) = self.acl.as_ref()
            && !acl.is_empty()
        {
            cfg.set_acl(Some(acl.clone()));
        }

        if let Some(data_compress_algo) = self.data_compress_algo {
            if data_compress_algo < 1 {
                flags.data_compress_algo = 1;
            } else {
                flags.data_compress_algo = data_compress_algo
            }
        }

        cfg.set_flags(flags);
        Ok(cfg)
    }

    fn new_from_config(config: impl ConfigLoader) -> Result<Self, anyhow::Error> {
        let default_config = TomlConfigLoader::default();

        let mut result = Self {
            ..Default::default()
        };

        result.instance_id = Some(config.get_id().to_string());
        if config.get_hostname() != default_config.get_hostname() {
            result.hostname = Some(config.get_hostname());
        }

        result.dhcp = Some(config.get_dhcp());

        let network_identity = config.get_network_identity();
        result.network_name = Some(network_identity.network_name.clone());
        result.network_secret = network_identity.network_secret;

        if let Some(ipv4) = config.get_ipv4() {
            result.virtual_ipv4 = Some(ipv4.address().to_string());
            result.network_length = Some(ipv4.network_length() as i32);
        }

        if config.get_ipv6_public_addr_provider() != default_config.get_ipv6_public_addr_provider()
        {
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
            result.peer_urls = peers.iter().map(|p| p.uri.to_string()).collect();
            result.peers = peers
                .iter()
                .map(|p| manage::NetworkPeerConfig {
                    uri: p.uri.to_string(),
                    peer_public_key: p.peer_public_key.clone(),
                })
                .collect();
        }

        result.listener_urls = config
            .get_listeners()
            .unwrap_or_default()
            .iter()
            .map(|l| l.to_string())
            .collect();

        result.proxy_cidrs = config
            .get_proxy_cidrs()
            .iter()
            .map(|c| {
                if let Some(mapped) = c.mapped_cidr {
                    format!("{}->{}", c.cidr, mapped)
                } else {
                    c.cidr.to_string()
                }
            })
            .collect();

        let port_forwards = config.get_port_forwards();
        if !port_forwards.is_empty() {
            result.port_forwards = port_forwards
                .iter()
                .map(|f| manage::PortForwardConfig {
                    proto: f.proto.clone(),
                    bind_ip: f.bind_addr.ip().to_string(),
                    bind_port: f.bind_addr.port() as u32,
                    dst_ip: f.dst_addr.ip().to_string(),
                    dst_port: f.dst_addr.port() as u32,
                })
                .collect();
        }

        if let Some(vpn_config) = config.get_vpn_portal_config() {
            result.enable_vpn_portal = Some(true);

            let cidr = vpn_config.client_cidr;
            result.vpn_portal_client_network_addr = Some(cidr.first_address().to_string());
            result.vpn_portal_client_network_len = Some(cidr.network_length() as i32);

            result.vpn_portal_listen_port = Some(vpn_config.wireguard_listen.port() as i32);
        }

        if let Some(routes) = config.get_routes()
            && !routes.is_empty()
        {
            result.enable_manual_routes = Some(true);
            result.routes = routes.iter().map(|r| r.to_string()).collect();
        }

        let exit_nodes = config.get_exit_nodes();
        if !exit_nodes.is_empty() {
            result.exit_nodes = exit_nodes.iter().map(|n| n.to_string()).collect();
        }

        if let Some(socks5_portal) = config.get_socks5_portal() {
            result.enable_socks5 = Some(true);
            result.socks5_port = socks5_portal.port().map(|p| p as i32);
        }

        let mapped_listeners = config.get_mapped_listeners();
        if !mapped_listeners.is_empty() {
            result.mapped_listeners = mapped_listeners.iter().map(|l| l.to_string()).collect();
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
            .then_some(flags.encryption_algorithm.clone());
        result.instance_recv_bps_limit =
            (flags.instance_recv_bps_limit != u64::MAX).then_some(flags.instance_recv_bps_limit);
        result.enable_private_mode = Some(flags.private_mode);

        result.acl = config.get_acl();

        if flags.relay_network_whitelist == "*" {
            result.enable_relay_network_whitelist = Some(false);
        } else {
            result.enable_relay_network_whitelist = Some(true);
            if flags.relay_network_whitelist.is_empty() {
                result.relay_network_whitelist = vec![];
            } else {
                result.relay_network_whitelist = flags
                    .relay_network_whitelist
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            }
        }

        Ok(result)
    }
}
