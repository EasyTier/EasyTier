//! Conversion between the management NetworkConfig schema and shared TOML.

use std::net::SocketAddr;

use anyhow::Context;
use easytier_proto::{api::manage, common::FlagsPatch};

#[cfg(all(
    feature = "browser-config",
    any(test, all(target_arch = "wasm32", target_os = "unknown"))
))]
use easytier_proto::common::Flags;
use optionize::{Optionizable, Optionized};

use crate::config::{
    MappedListenerPolicy,
    toml::{
        ConfigLoader, NetworkIdentity, PeerConfig, PortForwardConfig, TomlConfigLoader,
        VpnPortalClientConfig, VpnPortalConfig,
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

use easytier_proto::api::manage::{copy_flags_to_network_config, copy_network_config_to_flags};

pub(crate) fn set_network_flags(result: &mut NetworkConfig, flags: FlagsPatch) {
    copy_flags_to_network_config(&flags, result);
    result.mtu = flags.mtu.map(|mtu| mtu as i32);
    result.data_compress_algo = flags.data_compress_algo;
    result.enable_relay_network_whitelist = flags
        .relay_network_whitelist
        .as_ref()
        .map(|list| list != "*");
    result.relay_network_whitelist = flags
        .relay_network_whitelist
        .filter(|list| list != "*")
        .map(|list| list.split_whitespace().map(ToOwned::to_owned).collect())
        .unwrap_or_default();
}

pub(crate) fn flags_patch_from_network_config(
    net: &NetworkConfig,
) -> Result<FlagsPatch, anyhow::Error> {
    let mut flags = FlagsPatch::default();
    copy_network_config_to_flags(net, &mut flags);
    flags.mtu = net
        .mtu
        .map(u32::try_from)
        .transpose()
        .context("invalid mtu: expected a non-negative integer")?;
    flags.data_compress_algo = net.data_compress_algo.map(|algorithm| algorithm.max(1));
    flags.relay_network_whitelist = net.enable_relay_network_whitelist.map(|enabled| {
        if enabled {
            net.relay_network_whitelist.join(" ")
        } else {
            "*".to_owned()
        }
    });
    Ok(flags)
}

pub trait NetworkConfigExt {
    fn gen_config(&self) -> Result<TomlConfigLoader, anyhow::Error>;
    fn new_from_config(config: impl ConfigLoader) -> Result<NetworkConfig, anyhow::Error>;
}

#[cfg(all(
    feature = "browser-config",
    any(test, all(target_arch = "wasm32", target_os = "unknown"))
))]
const FORM_MANAGED_TOML_FIELDS: &[&str] = &[
    "hostname",
    "instance_id",
    "ipv4",
    "ipv6_public_addr_provider",
    "ipv6_public_addr_auto",
    "ipv6_public_addr_prefix",
    "dhcp",
    "network_identity",
    "listeners",
    "mapped_listeners",
    "exit_nodes",
    "peer",
    "proxy_network",
    "vpn_portal_config",
    "routes",
    "socks5_proxy",
    "port_forward",
    "secure_mode",
    "acl",
    "credential_file",
    "managed_credentials",
];

#[cfg(all(
    feature = "browser-config",
    any(test, all(target_arch = "wasm32", target_os = "unknown"))
))]
pub(crate) fn merge_network_config_toml(
    original_toml: &str,
    config: &NetworkConfig,
) -> Result<String, anyhow::Error> {
    let generated_toml = config.gen_config()?.dump();
    let mut original = toml::from_str::<toml::Table>(original_toml)
        .context("failed to parse the original TOML document")?;
    let mut generated = toml::from_str::<toml::Table>(&generated_toml)
        .context("failed to parse the generated TOML document")?;

    for (key, value) in original.iter() {
        if key != "flags" && !FORM_MANAGED_TOML_FIELDS.contains(&key.as_str()) {
            generated.insert(key.clone(), value.clone());
        }
    }
    if !original.contains_key("instance_name") {
        generated.remove("instance_name");
    }

    let mut merged_flags: toml::Table = original
        .remove("flags")
        .and_then(|value| value.try_into().ok())
        .unwrap_or_default();
    let generated_flags: toml::Table = generated
        .remove("flags")
        .and_then(|value| value.try_into().ok())
        .unwrap_or_default();

    // Normalize any camelCase aliases in original [flags] to their canonical field names
    // so each field appears at most once in the merged table.
    for field in Flags::flags() {
        if let (Some(name), Some(json_name)) = (field.name.as_deref(), field.json_name.as_deref()) {
            if name != json_name
                && let Some(val) = merged_flags.remove(json_name)
            {
                merged_flags.entry(name.to_owned()).or_insert(val);
            }
        }
    }

    // The keys a config form owns are the flags it offers a control for, which
    // the schema declares with `(easytier.flag)`.
    for key in Flags::form() {
        if let Some(value) = generated_flags.get(*key) {
            merged_flags.insert((*key).to_owned(), value.clone());
        } else {
            merged_flags.remove(*key);
        }
    }
    if !merged_flags.is_empty() {
        generated.insert("flags".to_owned(), toml::Value::Table(merged_flags));
    }

    toml::to_string_pretty(&generated).context("failed to serialize the merged TOML document")
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
    #[allow(deprecated)]
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

        if self.enable_vpn_portal == Some(true) {
            anyhow::bail!(
                "legacy VPN portal configuration is no longer supported; configure vpn_portal_config with named clients"
            );
        }

        if let Some(vpn_config) = &self.vpn_portal_config {
            cfg.set_vpn_portal_config(VpnPortalConfig {
                enabled: vpn_config.enabled,
                wireguard_listen: vpn_config.wireguard_listen.parse().with_context(|| {
                    format!(
                        "failed to parse vpn portal wireguard listen address: {}",
                        vpn_config.wireguard_listen
                    )
                })?,
                wireguard_private_key: vpn_config.wireguard_private_key.clone(),
                clients: vpn_config
                    .clients
                    .iter()
                    .map(|client| {
                        Ok(VpnPortalClientConfig {
                            name: client.name.clone(),
                            virtual_ip: client.virtual_ip.parse().with_context(|| {
                                format!(
                                    "failed to parse vpn portal virtual IP for client {}: {}",
                                    client.name, client.virtual_ip
                                )
                            })?,
                            groups: client.groups.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>, anyhow::Error>>()?,
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

        cfg.set_managed_credentials(
            self.managed_credentials
                .iter()
                .map(|credential| credential.clone().upgrade())
                .collect::<Result<Vec<_>, _>>()?,
        );

        if let Some(credential_secret) = credential_secret {
            cfg.set_secure_mode(Some(easytier_proto::common::SecureModeConfig {
                enabled: true,
                local_private_key: Some(credential_secret),
                local_public_key: None,
            }))?;
        } else {
            cfg.set_secure_mode(self.secure_mode.clone())?;
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

        if let Some(acl) = self.acl.as_ref()
            && !acl.is_empty()
        {
            cfg.set_acl(Some(acl.clone()));
        }

        cfg.patch_flags(flags_patch_from_network_config(self)?);
        Ok(cfg)
    }

    fn new_from_config(config: impl ConfigLoader) -> Result<Self, anyhow::Error> {
        Ok(network_config_from_loader(config))
    }
}

pub fn network_config_from_loader(config: impl ConfigLoader) -> NetworkConfig {
    let default_config = TomlConfigLoader::default();

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
    #![allow(deprecated)]

    use super::*;
    use easytier_proto::common::Flags;

    fn api_portal_config() -> manage::VpnPortalConfig {
        manage::VpnPortalConfig {
            enabled: None,
            wireguard_listen: "0.0.0.0:51820".to_owned(),
            wireguard_private_key: Some("server-private-key".to_owned()),
            clients: vec![manage::VpnPortalClientConfig {
                name: "alice".to_owned(),
                virtual_ip: "10.144.144.10/16".to_owned(),
                groups: vec!["staff".to_owned()],
            }],
        }
    }

    fn standalone_config() -> NetworkConfig {
        NetworkConfig {
            networking_method: Some(NetworkingMethod::Standalone as i32),
            ..Default::default()
        }
    }

    /// The management API's name for a flag is the schema's to state, and the
    /// projection is what actually names the fields. Turning the flag the
    /// annotation names must turn the field it points at, in the direction the
    /// annotation declares.
    #[test]
    fn declared_api_names_match_the_projection() {
        use prost_reflect::{DescriptorPool, Value};

        let pool = DescriptorPool::decode(easytier_proto::ALL_DESCRIPTOR_BYTES).unwrap();
        let flags = pool.get_message_by_name("common.Flags").unwrap();
        let extension = pool.get_extension_by_name("easytier.flag").unwrap();

        // A patch states every field, so the values survive serialization:
        // protobuf JSON omits a field holding its zero value.
        let patch: FlagsPatch = Flags::defaults().downgrade();
        let defaults = serde_json::to_value(&patch).unwrap();

        for field in flags.fields() {
            let name = field.name();
            let options = field.options();
            let annotation = options.get_extension(&extension).into_owned();
            let Value::Message(meta) = annotation else {
                panic!("{name}: the annotation is not a message");
            };
            if !meta.has_field_by_name("api") {
                continue;
            }
            let Value::Message(spelling) = meta.get_field_by_name("api").unwrap().into_owned()
            else {
                panic!("{name}: the api spelling is not a message");
            };
            let api_field = match spelling.get_field_by_name("field").as_deref() {
                Some(Value::String(api_field)) if !api_field.is_empty() => api_field.clone(),
                _ => continue,
            };
            let negate = matches!(
                spelling.get_field_by_name("negate").as_deref(),
                Some(Value::Bool(true))
            );

            let declared = defaults[name]
                .as_bool()
                .unwrap_or_else(|| panic!("{name} is not a boolean flag"));

            let mut flipped = defaults.clone();
            flipped[name] = serde_json::json!(!declared);
            let patch: FlagsPatch = serde_json::from_value(flipped).unwrap();

            let mut projected = NetworkConfig::default();
            set_network_flags(&mut projected, patch);

            // Protobuf JSON omits a field holding its zero value.
            let projected = serde_json::to_value(&projected).unwrap();
            let value = projected[&api_field].as_bool().unwrap_or(false);
            assert_eq!(
                value,
                if negate { declared } else { !declared },
                "flipping {name} should leave {api_field} as the annotation declares"
            );
        }
    }

    #[cfg(feature = "config-write")]
    #[test]
    fn api_flags_round_trip_preserves_missing_default_and_custom_values() {
        for disabled in [None, Some(false), Some(true)] {
            for whitelist in [None, Some(false), Some(true)] {
                let input = NetworkConfig {
                    disable_encryption: disabled,
                    enable_relay_network_whitelist: whitelist,
                    latency_first: Some(false),
                    mtu: Some(0),
                    instance_recv_bps_limit: Some(u64::MAX),
                    ..standalone_config()
                };
                let config = input.gen_config().unwrap();
                let config = TomlConfigLoader::new_from_str(&config.dump()).unwrap();
                let output = NetworkConfig::new_from_config(&config).unwrap();
                assert_eq!(output.disable_encryption, disabled);
                assert_eq!(output.enable_relay_network_whitelist, whitelist);
                assert_eq!(output.latency_first, Some(false));
                assert_eq!(output.mtu, Some(0));
                assert_eq!(output.instance_recv_bps_limit, Some(u64::MAX));
                assert_eq!(output.disable_ipv6, None);
                assert_eq!(output.encryption_algorithm, None);
            }
        }
        assert!(
            NetworkConfig {
                mtu: Some(-1),
                ..standalone_config()
            }
            .gen_config()
            .is_err()
        );
    }

    #[test]
    fn vpn_portal_api_config_round_trips_through_toml_model() {
        let input = NetworkConfig {
            vpn_portal_config: Some(api_portal_config()),
            ..standalone_config()
        };

        let config = input.gen_config().unwrap();
        let portal = config.get_vpn_portal_config().unwrap();
        assert_eq!(portal.wireguard_listen, "0.0.0.0:51820".parse().unwrap());
        assert_eq!(
            portal.wireguard_private_key.as_deref(),
            Some("server-private-key")
        );
        assert_eq!(portal.clients[0].name, "alice");
        assert_eq!(portal.clients[0].virtual_ip.to_string(), "10.144.144.10/16");
        assert_eq!(portal.clients[0].groups, vec!["staff".to_owned()]);

        let output = NetworkConfig::new_from_config(&config).unwrap();
        assert_eq!(output.vpn_portal_config, input.vpn_portal_config);
        assert_eq!(output.enable_vpn_portal, None);
    }

    #[test]
    fn disabled_vpn_portal_preserves_clients_and_key_without_a_runtime() {
        let mut portal = api_portal_config();
        portal.enabled = Some(false);
        let input = NetworkConfig {
            vpn_portal_config: Some(portal),
            ..standalone_config()
        };
        let config = input.gen_config().unwrap();
        let restored = crate::config::toml::TomlConfig::new_from_str(&config.dump()).unwrap();
        let output = NetworkConfig::new_from_config(&restored).unwrap();
        assert_eq!(output.vpn_portal_config, input.vpn_portal_config);
        assert!(
            crate::instance::CoreInstanceConfig::from_toml(&restored)
                .unwrap()
                .vpn_portal
                .is_none()
        );

        let mut portal = restored.get_vpn_portal_config().unwrap();
        portal.enabled = Some(true);
        restored.set_vpn_portal_config(portal);
        let runtime = crate::instance::CoreInstanceConfig::from_toml(&restored).unwrap();
        assert_eq!(runtime.vpn_portal.unwrap().clients[0].name, "alice");
    }

    #[test]
    fn managed_credentials_round_trip_through_toml_model() {
        let input = NetworkConfig {
            managed_credentials: vec![manage::ManagedCredentialConfig {
                credential_id: "managed-a".to_owned(),
                credential_secret: "secret".to_owned(),
                groups: vec!["ops".to_owned()],
                allow_relay: true,
                allowed_proxy_cidrs: vec!["10.0.0.0/24".to_owned()],
                expiry_unix: 2_000_000_000,
                reusable: None,
            }],
            ..standalone_config()
        };

        let config = input.gen_config().unwrap();
        let output = NetworkConfig::new_from_config(&config).unwrap();
        assert_eq!(output.managed_credentials[0].credential_id, "managed-a");
        assert_eq!(output.managed_credentials[0].reusable, Some(true));
    }

    #[test]
    fn peer_relay_preference_round_trips_independently() {
        let input = NetworkConfig {
            disable_relay_data: Some(false),
            prefer_peer_relay: Some(true),
            ..standalone_config()
        };

        let config = input.gen_config().unwrap();
        let flags = config.get_flags();
        assert!(!flags.disable_relay_data);
        assert!(flags.prefer_peer_relay);

        let output = NetworkConfig::new_from_config(&config).unwrap();
        assert_eq!(output.disable_relay_data, Some(false));
        assert_eq!(output.prefer_peer_relay, Some(true));
    }

    #[test]
    fn legacy_enabled_vpn_portal_config_reports_migration_error() {
        let error = NetworkConfig {
            enable_vpn_portal: Some(true),
            ..standalone_config()
        }
        .gen_config()
        .unwrap_err()
        .to_string();

        assert!(error.contains("legacy VPN portal"), "{error}");
    }

    #[test]
    fn legacy_disabled_vpn_portal_defaults_are_ignored() {
        let config = NetworkConfig {
            enable_vpn_portal: Some(false),
            vpn_portal_listen_port: Some(0),
            vpn_portal_client_network_addr: Some(String::new()),
            vpn_portal_client_network_len: Some(0),
            ..standalone_config()
        }
        .gen_config()
        .unwrap();

        assert!(config.get_vpn_portal_config().is_none());
    }

    #[cfg(feature = "browser-config")]
    #[test]
    fn browser_merge_reconciles_renamed_flags() {
        let original = r#"
[flags]
default_protocol = "udp"
enable_encryption = false
enable_ipv6 = false
accept_dns = false
private_mode = false
"#;

        for value in [Some(false), Some(true), None] {
            let network_config = NetworkConfig {
                disable_encryption: value,
                disable_ipv6: value,
                enable_magic_dns: value,
                enable_private_mode: value,
                ..standalone_config()
            };
            let merged = merge_network_config_toml(original, &network_config).unwrap();
            let merged: toml::Table = toml::from_str(&merged).unwrap();
            let flags = merged["flags"].as_table().unwrap();

            assert_eq!(flags["default_protocol"].as_str(), Some("udp"));
            for (field, expected) in [
                ("enable_encryption", value.map(|disabled| !disabled)),
                ("enable_ipv6", value.map(|disabled| !disabled)),
                ("accept_dns", value),
                ("private_mode", value),
            ] {
                assert_eq!(
                    flags.get(field).and_then(toml::Value::as_bool),
                    expected,
                    "merging {field} from API value {value:?}"
                );
            }
        }
    }

    #[cfg(feature = "browser-config")]
    #[test]
    fn browser_merge_preserves_fields_outside_the_shared_form() {
        let original = r#"
instance_name = "module-instance"
rpc_portal = "0.0.0.0:15888"
tcp_whitelist = ["22"]
stun_servers = ["custom.example.com:3478"]

[network_identity]
network_name = "old-network"
network_secret = "secret"

[flags]
default_protocol = "udp"
disable_p2p = true
"#;
        let parsed = TomlConfigLoader::new_from_str(original).unwrap();
        let mut network_config = NetworkConfig::new_from_config(&parsed).unwrap();
        network_config.network_name = Some("edited-network".to_owned());
        network_config.disable_p2p = Some(false);

        let merged = merge_network_config_toml(original, &network_config).unwrap();
        let merged: toml::Table = toml::from_str(&merged).unwrap();

        assert_eq!(merged["instance_name"].as_str(), Some("module-instance"));
        assert_eq!(merged["rpc_portal"].as_str(), Some("0.0.0.0:15888"));
        assert_eq!(merged["tcp_whitelist"][0].as_str(), Some("22"));
        assert_eq!(
            merged["stun_servers"][0].as_str(),
            Some("custom.example.com:3478")
        );
        assert_eq!(
            merged["network_identity"]["network_name"].as_str(),
            Some("edited-network")
        );
        assert_eq!(merged["flags"]["default_protocol"].as_str(), Some("udp"));
        assert_eq!(merged["flags"]["disable_p2p"].as_bool(), Some(false));
    }

    #[cfg(feature = "browser-config")]
    #[test]
    fn browser_merge_normalizes_camel_case_flag_aliases() {
        let original = r#"
[flags]
disableP2p = true
enableEncryption = false
foreignRelayBpsLimit = 1234
"#;
        let parsed_orig = TomlConfigLoader::new_from_str(original).unwrap();
        let mut network_config = NetworkConfig::new_from_config(&parsed_orig).unwrap();
        network_config.disable_p2p = Some(false);

        let merged = merge_network_config_toml(original, &network_config).unwrap();
        let parsed = TomlConfigLoader::new_from_str(&merged)
            .expect("merged config should be parseable without duplicate-field error");
        assert!(!parsed.get_flags().disable_p2p);
        assert!(!parsed.get_flags().enable_encryption);
        assert_eq!(parsed.get_flags().foreign_relay_bps_limit, 1234);

        let merged_table: toml::Table = toml::from_str(&merged).unwrap();
        let flags = merged_table["flags"].as_table().unwrap();
        assert_eq!(
            flags.get("disable_p2p").and_then(toml::Value::as_bool),
            Some(false)
        );
        assert!(flags.get("disableP2p").is_none());
        assert_eq!(
            flags
                .get("enable_encryption")
                .and_then(toml::Value::as_bool),
            Some(false)
        );
        assert!(flags.get("enableEncryption").is_none());
        assert_eq!(
            flags
                .get("foreign_relay_bps_limit")
                .and_then(toml::Value::as_integer),
            Some(1234)
        );
        assert!(flags.get("foreignRelayBpsLimit").is_none());
    }

    #[cfg(feature = "browser-config")]
    #[test]
    fn browser_merge_repro_camel_case_disable_p2p_collision() {
        let original = r#"
[flags]
disableP2p = false
"#;
        let mut network_config = standalone_config();
        network_config.hostname = Some("new-hostname".to_owned());
        network_config.disable_p2p = Some(false);

        let merged = merge_network_config_toml(original, &network_config).unwrap();
        let parsed = TomlConfigLoader::new_from_str(&merged)
            .expect("saving config with camelCase alias must not fail on reload");
        assert!(!parsed.get_flags().disable_p2p);

        let merged_table: toml::Table = toml::from_str(&merged).unwrap();
        let flags = merged_table["flags"].as_table().unwrap();
        assert_eq!(
            flags.get("disable_p2p").and_then(toml::Value::as_bool),
            Some(false)
        );
        assert!(flags.get("disableP2p").is_none());
    }
}
