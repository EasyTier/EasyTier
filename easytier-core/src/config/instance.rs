use anyhow::Context;
use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};
use easytier_proto::acl::Acl;
use easytier_proto::common::{Flags, FlagsPatch, SecureModeConfig};
use optionize::Optionizable;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use url::Url;

use super::base::ConfigBase;
use super::gateway::PortForwardConfig;
use super::normalize_secure_mode_config;
use super::toml::{
    ConfigSourceConfig, ManagedCredentialConfig, NetworkIdentity, PeerConfig, ProxyNetworkConfig,
    TomlConfig, VpnPortalConfig, default_instance_name,
};

pub fn normalize_hostname(hostname: Option<&str>) -> String {
    hostname
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(32)
        .collect()
}

pub fn normalize_ipv4(ipv4: Option<Ipv4Inet>) -> Option<Ipv4Inet> {
    ipv4.map(|c| {
        if c.network_length() == 32 {
            Ipv4Inet::new(c.address(), 24).unwrap()
        } else {
            c
        }
    })
}

pub fn normalize_network_identity(
    raw_id: Option<&NetworkIdentity>,
    secure_mode: Option<&SecureModeConfig>,
) -> NetworkIdentity {
    let Some(raw_id) = raw_id else {
        return NetworkIdentity::default();
    };

    let secure_enabled = secure_mode.map(|sm| sm.enabled).unwrap_or(false);

    match (&raw_id.network_secret, raw_id.network_secret_digest) {
        (None, Some(digest)) => NetworkIdentity {
            network_name: raw_id.network_name.clone(),
            network_secret: None,
            network_secret_digest: Some(digest),
        },
        (None, None) => NetworkIdentity::new_credential(raw_id.network_name.clone()),
        (Some(secret), _) if secret.is_empty() && secure_enabled => {
            NetworkIdentity::new_credential(raw_id.network_name.clone())
        }
        (Some(secret), _) => NetworkIdentity::new(raw_id.network_name.clone(), secret.clone()),
    }
}

#[optionize::optionized]
#[optionize(name = "InstanceConfigRaw")]
#[optionize(attrs(.., derive(Default)))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct InstanceConfigParsed {
    pub instance_name: String,
    pub hostname: String,
    pub instance_id: uuid::Uuid,
    #[optionize(flatten)]
    pub netns: Option<String>,
    #[optionize(flatten)]
    pub ipv4: Option<Ipv4Inet>,
    #[optionize(flatten)]
    pub ipv6: Option<Ipv6Inet>,
    pub ipv6_public_addr_provider: bool,
    pub ipv6_public_addr_auto: bool,
    #[optionize(flatten)]
    pub ipv6_public_addr_prefix: Option<Ipv6Cidr>,
    pub dhcp: bool,
    pub network_identity: NetworkIdentity,
    #[optionize(flatten)]
    pub listeners: Option<Vec<Url>>,
    pub mapped_listeners: Vec<Url>,
    pub exit_nodes: Vec<IpAddr>,
    pub peer: Vec<PeerConfig>,
    pub proxy_network: Vec<ProxyNetworkConfig>,
    #[optionize(flatten)]
    pub vpn_portal_config: Option<VpnPortalConfig>,
    #[optionize(flatten)]
    pub routes: Option<Vec<Ipv4Cidr>>,
    #[optionize(flatten)]
    pub socks5_proxy: Option<Url>,
    pub port_forward: Vec<PortForwardConfig>,
    #[optionize(flatten)]
    pub secure_mode: Option<SecureModeConfig>,
    #[serde(default)]
    #[optionize(flatten, nest = FlagsPatch)]
    pub flags: Flags,
    #[optionize(flatten)]
    pub acl: Option<Acl>,
    pub tcp_whitelist: Vec<String>,
    pub udp_whitelist: Vec<String>,
    #[optionize(flatten)]
    pub stun_servers: Option<Vec<String>>,
    #[optionize(flatten)]
    pub tcp_stun_servers: Option<Vec<String>>,
    #[optionize(flatten)]
    pub stun_servers_v6: Option<Vec<String>>,
    #[optionize(flatten)]
    pub credential_file: Option<PathBuf>,
    pub managed_credentials: Vec<ManagedCredentialConfig>,
    #[optionize(flatten)]
    pub source: Option<ConfigSourceConfig>,
}

impl Default for InstanceConfigParsed {
    fn default() -> Self {
        Self {
            instance_name: default_instance_name(),
            hostname: String::new(),
            instance_id: uuid::Uuid::nil(),
            netns: None,
            ipv4: None,
            ipv6: None,
            ipv6_public_addr_provider: false,
            ipv6_public_addr_auto: false,
            ipv6_public_addr_prefix: None,
            dhcp: false,
            network_identity: NetworkIdentity::default(),
            listeners: None,
            mapped_listeners: Vec::new(),
            exit_nodes: Vec::new(),
            peer: Vec::new(),
            proxy_network: Vec::new(),
            vpn_portal_config: None,
            routes: None,
            socks5_proxy: None,
            port_forward: Vec::new(),
            secure_mode: None,
            flags: Flags::defaults(),
            acl: None,
            tcp_whitelist: Vec::new(),
            udp_whitelist: Vec::new(),
            stun_servers: None,
            tcp_stun_servers: None,
            stun_servers_v6: None,
            credential_file: None,
            managed_credentials: Vec::new(),
            source: None,
        }
    }
}

impl InstanceConfigParsed {
    pub fn generate_raw(&self) -> InstanceConfigRaw {
        self.clone().downgrade()
    }
}

pub fn validate_proxy_cidr_pair(cidr: Ipv4Cidr, mapped_cidr: Ipv4Cidr) -> anyhow::Result<()> {
    if cidr.network_length() != mapped_cidr.network_length() {
        anyhow::bail!(
            "Mapped CIDR must have the same network length as the original CIDR: {} != {}",
            cidr.network_length(),
            mapped_cidr.network_length()
        );
    }
    Ok(())
}

impl InstanceConfigRaw {
    pub fn add_proxy_cidr(
        &mut self,
        cidr: Ipv4Cidr,
        mapped_cidr: Option<Ipv4Cidr>,
    ) -> anyhow::Result<()> {
        if let Some(mapped_cidr) = mapped_cidr.as_ref() {
            validate_proxy_cidr_pair(cidr, *mapped_cidr)?;
        }
        if self.proxy_network.is_none() {
            self.proxy_network = Some(vec![]);
        }
        if !self
            .proxy_network
            .as_ref()
            .unwrap()
            .iter()
            .any(|c| c.cidr == cidr && c.mapped_cidr == mapped_cidr)
        {
            self.proxy_network
                .as_mut()
                .unwrap()
                .push(ProxyNetworkConfig {
                    cidr,
                    mapped_cidr,
                    allow: None,
                });
        }
        Ok(())
    }

    pub fn remove_proxy_cidr(&mut self, cidr: Ipv4Cidr) {
        if let Some(proxy_cidrs) = &mut self.proxy_network {
            proxy_cidrs.retain(|c| c.cidr != cidr);
        }
    }

    pub fn clear_proxy_cidrs(&mut self) {
        self.proxy_network = None;
    }

    pub fn patch_flags(&mut self, flags: FlagsPatch) {
        let update = prost::Message::encode_to_vec(&flags);
        prost::Message::merge(&mut self.flags, update.as_slice())
            .expect("decoding the bytes just encoded cannot fail");
    }
}

pub type InstanceConfig = ConfigBase<InstanceConfigRaw, InstanceConfigParsed>;

impl TryFrom<InstanceConfigRaw> for InstanceConfig {
    type Error = anyhow::Error;

    fn try_from(mut raw: InstanceConfigRaw) -> Result<Self, Self::Error> {
        TomlConfig::normalize_config_source(&mut raw);

        if let Some(secure_mode) = raw.secure_mode.take() {
            let normalized = normalize_secure_mode_config(secure_mode)
                .context("failed to normalize [secure_mode] config")?;
            raw.secure_mode = Some(normalized);
        }

        let network_identity =
            normalize_network_identity(raw.network_identity.as_ref(), raw.secure_mode.as_ref());
        if raw.network_identity.is_some() {
            raw.network_identity = Some(network_identity.clone());
        }

        let instance_id = raw.instance_id.unwrap_or_else(uuid::Uuid::new_v4);
        raw.instance_id = Some(instance_id);

        let mut parsed = InstanceConfigParsed {
            instance_id,
            network_identity,
            ..InstanceConfigParsed::default()
        };
        parsed.load(raw.clone());
        parsed.instance_id = instance_id;

        // 规范化与业务校验
        parsed.hostname = normalize_hostname(raw.hostname.as_deref());
        parsed.ipv4 = normalize_ipv4(parsed.ipv4);

        for proxy in &parsed.proxy_network {
            if let Some(mapped) = &proxy.mapped_cidr {
                validate_proxy_cidr_pair(proxy.cidr, *mapped)?;
            }
        }

        if !parsed.managed_credentials.is_empty()
            && parsed.network_identity.network_secret.is_none()
        {
            anyhow::bail!(
                "only admin nodes with a network_secret can configure managed credentials"
            );
        }

        Ok(ConfigBase::new(parsed, raw, ()))
    }
}

impl From<InstanceConfigParsed> for InstanceConfig {
    fn from(parsed: InstanceConfigParsed) -> Self {
        let raw = parsed.generate_raw();
        ConfigBase::new(parsed, raw, ())
    }
}

impl InstanceConfig {
    pub fn from_parsed(parsed: InstanceConfigParsed) -> Self {
        parsed.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::toml::{ConfigLoader, TomlConfig};

    #[test]
    fn test_unfilled_vs_false_vs_zero_vs_empty_list() {
        // 1. Unfilled
        let toml_unfilled = r#"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        let cfg_unfilled = TomlConfig::new_from_str(toml_unfilled).unwrap();
        let snap_unfilled = cfg_unfilled.snapshot().unwrap();
        assert!(!snap_unfilled.dhcp);
        assert_eq!(snap_unfilled.raw().dhcp, None);
        assert_eq!(snap_unfilled.routes, None);
        assert_eq!(snap_unfilled.raw().routes, None);
        assert_eq!(snap_unfilled.flags.socket_mark, None);
        assert_eq!(snap_unfilled.raw().flags.socket_mark, None);

        // 2. Explicit false, 0, and empty list
        let toml_explicit = r#"
dhcp = false
routes = []

[network_identity]
network_name = "test"
network_secret = "secret"

[flags]
socket_mark = 0
"#;
        let cfg_explicit = TomlConfig::new_from_str(toml_explicit).unwrap();
        let snap_explicit = cfg_explicit.snapshot().unwrap();
        assert!(!snap_explicit.dhcp);
        assert_eq!(snap_explicit.raw().dhcp, Some(false));
        assert_eq!(snap_explicit.routes, Some(vec![]));
        assert_eq!(snap_explicit.raw().routes, Some(vec![]));
        assert_eq!(snap_explicit.flags.socket_mark, Some(0));
        assert_eq!(snap_explicit.raw().flags.socket_mark, Some(0));

        // Roundtrip check: dump and re-parse preserves distinction
        let dumped = cfg_explicit.dump();
        let cfg_restored = TomlConfig::new_from_str(&dumped).unwrap();
        let snap_restored = cfg_restored.snapshot().unwrap();
        assert_eq!(snap_restored.raw().dhcp, Some(false));
        assert_eq!(snap_restored.raw().routes, Some(vec![]));
        assert_eq!(snap_restored.raw().flags.socket_mark, Some(0));
    }

    #[test]
    fn test_flags_defaults_and_patch() {
        let toml = r#"
[network_identity]
network_name = "test"
network_secret = "secret"

[flags]
mtu = 1350
"#;
        let cfg = TomlConfig::new_from_str(toml).unwrap();
        let snap = cfg.snapshot().unwrap();
        // Custom value patched
        assert_eq!(snap.flags.mtu, 1350);
        // Default values preserved
        let defaults = Flags::defaults();
        assert_eq!(snap.flags.default_protocol, defaults.default_protocol);
        assert_eq!(snap.flags.enable_encryption, defaults.enable_encryption);
    }

    #[test]
    fn test_invalid_address_reported_at_load_time() {
        // Invalid IPv4
        let toml_bad_ipv4 = r#"
ipv4 = "999.999.999.999/24"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        assert!(TomlConfig::new_from_str(toml_bad_ipv4).is_err());

        // Invalid IPv6
        let toml_bad_ipv6 = r#"
ipv6 = "invalid:ipv6"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        assert!(TomlConfig::new_from_str(toml_bad_ipv6).is_err());

        // Invalid IPv6 CIDR prefix
        let toml_bad_prefix = r#"
ipv6_public_addr_prefix = "invalid_prefix"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        assert!(TomlConfig::new_from_str(toml_bad_prefix).is_err());
    }

    #[test]
    fn test_ipv4_normalization_in_parsed() {
        // /32 normalized to /24
        let toml = r#"
ipv4 = "10.144.144.1/32"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        let cfg = TomlConfig::new_from_str(toml).unwrap();
        let snap = cfg.snapshot().unwrap();
        assert_eq!(snap.ipv4.unwrap().to_string(), "10.144.144.1/24");
        // Raw retains the parsed type with length 32
        assert_eq!(snap.raw().ipv4.unwrap().network_length(), 32);

        // /16 stays /16
        let toml16 = r#"
ipv4 = "10.144.144.1/16"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        let cfg16 = TomlConfig::new_from_str(toml16).unwrap();
        let snap16 = cfg16.snapshot().unwrap();
        assert_eq!(snap16.ipv4.unwrap().to_string(), "10.144.144.1/16");
    }

    #[test]
    fn test_getter_does_not_mutate_raw_and_snapshot_is_stable() {
        let toml = r#"
hostname = "node\u0007-name"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        let cfg = TomlConfig::new_from_str(toml).unwrap();
        let original_raw_hostname = cfg.snapshot().unwrap().raw().hostname.clone();
        assert_eq!(original_raw_hostname, Some("node\u{0007}-name".to_string()));

        // Getter returns cleaned string without mutating Raw
        let hostname = cfg.get_hostname();
        assert_eq!(hostname, "node-name");
        assert_eq!(
            cfg.snapshot().unwrap().raw().hostname,
            Some("node\u{0007}-name".to_string())
        );

        // Repeated snapshots yield stable UUID and equal parsed configurations
        let snap1 = cfg.snapshot().unwrap();
        let snap2 = cfg.snapshot().unwrap();
        assert_eq!(snap1, snap2);
        assert_eq!(snap1.instance_id, snap2.instance_id);
        assert_ne!(snap1.instance_id, uuid::Uuid::nil());
    }

    #[test]
    fn test_snapshot_independence() {
        let toml = r#"
hostname = "original"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        let cfg = TomlConfig::new_from_str(toml).unwrap();
        let snap1 = cfg.snapshot().unwrap();
        assert_eq!(snap1.hostname, "original");

        // Mutating the TomlConfig later does not affect previously captured snapshot
        cfg.set_hostname(Some("modified".to_string()));
        assert_eq!(snap1.hostname, "original");

        let snap2 = cfg.snapshot().unwrap();
        assert_eq!(snap2.hostname, "modified");
    }

    #[test]
    fn test_stun_fallback_preserved() {
        // Omitted stun_servers is None
        let toml_none = r#"
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        let cfg_none = TomlConfig::new_from_str(toml_none).unwrap();
        let snap_none = cfg_none.snapshot().unwrap();
        assert_eq!(snap_none.stun_servers, None);

        // Explicit empty list is Some([])
        let toml_empty = r#"
stun_servers = []
[network_identity]
network_name = "test"
network_secret = "secret"
"#;
        let cfg_empty = TomlConfig::new_from_str(toml_empty).unwrap();
        let snap_empty = cfg_empty.snapshot().unwrap();
        assert_eq!(snap_empty.stun_servers, Some(vec![]));
    }

    #[test]
    fn test_credential_mode_and_secret_redaction() {
        let toml = r#"
[network_identity]
network_name = "cred-net"

[secure_mode]
enabled = true
"#;
        let cfg = TomlConfig::new_from_str(toml).unwrap();
        let snap = cfg.snapshot().unwrap();
        assert_eq!(snap.network_identity.network_name, "cred-net");
        assert_eq!(snap.network_identity.network_secret, None);

        // Key preservation and dump redacted
        let dumped = cfg.dump();
        assert!(dumped.contains("cred-net"));
    }

    #[test]
    fn test_proxy_network_cidr_length_validation() {
        let raw = InstanceConfigRaw {
            network_identity: Some(NetworkIdentity::new("net".into(), "secret".into())),
            proxy_network: Some(vec![ProxyNetworkConfig {
                cidr: "10.0.0.0/24".parse().unwrap(),
                mapped_cidr: Some("10.1.0.0/16".parse().unwrap()),
                allow: None,
            }]),
            ..Default::default()
        };

        let err = InstanceConfig::try_from(raw).unwrap_err();
        assert!(
            err.to_string()
                .contains("Mapped CIDR must have the same network length")
        );
    }

    #[test]
    fn test_managed_credentials_requires_network_secret() {
        let raw = InstanceConfigRaw {
            network_identity: Some(NetworkIdentity::new_credential("net".into())),
            managed_credentials: Some(vec![crate::config::toml::ManagedCredentialConfig {
                credential_id: "c1".into(),
                credential_secret: "sec".into(),
                groups: vec![],
                allow_relay: true,
                allowed_proxy_cidrs: vec![],
                expiry_unix: 0,
                reusable: true,
            }]),
            ..Default::default()
        };

        let err = InstanceConfig::try_from(raw).unwrap_err();
        assert!(
            err.to_string()
                .contains("only admin nodes with a network_secret")
        );
    }

    #[test]
    fn review_loading_paths_should_agree_on_identity() {
        let input = "[network_identity]\nnetwork_name = 'review'\n";
        let direct: InstanceConfig = toml::from_str(input).unwrap();
        let via_loader = TomlConfig::new_from_str(input).unwrap().snapshot().unwrap();
        assert_eq!(
            direct.network_identity.network_secret.is_some(),
            via_loader.network_identity.network_secret.is_some(),
            "same document selects different identity modes"
        );
    }

    #[test]
    fn review_direct_loading_should_validate_secure_mode() {
        let input = "[secure_mode]\nenabled = true\nlocal_private_key = 'not-base64'\n";
        assert!(TomlConfig::new_from_str(input).is_err());
        assert!(toml::from_str::<InstanceConfig>(input).is_err());
    }

    #[test]
    fn review_repeated_projection_should_preserve_identity() {
        let config = TomlConfig::default().snapshot().unwrap();
        let host = crate::instance::CoreInstanceHostConfig::default();
        let first = crate::instance::prepare_instance_config(config.clone(), &host).unwrap();
        let second = crate::instance::prepare_instance_config(config, &host).unwrap();
        assert_eq!(first.parsed().instance_id, second.parsed().instance_id,);
    }

    #[test]
    fn editing_raw_preserves_unedited_fields_and_allows_clearing() {
        let original: InstanceConfig = toml::from_str("ipv4 = '10.0.0.1/24'\n").unwrap();
        let mut raw = original.raw().clone();
        raw.hostname = Some("review".into());
        let renamed = InstanceConfig::try_from(raw).unwrap();
        assert_eq!(renamed.hostname, "review");
        assert_eq!(renamed.ipv4, original.ipv4);
        assert_eq!(renamed.instance_id, original.instance_id);

        let mut raw = renamed.into_raw();
        raw.ipv4 = None;
        let cleared = InstanceConfig::try_from(raw).unwrap();
        assert_eq!(cleared.ipv4, None);
        assert_eq!(cleared.hostname, "review");
        assert!(original.ipv4.is_some());
    }

    #[test]
    fn secure_mode_setter_should_not_make_snapshots_rotate_keys() {
        let config = TomlConfig::default();
        let template = TomlConfig::new_from_str("[secure_mode]\nenabled = true").unwrap();
        let mut secure = template.get_secure_mode().unwrap();
        secure.local_private_key = None;
        secure.local_public_key = None;
        config.set_secure_mode(Some(secure)).unwrap();
        let first = config.snapshot().unwrap();
        let second = config.snapshot().unwrap();
        // Do not print private key material on failure.
        assert!(
            first.secure_mode.as_ref().unwrap().local_private_key
                == second.secure_mode.as_ref().unwrap().local_private_key
        );
    }

    #[test]
    fn secure_mode_setter_with_invalid_key_errors_and_preserves_old_config() {
        let config = TomlConfig::default();
        let old_secure = crate::proto::common::SecureModeConfig {
            enabled: false,
            ..Default::default()
        };
        config.set_secure_mode(Some(old_secure.clone())).unwrap();

        let invalid_secure = crate::proto::common::SecureModeConfig {
            enabled: true,
            local_private_key: Some("not-a-valid-hex-or-base64-key".into()),
            local_public_key: None,
        };
        assert!(config.set_secure_mode(Some(invalid_secure)).is_err());
        assert_eq!(config.get_secure_mode().as_ref(), Some(&old_secure));
    }

    #[test]
    fn digest_only_identity_should_keep_its_digest() {
        let config = TomlConfig::default();
        config.set_network_identity(NetworkIdentity {
            network_name: "review".into(),
            network_secret: None,
            network_secret_digest: Some([7; 32]),
        });
        assert_eq!(
            config
                .snapshot()
                .unwrap()
                .network_identity
                .network_secret_digest,
            Some([7; 32])
        );
    }

    #[test]
    fn file_without_secret_should_keep_legacy_identity_mode() {
        let config: InstanceConfig =
            toml::from_str("[network_identity]\nnetwork_name = 'review'").unwrap();
        assert_eq!(config.network_identity.network_secret.as_deref(), Some(""));
    }

    #[test]
    fn enabling_secure_mode_after_loading_should_match_direct_loading() {
        let input = "[network_identity]\nnetwork_name = 'review'\nnetwork_secret = ''\n";
        let direct =
            TomlConfig::new_from_str(&format!("{input}\n[secure_mode]\nenabled = true\n")).unwrap();
        let edited = TomlConfig::new_from_str(input).unwrap();
        edited.set_secure_mode(direct.get_secure_mode()).unwrap();
        assert_eq!(
            edited
                .snapshot()
                .unwrap()
                .network_identity
                .network_secret
                .is_none(),
            direct
                .snapshot()
                .unwrap()
                .network_identity
                .network_secret
                .is_none(),
            "setter and file input disagree about credential identity"
        );
    }

    #[test]
    fn enabling_secure_mode_should_preserve_identity_after_serialize_reload() {
        let config = TomlConfig::new_from_str(
            "[network_identity]\nnetwork_name = 'review'\nnetwork_secret = ''\n",
        )
        .unwrap();
        let template = TomlConfig::new_from_str("[secure_mode]\nenabled = true\n").unwrap();
        config.set_secure_mode(template.get_secure_mode()).unwrap();
        let snapshot = config.snapshot().unwrap();
        let saved = toml::to_string(&snapshot).unwrap();
        let restored: InstanceConfig = toml::from_str(&saved).unwrap();
        assert_eq!(
            snapshot.network_identity.network_secret.is_none(),
            restored.network_identity.network_secret.is_none(),
            "serialize/reload changes credential identity"
        );
    }

    #[test]
    fn writing_back_default_admin_preserves_identity_after_reload() {
        let config = TomlConfig::new_from_str("[secure_mode]\nenabled = true").unwrap();
        let identity = config.get_network_identity();
        assert_eq!(identity.network_secret.as_deref(), Some(""));

        config.set_network_identity(identity);
        let snapshot = config.snapshot().unwrap();
        assert_eq!(
            config.get_network_identity().network_secret.as_deref(),
            Some("")
        );
        assert_eq!(
            snapshot.network_identity.network_secret.as_deref(),
            Some("")
        );
        let restored: InstanceConfig =
            toml::from_str(&toml::to_string(&snapshot).unwrap()).unwrap();
        assert_eq!(
            restored.network_identity.network_secret.as_deref(),
            Some("")
        );
    }

    #[test]
    fn writing_default_network_credential_and_digest_only_identities_preserves_them() {
        let default = NetworkIdentity::default();
        let identities = [
            NetworkIdentity::new_credential(default.network_name.clone()),
            NetworkIdentity {
                network_name: default.network_name,
                network_secret: None,
                network_secret_digest: default.network_secret_digest,
            },
        ];
        for identity in identities {
            let config = TomlConfig::new_from_str("[secure_mode]\nenabled = true").unwrap();
            config.set_network_identity(identity.clone());
            let snapshot = config.snapshot().unwrap();
            assert!(snapshot.network_identity.network_secret.is_none());
            assert_eq!(
                snapshot.network_identity.network_secret_digest,
                identity.network_secret_digest
            );
        }
    }
}
