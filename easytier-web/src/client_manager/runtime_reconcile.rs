use anyhow::Context as _;
use easytier::{
    common::config::{
        ConfigLoader, EncryptionAlgorithm, PortForwardConfig as RuntimePortForwardConfig,
    },
    proto::{
        acl::Acl,
        api::{
            config::{
                AclPatch, ConfigPatchAction, InstanceConfigPatch, PatchConfigRequest,
                PortForwardPatch, ProxyNetworkPatch,
            },
            instance::{InstanceIdentifier, instance_identifier},
            manage::{
                ConfigSource as RpcConfigSource, GetNetworkInstanceConfigRequest, NetworkConfig,
                RunNetworkInstanceRequest,
            },
        },
        common::{CompressionAlgoPb, Ipv4Inet as RpcIpv4Inet},
        rpc_types::controller::BaseController,
    },
};

use super::session::{SessionConfigClient, SessionRpcClient};

pub(super) enum RuntimeReconcileAction {
    None,
    Run {
        config: Box<NetworkConfig>,
        overwrite: bool,
    },
    Patch(Box<InstanceConfigPatch>),
}

#[derive(Clone, PartialEq)]
struct RuntimeProxyNetwork {
    cidr: String,
    mapped_cidr: Option<String>,
}

fn instance_identifier(inst_id: &str) -> anyhow::Result<InstanceIdentifier> {
    let inst_id = uuid::Uuid::parse_str(inst_id)
        .with_context(|| format!("invalid runtime instance id: {inst_id}"))?;
    Ok(InstanceIdentifier {
        selector: Some(instance_identifier::Selector::Id(inst_id.into())),
    })
}

fn hot_patch_base(config: &NetworkConfig) -> anyhow::Result<NetworkConfig> {
    let data_compress_algo = normalized_data_compress_algo(config.data_compress_algo);
    let encryption_algorithm = normalized_encryption_algorithm(config.encryption_algorithm.clone());
    let mut config = NetworkConfig::new_from_config(config.gen_config()?)?;
    let is_credential_mode = config.network_secret.is_none()
        && config
            .secure_mode
            .as_ref()
            .and_then(|mode| mode.local_private_key.as_deref())
            .is_some_and(|key| !key.is_empty());
    config.acl = None;
    config.port_forwards.clear();
    config.proxy_cidrs.clear();
    config.disable_relay_data = None;
    if config.dhcp.unwrap_or_default() {
        config.virtual_ipv4 = None;
        config.network_length = None;
    }
    if let Some(secure_mode) = config.secure_mode.as_mut() {
        if !is_credential_mode {
            secure_mode.local_private_key = None;
        }
        secure_mode.local_public_key = None;
    }
    config.data_compress_algo = data_compress_algo;
    config.encryption_algorithm = encryption_algorithm;
    Ok(config)
}

fn normalized_data_compress_algo(algo: Option<i32>) -> Option<i32> {
    let default = CompressionAlgoPb::None as i32;
    let effective = algo.map(|algo| if algo < default { default } else { algo });
    effective.filter(|algo| *algo != default)
}

fn normalized_encryption_algorithm(algo: Option<String>) -> Option<String> {
    let default = EncryptionAlgorithm::default().to_string();
    algo.filter(|algo| algo != &default)
}

fn diff_port_forwards(
    current: &[RuntimePortForwardConfig],
    desired: &[RuntimePortForwardConfig],
) -> Vec<PortForwardPatch> {
    let mut patches = Vec::new();
    for cfg in unique_port_forwards(current, desired) {
        let current_count = current.iter().filter(|item| *item == &cfg).count();
        let desired_count = desired.iter().filter(|item| *item == &cfg).count();
        if current_count == desired_count {
            continue;
        }
        if current_count > 0 {
            patches.push(PortForwardPatch {
                action: ConfigPatchAction::Remove as i32,
                cfg: Some(cfg.clone().into()),
            });
        }
        patches.extend((0..desired_count).map(|_| PortForwardPatch {
            action: ConfigPatchAction::Add as i32,
            cfg: Some(cfg.clone().into()),
        }));
    }
    patches
}

fn unique_port_forwards(
    current: &[RuntimePortForwardConfig],
    desired: &[RuntimePortForwardConfig],
) -> Vec<RuntimePortForwardConfig> {
    let mut unique = Vec::new();
    for cfg in current.iter().chain(desired.iter()) {
        if !unique.contains(cfg) {
            unique.push(cfg.clone());
        }
    }
    unique
}

fn parse_rpc_ipv4_inet(value: &str) -> anyhow::Result<RpcIpv4Inet> {
    value
        .parse::<RpcIpv4Inet>()
        .with_context(|| format!("failed to parse runtime ipv4 cidr: {value}"))
}

fn diff_proxy_networks(
    current: &[RuntimeProxyNetwork],
    desired: &[RuntimeProxyNetwork],
) -> anyhow::Result<Vec<ProxyNetworkPatch>> {
    if current == desired {
        return Ok(Vec::new());
    }

    let mut patches = vec![ProxyNetworkPatch {
        action: ConfigPatchAction::Clear as i32,
        cidr: Some(clear_proxy_network_cidr(current, desired)?),
        ..Default::default()
    }];
    for proxy_network in desired {
        patches.push(ProxyNetworkPatch {
            action: ConfigPatchAction::Add as i32,
            cidr: Some(parse_rpc_ipv4_inet(&proxy_network.cidr)?),
            mapped_cidr: proxy_network
                .mapped_cidr
                .as_deref()
                .map(parse_rpc_ipv4_inet)
                .transpose()?,
        });
    }
    Ok(patches)
}

fn clear_proxy_network_cidr(
    current: &[RuntimeProxyNetwork],
    desired: &[RuntimeProxyNetwork],
) -> anyhow::Result<RpcIpv4Inet> {
    let cidr = desired
        .first()
        .or_else(|| current.first())
        .map(|proxy_network| proxy_network.cidr.as_str())
        .unwrap_or("0.0.0.0/0");
    parse_rpc_ipv4_inet(cidr)
}

fn normalized_acl(acl: &Option<Acl>) -> Option<Acl> {
    let acl = acl.clone().unwrap_or_default();
    (acl != Acl::default()).then_some(acl)
}

fn normalized_port_forwards(
    config: &NetworkConfig,
) -> anyhow::Result<Vec<RuntimePortForwardConfig>> {
    Ok(config
        .gen_config()?
        .get_port_forwards()
        .into_iter()
        .map(|cfg| {
            RuntimePortForwardConfig::from(easytier::proto::common::PortForwardConfigPb::from(cfg))
        })
        .collect())
}

fn normalized_proxy_networks(config: &NetworkConfig) -> anyhow::Result<Vec<RuntimeProxyNetwork>> {
    Ok(config
        .gen_config()?
        .get_proxy_cidrs()
        .into_iter()
        .map(|proxy_network| RuntimeProxyNetwork {
            cidr: proxy_network.cidr.to_string(),
            mapped_cidr: proxy_network.mapped_cidr.map(|cidr| cidr.to_string()),
        })
        .collect())
}

fn normalized_disable_relay_data(config: &NetworkConfig) -> anyhow::Result<bool> {
    Ok(config.gen_config()?.get_flags().disable_relay_data)
}

fn web_source_runtime_patch(
    current: &NetworkConfig,
    desired: &NetworkConfig,
) -> anyhow::Result<Option<InstanceConfigPatch>> {
    if let Some(desired_hostname) = desired
        .hostname
        .as_deref()
        .filter(|hostname| !hostname.is_empty())
        && current.hostname.as_deref() != Some(desired_hostname)
    {
        return Ok(None);
    }
    let mut current_base = hot_patch_base(current)?;
    let mut desired_base = hot_patch_base(desired)?;
    current_base.hostname = None;
    desired_base.hostname = None;
    if current_base != desired_base {
        return Ok(None);
    }

    let mut patch = InstanceConfigPatch::default();
    let current_acl = normalized_acl(&current.acl);
    let desired_acl = normalized_acl(&desired.acl);
    if current_acl != desired_acl {
        patch.acl = Some(AclPatch {
            acl: Some(desired_acl.unwrap_or_default()),
            ..Default::default()
        });
    }

    let current_port_forwards = normalized_port_forwards(current)?;
    let desired_port_forwards = normalized_port_forwards(desired)?;
    if current_port_forwards != desired_port_forwards {
        patch.port_forwards = diff_port_forwards(&current_port_forwards, &desired_port_forwards);
    }

    let current_proxy_networks = normalized_proxy_networks(current)?;
    let desired_proxy_networks = normalized_proxy_networks(desired)?;
    if current_proxy_networks != desired_proxy_networks {
        if current_proxy_networks.is_empty() {
            return Ok(None);
        }
        patch.proxy_networks =
            diff_proxy_networks(&current_proxy_networks, &desired_proxy_networks)?;
    }

    let current_disable_relay_data = normalized_disable_relay_data(current)?;
    let desired_disable_relay_data = normalized_disable_relay_data(desired)?;
    if current_disable_relay_data != desired_disable_relay_data {
        patch.disable_relay_data = Some(desired_disable_relay_data);
    }

    Ok(Some(patch))
}

fn ensure_runtime_config_converged(
    current: &NetworkConfig,
    desired: &NetworkConfig,
) -> anyhow::Result<()> {
    let patch = web_source_runtime_patch(current, desired)?;
    match patch {
        Some(patch) if patch == InstanceConfigPatch::default() => Ok(()),
        Some(patch) => anyhow::bail!("runtime config still needs patch after reconcile: {patch:?}"),
        None => anyhow::bail!("runtime config still needs full overwrite after reconcile"),
    }
}

async fn run_web_source_instance(
    rpc_client: &mut SessionRpcClient,
    inst_id: &str,
    config: NetworkConfig,
    overwrite: bool,
) -> anyhow::Result<()> {
    rpc_client
        .run_network_instance(
            BaseController::default(),
            RunNetworkInstanceRequest {
                inst_id: Some(inst_id.to_string().into()),
                config: Some(config),
                overwrite,
                source: RpcConfigSource::Web as i32,
            },
        )
        .await?;
    Ok(())
}

pub(super) async fn get_runtime_config(
    rpc_client: &mut SessionRpcClient,
    inst_id: &str,
) -> anyhow::Result<NetworkConfig> {
    rpc_client
        .get_network_instance_config(
            BaseController::default(),
            GetNetworkInstanceConfigRequest {
                inst_id: Some(inst_id.to_string().into()),
            },
        )
        .await?
        .config
        .ok_or_else(|| anyhow::anyhow!("runtime returned empty config for {inst_id}"))
}

pub(super) async fn prepare_web_source_runtime_reconcile(
    rpc_client: &mut SessionRpcClient,
    inst_id: &str,
    desired_config: NetworkConfig,
    is_running: bool,
) -> anyhow::Result<RuntimeReconcileAction> {
    if !is_running {
        return Ok(RuntimeReconcileAction::Run {
            config: Box::new(desired_config),
            overwrite: false,
        });
    }

    let current_config = get_runtime_config(rpc_client, inst_id).await?;

    prepare_web_source_runtime_reconcile_from_current(&current_config, desired_config)
}

pub(super) fn prepare_web_source_runtime_reconcile_from_current(
    current_config: &NetworkConfig,
    desired_config: NetworkConfig,
) -> anyhow::Result<RuntimeReconcileAction> {
    let Some(patch) = web_source_runtime_patch(current_config, &desired_config)? else {
        return Ok(RuntimeReconcileAction::Run {
            config: Box::new(desired_config),
            overwrite: true,
        });
    };
    if patch == InstanceConfigPatch::default() {
        return Ok(RuntimeReconcileAction::None);
    }

    Ok(RuntimeReconcileAction::Patch(Box::new(patch)))
}

pub(super) async fn apply_web_source_runtime_reconcile(
    rpc_client: &mut SessionRpcClient,
    config_client: &mut SessionConfigClient,
    inst_id: &str,
    desired_config: NetworkConfig,
    action: RuntimeReconcileAction,
) -> anyhow::Result<NetworkConfig> {
    match action {
        RuntimeReconcileAction::None => Ok(desired_config),
        RuntimeReconcileAction::Run { config, overwrite } => {
            run_web_source_instance(rpc_client, inst_id, *config, overwrite).await?;
            Ok(desired_config)
        }
        RuntimeReconcileAction::Patch(patch) => {
            config_client
                .patch_config(
                    BaseController::default(),
                    PatchConfigRequest {
                        instance: Some(instance_identifier(inst_id)?),
                        patch: Some(*patch),
                    },
                )
                .await?;
            let current_config = get_runtime_config(rpc_client, inst_id).await?;
            ensure_runtime_config_converged(&current_config, &desired_config)?;
            Ok(current_config)
        }
    }
}

#[cfg(test)]
mod tests {
    use easytier::proto::{
        api::{
            config::ConfigPatchAction,
            manage::{NetworkingMethod, PortForwardConfig},
        },
        common::{CompressionAlgoPb, SocketType},
    };

    use super::*;

    fn config_with_port_forwards(port_forwards: Vec<PortForwardConfig>) -> NetworkConfig {
        NetworkConfig {
            instance_id: Some("11111111-1111-1111-1111-111111111111".to_string()),
            dhcp: Some(true),
            network_name: Some("managed".to_string()),
            network_secret: Some("secret".to_string()),
            networking_method: Some(NetworkingMethod::Manual as i32),
            port_forwards,
            ..Default::default()
        }
    }

    fn port_forward(bind_port: u32, dst_port: u32) -> PortForwardConfig {
        PortForwardConfig {
            bind_ip: "127.0.0.1".to_string(),
            bind_port,
            dst_ip: "10.144.0.1".to_string(),
            dst_port,
            proto: "tcp".to_string(),
        }
    }

    fn patch_port(patch: &PortForwardPatch) -> (i32, u32, u32, i32) {
        let cfg = patch.cfg.as_ref().expect("port forward patch cfg");
        (
            patch.action,
            cfg.bind_addr.as_ref().expect("bind addr").port,
            cfg.dst_addr.as_ref().expect("dst addr").port,
            cfg.socket_type,
        )
    }

    fn patch_proxy_network(patch: &ProxyNetworkPatch) -> (i32, String, Option<String>) {
        (
            patch.action,
            patch.cidr.map(|cidr| cidr.to_string()).unwrap_or_default(),
            patch.mapped_cidr.map(|cidr| cidr.to_string()),
        )
    }

    #[test]
    fn runtime_patch_ignores_runtime_defaults_and_adds_port_forward() {
        let mut current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        current.virtual_ipv4 = Some("10.144.0.2".to_string());
        current.network_length = Some(16);
        current.bind_device = Some(true);
        current.dev_name = Some(String::new());
        current.disable_ipv6 = Some(false);
        current.mtu = Some(1380);
        current.multi_thread = Some(true);

        let desired =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23007, 3389)]);

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.port_forwards.len(), 1);
        assert_eq!(
            patch_port(&patch.port_forwards[0]),
            (
                ConfigPatchAction::Add as i32,
                23007,
                3389,
                SocketType::Tcp as i32
            )
        );
    }

    #[test]
    fn runtime_patch_removes_deleted_port_forward_without_clear() {
        let current =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23007, 3389)]);
        let desired = config_with_port_forwards(vec![port_forward(23000, 5174)]);

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.port_forwards.len(), 1);
        assert_eq!(
            patch_port(&patch.port_forwards[0]),
            (
                ConfigPatchAction::Remove as i32,
                23007,
                3389,
                SocketType::Tcp as i32
            )
        );
    }

    #[test]
    fn runtime_patch_reconciles_duplicate_port_forward_count() {
        let current =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23000, 5174)]);
        let desired = config_with_port_forwards(vec![port_forward(23000, 5174)]);

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.port_forwards.len(), 2);
        assert_eq!(
            patch_port(&patch.port_forwards[0]),
            (
                ConfigPatchAction::Remove as i32,
                23000,
                5174,
                SocketType::Tcp as i32
            )
        );
        assert_eq!(
            patch_port(&patch.port_forwards[1]),
            (
                ConfigPatchAction::Add as i32,
                23000,
                5174,
                SocketType::Tcp as i32
            )
        );
    }

    #[test]
    fn runtime_convergence_rejects_stale_extra_port_forward() {
        let current = config_with_port_forwards(vec![
            port_forward(23000, 5174),
            port_forward(23007, 3389),
            port_forward(23100, 8080),
        ]);
        let desired =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23007, 3389)]);

        let err = ensure_runtime_config_converged(&current, &desired)
            .expect_err("extra runtime port forward should not converge");

        assert!(
            err.to_string()
                .contains("runtime config still needs patch after reconcile"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn runtime_patch_canonicalizes_port_forward_protocol() {
        let current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        let mut desired_port_forward = port_forward(23000, 5174);
        desired_port_forward.proto = "TCP".to_string();
        let desired = config_with_port_forwards(vec![desired_port_forward]);

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch, InstanceConfigPatch::default());
        ensure_runtime_config_converged(&current, &desired).expect("runtime converged");
    }

    #[test]
    fn runtime_patch_rejects_non_hot_config_change() {
        let current = config_with_port_forwards(Vec::new());
        let mut desired = current.clone();
        desired.network_secret = Some("new-secret".to_string());

        let patch = web_source_runtime_patch(&current, &desired).expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn runtime_patch_rejects_routes_change() {
        let mut current = config_with_port_forwards(Vec::new());
        current.enable_manual_routes = Some(true);
        current.routes = vec!["10.1.0.0/16".to_string(), "10.2.0.0/16".to_string()];
        let mut desired = config_with_port_forwards(Vec::new());
        desired.enable_manual_routes = Some(true);
        desired.routes = vec!["10.2.0.0/16".to_string(), "10.3.0.0/16".to_string()];

        let patch = web_source_runtime_patch(&current, &desired).expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn runtime_patch_replaces_proxy_networks() {
        let mut current = config_with_port_forwards(Vec::new());
        current.proxy_cidrs = vec![
            "10.1.0.0/16".to_string(),
            "10.2.0.0/16->10.20.0.0/16".to_string(),
        ];
        let mut desired = config_with_port_forwards(Vec::new());
        desired.proxy_cidrs = vec![
            "10.2.0.0/16->10.21.0.0/16".to_string(),
            "10.3.0.0/16".to_string(),
        ];

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.proxy_networks.len(), 3);
        assert_eq!(
            patch_proxy_network(&patch.proxy_networks[0]),
            (
                ConfigPatchAction::Clear as i32,
                "10.2.0.0/16".to_string(),
                None
            )
        );
        assert_eq!(
            patch_proxy_network(&patch.proxy_networks[1]),
            (
                ConfigPatchAction::Add as i32,
                "10.2.0.0/16".to_string(),
                Some("10.21.0.0/16".to_string())
            )
        );
        assert_eq!(
            patch_proxy_network(&patch.proxy_networks[2]),
            (
                ConfigPatchAction::Add as i32,
                "10.3.0.0/16".to_string(),
                None
            )
        );
    }

    #[test]
    fn runtime_patch_replaces_proxy_networks_with_same_source_cidr() {
        let mut current = config_with_port_forwards(Vec::new());
        current.proxy_cidrs = vec![
            "10.1.2.0/24".to_string(),
            "10.1.2.0/24->10.1.3.0/24".to_string(),
        ];
        let mut desired = config_with_port_forwards(Vec::new());
        desired.proxy_cidrs = vec!["10.1.2.0/24->10.1.3.0/24".to_string()];

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.proxy_networks.len(), 2);
        assert_eq!(
            patch_proxy_network(&patch.proxy_networks[0]),
            (
                ConfigPatchAction::Clear as i32,
                "10.1.2.0/24".to_string(),
                None
            )
        );
        assert_eq!(
            patch_proxy_network(&patch.proxy_networks[1]),
            (
                ConfigPatchAction::Add as i32,
                "10.1.2.0/24".to_string(),
                Some("10.1.3.0/24".to_string())
            )
        );
    }

    #[test]
    fn runtime_patch_rejects_proxy_network_empty_to_nonempty() {
        let current = config_with_port_forwards(Vec::new());
        let mut desired = config_with_port_forwards(Vec::new());
        desired.proxy_cidrs = vec!["10.1.2.0/24".to_string()];

        let patch = web_source_runtime_patch(&current, &desired).expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn runtime_patch_clears_proxy_networks_with_legacy_compatible_cidr() {
        let mut current = config_with_port_forwards(Vec::new());
        current.proxy_cidrs = vec!["10.1.2.0/24".to_string()];
        let desired = config_with_port_forwards(Vec::new());

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.proxy_networks.len(), 1);
        assert_eq!(
            patch_proxy_network(&patch.proxy_networks[0]),
            (
                ConfigPatchAction::Clear as i32,
                "10.1.2.0/24".to_string(),
                None
            )
        );
    }

    #[test]
    fn runtime_patch_updates_disable_relay_data() {
        let current = config_with_port_forwards(Vec::new());
        let mut desired = current.clone();
        desired.disable_relay_data = Some(true);

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.disable_relay_data, Some(true));
    }

    #[test]
    fn runtime_patch_still_rejects_unsupported_flag_change() {
        let current = config_with_port_forwards(Vec::new());
        let mut desired = current.clone();
        desired.no_tun = Some(true);

        let patch = web_source_runtime_patch(&current, &desired).expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn runtime_patch_rejects_encryption_algorithm_change() {
        let current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        let mut desired = current.clone();
        desired.encryption_algorithm = Some("managed-test-algo".to_string());

        let patch = web_source_runtime_patch(&current, &desired).expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn runtime_patch_rejects_data_compress_algo_change() {
        let current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        let mut desired = current.clone();
        desired.data_compress_algo = Some(CompressionAlgoPb::Zstd as i32);

        let patch = web_source_runtime_patch(&current, &desired).expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn runtime_patch_rejects_credential_private_key_change() {
        let mut current = config_with_port_forwards(Vec::new());
        current.network_secret = None;
        current.secure_mode = Some(easytier::proto::common::SecureModeConfig {
            enabled: true,
            local_private_key: Some("mUuD5fsIm/ftvgS4WBAYFMNLqWX3qT9rnm4PrnOqb9s=".to_string()),
            local_public_key: None,
        });
        let mut desired = current.clone();
        desired.secure_mode = Some(easytier::proto::common::SecureModeConfig {
            enabled: true,
            local_private_key: Some("aEpz80FuYbaY4QLJizAIuIcK4TYsoSA9jHHCXCOQJoc=".to_string()),
            local_public_key: None,
        });

        let patch = web_source_runtime_patch(&current, &desired).expect("build patch");

        assert!(patch.is_none());
    }

    #[test]
    fn runtime_patch_ignores_generated_secure_key_when_network_secret_exists() {
        let mut current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        current.secure_mode = Some(easytier::proto::common::SecureModeConfig {
            enabled: true,
            local_private_key: Some("mUuD5fsIm/ftvgS4WBAYFMNLqWX3qT9rnm4PrnOqb9s=".to_string()),
            local_public_key: Some("4x6L5dZjB8hsPO4f96Hyhi4xFealBu6i3BxRVBYR1Fc=".to_string()),
        });
        let mut desired =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23007, 3389)]);
        desired.secure_mode = Some(easytier::proto::common::SecureModeConfig {
            enabled: true,
            local_private_key: None,
            local_public_key: None,
        });

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.port_forwards.len(), 1);
        assert_eq!(
            patch_port(&patch.port_forwards[0]),
            (
                ConfigPatchAction::Add as i32,
                23007,
                3389,
                SocketType::Tcp as i32
            )
        );
    }

    #[test]
    fn runtime_patch_ignores_runtime_hostname_when_desired_omits_hostname() {
        let mut current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        current.hostname = Some("runtime-host".to_string());
        let desired =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23007, 3389)]);

        let patch = web_source_runtime_patch(&current, &desired)
            .expect("build patch")
            .expect("hot patch");

        assert_eq!(patch.port_forwards.len(), 1);
        assert_eq!(
            patch_port(&patch.port_forwards[0]),
            (
                ConfigPatchAction::Add as i32,
                23007,
                3389,
                SocketType::Tcp as i32
            )
        );
    }

    #[test]
    fn runtime_patch_rejects_explicit_desired_hostname_change() {
        let current = config_with_port_forwards(vec![port_forward(23000, 5174)]);
        let mut desired =
            config_with_port_forwards(vec![port_forward(23000, 5174), port_forward(23007, 3389)]);
        desired.hostname =
            Some(easytier::common::config::TomlConfigLoader::default().get_hostname());

        let patch = web_source_runtime_patch(&current, &desired).expect("build patch");

        assert!(patch.is_none());
    }
}
