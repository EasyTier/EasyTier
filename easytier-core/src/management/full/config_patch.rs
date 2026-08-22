use std::{fmt::Debug, sync::Arc};

use anyhow::Context as _;
use easytier_proto::api::config::{
    self, AclPatch, ConfigPatchAction, ExitNodePatch, InstanceConfigPatch, Patchable,
    PortForwardPatch, ProxyNetworkPatch, RoutePatch, UrlPatch, VpnPortalClientPatch,
};

use crate::{
    config::{
        peers::AclRuleConfig,
        runtime::CoreInstanceRuntimeConfig,
        toml::{ConfigLoader as _, ManagedCredentialConfig, TomlConfig},
    },
    instance::{CoreInstance, CoreInstanceConfig, CoreInstanceHost, CoreInstanceState},
    peers::credential_manager::CredentialManager,
};

#[async_trait::async_trait]
pub trait ConfigPatchPersistence: Send + Sync {
    async fn persist(&self, instance_id: uuid::Uuid, config: &TomlConfig) -> anyhow::Result<()>;
}

pub async fn apply_config_patch<H>(
    instance: &Arc<CoreInstance<H>>,
    patch: InstanceConfigPatch,
    persistence: Option<&dyn ConfigPatchPersistence>,
) -> anyhow::Result<()>
where
    H: CoreInstanceHost,
{
    let _operation = instance.operation.lock().await;
    if instance.state() != CoreInstanceState::Running {
        anyhow::bail!("instance is not ready; config patch rejected");
    }

    let config = instance
        .toml_config()
        .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))?;
    let candidate = config.detached_snapshot();
    let parsed_prefix =
        parse_ipv6_public_addr_prefix_patch(patch.ipv6_public_addr_prefix.as_deref())?;
    // Take the credential set out first so the host-facing copy below never
    // clones secret material.
    let mut patch = patch;
    let managed_credentials = patch.managed_credentials.take();
    let patch_for_host = patch_without_managed_credentials(&patch);

    // Preserve the existing ordered partial-commit contract: earlier valid
    // sub-patches remain applied if a later sub-patch fails.
    let patch_result: anyhow::Result<(bool, bool)> = async {
        let result = patch_port_forwards(&candidate, patch.port_forwards);
        validate_and_commit_candidate(instance, &config, &candidate)?;
        result?;

        let result = patch_acl(&candidate, patch.acl);
        validate_and_commit_candidate(instance, &config, &candidate)?;
        result?;

        let result = patch_proxy_networks(&candidate, patch.proxy_networks);
        validate_and_commit_candidate(instance, &config, &candidate)?;
        result?;

        let result = patch_routes(&candidate, patch.routes);
        validate_and_commit_candidate(instance, &config, &candidate)?;
        result?;

        let result = patch_exit_nodes_config(&candidate, patch.exit_nodes);
        let normalized = validate_and_commit_candidate(instance, &config, &candidate)?;
        result?;
        instance
            .update_exit_nodes(normalized.peer.exit_nodes.clone())
            .await;

        let result = patch_mapped_listeners(&candidate, patch.mapped_listeners);
        validate_and_commit_candidate(instance, &config, &candidate)?;
        result?;

        patch_connectors(instance, patch.connectors)?;

        let mut provider_config_changed = false;
        if let Some(hostname) = patch.hostname {
            candidate.set_hostname(Some(hostname));
        }
        if let Some(ipv4) = patch.ipv4
            && !candidate.get_dhcp()
        {
            candidate.set_ipv4(Some(ipv4.into()));
        }
        if let Some(ipv6) = patch.ipv6 {
            candidate.set_ipv6(Some(ipv6.into()));
        }
        if let Some(disable_relay_data) = patch.disable_relay_data {
            let mut flags = candidate.get_flags();
            flags.disable_relay_data = disable_relay_data;
            candidate.set_flags(flags);
        }
        if let Some(enabled) = patch.ipv6_public_addr_provider {
            candidate.set_ipv6_public_addr_provider(enabled);
            provider_config_changed = true;
        }
        if let Some(enabled) = patch.ipv6_public_addr_auto {
            candidate.set_ipv6_public_addr_auto(enabled);
        }
        if let Some(prefix) = parsed_prefix {
            candidate.set_ipv6_public_addr_prefix(prefix);
            provider_config_changed = true;
        }
        let mut managed_credentials_changed = false;

        // Runs last so client validation sees the fully patched candidate,
        // including routes and the node IPv4 set earlier in this request.
        if !patch.vpn_portal_clients.is_empty() {
            apply_vpn_portal_client_patches(&candidate, patch.vpn_portal_clients)?;
            // Deep-validate and hot-apply before committing, so a rejected
            // client set leaves neither the shared TOML model nor the live
            // portal changed.
            let normalized = validate_candidate(instance, &candidate)?;
            #[cfg(feature = "vpn-portal")]
            {
                let portal = normalized
                    .vpn_portal
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("VPN portal is not configured"))?;
                instance
                    .update_vpn_portal_clients(
                        portal.clients,
                        &runtime_config_from_normalized(&normalized),
                    )
                    .await?;
            }
            #[cfg(not(feature = "vpn-portal"))]
            {
                let _ = normalized;
            }
            validate_and_commit_candidate(instance, &config, &candidate)?;
        }

        if let Some(managed) = &managed_credentials {
            // Managed credential patch transaction: validate and reserve →
            // persist → install. The reservation prevents base or ephemeral
            // credential mutations from invalidating the replacement while
            // the durable write is in flight, without holding a synchronous
            // lock across the await. Dropping the replacement before install
            // releases the reservation.
            let credential_manager = instance.credential_manager();
            let entries = managed
                .entries
                .iter()
                .map(|credential| ManagedCredentialConfig {
                    credential_id: credential.credential_id.clone(),
                    credential_secret: credential.credential_secret.clone(),
                    groups: credential.groups.clone(),
                    allow_relay: credential.allow_relay,
                    allowed_proxy_cidrs: credential.allowed_proxy_cidrs.clone(),
                    expiry_unix: credential.expiry_unix,
                    reusable: credential.reusable.unwrap_or(true),
                })
                .collect::<Vec<_>>();
            let replacement = credential_manager
                .validate_managed_credentials(&entries)
                .map_err(anyhow::Error::msg)?;
            candidate.set_managed_credentials(entries);
            validate_candidate(instance, &candidate)?;
            // File-backed configs persist every successful patch, so the
            // durable file and the shared TOML model can never diverge.
            persistence
                .ok_or_else(|| anyhow::anyhow!("durable config patching is unavailable"))?
                .persist(instance.instance_id(), &candidate)
                .await?;
            config.replace_from_snapshot(&candidate);
            managed_credentials_changed =
                CredentialManager::install_managed_credentials(replacement);
        } else {
            validate_and_commit_candidate(instance, &config, &candidate)?;
        }
        let normalized = validate_candidate(instance, &candidate)?;
        let runtime = runtime_config_from_normalized(&normalized);
        if patch_for_host != InstanceConfigPatch::default() {
            instance
                .instance_runtime
                .synchronize_config(&patch_for_host, &runtime);
        }
        Ok((provider_config_changed, managed_credentials_changed))
    }
    .await;

    instance
        .update_runtime_config_under_operation(runtime_config_from_toml(instance, &config)?)
        .await?;
    let (provider_config_changed, managed_credentials_changed) = patch_result?;
    if patch_for_host != InstanceConfigPatch::default() {
        instance
            .instance_runtime
            .publish_config_patch(patch_for_host);
    }
    if managed_credentials_changed {
        instance.notify_credential_changed();
    }
    #[cfg(feature = "public-ipv6-provider")]
    if provider_config_changed && instance.state() == CoreInstanceState::Running {
        instance.reconcile_public_ipv6_provider().await;
    }
    #[cfg(not(feature = "public-ipv6-provider"))]
    let _ = provider_config_changed;
    Ok(())
}

fn patch_without_managed_credentials(patch: &InstanceConfigPatch) -> InstanceConfigPatch {
    let mut patch = patch.clone();
    patch.managed_credentials = None;
    patch
}

fn validate_candidate<H>(
    instance: &CoreInstance<H>,
    candidate: &TomlConfig,
) -> anyhow::Result<CoreInstanceConfig>
where
    H: CoreInstanceHost,
{
    let normalized = CoreInstanceConfig::from_toml_with_host(candidate, instance.host_config())?;
    let runtime = runtime_config_from_normalized(&normalized);
    runtime.services.public_ipv6_provider.validate()?;
    instance.validate_runtime_config_capabilities(&runtime)?;
    Ok(normalized)
}

fn validate_and_commit_candidate<H>(
    instance: &CoreInstance<H>,
    shared: &TomlConfig,
    candidate: &TomlConfig,
) -> anyhow::Result<CoreInstanceConfig>
where
    H: CoreInstanceHost,
{
    let normalized = validate_candidate(instance, candidate)?;
    shared.replace_from_snapshot(candidate);
    Ok(normalized)
}

fn runtime_config_from_toml<H>(
    instance: &CoreInstance<H>,
    config: &TomlConfig,
) -> anyhow::Result<CoreInstanceRuntimeConfig>
where
    H: CoreInstanceHost,
{
    let normalized = CoreInstanceConfig::from_toml_with_host(config, instance.host_config())?;
    Ok(runtime_config_from_normalized(&normalized))
}

fn runtime_config_from_normalized(config: &CoreInstanceConfig) -> CoreInstanceRuntimeConfig {
    CoreInstanceRuntimeConfig {
        services: config.connectivity.runtime.clone(),
        peer: Arc::new(config.peer.snapshot.clone()),
    }
}

fn parse_ipv6_public_addr_prefix_patch(
    prefix: Option<&str>,
) -> anyhow::Result<Option<Option<cidr::Ipv6Cidr>>> {
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return Ok(Some(None));
    }
    Ok(Some(Some(prefix.parse().with_context(|| {
        format!("failed to parse ipv6 public address prefix: {prefix}")
    })?)))
}

fn trace_patchables<T: Debug>(patches: &[Patchable<T>]) {
    for patch in patches {
        match patch.action {
            Some(ConfigPatchAction::Add) | Some(ConfigPatchAction::Remove) => {
                if let Some(value) = &patch.value {
                    tracing::info!(?patch.action, ?value, "applying configuration patch");
                } else {
                    tracing::warn!(?patch.action, "ignored configuration patch without value");
                }
            }
            Some(ConfigPatchAction::Clear) => {
                tracing::info!("clearing configuration collection");
            }
            None => tracing::warn!("ignored invalid configuration patch action"),
        }
    }
}

#[cfg(test)]
mod managed_credential_tests {
    use easytier_proto::api::manage::ManagedCredentialSet;

    use super::*;

    #[test]
    fn event_patch_drops_managed_credential_secrets() {
        let patch = InstanceConfigPatch {
            managed_credentials: Some(ManagedCredentialSet::default()),
            ..Default::default()
        };

        assert!(
            patch_without_managed_credentials(&patch)
                .managed_credentials
                .is_none()
        );
    }
}

fn patch_port_forwards(config: &TomlConfig, patches: Vec<PortForwardPatch>) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut current = config.get_port_forwards();
    let patches = patches
        .into_iter()
        .map(|patch| Patchable {
            action: ConfigPatchAction::try_from(patch.action).ok(),
            value: patch.cfg.map(Into::into),
        })
        .collect::<Vec<_>>();
    trace_patchables(&patches);
    config::patch_vec(&mut current, patches);
    config.set_port_forwards(current);
    Ok(())
}

fn patch_acl(config: &TomlConfig, patch: Option<AclPatch>) -> anyhow::Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };
    let mut acl = AclRuleConfig {
        acl: config.get_acl(),
        tcp_whitelist: config.get_tcp_whitelist(),
        udp_whitelist: config.get_udp_whitelist(),
        whitelist_priority: None,
    };
    if let Some(next) = patch.acl {
        acl.acl = Some(next);
    }
    if !patch.tcp_whitelist.is_empty() {
        let patches = patch
            .tcp_whitelist
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        trace_patchables(&patches);
        config::patch_vec(&mut acl.tcp_whitelist, patches);
    }
    if !patch.udp_whitelist.is_empty() {
        let patches = patch
            .udp_whitelist
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        trace_patchables(&patches);
        config::patch_vec(&mut acl.udp_whitelist, patches);
    }
    acl.build()?;
    config.set_acl(acl.acl);
    config.set_tcp_whitelist(acl.tcp_whitelist);
    config.set_udp_whitelist(acl.udp_whitelist);
    Ok(())
}

fn patch_proxy_networks(
    config: &TomlConfig,
    patches: Vec<ProxyNetworkPatch>,
) -> anyhow::Result<()> {
    for patch in patches {
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => {
                let Some(cidr) = patch.cidr.map(Into::into) else {
                    tracing::warn!("ignored proxy-network add without CIDR");
                    continue;
                };
                config.add_proxy_cidr(cidr, patch.mapped_cidr.map(Into::into))?;
            }
            Ok(ConfigPatchAction::Remove) => {
                let Some(cidr) = patch.cidr.map(Into::into) else {
                    tracing::warn!("ignored proxy-network remove without CIDR");
                    continue;
                };
                config.remove_proxy_cidr(cidr);
            }
            Ok(ConfigPatchAction::Clear) => config.clear_proxy_cidrs(),
            Err(_) => tracing::warn!(
                action = patch.action,
                "ignored invalid proxy-network action"
            ),
        }
    }
    Ok(())
}

fn patch_routes(config: &TomlConfig, patches: Vec<RoutePatch>) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut current = config.get_routes().unwrap_or_default();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    config::patch_vec(&mut current, patches);
    config.set_routes((!current.is_empty()).then_some(current));
    Ok(())
}

fn patch_exit_nodes_config(
    config: &TomlConfig,
    patches: Vec<ExitNodePatch>,
) -> anyhow::Result<Vec<std::net::IpAddr>> {
    if patches.is_empty() {
        return Ok(config.get_exit_nodes());
    }
    let mut current = config.get_exit_nodes();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    config::patch_vec(&mut current, patches);
    config.set_exit_nodes(current.clone());
    Ok(current)
}

fn patch_mapped_listeners(config: &TomlConfig, patches: Vec<UrlPatch>) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut current = config.get_mapped_listeners();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    config::patch_vec(&mut current, patches);
    config.set_mapped_listeners((!current.is_empty()).then_some(current));
    Ok(())
}

/// Applies VPN portal client patches to the candidate TOML model. The live
/// portal is updated by the caller after the candidate commits, so deep
/// validation runs against the final configuration state.
fn apply_vpn_portal_client_patches(
    config: &TomlConfig,
    patches: Vec<VpnPortalClientPatch>,
) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut portal = config
        .get_vpn_portal_config()
        .ok_or_else(|| anyhow::anyhow!("VPN portal is not configured; cannot patch its clients"))?;
    for patch in patches {
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => {
                let Some(client) = patch.client else {
                    tracing::warn!("ignored VPN portal client add without client");
                    continue;
                };
                let virtual_ip = client
                    .virtual_ip
                    .parse::<std::net::Ipv4Addr>()
                    .with_context(|| {
                        format!(
                            "invalid VPN portal client virtual IP: {}",
                            client.virtual_ip
                        )
                    })?;
                portal
                    .clients
                    .push(crate::config::toml::VpnPortalClientConfig {
                        name: client.name,
                        virtual_ip,
                        groups: client.groups,
                    });
            }
            Ok(ConfigPatchAction::Remove) => {
                let Some(client) = patch.client else {
                    tracing::warn!("ignored VPN portal client remove without client");
                    continue;
                };
                let before = portal.clients.len();
                portal
                    .clients
                    .retain(|existing| existing.name != client.name);
                if portal.clients.len() == before {
                    anyhow::bail!("VPN portal client not found: {}", client.name);
                }
            }
            Ok(ConfigPatchAction::Clear) => portal.clients.clear(),
            Err(_) => tracing::warn!(
                action = patch.action,
                "ignored invalid VPN portal client action"
            ),
        }
    }
    config.set_vpn_portal_config(portal);
    Ok(())
}

fn patch_connectors<H>(instance: &CoreInstance<H>, patches: Vec<UrlPatch>) -> anyhow::Result<()>
where
    H: CoreInstanceHost,
{
    for patch in patches {
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => {
                let Some(url) = patch.url.map(Into::<url::Url>::into) else {
                    tracing::warn!("ignored connector add without URL");
                    continue;
                };
                if !instance.host_config().accepts_runtime_url(&url) {
                    continue;
                }
                instance.add_connector(url)?;
            }
            Ok(ConfigPatchAction::Remove) => {
                let Some(url) = patch.url.map(Into::<url::Url>::into) else {
                    tracing::warn!("ignored connector remove without URL");
                    continue;
                };
                if !instance.host_config().accepts_runtime_url(&url) {
                    continue;
                }
                if !instance.remove_connector(&url) {
                    anyhow::bail!("connector not found: {url}");
                }
            }
            Ok(ConfigPatchAction::Clear) => instance.clear_connectors(),
            Err(_) => tracing::warn!(action = patch.action, "ignored invalid connector action"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::toml::{VpnPortalClientConfig, VpnPortalConfig};
    use easytier_proto::api::manage::VpnPortalClientConfig as ClientPb;

    fn portal_config() -> TomlConfig {
        let config = TomlConfig::default();
        config.set_vpn_portal_config(VpnPortalConfig {
            wireguard_listen: "0.0.0.0:51820".parse().unwrap(),
            wireguard_private_key: None,
            clients: vec![VpnPortalClientConfig {
                name: "alice".to_owned(),
                virtual_ip: "10.0.0.2".parse().unwrap(),
                groups: Vec::new(),
            }],
        });
        config
    }

    fn configured_names(config: &TomlConfig) -> Vec<String> {
        config
            .get_vpn_portal_config()
            .unwrap()
            .clients
            .into_iter()
            .map(|client| client.name)
            .collect()
    }

    fn add(name: &str, ip: &str) -> VpnPortalClientPatch {
        VpnPortalClientPatch {
            action: ConfigPatchAction::Add as i32,
            client: Some(ClientPb {
                name: name.to_owned(),
                virtual_ip: ip.to_owned(),
                groups: Vec::new(),
            }),
        }
    }

    fn remove(name: &str) -> VpnPortalClientPatch {
        VpnPortalClientPatch {
            action: ConfigPatchAction::Remove as i32,
            client: Some(ClientPb {
                name: name.to_owned(),
                virtual_ip: String::new(),
                groups: Vec::new(),
            }),
        }
    }

    #[test]
    fn vpn_portal_client_patches_add_remove_and_clear() {
        let config = portal_config();

        apply_vpn_portal_client_patches(&config, vec![add("bob", "10.0.0.3")]).unwrap();
        assert_eq!(configured_names(&config), ["alice", "bob"]);

        apply_vpn_portal_client_patches(&config, vec![remove("alice")]).unwrap();
        assert_eq!(configured_names(&config), ["bob"]);

        apply_vpn_portal_client_patches(
            &config,
            vec![VpnPortalClientPatch {
                action: ConfigPatchAction::Clear as i32,
                client: None,
            }],
        )
        .unwrap();
        assert!(configured_names(&config).is_empty());
    }

    #[test]
    fn vpn_portal_client_patches_reject_missing_prerequisites() {
        let bare = TomlConfig::default();
        let error =
            apply_vpn_portal_client_patches(&bare, vec![add("alice", "10.0.0.2")]).unwrap_err();
        assert!(error.to_string().contains("not configured"));

        let config = portal_config();
        let error = apply_vpn_portal_client_patches(&config, vec![remove("ghost")]).unwrap_err();
        assert!(error.to_string().contains("not found"));

        let error =
            apply_vpn_portal_client_patches(&config, vec![add("bob", "not-an-ip")]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid VPN portal client virtual IP")
        );
    }
}
