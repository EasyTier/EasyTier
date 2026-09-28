use std::{fmt::Debug, sync::Arc};

use anyhow::Context as _;
use easytier_proto::api::config::{
    self, AclPatch, ConfigPatchAction, ExitNodePatch, InstanceConfigPatch, Patchable,
    PortForwardPatch, ProxyNetworkPatch, RoutePatch, UrlPatch, VpnPortalClientPatch,
};
use easytier_proto::common::FlagsPatch;
use optionize::Optionized as _;

use crate::{
    config::{
        InstanceConfig, InstanceConfigRaw,
        peers::{AclRuleConfig, PublicIpv6ProviderConfig},
        serialize_raw_to_toml,
    },
    instance::{CoreInstance, CoreInstanceHost, CoreInstanceState, prepare_instance_config},
    peers::credential_manager::CredentialManager,
};

#[async_trait::async_trait]
pub trait ConfigPatchPersistence: Send + Sync {
    async fn persist(&self, instance_id: uuid::Uuid, config: &InstanceConfig)
    -> anyhow::Result<()>;
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

    let initial_snapshot = instance.config_store().snapshot();
    let mut last_accepted: Arc<InstanceConfig> = initial_snapshot;
    let mut candidate = last_accepted.raw().clone();
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
        if !patch.port_forwards.is_empty() {
            let result = patch_port_forwards(&mut candidate, patch.port_forwards);
            validate_persist_and_commit_candidate(
                instance,
                &mut last_accepted,
                &candidate,
                persistence,
            )
            .await?;
            result?;
        }

        if patch.acl.is_some() {
            let result = patch_acl(&mut candidate, patch.acl);
            validate_persist_and_commit_candidate(
                instance,
                &mut last_accepted,
                &candidate,
                persistence,
            )
            .await?;
            result?;
        }

        if !patch.proxy_networks.is_empty() {
            let result = patch_proxy_networks(&mut candidate, patch.proxy_networks);
            validate_persist_and_commit_candidate(
                instance,
                &mut last_accepted,
                &candidate,
                persistence,
            )
            .await?;
            result?;
        }

        if !patch.routes.is_empty() {
            let result = patch_routes(&mut candidate, patch.routes);
            validate_persist_and_commit_candidate(
                instance,
                &mut last_accepted,
                &candidate,
                persistence,
            )
            .await?;
            result?;
        }

        if !patch.exit_nodes.is_empty() {
            let result = patch_exit_nodes_config(&mut candidate, patch.exit_nodes);
            validate_persist_and_commit_candidate(
                instance,
                &mut last_accepted,
                &candidate,
                persistence,
            )
            .await?;
            result?;
            instance
                .update_exit_nodes(last_accepted.parsed().exit_nodes.clone())
                .await;
        }

        if !patch.mapped_listeners.is_empty() {
            let result = patch_mapped_listeners(&mut candidate, patch.mapped_listeners);
            validate_persist_and_commit_candidate(
                instance,
                &mut last_accepted,
                &candidate,
                persistence,
            )
            .await?;
            result?;
        }

        if !patch.connectors.is_empty() {
            patch_connectors(instance, patch.connectors)?;
        }

        let mut provider_config_changed = false;
        if let Some(hostname) = patch.hostname {
            candidate.hostname = Some(hostname);
        }
        if let Some(ipv4) = patch.ipv4
            && !candidate.dhcp.unwrap_or_default()
        {
            candidate.ipv4 = Some(ipv4.into());
        }
        if let Some(ipv6) = patch.ipv6 {
            candidate.ipv6 = Some(ipv6.into());
        }
        candidate.patch_flags(FlagsPatch {
            disable_relay_data: patch.disable_relay_data,
            prefer_peer_relay: patch.prefer_peer_relay,
            ..Default::default()
        });
        if let Some(enabled) = patch.ipv6_public_addr_provider {
            candidate.ipv6_public_addr_provider = Some(enabled);
            provider_config_changed = true;
        }
        if let Some(enabled) = patch.ipv6_public_addr_auto {
            candidate.ipv6_public_addr_auto = Some(enabled);
        }
        if let Some(prefix) = parsed_prefix {
            candidate.ipv6_public_addr_prefix = prefix;
            provider_config_changed = true;
        }
        let mut managed_credentials_changed = false;

        // Runs last so client validation sees the fully patched candidate,
        // including routes and the node IPv4 set earlier in this request.
        if !patch.vpn_portal_clients.is_empty() {
            let previous = last_accepted.clone();
            apply_vpn_portal_client_patches(&mut candidate, patch.vpn_portal_clients)?;
            // Deep-validate and durably persist before hot-applying. A failed
            // write leaves the live Portal untouched. If the host rejects the
            // hot update, restore the previous durable snapshot before
            // returning so a later patch cannot overwrite from stale shared
            // state and a restart cannot apply a rejected client set.
            let prepared = validate_candidate(instance, &candidate)?;
            let changed = persist_candidate_if_changed(
                instance,
                last_accepted.as_ref(),
                &prepared,
                persistence,
            )
            .await?;
            #[cfg(feature = "vpn-portal")]
            {
                let portal = prepared
                    .parsed()
                    .vpn_portal_config
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("VPN portal is not configured"))?;
                let clients: Vec<crate::gateway::vpn_portal::PortalClientConfig> =
                    portal.clients.into_iter().map(Into::into).collect();
                if let Err(error) = instance
                    .update_vpn_portal_clients(clients, prepared.parsed())
                    .await
                {
                    if let Some(persistence) = persistence
                        && changed
                        && let Err(rollback_error) =
                            persistence.persist(instance.instance_id(), &previous).await
                    {
                        return Err(error.context(format!(
                            "failed to restore durable configuration after VPN portal update: \
                             {rollback_error:#}"
                        )));
                    }
                    return Err(error);
                }
            }
            #[cfg(not(feature = "vpn-portal"))]
            {
                let _ = prepared;
            }
            if changed {
                last_accepted = Arc::new(prepared);
            }
        }

        if let Some(managed) = &managed_credentials {
            // Managed credential patch transaction: validate and reserve →
            // persist → install. The reservation prevents base or ephemeral
            // credential mutations from invalidating the replacement while
            // the durable write is in flight, without holding a synchronous
            // lock across the await. Dropping the replacement before install
            // releases the reservation.
            //
            // Accepted consistency limits:
            //
            // 1. A persistence implementation may finish its write after this
            //    RPC future is cancelled. The reservation is then released and
            //    the running instance keeps its previous credentials even if
            //    the durable file contains the replacement. A retry, controller
            //    reconcile, or restart is required to converge; until then a
            //    removed credential may remain trusted by the running instance.
            //
            // 2. This instance operation is not serialized with a process-level
            //    instance overwrite. The built-in web reconciler serializes its
            //    own actions, but independently concurrent admin RPCs are
            //    last-writer-wins and may leave the running instance and durable
            //    file on different config generations. A restart aligns runtime
            //    with the file; controller reconcile is required to restore its
            //    desired generation.
            let credential_manager = instance.credential_manager();
            let entries = managed
                .entries
                .iter()
                .map(|credential| credential.clone().upgrade())
                .collect::<Result<Vec<_>, _>>()?;
            let replacement = credential_manager
                .validate_managed_credentials(&entries)
                .map_err(anyhow::Error::msg)?;
            candidate.managed_credentials = Some(entries);
            let prepared = validate_candidate(instance, &candidate)?;
            // When durable storage is configured, persist before installing
            // secret authority so a successful replacement survives restart.
            if let Some(persistence) = persistence {
                persistence
                    .persist(instance.instance_id(), &prepared)
                    .await?;
            }
            last_accepted = Arc::new(prepared);
            managed_credentials_changed =
                CredentialManager::install_managed_credentials(replacement);
        } else {
            validate_persist_and_commit_candidate(
                instance,
                &mut last_accepted,
                &candidate,
                persistence,
            )
            .await?;
        }
        Ok((provider_config_changed, managed_credentials_changed))
    }
    .await;

    instance
        .update_runtime_config_under_operation((*last_accepted).clone())
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
    candidate: &InstanceConfigRaw,
) -> anyhow::Result<InstanceConfig>
where
    H: CoreInstanceHost,
{
    let config = InstanceConfig::try_from(candidate.clone())?;
    let prepared = prepare_instance_config(config, instance.host_config())?;
    let provider_config = PublicIpv6ProviderConfig {
        provider_enabled: prepared.parsed().ipv6_public_addr_provider,
        configured_prefix: prepared.parsed().ipv6_public_addr_prefix,
        provider_supported: instance.host_config().public_ipv6_provider_supported,
    };
    provider_config.validate()?;
    instance.validate_runtime_config_capabilities(prepared.parsed())?;
    Ok(prepared)
}

async fn validate_persist_and_commit_candidate<H>(
    instance: &CoreInstance<H>,
    last_accepted: &mut Arc<InstanceConfig>,
    candidate: &InstanceConfigRaw,
    persistence: Option<&dyn ConfigPatchPersistence>,
) -> anyhow::Result<()>
where
    H: CoreInstanceHost,
{
    let prepared = validate_candidate(instance, candidate)?;
    if persist_candidate_if_changed(instance, last_accepted.as_ref(), &prepared, persistence)
        .await?
    {
        *last_accepted = Arc::new(prepared);
    }
    Ok(())
}

async fn persist_candidate_if_changed<H>(
    instance: &CoreInstance<H>,
    last_accepted: &InstanceConfig,
    prepared: &InstanceConfig,
    persistence: Option<&dyn ConfigPatchPersistence>,
) -> anyhow::Result<bool>
where
    H: CoreInstanceHost,
{
    let last_toml = serialize_raw_to_toml(last_accepted.raw())
        .map_err(|e| anyhow::anyhow!("failed to serialize config: {e}"))?;
    let candidate_toml = serialize_raw_to_toml(prepared.raw())
        .map_err(|e| anyhow::anyhow!("failed to serialize config: {e}"))?;
    if last_toml == candidate_toml {
        return Ok(false);
    }
    if let Some(persistence) = persistence {
        persistence
            .persist(instance.instance_id(), prepared)
            .await?;
    }
    Ok(true)
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

fn patch_port_forwards(
    raw: &mut InstanceConfigRaw,
    patches: Vec<PortForwardPatch>,
) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut current = raw.port_forward.clone().unwrap_or_default();
    let patches = patches
        .into_iter()
        .map(|patch| Patchable {
            action: ConfigPatchAction::try_from(patch.action).ok(),
            value: patch.cfg.map(Into::into),
        })
        .collect::<Vec<_>>();
    trace_patchables(&patches);
    config::patch_vec(&mut current, patches);
    raw.port_forward = Some(current);
    Ok(())
}

fn patch_acl(raw: &mut InstanceConfigRaw, patch: Option<AclPatch>) -> anyhow::Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };
    let mut acl = AclRuleConfig {
        acl: raw.acl.clone(),
        tcp_whitelist: raw.tcp_whitelist.clone().unwrap_or_default(),
        udp_whitelist: raw.udp_whitelist.clone().unwrap_or_default(),
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
    raw.acl = acl.acl;
    raw.tcp_whitelist = Some(acl.tcp_whitelist);
    raw.udp_whitelist = Some(acl.udp_whitelist);
    Ok(())
}

fn patch_proxy_networks(
    raw: &mut InstanceConfigRaw,
    patches: Vec<ProxyNetworkPatch>,
) -> anyhow::Result<()> {
    for patch in patches {
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => {
                let Some(cidr) = patch.cidr.map(Into::into) else {
                    tracing::warn!("ignored proxy-network add without CIDR");
                    continue;
                };
                raw.add_proxy_cidr(cidr, patch.mapped_cidr.map(Into::into))?;
            }
            Ok(ConfigPatchAction::Remove) => {
                let Some(cidr) = patch.cidr.map(Into::into) else {
                    tracing::warn!("ignored proxy-network remove without CIDR");
                    continue;
                };
                raw.remove_proxy_cidr(cidr);
            }
            Ok(ConfigPatchAction::Clear) => raw.clear_proxy_cidrs(),
            Err(_) => tracing::warn!(
                action = patch.action,
                "ignored invalid proxy-network action"
            ),
        }
    }
    Ok(())
}

fn patch_routes(raw: &mut InstanceConfigRaw, patches: Vec<RoutePatch>) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut current = raw.routes.clone().unwrap_or_default();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    config::patch_vec(&mut current, patches);
    raw.routes = (!current.is_empty()).then_some(current);
    Ok(())
}

fn patch_exit_nodes_config(
    raw: &mut InstanceConfigRaw,
    patches: Vec<ExitNodePatch>,
) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut current = raw.exit_nodes.clone().unwrap_or_default();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    config::patch_vec(&mut current, patches);
    raw.exit_nodes = Some(current);
    Ok(())
}

fn patch_mapped_listeners(
    raw: &mut InstanceConfigRaw,
    patches: Vec<UrlPatch>,
) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut current = raw.mapped_listeners.clone().unwrap_or_default();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    config::patch_vec(&mut current, patches);
    raw.mapped_listeners = (!current.is_empty()).then_some(current);
    Ok(())
}

/// Applies VPN portal client patches to the candidate model. The live
/// portal is updated by the caller after the candidate commits, so deep
/// validation runs against the final configuration state.
fn apply_vpn_portal_client_patches(
    raw: &mut InstanceConfigRaw,
    patches: Vec<VpnPortalClientPatch>,
) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let portal = raw
        .vpn_portal_config
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("VPN portal is not configured; cannot patch its clients"))?;
    let mut clients = portal.clients.clone();
    for patch in patches {
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => {
                let Some(client) = patch.client else {
                    tracing::warn!("ignored VPN portal client add without client");
                    continue;
                };
                let virtual_ip =
                    client
                        .virtual_ip
                        .parse::<cidr::Ipv4Inet>()
                        .with_context(|| {
                            format!(
                                "invalid VPN portal client virtual CIDR: {}",
                                client.virtual_ip
                            )
                        })?;
                clients.push(crate::config::toml::VpnPortalClientConfig {
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
                let before = clients.len();
                clients.retain(|existing| existing.name != client.name);
                if clients.len() == before {
                    anyhow::bail!("VPN portal client not found: {}", client.name);
                }
            }
            Ok(ConfigPatchAction::Clear) => clients.clear(),
            Err(_) => tracing::warn!(
                action = patch.action,
                "ignored invalid VPN portal client action"
            ),
        }
    }
    portal.clients = clients;
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

    fn portal_config() -> InstanceConfigRaw {
        let mut raw = InstanceConfigRaw::default();
        raw.vpn_portal_config = Some(VpnPortalConfig {
            wireguard_listen: "0.0.0.0:51820".parse().unwrap(),
            wireguard_private_key: None,
            clients: vec![VpnPortalClientConfig {
                name: "alice".to_owned(),
                virtual_ip: "10.0.0.2/24".parse().unwrap(),
                groups: Vec::new(),
            }],
        });
        raw
    }

    fn configured_names(raw: &InstanceConfigRaw) -> Vec<String> {
        raw.vpn_portal_config
            .as_ref()
            .unwrap()
            .clients
            .iter()
            .map(|client| client.name.clone())
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
        let mut raw = portal_config();

        apply_vpn_portal_client_patches(&mut raw, vec![add("bob", "10.0.0.3/24")]).unwrap();
        assert_eq!(configured_names(&raw), ["alice", "bob"]);

        apply_vpn_portal_client_patches(&mut raw, vec![remove("alice")]).unwrap();
        assert_eq!(configured_names(&raw), ["bob"]);

        apply_vpn_portal_client_patches(
            &mut raw,
            vec![VpnPortalClientPatch {
                action: ConfigPatchAction::Clear as i32,
                client: None,
            }],
        )
        .unwrap();
        assert!(configured_names(&raw).is_empty());
    }

    #[test]
    fn vpn_portal_client_patches_reject_missing_prerequisites() {
        let mut bare = InstanceConfigRaw::default();
        let error =
            apply_vpn_portal_client_patches(&mut bare, vec![add("alice", "10.0.0.2")]).unwrap_err();
        assert!(error.to_string().contains("not configured"));

        let mut raw = portal_config();
        let error = apply_vpn_portal_client_patches(&mut raw, vec![remove("ghost")]).unwrap_err();
        assert!(error.to_string().contains("not found"));

        let error =
            apply_vpn_portal_client_patches(&mut raw, vec![add("bob", "not-an-ip")]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid VPN portal client virtual CIDR")
        );
    }
}
