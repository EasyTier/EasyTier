use std::{fmt::Debug, sync::Arc};

use anyhow::Context as _;
use easytier_proto::api::config::{
    self, AclPatch, ConfigPatchAction, ExitNodePatch, InstanceConfigPatch, Patchable,
    PortForwardPatch, ProxyNetworkPatch, RoutePatch, UrlPatch,
};

use crate::{
    config::{
        peers::AclRuleConfig,
        runtime::CoreInstanceRuntimeConfig,
        toml::{ConfigLoader as _, TomlConfig},
    },
    instance::{CoreInstance, CoreInstanceConfig, CoreInstanceHost, CoreInstanceState},
};

pub async fn apply_config_patch<H>(
    instance: &Arc<CoreInstance<H>>,
    patch: InstanceConfigPatch,
) -> anyhow::Result<()>
where
    H: CoreInstanceHost,
{
    let _operation = instance.operation.lock().await;
    if instance.state() != CoreInstanceState::Running || !instance.is_ready() {
        anyhow::bail!("instance is not ready; config patch rejected");
    }

    let config = instance
        .toml_config()
        .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))?;
    let candidate = config.detached_snapshot();
    let parsed_prefix = validate_public_ipv6_patch(instance, &config, &patch)?;
    let patch_for_host = patch.clone();

    // Preserve the existing ordered partial-commit contract: earlier valid
    // sub-patches remain applied if a later sub-patch fails.
    let patch_result: anyhow::Result<bool> = async {
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
        validate_and_commit_candidate(instance, &config, &candidate)?;
        instance.update_exit_nodes(result?).await;

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
        validate_and_commit_candidate(instance, &config, &candidate)?;
        instance
            .instance_runtime
            .synchronize_config(&patch_for_host);
        Ok(provider_config_changed)
    }
    .await;

    instance
        .update_runtime_config_under_operation(runtime_config_from_toml(instance, &config)?)
        .await?;
    let provider_config_changed = patch_result?;
    instance
        .instance_runtime
        .publish_config_patch(patch_for_host);
    if provider_config_changed && instance.state() == CoreInstanceState::Running {
        instance.reconcile_public_ipv6_provider().await;
    }
    Ok(())
}

fn validate_and_commit_candidate<H>(
    instance: &CoreInstance<H>,
    shared: &TomlConfig,
    candidate: &TomlConfig,
) -> anyhow::Result<()>
where
    H: CoreInstanceHost,
{
    let runtime = runtime_config_from_toml(instance, candidate)?;
    instance.validate_runtime_config_capabilities(&runtime)?;
    shared.replace_from_snapshot(candidate);
    Ok(())
}

fn runtime_config_from_toml<H>(
    instance: &CoreInstance<H>,
    config: &TomlConfig,
) -> anyhow::Result<CoreInstanceRuntimeConfig>
where
    H: CoreInstanceHost,
{
    let normalized = CoreInstanceConfig::from_toml_with_host(config, instance.host_config())?;
    let current = instance.runtime_config_snapshot();
    let services = normalized.connectivity.runtime;
    let mut peer = normalized.peer.snapshot;
    peer.runtime.stun_info = current.peer.runtime.stun_info.clone();

    Ok(CoreInstanceRuntimeConfig {
        services,
        peer: Arc::new(peer),
    })
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

fn validate_public_ipv6_patch<H>(
    instance: &CoreInstance<H>,
    config: &TomlConfig,
    patch: &InstanceConfigPatch,
) -> anyhow::Result<Option<Option<cidr::Ipv6Cidr>>>
where
    H: CoreInstanceHost,
{
    let parsed_prefix =
        parse_ipv6_public_addr_prefix_patch(patch.ipv6_public_addr_prefix.as_deref())?;
    let provider_enabled = patch
        .ipv6_public_addr_provider
        .unwrap_or(config.get_ipv6_public_addr_provider());
    let configured_prefix = parsed_prefix.unwrap_or_else(|| config.get_ipv6_public_addr_prefix());
    let provider_supported = instance
        .runtime_config_snapshot()
        .services
        .public_ipv6_provider
        .provider_supported;
    crate::config::peers::PublicIpv6ProviderConfig {
        provider_enabled,
        configured_prefix,
        provider_supported,
    }
    .validate()?;
    Ok(parsed_prefix)
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

fn patch_connectors<H>(instance: &CoreInstance<H>, patches: Vec<UrlPatch>) -> anyhow::Result<()>
where
    H: CoreInstanceHost,
{
    for patch in patches {
        let Some(url) = patch.url.map(Into::<url::Url>::into) else {
            tracing::warn!("ignored connector patch without URL");
            return Ok(());
        };
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => instance.add_connector(url)?,
            Ok(ConfigPatchAction::Remove) => {
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
