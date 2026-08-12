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
    if instance.state() != CoreInstanceState::Running {
        anyhow::bail!("instance is not ready; config patch rejected");
    }

    let config = instance
        .toml_config()
        .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))?;
    let candidate = config.detached_snapshot();
    let parsed_prefix =
        parse_ipv6_public_addr_prefix_patch(patch.ipv6_public_addr_prefix.as_deref())?;
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
        let normalized = validate_and_commit_candidate(instance, &config, &candidate)?;
        let runtime = runtime_config_from_normalized(&normalized);
        instance
            .instance_runtime
            .synchronize_config(&patch_for_host, &runtime);
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
    #[cfg(feature = "public-ipv6-provider")]
    if provider_config_changed && instance.state() == CoreInstanceState::Running {
        instance.reconcile_public_ipv6_provider().await;
    }
    #[cfg(not(feature = "public-ipv6-provider"))]
    let _ = provider_config_changed;
    Ok(())
}

fn validate_and_commit_candidate<H>(
    instance: &CoreInstance<H>,
    shared: &TomlConfig,
    candidate: &TomlConfig,
) -> anyhow::Result<CoreInstanceConfig>
where
    H: CoreInstanceHost,
{
    let normalized = CoreInstanceConfig::from_toml_with_host(candidate, instance.host_config())?;
    let runtime = runtime_config_from_normalized(&normalized);
    runtime.services.public_ipv6_provider.validate()?;
    instance.validate_runtime_config_capabilities(&runtime)?;
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
