use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use easytier::proto::api::manage::{NetworkConfig, NetworkingMethod};

use crate::{
    attachment::{
        AttachmentLock, attachment_id, ensure_attachment_persisted, read_network_secret,
        restore_persisted_attachment, take_persisted_attachment,
    },
    cni::{
        CniArgs, CniInterface, CniResult, PluginConfig, required_attachment_args, validate_version,
    },
    ipam::{run_ipam, select_ipv4},
    runtime::{
        StartInstanceResult, check_interface, delete_instance, ensure_same_attachment,
        instance_config, start_instance, wait_ready,
    },
};

pub(crate) async fn add(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<CniResult> {
    validate_version(&config.cni_version)?;
    ensure!(
        config.prev_result.is_none(),
        "prevResult is not supported; use EasyTier as a standalone Multus delegate"
    );
    let (container_id, ifname) = required_attachment_args(args)?;
    let netns = args.netns.as_deref().context("CNI_NETNS is required")?;
    ensure!(Path::new(netns).is_absolute(), "CNI_NETNS must be absolute");
    ensure!(config.mtu >= 576, "mtu must be at least 576");
    ensure!(
        config.timeout_seconds > 0,
        "timeoutSeconds must be positive"
    );
    ensure!(!config.network_name.is_empty(), "networkName is required");
    ensure!(!config.peers.is_empty(), "at least one peer is required");

    let id = attachment_id(&config.name, container_id, ifname);
    let _lock = AttachmentLock::acquire(id)?;
    let existing = instance_config(&config.rpc_portal, id).await?;

    let secret = read_network_secret(&config.network_secret_file)?;

    let ipam_output = run_ipam(config, input, args, "ADD")?;
    let mut ipam_result: CniResult = match serde_json::from_slice(&ipam_output)
        .context("failed to decode the delegated IPAM result")
    {
        Ok(result) => result,
        Err(error) => {
            return match run_ipam(config, input, args, "DEL") {
                Ok(_) => Err(error),
                Err(rollback) => {
                    Err(error.context(format!("IPAM rollback also failed: {rollback:#}")))
                }
            };
        }
    };
    let (address, prefix) = match select_ipv4(&mut ipam_result) {
        Ok(value) => value,
        Err(error) => {
            return match run_ipam(config, input, args, "DEL") {
                Ok(_) => Err(error),
                Err(rollback) => {
                    Err(error.context(format!("IPAM rollback also failed: {rollback:#}")))
                }
            };
        }
    };
    let network_config = NetworkConfig {
        instance_id: Some(id.to_string()),
        dhcp: Some(false),
        virtual_ipv4: Some(address.to_string()),
        network_length: Some(prefix.into()),
        hostname: Some(format!("cni-{}", &id.simple().to_string()[..12])),
        network_name: Some(config.network_name.clone()),
        network_secret: Some(secret.clone()),
        networking_method: Some(NetworkingMethod::Manual.into()),
        peer_urls: config.peers.clone(),
        dev_name: Some(ifname.to_string()),
        disable_ipv6: Some(true),
        no_tun: Some(false),
        multi_thread: Some(false),
        enable_magic_dns: Some(false),
        mtu: Some(config.mtu.into()),
        netns: Some(netns.to_string()),
        ..Default::default()
    };

    let created = if let Some(actual) = existing {
        ensure_same_attachment(&actual, &network_config)?;
        false
    } else {
        match start_instance(&config.rpc_portal, id, network_config.clone()).await? {
            StartInstanceResult::Started => true,
            StartInstanceResult::Rejected(error) => {
                match instance_config(&config.rpc_portal, id).await {
                    Ok(Some(actual)) => {
                        ensure_same_attachment(&actual, &network_config)?;
                        false
                    }
                    Ok(None) => {
                        return match run_ipam(config, input, args, "DEL") {
                            Ok(_) => Err(error),
                            Err(rollback) => {
                                Err(error
                                    .context(format!("IPAM rollback also failed: {rollback:#}")))
                            }
                        };
                    }
                    Err(state_error) => {
                        return Err(error.context(format!(
                            "attachment state is unknown; IPAM allocation was retained: {state_error:#}"
                        )));
                    }
                }
            }
        }
    };

    let start_result = async {
        wait_ready(
            &config.rpc_portal,
            id,
            ifname,
            address,
            Duration::from_secs(config.timeout_seconds),
        )
        .await?;
        check_interface(netns, ifname, address, prefix)?;
        ensure_attachment_persisted(id, address, prefix, netns, ifname, config, &secret)
    }
    .await;

    if let Err(error) = start_result {
        if !created {
            return Err(error.context("existing attachment and IPAM allocation were retained"));
        }
        let persisted = match take_persisted_attachment(id) {
            Ok(persisted) => persisted,
            Err(rollback) => {
                return Err(error.context(format!(
                    "attachment config rollback also failed; instance and IPAM allocation were retained: {rollback:#}"
                )));
            }
        };
        if let Err(rollback) = delete_instance(&config.rpc_portal, id).await {
            let restore = restore_persisted_attachment(id, persisted.as_deref());
            return Err(error.context(format!(
                "EasyTier rollback also failed; IPAM allocation was retained: {rollback:#}; config restore: {restore:?}"
            )));
        }
        return match run_ipam(config, input, args, "DEL") {
            Ok(_) => Err(error),
            Err(rollback) => Err(error.context(format!("IPAM rollback also failed: {rollback:#}"))),
        };
    }

    ipam_result.cni_version = config.cni_version.clone();
    ipam_result.interfaces = vec![CniInterface {
        name: ifname.to_string(),
        sandbox: Some(netns.to_string()),
    }];
    Ok(ipam_result)
}

pub(crate) async fn delete(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<()> {
    validate_version(&config.cni_version)?;
    let (container_id, ifname) = required_attachment_args(args)?;
    let id = attachment_id(&config.name, container_id, ifname);
    let _lock = AttachmentLock::acquire(id)?;
    let persisted = take_persisted_attachment(id).context(
        "IPAM allocation was retained because the attachment config could not be removed",
    )?;
    if let Err(error) = delete_instance(&config.rpc_portal, id).await {
        let restore = restore_persisted_attachment(id, persisted.as_deref());
        return Err(error.context(format!(
            "IPAM allocation was retained; attachment config restore: {restore:?}"
        )));
    }
    run_ipam(config, input, args, "DEL").map(|_| ())
}

pub(crate) async fn check(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<()> {
    validate_version(&config.cni_version)?;
    let (container_id, ifname) = required_attachment_args(args)?;
    let netns = args.netns.as_deref().context("CNI_NETNS is required")?;
    let id = attachment_id(&config.name, container_id, ifname);
    let _lock = AttachmentLock::acquire(id)?;
    let previous = config
        .prev_result
        .clone()
        .context("prevResult is required for CHECK")?;
    let mut result: CniResult = serde_json::from_value(previous)?;
    let (address, prefix) = select_ipv4(&mut result)?;
    run_ipam(config, input, args, "CHECK")?;
    let secret = read_network_secret(&config.network_secret_file)?;

    wait_ready(
        &config.rpc_portal,
        id,
        ifname,
        address,
        Duration::from_secs(config.timeout_seconds),
    )
    .await?;
    check_interface(netns, ifname, address, prefix)?;
    ensure_attachment_persisted(id, address, prefix, netns, ifname, config, &secret)?;
    Ok(())
}
