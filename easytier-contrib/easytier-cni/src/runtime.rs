use std::{fs, net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use easytier::{
    common::netns::NetNSGuard,
    proto::{
        api::manage::{
            CollectNetworkInfoRequest, ConfigSource, DeleteNetworkInstanceRequest,
            GetNetworkInstanceConfigRequest, ListNetworkInstanceRequest, NetworkConfig,
            RunNetworkInstanceRequest, WebClientService, WebClientServiceClientFactory,
        },
        rpc::standalone::{RuntimeUnixRpcClient, runtime_unix_rpc_client, validate_unix_rpc_url},
        rpc_types::controller::BaseController,
    },
};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use uuid::Uuid;

fn netmask_prefix(netmask: Ipv4Addr) -> Result<u8> {
    let bits = u32::from(netmask);
    let prefix = bits.leading_ones() as u8;
    ensure!(
        bits == u32::MAX.checked_shl((32 - prefix).into()).unwrap_or(0),
        "non-contiguous IPv4 netmask"
    );
    Ok(prefix)
}

pub(crate) fn check_interface(
    netns: &str,
    ifname: &str,
    address: Ipv4Addr,
    prefix: u8,
) -> Result<()> {
    let _guard = NetNSGuard::try_new(Some(netns.to_string()))?;
    let interface = NetworkInterface::show()?
        .into_iter()
        .find(|interface| interface.name == ifname)
        .with_context(|| format!("interface {ifname} does not exist"))?;
    let has_address = interface.addr.into_iter().any(|entry| match entry {
        Addr::V4(entry) if entry.ip == address => entry
            .netmask
            .is_some_and(|netmask| netmask_prefix(netmask).is_ok_and(|value| value == prefix)),
        _ => false,
    });
    ensure!(
        has_address,
        "interface {ifname} does not have {address}/{prefix}"
    );
    let is_up = pnet::datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == ifname)
        .is_some_and(|interface| interface.is_up());
    ensure!(is_up, "interface {ifname} is not up");
    Ok(())
}

struct ManageClient {
    client: Box<dyn WebClientService<Controller = BaseController>>,
    _connection: RuntimeUnixRpcClient,
}

async fn rpc_client(portal: &str) -> Result<ManageClient> {
    let url: url::Url = if portal.contains("://") {
        portal.parse()?
    } else {
        format!("tcp://{portal}").parse()?
    };
    validate_unix_rpc_url(&url)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

        let metadata = fs::symlink_metadata(url.path())
            .with_context(|| format!("failed to inspect RPC socket {}", url.path()))?;
        ensure!(
            metadata.file_type().is_socket(),
            "RPC portal is not a socket"
        );
        ensure!(metadata.uid() == 0, "RPC socket must be owned by root");
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "RPC socket must not be accessible by group or other users"
        );
    }

    let mut connection = runtime_unix_rpc_client(url);
    let client = connection
        .scoped_client::<WebClientServiceClientFactory<BaseController>>(String::new())
        .await?;
    Ok(ManageClient {
        client: Box::new(client),
        _connection: connection,
    })
}

pub(crate) async fn instance_config(portal: &str, id: Uuid) -> Result<Option<NetworkConfig>> {
    let client = rpc_client(portal).await?;
    let instances = client
        .client
        .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
        .await?;
    if !instances.inst_ids.contains(&id.into()) {
        return Ok(None);
    }
    let response = client
        .client
        .get_network_instance_config(
            BaseController::default(),
            GetNetworkInstanceConfigRequest {
                inst_id: Some(id.into()),
            },
        )
        .await?;
    Ok(Some(
        response.config.context("instance has no configuration")?,
    ))
}

pub(crate) fn ensure_same_attachment(
    actual: &NetworkConfig,
    expected: &NetworkConfig,
) -> Result<()> {
    ensure!(
        actual.instance_id == expected.instance_id
            && actual.virtual_ipv4 == expected.virtual_ipv4
            && actual.network_length == expected.network_length
            && actual.network_name == expected.network_name
            && actual.network_secret == expected.network_secret
            && actual.dev_name == expected.dev_name
            && actual.mtu == expected.mtu
            && actual.netns == expected.netns,
        "existing attachment configuration differs from the requested configuration"
    );
    Ok(())
}

pub(crate) enum StartInstanceResult {
    Started,
    Rejected(anyhow::Error),
}

pub(crate) async fn start_instance(
    portal: &str,
    id: Uuid,
    config: NetworkConfig,
) -> Result<StartInstanceResult> {
    let client = rpc_client(portal).await?;
    match client
        .client
        .run_network_instance(
            BaseController::default(),
            RunNetworkInstanceRequest {
                inst_id: Some(id.into()),
                config: Some(config),
                overwrite: false,
                source: ConfigSource::User.into(),
            },
        )
        .await
    {
        Ok(_) => Ok(StartInstanceResult::Started),
        Err(error) => Ok(StartInstanceResult::Rejected(error.into())),
    }
}

pub(crate) async fn delete_instance(portal: &str, id: Uuid) -> Result<()> {
    let client = rpc_client(portal).await?;
    let response = client
        .client
        .delete_network_instance(
            BaseController::default(),
            DeleteNetworkInstanceRequest {
                inst_ids: vec![id.into()],
            },
        )
        .await?;
    ensure!(
        !response.remain_inst_ids.contains(&id.into()),
        "EasyTier instance {id} could not be deleted"
    );
    Ok(())
}

pub(crate) async fn wait_ready(
    portal: &str,
    id: Uuid,
    ifname: &str,
    address: Ipv4Addr,
    timeout: Duration,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let client = rpc_client(portal).await?;
        let response = client
            .client
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest {
                    inst_ids: vec![id.into()],
                },
            )
            .await?;
        if let Some(info) = response
            .info
            .and_then(|map| map.map.get(&id.to_string()).cloned())
        {
            if let Some(error) = info.error_msg.filter(|value| !value.is_empty()) {
                bail!("EasyTier instance failed: {error}");
            }
            let actual_address = info
                .my_node_info
                .and_then(|node| node.virtual_ipv4)
                .and_then(|inet| inet.address)
                .map(Ipv4Addr::from);
            if info.running && info.dev_name == ifname && actual_address == Some(address) {
                return Ok(());
            }
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "timed out waiting for EasyTier TUN"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use easytier::proto::api::manage::NetworkConfig;

    use super::*;

    #[test]
    fn validates_existing_attachment_identity() {
        let expected = NetworkConfig {
            instance_id: Some(Uuid::nil().to_string()),
            virtual_ipv4: Some("10.200.0.8".to_string()),
            network_length: Some(24),
            network_name: Some("overlay".to_string()),
            network_secret: Some("secret".to_string()),
            dev_name: Some("net1".to_string()),
            mtu: Some(1380),
            netns: Some("/proc/123/ns/net".to_string()),
            ..Default::default()
        };
        assert!(ensure_same_attachment(&expected, &expected).is_ok());

        let mut changed = expected.clone();
        changed.netns = Some("/proc/456/ns/net".to_string());
        assert!(ensure_same_attachment(&changed, &expected).is_err());
    }
}
