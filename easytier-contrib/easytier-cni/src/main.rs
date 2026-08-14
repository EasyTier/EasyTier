use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{self, Read},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use easytier::{
    common::{
        config::{ConfigLoader as _, load_toml_config_from_path},
        netns::NetNSGuard,
    },
    proto::{
        api::manage::{
            CollectNetworkInfoRequest, ConfigSource, DeleteNetworkInstanceRequest,
            GetNetworkInstanceConfigRequest, ListNetworkInstanceRequest, NetworkConfig,
            NetworkingMethod, RunNetworkInstanceRequest, WebClientService,
            WebClientServiceClientFactory,
        },
        rpc::standalone::{RuntimeUnixRpcClient, runtime_unix_rpc_client},
        rpc_types::controller::BaseController,
    },
};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SUPPORTED_VERSIONS: &[&str] = &["1.0.0"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginConfig {
    cni_version: String,
    name: String,
    #[serde(default = "default_rpc_portal")]
    rpc_portal: String,
    network_name: String,
    network_secret_file: PathBuf,
    #[serde(default)]
    peers: Vec<String>,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default = "default_timeout_seconds")]
    timeout_seconds: u64,
    ipam: IpamConfig,
    #[serde(default)]
    prev_result: Option<Value>,
    #[serde(flatten)]
    _extra: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct IpamConfig {
    #[serde(rename = "type")]
    plugin_type: String,
    #[serde(flatten)]
    _extra: Map<String, Value>,
}

#[derive(Debug)]
struct CniArgs {
    command: String,
    container_id: Option<String>,
    netns: Option<String>,
    ifname: Option<String>,
    path: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CniResult {
    #[serde(rename = "cniVersion")]
    cni_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<CniInterface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ips: Vec<CniIp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    routes: Vec<CniRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CniInterface {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CniIp {
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CniRoute {
    dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gw: Option<String>,
}

fn default_rpc_portal() -> String {
    "unix:///run/easytier-cni/rpc.sock".to_string()
}

fn default_mtu() -> u16 {
    1380
}

fn default_timeout_seconds() -> u64 {
    30
}

fn config_dir() -> PathBuf {
    env::var_os("EASYTIER_CNI_TEST_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/easytier-cni/configs"))
}

fn read_stdin() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    Ok(input)
}

fn parse_args() -> CniArgs {
    CniArgs {
        command: env::var("CNI_COMMAND").unwrap_or_default(),
        container_id: env::var("CNI_CONTAINERID").ok(),
        netns: env::var("CNI_NETNS").ok().filter(|value| !value.is_empty()),
        ifname: env::var("CNI_IFNAME").ok(),
        path: env::var_os("CNI_PATH")
            .map(|value| env::split_paths(&value).collect())
            .unwrap_or_default(),
    }
}

fn validate_version(version: &str) -> Result<()> {
    ensure!(
        SUPPORTED_VERSIONS.contains(&version),
        "unsupported CNI version {version}"
    );
    Ok(())
}

fn attachment_id(network: &str, container_id: &str, ifname: &str) -> Uuid {
    let digest = Sha256::digest(format!("{network}\0{container_id}\0{ifname}"));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

struct AttachmentLock {
    _file: File,
}

impl AttachmentLock {
    fn acquire(id: Uuid) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

            let config_dir = config_dir();
            let metadata = fs::symlink_metadata(&config_dir).with_context(|| {
                format!(
                    "failed to inspect config directory {}",
                    config_dir.display()
                )
            })?;
            ensure!(metadata.is_dir(), "configDir must be a directory");
            ensure!(metadata.uid() == 0, "configDir must be owned by root");
            ensure!(
                metadata.permissions().mode() & 0o022 == 0,
                "configDir must not be writable by group or other users"
            );

            let lock_dir = config_dir.join(".locks");
            fs::create_dir_all(&lock_dir)?;
            fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700))?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(lock_dir.join(id.to_string()))?;
            file.lock()?;
            Ok(Self { _file: file })
        }
        #[cfg(not(unix))]
        bail!("EasyTier CNI is unsupported on this platform")
    }
}

fn ensure_attachment_persisted(
    id: Uuid,
    address: Ipv4Addr,
    prefix: u8,
    netns: &str,
    ifname: &str,
    config: &PluginConfig,
    secret: &str,
) -> Result<()> {
    let path = config_dir().join(format!("{id}.toml"));
    let persisted = load_toml_config_from_path(&path)
        .with_context(|| format!("persisted attachment config {} is invalid", path.display()))?;
    ensure!(persisted.get_id() == id, "persisted attachment ID differs");
    ensure!(
        persisted.get_ipv4().is_some_and(|value| {
            value.address() == address && value.network_length() == prefix
        }),
        "persisted attachment address differs"
    );
    ensure!(
        persisted.get_netns().as_deref() == Some(netns),
        "persisted attachment network namespace differs"
    );
    let identity = persisted.get_network_identity();
    ensure!(
        identity.network_name == config.network_name
            && identity.network_secret.as_deref() == Some(secret),
        "persisted attachment network identity differs"
    );
    let expected_peers = config
        .peers
        .iter()
        .map(|peer| peer.parse::<url::Url>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        persisted
            .get_peers()
            .into_iter()
            .map(|peer| peer.uri)
            .eq(expected_peers),
        "persisted attachment peers differ"
    );
    let flags = persisted.get_flags();
    ensure!(
        flags.dev_name == ifname
            && flags.mtu == u32::from(config.mtu)
            && !flags.no_tun
            && !flags.enable_ipv6
            && !flags.multi_thread,
        "persisted attachment interface settings differ"
    );
    Ok(())
}

fn take_persisted_attachment(id: Uuid) -> Result<Option<Vec<u8>>> {
    let path = config_dir().join(format!("{id}.toml"));
    if !path.exists() {
        return Ok(None);
    }
    let persisted = load_toml_config_from_path(&path)
        .with_context(|| format!("orphaned attachment config {} is invalid", path.display()))?;
    ensure!(persisted.get_id() == id, "orphaned attachment ID differs");
    let contents = fs::read(&path)?;
    fs::remove_file(&path)
        .with_context(|| format!("failed to remove attachment config {}", path.display()))?;
    Ok(Some(contents))
}

fn restore_persisted_attachment(id: Uuid, contents: Option<&[u8]>) -> Result<()> {
    let Some(contents) = contents else {
        return Ok(());
    };
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let path = config_dir().join(format!("{id}.toml"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("failed to restore attachment config {}", path.display()))?;
    io::Write::write_all(&mut file, contents)?;
    file.sync_all()?;
    Ok(())
}

fn read_network_secret(path: &Path) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let parent = path.parent().context("networkSecretFile has no parent")?;
        let parent_metadata = fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect networkSecretFile directory {}",
                parent.display()
            )
        })?;
        ensure!(
            parent_metadata.is_dir()
                && parent_metadata.uid() == 0
                && parent_metadata.permissions().mode() & 0o022 == 0,
            "networkSecretFile directory must be root-owned and not group/world-writable"
        );
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect networkSecretFile {}", path.display()))?;
        ensure!(
            metadata.is_file(),
            "networkSecretFile must be a regular file"
        );
        ensure!(
            metadata.uid() == 0,
            "networkSecretFile must be owned by root"
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "networkSecretFile must not be accessible by group or other users"
        );
        ensure!(metadata.len() <= 4096, "networkSecretFile is too large");
    }

    let secret = fs::read_to_string(path)
        .with_context(|| format!("failed to read networkSecretFile {}", path.display()))?
        .trim()
        .to_string();
    ensure!(!secret.is_empty(), "networkSecretFile is empty");
    Ok(secret)
}

fn required_attachment_args(args: &CniArgs) -> Result<(&str, &str)> {
    let container_id = args
        .container_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("CNI_CONTAINERID is required")?;
    let ifname = args
        .ifname
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("CNI_IFNAME is required")?;
    Ok((container_id, ifname))
}

fn find_plugin(name: &str, paths: &[PathBuf]) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && !name.contains('/') && !name.contains('\\'),
        "invalid IPAM plugin type {name:?}"
    );
    paths
        .iter()
        .map(|path| path.join(name))
        .find(|path| path.is_file())
        .with_context(|| format!("IPAM plugin {name:?} was not found in CNI_PATH"))
}

fn run_ipam(config: &PluginConfig, input: &[u8], args: &CniArgs, command: &str) -> Result<Vec<u8>> {
    let plugin = find_plugin(&config.ipam.plugin_type, &args.path)?;
    let mut child = Command::new(&plugin)
        .env("CNI_COMMAND", command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute IPAM plugin {}", plugin.display()))?;
    io::Write::write_all(child.stdin.as_mut().unwrap(), input)?;
    let output = child.wait_with_output()?;
    if !output.stderr.is_empty() {
        let _ = io::Write::write_all(&mut io::stderr(), &output.stderr);
    }
    ensure!(
        output.status.success(),
        "IPAM plugin {} failed with {}: {}",
        config.ipam.plugin_type,
        output.status,
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(output.stdout)
}

fn select_ipv4(result: &mut CniResult) -> Result<(Ipv4Addr, u8)> {
    ensure!(
        result.ips.len() == 1,
        "IPAM must return exactly one address"
    );
    ensure!(
        result.routes.is_empty(),
        "routes returned by IPAM are not supported"
    );
    let (address, prefix) = result.ips[0]
        .address
        .split_once('/')
        .context("IPAM address must include a prefix length")?;
    let address: Ipv4Addr = address
        .parse()
        .context("IPAM must return an IPv4 address")?;
    let prefix: u8 = prefix.parse().context("invalid IPv4 prefix length")?;
    ensure!(prefix <= 32, "invalid IPv4 prefix length {prefix}");
    result.ips[0].interface = Some(0);
    Ok((address, prefix))
}

fn netmask_prefix(netmask: Ipv4Addr) -> Result<u8> {
    let bits = u32::from(netmask);
    let prefix = bits.leading_ones() as u8;
    ensure!(
        bits == u32::MAX.checked_shl((32 - prefix).into()).unwrap_or(0),
        "non-contiguous IPv4 netmask"
    );
    Ok(prefix)
}

fn check_interface(netns: &str, ifname: &str, address: Ipv4Addr, prefix: u8) -> Result<()> {
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
    ensure!(
        url.scheme() == "unix",
        "CNI RPC portal must use a Unix socket"
    );
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

async fn instance_config(portal: &str, id: Uuid) -> Result<Option<NetworkConfig>> {
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

fn ensure_same_attachment(actual: &NetworkConfig, expected: &NetworkConfig) -> Result<()> {
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

async fn delete_instance(portal: &str, id: Uuid) -> Result<()> {
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

async fn wait_ready(
    portal: &str,
    id: Uuid,
    ifname: &str,
    address: Ipv4Addr,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
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
            Instant::now() < deadline,
            "timed out waiting for EasyTier TUN"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn add(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<CniResult> {
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
        let start_result = rpc_client(&config.rpc_portal)
            .await?
            .client
            .run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: Some(id.into()),
                    config: Some(network_config.clone()),
                    overwrite: false,
                    source: ConfigSource::User.into(),
                },
            )
            .await;
        match start_result {
            Ok(_) => true,
            Err(error) => match instance_config(&config.rpc_portal, id).await {
                Ok(Some(actual)) => {
                    ensure_same_attachment(&actual, &network_config)?;
                    false
                }
                Ok(None) => {
                    return match run_ipam(config, input, args, "DEL") {
                        Ok(_) => Err(error.into()),
                        Err(rollback) => Err(anyhow::Error::from(error)
                            .context(format!("IPAM rollback also failed: {rollback:#}"))),
                    };
                }
                Err(state_error) => {
                    return Err(anyhow::Error::from(error).context(format!(
                        "attachment state is unknown; IPAM allocation was retained: {state_error:#}"
                    )));
                }
            },
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

async fn delete(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<()> {
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

async fn check(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<()> {
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

fn print_json(value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(io::stdout(), value)?;
    println!();
    Ok(())
}

fn print_error(version: &str, error: &anyhow::Error) {
    let _ = print_json(&json!({
        "cniVersion": version,
        "code": 100,
        "msg": "EasyTier CNI operation failed",
        "details": format!("{error:#}"),
    }));
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = parse_args();
    if args.command == "VERSION" {
        let input = read_stdin().unwrap_or_default();
        let requested = serde_json::from_slice::<Value>(&input)
            .ok()
            .and_then(|value| value.get("cniVersion")?.as_str().map(str::to_string))
            .unwrap_or_else(|| "1.0.0".to_string());
        if let Err(error) = print_json(&json!({
            "cniVersion": requested,
            "supportedVersions": SUPPORTED_VERSIONS,
        })) {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
        return;
    }

    let input = match read_stdin() {
        Ok(input) => input,
        Err(error) => {
            print_error("1.0.0", &error);
            std::process::exit(1);
        }
    };
    let config: PluginConfig = match serde_json::from_slice(&input) {
        Ok(config) => config,
        Err(error) => {
            print_error("1.0.0", &error.into());
            std::process::exit(1);
        }
    };
    let result = match args.command.as_str() {
        "ADD" => add(&config, &input, &args).await.and_then(|result| {
            print_json(&result)?;
            Ok(())
        }),
        "DEL" => delete(&config, &input, &args).await,
        "CHECK" => check(&config, &input, &args).await,
        command => Err(anyhow::anyhow!("unsupported CNI_COMMAND {command:?}")),
    };
    if let Err(error) = result {
        print_error(&config.cni_version, &error);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_ids_are_stable_and_distinct() {
        let first = attachment_id("overlay", "container-a", "net1");
        assert_eq!(first, attachment_id("overlay", "container-a", "net1"));
        assert_ne!(first, attachment_id("overlay", "container-b", "net1"));
        assert_ne!(first, attachment_id("overlay", "container-a", "net2"));
    }

    #[test]
    fn parses_minimal_config() {
        let config: PluginConfig = serde_json::from_value(json!({
            "cniVersion": "1.0.0",
            "name": "overlay",
            "type": "easytier-cni",
            "networkName": "cluster",
            "networkSecretFile": "/etc/easytier/secret",
            "peers": ["tcp://192.0.2.1:11010"],
            "ipam": {"type": "whereabouts", "range": "10.200.0.0/24"}
        }))
        .unwrap();
        assert_eq!(config.rpc_portal, default_rpc_portal());
        assert_eq!(config.mtu, 1380);
        assert_eq!(config.ipam.plugin_type, "whereabouts");
    }

    #[test]
    fn selects_one_ipv4_address() {
        let mut result: CniResult = serde_json::from_value(json!({
            "cniVersion": "1.0.0",
            "ips": [{"address": "10.200.0.8/24"}]
        }))
        .unwrap();
        assert_eq!(
            select_ipv4(&mut result).unwrap(),
            (Ipv4Addr::new(10, 200, 0, 8), 24)
        );
        assert_eq!(result.ips[0].interface, Some(0));
    }

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
