use std::{
    env, fs,
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use easytier::{
    proto::{
        api::manage::{
            CollectNetworkInfoRequest, ConfigSource, DeleteNetworkInstanceRequest,
            GetNetworkInstanceConfigRequest, NetworkConfig, NetworkingMethod,
            RunNetworkInstanceRequest, WebClientService, WebClientServiceClientFactory,
        },
        rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    tunnel::tcp::TcpTunnelConnector,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SUPPORTED_VERSIONS: &[&str] = &["0.4.0", "1.0.0", "1.1.0"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginConfig {
    cni_version: String,
    name: String,
    #[serde(default = "default_rpc_portal")]
    rpc_portal: SocketAddr,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u16>,
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

fn default_rpc_portal() -> SocketAddr {
    "127.0.0.1:15888".parse().unwrap()
}

fn default_mtu() -> u16 {
    1380
}

fn default_timeout_seconds() -> u64 {
    30
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
        io::Write::write_all(&mut io::stderr(), &output.stderr)?;
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

type RpcClient = StandAloneClient<TcpTunnelConnector>;

struct ManageClient {
    client: Box<dyn WebClientService<Controller = BaseController>>,
    _connection: RpcClient,
}

async fn rpc_client(portal: SocketAddr) -> Result<ManageClient> {
    let mut connection =
        RpcClient::new(TcpTunnelConnector::new(format!("tcp://{portal}").parse()?));
    let client = connection
        .scoped_client::<WebClientServiceClientFactory<BaseController>>(String::new())
        .await?;
    Ok(ManageClient {
        client: Box::new(client),
        _connection: connection,
    })
}

async fn delete_instance(portal: SocketAddr, id: Uuid) -> Result<()> {
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
    portal: SocketAddr,
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
    let existing_client = rpc_client(config.rpc_portal).await?;
    let existing = existing_client
        .client
        .get_network_instance_config(
            BaseController::default(),
            GetNetworkInstanceConfigRequest {
                inst_id: Some(id.into()),
            },
        )
        .await;
    ensure!(existing.is_err(), "attachment already exists");

    let secret = fs::read_to_string(&config.network_secret_file)
        .with_context(|| {
            format!(
                "failed to read networkSecretFile {}",
                config.network_secret_file.display()
            )
        })?
        .trim()
        .to_string();
    ensure!(!secret.is_empty(), "networkSecretFile is empty");

    let ipam_output = run_ipam(config, input, args, "ADD")?;
    let mut ipam_result: CniResult = serde_json::from_slice(&ipam_output)
        .context("failed to decode the delegated IPAM result")?;
    let (address, prefix) = match select_ipv4(&mut ipam_result) {
        Ok(value) => value,
        Err(error) => {
            let _ = run_ipam(config, input, args, "DEL");
            return Err(error);
        }
    };
    let network_config = NetworkConfig {
        instance_id: Some(id.to_string()),
        dhcp: Some(false),
        virtual_ipv4: Some(address.to_string()),
        network_length: Some(prefix.into()),
        hostname: Some(format!("cni-{}", &id.simple().to_string()[..12])),
        network_name: Some(config.network_name.clone()),
        network_secret: Some(secret),
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

    let start_result = async {
        rpc_client(config.rpc_portal)
            .await?
            .client
            .run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: Some(id.into()),
                    config: Some(network_config),
                    overwrite: false,
                    source: ConfigSource::User.into(),
                },
            )
            .await?;
        wait_ready(
            config.rpc_portal,
            id,
            ifname,
            address,
            Duration::from_secs(config.timeout_seconds),
        )
        .await
    }
    .await;

    if let Err(error) = start_result {
        let _ = delete_instance(config.rpc_portal, id).await;
        let _ = run_ipam(config, input, args, "DEL");
        return Err(error);
    }

    ipam_result.cni_version = config.cni_version.clone();
    ipam_result.interfaces = vec![CniInterface {
        name: ifname.to_string(),
        sandbox: Some(netns.to_string()),
        mtu: Some(config.mtu),
    }];
    Ok(ipam_result)
}

async fn delete(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<()> {
    validate_version(&config.cni_version)?;
    let (container_id, ifname) = required_attachment_args(args)?;
    let id = attachment_id(&config.name, container_id, ifname);
    let instance_result = delete_instance(config.rpc_portal, id).await;
    let ipam_result = run_ipam(config, input, args, "DEL").map(|_| ());
    match (instance_result, ipam_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(instance), Ok(())) => Err(instance),
        (Ok(()), Err(ipam)) => Err(ipam),
        (Err(instance), Err(ipam)) => {
            bail!("failed to delete EasyTier instance: {instance}; failed to release IPAM: {ipam}")
        }
    }
}

async fn check(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<()> {
    validate_version(&config.cni_version)?;
    let (container_id, ifname) = required_attachment_args(args)?;
    let netns = args.netns.as_deref().context("CNI_NETNS is required")?;
    let previous = config
        .prev_result
        .clone()
        .context("prevResult is required for CHECK")?;
    let mut result: CniResult = serde_json::from_value(previous)?;
    let (address, _) = select_ipv4(&mut result)?;
    run_ipam(config, input, args, "CHECK")?;

    let id = attachment_id(&config.name, container_id, ifname);
    wait_ready(
        config.rpc_portal,
        id,
        ifname,
        address,
        Duration::from_secs(config.timeout_seconds),
    )
    .await?;
    ensure!(
        Path::new(netns).exists(),
        "network namespace no longer exists"
    );
    Ok(())
}

async fn status(config: &PluginConfig, input: &[u8], args: &CniArgs) -> Result<()> {
    validate_version(&config.cni_version)?;
    let _client = rpc_client(config.rpc_portal).await?;
    run_ipam(config, input, args, "STATUS")?;
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
            .unwrap_or_else(|| "1.1.0".to_string());
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
            print_error("1.1.0", &error);
            std::process::exit(1);
        }
    };
    let config: PluginConfig = match serde_json::from_slice(&input) {
        Ok(config) => config,
        Err(error) => {
            print_error("1.1.0", &error.into());
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
        "STATUS" => status(&config, &input, &args).await,
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
            "cniVersion": "1.1.0",
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
            "cniVersion": "1.1.0",
            "ips": [{"address": "10.200.0.8/24"}]
        }))
        .unwrap();
        assert_eq!(
            select_ipv4(&mut result).unwrap(),
            (Ipv4Addr::new(10, 200, 0, 8), 24)
        );
        assert_eq!(result.ips[0].interface, Some(0));
    }
}
