use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time::Duration,
    vec,
};

use anyhow::Context;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use cidr::Ipv4Inet;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, builder::BoolishValueParser};
use dashmap::DashMap;
use easytier::ShellType;
use humansize::format_size;
use rust_i18n::t;
use service_manager::*;
use tabled::settings::{Disable, Modify, Style, Width, location::ByColumnName, object::Columns};
use terminal_size::{Width as TerminalWidth, terminal_size};
use unicode_width::UnicodeWidthStr;

use easytier::service_manager::{Service, ServiceInstallOptions};
use tokio::time::timeout;

use easytier::{
    common::{
        constants::EASYTIER_VERSION,
        stun::{StunInfoCollector, StunInfoCollectorTrait},
    },
    peers,
    proto::{
        acl::AclStats,
        api::{
            config::{
                AclPatch, ConfigPatchAction, ConfigRpc, ConfigRpcClientFactory,
                InstanceConfigPatch, PatchConfigRequest, PortForwardPatch, StringPatch, UrlPatch,
            },
            instance::{
                AclManageRpc, AclManageRpcClientFactory, Connector, ConnectorManageRpc,
                ConnectorManageRpcClientFactory, CredentialManageRpc,
                CredentialManageRpcClientFactory, DumpRouteRequest, ForeignNetworkEntryPb,
                GenerateCredentialRequest, GetAclStatsRequest, GetPrometheusStatsRequest,
                GetStatsRequest, GetVpnPortalInfoRequest, GetWhitelistRequest,
                GetWhitelistResponse, InstanceIdentifier, ListConnectorRequest,
                ListCredentialsRequest, ListCredentialsResponse, ListForeignNetworkRequest,
                ListGlobalForeignNetworkRequest, ListMappedListenerRequest, ListPeerRequest,
                ListPeerResponse, ListPortForwardRequest, ListPortForwardResponse,
                ListPublicIpv6InfoRequest, ListPublicIpv6InfoResponse, ListRouteRequest,
                ListRouteResponse, MappedListener, MappedListenerManageRpc,
                MappedListenerManageRpcClientFactory, MetricSnapshot, NodeInfo, PeerManageRpc,
                PeerManageRpcClientFactory, PortForwardManageRpc,
                PortForwardManageRpcClientFactory, RevokeCredentialRequest, Route as ApiRoute,
                ShowNodeInfoRequest, StatsRpc, StatsRpcClientFactory, TcpProxyEntryState,
                TcpProxyEntryTransportType, TcpProxyRpc, TcpProxyRpcClientFactory,
                TrustedKeySourcePb, VpnPortalInfo, VpnPortalRpc, VpnPortalRpcClientFactory,
                instance_identifier::{InstanceSelector, Selector},
                list_global_foreign_network_response, list_peer_route_pair,
            },
            logger::{
                GetLoggerConfigRequest, LogLevel, LoggerRpc, LoggerRpcClientFactory,
                SetLoggerConfigRequest,
            },
            manage::{
                ListNetworkInstanceMetaRequest, ListNetworkInstanceRequest, WebClientService,
                WebClientServiceClientFactory,
            },
        },
        common::{NatType, PortForwardConfigPb, SocketType},
        peer_rpc::{GetGlobalPeerMapRequest, PeerCenterRpc, PeerCenterRpcClientFactory},
        rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    tunnel::{scheme::TunnelScheme, tcp::TcpTunnelConnector},
    utils::{PeerRoutePair, string::cost_to_str},
};

rust_i18n::i18n!("locales", fallback = "en");

#[derive(Parser, Debug)]
#[command(name = "easytier-cli", author, version = EASYTIER_VERSION, about, long_about = None)]
struct Cli {
    #[arg(
        short = 'p',
        long,
        default_value = "127.0.0.1:15888",
        help = "easytier-core rpc portal address"
    )]
    rpc_portal: SocketAddr,

    #[arg(short, long, default_value = "false", help = "verbose output")]
    verbose: bool,

    #[arg(
        short = 'o',
        long = "output",
        value_enum,
        default_value = "table",
        help = "output format"
    )]
    output_format: OutputFormat,

    #[arg(
        long = "no-trunc",
        default_value = "false",
        help = "disable column truncation"
    )]
    no_trunc: bool,

    #[command(flatten)]
    instance_select: InstanceSelectArgs,

    #[command(subcommand)]
    sub_command: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    #[command(about = "show peers info")]
    Peer(PeerArgs),
    #[command(about = "manage connectors")]
    Connector(ConnectorArgs),
    #[command(about = "manage mapped listeners")]
    MappedListener(MappedListenerArgs),
    #[command(about = "do stun test")]
    Stun,
    #[command(about = "show route info")]
    Route(RouteArgs),
    #[command(about = "show global peers info")]
    PeerCenter,
    #[command(about = "show vpn portal (wireguard) info")]
    VpnPortal,
    #[command(about = "inspect self easytier-core status")]
    Node(NodeArgs),
    #[command(about = "manage easytier-core as a system service")]
    Service(ServiceArgs),
    #[command(about = "show tcp/kcp proxy status")]
    Proxy,
    #[command(about = "show ACL rules statistics")]
    Acl(AclArgs),
    #[command(about = "manage port forwarding")]
    PortForward(PortForwardArgs),
    #[command(about = "manage TCP/UDP whitelist")]
    Whitelist(WhitelistArgs),
    #[command(about = "show statistics information")]
    Stats(StatsArgs),
    #[command(about = "manage logger configuration")]
    Logger(LoggerArgs),
    #[command(about = "manage temporary credentials")]
    Credential(CredentialArgs),
    #[command(about = t!("core_clap.generate_completions").to_string())]
    GenAutocomplete { shell: ShellType },
}

#[derive(clap::ValueEnum, Debug, Clone, PartialEq)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Parser, Debug)]
struct InstanceSelectArgs {
    #[arg(short = 'i', long = "instance-id", help = "the instance id")]
    id: Option<uuid::Uuid>,

    #[arg(short = 'n', long = "instance-name", help = "the instance name")]
    name: Option<String>,
}

impl From<&InstanceSelectArgs> for InstanceIdentifier {
    fn from(args: &InstanceSelectArgs) -> Self {
        InstanceIdentifier {
            selector: match args.id {
                Some(id) => Some(Selector::Id(id.into())),
                None => Some(Selector::InstanceSelector(InstanceSelector {
                    name: args.name.clone(),
                })),
            },
        }
    }
}

#[derive(Args, Debug)]
struct PeerArgs {
    #[command(subcommand)]
    sub_command: Option<PeerSubCommand>,
}

#[derive(Subcommand, Debug)]
enum PeerSubCommand {
    List,
    Ipv6,
    ListForeign {
        #[arg(
            long,
            default_value = "false",
            help = "include trusted keys for each foreign network"
        )]
        trusted_keys: bool,
    },
    ListGlobalForeign,
}

#[derive(Args, Debug)]
struct RouteArgs {
    #[command(subcommand)]
    sub_command: Option<RouteSubCommand>,
}

#[derive(Subcommand, Debug)]
enum RouteSubCommand {
    List,
    Dump,
}

#[derive(Args, Debug)]
struct ConnectorArgs {
    #[arg(short, long)]
    ipv4: Option<String>,

    #[arg(short, long)]
    peers: Vec<String>,

    #[command(subcommand)]
    sub_command: Option<ConnectorSubCommand>,
}

#[derive(Subcommand, Debug)]
enum ConnectorSubCommand {
    /// Add a connector
    Add {
        #[arg(help = "connector url, e.g., tcp://1.2.3.4:11010")]
        url: String,
    },
    /// Remove a connector
    Remove {
        #[arg(help = "connector url, e.g., tcp://1.2.3.4:11010")]
        url: String,
    },
    List,
}

#[derive(Args, Debug)]
struct MappedListenerArgs {
    #[command(subcommand)]
    sub_command: Option<MappedListenerSubCommand>,
}

#[derive(Subcommand, Debug)]
enum MappedListenerSubCommand {
    /// Add Mapped Listerner
    Add { url: String },
    /// Remove Mapped Listener
    Remove { url: String },
    /// List Existing Mapped Listener
    List,
}

#[derive(Subcommand, Debug)]
enum NodeSubCommand {
    #[command(about = "show node info")]
    Info,
    #[command(about = "show node config")]
    Config,
}

#[derive(Args, Debug)]
struct NodeArgs {
    #[command(subcommand)]
    sub_command: Option<NodeSubCommand>,
}

#[derive(Args, Debug)]
struct AclArgs {
    #[command(subcommand)]
    sub_command: Option<AclSubCommand>,
}

#[derive(Subcommand, Debug)]
enum AclSubCommand {
    Stats,
}

#[derive(Args, Debug)]
struct PortForwardArgs {
    #[command(subcommand)]
    sub_command: Option<PortForwardSubCommand>,
}

#[derive(Subcommand, Debug)]
enum PortForwardSubCommand {
    /// Add port forward rule
    Add {
        #[arg(help = "Protocol (tcp/udp)")]
        protocol: String,
        #[arg(help = "Local bind address (e.g., 0.0.0.0:8080)")]
        bind_addr: String,
        #[arg(help = "Destination address (e.g., 10.1.1.1:80)")]
        dst_addr: String,
    },
    /// Remove port forward rule
    Remove {
        #[arg(help = "Protocol (tcp/udp)")]
        protocol: String,
        #[arg(help = "Local bind address (e.g., 0.0.0.0:8080)")]
        bind_addr: String,
        #[arg(help = "Optional Destination address (e.g., 10.1.1.1:80)")]
        dst_addr: Option<String>,
    },
    /// List port forward rules
    List,
}

#[derive(Args, Debug)]
struct WhitelistArgs {
    #[command(subcommand)]
    sub_command: Option<WhitelistSubCommand>,
}

#[derive(Subcommand, Debug)]
enum WhitelistSubCommand {
    /// Set TCP port whitelist
    SetTcp {
        #[arg(help = "TCP ports (e.g., 80,443,8000-9000)")]
        ports: String,
    },
    /// Set UDP port whitelist
    SetUdp {
        #[arg(help = "UDP ports (e.g., 53,5000-6000)")]
        ports: String,
    },
    /// Clear TCP whitelist
    ClearTcp,
    /// Clear UDP whitelist
    ClearUdp,
    /// Show current whitelist configuration
    Show,
}

#[derive(Args, Debug)]
struct StatsArgs {
    #[command(subcommand)]
    sub_command: Option<StatsSubCommand>,
}

#[derive(Subcommand, Debug)]
enum StatsSubCommand {
    /// Show general statistics
    Show,
    /// Show statistics in Prometheus format
    Prometheus,
}

#[derive(Args, Debug)]
struct LoggerArgs {
    #[command(subcommand)]
    sub_command: Option<LoggerSubCommand>,
}

#[derive(Subcommand, Debug)]
enum LoggerSubCommand {
    /// Get current logger configuration
    Get,
    /// Set logger level
    Set {
        #[arg(help = "Log level (disabled, error, warning, info, debug, trace)")]
        level: String,
    },
}

#[derive(Args, Debug)]
struct CredentialArgs {
    #[command(subcommand)]
    sub_command: CredentialSubCommand,
}

#[derive(Subcommand, Debug)]
enum CredentialSubCommand {
    /// Generate a new temporary credential
    Generate {
        #[arg(long, help = "TTL in seconds (required)")]
        ttl: i64,
        #[arg(
            long,
            help = "custom credential ID, return existing credential if already generated"
        )]
        credential_id: Option<String>,
        #[arg(long, value_delimiter = ',', help = "ACL groups (comma-separated)")]
        groups: Option<Vec<String>>,
        #[arg(
            long,
            default_value = "false",
            help = "allow relay through this credential node"
        )]
        allow_relay: bool,
        #[arg(
            long,
            value_delimiter = ',',
            help = "allowed proxy CIDRs (comma-separated)"
        )]
        allowed_proxy_cidrs: Option<Vec<String>>,
        #[arg(
            long,
            action = ArgAction::Set,
            default_value = "true",
            value_parser = BoolishValueParser::new(),
            help = "whether this credential may be reused by multiple peers concurrently"
        )]
        reusable: bool,
    },
    /// Revoke a credential by its ID
    Revoke {
        #[arg(help = "credential ID (UUID)")]
        credential_id: String,
    },
    /// List all active credentials
    List,
}

#[derive(Args, Debug)]
struct ServiceArgs {
    #[arg(short, long, default_value = env!("CARGO_PKG_NAME"), help = "service name")]
    name: String,

    #[command(subcommand)]
    sub_command: ServiceSubCommand,
}

#[derive(Subcommand, Debug)]
enum ServiceSubCommand {
    #[command(about = "register easytier-core as a system service")]
    Install(InstallArgs),
    #[command(about = "unregister easytier-core system service")]
    Uninstall,
    #[command(about = "check easytier-core system service status")]
    Status,
    #[command(about = "start easytier-core system service")]
    Start,
    #[command(about = "stop easytier-core system service")]
    Stop,
}

#[derive(Args, Debug)]
struct InstallArgs {
    #[arg(long, default_value = env!("CARGO_PKG_DESCRIPTION"), help = "service description")]
    description: String,

    #[arg(long)]
    display_name: Option<String>,

    #[arg(long)]
    disable_autostart: Option<bool>,

    #[arg(long)]
    disable_restart_on_failure: Option<bool>,

    #[arg(long, help = "path to easytier-core binary")]
    core_path: Option<PathBuf>,

    #[arg(long)]
    service_work_dir: Option<PathBuf>,

    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "args to pass to easytier-core"
    )]
    core_args: Option<Vec<OsString>>,
}

type Error = anyhow::Error;

#[derive(Clone, Debug)]
struct InstanceTarget {
    identifier: InstanceIdentifier,
    instance_id: String,
    instance_name: String,
}

struct InstanceResult<T> {
    target: Option<InstanceTarget>,
    value: T,
}

impl InstanceTarget {
    fn label(&self) -> String {
        match (self.instance_name.is_empty(), self.instance_id.is_empty()) {
            (false, false) => format!("{} ({})", self.instance_name, self.instance_id),
            (false, true) => self.instance_name.clone(),
            (true, false) => self.instance_id.clone(),
            (true, true) => "selected instance".to_string(),
        }
    }
}

impl<T> InstanceResult<T> {
    fn new(target: Option<InstanceTarget>, value: T) -> Self {
        Self { target, value }
    }

    fn map<U>(self, f: impl FnOnce(T) -> U) -> InstanceResult<U> {
        InstanceResult {
            target: self.target,
            value: f(self.value),
        }
    }
}

struct CommandHandler<'a> {
    client: Arc<tokio::sync::Mutex<RpcClient>>,
    verbose: bool,
    output_format: &'a OutputFormat,
    no_trunc: bool,
    instance_select: &'a InstanceSelectArgs,
    instance_selector: InstanceIdentifier,
    resolved_target: Option<InstanceTarget>,
}

type RpcClient = StandAloneClient<TcpTunnelConnector>;
type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Error>> + 'a>>;
type ForeignNetworkMap = BTreeMap<String, ForeignNetworkEntryPb>;
type GlobalForeignNetworkMap = BTreeMap<u32, list_global_foreign_network_response::ForeignNetworks>;

#[derive(serde::Serialize)]
struct PeerListData {
    node_info: NodeInfo,
    peer_routes: Vec<PeerRoutePair>,
}

#[derive(serde::Serialize)]
struct RouteListData {
    node_info: NodeInfo,
    peer_routes: Vec<PeerRoutePair>,
}

struct PeerIpv6DataRaw {
    node_info: NodeInfo,
    routes: Vec<ApiRoute>,
    provider_info: ListPublicIpv6InfoResponse,
}

#[derive(serde::Serialize)]
struct PeerCenterRowData {
    node_id: String,
    hostname: String,
    ipv4: String,
    direct_peers: Vec<PeerCenterDirectPeerData>,
}

#[derive(serde::Serialize)]
struct PeerCenterDirectPeerData {
    node_id: String,
    hostname: String,
    ipv4: String,
    latency_ms: i32,
}

impl<'a> CommandHandler<'a> {
    fn has_explicit_instance_selector(&self) -> bool {
        self.instance_select.id.is_some() || self.instance_select.name.is_some()
    }

    fn scoped_to_instance(&self, target: &InstanceTarget) -> Self {
        Self {
            client: self.client.clone(),
            verbose: self.verbose,
            output_format: self.output_format,
            no_trunc: self.no_trunc,
            instance_select: self.instance_select,
            instance_selector: target.identifier.clone(),
            resolved_target: Some(target.clone()),
        }
    }

    fn print_target_header(&self, target: &InstanceTarget) {
        println!("== {} ==", target.label());
    }

    async fn get_manage_client(
        &self,
    ) -> Result<Box<dyn WebClientService<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<WebClientServiceClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get manage client")?)
    }

    async fn fanout_targets(&self) -> Result<Option<Vec<InstanceTarget>>, Error> {
        if self.resolved_target.is_some() || self.has_explicit_instance_selector() {
            return Ok(None);
        }

        let client = self.get_manage_client().await?;
        let inst_ids = client
            .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
            .await?
            .inst_ids
            .into_iter()
            .map(uuid::Uuid::from)
            .collect::<Vec<_>>();

        if inst_ids.is_empty() {
            return Err(anyhow::anyhow!("no running instances found"));
        }

        let metas = client
            .list_network_instance_meta(
                BaseController::default(),
                ListNetworkInstanceMetaRequest {
                    inst_ids: inst_ids.iter().cloned().map(Into::into).collect(),
                },
            )
            .await?
            .metas;

        let mut name_map = HashMap::new();
        for meta in metas {
            if let Some(inst_id) = meta.inst_id {
                name_map.insert(
                    uuid::Uuid::from(inst_id),
                    if meta.instance_name.is_empty() {
                        meta.network_name
                    } else {
                        meta.instance_name
                    },
                );
            }
        }

        let mut targets = inst_ids
            .into_iter()
            .map(|inst_id| InstanceTarget {
                identifier: InstanceIdentifier {
                    selector: Some(Selector::Id(inst_id.into())),
                },
                instance_id: inst_id.to_string(),
                instance_name: name_map.remove(&inst_id).unwrap_or_default(),
            })
            .collect::<Vec<_>>();

        targets.sort_by_key(|a| a.label());
        Ok(Some(targets))
    }

    async fn collect_instance_results<T, F>(
        &self,
        fetch: F,
    ) -> Result<Vec<InstanceResult<T>>, Error>
    where
        F: for<'b> Fn(&'b CommandHandler<'a>) -> LocalBoxFuture<'b, T>,
    {
        if let Some(targets) = self.fanout_targets().await? {
            let mut results = Vec::with_capacity(targets.len());
            for target in targets {
                let scoped = self.scoped_to_instance(&target);
                let value = fetch(&scoped)
                    .await
                    .with_context(|| format!("instance {}", target.label()))?;
                results.push(InstanceResult::new(Some(target), value));
            }
            Ok(results)
        } else {
            Ok(vec![InstanceResult::new(None, fetch(self).await?)])
        }
    }

    async fn apply_to_instances<F>(&self, apply: F) -> Result<(), Error>
    where
        F: for<'b> Fn(&'b CommandHandler<'a>) -> LocalBoxFuture<'b, ()>,
    {
        self.collect_instance_results(apply).await?;
        Ok(())
    }

    fn print_results<T>(
        &self,
        results: &[InstanceResult<T>],
        mut render: impl FnMut(&T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let multi = results.len() > 1;
        for (idx, result) in results.iter().enumerate() {
            if multi {
                if idx > 0 {
                    println!();
                }
                if let Some(target) = result.target.as_ref() {
                    self.print_target_header(target);
                }
            }
            render(&result.value)?;
        }
        Ok(())
    }

    fn print_json_results<T: serde::Serialize>(
        &self,
        results: Vec<InstanceResult<T>>,
    ) -> Result<(), Error> {
        if results.len() == 1 {
            println!("{}", serde_json::to_string_pretty(&results[0].value)?);
            return Ok(());
        }

        let wrapped = results
            .into_iter()
            .map(|result| {
                let target = result
                    .target
                    .ok_or_else(|| anyhow::anyhow!("missing instance target for multi-result"))?;
                Ok(serde_json::json!({
                    "instance_id": target.instance_id,
                    "instance_name": target.instance_name,
                    "result": result.value,
                }))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        println!("{}", serde_json::to_string_pretty(&wrapped)?);
        Ok(())
    }

    async fn get_peer_manager_client(
        &self,
    ) -> Result<Box<dyn PeerManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<PeerManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get peer manager client")?)
    }

    async fn get_connector_manager_client(
        &self,
    ) -> Result<Box<dyn ConnectorManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<ConnectorManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get connector manager client")?)
    }

    async fn get_mapped_listener_manager_client(
        &self,
    ) -> Result<Box<dyn MappedListenerManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<MappedListenerManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get mapped listener manager client")?)
    }

    async fn get_peer_center_client(
        &self,
    ) -> Result<Box<dyn PeerCenterRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<PeerCenterRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get peer center client")?)
    }

    async fn get_vpn_portal_client(
        &self,
    ) -> Result<Box<dyn VpnPortalRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<VpnPortalRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get vpn portal client")?)
    }

    async fn get_acl_manager_client(
        &self,
    ) -> Result<Box<dyn AclManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<AclManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get acl manager client")?)
    }

    async fn get_tcp_proxy_client(
        &self,
        transport_type: &str,
    ) -> Result<Box<dyn TcpProxyRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<TcpProxyRpcClientFactory<BaseController>>(transport_type.to_string())
            .await
            .with_context(|| "failed to get vpn portal client")?)
    }

    async fn get_port_forward_manager_client(
        &self,
    ) -> Result<Box<dyn PortForwardManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<PortForwardManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get port forward manager client")?)
    }

    async fn get_stats_client(
        &self,
    ) -> Result<Box<dyn StatsRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<StatsRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get stats client")?)
    }

    async fn get_logger_client(
        &self,
    ) -> Result<Box<dyn LoggerRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<LoggerRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get logger client")?)
    }

    async fn get_config_client(
        &self,
    ) -> Result<Box<dyn ConfigRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<ConfigRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get config client")?)
    }

    async fn get_credential_client(
        &self,
    ) -> Result<Box<dyn CredentialManageRpc<Controller = BaseController>>, Error> {
        Ok(self
            .client
            .lock()
            .await
            .scoped_client::<CredentialManageRpcClientFactory<BaseController>>("".to_string())
            .await
            .with_context(|| "failed to get credential client")?)
    }

    async fn list_peers(&self) -> Result<ListPeerResponse, Error> {
        let client = self.get_peer_manager_client().await?;
        let request = ListPeerRequest {
            instance: Some(self.instance_selector.clone()),
        };
        let response = client.list_peer(BaseController::default(), request).await?;
        Ok(response)
    }

    async fn list_routes(&self) -> Result<ListRouteResponse, Error> {
        let client = self.get_peer_manager_client().await?;
        let request = ListRouteRequest {
            instance: Some(self.instance_selector.clone()),
        };
        let response = client
            .list_route(BaseController::default(), request)
            .await?;
        Ok(response)
    }

    async fn list_peer_route_pair(&self) -> Result<Vec<PeerRoutePair>, Error> {
        let peers = self.list_peers().await?.peer_infos;
        let routes = self.list_routes().await?.routes;
        Ok(list_peer_route_pair(peers, routes))
    }

    async fn fetch_node_info(&self) -> Result<NodeInfo, Error> {
        self.get_peer_manager_client()
            .await?
            .show_node_info(
                BaseController::default(),
                ShowNodeInfoRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .node_info
            .ok_or(anyhow::anyhow!("node info not found"))
    }

    async fn fetch_peer_list_data(&self) -> Result<PeerListData, Error> {
        Ok(PeerListData {
            node_info: self.fetch_node_info().await?,
            peer_routes: self.list_peer_route_pair().await?,
        })
    }

    async fn fetch_route_dump(&self) -> Result<String, Error> {
        Ok(self
            .get_peer_manager_client()
            .await?
            .dump_route(
                BaseController::default(),
                DumpRouteRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .result)
    }

    async fn fetch_foreign_networks(
        &self,
        include_trusted_keys: bool,
    ) -> Result<ForeignNetworkMap, Error> {
        Ok(self
            .get_peer_manager_client()
            .await?
            .list_foreign_network(
                BaseController::default(),
                ListForeignNetworkRequest {
                    instance: Some(self.instance_selector.clone()),
                    include_trusted_keys,
                },
            )
            .await?
            .foreign_networks)
    }

    async fn fetch_global_foreign_networks(&self) -> Result<GlobalForeignNetworkMap, Error> {
        Ok(self
            .get_peer_manager_client()
            .await?
            .list_global_foreign_network(
                BaseController::default(),
                ListGlobalForeignNetworkRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .foreign_networks)
    }

    async fn fetch_route_list_data(&self) -> Result<RouteListData, Error> {
        Ok(RouteListData {
            node_info: self.fetch_node_info().await?,
            peer_routes: self.list_peer_route_pair().await?,
        })
    }

    async fn fetch_local_public_ipv6_info(&self) -> Result<ListPublicIpv6InfoResponse, Error> {
        Ok(self
            .get_peer_manager_client()
            .await?
            .list_public_ipv6_info(
                BaseController::default(),
                ListPublicIpv6InfoRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?)
    }

    async fn fetch_peer_ipv6_data(&self) -> Result<PeerIpv6DataRaw, Error> {
        Ok(PeerIpv6DataRaw {
            node_info: self.fetch_node_info().await?,
            routes: self.list_routes().await?.routes,
            provider_info: self.fetch_local_public_ipv6_info().await?,
        })
    }

    async fn fetch_connector_list(&self) -> Result<Vec<Connector>, Error> {
        Ok(self
            .get_connector_manager_client()
            .await?
            .list_connector(
                BaseController::default(),
                ListConnectorRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .connectors)
    }

    async fn fetch_acl_stats(&self) -> Result<Option<AclStats>, Error> {
        Ok(self
            .get_acl_manager_client()
            .await?
            .get_acl_stats(
                BaseController::default(),
                GetAclStatsRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .acl_stats)
    }

    async fn fetch_mapped_listener_list(&self) -> Result<Vec<MappedListener>, Error> {
        Ok(self
            .get_mapped_listener_manager_client()
            .await?
            .list_mapped_listener(
                BaseController::default(),
                ListMappedListenerRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .mappedlisteners)
    }

    async fn fetch_port_forward_list(&self) -> Result<ListPortForwardResponse, Error> {
        Ok(self
            .get_port_forward_manager_client()
            .await?
            .list_port_forward(
                BaseController::default(),
                ListPortForwardRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?)
    }

    async fn fetch_whitelist(&self) -> Result<GetWhitelistResponse, Error> {
        Ok(self
            .get_acl_manager_client()
            .await?
            .get_whitelist(
                BaseController::default(),
                GetWhitelistRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?)
    }

    async fn fetch_credential_list(&self) -> Result<ListCredentialsResponse, Error> {
        Ok(self
            .get_credential_client()
            .await?
            .list_credentials(
                BaseController::default(),
                ListCredentialsRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?)
    }

    async fn fetch_peer_center_rows(&self) -> Result<Vec<PeerCenterRowData>, Error> {
        struct PeerCenterNodeInfo {
            hostname: String,
            ipv4: String,
        }

        let resp = self
            .get_peer_center_client()
            .await?
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest::default(),
            )
            .await?;
        let route_infos = self.list_peer_route_pair().await?;
        let node_id_to_node_info = DashMap::new();
        let node_info = self.fetch_node_info().await?;
        node_id_to_node_info.insert(
            node_info.peer_id,
            PeerCenterNodeInfo {
                hostname: node_info.hostname.clone(),
                ipv4: node_info.ipv4_addr,
            },
        );
        for route_info in route_infos {
            let Some(peer_id) = route_info.route.as_ref().map(|x| x.peer_id) else {
                continue;
            };
            node_id_to_node_info.insert(
                peer_id,
                PeerCenterNodeInfo {
                    hostname: route_info
                        .route
                        .as_ref()
                        .map(|x| x.hostname.clone())
                        .unwrap_or_default(),
                    ipv4: route_info
                        .route
                        .as_ref()
                        .and_then(|x| x.ipv4_addr)
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
                },
            );
        }

        Ok(resp
            .global_peer_map
            .iter()
            .map(|(node_id, directs)| PeerCenterRowData {
                node_id: node_id.to_string(),
                hostname: node_id_to_node_info
                    .get(node_id)
                    .map(|x| x.hostname.clone())
                    .unwrap_or_default(),
                ipv4: node_id_to_node_info
                    .get(node_id)
                    .map(|x| x.ipv4.clone())
                    .unwrap_or_default(),
                direct_peers: directs
                    .direct_peers
                    .iter()
                    .map(|(k, v)| PeerCenterDirectPeerData {
                        node_id: k.to_string(),
                        hostname: node_id_to_node_info
                            .get(k)
                            .map(|x| x.hostname.clone())
                            .unwrap_or_default(),
                        ipv4: node_id_to_node_info
                            .get(k)
                            .map(|x| x.ipv4.clone())
                            .unwrap_or_default(),
                        latency_ms: v.latency_ms,
                    })
                    .collect(),
            })
            .collect())
    }

    async fn fetch_vpn_portal_info(&self) -> Result<VpnPortalInfo, Error> {
        Ok(self
            .get_vpn_portal_client()
            .await?
            .get_vpn_portal_info(
                BaseController::default(),
                GetVpnPortalInfoRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .vpn_portal_info
            .unwrap_or_default())
    }

    async fn fetch_stats(&self) -> Result<Vec<MetricSnapshot>, Error> {
        Ok(self
            .get_stats_client()
            .await?
            .get_stats(
                BaseController::default(),
                GetStatsRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .metrics)
    }

    async fn fetch_prometheus_stats(&self) -> Result<String, Error> {
        Ok(self
            .get_stats_client()
            .await?
            .get_prometheus_stats(
                BaseController::default(),
                GetPrometheusStatsRequest {
                    instance: Some(self.instance_selector.clone()),
                },
            )
            .await?
            .prometheus_text)
    }

    fn connector_validate_url(url: &str) -> Result<url::Url, Error> {
        let url = url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid url ({url}): {e}"))?;
        TunnelScheme::try_from(&url).map_err(|_| {
            anyhow::anyhow!("unsupported scheme \"{}\" in url ({url})", url.scheme())
        })?;
        Ok(url)
    }

    async fn apply_connector_modify(
        &self,
        url: &str,
        action: ConfigPatchAction,
    ) -> Result<(), Error> {
        let url = match action {
            ConfigPatchAction::Add => Self::connector_validate_url(url)?,
            ConfigPatchAction::Remove => {
                url::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid url ({url}): {e}"))?
            }
            ConfigPatchAction::Clear => {
                return Err(anyhow::anyhow!(
                    "unsupported connector patch action: {:?}",
                    action
                ));
            }
        };
        let client = self.get_config_client().await?;
        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                connectors: vec![UrlPatch {
                    action: action.into(),
                    url: Some(url.into()),
                }],
                ..Default::default()
            }),
        };
        let _response = client
            .patch_config(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn handle_connector_modify(
        &self,
        url: &str,
        action: ConfigPatchAction,
    ) -> Result<(), Error> {
        let url = url.to_string();
        self.apply_to_instances(|handler| {
            let url = url.clone();
            Box::pin(async move { handler.apply_connector_modify(&url, action).await })
        })
        .await
    }

    async fn handle_peer_list(&self) -> Result<(), Error> {
        #[derive(tabled::Tabled, serde::Serialize)]
        struct PeerTableItem {
            #[tabled(rename = "ipv4")]
            cidr: String,
            #[tabled(skip)]
            ipv4: String,
            hostname: String,
            cost: String,
            #[tabled(rename = "lat(ms)")]
            lat_ms: String,
            #[tabled(rename = "loss")]
            loss_rate: String,
            #[tabled(rename = "rx")]
            rx_bytes: String,
            #[tabled(rename = "tx")]
            tx_bytes: String,
            #[tabled(rename = "tunnel")]
            tunnel_proto: String,
            #[tabled(rename = "NAT")]
            nat_type: String,
            #[tabled(skip)]
            id: String,
            version: String,
        }

        impl From<PeerRoutePair> for PeerTableItem {
            fn from(p: PeerRoutePair) -> Self {
                let route = p.route.clone().unwrap_or_default();
                let lat_ms = if route.cost == 1 {
                    p.get_latency_ms().unwrap_or(0.0)
                } else {
                    route.path_latency_latency_first() as f64
                };
                PeerTableItem {
                    cidr: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                    ipv4: route
                        .ipv4_addr
                        .map(|ip: easytier::proto::common::Ipv4Inet| ip.address.unwrap_or_default())
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    hostname: route.hostname.clone(),
                    cost: cost_to_str(route.cost),
                    lat_ms: format!("{:.2}", lat_ms),
                    loss_rate: format!("{:.1}%", p.get_loss_rate().unwrap_or(0.0) * 100.0),
                    rx_bytes: format_size(p.get_rx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tx_bytes: format_size(p.get_tx_bytes().unwrap_or(0), humansize::DECIMAL),
                    tunnel_proto: p.get_conn_protos().unwrap_or_default().join(","),
                    nat_type: p.get_udp_nat_type(),
                    id: route.peer_id.to_string(),
                    version: if route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        route.version
                    },
                }
            }
        }

        impl From<NodeInfo> for PeerTableItem {
            fn from(p: NodeInfo) -> Self {
                PeerTableItem {
                    cidr: p.ipv4_addr.clone(),
                    ipv4: Ipv4Inet::from_str(&p.ipv4_addr)
                        .map(|ip| ip.address().to_string())
                        .unwrap_or_default(),
                    hostname: p.hostname.clone(),
                    cost: "Local".to_string(),
                    lat_ms: "-".to_string(),
                    loss_rate: "-".to_string(),
                    rx_bytes: "-".to_string(),
                    tx_bytes: "-".to_string(),
                    tunnel_proto: "-".to_string(),
                    nat_type: if let Some(info) = p.stun_info {
                        info.udp_nat_type().as_str_name().to_string()
                    } else {
                        "Unknown".to_string()
                    },
                    id: p.peer_id.to_string(),
                    version: p.version,
                }
            }
        }

        let build_items = |data: &PeerListData| {
            let mut items = Vec::with_capacity(data.peer_routes.len() + 1);
            items.push(PeerTableItem::from(data.node_info.clone()));
            items.extend(data.peer_routes.iter().cloned().map(Into::into));
            items.sort_by(|a, b| {
                use std::net::{IpAddr, Ipv4Addr};

                let a_is_local = a.cost == "Local";
                let b_is_local = b.cost == "Local";
                if a_is_local != b_is_local {
                    return if a_is_local {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    };
                }

                let a_is_public = a.hostname.starts_with(peers::PUBLIC_SERVER_HOSTNAME_PREFIX);
                let b_is_public = b.hostname.starts_with(peers::PUBLIC_SERVER_HOSTNAME_PREFIX);
                if a_is_public != b_is_public {
                    return if a_is_public {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    };
                }

                let a_ip = IpAddr::from_str(&a.ipv4).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                let b_ip = IpAddr::from_str(&b.ipv4).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                match a_ip.cmp(&b_ip) {
                    std::cmp::Ordering::Equal => a.hostname.cmp(&b.hostname),
                    other => other,
                }
            });
            items
        };

        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_peer_list_data()))
            .await?;

        if self.verbose {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|data| data.peer_routes))
                    .collect(),
            );
        }
        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|data| build_items(&data)))
                    .collect(),
            );
        }

        self.print_results(&results, |data| {
            let items = build_items(data);
            print_output(
                &items,
                self.output_format,
                &["tunnel", "version"],
                &["version", "tunnel", "nat", "tx", "rx", "loss", "lat(ms)"],
                self.no_trunc,
            )
        })
    }

    async fn handle_peer_ipv6(&self) -> Result<(), Error> {
        #[derive(tabled::Tabled, serde::Serialize)]
        struct PeerIpv6NodeRow {
            peer_id: u32,
            hostname: String,
            inst_id: String,
            ipv4: String,
            public_ipv6_addr: String,
            provider_prefix: String,
        }

        #[derive(tabled::Tabled, serde::Serialize)]
        struct ProviderLeaseRow {
            peer_id: u32,
            inst_id: String,
            leased_addr: String,
            valid_until: String,
            reused: bool,
        }

        #[derive(serde::Serialize)]
        struct ProviderLeaseSection {
            provider_prefix: String,
            leases: Vec<ProviderLeaseRow>,
        }

        #[derive(serde::Serialize)]
        struct PeerIpv6View {
            nodes: Vec<PeerIpv6NodeRow>,
            local_provider: Option<ProviderLeaseSection>,
        }

        fn fmt_ipv6_inet(value: Option<easytier::proto::common::Ipv6Inet>) -> String {
            value
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string())
        }

        fn fmt_valid_until(unix_seconds: i64) -> String {
            chrono::DateTime::<chrono::Utc>::from_timestamp(unix_seconds, 0)
                .map(|ts| {
                    ts.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M:%S")
                        .to_string()
                })
                .unwrap_or_else(|| unix_seconds.to_string())
        }

        let build_view = |data: &PeerIpv6DataRaw| {
            let mut nodes = Vec::with_capacity(data.routes.len() + 1);
            nodes.push(PeerIpv6NodeRow {
                peer_id: data.node_info.peer_id,
                hostname: data.node_info.hostname.clone(),
                inst_id: data.node_info.inst_id.clone(),
                ipv4: data.node_info.ipv4_addr.clone(),
                public_ipv6_addr: fmt_ipv6_inet(data.node_info.public_ipv6_addr),
                provider_prefix: fmt_ipv6_inet(data.node_info.ipv6_public_addr_prefix),
            });
            nodes.extend(data.routes.iter().map(|route| {
                PeerIpv6NodeRow {
                    peer_id: route.peer_id,
                    hostname: route.hostname.clone(),
                    inst_id: route.inst_id.clone(),
                    ipv4: route
                        .ipv4_addr
                        .map(|ipv4| ipv4.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    public_ipv6_addr: fmt_ipv6_inet(route.public_ipv6_addr),
                    provider_prefix: fmt_ipv6_inet(route.ipv6_public_addr_prefix),
                }
            }));
            nodes.sort_by_key(|row| {
                (
                    row.peer_id != data.node_info.peer_id,
                    row.peer_id,
                    row.inst_id.clone(),
                )
            });

            let local_provider = data.provider_info.provider_prefix.map(|provider_prefix| {
                let mut leases = data
                    .provider_info
                    .provider_leases
                    .iter()
                    .map(|lease| ProviderLeaseRow {
                        peer_id: lease.peer_id,
                        inst_id: lease.inst_id.clone(),
                        leased_addr: fmt_ipv6_inet(lease.leased_addr),
                        valid_until: fmt_valid_until(lease.valid_until_unix_seconds),
                        reused: lease.reused,
                    })
                    .collect::<Vec<_>>();
                leases.sort_by_key(|lease| {
                    (
                        lease.peer_id,
                        lease.inst_id.clone(),
                        lease.leased_addr.clone(),
                    )
                });
                ProviderLeaseSection {
                    provider_prefix: provider_prefix.to_string(),
                    leases,
                }
            });

            PeerIpv6View {
                nodes,
                local_provider,
            }
        };

        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_peer_ipv6_data()))
            .await?;

        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|data| build_view(&data)))
                    .collect(),
            );
        }

        self.print_results(&results, |data| {
            let view = build_view(data);
            print_output(&view.nodes, self.output_format, &[], &[], self.no_trunc)?;

            if let Some(local_provider) = view.local_provider {
                println!();
                println!("Local provider prefix: {}", local_provider.provider_prefix);
                if local_provider.leases.is_empty() {
                    println!("No active provider leases");
                } else {
                    print_output(
                        &local_provider.leases,
                        self.output_format,
                        &[],
                        &[],
                        self.no_trunc,
                    )?;
                }
            }

            Ok(())
        })
    }

    async fn handle_route_dump(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_route_dump()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }
        self.print_results(&results, |result| {
            println!("response: {}", result);
            Ok(())
        })
    }

    async fn handle_foreign_network_list(&self, include_trusted_keys: bool) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| {
                Box::pin(handler.fetch_foreign_networks(include_trusted_keys))
            })
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |networks| {
            for (idx, (k, v)) in networks.iter().enumerate() {
                println!("{} Network Name: {}", idx + 1, k);
                for peer in v.peers.iter() {
                    println!(
                        "  peer_id: {}, peer_conn_count: {}, conns: [ {} ]",
                        peer.peer_id,
                        peer.conns.len(),
                        peer.conns
                            .iter()
                            .map(|conn| format!(
                                "remote_addr: {}, rx_bytes: {}, tx_bytes: {}, latency_us: {}",
                                conn.tunnel
                                    .as_ref()
                                    .and_then(|t| t.display_remote_addr())
                                    .unwrap_or_default(),
                                conn.stats.as_ref().map(|s| s.rx_bytes).unwrap_or_default(),
                                conn.stats.as_ref().map(|s| s.tx_bytes).unwrap_or_default(),
                                conn.stats
                                    .as_ref()
                                    .map(|s| s.latency_us)
                                    .unwrap_or_default(),
                            ))
                            .collect::<Vec<_>>()
                            .join("; ")
                    );
                }
                if include_trusted_keys {
                    println!("  trusted_keys:");
                    for trusted_key in &v.trusted_keys {
                        let source = TrustedKeySourcePb::try_from(trusted_key.source)
                            .map(|source| source.as_str_name())
                            .unwrap_or("TRUSTED_KEY_SOURCE_PB_UNSPECIFIED");
                        let expiry = trusted_key
                            .expiry_unix
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string());
                        println!(
                            "    source: {}, expiry_unix: {}, pubkey: {}",
                            source,
                            expiry,
                            BASE64_STANDARD.encode(&trusted_key.pubkey),
                        );
                    }
                }
            }
            Ok(())
        })
    }

    async fn handle_global_foreign_network_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_global_foreign_networks()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |networks| {
            for (k, v) in networks.iter() {
                println!("Peer ID: {}", k);
                for n in v.foreign_networks.iter() {
                    println!(
                        "  Network Name: {}, Last Updated: {}, Version: {}, PeerIds: {:?}",
                        n.network_name, n.last_updated, n.version, n.peer_ids
                    );
                }
            }
            Ok(())
        })
    }

    async fn handle_route_list(&self) -> Result<(), Error> {
        #[derive(tabled::Tabled, serde::Serialize)]
        struct RouteTableItem {
            ipv4: String,
            hostname: String,
            proxy_cidrs: String,

            next_hop_ipv4: String,
            next_hop_hostname: String,
            next_hop_lat: f64,
            path_len: i32,
            path_latency: i32,

            next_hop_ipv4_lat_first: String,
            next_hop_hostname_lat_first: String,
            path_len_lat_first: i32,
            path_latency_lat_first: i32,

            version: String,
        }

        let build_items = |data: &RouteListData| {
            let mut items = vec![RouteTableItem {
                ipv4: data.node_info.ipv4_addr.clone(),
                hostname: data.node_info.hostname.clone(),
                proxy_cidrs: data.node_info.proxy_cidrs.join(", "),
                next_hop_ipv4: "-".to_string(),
                next_hop_hostname: "Local".to_string(),
                next_hop_lat: 0.0,
                path_len: 0,
                path_latency: 0,
                next_hop_ipv4_lat_first: "-".to_string(),
                next_hop_hostname_lat_first: "Local".to_string(),
                path_len_lat_first: 0,
                path_latency_lat_first: 0,
                version: data.node_info.version.clone(),
            }];

            for p in data.peer_routes.iter() {
                let Some(next_hop_pair) = data.peer_routes.iter().find(|pair| {
                    pair.route.clone().unwrap_or_default().peer_id
                        == p.route.clone().unwrap_or_default().next_hop_peer_id
                }) else {
                    continue;
                };

                let next_hop_pair_latency_first = data.peer_routes.iter().find(|pair| {
                    pair.route.clone().unwrap_or_default().peer_id
                        == p.route
                            .clone()
                            .unwrap_or_default()
                            .next_hop_peer_id_latency_first
                            .unwrap_or_default()
                });

                let route = p.route.clone().unwrap_or_default();
                items.push(RouteTableItem {
                    ipv4: route.ipv4_addr.map(|ip| ip.to_string()).unwrap_or_default(),
                    hostname: route.hostname.clone(),
                    proxy_cidrs: route.proxy_cidrs.clone().join(","),
                    next_hop_ipv4: if route.cost == 1 {
                        "DIRECT".to_string()
                    } else {
                        next_hop_pair
                            .route
                            .clone()
                            .unwrap_or_default()
                            .ipv4_addr
                            .map(|ip| ip.to_string())
                            .unwrap_or_default()
                    },
                    next_hop_hostname: if route.cost == 1 {
                        "DIRECT".to_string()
                    } else {
                        next_hop_pair.route.clone().unwrap_or_default().hostname
                    },
                    next_hop_lat: next_hop_pair.get_latency_ms().unwrap_or(0.0),
                    path_len: route.cost,
                    path_latency: route.path_latency,
                    next_hop_ipv4_lat_first: if route.cost_latency_first.unwrap_or_default() == 1 {
                        "DIRECT".to_string()
                    } else {
                        next_hop_pair_latency_first
                            .map(|pair| pair.route.clone().unwrap_or_default().ipv4_addr)
                            .unwrap_or_default()
                            .map(|ip| ip.to_string())
                            .unwrap_or_default()
                    },
                    next_hop_hostname_lat_first: if route.cost_latency_first.unwrap_or_default()
                        == 1
                    {
                        "DIRECT".to_string()
                    } else {
                        next_hop_pair_latency_first
                            .map(|pair| pair.route.clone().unwrap_or_default().hostname)
                            .unwrap_or_default()
                    },
                    path_latency_lat_first: route.path_latency_latency_first.unwrap_or_default(),
                    path_len_lat_first: route.cost_latency_first.unwrap_or_default(),
                    version: if route.version.is_empty() {
                        "unknown".to_string()
                    } else {
                        route.version
                    },
                });
            }

            items
        };

        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_route_list_data()))
            .await?;

        if self.verbose {
            return self.print_json_results(results);
        }
        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|data| build_items(&data)))
                    .collect(),
            );
        }

        self.print_results(&results, |data| {
            let items = build_items(data);
            print_output(
                &items,
                self.output_format,
                &["proxy_cidrs", "version"],
                &["proxy_cidrs", "version"],
                self.no_trunc,
            )
        })
    }

    async fn handle_connector_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_connector_list()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }
        self.print_results(&results, |connectors| {
            println!("response: {:#?}", connectors);
            Ok(())
        })
    }

    async fn handle_acl_stats(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_acl_stats()))
            .await?;
        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |acl_stats| {
            if let Some(acl_stats) = acl_stats {
                println!("{}", acl_stats);
            } else {
                println!("No ACL statistics available");
            }
            Ok(())
        })
    }

    async fn handle_mapped_listener_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_mapped_listener_list()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }
        self.print_results(&results, |listeners| {
            println!("response: {:#?}", listeners);
            Ok(())
        })
    }

    async fn apply_mapped_listener_modify(
        &self,
        url: &str,
        action: ConfigPatchAction,
    ) -> Result<(), Error> {
        let url = Self::mapped_listener_validate_url(url)?;
        let client = self.get_config_client().await?;
        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                mapped_listeners: vec![UrlPatch {
                    action: action.into(),
                    url: Some(url.into()),
                }],
                ..Default::default()
            }),
        };
        let _response = client
            .patch_config(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn handle_mapped_listener_modify(
        &self,
        url: &str,
        action: ConfigPatchAction,
    ) -> Result<(), Error> {
        let url = url.to_string();
        self.apply_to_instances(|handler| {
            let url = url.clone();
            Box::pin(async move { handler.apply_mapped_listener_modify(&url, action).await })
        })
        .await
    }

    fn mapped_listener_validate_url(url: &str) -> Result<url::Url, Error> {
        let url = url::Url::parse(url)?;
        if url.scheme() != "tcp" && url.scheme() != "udp" {
            return Err(anyhow::anyhow!(
                "Url ({url}) must start with tcp:// or udp://"
            ));
        } else if url.port().is_none() {
            return Err(anyhow::anyhow!("Url ({url}) is missing port num"));
        }
        Ok(url)
    }

    async fn apply_port_forward_modify(
        &self,
        action: ConfigPatchAction,
        protocol: &str,
        bind_addr: &str,
        dst_addr: Option<&str>,
    ) -> Result<(), Error> {
        let bind_addr: std::net::SocketAddr = bind_addr
            .parse()
            .with_context(|| format!("Invalid bind address: {}", bind_addr))?;

        let socket_type = match protocol {
            "tcp" => SocketType::Tcp,
            "udp" => SocketType::Udp,
            _ => return Err(anyhow::anyhow!("Protocol must be 'tcp' or 'udp'")),
        };

        let client = self.get_config_client().await?;
        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                port_forwards: vec![PortForwardPatch {
                    action: action.into(),
                    cfg: Some(PortForwardConfigPb {
                        bind_addr: Some(bind_addr.into()),
                        dst_addr: dst_addr.map(|s| s.parse::<SocketAddr>().unwrap().into()),
                        socket_type: socket_type.into(),
                    }),
                }],
                ..Default::default()
            }),
        };

        client
            .patch_config(BaseController::default(), request)
            .await?;
        println!(
            "Port forward rule {}: {} {}",
            action.as_str_name().to_lowercase(),
            protocol,
            bind_addr
        );
        Ok(())
    }

    async fn handle_port_forward_modify(
        &self,
        action: ConfigPatchAction,
        protocol: &str,
        bind_addr: &str,
        dst_addr: Option<&str>,
    ) -> Result<(), Error> {
        let protocol = protocol.to_string();
        let bind_addr = bind_addr.to_string();
        let dst_addr = dst_addr.map(str::to_string);
        self.apply_to_instances(|handler| {
            let protocol = protocol.clone();
            let bind_addr = bind_addr.clone();
            let dst_addr = dst_addr.clone();
            Box::pin(async move {
                handler
                    .apply_port_forward_modify(action, &protocol, &bind_addr, dst_addr.as_deref())
                    .await
            })
        })
        .await
    }

    async fn handle_port_forward_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_port_forward_list()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        #[derive(tabled::Tabled, serde::Serialize)]
        struct PortForwardTableItem {
            protocol: String,
            bind_addr: String,
            dst_addr: String,
        }

        self.print_results(&results, |response| {
            let items: Vec<PortForwardTableItem> = response
                .cfgs
                .iter()
                .cloned()
                .map(|rule| PortForwardTableItem {
                    protocol: format!(
                        "{:?}",
                        SocketType::try_from(rule.socket_type).unwrap_or(SocketType::Tcp)
                    ),
                    bind_addr: rule
                        .bind_addr
                        .map(|addr| addr.to_string())
                        .unwrap_or_default(),
                    dst_addr: rule
                        .dst_addr
                        .map(|addr| addr.to_string())
                        .unwrap_or_default(),
                })
                .collect();

            print_output(&items, self.output_format, &[], &[], self.no_trunc)
        })
    }

    async fn apply_whitelist_set(&self, ports: &str, is_tcp: bool) -> Result<(), Error> {
        let mut whitelist = Self::parse_port_list(ports)?
            .into_iter()
            .map(|p| StringPatch {
                action: ConfigPatchAction::Add.into(),
                value: p,
            })
            .collect::<Vec<_>>();
        whitelist.insert(
            0,
            StringPatch {
                action: ConfigPatchAction::Clear.into(),
                value: "".to_string(),
            },
        );
        let client = self.get_config_client().await?;

        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                acl: Some(AclPatch {
                    tcp_whitelist: if is_tcp { whitelist.clone() } else { vec![] },
                    udp_whitelist: if is_tcp { vec![] } else { whitelist },
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        client
            .patch_config(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn handle_whitelist_set_tcp(&self, ports: &str) -> Result<(), Error> {
        let ports = ports.to_string();
        self.apply_to_instances(|handler| {
            let ports = ports.clone();
            Box::pin(async move { handler.apply_whitelist_set(&ports, true).await })
        })
        .await?;
        println!("TCP whitelist updated: {}", ports);
        Ok(())
    }

    async fn handle_whitelist_set_udp(&self, ports: &str) -> Result<(), Error> {
        let ports = ports.to_string();
        self.apply_to_instances(|handler| {
            let ports = ports.clone();
            Box::pin(async move { handler.apply_whitelist_set(&ports, false).await })
        })
        .await?;
        println!("UDP whitelist updated: {}", ports);
        Ok(())
    }

    async fn apply_whitelist_clear(&self, is_tcp: bool) -> Result<(), Error> {
        let client = self.get_config_client().await?;

        let request = PatchConfigRequest {
            instance: Some(self.instance_selector.clone()),
            patch: Some(InstanceConfigPatch {
                acl: Some(AclPatch {
                    tcp_whitelist: if is_tcp {
                        vec![StringPatch {
                            action: ConfigPatchAction::Clear.into(),
                            value: "".to_string(),
                        }]
                    } else {
                        vec![]
                    },
                    udp_whitelist: if is_tcp {
                        vec![]
                    } else {
                        vec![StringPatch {
                            action: ConfigPatchAction::Clear.into(),
                            value: "".to_string(),
                        }]
                    },
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        client
            .patch_config(BaseController::default(), request)
            .await?;
        Ok(())
    }

    async fn handle_whitelist_clear_tcp(&self) -> Result<(), Error> {
        self.apply_to_instances(|handler| Box::pin(handler.apply_whitelist_clear(true)))
            .await?;
        println!("TCP whitelist cleared");
        Ok(())
    }

    async fn handle_whitelist_clear_udp(&self) -> Result<(), Error> {
        self.apply_to_instances(|handler| Box::pin(handler.apply_whitelist_clear(false)))
            .await?;
        println!("UDP whitelist cleared");
        Ok(())
    }

    async fn handle_whitelist_show(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_whitelist()))
            .await?;
        if self.verbose || *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |response| {
            println!(
                "TCP Whitelist: {}",
                if response.tcp_ports.is_empty() {
                    "None".to_string()
                } else {
                    response.tcp_ports.join(", ")
                }
            );

            println!(
                "UDP Whitelist: {}",
                if response.udp_ports.is_empty() {
                    "None".to_string()
                } else {
                    response.udp_ports.join(", ")
                }
            );
            Ok(())
        })
    }

    async fn handle_logger_get(&self) -> Result<(), Error> {
        let client = self.get_logger_client().await?;
        let request = GetLoggerConfigRequest::default();
        let response = client
            .get_logger_config(BaseController::default(), request)
            .await?;

        match self.output_format {
            OutputFormat::Table => {
                let level_str = match response.level() {
                    LogLevel::Disabled => "disabled",
                    LogLevel::Error => "error",
                    LogLevel::Warning => "warning",
                    LogLevel::Info => "info",
                    LogLevel::Debug => "debug",
                    LogLevel::Trace => "trace",
                };
                println!("Current Log Level: {}", level_str);
            }
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&response)?;
                println!("{}", json);
            }
        }

        Ok(())
    }

    async fn handle_logger_set(&self, level: &str) -> Result<(), Error> {
        let log_level = match level.to_lowercase().as_str() {
            "disabled" => LogLevel::Disabled,
            "error" => LogLevel::Error,
            "warning" => LogLevel::Warning,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid log level: {}. Valid levels are: disabled, error, warning, info, debug, trace",
                    level
                ));
            }
        };

        let client = self.get_logger_client().await?;
        let request = SetLoggerConfigRequest {
            level: log_level.into(),
        };
        let response = client
            .set_logger_config(BaseController::default(), request)
            .await?;

        match self.output_format {
            OutputFormat::Table => {
                println!("Log level successfully set to: {}", level);
            }
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&response)?;
                println!("{}", json);
            }
        }

        Ok(())
    }

    async fn handle_credential_generate(
        &self,
        ttl: i64,
        credential_id: Option<String>,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        reusable: bool,
    ) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| {
                let credential_id = credential_id.clone();
                let groups = groups.clone();
                let allowed_proxy_cidrs = allowed_proxy_cidrs.clone();
                Box::pin(async move {
                    handler
                        .get_credential_client()
                        .await?
                        .generate_credential(
                            BaseController::default(),
                            GenerateCredentialRequest {
                                credential_id,
                                groups,
                                allow_relay,
                                allowed_proxy_cidrs,
                                ttl_seconds: ttl,
                                instance: Some(handler.instance_selector.clone()),
                                reusable: Some(reusable),
                            },
                        )
                        .await
                        .map_err(Into::into)
                })
            })
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |response| {
            println!("Credential generated successfully:");
            println!("  credential_id:     {}", response.credential_id);
            println!("  credential_secret: {}", response.credential_secret);
            println!();
            println!("To use this credential on a new node:");
            println!(
                "  easytier-core --network-name <name> --secure-mode --credential {} -p <node-url>",
                response.credential_secret
            );
            Ok(())
        })
    }

    async fn handle_credential_revoke(&self, credential_id: &str) -> Result<(), Error> {
        let credential_id = credential_id.to_string();
        let results = self
            .collect_instance_results(|handler| {
                let credential_id = credential_id.clone();
                Box::pin(async move {
                    handler
                        .get_credential_client()
                        .await?
                        .revoke_credential(
                            BaseController::default(),
                            RevokeCredentialRequest {
                                credential_id,
                                instance: Some(handler.instance_selector.clone()),
                            },
                        )
                        .await
                        .map_err(Into::into)
                })
            })
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |response| {
            if response.success {
                println!("Credential revoked successfully");
            } else {
                println!("Credential not found");
            }
            Ok(())
        })
    }

    async fn handle_credential_list(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_credential_list()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |response| {
            if response.credentials.is_empty() {
                println!("No active credentials");
            } else {
                use tabled::{builder::Builder, settings::Style};
                let mut builder = Builder::default();
                builder.push_record([
                    "ID",
                    "Groups",
                    "Relay",
                    "Reusable",
                    "Expiry",
                    "Allowed CIDRs",
                ]);
                for cred in &response.credentials {
                    let expiry = {
                        let secs = cred.expiry_unix;
                        let remaining = secs
                            - std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64;
                        if remaining > 0 {
                            format!("{}s remaining", remaining)
                        } else {
                            "expired".to_string()
                        }
                    };
                    builder.push_record([
                        &cred.credential_id[..],
                        &cred.groups.join(","),
                        if cred.allow_relay { "yes" } else { "no" },
                        if cred.reusable.unwrap_or(true) {
                            "yes"
                        } else {
                            "no"
                        },
                        &expiry,
                        &cred.allowed_proxy_cidrs.join(","),
                    ]);
                }
                let table = builder.build().with(Style::rounded()).to_string();
                println!("{}", table);
            }
            Ok(())
        })
    }

    async fn handle_peer_center(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_peer_center_rows()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        #[derive(tabled::Tabled, serde::Serialize)]
        struct PeerCenterTableItem {
            node_id: String,
            hostname: String,
            ipv4: String,
            #[tabled(rename = "direct_peers")]
            direct_peers_str: String,
        }

        self.print_results(&results, |rows| {
            let table_rows = rows
                .iter()
                .map(|row| PeerCenterTableItem {
                    node_id: row.node_id.clone(),
                    hostname: row.hostname.clone(),
                    ipv4: row.ipv4.clone(),
                    direct_peers_str: row
                        .direct_peers
                        .iter()
                        .map(|x| {
                            format!(
                                "{}({}[{}]): {}ms",
                                x.node_id, x.hostname, x.ipv4, x.latency_ms,
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                })
                .collect::<Vec<_>>();
            print_output(
                &table_rows,
                self.output_format,
                &["direct_peers"],
                &["direct_peers"],
                self.no_trunc,
            )
        })
    }

    async fn handle_vpn_portal(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_vpn_portal_info()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        self.print_results(&results, |resp| {
            println!("portal_name: {}", resp.vpn_type);
            println!(
                r#"
############### client_config_start ###############
{}
############### client_config_end ###############
"#,
                resp.client_config
            );
            println!("connected_clients:\n{:#?}", resp.connected_clients);
            Ok(())
        })
    }

    async fn handle_node(&self, sub_command: Option<&NodeSubCommand>) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_node_info()))
            .await?;

        if self.verbose || *self.output_format == OutputFormat::Json {
            return match sub_command {
                Some(NodeSubCommand::Config) => self.print_json_results(
                    results
                        .into_iter()
                        .map(|result| result.map(|node| node.config))
                        .collect(),
                ),
                _ => self.print_json_results(results),
            };
        }

        self.print_results(&results, |node_info| match sub_command {
            Some(NodeSubCommand::Config) => {
                println!("{}", node_info.config);
                Ok(())
            }
            Some(NodeSubCommand::Info) | None => {
                let stun_info = node_info.stun_info.clone().unwrap_or_default();
                let ip_list = node_info.ip_list.clone().unwrap_or_default();

                let mut builder = tabled::builder::Builder::default();
                builder.push_record(vec!["Virtual IP", node_info.ipv4_addr.as_str()]);
                builder.push_record(vec!["Hostname", node_info.hostname.as_str()]);
                builder.push_record(vec![
                    "Proxy CIDRs",
                    node_info.proxy_cidrs.join(", ").as_str(),
                ]);
                builder.push_record(vec!["Peer ID", node_info.peer_id.to_string().as_str()]);
                stun_info.public_ip.iter().for_each(|ip| {
                    let Ok(ip) = ip.parse::<IpAddr>() else {
                        return;
                    };
                    if ip.is_ipv4() {
                        builder.push_record(vec!["Public IPv4", ip.to_string().as_str()]);
                    } else {
                        builder.push_record(vec!["Public IPv6", ip.to_string().as_str()]);
                    }
                });
                builder.push_record(vec![
                    "UDP Stun Type",
                    format!("{:?}", stun_info.udp_nat_type()).as_str(),
                ]);
                ip_list.interface_ipv4s.iter().for_each(|ip| {
                    builder.push_record(vec!["Interface IPv4", ip.to_string().as_str()]);
                });
                ip_list.interface_ipv6s.iter().for_each(|ip| {
                    builder.push_record(vec!["Interface IPv6", ip.to_string().as_str()]);
                });
                for (idx, l) in node_info.listeners.iter().enumerate() {
                    if l.starts_with("ring") {
                        continue;
                    }
                    builder.push_record(vec![format!("Listener {}", idx).as_str(), l]);
                }

                println!("{}", builder.build().with(Style::markdown()));
                Ok(())
            }
        })
    }

    async fn handle_stats_show(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_stats()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(results);
        }

        #[derive(tabled::Tabled, serde::Serialize)]
        struct StatsTableRow {
            #[tabled(rename = "Metric Name")]
            name: String,
            #[tabled(rename = "Value")]
            value: String,
            #[tabled(rename = "Labels")]
            labels: String,
        }

        self.print_results(&results, |metrics| {
            let table_rows: Vec<StatsTableRow> = metrics
                .iter()
                .map(|metric| {
                    let labels_str = if metric.labels.is_empty() {
                        "-".to_string()
                    } else {
                        metric
                            .labels
                            .iter()
                            .map(|(k, v)| format!("{}={}", k, v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };

                    let formatted_value = if metric.name.contains("bytes") {
                        format_size(metric.value, humansize::BINARY)
                    } else if metric.name.contains("duration") {
                        format!("{} ms", metric.value)
                    } else {
                        metric.value.to_string()
                    };

                    StatsTableRow {
                        name: metric.name.clone(),
                        value: formatted_value,
                        labels: labels_str,
                    }
                })
                .collect();

            print_output(
                &table_rows,
                self.output_format,
                &["labels"],
                &["labels"],
                self.no_trunc,
            )
        })
    }

    async fn handle_stats_prometheus(&self) -> Result<(), Error> {
        let results = self
            .collect_instance_results(|handler| Box::pin(handler.fetch_prometheus_stats()))
            .await?;

        if *self.output_format == OutputFormat::Json {
            return self.print_json_results(
                results
                    .into_iter()
                    .map(|result| result.map(|text| serde_json::json!({ "prometheus_text": text })))
                    .collect(),
            );
        }

        self.print_results(&results, |text| {
            println!("{}", text);
            Ok(())
        })
    }

    fn parse_port_list(ports_str: &str) -> Result<Vec<String>, Error> {
        let mut ports = Vec::new();
        for port_spec in ports_str.split(',') {
            let port_spec = port_spec.trim();
            if port_spec.contains('-') {
                // Handle port range
                let parts: Vec<&str> = port_spec.split('-').collect();
                if parts.len() != 2 {
                    return Err(anyhow::anyhow!("Invalid port range: {}", port_spec));
                }
                let start: u16 = parts[0]
                    .parse()
                    .with_context(|| format!("Invalid start port: {}", parts[0]))?;
                let end: u16 = parts[1]
                    .parse()
                    .with_context(|| format!("Invalid end port: {}", parts[1]))?;
                if start > end {
                    return Err(anyhow::anyhow!("Invalid port range: start > end"));
                }
                ports.push(format!("{}-{}", start, end));
            } else {
                // Handle single port
                let port: u16 = port_spec
                    .parse()
                    .with_context(|| format!("Invalid port number: {}", port_spec))?;
                ports.push(port.to_string());
            }
        }
        Ok(ports)
    }
}

fn print_output<T>(
    items: &[T],
    format: &OutputFormat,
    optional_columns: &[&str],
    drop_columns: &[&str],
    no_trunc: bool,
) -> Result<(), Error>
where
    T: tabled::Tabled + serde::Serialize,
{
    match format {
        OutputFormat::Table => {
            let mut table = tabled::Table::new(items);
            table.with(Style::markdown());
            if no_trunc {
                println!("{}", table);
                return Ok(());
            }
            let headers = T::headers()
                .iter()
                .map(|header| header.as_ref().to_string())
                .collect::<Vec<_>>();
            let col_widths = compute_column_widths(items);
            let terminal_width = terminal_table_width();
            let drop_indices = header_indices(&headers, drop_columns);
            let optional_indices = header_indices(&headers, optional_columns);
            let (active, drop_indices, total_width) =
                select_columns_to_drop(terminal_width, &drop_indices, &col_widths);
            apply_column_drops(&mut table, &drop_indices);
            apply_optional_column_truncation(
                &mut table,
                terminal_width,
                &headers,
                &optional_indices,
                &col_widths,
                &active,
                total_width,
            );
            println!("{}", table);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(items)?);
        }
    }
    Ok(())
}

fn terminal_table_width() -> Option<usize> {
    let (TerminalWidth(width), _) = terminal_size()?;
    let width = width as usize;
    // Avoid wrapping at the last column which can still trigger a hard line break.
    width.checked_sub(1)
}

fn apply_optional_column_truncation(
    table: &mut tabled::Table,
    terminal_width: Option<usize>,
    headers: &[String],
    optional_indices: &[usize],
    col_widths: &[usize],
    active: &[bool],
    total_width: usize,
) {
    let Some(terminal_width) = terminal_width else {
        return;
    };
    if optional_indices.is_empty() || total_width <= terminal_width {
        return;
    }

    let targets = optional_column_targets(terminal_width, optional_indices, col_widths, active);
    for (index, width) in targets {
        if let Some(name) = headers.get(index) {
            table.with(
                Modify::new(ByColumnName::new(name)).with(Width::truncate(width).suffix("...")),
            );
        }
    }
}

fn apply_column_drops(table: &mut tabled::Table, drop_indices: &[usize]) {
    let mut indices = drop_indices.to_vec();
    indices.sort_unstable_by(|a, b| b.cmp(a));
    for index in indices {
        table.with(Disable::column(Columns::single(index)));
    }
}

fn compute_column_widths<T>(items: &[T]) -> Vec<usize>
where
    T: tabled::Tabled,
{
    let mut widths = vec![0usize; T::LENGTH];
    for (idx, header) in T::headers().iter().enumerate() {
        widths[idx] = widths[idx].max(text_width(header.as_ref()));
    }
    for item in items {
        for (idx, field) in item.fields().iter().enumerate() {
            widths[idx] = widths[idx].max(text_width(field.as_ref()));
        }
    }
    widths
}

fn text_width(text: &str) -> usize {
    text.split('\n')
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
}

fn header_indices(headers: &[String], names: &[&str]) -> Vec<usize> {
    let mut indices = Vec::new();
    for name in names {
        if let Some(index) = headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case(name))
            && !indices.contains(&index)
        {
            indices.push(index);
        }
    }
    indices
}

fn select_columns_to_drop(
    terminal_width: Option<usize>,
    drop_indices: &[usize],
    col_widths: &[usize],
) -> (Vec<bool>, Vec<usize>, usize) {
    let mut active = vec![true; col_widths.len()];
    let Some(terminal_width) = terminal_width else {
        let total = table_total_width(col_widths, &active);
        return (active, vec![], total);
    };

    let mut total = table_total_width(col_widths, &active);
    if total <= terminal_width {
        return (active, vec![], total);
    }

    let mut dropped = vec![];
    for &index in drop_indices {
        if total <= terminal_width {
            break;
        }
        if active[index] {
            active[index] = false;
            dropped.push(index);
            total = table_total_width(col_widths, &active);
        }
    }

    (active, dropped, total)
}

fn table_total_width(col_widths: &[usize], active: &[bool]) -> usize {
    let col_count = active.iter().filter(|value| **value).count();
    if col_count == 0 {
        return 0;
    }
    let content_width = col_widths
        .iter()
        .zip(active.iter())
        .filter_map(|(width, keep)| keep.then_some(*width))
        .sum::<usize>();
    content_width + 3 * col_count + 1
}

fn optional_column_targets(
    terminal_width: usize,
    optional_indices: &[usize],
    col_widths: &[usize],
    active: &[bool],
) -> Vec<(usize, usize)> {
    if optional_indices.is_empty() {
        return vec![];
    }

    let mut is_optional = vec![false; col_widths.len()];
    for &index in optional_indices {
        if let Some(flag) = is_optional.get_mut(index) {
            *flag = true;
        }
    }

    let optional_indices = optional_indices
        .iter()
        .copied()
        .filter(|idx| active.get(*idx).copied().unwrap_or(false))
        .collect::<Vec<_>>();
    if optional_indices.is_empty() {
        return vec![];
    }

    let col_count = active.iter().filter(|value| **value).count();
    let overhead = 3 * col_count + 1;
    let mut required_width = overhead;
    for (idx, width) in col_widths.iter().enumerate() {
        if active.get(idx).copied().unwrap_or(false) && !is_optional[idx] {
            required_width += *width;
        }
    }

    let remaining = terminal_width.saturating_sub(required_width);
    let min_width = 6usize;
    let per_column = if remaining == 0 {
        min_width
    } else {
        (remaining / optional_indices.len()).clamp(min_width, 24)
    };

    optional_indices
        .into_iter()
        .map(|idx| (idx, col_widths[idx].min(per_column)))
        .collect()
}

#[tokio::main]
#[tracing::instrument]
async fn main() -> Result<(), Error> {
    let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
    rust_i18n::set_locale(&locale);
    let cli = Cli::parse();

    let client = RpcClient::new(TcpTunnelConnector::new(
        format!("tcp://{}:{}", cli.rpc_portal.ip(), cli.rpc_portal.port())
            .parse()
            .unwrap(),
    ));
    let handler = CommandHandler {
        client: Arc::new(tokio::sync::Mutex::new(client)),
        verbose: cli.verbose,
        output_format: &cli.output_format,
        no_trunc: cli.no_trunc,
        instance_select: &cli.instance_select,
        instance_selector: (&cli.instance_select).into(),
        resolved_target: None,
    };

    match cli.sub_command {
        SubCommand::Peer(peer_args) => match &peer_args.sub_command {
            Some(PeerSubCommand::List) => {
                handler.handle_peer_list().await?;
            }
            Some(PeerSubCommand::Ipv6) => {
                handler.handle_peer_ipv6().await?;
            }
            Some(PeerSubCommand::ListForeign { trusted_keys }) => {
                handler.handle_foreign_network_list(*trusted_keys).await?;
            }
            Some(PeerSubCommand::ListGlobalForeign) => {
                handler.handle_global_foreign_network_list().await?;
            }
            None => {
                handler.handle_peer_list().await?;
            }
        },
        SubCommand::Connector(conn_args) => match conn_args.sub_command {
            Some(ConnectorSubCommand::Add { url }) => {
                handler
                    .handle_connector_modify(&url, ConfigPatchAction::Add)
                    .await?;
                println!("connector add applied to selected instance(s): {url}");
            }
            Some(ConnectorSubCommand::Remove { url }) => {
                handler
                    .handle_connector_modify(&url, ConfigPatchAction::Remove)
                    .await?;
                println!("connector remove applied to selected instance(s): {url}");
            }
            Some(ConnectorSubCommand::List) => {
                handler.handle_connector_list().await?;
            }
            None => {
                handler.handle_connector_list().await?;
            }
        },
        SubCommand::MappedListener(mapped_listener_args) => {
            match mapped_listener_args.sub_command {
                Some(MappedListenerSubCommand::Add { url }) => {
                    handler
                        .handle_mapped_listener_modify(&url, ConfigPatchAction::Add)
                        .await?;
                    println!("add mapped listener: {url}");
                }
                Some(MappedListenerSubCommand::Remove { url }) => {
                    handler
                        .handle_mapped_listener_modify(&url, ConfigPatchAction::Remove)
                        .await?;
                    println!("remove mapped listener: {url}");
                }
                Some(MappedListenerSubCommand::List) | None => {
                    handler.handle_mapped_listener_list().await?;
                }
            }
        }
        SubCommand::Route(route_args) => match route_args.sub_command {
            Some(RouteSubCommand::List) | None => handler.handle_route_list().await?,
            Some(RouteSubCommand::Dump) => handler.handle_route_dump().await?,
        },
        SubCommand::Stun => {
            timeout(Duration::from_secs(25), async move {
                let collector = StunInfoCollector::new_with_default_servers();
                loop {
                    let ret = collector.get_stun_info();
                    if ret.udp_nat_type != NatType::Unknown as i32
                        && ret.tcp_nat_type != NatType::Unknown as i32
                    {
                        if cli.output_format == OutputFormat::Json {
                            match serde_json::to_string_pretty(&ret) {
                                Ok(json) => println!("{}", json),
                                Err(e) => eprintln!("Error serializing to JSON: {}", e),
                            }
                        } else {
                            println!("stun info: {:#?}", ret);
                        }
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
            .await
            .unwrap();
        }
        SubCommand::PeerCenter => {
            handler.handle_peer_center().await?;
        }
        SubCommand::VpnPortal => {
            handler.handle_vpn_portal().await?;
        }
        SubCommand::Node(sub_cmd) => {
            handler.handle_node(sub_cmd.sub_command.as_ref()).await?;
        }
        SubCommand::Service(service_args) => {
            let service = Service::new(service_args.name)?;
            match service_args.sub_command {
                ServiceSubCommand::Install(install_args) => {
                    let bin_path = install_args.core_path.unwrap_or_else(|| {
                        let mut ret = std::env::current_exe()
                            .unwrap()
                            .parent()
                            .unwrap()
                            .join("easytier-core");

                        if cfg!(target_os = "windows") {
                            ret.set_extension("exe");
                        }

                        ret
                    });
                    let bin_path = std::fs::canonicalize(bin_path).map_err(|e| {
                        anyhow::anyhow!("failed to get easytier core application: {}", e)
                    })?;
                    let bin_args = install_args.core_args.unwrap_or_default();
                    let work_dir = install_args.service_work_dir.unwrap_or_else(|| {
                        if cfg!(target_os = "windows") {
                            bin_path.parent().unwrap().to_path_buf()
                        } else {
                            std::env::temp_dir()
                        }
                    });

                    let work_dir = std::fs::canonicalize(&work_dir).map_err(|e| {
                        anyhow::anyhow!(
                            "failed to get service work directory[{}]: {}",
                            work_dir.display(),
                            e
                        )
                    })?;

                    if !work_dir.is_dir() {
                        return Err(anyhow::anyhow!("work directory is not a directory"));
                    }

                    let install_options = ServiceInstallOptions {
                        program: bin_path,
                        args: bin_args,
                        work_directory: work_dir,
                        disable_autostart: install_args.disable_autostart.unwrap_or(false),
                        description: Some(install_args.description),
                        display_name: install_args.display_name,
                        disable_restart_on_failure: install_args
                            .disable_restart_on_failure
                            .unwrap_or(false),
                    };
                    println!("install_options: {:#?}", install_options);
                    service.install(&install_options)?;
                }
                ServiceSubCommand::Uninstall => {
                    service.uninstall()?;
                }
                ServiceSubCommand::Status => {
                    let status = service.status()?;
                    match status {
                        ServiceStatus::Running => println!("Service is running"),
                        ServiceStatus::Stopped(_) => println!("Service is stopped"),
                        ServiceStatus::NotInstalled => println!("Service is not installed"),
                    }
                }
                ServiceSubCommand::Start => {
                    service.start()?;
                }
                ServiceSubCommand::Stop => {
                    service.stop()?;
                }
            }
        }
        SubCommand::Proxy => {
            let mut entries = vec![];

            for client_type in &["tcp", "kcp_src", "kcp_dst", "quic_src", "quic_dst"] {
                let client = handler.get_tcp_proxy_client(client_type).await?;
                let ret = client
                    .list_tcp_proxy_entry(BaseController::default(), Default::default())
                    .await;
                entries.extend(ret.unwrap_or_default().entries);
            }

            if cli.verbose {
                println!("{}", serde_json::to_string_pretty(&entries)?);
                return Ok(());
            }

            #[derive(tabled::Tabled, serde::Serialize)]
            struct TableItem {
                src: String,
                dst: String,
                start_time: String,
                state: String,
                transport_type: String,
            }

            let table_rows = entries
                .iter()
                .map(|e| TableItem {
                    src: SocketAddr::from(e.src.unwrap_or_default()).to_string(),
                    dst: SocketAddr::from(e.dst.unwrap_or_default()).to_string(),
                    start_time: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                        (e.start_time * 1000) as i64,
                    )
                    .unwrap()
                    .with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
                    state: format!("{:?}", TcpProxyEntryState::try_from(e.state).unwrap()),
                    transport_type: format!(
                        "{:?}",
                        TcpProxyEntryTransportType::try_from(e.transport_type).unwrap()
                    ),
                })
                .collect::<Vec<_>>();

            print_output(
                &table_rows,
                &cli.output_format,
                &["start_time", "state", "transport_type"],
                &["start_time", "state", "transport_type"],
                cli.no_trunc,
            )?;
        }
        SubCommand::Acl(acl_args) => match &acl_args.sub_command {
            Some(AclSubCommand::Stats) | None => {
                handler.handle_acl_stats().await?;
            }
        },
        SubCommand::PortForward(port_forward_args) => match &port_forward_args.sub_command {
            Some(PortForwardSubCommand::Add {
                protocol,
                bind_addr,
                dst_addr,
            }) => {
                handler
                    .handle_port_forward_modify(
                        ConfigPatchAction::Add,
                        protocol,
                        bind_addr,
                        Some(dst_addr),
                    )
                    .await?;
            }
            Some(PortForwardSubCommand::Remove {
                protocol,
                bind_addr,
                dst_addr,
            }) => {
                handler
                    .handle_port_forward_modify(
                        ConfigPatchAction::Remove,
                        protocol,
                        bind_addr,
                        dst_addr.as_deref(),
                    )
                    .await?;
            }
            Some(PortForwardSubCommand::List) | None => {
                handler.handle_port_forward_list().await?;
            }
        },
        SubCommand::Whitelist(whitelist_args) => match &whitelist_args.sub_command {
            Some(WhitelistSubCommand::SetTcp { ports }) => {
                handler.handle_whitelist_set_tcp(ports).await?;
            }
            Some(WhitelistSubCommand::SetUdp { ports }) => {
                handler.handle_whitelist_set_udp(ports).await?;
            }
            Some(WhitelistSubCommand::ClearTcp) => {
                handler.handle_whitelist_clear_tcp().await?;
            }
            Some(WhitelistSubCommand::ClearUdp) => {
                handler.handle_whitelist_clear_udp().await?;
            }
            Some(WhitelistSubCommand::Show) | None => {
                handler.handle_whitelist_show().await?;
            }
        },
        SubCommand::Stats(stats_args) => match &stats_args.sub_command {
            Some(StatsSubCommand::Show) | None => {
                handler.handle_stats_show().await?;
            }
            Some(StatsSubCommand::Prometheus) => {
                handler.handle_stats_prometheus().await?;
            }
        },
        SubCommand::Logger(logger_args) => match &logger_args.sub_command {
            Some(LoggerSubCommand::Get) | None => {
                handler.handle_logger_get().await?;
            }
            Some(LoggerSubCommand::Set { level }) => {
                handler.handle_logger_set(level).await?;
            }
        },
        SubCommand::Credential(credential_args) => match &credential_args.sub_command {
            CredentialSubCommand::Generate {
                ttl,
                credential_id,
                groups,
                allow_relay,
                allowed_proxy_cidrs,
                reusable,
            } => {
                handler
                    .handle_credential_generate(
                        *ttl,
                        credential_id.clone(),
                        groups.clone().unwrap_or_default(),
                        *allow_relay,
                        allowed_proxy_cidrs.clone().unwrap_or_default(),
                        *reusable,
                    )
                    .await?;
            }
            CredentialSubCommand::Revoke { credential_id } => {
                handler.handle_credential_revoke(credential_id).await?;
            }
            CredentialSubCommand::List => {
                handler.handle_credential_list().await?;
            }
        },
        SubCommand::GenAutocomplete { shell } => {
            let mut cmd = Cli::command();
            if let Some(shell) = shell.to_shell() {
                easytier::print_completions(shell, &mut cmd, "easytier-cli");
            } else {
                // Handle Nushell
                easytier::print_nushell_completions(&mut cmd, "easytier-cli");
            }
        }
    }

    Ok(())
}
