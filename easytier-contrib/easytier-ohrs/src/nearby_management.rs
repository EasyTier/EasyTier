//! HarmonyOS nearby transport for the canonical EasyTier management RPC surface.
//!
//! Cross-device payloads are native EasyTier `ZCPacket`s. The host-facing side
//! connects to a Unix-domain standalone RPC server owned by the process that
//! actually runs the EasyTier instance, so a VPN Extension never accidentally
//! exposes the empty `InstanceManager` loaded by `EntryAbility`.

use std::{
    collections::{HashMap, VecDeque},
    fmt, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::BytesMut;
use easytier::{common::config::NetworkConfigExt as _, instance::factory::NativeInstanceFactory};
use easytier_core::{
    management::{ConfigFileControl, ProcessManagementRpc, UnsupportedConfigFileStorage},
    packet::{PacketType, ZCPacket, ZCPacketType},
    rpc::{bidirect::BidirectRpcManager, client::Client, standalone::StandAloneServer},
    socket::{SocketListener, tcp::VirtualTcpSocket},
    tunnel::{SplitTunnel, Tunnel, tcp::TcpTunnelUpgrader},
};
use easytier_proto::{
    api::manage::{
        CollectNetworkInfoRequest, CollectNetworkInfoResponse, DeleteNetworkInstanceRequest,
        DeleteNetworkInstanceResponse, GetNetworkInstanceConfigRequest,
        GetNetworkInstanceConfigResponse, ListNetworkInstanceMetaRequest,
        ListNetworkInstanceMetaResponse, ListNetworkInstanceRequest, ListNetworkInstanceResponse,
        RetainNetworkInstanceRequest, RetainNetworkInstanceResponse, RunNetworkInstanceRequest,
        RunNetworkInstanceResponse, ValidateConfigRequest, ValidateConfigResponse,
        WebClientService, WebClientServiceClientFactory, WebClientServiceServer,
    },
    common::TunnelInfo,
    rpc_types::{controller::BaseController, error::Error as RpcError},
};
use futures::{SinkExt, StreamExt};
use napi_derive_ohos::napi;
use napi_ohos::bindgen_prelude::Uint8Array;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{UnixListener, UnixStream},
    sync::{
        mpsc::{Receiver, Sender, channel},
        oneshot,
    },
    task::JoinHandle,
    time::timeout,
};
use url::Url;
use uuid::Uuid;

use crate::{ASYNC_RUNTIME, INSTANCE_MANAGER, config::repository::config_root_dir};

const MAX_NEARBY_SESSIONS: usize = 8;
const MAX_SESSION_KEY_LENGTH: usize = 128;
const MAX_PACKET_BYTES: usize = 64 * 1024;
const MAX_JSON_PAYLOAD_BYTES: usize = 48 * 1024;
const MAX_DRAIN_PACKETS: usize = 32;
const PACKET_QUEUE_CAPACITY: usize = 64;
const RPC_PEER_ID: u32 = 1;
const RPC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(45);
const WEB_CLIENT_SERVICE_NAME: &str = "api.manage.WebClientService";
const MANAGEMENT_SOCKET_FILE_NAME: &str = "easytier-nearby-management.sock";
const MAX_PENDING_HOST_COMMANDS: usize = 8;
const HOST_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const HOST_COMMAND_START: &str = "start_once";
const HOST_COMMAND_STOP: &str = "stop";
const OHOS_PRIVATE_PACKET_TYPE: u8 = 0xF0;
const OHOS_PRIVATE_SCHEMA_VERSION: u32 = 1;
const MAX_OHOS_PRIVATE_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_OHOS_PRIVATE_ERROR_LENGTH: usize = 512;
const OHOS_OPERATION_GET_SETTINGS: &str = "get_settings";
const OHOS_OPERATION_UPDATE_SETTING: &str = "update_setting";

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct NearbyOhosEnvelope {
    schema_version: u32,
    kind: String,
    request_id: String,
    operation: String,
    payload_json: Option<String>,
    ok: Option<bool>,
    error: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NearbyHostCommand {
    pub request_id: String,
    pub operation: String,
    pub instance_id: String,
    pub config_json: Option<String>,
}

struct NearbyHostCommandState {
    queued: VecDeque<NearbyHostCommand>,
    completions: HashMap<String, oneshot::Sender<Result<(), String>>>,
}

static NEARBY_HOST_COMMANDS: once_cell::sync::Lazy<Mutex<NearbyHostCommandState>> =
    once_cell::sync::Lazy::new(|| {
        Mutex::new(NearbyHostCommandState {
            queued: VecDeque::new(),
            completions: HashMap::new(),
        })
    });

#[derive(Clone, Copy, PartialEq, Eq)]
enum NearbyRole {
    Client,
    HostProxy,
}

struct NearbyUnixSocket {
    stream: UnixStream,
}

impl NearbyUnixSocket {
    fn new(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl AsyncRead for NearbyUnixSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for NearbyUnixSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl VirtualTcpSocket for NearbyUnixSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)))
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2)))
    }

    fn transport_label(&self) -> Option<&str> {
        Some("unix")
    }
}

struct NearbyUnixListener {
    socket_path: PathBuf,
    listener: Option<UnixListener>,
}

impl NearbyUnixListener {
    fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            listener: None,
        }
    }
}

impl fmt::Debug for NearbyUnixListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NearbyUnixListener")
            .field("socket_path", &self.socket_path)
            .field("listening", &self.listener.is_some())
            .finish()
    }
}

#[async_trait]
impl SocketListener for NearbyUnixListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.listener.is_some() {
            return Ok(());
        }
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }
        let listener = UnixListener::bind(&self.socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))?;
        }
        self.listener = Some(listener);
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("nearby management listener is not started"))?;
        let (stream, _) = listener.accept().await?;
        let tunnel_info = TunnelInfo {
            tunnel_type: "unix".to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: None,
            resolved_remote_addr: None,
        };
        Ok(TcpTunnelUpgrader::new(tunnel_info).upgrade(NearbyUnixSocket::new(stream))?)
    }

    fn local_url(&self) -> Url {
        management_socket_url(&self.socket_path)
    }
}

impl Drop for NearbyUnixListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn dispatch_host_command(
    operation: &str,
    instance_id: Uuid,
    config_json: Option<String>,
) -> Result<(), RpcError> {
    let request_id = Uuid::new_v4().to_string();
    let command = NearbyHostCommand {
        request_id: request_id.clone(),
        operation: operation.to_owned(),
        instance_id: instance_id.to_string(),
        config_json,
    };
    let (sender, receiver) = oneshot::channel::<Result<(), String>>();
    {
        let mut state = NEARBY_HOST_COMMANDS
            .lock()
            .map_err(|_| anyhow::anyhow!("HarmonyOS host command queue is unavailable"))?;
        if state.queued.len() >= MAX_PENDING_HOST_COMMANDS
            || state.completions.len() >= MAX_PENDING_HOST_COMMANDS
        {
            return Err(anyhow::anyhow!("HarmonyOS host command queue is full").into());
        }
        state.completions.insert(request_id.clone(), sender);
        state.queued.push_back(command);
    }

    let completion = timeout(HOST_COMMAND_TIMEOUT, receiver).await;
    let timed_out = completion.is_err();
    if let Ok(mut state) = NEARBY_HOST_COMMANDS.lock() {
        state.completions.remove(&request_id);
        if timed_out {
            state
                .queued
                .retain(|command| command.request_id != request_id);
        }
    }
    match completion {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(anyhow::anyhow!(error).into()),
        Ok(Err(_)) => Err(anyhow::anyhow!("HarmonyOS host command was cancelled").into()),
        Err(_) => Err(anyhow::anyhow!("HarmonyOS host command timed out").into()),
    }
}

pub(crate) fn drain_nearby_host_commands() -> Vec<NearbyHostCommand> {
    NEARBY_HOST_COMMANDS
        .lock()
        .map(|mut state| state.queued.drain(..).collect())
        .unwrap_or_default()
}

pub(crate) fn complete_nearby_host_command(
    request_id: String,
    success: bool,
    error: Option<String>,
) -> bool {
    let sender = NEARBY_HOST_COMMANDS
        .lock()
        .ok()
        .and_then(|mut state| state.completions.remove(&request_id));
    let Some(sender) = sender else {
        return false;
    };
    let result = if success {
        Ok(())
    } else {
        Err(error
            .filter(|message| !message.trim().is_empty())
            .unwrap_or_else(|| "HarmonyOS host rejected the command".to_owned()))
    };
    sender.send(result).is_ok()
}

#[derive(Clone)]
struct NearbyWebClientService {
    inner: ProcessManagementRpc<NativeInstanceFactory>,
}

impl NearbyWebClientService {
    fn new() -> Self {
        Self {
            inner: ProcessManagementRpc::new(
                INSTANCE_MANAGER.clone(),
                Arc::new(()),
                Arc::new(UnsupportedConfigFileStorage),
            ),
        }
    }

    fn validate_one_shot_start(
        &self,
        request: &RunNetworkInstanceRequest,
    ) -> Result<(Uuid, String), RpcError> {
        if request.overwrite {
            return Err(anyhow::anyhow!(
                "HarmonyOS nearby deployment is one-shot and never overwrites a running config"
            )
            .into());
        }
        let requested_id = request.inst_id.map(Uuid::from).ok_or_else(|| {
            anyhow::anyhow!("HarmonyOS nearby deployment requires an instance ID")
        })?;
        let config = request
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HarmonyOS nearby deployment requires a config"))?;
        config.gen_config()?;
        let config_id = config
            .instance_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("HarmonyOS nearby config has no instance ID"))?;
        let parsed_config_id = Uuid::parse_str(config_id)
            .map_err(|_| anyhow::anyhow!("HarmonyOS nearby config instance ID is invalid"))?;
        if parsed_config_id != requested_id {
            return Err(anyhow::anyhow!(
                "HarmonyOS nearby config instance ID does not match the request"
            )
            .into());
        }
        if !INSTANCE_MANAGER.instance_ids().is_empty() {
            return Err(anyhow::anyhow!(
                "HarmonyOS config is running; stop it before deploying another config"
            )
            .into());
        }
        let config_json = serde_json::to_string(config).map_err(|error| {
            anyhow::anyhow!("failed to encode HarmonyOS one-shot config: {error}")
        })?;
        Ok((requested_id, config_json))
    }
}

#[async_trait]
impl WebClientService for NearbyWebClientService {
    type Controller = BaseController;

    async fn validate_config(
        &self,
        _controller: BaseController,
        _request: ValidateConfigRequest,
    ) -> Result<ValidateConfigResponse, RpcError> {
        Err(anyhow::anyhow!("nearby management does not export or validate remote configs").into())
    }

    async fn run_network_instance(
        &self,
        _controller: BaseController,
        request: RunNetworkInstanceRequest,
    ) -> Result<RunNetworkInstanceResponse, RpcError> {
        let (instance_id, config_json) = self.validate_one_shot_start(&request)?;
        dispatch_host_command(HOST_COMMAND_START, instance_id, Some(config_json)).await?;
        if !INSTANCE_MANAGER.instance_ids().contains(&instance_id) {
            return Err(anyhow::anyhow!(
                "HarmonyOS host reported success but the instance is not running"
            )
            .into());
        }
        Ok(RunNetworkInstanceResponse {
            inst_id: Some(instance_id.into()),
        })
    }

    async fn retain_network_instance(
        &self,
        _controller: BaseController,
        _request: RetainNetworkInstanceRequest,
    ) -> Result<RetainNetworkInstanceResponse, RpcError> {
        Err(anyhow::anyhow!("nearby management cannot retain or remove HarmonyOS instances").into())
    }

    async fn collect_network_info(
        &self,
        controller: BaseController,
        request: CollectNetworkInfoRequest,
    ) -> Result<CollectNetworkInfoResponse, RpcError> {
        self.inner.collect_network_info(controller, request).await
    }

    async fn list_network_instance(
        &self,
        controller: BaseController,
        request: ListNetworkInstanceRequest,
    ) -> Result<ListNetworkInstanceResponse, RpcError> {
        self.inner.list_network_instance(controller, request).await
    }

    async fn delete_network_instance(
        &self,
        _controller: BaseController,
        request: DeleteNetworkInstanceRequest,
    ) -> Result<DeleteNetworkInstanceResponse, RpcError> {
        if request.inst_ids.len() != 1 {
            return Err(anyhow::anyhow!(
                "HarmonyOS nearby control stops exactly one running instance"
            )
            .into());
        }
        let instance_id = Uuid::from(request.inst_ids[0]);
        let running = INSTANCE_MANAGER.instance_ids();
        if running.is_empty() {
            return Ok(DeleteNetworkInstanceResponse {
                remain_inst_ids: Vec::new(),
            });
        }
        if running.len() != 1 || running[0] != instance_id {
            return Err(anyhow::anyhow!(
                "requested HarmonyOS instance is not the active controlled instance"
            )
            .into());
        }
        dispatch_host_command(HOST_COMMAND_STOP, instance_id, None).await?;
        let remaining = INSTANCE_MANAGER.instance_ids();
        if remaining.contains(&instance_id) {
            return Err(anyhow::anyhow!(
                "HarmonyOS host reported success but the instance is still running"
            )
            .into());
        }
        Ok(DeleteNetworkInstanceResponse {
            remain_inst_ids: remaining.into_iter().map(Into::into).collect(),
        })
    }

    async fn get_network_instance_config(
        &self,
        _controller: BaseController,
        _request: GetNetworkInstanceConfigRequest,
    ) -> Result<GetNetworkInstanceConfigResponse, RpcError> {
        Err(anyhow::anyhow!("nearby management does not export remote configs").into())
    }

    async fn list_network_instance_meta(
        &self,
        controller: BaseController,
        request: ListNetworkInstanceMetaRequest,
    ) -> Result<ListNetworkInstanceMetaResponse, RpcError> {
        self.inner
            .list_network_instance_meta(controller, request)
            .await
    }
}

struct NearbyManagementHostServer {
    socket_path: PathBuf,
    _server: StandAloneServer<NearbyUnixListener>,
}

static NEARBY_HOST_SERVER: once_cell::sync::Lazy<Mutex<Option<NearbyManagementHostServer>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

pub(crate) fn runtime_management_config_control(_instance_id: Uuid) -> ConfigFileControl {
    ConfigFileControl::STATIC_CONFIG
}

pub(crate) fn ensure_runtime_management_server_started() -> bool {
    let Some(socket_path) = management_socket_path() else {
        ohrs_log_error!("[Rust] nearby management config store is not initialized");
        return false;
    };
    let Ok(mut state) = NEARBY_HOST_SERVER.lock() else {
        return false;
    };
    if state
        .as_ref()
        .is_some_and(|server| server.socket_path == socket_path && socket_path.exists())
    {
        return true;
    }
    state.take();

    let mut server = StandAloneServer::new(NearbyUnixListener::new(socket_path.clone()));
    server.registry().register(
        WebClientServiceServer::new(NearbyWebClientService::new()),
        "",
    );
    if let Err(error) = ASYNC_RUNTIME.block_on(server.serve()) {
        ohrs_log_error!("[Rust] nearby management server failed to start: {}", error);
        return false;
    }
    *state = Some(NearbyManagementHostServer {
        socket_path,
        _server: server,
    });
    true
}

pub(crate) fn stop_runtime_management_server() -> bool {
    let stopped = NEARBY_HOST_SERVER
        .lock()
        .map(|mut state| state.take().is_some())
        .unwrap_or(false);
    if let Ok(mut commands) = NEARBY_HOST_COMMANDS.lock() {
        commands.queued.clear();
        for (_, sender) in commands.completions.drain() {
            let _ = sender.send(Err("HarmonyOS nearby management host stopped".to_owned()));
        }
    }
    shutdown_all_sessions();
    stopped
}

struct NearbyManagementSession {
    role: NearbyRole,
    rpc: Option<Arc<BidirectRpcManager>>,
    inbound: Mutex<Option<Sender<Vec<u8>>>>,
    outbound: Mutex<Receiver<Vec<u8>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    closed: AtomicBool,
}

impl NearbyManagementSession {
    fn client() -> Self {
        // Synchronous NAPI calls arrive outside Tokio's runtime context.
        let _runtime_guard = ASYNC_RUNTIME.enter();
        let rpc = Arc::new(BidirectRpcManager::new().set_rx_timeout(Some(RPC_RESPONSE_TIMEOUT)));
        let tunnel = rpc.run_and_create_tunnel();
        Self::from_split(NearbyRole::Client, Some(rpc), tunnel.split())
    }

    fn host_proxy() -> anyhow::Result<Self> {
        let socket_path = management_socket_path()
            .ok_or_else(|| anyhow::anyhow!("HarmonyOS config store is not initialized"))?;
        let stream = ASYNC_RUNTIME.block_on(UnixStream::connect(&socket_path))?;
        let tunnel_info = TunnelInfo {
            tunnel_type: "unix".to_owned(),
            local_addr: None,
            remote_addr: Some(management_socket_url(&socket_path).into()),
            resolved_remote_addr: None,
        };
        let tunnel = TcpTunnelUpgrader::new(tunnel_info).upgrade(NearbyUnixSocket::new(stream))?;
        Ok(Self::from_split(
            NearbyRole::HostProxy,
            None,
            tunnel.split(),
        ))
    }

    fn from_split(
        role: NearbyRole,
        rpc: Option<Arc<BidirectRpcManager>>,
        split: SplitTunnel,
    ) -> Self {
        let (mut bridge_stream, mut bridge_sink) = split;
        let (inbound_tx, mut inbound_rx) = channel::<Vec<u8>>(PACKET_QUEUE_CAPACITY);
        let (outbound_tx, outbound_rx) = channel::<Vec<u8>>(PACKET_QUEUE_CAPACITY);

        let inbound_task = ASYNC_RUNTIME.spawn(async move {
            while let Some(bytes) = inbound_rx.recv().await {
                let packet = ZCPacket::new_from_buf(
                    BytesMut::from(bytes.as_slice()),
                    ZCPacketType::DummyTunnel,
                );
                if bridge_sink.send(packet).await.is_err() {
                    break;
                }
            }
            let _ = bridge_sink.close().await;
        });
        let outbound_task = ASYNC_RUNTIME.spawn(async move {
            while let Some(result) = bridge_stream.next().await {
                let Ok(packet) = result else {
                    break;
                };
                let bytes = packet
                    .convert_type(ZCPacketType::DummyTunnel)
                    .into_bytes()
                    .to_vec();
                if outbound_tx.send(bytes).await.is_err() {
                    break;
                }
            }
        });

        Self {
            role,
            rpc,
            inbound: Mutex::new(Some(inbound_tx)),
            outbound: Mutex::new(outbound_rx),
            tasks: Mutex::new(vec![inbound_task, outbound_task]),
            closed: AtomicBool::new(false),
        }
    }

    fn push_packet(&self, bytes: Vec<u8>) -> bool {
        if self.closed.load(Ordering::Acquire) || !valid_rpc_packet_bytes(&bytes) {
            return false;
        }
        self.inbound
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().cloned())
            .is_some_and(|sender| sender.try_send(bytes).is_ok())
    }

    fn drain_packets(&self) -> Vec<Uint8Array> {
        let Ok(mut receiver) = self.outbound.lock() else {
            return Vec::new();
        };
        let mut packets = Vec::new();
        while packets.len() < MAX_DRAIN_PACKETS {
            match receiver.try_recv() {
                Ok(packet) => packets.push(Uint8Array::from(packet)),
                Err(_) => break,
            }
        }
        packets
    }

    async fn call_json(
        &self,
        service_name: &str,
        method_name: &str,
        domain_name: &str,
        payload: Value,
    ) -> Result<Value, RpcError> {
        if self.role != NearbyRole::Client {
            return Err(RpcError::ExecutionError(anyhow::anyhow!(
                "nearby host proxy sessions cannot originate management calls"
            )));
        }
        let rpc = self.rpc.as_ref().ok_or_else(|| {
            RpcError::ExecutionError(anyhow::anyhow!("nearby RPC client is unavailable"))
        })?;
        call_official_management_json_rpc(
            rpc.rpc_client(),
            service_name,
            method_name,
            domain_name,
            payload,
        )
        .await
    }

    fn shutdown(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(mut inbound) = self.inbound.lock() {
            inbound.take();
        }
        if let Ok(mut tasks) = self.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        if let Some(rpc) = self.rpc.clone() {
            ASYNC_RUNTIME.spawn(async move {
                rpc.stop().await;
            });
        }
    }
}

impl Drop for NearbyManagementSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}

static NEARBY_SESSIONS: once_cell::sync::Lazy<
    Mutex<HashMap<String, Arc<NearbyManagementSession>>>,
> = once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

fn management_socket_path() -> Option<PathBuf> {
    config_root_dir().map(|root| root.join(MANAGEMENT_SOCKET_FILE_NAME))
}

fn management_socket_url(path: &Path) -> Url {
    format!("unix://{}", path.display())
        .parse()
        .expect("HarmonyOS sandbox path must form a Unix URL")
}

fn valid_session_key(session_key: &str) -> bool {
    !session_key.is_empty()
        && session_key.len() <= MAX_SESSION_KEY_LENGTH
        && session_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

fn valid_rpc_packet_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
        return false;
    }
    let packet = ZCPacket::new_from_buf(BytesMut::from(bytes), ZCPacketType::DummyTunnel);
    let Some(header) = packet.peer_manager_header() else {
        return false;
    };
    header.from_peer_id.get() == RPC_PEER_ID
        && header.to_peer_id.get() == RPC_PEER_ID
        && matches!(
            header.packet_type,
            value if value == PacketType::RpcReq as u8 || value == PacketType::RpcResp as u8
        )
}

fn validate_ohos_envelope(envelope: &NearbyOhosEnvelope) -> anyhow::Result<()> {
    if envelope.schema_version != OHOS_PRIVATE_SCHEMA_VERSION {
        anyhow::bail!("unsupported HarmonyOS private packet schema");
    }
    Uuid::parse_str(&envelope.request_id)
        .map_err(|_| anyhow::anyhow!("invalid HarmonyOS private request ID"))?;
    if !matches!(
        envelope.operation.as_str(),
        OHOS_OPERATION_GET_SETTINGS | OHOS_OPERATION_UPDATE_SETTING
    ) {
        anyhow::bail!("unsupported HarmonyOS private operation");
    }
    if !matches!(envelope.kind.as_str(), "request" | "response") {
        anyhow::bail!("invalid HarmonyOS private packet kind");
    }
    if envelope.kind == "request" && envelope.ok.is_some() {
        anyhow::bail!("HarmonyOS private request cannot carry a result state");
    }
    if envelope.kind == "response" && envelope.ok.is_none() {
        anyhow::bail!("HarmonyOS private response must carry a result state");
    }
    if envelope
        .payload_json
        .as_ref()
        .is_some_and(|payload| payload.len() > MAX_OHOS_PRIVATE_PAYLOAD_BYTES)
    {
        anyhow::bail!("HarmonyOS private payload is too large");
    }
    if envelope
        .error
        .as_ref()
        .is_some_and(|error| error.len() > MAX_OHOS_PRIVATE_ERROR_LENGTH)
    {
        anyhow::bail!("HarmonyOS private error is too large");
    }
    Ok(())
}

fn decode_ohos_envelope(bytes: &[u8]) -> anyhow::Result<NearbyOhosEnvelope> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
        anyhow::bail!("HarmonyOS private packet size is invalid");
    }
    let packet = ZCPacket::new_from_buf(BytesMut::from(bytes), ZCPacketType::DummyTunnel);
    let header = packet
        .peer_manager_header()
        .ok_or_else(|| anyhow::anyhow!("HarmonyOS private packet header is missing"))?;
    if header.packet_type != OHOS_PRIVATE_PACKET_TYPE {
        anyhow::bail!("packet is not a HarmonyOS private packet");
    }
    if header.from_peer_id.get() != RPC_PEER_ID || header.to_peer_id.get() != RPC_PEER_ID {
        anyhow::bail!("HarmonyOS private packet peer ID is invalid");
    }
    let envelope = serde_json::from_slice::<NearbyOhosEnvelope>(packet.payload())?;
    validate_ohos_envelope(&envelope)?;
    Ok(envelope)
}

pub(crate) fn nearby_management_packet_kind(packet: Uint8Array) -> i32 {
    let bytes = packet.to_vec();
    if valid_rpc_packet_bytes(&bytes) {
        return 1;
    }
    if decode_ohos_envelope(&bytes).is_ok() {
        return 2;
    }
    0
}

pub(crate) fn encode_nearby_ohos_packet(envelope_json: String) -> Option<Uint8Array> {
    let envelope = serde_json::from_str::<NearbyOhosEnvelope>(&envelope_json).ok()?;
    validate_ohos_envelope(&envelope).ok()?;
    let payload = serde_json::to_vec(&envelope).ok()?;
    if payload.len() > MAX_OHOS_PRIVATE_PAYLOAD_BYTES {
        return None;
    }
    let mut packet = ZCPacket::new_with_payload(&payload);
    packet.fill_peer_manager_hdr(RPC_PEER_ID, RPC_PEER_ID, OHOS_PRIVATE_PACKET_TYPE);
    Some(Uint8Array::from(
        packet
            .convert_type(ZCPacketType::DummyTunnel)
            .into_bytes()
            .to_vec(),
    ))
}

pub(crate) fn decode_nearby_ohos_packet(packet: Uint8Array) -> Option<String> {
    let envelope = decode_ohos_envelope(&packet).ok()?;
    serde_json::to_string(&envelope).ok()
}

fn session(session_key: &str) -> Option<Arc<NearbyManagementSession>> {
    NEARBY_SESSIONS
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(session_key).cloned())
}

fn open_session(session_key: String, role: NearbyRole) -> bool {
    if !valid_session_key(&session_key) {
        return false;
    }
    {
        let Ok(sessions) = NEARBY_SESSIONS.lock() else {
            return false;
        };
        if sessions.contains_key(&session_key) || sessions.len() >= MAX_NEARBY_SESSIONS {
            return false;
        }
    }
    let session = match role {
        NearbyRole::Client => NearbyManagementSession::client(),
        NearbyRole::HostProxy => match NearbyManagementSession::host_proxy() {
            Ok(session) => session,
            Err(error) => {
                ohrs_log_error!("[Rust] nearby management host proxy failed: {}", error);
                return false;
            }
        },
    };
    let Ok(mut sessions) = NEARBY_SESSIONS.lock() else {
        session.shutdown();
        return false;
    };
    if sessions.contains_key(&session_key) || sessions.len() >= MAX_NEARBY_SESSIONS {
        session.shutdown();
        return false;
    }
    sessions.insert(session_key, Arc::new(session));
    true
}

fn shutdown_all_sessions() {
    let sessions = NEARBY_SESSIONS
        .lock()
        .map(|mut sessions| {
            sessions
                .drain()
                .map(|(_, session)| session)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for session in sessions {
        session.shutdown();
    }
}

pub(crate) fn open_nearby_management_session(session_key: String, host: bool) -> bool {
    open_session(
        session_key,
        if host {
            NearbyRole::HostProxy
        } else {
            NearbyRole::Client
        },
    )
}

pub(crate) fn close_nearby_management_session(session_key: String) -> bool {
    let removed = NEARBY_SESSIONS
        .lock()
        .ok()
        .and_then(|mut sessions| sessions.remove(&session_key));
    if let Some(session) = removed {
        session.shutdown();
        true
    } else {
        false
    }
}

pub(crate) fn push_nearby_management_packet(session_key: String, packet: Uint8Array) -> bool {
    session(&session_key).is_some_and(|session| session.push_packet(packet.to_vec()))
}

pub(crate) fn drain_nearby_management_packets(session_key: String) -> Vec<Uint8Array> {
    session(&session_key)
        .map(|session| session.drain_packets())
        .unwrap_or_default()
}

pub(crate) async fn call_nearby_management_json_rpc(
    session_key: String,
    service_name: String,
    method_name: String,
    domain_name: Option<String>,
    payload_json: String,
) -> String {
    if payload_json.len() > MAX_JSON_PAYLOAD_BYTES {
        return json!({ "ok": false, "error": "management payload is too large" }).to_string();
    }
    let Some(session) = session(&session_key) else {
        return json!({ "ok": false, "error": "nearby management session not found" }).to_string();
    };
    let payload = match serde_json::from_str::<Value>(&payload_json) {
        Ok(payload) => payload,
        Err(error) => {
            return json!({ "ok": false, "error": format!("invalid management JSON: {error}") })
                .to_string();
        }
    };
    match session
        .call_json(
            service_name.trim(),
            method_name.trim(),
            domain_name.as_deref().unwrap_or_default().trim(),
            payload,
        )
        .await
    {
        Ok(result) => json!({ "ok": true, "result": result }).to_string(),
        Err(error) => json!({ "ok": false, "error": error.to_string() }).to_string(),
    }
}

async fn call_official_management_json_rpc(
    client: &Client,
    service_name: &str,
    method_name: &str,
    domain_name: &str,
    payload: Value,
) -> Result<Value, RpcError> {
    if !valid_management_json_call(service_name, method_name, domain_name) {
        return Err(RpcError::InvalidServiceKey(
            service_name.to_owned(),
            method_name.to_owned(),
        ));
    }
    let controller = BaseController::default();
    client
        .scoped_client::<WebClientServiceClientFactory<BaseController>>(
            RPC_PEER_ID,
            RPC_PEER_ID,
            String::new(),
        )
        .json_call_method(controller, method_name, payload)
        .await
}

fn valid_management_json_call(service_name: &str, method_name: &str, domain_name: &str) -> bool {
    service_name == WEB_CLIENT_SERVICE_NAME
        && domain_name.is_empty()
        && matches!(
            method_name,
            "ListNetworkInstance"
                | "ListNetworkInstanceMeta"
                | "CollectNetworkInfo"
                | "RunNetworkInstance"
                | "DeleteNetworkInstance"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_rpc_packets_before_the_harmony_transport() {
        assert!(!valid_rpc_packet_bytes(&[]));
        assert!(!valid_rpc_packet_bytes(&[1, 2, 3]));
        assert!(!valid_session_key("contains space"));
        assert!(valid_session_key("42:client"));

        let mut valid = ZCPacket::new_with_payload(&[]);
        valid.fill_peer_manager_hdr(RPC_PEER_ID, RPC_PEER_ID, PacketType::RpcReq as u8);
        let expected_wire = valid.tunnel_payload().to_vec();
        let valid_bytes = valid
            .convert_type(ZCPacketType::DummyTunnel)
            .into_bytes()
            .to_vec();
        assert_eq!(valid_bytes, expected_wire);
        assert!(valid_rpc_packet_bytes(&valid_bytes));

        let mut wrong_peer = ZCPacket::new_with_payload(&[]);
        wrong_peer.fill_peer_manager_hdr(2, RPC_PEER_ID, PacketType::RpcReq as u8);
        let wrong_peer_bytes = wrong_peer
            .convert_type(ZCPacketType::DummyTunnel)
            .into_bytes()
            .to_vec();
        assert!(!valid_rpc_packet_bytes(&wrong_peer_bytes));
    }

    #[test]
    fn nearby_wire_round_trips_as_dummy_tunnel() {
        let payload = b"management rpc";
        let mut source = ZCPacket::new_with_payload(payload);
        source.fill_peer_manager_hdr(RPC_PEER_ID, RPC_PEER_ID, PacketType::RpcResp as u8);
        let expected_wire = source.tunnel_payload().to_vec();

        let wire = source
            .convert_type(ZCPacketType::DummyTunnel)
            .into_bytes()
            .to_vec();
        assert_eq!(wire, expected_wire);

        let decoded =
            ZCPacket::new_from_buf(BytesMut::from(wire.as_slice()), ZCPacketType::DummyTunnel);
        assert_eq!(decoded.tunnel_payload(), expected_wire);
        assert_eq!(decoded.payload(), payload);
    }

    #[test]
    fn only_allows_the_nearby_web_client_surface() {
        assert!(valid_management_json_call(
            WEB_CLIENT_SERVICE_NAME,
            "CollectNetworkInfo",
            ""
        ));
        assert!(!valid_management_json_call(
            WEB_CLIENT_SERVICE_NAME,
            "RetainNetworkInstance",
            ""
        ));
        assert!(!valid_management_json_call(
            WEB_CLIENT_SERVICE_NAME,
            "GetNetworkInstanceConfig",
            ""
        ));
        assert!(!valid_management_json_call(
            "api.logger.LoggerRpcService",
            "GetLoggerConfig",
            ""
        ));
        assert!(!valid_management_json_call(
            WEB_CLIENT_SERVICE_NAME,
            "CollectNetworkInfo",
            "unexpected-domain"
        ));
    }

    #[test]
    fn ohos_private_settings_packet_round_trips_as_zcpacket() {
        let request_id = Uuid::new_v4().to_string();
        let raw = json!({
            "schemaVersion": OHOS_PRIVATE_SCHEMA_VERSION,
            "kind": "request",
            "requestId": request_id,
            "operation": OHOS_OPERATION_GET_SETTINGS,
        })
        .to_string();
        let encoded = encode_nearby_ohos_packet(raw).expect("private packet must encode");
        let bytes = encoded.to_vec();
        assert_eq!(
            nearby_management_packet_kind(Uint8Array::from(bytes.clone())),
            2
        );
        let decoded =
            decode_nearby_ohos_packet(Uint8Array::from(bytes)).expect("private packet must decode");
        let envelope: NearbyOhosEnvelope = serde_json::from_str(&decoded).unwrap();
        assert_eq!(envelope.request_id, request_id);
        assert_eq!(envelope.operation, OHOS_OPERATION_GET_SETTINGS);
    }

    #[test]
    fn one_shot_runtime_has_no_persistent_config_path() {
        let control = runtime_management_config_control(Uuid::new_v4());
        assert!(control.path.is_none());
        assert!(control.is_read_only());
        assert!(control.is_no_delete());
    }
}
