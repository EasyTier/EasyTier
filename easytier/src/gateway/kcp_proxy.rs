use std::{
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex, Weak},
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use dashmap::DashMap;
use guarden::defer;
use kcp_sys::{
    endpoint::{ConnId, KcpEndpoint, KcpPacketReceiver},
    ffi_safe::KcpConfig,
    packet_def::KcpPacket,
    stream::KcpStream,
};
use prost::Message;
use tokio::{
    sync::Mutex,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use easytier_core::{
    proxy::wrapped_transport::{
        WrappedTransportConnect, WrappedTransportDatagram, WrappedTransportDatagramBuffer,
        WrappedTransportEngine, WrappedTransportEngineStart, WrappedTransportKind,
        WrappedTransportRole,
    },
    proxy::{
        cidr_table::ProxyCidrTable,
        runtime::{TcpProxyDestinationConnector, TcpProxyStream},
        tcp_proxy_engine::TcpProxyMode,
        wrapped_tcp_proxy::{WrappedTcpDestinationRequest, plan_wrapped_tcp_destination},
    },
};

use super::{RuntimeWrappedTcpDestinationAdapter, tcp_proxy::NatDstTcpConnector};
use crate::utils::task::HedgeExt;
use crate::{
    common::{error::Result, global_ctx::ArcGlobalCtx},
    peers::peer_manager::PeerManager,
    proto::{
        api::instance::{
            ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
            TcpProxyEntryTransportType, TcpProxyRpc,
        },
        peer_rpc::KcpConnData,
        rpc_types::{self, controller::BaseController},
    },
};

fn create_kcp_endpoint() -> KcpEndpoint {
    let mut kcp_endpoint = KcpEndpoint::new();
    kcp_endpoint.set_kcp_config_factory(Box::new(|conv| {
        let mut cfg = KcpConfig::new_turbo(conv);
        cfg.interval = Some(5);
        cfg
    }));
    kcp_endpoint
}

#[tracing::instrument]
async fn handle_kcp_output(
    mut output_receiver: KcpPacketReceiver,
    role: WrappedTransportRole,
    datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
) {
    while let Some(packet) = output_receiver.recv().await {
        let peer_id = match role {
            WrappedTransportRole::Source => packet.header().dst_session_id(),
            WrappedTransportRole::Destination => packet.header().src_session_id(),
        };
        if datagrams
            .send(WrappedTransportDatagram {
                transport: WrappedTransportKind::Kcp,
                role,
                peer_id,
                buffer: WrappedTransportDatagramBuffer::copy_from_payload(&packet.inner().freeze()),
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

#[derive(Debug, Clone)]
pub struct NatDstKcpConnector {
    pub(crate) kcp_endpoint: Arc<KcpEndpoint>,
    pub(crate) peer_mgr: Weak<PeerManager>,
}

async fn connect_kcp_source(
    kcp_endpoint: Arc<KcpEndpoint>,
    my_peer_id: u32,
    dst_peer_id: u32,
    src: SocketAddr,
    dst: SocketAddr,
) -> anyhow::Result<KcpStream> {
    let conn_data = KcpConnData {
        src: Some(src.into()),
        dst: Some(dst.into()),
    };

    (0..5)
        .map(|_| {
            let kcp_endpoint = kcp_endpoint.clone();
            let conn_data = conn_data.clone();
            async move {
                let conn_id = kcp_endpoint
                    .connect(
                        Duration::from_secs(10),
                        my_peer_id,
                        dst_peer_id,
                        Bytes::from(conn_data.encode_to_vec()),
                    )
                    .await?;

                KcpStream::new(&kcp_endpoint, conn_id).context("failed to create kcp stream")
            }
        })
        .hedge(Duration::from_millis(200))
        .await
        .context("failed to connect to peer")
}

#[async_trait::async_trait]
impl TcpProxyDestinationConnector for NatDstKcpConnector {
    type DstStream = KcpStream;

    async fn connect(
        &self,
        src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> anyhow::Result<Self::DstStream> {
        let peer_mgr = self
            .peer_mgr
            .upgrade()
            .ok_or_else(|| anyhow!("peer manager is not available"))?;

        let dst_peer = {
            let SocketAddr::V4(addr) = nat_dst else {
                bail!("ipv6 is not supported");
            };
            peer_mgr
                .core()
                .get_peer_map()
                .get_peer_id_by_ipv4(addr.ip())
                .await
                .ok_or_else(|| anyhow!("no peer found for nat dst: {}", nat_dst))?
        };

        tracing::trace!(?nat_dst, ?dst_peer, "kcp nat");
        connect_kcp_source(
            self.kcp_endpoint.clone(),
            peer_mgr.my_peer_id(),
            dst_peer,
            src,
            nat_dst,
        )
        .await
    }

    fn proxy_mode(&self) -> TcpProxyMode {
        TcpProxyMode::KcpSrc
    }
}

pub struct KcpProxySrc {
    kcp_endpoint: Arc<KcpEndpoint>,
    tasks: JoinSet<()>,
}

impl KcpProxySrc {
    pub async fn new(datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>) -> Self {
        let mut kcp_endpoint = create_kcp_endpoint();
        kcp_endpoint.run().await;

        let output_receiver = kcp_endpoint.output_receiver().unwrap();
        let mut tasks = JoinSet::new();

        tasks.spawn(handle_kcp_output(
            output_receiver,
            WrappedTransportRole::Source,
            datagrams,
        ));

        let kcp_endpoint = Arc::new(kcp_endpoint);

        Self {
            kcp_endpoint,
            tasks,
        }
    }

    pub fn get_kcp_endpoint(&self) -> Arc<KcpEndpoint> {
        self.kcp_endpoint.clone()
    }

    async fn stop(&mut self) {
        self.tasks.shutdown().await;
    }
}

pub struct KcpProxyDst {
    kcp_endpoint: Arc<KcpEndpoint>,
    peer_manager: Arc<PeerManager>,
    proxy_entries: Arc<DashMap<ConnId, TcpProxyEntry>>,
    cidr_table: Arc<ProxyCidrTable>,
    tasks: JoinSet<()>,
    accept_cancel: CancellationToken,
    accept_task: Option<JoinHandle<()>>,
}

impl KcpProxyDst {
    pub async fn new(
        peer_manager: Arc<PeerManager>,
        cidr_table: Arc<ProxyCidrTable>,
        datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
    ) -> Self {
        let mut kcp_endpoint = create_kcp_endpoint();
        kcp_endpoint.run().await;

        let mut tasks = JoinSet::new();
        let output_receiver = kcp_endpoint.output_receiver().unwrap();
        tasks.spawn(handle_kcp_output(
            output_receiver,
            WrappedTransportRole::Destination,
            datagrams,
        ));
        Self {
            kcp_endpoint: Arc::new(kcp_endpoint),
            peer_manager,
            proxy_entries: Arc::new(DashMap::new()),
            cidr_table,
            tasks,
            accept_cancel: CancellationToken::new(),
            accept_task: None,
        }
    }

    #[tracing::instrument(ret, skip(route, runtime, acl_filter))]
    async fn handle_one_in_stream(
        kcp_stream: KcpStream,
        global_ctx: ArcGlobalCtx,
        proxy_entries: Arc<DashMap<ConnId, TcpProxyEntry>>,
        cidr_table: Arc<ProxyCidrTable>,
        runtime: Arc<RuntimeWrappedTcpDestinationAdapter>,
        acl_filter: Arc<easytier_core::peers::acl_filter::AclFilter>,
        route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
    ) -> Result<()> {
        let mut conn_data = kcp_stream.conn_data().clone();
        let parsed_conn_data = KcpConnData::decode(&mut conn_data)
            .with_context(|| format!("failed to decode kcp conn data: {:?}", conn_data))?;
        let dst_socket: SocketAddr = parsed_conn_data
            .dst
            .ok_or(anyhow::anyhow!(
                "failed to get dst socket from kcp conn data: {:?}",
                parsed_conn_data
            ))?
            .into();
        let src_socket: SocketAddr = parsed_conn_data.src.unwrap_or_default().into();

        let conn_id = kcp_stream.conn_id();
        proxy_entries.insert(
            conn_id,
            TcpProxyEntry {
                src: parsed_conn_data.src,
                dst: parsed_conn_data.dst,
                start_time: chrono::Local::now().timestamp() as u64,
                state: TcpProxyEntryState::ConnectingDst.into(),
                transport_type: TcpProxyEntryTransportType::Kcp.into(),
            },
        );
        defer! {
            proxy_entries.remove(&conn_id);
            if proxy_entries.capacity() - proxy_entries.len() > 16 {
                proxy_entries.shrink_to_fit();
            }
        }

        let plan = plan_wrapped_tcp_destination(
            WrappedTcpDestinationRequest {
                src: src_socket,
                dst: dst_socket,
                initial_payload: &conn_data,
            },
            cidr_table.as_ref(),
            runtime.as_ref(),
            route.as_ref(),
            acl_filter,
        )
        .await?;
        let dst_socket = plan.socket_dst;
        let acl_handler = plan.acl_handler;

        tracing::debug!("kcp connect to dst socket: {:?}", dst_socket);

        let connector = NatDstTcpConnector::new(crate::connector::runtime::runtime_connector_host(
            global_ctx.clone(),
        ));
        let ret = connector
            .connect("0.0.0.0:0".parse().unwrap(), dst_socket)
            .await?;

        if let Some(mut e) = proxy_entries.get_mut(&kcp_stream.conn_id()) {
            e.state = TcpProxyEntryState::Connected.into();
        }

        acl_handler
            .copy_bidirection_with_acl(kcp_stream, ret)
            .await?;

        Ok(())
    }

    async fn run_accept_task(&mut self) {
        let kcp_endpoint = self.kcp_endpoint.clone();
        let global_ctx = self.peer_manager.get_global_ctx();
        let proxy_entries = self.proxy_entries.clone();
        let cidr_table = self.cidr_table.clone();
        let route = self.peer_manager.core().get_route();
        let runtime = Arc::new(RuntimeWrappedTcpDestinationAdapter::new(global_ctx.clone()));
        let acl_filter = self.peer_manager.core().acl_filter();
        let cancel = self.accept_cancel.clone();
        self.accept_task = Some(tokio::spawn(async move {
            let mut streams = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        streams.shutdown().await;
                        break;
                    }
                    accepted = kcp_endpoint.accept() => {
                        let Ok(conn) = accepted else {
                            streams.shutdown().await;
                            break;
                        };
                        let Some(stream) = KcpStream::new(&kcp_endpoint, conn) else {
                            tracing::warn!("failed to create accepted kcp stream");
                            continue;
                        };

                        let global_ctx = global_ctx.clone();
                        let proxy_entries = proxy_entries.clone();
                        let cidr_table = cidr_table.clone();
                        let route = route.clone();
                        let runtime = runtime.clone();
                        let acl_filter = acl_filter.clone();
                        streams.spawn(async move {
                            let _ = Self::handle_one_in_stream(
                                stream,
                                global_ctx,
                                proxy_entries,
                                cidr_table,
                                runtime,
                                acl_filter,
                                route,
                            )
                            .await;
                        });
                    }
                    _ = streams.join_next(), if !streams.is_empty() => {}
                }
            }
        }));
    }

    pub async fn start(&mut self) {
        self.run_accept_task().await;
    }

    async fn stop(&mut self) {
        self.accept_cancel.cancel();
        if let Some(task) = self.accept_task.as_mut() {
            let _ = task.await;
        }
        self.accept_task.take();
        self.tasks.shutdown().await;
    }
}

#[derive(Default)]
struct KcpProxyServiceState {
    src: Option<KcpProxySrc>,
    dst: Option<KcpProxyDst>,
}

impl KcpProxyServiceState {
    async fn stop(&mut self) {
        if let Some(dst) = &mut self.dst {
            dst.stop().await;
        }
        if let Some(src) = &mut self.src {
            src.stop().await;
        }
    }
}

pub struct KcpProxyService {
    peer_manager: Arc<PeerManager>,
    cidr_table: Arc<ProxyCidrTable>,
    state: Mutex<Option<KcpProxyServiceState>>,
    src_endpoint: StdMutex<Option<Arc<KcpEndpoint>>>,
    dst_proxy_entries: StdMutex<Option<Arc<DashMap<ConnId, TcpProxyEntry>>>>,
}

impl KcpProxyService {
    pub fn new(peer_manager: Arc<PeerManager>, cidr_table: Arc<ProxyCidrTable>) -> Self {
        Self {
            peer_manager,
            cidr_table,
            state: Mutex::new(None),
            src_endpoint: StdMutex::new(None),
            dst_proxy_entries: StdMutex::new(None),
        }
    }

    pub fn src_endpoint(&self) -> Option<Arc<KcpEndpoint>> {
        self.src_endpoint
            .lock()
            .expect("KCP source endpoint mutex poisoned")
            .clone()
    }

    pub fn dst_rpc_service(&self) -> Option<KcpProxyDstRpcService> {
        self.dst_proxy_entries
            .lock()
            .expect("KCP destination proxy entries mutex poisoned")
            .as_ref()
            .map(KcpProxyDstRpcService::new)
    }
}

#[async_trait::async_trait]
impl WrappedTransportEngine for KcpProxyService {
    async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if state.is_some() {
            return Ok(());
        }
        let directions = options.directions;

        let src = if directions.source {
            let src = KcpProxySrc::new(options.datagrams.clone()).await;
            Some(src)
        } else {
            None
        };
        let dst = if directions.destination {
            let dst = KcpProxyDst::new(
                self.peer_manager.clone(),
                self.cidr_table.clone(),
                options.datagrams,
            )
            .await;
            Some(dst)
        } else {
            None
        };

        *self
            .src_endpoint
            .lock()
            .expect("KCP source endpoint mutex poisoned") =
            src.as_ref().map(KcpProxySrc::get_kcp_endpoint);
        *self
            .dst_proxy_entries
            .lock()
            .expect("KCP destination proxy entries mutex poisoned") =
            dst.as_ref().map(|dst| dst.proxy_entries.clone());
        *state = Some(KcpProxyServiceState { src, dst });
        Ok(())
    }

    async fn activate(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        let state = state
            .as_mut()
            .ok_or_else(|| anyhow!("KCP engine is not prepared"))?;
        if let Some(dst) = state.dst.as_mut() {
            dst.start().await;
        }
        Ok(())
    }

    async fn inject_peer_datagram(
        &self,
        role: WrappedTransportRole,
        _from_peer_id: u32,
        payload: Bytes,
    ) -> anyhow::Result<()> {
        let endpoint = {
            let state = self.state.lock().await;
            match (state.as_ref(), role) {
                (Some(state), WrappedTransportRole::Source) => {
                    state.src.as_ref().map(KcpProxySrc::get_kcp_endpoint)
                }
                (Some(state), WrappedTransportRole::Destination) => {
                    state.dst.as_ref().map(|dst| dst.kcp_endpoint.clone())
                }
                (None, _) => None,
            }
        }
        .ok_or_else(|| anyhow!("KCP {role:?} endpoint is not active"))?;

        endpoint
            .input_sender_ref()
            .send(KcpPacket::from(bytes::BytesMut::from(payload)))
            .await
            .map_err(|error| anyhow!("failed to inject KCP datagram: {error}"))
    }

    async fn connect_source(
        &self,
        request: WrappedTransportConnect,
    ) -> anyhow::Result<Box<dyn TcpProxyStream>> {
        let endpoint = {
            let state = self.state.lock().await;
            state
                .as_ref()
                .and_then(|state| state.src.as_ref())
                .map(KcpProxySrc::get_kcp_endpoint)
        }
        .ok_or_else(|| anyhow!("KCP source endpoint is not prepared"))?;
        let stream = connect_kcp_source(
            endpoint,
            request.my_peer_id,
            request.dst_peer_id,
            request.src,
            request.dst,
        )
        .await?;
        Ok(Box::new(stream))
    }

    async fn stop(&self) {
        let mut state = self.state.lock().await;
        if let Some(active) = state.as_mut() {
            active.stop().await;
        }
        self.src_endpoint
            .lock()
            .expect("KCP source endpoint mutex poisoned")
            .take();
        self.dst_proxy_entries
            .lock()
            .expect("KCP destination proxy entries mutex poisoned")
            .take();
        state.take();
    }
}

#[derive(Clone)]
pub struct KcpProxyDstRpcService(Weak<DashMap<ConnId, TcpProxyEntry>>);

impl KcpProxyDstRpcService {
    pub fn new(proxy_entries: &Arc<DashMap<ConnId, TcpProxyEntry>>) -> Self {
        Self(Arc::downgrade(proxy_entries))
    }
}

#[async_trait::async_trait]
impl TcpProxyRpc for KcpProxyDstRpcService {
    type Controller = BaseController;
    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest, // Accept request of type HelloRequest
    ) -> std::result::Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.0.upgrade() {
            for item in tcp_proxy.iter() {
                reply.entries.push(*item.value());
            }
        }
        Ok(reply)
    }
}
