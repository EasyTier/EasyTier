//! Host-listener adapter that translates SOCKS5 sessions into data-plane calls.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    foundation::task::reap_joinset_background,
    gateway::dataplane::{
        DataPlaneConsumerLease, DataPlaneError, DataPlaneErrorKind, DataPlaneRuntime,
        DataPlaneTcpConnectOptions, DataPlaneTcpStream,
    },
    host::dns::DnsResolver,
    socket::{
        SocketContext,
        tcp::{
            TcpListenOptions, TcpSocketPurpose, VirtualTcpListener, VirtualTcpListenerFactory,
            VirtualTcpSocket, VirtualTcpSocketFactory,
        },
        udp::VirtualUdpSocketFactory,
    },
};

use super::{
    AcceptAuthentication, AsyncTcpConnector, Config, HostSocks5ServerRuntime, Result, Socks5Socket,
    SocksError, codec::ReplyError,
};

struct Socks5DataPlaneConnector<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    data_plane: Arc<DataPlaneRuntime<H>>,
    source_addr: SocketAddr,
}

#[async_trait::async_trait]
impl<H> AsyncTcpConnector for Socks5DataPlaneConnector<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    type S = DataPlaneTcpStream;

    async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<Self::S> {
        self.data_plane
            .connect_tcp(
                addr,
                DataPlaneTcpConnectOptions::gateway(
                    Duration::from_secs(timeout_s),
                    TcpSocketPurpose::Socks5,
                    self.source_addr,
                ),
            )
            .await
            .map_err(map_data_plane_error)
    }
}

fn map_data_plane_error(error: DataPlaneError) -> SocksError {
    match error.kind() {
        DataPlaneErrorKind::DeadlineExceeded => ReplyError::ConnectionTimeout.into(),
        DataPlaneErrorKind::ConnectionRefused => ReplyError::ConnectionRefused.into(),
        DataPlaneErrorKind::NoOverlayRoute | DataPlaneErrorKind::PathNotReady => {
            ReplyError::NetworkUnreachable.into()
        }
        DataPlaneErrorKind::AddressFamilyUnsupported => ReplyError::AddressTypeNotSupported.into(),
        DataPlaneErrorKind::Cancelled
        | DataPlaneErrorKind::InstanceStopped
        | DataPlaneErrorKind::HandleClosed
        | DataPlaneErrorKind::NetworkChanged => ReplyError::ConnectionNotAllowed.into(),
        DataPlaneErrorKind::AddressInUse
        | DataPlaneErrorKind::ResourceLimit
        | DataPlaneErrorKind::BufferTooSmall
        | DataPlaneErrorKind::Io => SocksError::Other(anyhow::Error::new(error)),
    }
}

async fn handle_socks5_stream<H, S>(
    stream: S,
    data_plane: Arc<DataPlaneRuntime<H>>,
    source_addr: SocketAddr,
    command_runtime: Arc<HostSocks5ServerRuntime<H>>,
) where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
    S: VirtualTcpSocket,
{
    let mut config = Config::<AcceptAuthentication>::default();
    config.set_request_timeout(10);
    config.set_skip_auth(false);
    config.set_allow_no_auth(true);

    let connector = Socks5DataPlaneConnector {
        data_plane,
        source_addr,
    };
    let socket = Socks5Socket::new(stream, Arc::new(config), connector, command_runtime);
    if let Err(error) = socket.upgrade_to_socks5().await {
        tracing::error!(?error, "SOCKS5 session failed");
    }
}

pub(crate) struct Socks5GatewayAdapter<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    operation: Mutex<()>,
    started: AtomicBool,
    runtime_config: CoreRuntimeConfigStore,
    data_plane: Arc<DataPlaneRuntime<H>>,
    host: Arc<H>,
    socket_context: SocketContext,
    command_runtime: Arc<HostSocks5ServerRuntime<H>>,
    consumer_lease: Mutex<Option<DataPlaneConsumerLease>>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl<H> Socks5GatewayAdapter<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub(crate) fn new(
        runtime_config: CoreRuntimeConfigStore,
        data_plane: Arc<DataPlaneRuntime<H>>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        socket_context: SocketContext,
    ) -> Arc<Self> {
        Arc::new(Self {
            operation: Mutex::new(()),
            started: AtomicBool::new(false),
            runtime_config,
            data_plane,
            host: host.clone(),
            socket_context: socket_context.clone(),
            command_runtime: Arc::new(HostSocks5ServerRuntime::new(host, dns, socket_context)),
            consumer_lease: Mutex::new(None),
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
        })
    }

    async fn start_inner(&self) -> anyhow::Result<()> {
        let Some(bind_addr) = self.runtime_config.snapshot().services.gateway.socks5_bind else {
            return Ok(());
        };
        let options = TcpListenOptions::socks5(bind_addr);
        let bind = options
            .bind
            .clone()
            .with_context(self.socket_context.clone());
        let listener = self.host.bind_tcp(options.with_bind(bind)).await?;
        let consumer_lease = self.data_plane.acquire_consumer_lease()?;

        self.tasks.lock().unwrap().spawn(reap_joinset_background(
            self.tasks.clone(),
            "SOCKS5 gateway adapter",
        ));
        let data_plane = self.data_plane.clone();
        let command_runtime = self.command_runtime.clone();
        let session_tasks = self.tasks.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, source_addr)) => {
                        tracing::info!(?source_addr, "accepted a SOCKS5 connection");
                        session_tasks.lock().unwrap().spawn(handle_socks5_stream(
                            socket,
                            data_plane.clone(),
                            source_addr,
                            command_runtime.clone(),
                        ));
                    }
                    Err(error) => tracing::error!(?error, "SOCKS5 accept failed"),
                }
            }
        });
        self.consumer_lease.lock().await.replace(consumer_lease);
        Ok(())
    }

    pub(crate) async fn start(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Err(error) = self.start_inner().await {
            self.stop_inner().await;
            return Err(error);
        }
        self.started.store(true, Ordering::Release);
        Ok(())
    }

    async fn stop_inner(&self) {
        self.started.store(false, Ordering::Release);
        self.consumer_lease.lock().await.take();
        let mut tasks = {
            let mut tasks = self.tasks.lock().unwrap();
            std::mem::replace(&mut *tasks, JoinSet::new())
        };
        tasks.shutdown().await;
    }

    pub(crate) async fn stop(&self) {
        let _operation = self.operation.lock().await;
        self.stop_inner().await;
    }
}
