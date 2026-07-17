use std::future::Future;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncWriteExt, copy};
use tokio::task::JoinSet;

use crate::{
    foundation::time::timeout,
    packet::ZCPacket,
    peers::{
        NicPacketFilter, PeerPacketFilter,
        peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    },
    socket::{
        SocketContext,
        tcp::{TcpBindOptions, TcpListenOptions, VirtualTcpListener, VirtualTcpListenerFactory},
    },
};

use super::cidr_table::ProxyCidrTable;
use super::runtime::{
    ProxyRuntimeError, TcpProxyConnectContext, TcpProxyDestinationConnector, TcpProxyRuntime,
    TcpProxyStream,
};
use super::tcp_proxy_engine::{
    TcpNatEntry, TcpNatEntryState, TcpProxyEngine, TcpProxyMode, TcpProxyNicContext,
    TcpProxyPacketAction, TcpProxyPeerContext,
};
#[cfg(feature = "proxy-smoltcp-stack")]
use crate::gateway::smoltcp::{SmolTcpStack, output_dst_ip};

fn spawn_tcp_proxy_task(
    lifecycle: &AtomicU64,
    expected_generation: u64,
    tasks: &std::sync::Mutex<JoinSet<()>>,
    task: impl Future<Output = ()> + Send + 'static,
) -> bool {
    let mut tasks = tasks.lock().unwrap();
    if lifecycle.load(Ordering::Acquire) != expected_generation {
        return false;
    }
    tasks.spawn(task);
    true
}

pub struct TcpProxyService<
    R: TcpProxyRuntime + 'static,
    F: VirtualTcpListenerFactory,
    C: TcpProxyDestinationConnector,
> {
    peer_manager: Arc<PeerManagerCore>,
    runtime: Arc<R>,
    listener_factory: Arc<F>,
    socket_context: SocketContext,
    connector: Arc<C>,
    engine: Arc<TcpProxyEngine>,
    mode: TcpProxyMode,
    peer_pipeline_guard: std::sync::Mutex<Option<PipelineRegistrationGuard>>,
    nic_pipeline_guard: std::sync::Mutex<Option<PipelineRegistrationGuard>>,
    kernel_listener: std::sync::Mutex<Option<Arc<F::Listener>>>,
    #[cfg(feature = "proxy-smoltcp-stack")]
    smoltcp_stack: std::sync::Mutex<Option<Arc<SmolTcpStack>>>,
    tasks: std::sync::Mutex<JoinSet<()>>,
    lifecycle: AtomicU64,
}

impl<R: TcpProxyRuntime + 'static, F: VirtualTcpListenerFactory, C: TcpProxyDestinationConnector>
    TcpProxyService<R, F, C>
{
    pub fn new_with_socket_context(
        peer_manager: Arc<PeerManagerCore>,
        runtime: Arc<R>,
        listener_factory: Arc<F>,
        connector: Arc<C>,
        cidr_table: Arc<ProxyCidrTable>,
        socket_context: SocketContext,
    ) -> Arc<Self> {
        let mode = connector.proxy_mode();
        Arc::new(Self {
            peer_manager,
            runtime,
            listener_factory,
            socket_context,
            connector,
            engine: Arc::new(TcpProxyEngine::new(cidr_table)),
            mode,
            peer_pipeline_guard: std::sync::Mutex::new(None),
            nic_pipeline_guard: std::sync::Mutex::new(None),
            kernel_listener: std::sync::Mutex::new(None),
            #[cfg(feature = "proxy-smoltcp-stack")]
            smoltcp_stack: std::sync::Mutex::new(None),
            tasks: std::sync::Mutex::new(JoinSet::new()),
            lifecycle: AtomicU64::new(0),
        })
    }

    pub fn engine(&self) -> Arc<TcpProxyEngine> {
        self.engine.clone()
    }

    pub fn is_started(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) & 1 != 0
    }

    pub async fn start(self: &Arc<Self>, register_pipeline: bool) -> Result<(), ProxyRuntimeError> {
        let generation = loop {
            let stopped = self.lifecycle.load(Ordering::Acquire);
            if stopped & 1 != 0 {
                return Ok(());
            }
            let active = stopped.wrapping_add(1);
            if self
                .lifecycle
                .compare_exchange(stopped, active, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break active;
            }
        };

        let snapshot = self.runtime.proxy_runtime_snapshot();
        let start_result = if snapshot.smoltcp_enabled {
            #[cfg(feature = "proxy-smoltcp-stack")]
            {
                self.start_smoltcp(generation).await
            }

            #[cfg(not(feature = "proxy-smoltcp-stack"))]
            {
                Err(ProxyRuntimeError::Other(anyhow::anyhow!(
                    "smoltcp proxy stack feature is disabled"
                )))
            }
        } else {
            self.start_kernel_listener(generation).await
        };

        if let Err(err) = start_result {
            let _ = self.lifecycle.compare_exchange(
                generation,
                generation.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(err);
        }

        if register_pipeline {
            self.register_pipeline().await;
        }
        self.spawn_syn_cleanup(generation);

        Ok(())
    }

    pub fn stop(&self) {
        self.stop_resources();
        self.tasks.lock().unwrap().abort_all();
    }

    pub(crate) async fn stop_and_wait(&self) {
        self.stop_resources();
        let mut tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        tasks.shutdown().await;
    }

    fn stop_resources(&self) {
        let _ = self
            .lifecycle
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                (generation & 1 != 0).then(|| generation.wrapping_add(1))
            });
        if let Some(guard) = self.peer_pipeline_guard.lock().unwrap().take() {
            guard.close();
        }
        if let Some(guard) = self.nic_pipeline_guard.lock().unwrap().take() {
            guard.close();
        }
        if let Some(listener) = self.kernel_listener.lock().unwrap().take() {
            drop(listener);
        }
        #[cfg(feature = "proxy-smoltcp-stack")]
        if let Some(stack) = self.smoltcp_stack.lock().unwrap().take() {
            drop(stack);
        }
    }

    async fn register_pipeline(self: &Arc<Self>) {
        self.register_peer_pipeline().await;
        self.register_nic_pipeline().await;
    }

    pub async fn register_peer_pipeline(self: &Arc<Self>) {
        if self.peer_pipeline_guard.lock().unwrap().is_some() {
            return;
        }
        let peer_guard = self
            .peer_manager
            .add_managed_packet_process_pipeline(Box::new(TcpProxyServiceFilter {
                service: Arc::downgrade(self),
            }))
            .await;
        self.peer_pipeline_guard.lock().unwrap().replace(peer_guard);
    }

    pub async fn register_nic_pipeline(self: &Arc<Self>) {
        if self.nic_pipeline_guard.lock().unwrap().is_some() {
            return;
        }
        let nic_guard = self
            .peer_manager
            .add_managed_nic_packet_process_pipeline(Box::new(TcpProxyServiceFilter {
                service: Arc::downgrade(self),
            }))
            .await;
        self.nic_pipeline_guard.lock().unwrap().replace(nic_guard);
    }

    fn spawn_syn_cleanup(self: &Arc<Self>, generation: u64) {
        let service = Arc::downgrade(self);
        let _ = spawn_tcp_proxy_task(&self.lifecycle, generation, &self.tasks, async move {
            loop {
                crate::foundation::time::sleep(Duration::from_secs(10)).await;
                let Some(service) = service.upgrade() else {
                    break;
                };
                service.engine.cleanup_expired_syn(Duration::from_secs(30));
                service.drain_completed_tasks();
            }
        });
    }

    fn drain_completed_tasks(&self) {
        let mut tasks = self.tasks.lock().unwrap();
        while let Some(result) = tasks.try_join_next() {
            if let Err(err) = result {
                tracing::warn!(?err, "tcp proxy task finished with error");
            }
        }
    }

    async fn start_kernel_listener(
        self: &Arc<Self>,
        generation: u64,
    ) -> Result<(), ProxyRuntimeError> {
        let listen_addr = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0);
        let listener = self
            .listener_factory
            .bind_tcp(
                TcpListenOptions::proxy_nat(listen_addr).with_bind(
                    TcpBindOptions::default()
                        .with_context(
                            self.socket_context
                                .clone()
                                .with_ip_version(crate::socket::IpVersion::V4),
                        )
                        .with_local_addr(Some(listen_addr)),
                ),
            )
            .await?;
        self.engine.set_local_port(listener.local_addr()?.port());
        self.kernel_listener
            .lock()
            .unwrap()
            .replace(listener.clone());

        let service = Arc::downgrade(self);
        let _ = spawn_tcp_proxy_task(&self.lifecycle, generation, &self.tasks, async move {
            loop {
                let accept_ret = listener.accept().await;
                let Ok((src_stream, socket_addr)) = accept_ret else {
                    tracing::error!(
                        error = ?accept_ret.err(),
                        "nat tcp listener accept failed"
                    );
                    continue;
                };
                let Some(service) = service.upgrade() else {
                    break;
                };
                service
                    .handle_accept(generation, socket_addr, Box::new(src_stream))
                    .await;
            }
        });

        Ok(())
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    async fn start_smoltcp(self: &Arc<Self>, generation: u64) -> Result<(), ProxyRuntimeError> {
        let local_ip = self
            .runtime
            .proxy_runtime_snapshot()
            .local_inet
            .map(|inet| inet.address())
            .unwrap_or(std::net::Ipv4Addr::new(192, 88, 99, 254));
        let stack = SmolTcpStack::new(local_ip).await?;
        self.engine.set_local_port(stack.local_port());

        let mut output_rx = stack.take_output_rx().await?;
        let peer_manager = self.peer_manager.clone();
        let _ = spawn_tcp_proxy_task(&self.lifecycle, generation, &self.tasks, async move {
            while let Some(data) = output_rx.recv().await {
                tracing::trace!(?data, "receive from smoltcp stack and send to peer manager");
                let dst = match output_dst_ip(&data) {
                    Ok(dst) => dst,
                    Err(err) => {
                        tracing::error!(?err, ?data, "invalid smoltcp output packet");
                        continue;
                    }
                };
                let packet = ZCPacket::new_with_payload(&data);
                if let Err(err) = peer_manager.send_msg_by_ip(packet, dst, false).await {
                    tracing::error!(?err, "send to peer failed in smoltcp sender");
                }
            }
            tracing::error!("smoltcp stack stream exited");
        });

        let service = Arc::downgrade(self);
        let accept_stack = stack.clone();
        let _ = spawn_tcp_proxy_task(&self.lifecycle, generation, &self.tasks, async move {
            loop {
                let accept_ret = accept_stack.accept().await;
                let Ok((socket_addr, src_stream)) = accept_ret else {
                    tracing::error!(error = ?accept_ret.err(), "smoltcp accept failed");
                    continue;
                };
                let Some(service) = service.upgrade() else {
                    break;
                };
                service
                    .handle_accept(generation, socket_addr, src_stream)
                    .await;
            }
        });

        self.smoltcp_stack.lock().unwrap().replace(stack);
        Ok(())
    }

    async fn handle_accept(
        self: Arc<Self>,
        generation: u64,
        socket_addr: std::net::SocketAddr,
        src_stream: Box<dyn TcpProxyStream>,
    ) {
        let snapshot = self.runtime.proxy_runtime_snapshot();
        let Some(entry) = self
            .engine
            .accept_connection(socket_addr, snapshot.local_inet)
        else {
            tracing::error!(
                ?socket_addr,
                "tcp connection from unknown source, ignore it"
            );
            return;
        };
        tracing::info!(
            ?socket_addr,
            "tcp connection accepted for proxy, nat dst: {:?}",
            entry.real_dst()
        );

        if !spawn_tcp_proxy_task(
            &self.lifecycle,
            generation,
            &self.tasks,
            Self::connect_to_nat_dst(self.clone(), src_stream, entry.clone()),
        ) {
            entry.set_state(TcpNatEntryState::Closed);
            self.engine.remove_entry(entry.id());
        }
    }

    async fn connect_to_nat_dst(
        service: Arc<Self>,
        mut src_stream: Box<dyn TcpProxyStream>,
        entry: Arc<TcpNatEntry>,
    ) {
        if service.runtime.should_deny_tcp_proxy(entry.real_dst()) {
            tracing::error!(
                ?entry,
                "nat dst port {} is in running listeners, ignore it",
                entry.real_dst().port()
            );
            entry.set_state(TcpNatEntryState::Closed);
            service.engine.remove_entry(entry.id());
            return;
        }

        let ctx = TcpProxyConnectContext {
            src: entry.src(),
            real_dst: entry.real_dst(),
            mapped_dst: entry.mapped_dst(),
        };
        let socket_dst = if service.runtime.is_ip_local_virtual_ip(&ctx.real_dst.ip()) {
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), ctx.real_dst.port())
        } else {
            ctx.real_dst
        };
        service.runtime.record_tcp_proxy_connect(ctx, socket_dst);

        let Ok(dst_stream) = service.connector.connect(ctx.src, socket_dst).await else {
            tracing::error!("connect to dst failed: {:?}", entry);
            entry.set_state(TcpNatEntryState::Closed);
            service.engine.remove_entry(entry.id());
            return;
        };
        let mut dst_stream: Box<dyn TcpProxyStream> = Box::new(dst_stream);

        tracing::info!(?entry, "tcp connection to dst established");
        if entry.state() == TcpNatEntryState::ConnectingDst {
            entry.set_state(TcpNatEntryState::Connected);
        }

        let ret = copy_bidirectional_no_shutdown(src_stream.as_mut(), dst_stream.as_mut()).await;
        tracing::info!(nat_entry = ?entry, ret = ?ret, "nat tcp connection closed");

        entry.set_state(TcpNatEntryState::ClosingSrc);
        let ret = timeout(Duration::from_secs(10), src_stream.shutdown()).await;
        tracing::info!(nat_entry = ?entry, ret = ?ret, "src tcp stream shutdown");

        entry.set_state(TcpNatEntryState::ClosingDst);
        let ret = timeout(Duration::from_secs(10), dst_stream.shutdown()).await;
        tracing::info!(nat_entry = ?entry, ret = ?ret, "dst tcp stream shutdown");

        drop(src_stream);
        drop(dst_stream);

        entry.set_state(TcpNatEntryState::Closed);
        crate::foundation::time::sleep(Duration::from_secs(10)).await;
        service.engine.remove_entry(entry.id());
    }

    async fn handle_peer_packet(self: Arc<Self>, mut packet: ZCPacket) -> Option<ZCPacket> {
        let snapshot = self.runtime.proxy_runtime_snapshot();
        let action = self.engine.try_handle_peer_packet(
            self.mode,
            &mut packet,
            TcpProxyPeerContext {
                local_inet: snapshot.local_inet,
                virtual_ipv4: snapshot.virtual_ipv4,
                local_port: self.engine.local_port(),
                enable_exit_node: snapshot.enable_exit_node,
                no_tun: snapshot.no_tun,
                smoltcp_enabled: snapshot.smoltcp_enabled,
            },
        );
        let TcpProxyPacketAction::Handled { new_syn: _new_syn } = action else {
            return Some(packet);
        };

        if snapshot.smoltcp_enabled {
            #[cfg(feature = "proxy-smoltcp-stack")]
            self.handle_smoltcp_packet(packet, _new_syn).await;

            #[cfg(not(feature = "proxy-smoltcp-stack"))]
            tracing::error!("smoltcp packet received but proxy-smoltcp-stack is disabled");
        } else if let Err(err) = self.peer_manager.get_nic_channel().send(packet).await {
            tracing::error!(?err, "send to nic failed");
        }

        None
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    async fn handle_smoltcp_packet(&self, packet: ZCPacket, new_syn: bool) {
        let stack = self.smoltcp_stack.lock().unwrap().clone();
        let Some(stack) = stack else {
            tracing::error!("smoltcp stack is not started");
            return;
        };
        if new_syn {
            stack.add_listener().await;
        }
        if let Err(err) = stack.send_ingress(packet).await {
            tracing::error!(?err, "send to smoltcp stack failed");
        }
    }

    async fn handle_nic_packet(&self, packet: &mut ZCPacket) -> bool {
        let snapshot = self.runtime.proxy_runtime_snapshot();
        self.engine.try_process_packet_from_nic(
            packet,
            TcpProxyNicContext {
                local_inet: snapshot.local_inet,
                local_port: self.engine.local_port(),
                my_peer_id: self.peer_manager.my_peer_id(),
                smoltcp_enabled: snapshot.smoltcp_enabled,
            },
        )
    }
}

async fn copy_bidirectional_no_shutdown(
    src: &mut dyn TcpProxyStream,
    dst: &mut dyn TcpProxyStream,
) -> Result<(), ProxyRuntimeError> {
    let (mut src_reader, mut src_writer) = tokio::io::split(src);
    let (mut dst_reader, mut dst_writer) = tokio::io::split(dst);
    let src_to_dst = copy(&mut src_reader, &mut dst_writer);
    let dst_to_src = copy(&mut dst_reader, &mut src_writer);
    tokio::pin!(src_to_dst);
    tokio::pin!(dst_to_src);
    tokio::select! {
        result = &mut src_to_dst => {
            result?;
        }
        result = &mut dst_to_src => {
            result?;
        }
    }
    Ok(())
}

impl<R: TcpProxyRuntime + 'static, F: VirtualTcpListenerFactory, C: TcpProxyDestinationConnector>
    Drop for TcpProxyService<R, F, C>
{
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    fn pending_task(dropped: Arc<AtomicBool>) -> impl Future<Output = ()> + Send + 'static {
        let signal = DropSignal(dropped);
        async move {
            let _signal = signal;
            std::future::pending::<()>().await;
        }
    }

    #[tokio::test]
    async fn stop_fence_linearizes_task_registration() {
        let lifecycle = AtomicU64::new(1);
        let tasks = std::sync::Mutex::new(JoinSet::new());
        let accepted_dropped = Arc::new(AtomicBool::new(false));

        assert!(spawn_tcp_proxy_task(
            &lifecycle,
            1,
            &tasks,
            pending_task(accepted_dropped.clone()),
        ));
        lifecycle.store(2, Ordering::Release);
        let mut stopping = std::mem::take(&mut *tasks.lock().unwrap());
        stopping.shutdown().await;
        assert!(accepted_dropped.load(Ordering::Acquire));

        lifecycle.store(3, Ordering::Release);

        let rejected_dropped = Arc::new(AtomicBool::new(false));
        assert!(!spawn_tcp_proxy_task(
            &lifecycle,
            1,
            &tasks,
            pending_task(rejected_dropped.clone()),
        ));
        assert!(rejected_dropped.load(Ordering::Acquire));

        let current_dropped = Arc::new(AtomicBool::new(false));
        assert!(spawn_tcp_proxy_task(
            &lifecycle,
            3,
            &tasks,
            pending_task(current_dropped.clone()),
        ));
        let mut current = std::mem::take(&mut *tasks.lock().unwrap());
        current.shutdown().await;
        assert!(current_dropped.load(Ordering::Acquire));
    }
}

struct TcpProxyServiceFilter<
    R: TcpProxyRuntime + 'static,
    F: VirtualTcpListenerFactory,
    C: TcpProxyDestinationConnector,
> {
    service: Weak<TcpProxyService<R, F, C>>,
}

#[async_trait::async_trait]
impl<R: TcpProxyRuntime + 'static, F: VirtualTcpListenerFactory, C: TcpProxyDestinationConnector>
    PeerPacketFilter for TcpProxyServiceFilter<R, F, C>
{
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let Some(service) = self.service.upgrade() else {
            return Some(packet);
        };
        service.handle_peer_packet(packet).await
    }
}

#[async_trait::async_trait]
impl<R: TcpProxyRuntime + 'static, F: VirtualTcpListenerFactory, C: TcpProxyDestinationConnector>
    NicPacketFilter for TcpProxyServiceFilter<R, F, C>
{
    async fn try_process_packet_from_nic(&self, packet: &mut ZCPacket) -> bool {
        let Some(service) = self.service.upgrade() else {
            return false;
        };
        service.handle_nic_packet(packet).await
    }
}
