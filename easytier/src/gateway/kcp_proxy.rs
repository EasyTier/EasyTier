use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use kcp_sys::{
    endpoint::{KcpEndpoint, KcpPacketReceiver},
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
    gateway::proxy::runtime::TcpProxyStream,
    gateway::proxy::wrapped_transport::{
        WrappedTransportAcceptedStream, WrappedTransportConnect, WrappedTransportDatagram,
        WrappedTransportDatagramBuffer, WrappedTransportDestinationIngress, WrappedTransportEngine,
        WrappedTransportEngineStart, WrappedTransportKind, WrappedTransportRole,
    },
};

use super::hedge::HedgeExt;
use crate::proto::peer_rpc::KcpConnData;

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
    destination_ingress: WrappedTransportDestinationIngress,
    tasks: JoinSet<()>,
    accept_cancel: CancellationToken,
    accept_task: Option<JoinHandle<()>>,
}

impl KcpProxyDst {
    pub async fn new(
        destination_ingress: WrappedTransportDestinationIngress,
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
            destination_ingress,
            tasks,
            accept_cancel: CancellationToken::new(),
            accept_task: None,
        }
    }

    #[tracing::instrument(ret, skip(destination_ingress))]
    async fn handle_one_in_stream(
        kcp_stream: KcpStream,
        destination_ingress: WrappedTransportDestinationIngress,
    ) -> anyhow::Result<()> {
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

        destination_ingress
            .submit(WrappedTransportAcceptedStream {
                src: src_socket,
                dst: dst_socket,
                initial_acl_packet_size: conn_data.len(),
                stream: Box::new(kcp_stream),
            })
            .await
    }

    async fn run_accept_task(&mut self) {
        let kcp_endpoint = self.kcp_endpoint.clone();
        let destination_ingress = self.destination_ingress.clone();
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

                        let destination_ingress = destination_ingress.clone();
                        streams.spawn(async move {
                            let _ = Self::handle_one_in_stream(stream, destination_ingress).await;
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
    state: Mutex<Option<KcpProxyServiceState>>,
}

impl KcpProxyService {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
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
            let destination_ingress = options
                .destination_ingress
                .ok_or_else(|| anyhow!("KCP destination ingress is required"))?;
            let dst = KcpProxyDst::new(destination_ingress, options.datagrams).await;
            Some(dst)
        } else {
            None
        };

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
        state.take();
    }
}
