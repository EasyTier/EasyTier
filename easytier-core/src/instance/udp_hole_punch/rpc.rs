use std::{fmt, net::SocketAddr, sync::Arc};

use async_trait::async_trait;

use crate::{
    config::PeerId,
    hole_punch::udp::{
        SelectPunchListener, SelectPunchListenerResponse as CoreSelectPunchListenerResponse,
        SendPunchPacketBothEasySym,
        SendPunchPacketBothEasySymResponse as CoreSendPunchPacketBothEasySymResponse,
        SendPunchPacketCone, SendPunchPacketEasySym, SendPunchPacketHardSym,
        SendPunchPacketHardSymResponse as CoreSendPunchPacketHardSymResponse, UdpHolePunchInbound,
        UdpHolePunchRuntime, UdpHolePunchServer as CoreUdpHolePunchServer, UdpHolePunchSignalError,
        UdpHolePunchSignaling, UdpHolePunchTransportSink, UdpSymPunchLock,
    },
    peers::peer_manager::PeerManagerCore,
    proto::{
        common::Void,
        peer_rpc::{
            SelectPunchListenerRequest, SelectPunchListenerResponse,
            SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse,
            SendPunchPacketConeRequest, SendPunchPacketEasySymRequest,
            SendPunchPacketHardSymRequest, SendPunchPacketHardSymResponse, UdpHolePunchRpc,
            UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    stun::StunInfoProvider,
};

#[derive(Clone)]
pub(super) struct PeerRpcUdpHolePunchSignaling {
    peer_manager: Arc<PeerManagerCore>,
}

impl fmt::Debug for PeerRpcUdpHolePunchSignaling {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRpcUdpHolePunchSignaling")
            .field("my_peer_id", &self.peer_manager.my_peer_id())
            .finish_non_exhaustive()
    }
}

impl PeerRpcUdpHolePunchSignaling {
    pub(super) fn new(peer_manager: Arc<PeerManagerCore>) -> Self {
        Self { peer_manager }
    }

    fn rpc_stub(
        &self,
        dst_peer_id: PeerId,
    ) -> Box<dyn UdpHolePunchRpc<Controller = BaseController> + Send + Sync + 'static> {
        self.peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_manager.my_peer_id(),
                dst_peer_id,
                self.peer_manager.network_name().to_owned(),
            )
    }
}

fn map_rpc_error(error: rpc_types::error::Error) -> UdpHolePunchSignalError {
    match error {
        rpc_types::error::Error::InvalidServiceKey(_, _) => {
            UdpHolePunchSignalError::InvalidServiceKey
        }
        rpc_types::error::Error::Timeout(_) => UdpHolePunchSignalError::Timeout,
        rpc_types::error::Error::ExecutionError(error) => {
            UdpHolePunchSignalError::RemoteRejected(error.to_string())
        }
        other => UdpHolePunchSignalError::Transport(other.to_string()),
    }
}

fn missing_field(field: &str) -> UdpHolePunchSignalError {
    UdpHolePunchSignalError::RemoteRejected(format!("missing {field}"))
}

#[async_trait]
impl UdpHolePunchSignaling for PeerRpcUdpHolePunchSignaling {
    async fn select_punch_listener(
        &self,
        dst_peer_id: PeerId,
        request: SelectPunchListener,
    ) -> Result<CoreSelectPunchListenerResponse, UdpHolePunchSignalError> {
        let response = self
            .rpc_stub(dst_peer_id)
            .select_punch_listener(
                BaseController::default(),
                SelectPunchListenerRequest {
                    force_new: request.force_new,
                    prefer_port_mapping: request.prefer_port_mapping,
                },
            )
            .await
            .map_err(map_rpc_error)?;

        Ok(CoreSelectPunchListenerResponse {
            listener_mapped_addr: SocketAddr::from(
                response
                    .listener_mapped_addr
                    .ok_or_else(|| missing_field("listener_mapped_addr"))?,
            ),
        })
    }

    async fn send_punch_packet_cone(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError> {
        self.rpc_stub(dst_peer_id)
            .send_punch_packet_cone(
                BaseController {
                    timeout_ms: 4000,
                    ..Default::default()
                },
                SendPunchPacketConeRequest {
                    listener_mapped_addr: Some(request.listener_mapped_addr.into()),
                    dest_addr: Some(request.dest_addr.into()),
                    transaction_id: request.transaction_id,
                    packet_count_per_batch: request.packet_count_per_batch,
                    packet_batch_count: request.packet_batch_count,
                    packet_interval_ms: request.packet_interval_ms,
                },
            )
            .await
            .map(|_| ())
            .map_err(map_rpc_error)
    }

    async fn send_punch_packet_hard_sym(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketHardSym,
    ) -> Result<CoreSendPunchPacketHardSymResponse, UdpHolePunchSignalError> {
        let response = self
            .rpc_stub(dst_peer_id)
            .send_punch_packet_hard_sym(
                BaseController {
                    timeout_ms: 4000,
                    trace_id: 0,
                    ..Default::default()
                },
                SendPunchPacketHardSymRequest {
                    listener_mapped_addr: Some(request.listener_mapped_addr.into()),
                    public_ips: request.public_ips.into_iter().map(Into::into).collect(),
                    transaction_id: request.transaction_id,
                    port_index: request.port_index,
                    round: request.round,
                },
            )
            .await
            .map_err(map_rpc_error)?;

        Ok(CoreSendPunchPacketHardSymResponse {
            next_port_index: response.next_port_index,
        })
    }

    async fn send_punch_packet_easy_sym(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError> {
        self.rpc_stub(dst_peer_id)
            .send_punch_packet_easy_sym(
                BaseController {
                    timeout_ms: 4000,
                    trace_id: 0,
                    ..Default::default()
                },
                SendPunchPacketEasySymRequest {
                    listener_mapped_addr: Some(request.listener_mapped_addr.into()),
                    public_ips: request.public_ips.into_iter().map(Into::into).collect(),
                    transaction_id: request.transaction_id,
                    base_port_num: request.base_port_num,
                    max_port_num: request.max_port_num,
                    is_incremental: request.is_incremental,
                },
            )
            .await
            .map(|_| ())
            .map_err(map_rpc_error)
    }

    async fn send_punch_packet_both_easy_sym(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketBothEasySym,
    ) -> Result<CoreSendPunchPacketBothEasySymResponse, UdpHolePunchSignalError> {
        let response = self
            .rpc_stub(dst_peer_id)
            .send_punch_packet_both_easy_sym(
                BaseController {
                    timeout_ms: 2000,
                    ..Default::default()
                },
                SendPunchPacketBothEasySymRequest {
                    transaction_id: request.transaction_id,
                    public_ip: Some(request.public_ip.into()),
                    dst_port_num: request.dst_port_num,
                    udp_socket_count: request.udp_socket_count,
                    wait_time_ms: request.wait_time_ms,
                },
            )
            .await
            .map_err(map_rpc_error)?;

        Ok(CoreSendPunchPacketBothEasySymResponse {
            is_busy: response.is_busy,
            base_mapped_addr: response.base_mapped_addr.map(SocketAddr::from),
        })
    }
}

pub(super) struct UdpHolePunchRpcEndpoint<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    inner: CoreUdpHolePunchServer<R, T>,
}

impl<R, T> UdpHolePunchRpcEndpoint<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    pub(super) fn new(
        stun: Arc<dyn StunInfoProvider>,
        transport_sink: Arc<T>,
        sym_punch_lock: UdpSymPunchLock,
        runtime: Arc<R>,
    ) -> Arc<Self> {
        let inner = CoreUdpHolePunchServer::new(runtime, stun, transport_sink, sym_punch_lock);
        Arc::new(Self { inner })
    }

    pub(super) async fn start(&self) {
        self.inner.start().await;
    }

    pub(super) fn begin_stop(&self) {
        self.inner.begin_stop();
    }

    pub(super) async fn stop(&self) {
        self.inner.stop().await;
    }
}

fn signal_error_to_rpc_error(error: UdpHolePunchSignalError) -> rpc_types::error::Error {
    match error {
        UdpHolePunchSignalError::InvalidServiceKey => rpc_types::error::Error::InvalidServiceKey(
            "UdpHolePunchRpc".to_owned(),
            "UdpHolePunchRpc".to_owned(),
        ),
        UdpHolePunchSignalError::Timeout => anyhow::anyhow!("timeout").into(),
        UdpHolePunchSignalError::RemoteRejected(message)
        | UdpHolePunchSignalError::Transport(message) => anyhow::anyhow!(message).into(),
    }
}

#[async_trait]
impl<R, T> UdpHolePunchInbound for UdpHolePunchRpcEndpoint<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    async fn select_punch_listener(
        &self,
        request: SelectPunchListener,
    ) -> Result<CoreSelectPunchListenerResponse, UdpHolePunchSignalError> {
        self.inner.select_punch_listener(request).await
    }

    async fn send_punch_packet_cone(
        &self,
        request: SendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError> {
        self.inner.send_punch_packet_cone(request).await
    }

    async fn send_punch_packet_hard_sym(
        &self,
        request: SendPunchPacketHardSym,
    ) -> Result<CoreSendPunchPacketHardSymResponse, UdpHolePunchSignalError> {
        self.inner.send_punch_packet_hard_sym(request).await
    }

    async fn send_punch_packet_easy_sym(
        &self,
        request: SendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError> {
        self.inner.send_punch_packet_easy_sym(request).await
    }

    async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySym,
    ) -> Result<CoreSendPunchPacketBothEasySymResponse, UdpHolePunchSignalError> {
        self.inner.send_punch_packet_both_easy_sym(request).await
    }
}

#[async_trait]
impl<R, T> UdpHolePunchRpc for UdpHolePunchRpcEndpoint<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTransportSink + 'static,
{
    type Controller = BaseController;

    async fn select_punch_listener(
        &self,
        _controller: Self::Controller,
        input: SelectPunchListenerRequest,
    ) -> rpc_types::error::Result<SelectPunchListenerResponse> {
        let response = UdpHolePunchInbound::select_punch_listener(
            self,
            SelectPunchListener {
                force_new: input.force_new,
                prefer_port_mapping: input.prefer_port_mapping,
            },
        )
        .await
        .map_err(signal_error_to_rpc_error)?;

        Ok(SelectPunchListenerResponse {
            listener_mapped_addr: Some(response.listener_mapped_addr.into()),
        })
    }

    async fn send_punch_packet_cone(
        &self,
        _controller: Self::Controller,
        input: SendPunchPacketConeRequest,
    ) -> rpc_types::error::Result<Void> {
        let listener_addr = input.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_for_cone request missing listener_mapped_addr"
        ))?;
        let dest_addr = input.dest_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_for_cone request missing dest_addr"
        ))?;

        UdpHolePunchInbound::send_punch_packet_cone(
            self,
            SendPunchPacketCone {
                listener_mapped_addr: listener_addr.into(),
                dest_addr: dest_addr.into(),
                transaction_id: input.transaction_id,
                packet_count_per_batch: input.packet_count_per_batch,
                packet_batch_count: input.packet_batch_count,
                packet_interval_ms: input.packet_interval_ms,
            },
        )
        .await
        .map_err(signal_error_to_rpc_error)?;

        Ok(Void::default())
    }

    async fn send_punch_packet_hard_sym(
        &self,
        _controller: Self::Controller,
        input: SendPunchPacketHardSymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketHardSymResponse> {
        let listener_addr = input.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "try_punch_symmetric request missing listener_addr"
        ))?;
        let response = UdpHolePunchInbound::send_punch_packet_hard_sym(
            self,
            SendPunchPacketHardSym {
                listener_mapped_addr: listener_addr.into(),
                public_ips: input.public_ips.into_iter().map(Into::into).collect(),
                transaction_id: input.transaction_id,
                port_index: input.port_index,
                round: input.round,
            },
        )
        .await
        .map_err(signal_error_to_rpc_error)?;

        Ok(SendPunchPacketHardSymResponse {
            next_port_index: response.next_port_index,
        })
    }

    async fn send_punch_packet_easy_sym(
        &self,
        _controller: Self::Controller,
        input: SendPunchPacketEasySymRequest,
    ) -> rpc_types::error::Result<Void> {
        let listener_addr = input.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_easy_sym request missing listener_addr"
        ))?;
        UdpHolePunchInbound::send_punch_packet_easy_sym(
            self,
            SendPunchPacketEasySym {
                listener_mapped_addr: listener_addr.into(),
                public_ips: input.public_ips.into_iter().map(Into::into).collect(),
                transaction_id: input.transaction_id,
                base_port_num: input.base_port_num,
                max_port_num: input.max_port_num,
                is_incremental: input.is_incremental,
            },
        )
        .await
        .map_err(signal_error_to_rpc_error)?;

        Ok(Void::default())
    }

    async fn send_punch_packet_both_easy_sym(
        &self,
        _controller: Self::Controller,
        input: SendPunchPacketBothEasySymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketBothEasySymResponse> {
        let public_ip = input
            .public_ip
            .ok_or(anyhow::anyhow!("public_ip is required"))?;
        let response = UdpHolePunchInbound::send_punch_packet_both_easy_sym(
            self,
            SendPunchPacketBothEasySym {
                transaction_id: input.transaction_id,
                public_ip: public_ip.into(),
                dst_port_num: input.dst_port_num,
                udp_socket_count: input.udp_socket_count,
                wait_time_ms: input.wait_time_ms,
            },
        )
        .await
        .map_err(signal_error_to_rpc_error)?;

        Ok(SendPunchPacketBothEasySymResponse {
            is_busy: response.is_busy,
            base_mapped_addr: response.base_mapped_addr.map(Into::into),
        })
    }
}
