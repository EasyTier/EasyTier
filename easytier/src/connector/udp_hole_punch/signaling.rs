use std::{fmt, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use easytier_core::hole_punch::udp::{
    SelectPunchListener, SelectPunchListenerResponse as CoreSelectPunchListenerResponse,
    SendPunchPacketBothEasySym, SendPunchPacketBothEasySymResponse as CoreBothEasySymResponse,
    SendPunchPacketCone, SendPunchPacketEasySym, SendPunchPacketHardSym,
    SendPunchPacketHardSymResponse as CoreHardSymResponse, UdpHolePunchSignalError,
    UdpHolePunchSignaling,
};

use crate::{
    common::PeerId,
    peers::peer_manager::PeerManager,
    proto::{
        peer_rpc::{
            SelectPunchListenerRequest, SendPunchPacketBothEasySymRequest,
            SendPunchPacketConeRequest, SendPunchPacketEasySymRequest,
            SendPunchPacketHardSymRequest, UdpHolePunchRpc, UdpHolePunchRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
};

#[derive(Clone)]
pub(crate) struct PeerRpcUdpHolePunchSignaling {
    peer_mgr: Arc<PeerManager>,
}

impl fmt::Debug for PeerRpcUdpHolePunchSignaling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerRpcUdpHolePunchSignaling")
            .field("my_peer_id", &self.peer_mgr.my_peer_id())
            .finish_non_exhaustive()
    }
}

impl PeerRpcUdpHolePunchSignaling {
    pub(crate) fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self { peer_mgr }
    }

    fn rpc_stub(
        &self,
        dst_peer_id: PeerId,
    ) -> Box<dyn UdpHolePunchRpc<Controller = BaseController> + Send + Sync + 'static> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                self.peer_mgr.get_global_ctx().get_network_name(),
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
    ) -> Result<CoreHardSymResponse, UdpHolePunchSignalError> {
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

        Ok(CoreHardSymResponse {
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
    ) -> Result<CoreBothEasySymResponse, UdpHolePunchSignalError> {
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

        Ok(CoreBothEasySymResponse {
            is_busy: response.is_busy,
            base_mapped_addr: response.base_mapped_addr.map(SocketAddr::from),
        })
    }
}
