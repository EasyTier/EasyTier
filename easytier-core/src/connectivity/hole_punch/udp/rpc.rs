use std::{fmt, net::SocketAddr, sync::Arc};

use async_trait::async_trait;

use crate::{
    config::PeerId,
    connectivity::hole_punch::udp::{
        SelectPunchListener, SelectPunchListenerResponse as CoreSelectPunchListenerResponse,
        SendPunchPacketBothEasySym,
        SendPunchPacketBothEasySymResponse as CoreSendPunchPacketBothEasySymResponse,
        SendPunchPacketCone, SendPunchPacketEasySym, SendPunchPacketHardSym,
        SendPunchPacketHardSymResponse as CoreSendPunchPacketHardSymResponse, UdpHolePunchInbound,
        UdpHolePunchRuntime, UdpHolePunchServer as CoreUdpHolePunchServer, UdpHolePunchSignalError,
        UdpHolePunchSignaling, UdpHolePunchTransportSink, UdpSymPunchLock,
    },
    connectivity::stun::StunInfoProvider,
    proto::{
        common::Void,
        peer_rpc::{
            SelectPunchListenerRequest, SelectPunchListenerResponse,
            SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse,
            SendPunchPacketConeRequest, SendPunchPacketEasySymRequest,
            SendPunchPacketHardSymRequest, SendPunchPacketHardSymResponse, UdpHolePunchRpc,
        },
        rpc_types::{self, controller::BaseController},
    },
};

const CONE_RPC_TIMEOUT_MS: i32 = 4000;
const SYMMETRIC_RPC_TIMEOUT_MS: i32 = 4000;
const BOTH_EASY_SYMMETRIC_RPC_TIMEOUT_MS: i32 = 2000;

fn cone_controller() -> BaseController {
    BaseController {
        timeout_ms: CONE_RPC_TIMEOUT_MS,
        ..Default::default()
    }
}

fn symmetric_controller() -> BaseController {
    BaseController {
        timeout_ms: SYMMETRIC_RPC_TIMEOUT_MS,
        trace_id: 0,
        ..Default::default()
    }
}

fn both_easy_symmetric_controller() -> BaseController {
    BaseController {
        timeout_ms: BOTH_EASY_SYMMETRIC_RPC_TIMEOUT_MS,
        ..Default::default()
    }
}

fn select_listener_request_to_rpc(request: SelectPunchListener) -> SelectPunchListenerRequest {
    SelectPunchListenerRequest {
        force_new: request.force_new,
        prefer_port_mapping: request.prefer_port_mapping,
    }
}

fn select_listener_request_from_rpc(input: SelectPunchListenerRequest) -> SelectPunchListener {
    SelectPunchListener {
        force_new: input.force_new,
        prefer_port_mapping: input.prefer_port_mapping,
    }
}

fn select_listener_response_from_rpc(
    response: SelectPunchListenerResponse,
) -> Result<CoreSelectPunchListenerResponse, UdpHolePunchSignalError> {
    Ok(CoreSelectPunchListenerResponse {
        listener_mapped_addr: SocketAddr::from(
            response
                .listener_mapped_addr
                .ok_or_else(|| missing_field("listener_mapped_addr"))?,
        ),
    })
}

fn select_listener_response_to_rpc(
    response: CoreSelectPunchListenerResponse,
) -> SelectPunchListenerResponse {
    SelectPunchListenerResponse {
        listener_mapped_addr: Some(response.listener_mapped_addr.into()),
    }
}

fn cone_request_to_rpc(request: SendPunchPacketCone) -> SendPunchPacketConeRequest {
    SendPunchPacketConeRequest {
        listener_mapped_addr: Some(request.listener_mapped_addr.into()),
        dest_addr: Some(request.dest_addr.into()),
        transaction_id: request.transaction_id,
        packet_count_per_batch: request.packet_count_per_batch,
        packet_batch_count: request.packet_batch_count,
        packet_interval_ms: request.packet_interval_ms,
    }
}

fn hard_symmetric_request_to_rpc(request: SendPunchPacketHardSym) -> SendPunchPacketHardSymRequest {
    SendPunchPacketHardSymRequest {
        listener_mapped_addr: Some(request.listener_mapped_addr.into()),
        public_ips: request.public_ips.into_iter().map(Into::into).collect(),
        transaction_id: request.transaction_id,
        port_index: request.port_index,
        round: request.round,
    }
}

fn easy_symmetric_request_to_rpc(request: SendPunchPacketEasySym) -> SendPunchPacketEasySymRequest {
    SendPunchPacketEasySymRequest {
        listener_mapped_addr: Some(request.listener_mapped_addr.into()),
        public_ips: request.public_ips.into_iter().map(Into::into).collect(),
        transaction_id: request.transaction_id,
        base_port_num: request.base_port_num,
        max_port_num: request.max_port_num,
        is_incremental: request.is_incremental,
    }
}

fn both_easy_symmetric_request_to_rpc(
    request: SendPunchPacketBothEasySym,
) -> SendPunchPacketBothEasySymRequest {
    SendPunchPacketBothEasySymRequest {
        transaction_id: request.transaction_id,
        public_ip: Some(request.public_ip.into()),
        dst_port_num: request.dst_port_num,
        udp_socket_count: request.udp_socket_count,
        wait_time_ms: request.wait_time_ms,
    }
}

fn hard_symmetric_response_from_rpc(
    response: SendPunchPacketHardSymResponse,
) -> CoreSendPunchPacketHardSymResponse {
    CoreSendPunchPacketHardSymResponse {
        next_port_index: response.next_port_index,
    }
}

fn hard_symmetric_response_to_rpc(
    response: CoreSendPunchPacketHardSymResponse,
) -> SendPunchPacketHardSymResponse {
    SendPunchPacketHardSymResponse {
        next_port_index: response.next_port_index,
    }
}

fn both_easy_symmetric_response_from_rpc(
    response: SendPunchPacketBothEasySymResponse,
) -> CoreSendPunchPacketBothEasySymResponse {
    CoreSendPunchPacketBothEasySymResponse {
        is_busy: response.is_busy,
        base_mapped_addr: response.base_mapped_addr.map(SocketAddr::from),
    }
}

fn both_easy_symmetric_response_to_rpc(
    response: CoreSendPunchPacketBothEasySymResponse,
) -> SendPunchPacketBothEasySymResponse {
    SendPunchPacketBothEasySymResponse {
        is_busy: response.is_busy,
        base_mapped_addr: response.base_mapped_addr.map(Into::into),
    }
}

/// Narrow source of peer-scoped UDP hole-punch RPC stubs.
///
/// Implemented only by the sealed peer adapter in `super::peer_adapters`.
pub trait UdpHolePunchRpcSource: Send + Sync + 'static {
    fn local_peer_id(&self) -> PeerId;

    fn rpc_stub(
        &self,
        dst_peer_id: PeerId,
    ) -> Box<dyn UdpHolePunchRpc<Controller = BaseController> + Send + Sync + 'static>;
}

#[derive(Clone)]
pub(super) struct PeerRpcUdpHolePunchSignaling<P>
where
    P: UdpHolePunchRpcSource,
{
    rpc_source: Arc<P>,
}

impl<P> fmt::Debug for PeerRpcUdpHolePunchSignaling<P>
where
    P: UdpHolePunchRpcSource,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRpcUdpHolePunchSignaling")
            .field("my_peer_id", &self.rpc_source.local_peer_id())
            .finish_non_exhaustive()
    }
}

impl<P> PeerRpcUdpHolePunchSignaling<P>
where
    P: UdpHolePunchRpcSource,
{
    pub(super) fn new(rpc_source: Arc<P>) -> Self {
        Self { rpc_source }
    }

    fn rpc_stub(
        &self,
        dst_peer_id: PeerId,
    ) -> Box<dyn UdpHolePunchRpc<Controller = BaseController> + Send + Sync + 'static> {
        self.rpc_source.rpc_stub(dst_peer_id)
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
impl<P> UdpHolePunchSignaling for PeerRpcUdpHolePunchSignaling<P>
where
    P: UdpHolePunchRpcSource,
{
    async fn select_punch_listener(
        &self,
        dst_peer_id: PeerId,
        request: SelectPunchListener,
    ) -> Result<CoreSelectPunchListenerResponse, UdpHolePunchSignalError> {
        let response = self
            .rpc_stub(dst_peer_id)
            .select_punch_listener(
                BaseController::default(),
                select_listener_request_to_rpc(request),
            )
            .await
            .map_err(map_rpc_error)?;

        select_listener_response_from_rpc(response)
    }

    async fn send_punch_packet_cone(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError> {
        self.rpc_stub(dst_peer_id)
            .send_punch_packet_cone(cone_controller(), cone_request_to_rpc(request))
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
                symmetric_controller(),
                hard_symmetric_request_to_rpc(request),
            )
            .await
            .map_err(map_rpc_error)?;

        Ok(hard_symmetric_response_from_rpc(response))
    }

    async fn send_punch_packet_easy_sym(
        &self,
        dst_peer_id: PeerId,
        request: SendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError> {
        self.rpc_stub(dst_peer_id)
            .send_punch_packet_easy_sym(
                symmetric_controller(),
                easy_symmetric_request_to_rpc(request),
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
                both_easy_symmetric_controller(),
                both_easy_symmetric_request_to_rpc(request),
            )
            .await
            .map_err(map_rpc_error)?;

        Ok(both_easy_symmetric_response_from_rpc(response))
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

fn cone_request_from_rpc(
    input: SendPunchPacketConeRequest,
) -> rpc_types::error::Result<SendPunchPacketCone> {
    let listener_addr = input.listener_mapped_addr.ok_or(anyhow::anyhow!(
        "send_punch_packet_for_cone request missing listener_mapped_addr"
    ))?;
    let dest_addr = input.dest_addr.ok_or(anyhow::anyhow!(
        "send_punch_packet_for_cone request missing dest_addr"
    ))?;
    Ok(SendPunchPacketCone {
        listener_mapped_addr: listener_addr.into(),
        dest_addr: dest_addr.into(),
        transaction_id: input.transaction_id,
        packet_count_per_batch: input.packet_count_per_batch,
        packet_batch_count: input.packet_batch_count,
        packet_interval_ms: input.packet_interval_ms,
    })
}

fn hard_symmetric_request_from_rpc(
    input: SendPunchPacketHardSymRequest,
) -> rpc_types::error::Result<SendPunchPacketHardSym> {
    let listener_addr = input.listener_mapped_addr.ok_or(anyhow::anyhow!(
        "try_punch_symmetric request missing listener_addr"
    ))?;
    Ok(SendPunchPacketHardSym {
        listener_mapped_addr: listener_addr.into(),
        public_ips: input.public_ips.into_iter().map(Into::into).collect(),
        transaction_id: input.transaction_id,
        port_index: input.port_index,
        round: input.round,
    })
}

fn easy_symmetric_request_from_rpc(
    input: SendPunchPacketEasySymRequest,
) -> rpc_types::error::Result<SendPunchPacketEasySym> {
    let listener_addr = input.listener_mapped_addr.ok_or(anyhow::anyhow!(
        "send_punch_packet_easy_sym request missing listener_addr"
    ))?;
    Ok(SendPunchPacketEasySym {
        listener_mapped_addr: listener_addr.into(),
        public_ips: input.public_ips.into_iter().map(Into::into).collect(),
        transaction_id: input.transaction_id,
        base_port_num: input.base_port_num,
        max_port_num: input.max_port_num,
        is_incremental: input.is_incremental,
    })
}

fn both_easy_symmetric_request_from_rpc(
    input: SendPunchPacketBothEasySymRequest,
) -> rpc_types::error::Result<SendPunchPacketBothEasySym> {
    let public_ip = input
        .public_ip
        .ok_or(anyhow::anyhow!("public_ip is required"))?;
    Ok(SendPunchPacketBothEasySym {
        transaction_id: input.transaction_id,
        public_ip: public_ip.into(),
        dst_port_num: input.dst_port_num,
        udp_socket_count: input.udp_socket_count,
        wait_time_ms: input.wait_time_ms,
    })
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
            select_listener_request_from_rpc(input),
        )
        .await
        .map_err(signal_error_to_rpc_error)?;

        Ok(select_listener_response_to_rpc(response))
    }

    async fn send_punch_packet_cone(
        &self,
        _controller: Self::Controller,
        input: SendPunchPacketConeRequest,
    ) -> rpc_types::error::Result<Void> {
        UdpHolePunchInbound::send_punch_packet_cone(self, cone_request_from_rpc(input)?)
            .await
            .map_err(signal_error_to_rpc_error)?;

        Ok(Void::default())
    }

    async fn send_punch_packet_hard_sym(
        &self,
        _controller: Self::Controller,
        input: SendPunchPacketHardSymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketHardSymResponse> {
        let response = UdpHolePunchInbound::send_punch_packet_hard_sym(
            self,
            hard_symmetric_request_from_rpc(input)?,
        )
        .await
        .map_err(signal_error_to_rpc_error)?;

        Ok(hard_symmetric_response_to_rpc(response))
    }

    async fn send_punch_packet_easy_sym(
        &self,
        _controller: Self::Controller,
        input: SendPunchPacketEasySymRequest,
    ) -> rpc_types::error::Result<Void> {
        UdpHolePunchInbound::send_punch_packet_easy_sym(
            self,
            easy_symmetric_request_from_rpc(input)?,
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
        let response = UdpHolePunchInbound::send_punch_packet_both_easy_sym(
            self,
            both_easy_symmetric_request_from_rpc(input)?,
        )
        .await
        .map_err(signal_error_to_rpc_error)?;

        Ok(both_easy_symmetric_response_to_rpc(response))
    }
}

#[cfg(test)]
mod tests {
    use std::{future, net::Ipv4Addr, time::Duration};

    use super::*;

    #[test]
    fn outbound_rpc_controllers_preserve_timeouts() {
        assert_eq!(cone_controller().timeout_ms, 4000);
        assert_eq!(symmetric_controller().timeout_ms, 4000);
        assert_eq!(symmetric_controller().trace_id, 0);
        assert_eq!(both_easy_symmetric_controller().timeout_ms, 2000);
    }

    #[test]
    fn select_listener_dto_preserves_fields_and_requires_response_addr() {
        let domain_request = SelectPunchListener {
            force_new: true,
            prefer_port_mapping: false,
        };
        let rpc_request = select_listener_request_to_rpc(domain_request.clone());
        assert!(rpc_request.force_new);
        assert!(!rpc_request.prefer_port_mapping);
        assert_eq!(
            select_listener_request_from_rpc(SelectPunchListenerRequest {
                force_new: true,
                prefer_port_mapping: false,
            }),
            domain_request
        );

        let mapped_addr: SocketAddr = "198.51.100.1:31001".parse().unwrap();
        let core_response = CoreSelectPunchListenerResponse {
            listener_mapped_addr: mapped_addr,
        };
        let rpc_response = select_listener_response_to_rpc(core_response.clone());
        assert_eq!(
            SocketAddr::from(rpc_response.listener_mapped_addr.unwrap()),
            mapped_addr
        );
        assert_eq!(
            select_listener_response_from_rpc(rpc_response).unwrap(),
            core_response
        );

        let error =
            select_listener_response_from_rpc(SelectPunchListenerResponse::default()).unwrap_err();
        assert_eq!(
            error,
            UdpHolePunchSignalError::RemoteRejected("missing listener_mapped_addr".to_owned())
        );
    }

    #[test]
    fn cone_dto_round_trip_preserves_all_fields() {
        let request = SendPunchPacketCone {
            listener_mapped_addr: "198.51.100.2:31002".parse().unwrap(),
            dest_addr: "203.0.113.2:32002".parse().unwrap(),
            transaction_id: 12,
            packet_count_per_batch: 3,
            packet_batch_count: 4,
            packet_interval_ms: 500,
        };

        let rpc = cone_request_to_rpc(request.clone());
        assert_eq!(
            SocketAddr::from(rpc.listener_mapped_addr.unwrap()),
            request.listener_mapped_addr
        );
        assert_eq!(SocketAddr::from(rpc.dest_addr.unwrap()), request.dest_addr);
        assert_eq!(rpc.transaction_id, 12);
        assert_eq!(rpc.packet_count_per_batch, 3);
        assert_eq!(rpc.packet_batch_count, 4);
        assert_eq!(rpc.packet_interval_ms, 500);
        assert_eq!(cone_request_from_rpc(rpc).unwrap(), request);
    }

    #[test]
    fn hard_symmetric_dto_round_trip_preserves_all_fields() {
        let request = SendPunchPacketHardSym {
            listener_mapped_addr: "198.51.100.3:31003".parse().unwrap(),
            public_ips: vec![Ipv4Addr::new(203, 0, 113, 3), Ipv4Addr::new(203, 0, 113, 4)],
            transaction_id: 13,
            port_index: 17,
            round: 19,
        };

        let rpc = hard_symmetric_request_to_rpc(request.clone());
        assert_eq!(
            SocketAddr::from(rpc.listener_mapped_addr.unwrap()),
            request.listener_mapped_addr
        );
        assert_eq!(
            rpc.public_ips
                .iter()
                .cloned()
                .map(Ipv4Addr::from)
                .collect::<Vec<_>>(),
            request.public_ips
        );
        assert_eq!(rpc.transaction_id, 13);
        assert_eq!(rpc.port_index, 17);
        assert_eq!(rpc.round, 19);
        assert_eq!(hard_symmetric_request_from_rpc(rpc).unwrap(), request);
    }

    #[test]
    fn easy_symmetric_dto_round_trip_preserves_all_fields() {
        let request = SendPunchPacketEasySym {
            listener_mapped_addr: "198.51.100.5:31005".parse().unwrap(),
            public_ips: vec![Ipv4Addr::new(203, 0, 113, 5)],
            transaction_id: 15,
            base_port_num: 33000,
            max_port_num: 51,
            is_incremental: true,
        };

        let rpc = easy_symmetric_request_to_rpc(request.clone());
        assert_eq!(
            SocketAddr::from(rpc.listener_mapped_addr.unwrap()),
            request.listener_mapped_addr
        );
        assert_eq!(
            rpc.public_ips
                .iter()
                .cloned()
                .map(Ipv4Addr::from)
                .collect::<Vec<_>>(),
            request.public_ips
        );
        assert_eq!(rpc.transaction_id, 15);
        assert_eq!(rpc.base_port_num, 33000);
        assert_eq!(rpc.max_port_num, 51);
        assert!(rpc.is_incremental);
        assert_eq!(easy_symmetric_request_from_rpc(rpc).unwrap(), request);
    }

    #[test]
    fn both_easy_symmetric_dto_round_trip_preserves_all_fields() {
        let request = SendPunchPacketBothEasySym {
            udp_socket_count: 25,
            public_ip: Ipv4Addr::new(203, 0, 113, 6),
            transaction_id: 16,
            dst_port_num: 34000,
            wait_time_ms: 2500,
        };

        let rpc = both_easy_symmetric_request_to_rpc(request.clone());
        assert_eq!(rpc.udp_socket_count, 25);
        assert_eq!(Ipv4Addr::from(rpc.public_ip.unwrap()), request.public_ip);
        assert_eq!(rpc.transaction_id, 16);
        assert_eq!(rpc.dst_port_num, 34000);
        assert_eq!(rpc.wait_time_ms, 2500);
        assert_eq!(both_easy_symmetric_request_from_rpc(rpc).unwrap(), request);
    }

    #[test]
    fn rpc_response_dtos_preserve_all_fields() {
        let hard_response = CoreSendPunchPacketHardSymResponse {
            next_port_index: 41,
        };
        let hard_rpc = hard_symmetric_response_to_rpc(hard_response.clone());
        assert_eq!(hard_rpc.next_port_index, 41);
        assert_eq!(hard_symmetric_response_from_rpc(hard_rpc), hard_response);

        let both_response = CoreSendPunchPacketBothEasySymResponse {
            is_busy: true,
            base_mapped_addr: Some("198.51.100.8:31008".parse().unwrap()),
        };
        let both_rpc = both_easy_symmetric_response_to_rpc(both_response.clone());
        assert!(both_rpc.is_busy);
        assert_eq!(
            SocketAddr::from(both_rpc.base_mapped_addr.unwrap()),
            both_response.base_mapped_addr.unwrap()
        );
        assert_eq!(
            both_easy_symmetric_response_from_rpc(both_rpc),
            both_response
        );
    }

    #[test]
    fn inbound_rpc_dtos_reject_missing_required_fields() {
        let cone_listener_error = cone_request_from_rpc(SendPunchPacketConeRequest::default())
            .unwrap_err()
            .to_string();
        assert_eq!(
            cone_listener_error,
            "Rust error: send_punch_packet_for_cone request missing listener_mapped_addr"
        );

        let cone_dest_error = cone_request_from_rpc(SendPunchPacketConeRequest {
            listener_mapped_addr: Some("198.51.100.7:31007".parse::<SocketAddr>().unwrap().into()),
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
        assert_eq!(
            cone_dest_error,
            "Rust error: send_punch_packet_for_cone request missing dest_addr"
        );

        assert_eq!(
            hard_symmetric_request_from_rpc(SendPunchPacketHardSymRequest::default())
                .unwrap_err()
                .to_string(),
            "Rust error: try_punch_symmetric request missing listener_addr"
        );
        assert_eq!(
            easy_symmetric_request_from_rpc(SendPunchPacketEasySymRequest::default())
                .unwrap_err()
                .to_string(),
            "Rust error: send_punch_packet_easy_sym request missing listener_addr"
        );
        assert_eq!(
            both_easy_symmetric_request_from_rpc(SendPunchPacketBothEasySymRequest::default())
                .unwrap_err()
                .to_string(),
            "Rust error: public_ip is required"
        );
    }

    #[tokio::test]
    async fn rpc_errors_keep_domain_classification() {
        assert_eq!(
            map_rpc_error(rpc_types::error::Error::InvalidServiceKey(
                "service".to_owned(),
                "proto".to_owned()
            )),
            UdpHolePunchSignalError::InvalidServiceKey
        );
        assert_eq!(
            map_rpc_error(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "rejected"
            ))),
            UdpHolePunchSignalError::RemoteRejected("rejected".to_owned())
        );
        assert_eq!(
            map_rpc_error(rpc_types::error::Error::TunnelError("closed".to_owned())),
            UdpHolePunchSignalError::Transport("Tunnel error: closed".to_owned())
        );

        let elapsed = tokio::time::timeout(Duration::ZERO, future::pending::<()>())
            .await
            .unwrap_err();
        assert_eq!(
            map_rpc_error(rpc_types::error::Error::Timeout(elapsed)),
            UdpHolePunchSignalError::Timeout
        );
    }

    #[test]
    fn domain_errors_keep_rpc_classification() {
        assert!(matches!(
            signal_error_to_rpc_error(UdpHolePunchSignalError::InvalidServiceKey),
            rpc_types::error::Error::InvalidServiceKey(_, _)
        ));
        for (domain_error, expected_message) in [
            (UdpHolePunchSignalError::Timeout, "timeout"),
            (
                UdpHolePunchSignalError::RemoteRejected("rejected".to_owned()),
                "rejected",
            ),
            (
                UdpHolePunchSignalError::Transport("closed".to_owned()),
                "closed",
            ),
        ] {
            let rpc_types::error::Error::ExecutionError(error) =
                signal_error_to_rpc_error(domain_error)
            else {
                panic!("domain error should map to execution error");
            };
            assert_eq!(error.to_string(), expected_message);
        }
    }
}
