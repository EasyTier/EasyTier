use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Error;
use both_easy_sym::PunchBothEasySymHoleServer;
use common::{
    PunchHoleServerCommon, RuntimeUdpHolePunchPeerSource, RuntimeUdpHolePunchRuntime,
    RuntimeUdpHolePunchTunnelSink,
};
use cone::PunchConeHoleServer;
use easytier_core::hole_punch::udp::{
    BLACKLIST_TIMEOUT_SEC, SelectPunchListener as CoreSelectPunchListener,
    SelectPunchListenerResponse as CoreSelectPunchListenerResponse,
    SendPunchPacketBothEasySym as CoreSendPunchPacketBothEasySym,
    SendPunchPacketBothEasySymResponse as CoreSendPunchPacketBothEasySymResponse,
    SendPunchPacketCone as CoreSendPunchPacketCone,
    SendPunchPacketEasySym as CoreSendPunchPacketEasySym,
    SendPunchPacketHardSym as CoreSendPunchPacketHardSym,
    SendPunchPacketHardSymResponse as CoreSendPunchPacketHardSymResponse,
    UdpHolePunchConnector as CoreUdpHolePunchConnector, UdpHolePunchInbound,
    UdpHolePunchServerCommon as CoreUdpHolePunchServerCommon, UdpHolePunchSignalError,
    get_udp_sym_punch_lock, should_blacklist_signal_error,
};
use once_cell::sync::Lazy;
use signaling::PeerRpcUdpHolePunchSignaling;
use sym_to_cone::PunchSymToConeHoleServer;

use crate::{
    common::PeerId,
    peers::peer_manager::PeerManager,
    proto::{
        common::Void,
        peer_rpc::{
            SelectPunchListenerRequest, SelectPunchListenerResponse,
            SendPunchPacketBothEasySymRequest, SendPunchPacketBothEasySymResponse,
            SendPunchPacketConeRequest, SendPunchPacketEasySymRequest,
            SendPunchPacketHardSymRequest, SendPunchPacketHardSymResponse, UdpHolePunchRpc,
            UdpHolePunchRpcServer,
        },
        rpc_types::{self, controller::BaseController},
    },
};

pub(crate) mod both_easy_sym;
pub(crate) mod common;
pub(crate) mod cone;
pub(crate) mod signaling;
pub(crate) mod sym_to_cone;

pub use easytier_core::hole_punch::udp::BackOff;

pub static RUN_TESTING: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

struct UdpHolePunchServer {
    common: Arc<PunchHoleServerCommon>,
    cone_server: PunchConeHoleServer,
    sym_to_cone_server: PunchSymToConeHoleServer,
    both_easy_sym_server: PunchBothEasySymHoleServer,
}

impl UdpHolePunchServer {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let common = Arc::new(PunchHoleServerCommon::new(peer_mgr.clone()));
        let cone_server = PunchConeHoleServer::new(common.clone());
        let sym_to_cone_server = PunchSymToConeHoleServer::new(common.clone());
        let core_common = Arc::new(CoreUdpHolePunchServerCommon::new(
            Arc::new(RuntimeUdpHolePunchRuntime::new(peer_mgr.get_global_ctx())),
            Arc::new(RuntimeUdpHolePunchTunnelSink::new(peer_mgr)),
        ));
        let both_easy_sym_server = PunchBothEasySymHoleServer::new(core_common);

        Arc::new(Self {
            common,
            cone_server,
            sym_to_cone_server,
            both_easy_sym_server,
        })
    }
}

fn rpc_error_to_signal_error(error: rpc_types::error::Error) -> UdpHolePunchSignalError {
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

#[async_trait::async_trait]
impl UdpHolePunchInbound for UdpHolePunchServer {
    async fn select_punch_listener(
        &self,
        request: CoreSelectPunchListener,
    ) -> Result<CoreSelectPunchListenerResponse, UdpHolePunchSignalError> {
        let (_, addr) = self
            .common
            .select_listener(request.force_new, request.prefer_port_mapping)
            .await
            .ok_or_else(|| {
                UdpHolePunchSignalError::RemoteRejected("no listener available".into())
            })?;

        Ok(CoreSelectPunchListenerResponse {
            listener_mapped_addr: addr,
        })
    }

    async fn send_punch_packet_cone(
        &self,
        request: CoreSendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError> {
        self.cone_server
            .send_punch_packet_cone(
                BaseController::default(),
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
            .map_err(rpc_error_to_signal_error)
    }

    async fn send_punch_packet_hard_sym(
        &self,
        request: CoreSendPunchPacketHardSym,
    ) -> Result<CoreSendPunchPacketHardSymResponse, UdpHolePunchSignalError> {
        let _locked = get_udp_sym_punch_lock(self.common.get_peer_mgr().my_peer_id())
            .try_lock_owned()
            .map_err(|_| {
                UdpHolePunchSignalError::RemoteRejected("sym punch lock is busy".into())
            })?;
        let response = self
            .sym_to_cone_server
            .send_punch_packet_hard_sym(SendPunchPacketHardSymRequest {
                listener_mapped_addr: Some(request.listener_mapped_addr.into()),
                public_ips: request.public_ips.into_iter().map(Into::into).collect(),
                transaction_id: request.transaction_id,
                port_index: request.port_index,
                round: request.round,
            })
            .await
            .map_err(rpc_error_to_signal_error)?;

        Ok(CoreSendPunchPacketHardSymResponse {
            next_port_index: response.next_port_index,
        })
    }

    async fn send_punch_packet_easy_sym(
        &self,
        request: CoreSendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError> {
        let _locked = get_udp_sym_punch_lock(self.common.get_peer_mgr().my_peer_id())
            .try_lock_owned()
            .map_err(|_| {
                UdpHolePunchSignalError::RemoteRejected("sym punch lock is busy".into())
            })?;
        self.sym_to_cone_server
            .send_punch_packet_easy_sym(SendPunchPacketEasySymRequest {
                listener_mapped_addr: Some(request.listener_mapped_addr.into()),
                public_ips: request.public_ips.into_iter().map(Into::into).collect(),
                transaction_id: request.transaction_id,
                base_port_num: request.base_port_num,
                max_port_num: request.max_port_num,
                is_incremental: request.is_incremental,
            })
            .await
            .map_err(rpc_error_to_signal_error)
    }

    async fn send_punch_packet_both_easy_sym(
        &self,
        request: CoreSendPunchPacketBothEasySym,
    ) -> Result<CoreSendPunchPacketBothEasySymResponse, UdpHolePunchSignalError> {
        let _locked = get_udp_sym_punch_lock(self.common.get_peer_mgr().my_peer_id())
            .try_lock_owned()
            .map_err(|_| {
                UdpHolePunchSignalError::RemoteRejected("sym punch lock is busy".into())
            })?;
        let response = self
            .both_easy_sym_server
            .send_punch_packet_both_easy_sym(SendPunchPacketBothEasySymRequest {
                transaction_id: request.transaction_id,
                public_ip: Some(request.public_ip.into()),
                dst_port_num: request.dst_port_num,
                udp_socket_count: request.udp_socket_count,
                wait_time_ms: request.wait_time_ms,
            })
            .await
            .map_err(rpc_error_to_signal_error)?;

        Ok(CoreSendPunchPacketBothEasySymResponse {
            is_busy: response.is_busy,
            base_mapped_addr: response.base_mapped_addr.map(Into::into),
        })
    }
}

#[async_trait::async_trait]
impl UdpHolePunchRpc for UdpHolePunchServer {
    type Controller = BaseController;

    async fn select_punch_listener(
        &self,
        _ctrl: Self::Controller,
        input: SelectPunchListenerRequest,
    ) -> rpc_types::error::Result<SelectPunchListenerResponse> {
        let response = UdpHolePunchInbound::select_punch_listener(
            self,
            CoreSelectPunchListener {
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

    /// send packet to one remote_addr, used by nat1-3 to nat1-3
    async fn send_punch_packet_cone(
        &self,
        _ctrl: Self::Controller,
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
            CoreSendPunchPacketCone {
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

    /// send packet to multiple remote_addr (birthday attack), used by nat4 to nat1-3
    async fn send_punch_packet_hard_sym(
        &self,
        _ctrl: Self::Controller,
        input: SendPunchPacketHardSymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketHardSymResponse> {
        let listener_addr = input.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "try_punch_symmetric request missing listener_addr"
        ))?;
        let response = UdpHolePunchInbound::send_punch_packet_hard_sym(
            self,
            CoreSendPunchPacketHardSym {
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
        _ctrl: Self::Controller,
        input: SendPunchPacketEasySymRequest,
    ) -> rpc_types::error::Result<Void> {
        let listener_addr = input.listener_mapped_addr.ok_or(anyhow::anyhow!(
            "send_punch_packet_easy_sym request missing listener_addr"
        ))?;
        UdpHolePunchInbound::send_punch_packet_easy_sym(
            self,
            CoreSendPunchPacketEasySym {
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

    /// nat4 to nat4 (both predictably)
    async fn send_punch_packet_both_easy_sym(
        &self,
        _ctrl: Self::Controller,
        input: SendPunchPacketBothEasySymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketBothEasySymResponse> {
        let public_ip = input
            .public_ip
            .ok_or(anyhow::anyhow!("public_ip is required"))?;
        let response = UdpHolePunchInbound::send_punch_packet_both_easy_sym(
            self,
            CoreSendPunchPacketBothEasySym {
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

pub fn handle_rpc_result<T>(
    ret: Result<T, rpc_types::error::Error>,
    dst_peer_id: PeerId,
    blacklist: &timedmap::TimedMap<PeerId, ()>,
) -> Result<T, rpc_types::error::Error> {
    match ret {
        Ok(ret) => Ok(ret),
        Err(e) => {
            if matches!(e, rpc_types::error::Error::InvalidServiceKey(_, _)) {
                blacklist.insert(dst_peer_id, (), Duration::from_secs(BLACKLIST_TIMEOUT_SEC));
            }
            Err(e)
        }
    }
}

pub fn handle_signal_result<T>(
    ret: Result<T, UdpHolePunchSignalError>,
    dst_peer_id: PeerId,
    blacklist: &timedmap::TimedMap<PeerId, ()>,
) -> Result<T, UdpHolePunchSignalError> {
    match ret {
        Ok(ret) => Ok(ret),
        Err(e) => {
            if should_blacklist_signal_error(&e) {
                blacklist.insert(dst_peer_id, (), Duration::from_secs(BLACKLIST_TIMEOUT_SEC));
            }
            Err(e)
        }
    }
}

type RuntimeUdpHolePunchConnector = CoreUdpHolePunchConnector<
    RuntimeUdpHolePunchPeerSource,
    PeerRpcUdpHolePunchSignaling,
    RuntimeUdpHolePunchTunnelSink,
    RuntimeUdpHolePunchRuntime,
>;

pub struct UdpHolePunchConnector {
    server: Arc<UdpHolePunchServer>,
    client: RuntimeUdpHolePunchConnector,
    peer_mgr: Arc<PeerManager>,
}

// Currently support:
// Symmetric -> Full Cone
// Any Type of Full Cone -> Any Type of Full Cone

// if same level of full cone, node with smaller peer_id will be the initiator
// if different level of full cone, node with more strict level will be the initiator

impl UdpHolePunchConnector {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let client = RuntimeUdpHolePunchConnector::new(
            Arc::new(RuntimeUdpHolePunchPeerSource::new(peer_mgr.clone())),
            Arc::new(PeerRpcUdpHolePunchSignaling::new(peer_mgr.clone())),
            Arc::new(RuntimeUdpHolePunchTunnelSink::new(peer_mgr.clone())),
            Arc::new(RuntimeUdpHolePunchRuntime::new(peer_mgr.get_global_ctx())),
            Some(peer_mgr.p2p_demand_notify()),
        );
        client.set_try_cone_before_sym(!RUN_TESTING.load(Ordering::Relaxed));

        Self {
            server: UdpHolePunchServer::new(peer_mgr.clone()),
            client,
            peer_mgr,
        }
    }

    pub async fn run_as_client(&mut self) -> Result<(), Error> {
        self.client.run_as_client();
        Ok(())
    }

    pub async fn run_as_server(&mut self) -> Result<(), Error> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                UdpHolePunchRpcServer::new(Arc::downgrade(&self.server)),
                &self.peer_mgr.get_global_ctx().get_network_name(),
            );

        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let global_ctx = self.peer_mgr.get_global_ctx();

        if global_ctx.get_flags().disable_udp_hole_punching {
            return Ok(());
        }

        self.run_as_client().await?;
        self.run_as_server().await?;

        Ok(())
    }

    #[cfg(test)]
    pub async fn run_immediately_for_test(&self) {
        self.client.run_immediately().await;
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::Arc;
    use std::time::Duration;

    use easytier_core::hole_punch::udp::{UdpHolePunchPeerSource, collect_udp_punch_tasks};

    use crate::common::stun::MockStunInfoCollector;
    use crate::peers::{
        peer_manager::PeerManager,
        tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
    };
    use crate::proto::common::NatType;
    use crate::tunnel::common::tests::wait_for_condition;

    use super::{RUN_TESTING, UdpHolePunchConnector, common::RuntimeUdpHolePunchPeerSource};

    pub fn replace_stun_info_collector(peer_mgr: Arc<PeerManager>, udp_nat_type: NatType) {
        let collector = Box::new(MockStunInfoCollector { udp_nat_type });
        peer_mgr
            .get_global_ctx()
            .replace_stun_info_collector(collector);
    }

    pub async fn create_mock_peer_manager_with_mock_stun(
        udp_nat_type: NatType,
    ) -> Arc<PeerManager> {
        let p_a = create_mock_peer_manager().await;
        let mut flags = p_a.get_global_ctx().get_flags();
        flags.disable_upnp = true;
        p_a.get_global_ctx().set_flags(flags);
        replace_stun_info_collector(p_a.clone(), udp_nat_type);
        p_a
    }

    async fn collect_lazy_punch_peers(peer_mgr: Arc<PeerManager>) -> Vec<u32> {
        let source = RuntimeUdpHolePunchPeerSource::new(peer_mgr.clone());
        let my_nat_type = peer_mgr
            .get_global_ctx()
            .get_stun_info_collector()
            .get_stun_info()
            .udp_nat_type;
        let my_nat_type = NatType::try_from(my_nat_type)
            .unwrap_or(NatType::Unknown)
            .into();
        collect_udp_punch_tasks(
            source.local_peer_id(),
            my_nat_type,
            source.p2p_policy_flags(),
            source.candidates().await,
            |_| false,
        )
        .into_iter()
        .map(|task| task.dst_peer_id)
        .collect()
    }

    #[rstest::rstest]
    #[tokio::test]
    pub async fn test_hole_punching_blacklist(
        #[values(NatType::Symmetric, NatType::PortRestricted, NatType::Unknown)] nat_type: NatType,
    ) {
        RUN_TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager_with_mock_stun(nat_type).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());

        hole_punching_a.run().await.unwrap();

        hole_punching_a.client.run_immediately().await;

        wait_for_condition(
            || async {
                hole_punching_a
                    .client
                    .data()
                    .is_blacklisted(p_c.my_peer_id())
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn lazy_p2p_collects_udp_hole_punch_tasks_only_after_recent_traffic() {
        let p_a = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_b = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;
        let p_c = create_mock_peer_manager_with_mock_stun(NatType::PortRestricted).await;

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.lazy_p2p = true;
        p_a.get_global_ctx().set_flags(flags);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        assert!(
            !collect_lazy_punch_peers(p_a.clone())
                .await
                .contains(&p_c.my_peer_id())
        );

        p_a.mark_recent_traffic(p_c.my_peer_id());

        assert!(
            collect_lazy_punch_peers(p_a.clone())
                .await
                .contains(&p_c.my_peer_id())
        );
    }
}
