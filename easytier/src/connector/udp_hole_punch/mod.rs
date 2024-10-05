use std::sync::Arc;

use anyhow::Error;
use both_easy_sym::{PunchBothEasySymHoleClient, PunchBothEasySymHoleServer};
use common::{PunchHoleServerCommon, UdpNatType};
use cone::{PunchConeHoleClient, PunchConeHoleServer};
use crossbeam::atomic::AtomicCell;
use sym_to_cone::{PunchSymToConeHoleClient, PunchSymToConeHoleServer};
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    common::{stun::StunInfoCollectorTrait, PeerId},
    connector::direct::PeerManagerForDirectConnector,
    peers::{
        peer_manager::PeerManager,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        common::{NatType, Void},
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
pub(crate) mod sym_to_cone;

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
        let both_easy_sym_server = PunchBothEasySymHoleServer::new(common.clone());

        Arc::new(Self {
            common,
            cone_server,
            sym_to_cone_server,
            both_easy_sym_server,
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
        let (_, addr) = self
            .common
            .select_listener(input.force_new)
            .await
            .ok_or(anyhow::anyhow!("no listener available"))?;

        Ok(SelectPunchListenerResponse {
            listener_mapped_addr: Some(addr.into()),
        })
    }

    /// send packet to one remote_addr, used by nat1-3 to nat1-3
    async fn send_punch_packet_cone(
        &self,
        ctrl: Self::Controller,
        input: SendPunchPacketConeRequest,
    ) -> rpc_types::error::Result<Void> {
        self.cone_server.send_punch_packet_cone(ctrl, input).await
    }

    /// send packet to multiple remote_addr (birthday attack), used by nat4 to nat1-3
    async fn send_punch_packet_hard_sym(
        &self,
        _ctrl: Self::Controller,
        input: SendPunchPacketHardSymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketHardSymResponse> {
        self.sym_to_cone_server
            .send_punch_packet_hard_sym(input)
            .await
    }

    async fn send_punch_packet_easy_sym(
        &self,
        _ctrl: Self::Controller,
        input: SendPunchPacketEasySymRequest,
    ) -> rpc_types::error::Result<Void> {
        self.sym_to_cone_server
            .send_punch_packet_easy_sym(input)
            .await
            .map(|_| Void {})
    }

    /// nat4 to nat4 (both predictably)
    async fn send_punch_packet_both_easy_sym(
        &self,
        _ctrl: Self::Controller,
        input: SendPunchPacketBothEasySymRequest,
    ) -> rpc_types::error::Result<SendPunchPacketBothEasySymResponse> {
        self.both_easy_sym_server
            .send_punch_packet_both_easy_sym(input)
            .await
    }
}

struct BackOff {
    backoffs_ms: Vec<u64>,
    current_idx: usize,
}

impl BackOff {
    pub fn new(backoffs_ms: Vec<u64>) -> Self {
        Self {
            backoffs_ms,
            current_idx: 0,
        }
    }

    pub fn next_backoff(&mut self) -> u64 {
        let backoff = self.backoffs_ms[self.current_idx];
        self.current_idx = (self.current_idx + 1).min(self.backoffs_ms.len() - 1);
        backoff
    }

    pub fn reset(&mut self) {
        self.current_idx = 0;
    }

    pub async fn sleep_for_next_backoff(&mut self) {
        let backoff = self.next_backoff();
        if backoff > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
        }
    }
}

struct UdpHoePunchConnectorData {
    cone_client: PunchConeHoleClient,
    sym_to_cone_client: PunchSymToConeHoleClient,
    both_easy_sym_client: PunchBothEasySymHoleClient,
    peer_mgr: Arc<PeerManager>,
    last_my_nat_type: AtomicCell<UdpNatType>,

    // sym punch should be serialized
    sym_punch_lock: Mutex<()>,
}

impl UdpHoePunchConnectorData {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let cone_client = PunchConeHoleClient::new(peer_mgr.clone());
        let sym_to_cone_client = PunchSymToConeHoleClient::new(peer_mgr.clone());
        let both_easy_sym_client = PunchBothEasySymHoleClient::new(peer_mgr.clone());

        Arc::new(Self {
            cone_client,
            sym_to_cone_client,
            both_easy_sym_client,
            peer_mgr,
            last_my_nat_type: AtomicCell::new(UdpNatType::Unknown),
            sym_punch_lock: Mutex::new(()),
        })
    }

    #[tracing::instrument(skip(self))]
    async fn cone_to_cone(self: Arc<Self>, task_info: PunchTaskInfo) -> Result<(), Error> {
        let mut backoff = BackOff::new(vec![0, 1000, 2000, 4000, 4000, 8000, 8000, 16000]);

        loop {
            backoff.sleep_for_next_backoff().await;

            let ret = self
                .cone_client
                .do_hole_punching(task_info.dst_peer_id)
                .await;
            if let Err(e) = ret {
                tracing::info!(?e, "cone_to_cone hole punching failed");
                continue;
            }

            if let Err(e) = self.peer_mgr.add_client_tunnel(ret.unwrap()).await {
                tracing::warn!(?e, "cone_to_cone add client tunnel failed");
                continue;
            }

            break;
        }

        tracing::info!("cone_to_cone hole punching success");
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn sym_to_cone(self: Arc<Self>, task_info: PunchTaskInfo) -> Result<(), Error> {
        let mut backoff = BackOff::new(vec![1000, 2000, 4000, 4000, 8000, 8000, 16000, 64000]);
        let mut round = 0;
        let mut port_idx = rand::random();

        loop {
            backoff.sleep_for_next_backoff().await;

            let ret = {
                let _lock = self.sym_punch_lock.lock().await;
                self.sym_to_cone_client
                    .do_hole_punching(task_info.dst_peer_id, round, &mut port_idx)
                    .await
            };

            round += 1;

            if let Err(e) = ret {
                tracing::info!(?e, "sym_to_cone hole punching failed");
                continue;
            }

            if let Err(e) = self.peer_mgr.add_client_tunnel(ret.unwrap()).await {
                tracing::warn!(?e, "sym_to_cone add client tunnel failed");
                continue;
            }

            break;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn both_easy_sym(self: Arc<Self>, task_info: PunchTaskInfo) -> Result<(), Error> {
        let mut backoff = BackOff::new(vec![1000, 2000, 4000, 4000, 8000, 8000, 16000, 64000]);

        loop {
            backoff.sleep_for_next_backoff().await;

            let ret = self
                .both_easy_sym_client
                .do_hole_punching(task_info.dst_peer_id)
                .await;
            if let Err(e) = ret {
                tracing::info!(?e, "both_easy_sym hole punching failed");
                continue;
            }

            if let Err(e) = self.peer_mgr.add_client_tunnel(ret.unwrap()).await {
                tracing::warn!(?e, "both_easy_sym add client tunnel failed");
                continue;
            }

            break;
        }

        Ok(())
    }
}

#[derive(Clone)]
struct UdpHolePunchPeerTaskLauncher {}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct PunchTaskInfo {
    dst_peer_id: PeerId,
    dst_nat_type: UdpNatType,
    my_nat_type: UdpNatType,
}

#[async_trait::async_trait]
impl PeerTaskLauncher for UdpHolePunchPeerTaskLauncher {
    type Data = Arc<UdpHoePunchConnectorData>;
    type CollectPeerItem = PunchTaskInfo;
    type TaskRet = ();

    fn new_data(&self, peer_mgr: Arc<PeerManager>) -> Self::Data {
        UdpHoePunchConnectorData::new(peer_mgr)
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        let mut peers_to_connect: Vec<Self::CollectPeerItem> = Vec::new();
        let my_nat_type = data.last_my_nat_type.load();

        // do not do anything if:
        // 1. our nat type is OpenInternet or NoPat, which means we can wait other peers to connect us
        // notice that if we are unknown, we treat ourselves as cone
        if my_nat_type.is_open() {
            return peers_to_connect;
        }

        // collect peer list from peer manager and do some filter:
        // 1. peers without direct conns;
        // 2. peers is full cone (any restricted type);
        for route in data.peer_mgr.list_routes().await.iter() {
            let Some(peer_stun_info) = route.stun_info.as_ref() else {
                continue;
            };
            let Ok(peer_nat_type) = NatType::try_from(peer_stun_info.udp_nat_type) else {
                continue;
            };
            let peer_nat_type = peer_nat_type.into();

            let peer_id: PeerId = route.peer_id;
            let conns = data.peer_mgr.list_peer_conns(peer_id).await;
            if conns.is_some() && conns.unwrap().len() > 0 {
                continue;
            }

            if !my_nat_type.can_punch_hole_as_client(peer_nat_type) {
                continue;
            }

            tracing::info!(
                ?peer_id,
                ?peer_nat_type,
                ?my_nat_type,
                "found peer to do hole punching"
            );

            peers_to_connect.push(PunchTaskInfo {
                dst_peer_id: peer_id,
                dst_nat_type: peer_nat_type,
                my_nat_type,
            });
        }

        peers_to_connect
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> JoinHandle<Result<Self::TaskRet, Error>> {
        let data = data.clone();
        tokio::spawn(data.cone_to_cone(item))
    }

    async fn need_clear_task(&self, data: &Self::Data) -> bool {
        let my_nat_type = data
            .peer_mgr
            .get_global_ctx()
            .get_stun_info_collector()
            .get_stun_info()
            .udp_nat_type;
        let my_nat_type = NatType::try_from(my_nat_type)
            .unwrap_or(NatType::Unknown)
            .into();
        let prev_nat_type = data.last_my_nat_type.load();
        data.last_my_nat_type.store(my_nat_type);

        if !my_nat_type.is_sym() {
            data.sym_to_cone_client.clear_udp_array().await;
        }

        my_nat_type != prev_nat_type
    }

    async fn all_task_done(&self, data: &Self::Data) {
        data.sym_to_cone_client.clear_udp_array().await;
    }

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

pub struct UdpHolePunchConnector {
    server: Arc<UdpHolePunchServer>,
    client: PeerTaskManager<UdpHolePunchPeerTaskLauncher>,
    peer_mgr: Arc<PeerManager>,
}

// Currently support:
// Symmetric -> Full Cone
// Any Type of Full Cone -> Any Type of Full Cone

// if same level of full cone, node with smaller peer_id will be the initiator
// if different level of full cone, node with more strict level will be the initiator

impl UdpHolePunchConnector {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            server: UdpHolePunchServer::new(peer_mgr.clone()),
            client: PeerTaskManager::new(UdpHolePunchPeerTaskLauncher {}, peer_mgr.clone()),
            peer_mgr,
        }
    }

    pub async fn run_as_client(&mut self) -> Result<(), Error> {
        self.client.start();
        Ok(())
    }

    pub async fn run_as_server(&mut self) -> Result<(), Error> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                UdpHolePunchRpcServer::new(self.server.clone()),
                &self.peer_mgr.get_global_ctx().get_network_name(),
            );

        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let global_ctx = self.peer_mgr.get_global_ctx();

        if global_ctx.get_flags().disable_p2p {
            return Ok(());
        }
        if global_ctx.get_flags().disable_udp_hole_punching {
            return Ok(());
        }

        self.run_as_client().await?;
        self.run_as_server().await?;

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::Arc;

    use crate::common::stun::MockStunInfoCollector;
    use crate::proto::common::NatType;

    use crate::peers::{peer_manager::PeerManager, tests::create_mock_peer_manager};

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
        replace_stun_info_collector(p_a.clone(), udp_nat_type);
        p_a
    }
}
