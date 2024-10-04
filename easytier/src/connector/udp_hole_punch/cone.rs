use std::sync::Arc;

use tokio::{sync::Notify, task::JoinSet};

use crate::{
    common::{global_ctx::ArcGlobalCtx, join_joinset_background, stun::StunInfoCollectorTrait},
    connector::udp_hole_punch::common::HOLE_PUNCH_PACKET_BODY_LEN,
    proto::{
        common::NatType,
        peer_rpc::{TryPunchHoleRequest, TryPunchHoleResponse},
        rpc_types,
    },
    tunnel::udp::new_hole_punch_packet,
};

pub(crate) struct PunchConeHoleServerImpl {
    global_ctx: ArcGlobalCtx,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}
