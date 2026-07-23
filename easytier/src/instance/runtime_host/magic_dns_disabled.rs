use cidr::Ipv4Inet;
use easytier_core::instance::CorePacketPlane;

use crate::common::global_ctx::ArcGlobalCtx;

#[derive(Default)]
pub(super) struct MagicDnsRuntime;

impl MagicDnsRuntime {
    pub(super) fn start(
        _global_ctx: ArcGlobalCtx,
        _packet_plane: std::sync::Arc<CorePacketPlane>,
        _tun_dev: Option<String>,
        _tun_ip: Ipv4Inet,
    ) -> Self {
        Self
    }

    pub(super) async fn stop(&mut self) {}
}
