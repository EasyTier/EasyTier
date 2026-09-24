use crate::common::global_ctx::ArcGlobalCtx;
use easytier_core::config::runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore};
use easytier_core::instance::{CoreInstanceConfig, CorePacketPlane};
pub use easytier_core::peers::PacketRecvChan;
pub use easytier_core::peers::peer_manager::RouteAlgoType;
use easytier_core::peers::peer_manager::{PeerManagerCore, PortablePeerManagerConfig};
use easytier_proto::common::FlagsInConfig;
use std::ops::Deref;
use std::sync::Arc;

pub struct PeerManager {
    core: Arc<PeerManagerCore>,
    global_ctx: ArcGlobalCtx,
    packet_plane: Arc<CorePacketPlane>,
}

impl std::fmt::Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("my_peer_id", &self.core.my_peer_id())
            .finish()
    }
}

impl Deref for PeerManager {
    type Target = PeerManagerCore;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl PeerManager {
    pub fn new(
        route_algo: RouteAlgoType,
        global_ctx: ArcGlobalCtx,
        _nic_channel: PacketRecvChan,
    ) -> Self {
        let toml_str = global_ctx.config.dump();
        let toml_config = crate::common::config::TomlConfigLoader::new_from_str_with_source(
            "peer_manager",
            &toml_str,
        )
        .unwrap_or_default();
        let normalized = CoreInstanceConfig::from_toml(&toml_config).unwrap_or_else(|_| {
            CoreInstanceConfig::from_toml(&crate::common::config::TomlConfig::default()).unwrap()
        });
        let peer_cfg = PortablePeerManagerConfig {
            snapshot: normalized.peer.snapshot.clone(),
            route_algo,
            exit_nodes: normalized.peer.exit_nodes,
            foreign_context_default_flags: FlagsInConfig::default(),
        };
        let (nic_sender, _) = tokio::sync::mpsc::channel(100);
        let core = Arc::new(PeerManagerCore::new_portable_for_test(peer_cfg, nic_sender).unwrap());
        let runtime_config = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(normalized.peer.snapshot),
        );
        let packet_plane = Arc::new(CorePacketPlane::new(core.clone(), runtime_config, false));

        Self {
            core,
            global_ctx,
            packet_plane,
        }
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn packet_plane(&self) -> Arc<CorePacketPlane> {
        self.packet_plane.clone()
    }

    pub async fn run(&self) -> Result<(), anyhow::Error> {
        self.core.run().await.map_err(Into::into)
    }

    pub async fn list_routes(&self) -> Vec<easytier_proto::core_peer::peer::Route> {
        use easytier_core::peers::peer_center::instance::PeerCenterPeerManagerTrait as _;
        self.core.list_routes().await
    }
}
