pub use easytier_core::peers::{acl_filter, foreign_network_client, peer_map, peer_ospf_route};

pub mod credential_manager {
    pub use crate::common::credential_manager::*;
}

pub mod peer_conn {
    pub use easytier_core::peers::peer_conn::*;

    pub(crate) fn core_conn_info_to_api(
        info: easytier_core::proto::core_peer::peer::PeerConnInfo,
    ) -> crate::proto::api::instance::PeerConnInfo {
        info.into()
    }

    #[cfg(test)]
    pub mod tests {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
        use rand::rngs::OsRng;
        use std::sync::Arc;

        use crate::common::{
            config::{ConfigLoader, TomlConfigLoader},
            global_ctx::{ArcGlobalCtx, GlobalCtx},
        };
        use crate::proto::common::SecureModeConfig;
        use easytier_core::peers::context::{NetworkIdentity as CoreNetworkIdentity, PeerContext};

        pub fn set_secure_mode_cfg(global_ctx: &ArcGlobalCtx, enabled: bool) {
            if !enabled {
                global_ctx.config.set_secure_mode(None);
            } else {
                let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                let public = x25519_dalek::PublicKey::from(&private);

                global_ctx.config.set_secure_mode(Some(SecureModeConfig {
                    enabled: true,
                    local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                    local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
                }));
            }
        }

        #[tokio::test]
        async fn global_ctx_secret_digest_derives_from_plaintext_secret() {
            crate::set_global_var!(HMAC_SECRET_DIGEST, false);

            let config = TomlConfigLoader::default();
            let identity = CoreNetworkIdentity {
                network_name: "net".to_string(),
                network_secret: Some("secret".to_string()),
                network_secret_digest: None,
            };
            config.set_network_identity(identity.clone().into());

            let global_ctx = Arc::new(GlobalCtx::new(config));
            let config = crate::peers::context::runtime_peer_manager_config(
                &global_ctx,
                crate::peers::peer_manager::RouteAlgoType::Ospf,
            );
            let (_, peer_context) =
                crate::peers::context::build_core_peer_context(&global_ctx, &config);
            let digest = peer_context.secret_digest(&identity);

            assert_eq!(digest, identity.secret_digest().unwrap().to_vec());
        }
    }
}
pub(crate) mod context;
#[cfg(test)]
pub mod peer_manager;
pub mod relay_peer_map {
    pub use easytier_core::peers::relay_peer_map::{
        RelayPeerMap, RelayPeerState, RelayRouteTransport, new_relay_peer_map,
    };
}
pub mod rpc_service;

pub mod foreign_network_manager;

pub mod encrypt;

#[cfg(test)]
pub mod tests;

pub mod peer_rpc {
    pub use easytier_core::peers::peer_rpc::*;

    pub use easytier_core::stats_manager::StatsRpcMetrics;
}

pub(crate) use easytier_core::peers::secure_datagram;
pub use easytier_core::peers::{
    BoxNicPacketFilter, BoxPeerPacketFilter, NicPacketFilter, PacketRecvChan,
    PacketRecvChanReceiver, PeerPacketFilter, create_packet_recv_chan, peer, peer_conn_ping,
    peer_session, recv_packet_from_chan, route_trait,
};

pub use easytier_core::peers::foreign_network_manager::PUBLIC_SERVER_HOSTNAME_PREFIX;
