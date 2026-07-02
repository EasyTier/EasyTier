use crate::proto::api::instance;
pub use easytier_core::peers::peer_conn::*;

pub(crate) fn core_conn_info_to_api(
    info: easytier_core::proto::core_peer::peer::PeerConnInfo,
) -> instance::PeerConnInfo {
    info.into()
}

#[cfg(test)]
pub mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use rand::rngs::OsRng;

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

        let global_ctx = GlobalCtx::new(config);
        let digest = PeerContext::secret_digest(&global_ctx, &identity);

        assert_eq!(digest, identity.secret_digest().unwrap().to_vec());
    }
}
