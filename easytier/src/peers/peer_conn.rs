use async_trait::async_trait;
use easytier_core::peers::context::{
    ArcByteLimiter, ByteLimiter, NetworkIdentity as CoreNetworkIdentity, PeerContext, PeerEvent,
    secret_proof_from_secret,
};
pub use easytier_core::peers::peer_conn::*;
use hmac::Mac as _;

use crate::{
    common::{
        global_ctx::{GlobalCtx, GlobalCtxEvent},
        stats_manager::{LabelSet, LabelType, MetricName},
        token_bucket::TokenBucket,
    },
    proto::{
        api::instance,
        common::{LimiterConfig, SecureModeConfig, TunnelInfo},
    },
    use_global_var,
};

#[async_trait]
impl ByteLimiter for TokenBucket {
    async fn consume(&self, bytes: u64) {
        TokenBucket::consume(self, bytes).await;
    }
}

impl PeerContext for GlobalCtx {
    fn network_identity(&self) -> CoreNetworkIdentity {
        let identity = self.get_network_identity();
        CoreNetworkIdentity {
            network_name: identity.network_name,
            network_secret: identity.network_secret,
            network_secret_digest: identity.network_secret_digest,
        }
    }

    fn flags(&self) -> crate::proto::common::FlagsInConfig {
        self.get_flags()
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        self.config.get_secure_mode()
    }

    fn pinned_remote_static_pubkey(&self, tunnel_info: Option<&TunnelInfo>) -> Option<String> {
        let remote_url_str = tunnel_info
            .and_then(|t| t.remote_addr.as_ref())
            .map(|u| u.url.as_str())?;
        let remote_url: url::Url = remote_url_str.parse().ok()?;

        self.config
            .get_peers()
            .into_iter()
            .find(|p| p.uri == remote_url)
            .and_then(|p| p.peer_public_key)
    }

    fn secret_proof(&self, challenge: &[u8]) -> Option<hmac::Hmac<sha2::Sha256>> {
        let secret = self.get_network_identity().network_secret?;
        secret_proof_from_secret(&secret, challenge)
    }

    fn secret_digest(&self, network_identity: &CoreNetworkIdentity) -> Vec<u8> {
        if use_global_var!(HMAC_SECRET_DIGEST) {
            self.get_secret_proof(b"digest")
                .map(|mac| mac.finalize().into_bytes().to_vec())
                .unwrap_or_default()
        } else {
            network_identity
                .secret_digest()
                .unwrap_or_default()
                .to_vec()
        }
    }

    fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        self.is_pubkey_trusted(pubkey, network_name)
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        record_control_metric(
            self,
            network_name,
            bytes,
            MetricName::TrafficControlBytesTx,
            MetricName::TrafficControlPacketsTx,
        );
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        record_control_metric(
            self,
            network_name,
            bytes,
            MetricName::TrafficControlBytesRx,
            MetricName::TrafficControlPacketsRx,
        );
    }

    fn recv_limiter(&self, network_name: &str, is_foreign_network: bool) -> Option<ArcByteLimiter> {
        let flags = self.get_flags();
        if is_foreign_network && flags.foreign_relay_bps_limit != u64::MAX {
            let limiter_config = LimiterConfig {
                burst_rate: None,
                bps: Some(flags.foreign_relay_bps_limit),
                fill_duration_ms: None,
            };
            return Some(
                self.token_bucket_manager()
                    .get_or_create(&format!("{network_name}:recv"), limiter_config.into()),
            );
        }

        if flags.instance_recv_bps_limit != u64::MAX {
            let limiter_config = LimiterConfig {
                burst_rate: None,
                bps: Some(flags.instance_recv_bps_limit),
                fill_duration_ms: None,
            };
            return Some(
                self.token_bucket_manager()
                    .get_or_create("instance:recv", limiter_config.into()),
            );
        }

        None
    }

    fn issue_event(&self, event: PeerEvent) {
        match event {
            PeerEvent::PeerAdded(peer_id) => self.issue_event(GlobalCtxEvent::PeerAdded(peer_id)),
            PeerEvent::PeerRemoved(peer_id) => {
                self.issue_event(GlobalCtxEvent::PeerRemoved(peer_id))
            }
            PeerEvent::PeerConnAdded(info) => {
                self.issue_event(GlobalCtxEvent::PeerConnAdded(info.into()))
            }
            PeerEvent::PeerConnRemoved(info) => {
                self.issue_event(GlobalCtxEvent::PeerConnRemoved(info.into()))
            }
        }
    }
}

fn record_control_metric(
    global_ctx: &GlobalCtx,
    network_name: &str,
    bytes: u64,
    bytes_metric: MetricName,
    packets_metric: MetricName,
) {
    let label_set =
        LabelSet::new().with_label_type(LabelType::NetworkName(network_name.to_string()));
    global_ctx
        .stats_manager()
        .get_counter(bytes_metric, label_set.clone())
        .add(bytes);
    global_ctx
        .stats_manager()
        .get_counter(packets_metric, label_set)
        .inc();
}

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
        global_ctx::ArcGlobalCtx,
    };

    use super::*;

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
