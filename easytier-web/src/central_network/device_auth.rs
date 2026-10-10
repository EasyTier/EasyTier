//! Central-console device registration through the ordinary webhook contract.

use easytier::proto::web::DeviceOsInfo;
use uuid::Uuid;

use crate::{
    db::{Db, DeviceHeartbeatRecord},
    webhook::{ValidateTokenRequest, ValidateTokenResponse, WebhookHandler},
};

#[derive(Debug)]
pub struct DeviceAuth {
    db: Db,
    allow_auto_create_user: bool,
}

impl DeviceAuth {
    pub fn new(db: Db, allow_auto_create_user: bool) -> Self {
        Self {
            db,
            allow_auto_create_user,
        }
    }
}

#[async_trait::async_trait]
impl WebhookHandler for DeviceAuth {
    async fn validate_token(
        &self,
        request: &ValidateTokenRequest,
    ) -> anyhow::Result<ValidateTokenResponse> {
        let mut response = ValidateTokenResponse {
            valid: false,
            pre_approved: false,
            binding_version: 0,
            config_revision: String::new(),
        };
        let Ok(machine_id) = Uuid::parse_str(&request.machine_id) else {
            return Ok(response);
        };
        let user_id = match self.db.get_user_id_by_token(&request.token).await? {
            Some(user_id) => user_id,
            None if self.allow_auto_create_user => {
                self.db.auto_create_user(&request.token).await?.id
            }
            None => return Ok(response),
        };
        let device = (user_id, machine_id);
        if self
            .db
            .record_blocked_attempt(device, &request.hostname)
            .await?
        {
            return Ok(response);
        }

        // Validation carries a public IP, not the transport URL. Keep any
        // historical URL; REST obtains current addresses from live sessions.
        let client_url = self
            .db
            .get_device(device)
            .await?
            .map(|device| device.client_url)
            .unwrap_or_default();
        self.db
            .upsert_device_heartbeat(DeviceHeartbeatRecord {
                user_id,
                machine_id,
                hostname: request.hostname.clone(),
                easytier_version: request.version.clone(),
                device_os: serde_json::to_string(&DeviceOsInfo {
                    os_type: request.os_type.clone().unwrap_or_default(),
                    version: request.os_version.clone().unwrap_or_default(),
                    distribution: request.os_distribution.clone().unwrap_or_default(),
                })?,
                client_url,
            })
            .await?;
        response.valid = true;
        response.pre_approved = true;
        response.config_revision = self
            .db
            .get_managed_config_revision(device)
            .await?
            .unwrap_or_default();
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use easytier::{
        common::config::{ConfigSource, network_config_from_raw},
        instance::factory::native_instance_manager,
        proto::rpc::standalone::{runtime_udp_tunnel_dialer, runtime_udp_tunnel_listener},
        web_client::WebClient,
    };

    use crate::{
        FeatureFlags,
        client_manager::{ClientManager, HeartbeatPolicy},
        webhook::{ManagedNetworkConfig, WebhookConfig},
    };

    use super::*;

    async fn wait_until<F, Fut>(mut condition: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        tokio::time::timeout(Duration::from_secs(20), async {
            while !condition().await {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("local device authentication did not converge");
    }

    async fn start_config_server(db: Db) -> (ClientManager, url::Url) {
        let webhook = WebhookConfig::new(None, None, None, None, None)
            .with_handler(Arc::new(DeviceAuth::new(db.clone(), false)));
        let mut manager = ClientManager::new(
            db,
            None,
            HeartbeatPolicy::from_millis(1_000, 10_000).unwrap(),
            Arc::new(FeatureFlags::default()),
            Arc::new(webhook),
        );
        let listener = runtime_udp_tunnel_listener(
            "udp://127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        );
        let url = manager.add_listener(listener).await.unwrap();
        (manager, url)
    }

    #[tokio::test]
    async fn web_client_registers_receives_full_config_and_cannot_reconnect_when_blocked() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("local-owner").await.unwrap().id;
        let machine_id = Uuid::new_v4();
        let instance_id = Uuid::new_v4();
        let core = Arc::new(native_instance_manager());
        let (manager, url) = start_config_server(db.clone()).await;
        let client = WebClient::new(
            runtime_udp_tunnel_dialer(url),
            "local-owner",
            machine_id,
            "local-device",
            false,
            core.clone(),
            None,
        );
        wait_until(|| async {
            db.get_device((user_id, machine_id))
                .await
                .unwrap()
                .is_some()
                && manager
                    .get_session_by_machine_id(user_id, &machine_id)
                    .is_some()
        })
        .await;
        assert_eq!(
            db.get_device((user_id, machine_id))
                .await
                .unwrap()
                .unwrap()
                .hostname,
            "local-device"
        );
        manager
            .reconcile_managed_network_configs(
                user_id,
                machine_id,
                vec![ManagedNetworkConfig {
                    instance_id: instance_id.to_string(),
                    network_config: serde_json::json!({
                        "instance_id": instance_id.to_string(),
                        "network_name": "local-managed-network",
                        "network_secret": "local-secret",
                        "networking_method": "Standalone",
                        "no_tun": true,
                        "disable_ipv6": true,
                        "multi_thread": false
                    }),
                }],
                Some("local-full-1".to_owned()),
                None,
            )
            .await
            .unwrap();
        wait_until(|| async {
            core.config(instance_id)
                .map(|config| network_config_from_raw(config.raw()))
                .is_some_and(|config| {
                    config.network_name.as_deref() == Some("local-managed-network")
                })
        })
        .await;
        assert_eq!(core.config_source(instance_id), Some(ConfigSource::Web));

        // Stop the original connection before deleting it. This exercises a
        // fresh authentication, without depending on in-flight revocation.
        drop(client);
        manager
            .disconnect_session_by_machine_id(user_id, &machine_id)
            .await;
        drop(manager);
        db.delete_device_with_optional_block((user_id, machine_id), true)
            .await
            .unwrap();
        let (manager, url) = start_config_server(db.clone()).await;
        let _blocked_client = WebClient::new(
            runtime_udp_tunnel_dialer(url),
            "local-owner",
            machine_id,
            "blocked-device",
            false,
            Arc::new(native_instance_manager()),
            None,
        );
        // A second validation comes from another reconnect after the first
        // rejected session fails its next heartbeat.
        wait_until(|| async {
            db.list_blocked_devices(user_id)
                .await
                .unwrap()
                .first()
                .is_some_and(|blocked| blocked.attempt_count >= 2)
        })
        .await;
        assert!(
            db.get_device((user_id, machine_id))
                .await
                .unwrap()
                .is_none()
        );
        assert!(manager.list_sessions().await.is_empty());
        assert!(
            manager
                .get_session_by_machine_id(user_id, &machine_id)
                .is_none()
        );
        core.delete_network_instances([instance_id]).await.unwrap();
    }

    fn request(token: &str, machine_id: Uuid) -> ValidateTokenRequest {
        ValidateTokenRequest {
            token: token.to_owned(),
            machine_id: machine_id.to_string(),
            public_ip: Some("192.0.2.1".to_owned()),
            hostname: "device".to_owned(),
            version: "2.7.0".to_owned(),
            os_type: Some("Linux".to_owned()),
            os_version: Some("6.12".to_owned()),
            os_distribution: Some("Debian".to_owned()),
            web_instance_id: None,
            web_instance_api_base_url: None,
            persisted_config_revision: None,
            applied_config_revision: None,
            applied_config_revision_known: false,
            failed_instance_ids: Vec::new(),
        }
    }

    #[tokio::test]
    async fn unknown_token_requires_auto_creation_and_a_valid_machine_id() {
        let db = Db::memory_db().await;
        let mut req = request("new-user", Uuid::new_v4());
        let auth = DeviceAuth::new(db.clone(), false);
        assert!(!auth.validate_token(&req).await.unwrap().valid);
        assert!(db.get_user_id_by_token(&req.token).await.unwrap().is_none());

        let auth = DeviceAuth::new(db.clone(), true);
        let machine_id = req.machine_id.clone();
        req.machine_id = "invalid".to_owned();
        assert!(!auth.validate_token(&req).await.unwrap().valid);
        assert!(db.get_user_id_by_token(&req.token).await.unwrap().is_none());
        req.machine_id = machine_id;
        assert!(auth.validate_token(&req).await.unwrap().valid);
        let user_id = db.get_user_id_by_token(&req.token).await.unwrap().unwrap();
        assert_eq!(db.list_devices(user_id).await.unwrap().len(), 1);
        assert!(
            DeviceAuth::new(db, false)
                .validate_token(&req)
                .await
                .unwrap()
                .valid
        );
    }

    #[tokio::test]
    async fn registration_refreshes_metadata_and_preserves_alias_and_address() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("owner").await.unwrap().id;
        let machine_id = Uuid::new_v4();
        let device = (user_id, machine_id);
        let auth = DeviceAuth::new(db.clone(), false);
        let mut req = request("owner", machine_id);
        let response = auth.validate_token(&req).await.unwrap();
        assert!(response.valid && response.pre_approved);
        let initial = db.get_device(device).await.unwrap().unwrap();
        assert!(initial.client_url.is_empty());
        db.set_device_alias(device, "office".to_owned())
            .await
            .unwrap();
        db.upsert_device_heartbeat(DeviceHeartbeatRecord {
            user_id,
            machine_id,
            hostname: initial.hostname,
            easytier_version: initial.easytier_version,
            device_os: initial.device_os,
            client_url: "tcp://192.0.2.2:1234".to_owned(),
        })
        .await
        .unwrap();
        db.set_managed_config_revision(device, "revision-1")
            .await
            .unwrap();
        req.hostname = "renamed".to_owned();
        req.version = "2.8.0".to_owned();
        assert_eq!(
            auth.validate_token(&req).await.unwrap().config_revision,
            "revision-1"
        );
        let refreshed = db.get_device(device).await.unwrap().unwrap();
        assert_eq!(refreshed.hostname, "renamed");
        assert_eq!(refreshed.easytier_version, "2.8.0");
        assert_eq!(refreshed.alias, "office");
        assert_eq!(refreshed.client_url, "tcp://192.0.2.2:1234");
        assert_eq!(refreshed.first_seen_time, initial.first_seen_time);
        let os: DeviceOsInfo = serde_json::from_str(&refreshed.device_os).unwrap();
        assert_eq!(os.os_type, "Linux");
        assert_eq!(os.version, "6.12");
        assert_eq!(os.distribution, "Debian");
    }

    #[tokio::test]
    async fn deleting_without_a_block_allows_registration_but_blocking_rejects_new_auth() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("owner").await.unwrap().id;
        let machine_id = Uuid::new_v4();
        let device = (user_id, machine_id);
        let auth = DeviceAuth::new(db.clone(), false);
        let mut req = request("owner", machine_id);
        assert!(auth.validate_token(&req).await.unwrap().valid);
        assert!(
            db.delete_device_with_optional_block(device, false)
                .await
                .unwrap()
        );
        assert!(db.get_device(device).await.unwrap().is_none());
        assert!(auth.validate_token(&req).await.unwrap().valid);

        assert!(
            db.delete_device_with_optional_block(device, true)
                .await
                .unwrap()
        );
        req.hostname = "blocked-retry".to_owned();
        assert!(!auth.validate_token(&req).await.unwrap().valid);
        assert!(!auth.validate_token(&req).await.unwrap().valid);
        assert!(db.get_device(device).await.unwrap().is_none());
        let blocked = db.list_blocked_devices(user_id).await.unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].hostname, "blocked-retry");
        assert_eq!(blocked[0].attempt_count, 2);
        assert!(blocked[0].last_attempt_time.is_some());
        assert!(db.unblock_device(device).await.unwrap());
        assert!(auth.validate_token(&req).await.unwrap().valid);
    }

    #[tokio::test]
    async fn registration_and_blocks_are_scoped_to_the_token_tenant() {
        let db = Db::memory_db().await;
        let user_a = db.auto_create_user("tenant-a").await.unwrap().id;
        let user_b = db.auto_create_user("tenant-b").await.unwrap().id;
        let machine_id = Uuid::new_v4();
        let auth = DeviceAuth::new(db.clone(), false);
        let req_a = request("tenant-a", machine_id);
        assert!(auth.validate_token(&req_a).await.unwrap().valid);
        db.delete_device_with_optional_block((user_a, machine_id), true)
            .await
            .unwrap();
        let mut req_b = request("tenant-b", machine_id);
        req_b.hostname = "tenant-b-host".to_owned();
        assert!(auth.validate_token(&req_b).await.unwrap().valid);
        assert!(!auth.validate_token(&req_a).await.unwrap().valid);
        assert!(db.get_device((user_a, machine_id)).await.unwrap().is_none());
        assert_eq!(
            db.get_device((user_b, machine_id))
                .await
                .unwrap()
                .unwrap()
                .hostname,
            "tenant-b-host"
        );
        assert!(db.list_blocked_devices(user_b).await.unwrap().is_empty());
    }
}
