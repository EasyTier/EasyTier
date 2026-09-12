use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use easytier::proto::web::HeartbeatRequest;
use tokio::sync::RwLock;

use super::{
    SessionAuthState, SessionData, SessionRpcService, WebhookConnectNotification,
    WebhookDisconnectNotification, send_webhook_connection_transition,
};
use crate::{
    client_manager::storage::{Storage, StorageToken},
    webhook::SharedWebhookConfig,
};

pub(super) const VALIDATION_RETRY_MS: u64 = 60_000;

pub(super) struct WebhookHeartbeatValidation {
    pub(super) config_revision: String,
    pub(super) binding_version: u64,
}

pub(super) struct WebhookValidationInput {
    pub(super) storage: Storage,
    pub(super) webhook_config: SharedWebhookConfig,
    pub(super) client_url: url::Url,
    pub(super) applied_config_revision: Option<String>,
    pub(super) applied_config_revision_known: bool,
    pub(super) failed_instance_ids: Vec<String>,
    pub(super) req: HeartbeatRequest,
    pub(super) machine_id: uuid::Uuid,
}

fn deterministic_machine_delay(machine_id: uuid::Uuid, max_delay_ms: u64) -> Duration {
    let delay_ms = (machine_id.as_u128() % u128::from(max_delay_ms + 1)) as u64;
    Duration::from_millis(delay_ms)
}

pub(super) fn retry_delay(machine_id: uuid::Uuid) -> Duration {
    Duration::from_millis(VALIDATION_RETRY_MS)
        + deterministic_machine_delay(machine_id, VALIDATION_RETRY_MS)
}

async fn request_heartbeat_validation(
    input: &WebhookValidationInput,
    persisted_config_revision: Option<&str>,
) -> anyhow::Result<Option<WebhookHeartbeatValidation>> {
    let webhook_req = crate::webhook::ValidateTokenRequest {
        token: input.req.user_token.clone(),
        machine_id: input.machine_id.to_string(),
        public_ip: input.client_url.host_str().map(str::to_string),
        hostname: input.req.hostname.clone(),
        version: input.req.easytier_version.clone(),
        os_type: input
            .req
            .device_os
            .as_ref()
            .map(|info| info.os_type.clone()),
        os_version: input
            .req
            .device_os
            .as_ref()
            .map(|info| info.version.clone()),
        os_distribution: input
            .req
            .device_os
            .as_ref()
            .map(|info| info.distribution.clone()),
        web_instance_id: input.webhook_config.web_instance_id.clone(),
        web_instance_api_base_url: input.webhook_config.web_instance_api_base_url.clone(),
        persisted_config_revision: persisted_config_revision.map(str::to_string),
        applied_config_revision: input.applied_config_revision.as_deref().map(str::to_string),
        applied_config_revision_known: input.applied_config_revision_known,
        failed_instance_ids: input.failed_instance_ids.to_vec(),
    };
    let resp = input
        .webhook_config
        .validate_token(&webhook_req)
        .await
        .map_err(|e| anyhow::anyhow!("Webhook token validation failed: {:?}", e))?;

    if !resp.valid {
        return Ok(None);
    }

    Ok(Some(WebhookHeartbeatValidation {
        config_revision: resp.config_revision,
        binding_version: resp.binding_version,
    }))
}

async fn resolve_user_id(storage: &Storage, token: &str) -> anyhow::Result<i32> {
    let user_id = match storage
        .db()
        .get_user_id_by_token(token)
        .await
        .map_err(|e| anyhow::anyhow!("DB error: {:?}", e))?
    {
        Some(id) => id,
        None => storage
            .auto_create_user(token)
            .await
            .with_context(|| format!("Failed to auto-create webhook user: {:?}", token))?,
    };

    Ok(user_id)
}

async fn persisted_config_revision_for_token(
    storage: &Storage,
    token: &str,
    machine_id: uuid::Uuid,
) -> anyhow::Result<Option<String>> {
    let Some(user_id) = storage
        .db()
        .get_user_id_by_token(token)
        .await
        .map_err(|e| anyhow::anyhow!("DB error: {:?}", e))?
    else {
        return Ok(None);
    };
    storage
        .db()
        .get_managed_config_revision((user_id, machine_id))
        .await
        .map_err(|e| anyhow::anyhow!("DB error: {:?}", e))
}

async fn wait_for_input(
    session_data: std::sync::Weak<RwLock<SessionData>>,
) -> Option<(WebhookValidationInput, u64)> {
    loop {
        let notify = {
            let session_data = session_data.upgrade()?;
            let mut data = session_data.write().await;
            if matches!(data.auth_state, SessionAuthState::Invalid) {
                data.webhook_validation_dirty = false;
                tracing::info!(
                    client_url = %data.client_url,
                    "webhook validation stopped for invalid session; reconnect is required before revalidation"
                );
                return None;
            }
            if data.webhook_validation_dirty {
                data.webhook_validation_dirty = false;
                let req = data.req.clone()?;
                let machine_id = req.machine_id.map(Into::into)?;
                let storage = Storage::try_from(data.storage.clone()).ok()?;
                let (applied_config_revision, applied_config_revision_known) = {
                    let runtime = data.managed_runtime();
                    (
                        runtime.applied_config_revision.clone(),
                        runtime.applied_config_revision_known,
                    )
                };
                return Some((
                    WebhookValidationInput {
                        storage,
                        webhook_config: data.webhook_config.clone(),
                        client_url: data.client_url.clone(),
                        applied_config_revision,
                        applied_config_revision_known,
                        failed_instance_ids: SessionRpcService::sorted_failed_instance_ids_locked(
                            &data,
                        ),
                        req,
                        machine_id,
                    },
                    data.webhook_validation_change_epoch,
                ));
            }
            data.webhook_validation_notify.clone()
        };
        notify.notified().await;
    }
}

async fn wait_for_retry_or_state_change(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    machine_id: uuid::Uuid,
    validation_change_epoch: u64,
    delay: Duration,
) {
    let retry_deadline = tokio::time::sleep(delay);
    tokio::pin!(retry_deadline);

    loop {
        let notify = {
            let Some(session_data) = session_data.upgrade() else {
                return;
            };
            let data = session_data.read().await;
            let Some(req) = data.req.as_ref() else {
                return;
            };
            if req.machine_id.map(uuid::Uuid::from) != Some(machine_id)
                || matches!(data.auth_state, SessionAuthState::Invalid)
            {
                return;
            }
            if data.webhook_validation_change_epoch != validation_change_epoch {
                return;
            }
            data.webhook_validation_notify.clone()
        };

        // Notify is only a wake-up hint. Periodic validation can set dirty,
        // but only a meaningful validation-state change may bypass backoff.
        // Recheck the epoch after every wake without resetting the deadline.
        tokio::select! {
            _ = &mut retry_deadline => {
                mark_dirty_if_current(session_data, machine_id).await;
                return;
            }
            _ = notify.notified() => {}
        }
    }
}

pub(super) async fn run_worker(session_data: std::sync::Weak<RwLock<SessionData>>) {
    while let Some((input, validation_change_epoch)) = wait_for_input(session_data.clone()).await {
        let machine_id = input.machine_id;
        if let Err(error) = run_round(session_data.clone(), input, validation_change_epoch).await {
            tracing::warn!(
                ?machine_id,
                %error,
                "webhook validation failed, will retry later"
            );
            wait_for_retry_or_state_change(
                &session_data,
                machine_id,
                validation_change_epoch,
                retry_delay(machine_id),
            )
            .await;
        }
    }
}

pub(super) async fn run_round(
    session_data: std::sync::Weak<RwLock<SessionData>>,
    input: WebhookValidationInput,
    validation_change_epoch: u64,
) -> anyhow::Result<()> {
    let persisted_config_revision = persisted_config_revision_for_token(
        &input.storage,
        &input.req.user_token,
        input.machine_id,
    )
    .await?;
    let validation =
        request_heartbeat_validation(&input, persisted_config_revision.as_deref()).await?;

    // The HTTP round trip can span heartbeats, revision updates, and
    // failed-instance changes. Results older than the current epoch are
    // discarded so a stale rejection cannot invalidate the session and a
    // stale success cannot emit outdated connection transitions.
    if !validation_results_are_current(&session_data, &input, validation_change_epoch).await {
        return Ok(());
    }

    let Some(validation) = validation else {
        apply_rejected(&session_data, &input).await;
        return Ok(());
    };

    let user_id = resolve_user_id(&input.storage, &input.req.user_token).await?;
    apply_success(&session_data, input, validation, user_id).await;
    Ok(())
}

async fn validation_results_are_current(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    input: &WebhookValidationInput,
    validation_change_epoch: u64,
) -> bool {
    let Some(session_data) = session_data.upgrade() else {
        return false;
    };
    let data = session_data.read().await;
    if data.webhook_validation_change_epoch != validation_change_epoch {
        tracing::debug!(
            machine_id = %input.machine_id,
            "discard stale webhook validation result"
        );
        return false;
    }
    true
}

async fn mark_dirty_if_current(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    machine_id: uuid::Uuid,
) {
    let Some(session_data) = session_data.upgrade() else {
        return;
    };
    let notify = {
        let mut data = session_data.write().await;
        let Some(req) = data.req.as_ref() else {
            return;
        };
        if req.machine_id.map(uuid::Uuid::from) != Some(machine_id) {
            return;
        }
        if matches!(data.auth_state, SessionAuthState::Invalid) {
            data.webhook_validation_dirty = false;
            tracing::debug!(
                %machine_id,
                "skip webhook validation retry for invalid session"
            );
            return;
        }
        SessionRpcService::mark_webhook_validation_dirty_locked(&mut data)
    };
    notify.notify_one();
}

pub(super) async fn apply_rejected(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    input: &WebhookValidationInput,
) {
    let Some(session_data) = session_data.upgrade() else {
        return;
    };
    let (storage_token, disconnect_notification, session_epoch) = {
        let mut data = session_data.write().await;
        if !data.req.as_ref().is_some_and(|req| {
            SessionRpcService::heartbeat_matches_identity(
                req,
                &input.req.user_token,
                input.machine_id,
            )
        }) {
            return;
        }
        tracing::info!(
            machine_id = %input.machine_id,
            client_url = %data.client_url,
            "webhook token rejected; marking session invalid and requiring client reconnect"
        );
        data.auth_state = SessionAuthState::Invalid;
        data.webhook_validation_dirty = false;
        data.binding_version = None;
        let storage_token = data.storage_token.clone();
        let disconnect_notification = storage_token.as_ref().and_then(|storage_token| {
            data.webhook_connected_binding_version
                .take()
                .map(|binding_version| WebhookDisconnectNotification {
                    webhook: data.webhook_config.clone(),
                    storage_token: storage_token.clone(),
                    binding_version,
                })
        });
        (storage_token, disconnect_notification, data.session_epoch)
    };
    if let Some(storage_token) = storage_token {
        let report_time = SessionRpcService::heartbeat_report_timestamp(&input.req);
        input
            .storage
            .update_session_client(storage_token, report_time, false, session_epoch);
    }
    if disconnect_notification.is_some() {
        wait_webhook_connection_transition(
            Arc::downgrade(&session_data),
            disconnect_notification,
            None,
        )
        .await;
    }
}

pub(super) async fn apply_success(
    session_data: &std::sync::Weak<RwLock<SessionData>>,
    input: WebhookValidationInput,
    validation: WebhookHeartbeatValidation,
    user_id: i32,
) {
    let WebhookHeartbeatValidation {
        config_revision: _,
        binding_version,
    } = validation;

    let Some(session_data) = session_data.upgrade() else {
        return;
    };
    let (
        storage_token,
        notifier,
        disconnect_notification,
        connect_notification,
        validation_notify,
        runtime_req,
        session_epoch,
    ) = {
        let mut data = session_data.write().await;
        let Some(runtime_req) = data.req.clone() else {
            return;
        };
        if !SessionRpcService::heartbeat_matches_identity(
            &runtime_req,
            &input.req.user_token,
            input.machine_id,
        ) {
            return;
        }
        if matches!(data.auth_state, SessionAuthState::Invalid) {
            tracing::info!(
                machine_id = %input.machine_id,
                client_url = %data.client_url,
                "ignore webhook validation success for invalid session; reconnect is required before revalidation"
            );
            return;
        }

        let previous_connected_binding_version = data.webhook_connected_binding_version;
        let client_url = data.client_url.clone();
        let is_new_storage_token = data.storage_token.is_none();
        let mut restored_runtime_revision = false;
        if is_new_storage_token {
            data.managed_runtime = input.storage.bind_managed_runtime_state(
                user_id,
                input.machine_id,
                SessionRpcService::heartbeat_runtime_id(&runtime_req),
                data.session_epoch,
            );
            let runtime = data.managed_runtime();
            restored_runtime_revision = runtime.applied_config_revision_known
                && (!input.applied_config_revision_known
                    || input.applied_config_revision != runtime.applied_config_revision);
        }
        let storage_token = data.storage_token.get_or_insert_with(|| StorageToken {
            token: runtime_req.user_token.clone(),
            client_url,
            machine_id: input.machine_id,
            user_id,
        });
        let storage_token = storage_token.clone();
        data.auth_state = SessionAuthState::Authorized;
        data.binding_version = Some(binding_version);
        if is_new_storage_token {
            tracing::info!(
                machine_id = %input.machine_id,
                user_id,
                session_epoch = data.session_epoch,
                binding_version,
                client_url = %data.client_url,
                "session identity established"
            );
        }
        let should_notify_connected = previous_connected_binding_version != Some(binding_version);
        let disconnect_notification = previous_connected_binding_version
            .filter(|previous_binding_version| *previous_binding_version != binding_version)
            .map(|previous_binding_version| {
                data.webhook_connected_binding_version = None;
                WebhookDisconnectNotification {
                    webhook: data.webhook_config.clone(),
                    storage_token: storage_token.clone(),
                    binding_version: previous_binding_version,
                }
            });

        let connect_notification = should_notify_connected.then(|| WebhookConnectNotification {
            webhook: data.webhook_config.clone(),
            storage_token: storage_token.clone(),
            binding_version,
            req: crate::webhook::NodeConnectedRequest {
                machine_id: input.machine_id.to_string(),
                token: runtime_req.user_token.clone(),
                user_id: Some(user_id),
                hostname: runtime_req.hostname.clone(),
                version: runtime_req.easytier_version.clone(),
                os_type: runtime_req
                    .device_os
                    .as_ref()
                    .map(|info| info.os_type.clone()),
                os_version: runtime_req
                    .device_os
                    .as_ref()
                    .map(|info| info.version.clone()),
                os_distribution: runtime_req
                    .device_os
                    .as_ref()
                    .map(|info| info.distribution.clone()),
                web_instance_id: data.webhook_config.web_instance_id.clone(),
                binding_version: Some(binding_version),
            },
        });
        let validation_notify = restored_runtime_revision
            .then(|| SessionRpcService::mark_webhook_validation_state_changed_locked(&mut data));

        (
            storage_token,
            data.notifier.clone(),
            disconnect_notification,
            connect_notification,
            validation_notify,
            runtime_req,
            data.session_epoch,
        )
    };

    let report_time = SessionRpcService::heartbeat_report_timestamp(&runtime_req);
    input
        .storage
        .update_session_client(storage_token, report_time, true, session_epoch);

    if let Some(validation_notify) = validation_notify {
        validation_notify.notify_one();
    }

    if disconnect_notification.is_some() || connect_notification.is_some() {
        wait_webhook_connection_transition(
            Arc::downgrade(&session_data),
            disconnect_notification,
            connect_notification,
        )
        .await;
    }

    let _ = notifier.send(runtime_req);
}

async fn wait_webhook_connection_transition(
    session_data: std::sync::Weak<RwLock<SessionData>>,
    disconnect: Option<WebhookDisconnectNotification>,
    connect: Option<WebhookConnectNotification>,
) {
    let transition = tokio::spawn(send_webhook_connection_transition(
        session_data,
        disconnect,
        connect,
    ));
    if let Err(error) = transition.await {
        tracing::warn!(%error, "webhook connection transition task failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn validation_session(machine_id: uuid::Uuid) -> Arc<RwLock<SessionData>> {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(crate::FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        data.req = Some(HeartbeatRequest {
            user_token: "token".to_string(),
            machine_id: Some(machine_id.into()),
            ..Default::default()
        });
        data.auth_state = SessionAuthState::Authorized;
        Arc::new(RwLock::new(data))
    }

    #[tokio::test]
    async fn reconnect_immediately_reports_restored_runtime_revision() {
        let storage = Storage::new(crate::db::Db::memory_db().await);
        let user_id = storage.db().auto_create_user("token").await.unwrap().id;
        let machine_id = uuid::Uuid::new_v4();
        let runtime_id = uuid::Uuid::new_v4();
        let shared = storage.bind_managed_runtime_state(user_id, machine_id, Some(runtime_id), 1);
        {
            let mut runtime = shared.lock().unwrap();
            runtime.applied_config_revision = Some("rev-applied".to_string());
            runtime.applied_config_revision_known = true;
        }
        let request = HeartbeatRequest {
            user_token: "token".to_string(),
            machine_id: Some(machine_id.into()),
            inst_id: Some(runtime_id.into()),
            ..Default::default()
        };
        let mut data = SessionData::new(
            storage.weak_ref(),
            url::Url::parse("http://127.0.0.1").unwrap(),
            None,
            Arc::new(crate::FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        );
        data.req = Some(request.clone());
        data.session_identity = Some(SessionRpcService::heartbeat_identity(&request, machine_id));
        data.session_epoch = 2;
        let session_data = Arc::new(RwLock::new(data));

        apply_success(
            &Arc::downgrade(&session_data),
            WebhookValidationInput {
                storage,
                webhook_config: Arc::new(crate::webhook::WebhookConfig::new(
                    None, None, None, None, None,
                )),
                client_url: url::Url::parse("http://127.0.0.1").unwrap(),
                applied_config_revision: None,
                applied_config_revision_known: false,
                failed_instance_ids: Vec::new(),
                req: request,
                machine_id,
            },
            WebhookHeartbeatValidation {
                config_revision: "rev-applied".to_string(),
                binding_version: 1,
            },
            user_id,
        )
        .await;

        let data = session_data.read().await;
        assert!(Arc::ptr_eq(&data.managed_runtime, &shared));
        assert!(data.webhook_validation_dirty);
        assert_eq!(data.webhook_validation_change_epoch, 1);
    }

    #[tokio::test]
    async fn validation_input_carries_merged_failed_instance_ids() {
        let machine_id = uuid::Uuid::new_v4();
        let core_failed = uuid::Uuid::new_v4();
        let local_failed = uuid::Uuid::new_v4().to_string();
        let session_data = validation_session(machine_id).await;
        let storage = Storage::new(crate::db::Db::memory_db().await);
        {
            let mut data = session_data.write().await;
            data.storage = storage.weak_ref();
            data.req
                .as_mut()
                .unwrap()
                .failed_network_instances
                .push(core_failed.into());
            data.direct_run_failed_instance_ids
                .insert(local_failed.clone());
            data.webhook_validation_dirty = true;
        }

        let (input, _) = wait_for_input(Arc::downgrade(&session_data))
            .await
            .expect("validation input");
        let mut expected = vec![core_failed.to_string(), local_failed];
        expected.sort_unstable();

        assert_eq!(input.failed_instance_ids, expected);
    }

    #[tokio::test]
    async fn stale_notification_does_not_bypass_validation_retry_delay() {
        let machine_id = uuid::Uuid::new_v4();
        let session_data = validation_session(machine_id).await;
        let notify = session_data.read().await.webhook_validation_notify.clone();
        notify.notify_one();
        let weak_session = Arc::downgrade(&session_data);

        let wait =
            wait_for_retry_or_state_change(&weak_session, machine_id, 0, Duration::from_secs(10));
        tokio::pin!(wait);

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wait)
                .await
                .is_err()
        );
        assert!(!session_data.read().await.webhook_validation_dirty);
    }

    #[tokio::test]
    async fn validation_retry_deadline_rearms_dirty_state() {
        let machine_id = uuid::Uuid::new_v4();
        let session_data = validation_session(machine_id).await;
        let weak_session = Arc::downgrade(&session_data);

        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_retry_or_state_change(&weak_session, machine_id, 0, Duration::from_millis(20)),
        )
        .await
        .expect("retry deadline should eventually expire");
        assert!(session_data.read().await.webhook_validation_dirty);
    }

    #[tokio::test]
    async fn periodic_dirty_state_does_not_interrupt_validation_retry_delay() {
        let machine_id = uuid::Uuid::new_v4();
        let session_data = validation_session(machine_id).await;
        let weak_session = Arc::downgrade(&session_data);
        let wait =
            wait_for_retry_or_state_change(&weak_session, machine_id, 0, Duration::from_secs(10));
        tokio::pin!(wait);

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wait)
                .await
                .is_err()
        );
        mark_dirty_if_current(&weak_session, machine_id).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wait)
                .await
                .is_err()
        );
        assert!(session_data.read().await.webhook_validation_dirty);
    }

    #[tokio::test]
    async fn validation_state_change_interrupts_retry_delay() {
        let machine_id = uuid::Uuid::new_v4();
        let session_data = validation_session(machine_id).await;
        let weak_session = Arc::downgrade(&session_data);
        let wait =
            wait_for_retry_or_state_change(&weak_session, machine_id, 0, Duration::from_secs(10));
        tokio::pin!(wait);

        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wait)
                .await
                .is_err()
        );
        let notify = {
            let mut data = session_data.write().await;
            SessionRpcService::mark_webhook_validation_state_changed_locked(&mut data)
        };
        notify.notify_one();
        tokio::time::timeout(Duration::from_millis(500), &mut wait)
            .await
            .expect("validation state change should interrupt retry delay");
        assert!(session_data.read().await.webhook_validation_dirty);
    }

    #[tokio::test]
    async fn invalid_session_does_not_rearm_validation_retry() {
        let machine_id = uuid::Uuid::new_v4();
        let session_data = validation_session(machine_id).await;
        session_data.write().await.auth_state = SessionAuthState::Invalid;
        let weak_session = Arc::downgrade(&session_data);

        tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_retry_or_state_change(&weak_session, machine_id, 0, Duration::from_secs(10)),
        )
        .await
        .expect("invalid session should stop waiting");
        assert!(!session_data.read().await.webhook_validation_dirty);
    }

    #[tokio::test]
    async fn validation_results_require_current_epoch_or_live_session() {
        let machine_id = uuid::Uuid::new_v4();
        let session_data = validation_session(machine_id).await;
        let input = WebhookValidationInput {
            storage: Storage::new(crate::db::Db::memory_db().await),
            webhook_config: Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
            client_url: url::Url::parse("http://127.0.0.1").unwrap(),
            applied_config_revision: None,
            applied_config_revision_known: false,
            failed_instance_ids: Vec::new(),
            req: HeartbeatRequest::default(),
            machine_id,
        };
        let weak_session = Arc::downgrade(&session_data);

        assert!(
            validation_results_are_current(&weak_session, &input, 0).await,
            "matching epoch is current"
        );

        session_data.write().await.webhook_validation_change_epoch = 7;
        assert!(
            !validation_results_are_current(&weak_session, &input, 0).await,
            "epoch bump discards stale results"
        );

        drop(session_data);
        assert!(
            !validation_results_are_current(&weak_session, &input, 7).await,
            "dropped session discards results"
        );
    }
}
