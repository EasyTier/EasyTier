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
    webhook_config: &crate::webhook::WebhookConfig,
    client_url: &url::Url,
    persisted_config_revision: Option<&str>,
    applied_config_revision: Option<&str>,
    req: &HeartbeatRequest,
    machine_id: uuid::Uuid,
) -> anyhow::Result<Option<WebhookHeartbeatValidation>> {
    let webhook_req = crate::webhook::ValidateTokenRequest {
        token: req.user_token.clone(),
        machine_id: machine_id.to_string(),
        public_ip: client_url.host_str().map(str::to_string),
        hostname: req.hostname.clone(),
        version: req.easytier_version.clone(),
        os_type: req.device_os.as_ref().map(|info| info.os_type.clone()),
        os_version: req.device_os.as_ref().map(|info| info.version.clone()),
        os_distribution: req.device_os.as_ref().map(|info| info.distribution.clone()),
        web_instance_id: webhook_config.web_instance_id.clone(),
        web_instance_api_base_url: webhook_config.web_instance_api_base_url.clone(),
        persisted_config_revision: persisted_config_revision.map(str::to_string),
        applied_config_revision: applied_config_revision.map(str::to_string),
    };
    let resp = webhook_config
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
) -> Option<WebhookValidationInput> {
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
                return Some(WebhookValidationInput {
                    storage,
                    webhook_config: data.webhook_config.clone(),
                    client_url: data.client_url.clone(),
                    applied_config_revision: data.applied_config_revision.clone(),
                    req,
                    machine_id,
                });
            }
            data.webhook_validation_notify.clone()
        };
        notify.notified().await;
    }
}

pub(super) async fn run_worker(session_data: std::sync::Weak<RwLock<SessionData>>) {
    while let Some(input) = wait_for_input(session_data.clone()).await {
        let machine_id = input.machine_id;
        if let Err(error) = run_round(session_data.clone(), input).await {
            tracing::warn!(
                ?machine_id,
                %error,
                "webhook validation failed, will retry later"
            );
            tokio::time::sleep(retry_delay(machine_id)).await;
            mark_dirty_if_current(&session_data, machine_id).await;
        }
    }
}

pub(super) async fn run_round(
    session_data: std::sync::Weak<RwLock<SessionData>>,
    input: WebhookValidationInput,
) -> anyhow::Result<()> {
    let persisted_config_revision = persisted_config_revision_for_token(
        &input.storage,
        &input.req.user_token,
        input.machine_id,
    )
    .await?;
    let validation = request_heartbeat_validation(
        &input.webhook_config,
        &input.client_url,
        persisted_config_revision.as_deref(),
        input.applied_config_revision.as_deref(),
        &input.req,
        input.machine_id,
    )
    .await?;

    let Some(validation) = validation else {
        apply_rejected(&session_data, &input).await;
        return Ok(());
    };

    let user_id = resolve_user_id(&input.storage, &input.req.user_token).await?;
    apply_success(&session_data, input, validation, user_id).await;
    Ok(())
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
    let (storage_token, disconnect_notification) = {
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
        data.applied_config_revision = None;
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
        (storage_token, disconnect_notification)
    };
    if let Some(storage_token) = storage_token {
        let report_time = SessionRpcService::heartbeat_report_timestamp(&input.req);
        input
            .storage
            .update_client(storage_token, report_time, false);
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
    let (storage_token, notifier, disconnect_notification, connect_notification, runtime_req) = {
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
        let storage_token = data.storage_token.get_or_insert_with(|| StorageToken {
            token: runtime_req.user_token.clone(),
            client_url,
            machine_id: input.machine_id,
            user_id,
        });
        let storage_token = storage_token.clone();
        data.auth_state = SessionAuthState::Authorized;
        data.binding_version = Some(binding_version);
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

        (
            storage_token,
            data.notifier.clone(),
            disconnect_notification,
            connect_notification,
            runtime_req,
        )
    };

    if disconnect_notification.is_some() || connect_notification.is_some() {
        wait_webhook_connection_transition(
            Arc::downgrade(&session_data),
            disconnect_notification,
            connect_notification,
        )
        .await;
    }

    let report_time = SessionRpcService::heartbeat_report_timestamp(&runtime_req);
    input
        .storage
        .update_client(storage_token, report_time, true);
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
