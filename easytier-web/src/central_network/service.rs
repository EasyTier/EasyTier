use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::Engine as _;
use easytier::{common::config::NetworkConfig, proto::api::manage::CollectNetworkInfoResponse};
use easytier_core::management::remote_client::{RemoteClientError, RemoteClientManager as _};
use futures::{StreamExt as _, TryStreamExt as _};
use rand::{RngCore as _, rngs::OsRng};
use sea_orm::{ColumnTrait as _, EntityTrait as _, QueryFilter as _, QueryOrder as _};
use uuid::Uuid;

use super::model::{
    AclPolicy, CentralNetworkIntent, CredentialGrant, NetworkCredentialIntent, NetworkMemberIntent,
    NetworkMode, member_group_name,
};
pub use super::temporary_peers::TemporaryPeerInfo;
use crate::{
    client_manager::ClientManager,
    db::{CentralIntentError, Db, UserIdInDb},
};

const TEMPORARY_MEMBER_DEFAULT_TTL_SECONDS: u32 = 7 * 24 * 3600;
const MAX_CREDENTIAL_TTL_SECONDS: u32 = 365 * 24 * 3600;

#[derive(Debug, thiserror::Error)]
pub enum CentralNetworkServiceError {
    #[error("{0}")]
    Invalid(String),
    #[error("network not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(String),
}

impl From<CentralIntentError> for CentralNetworkServiceError {
    fn from(error: CentralIntentError) -> Self {
        match error {
            CentralIntentError::Compile(error) => Self::Invalid(error.to_string()),
            CentralIntentError::InvalidDeviceId(device_id) => {
                Self::Invalid(format!("invalid device id: {device_id}"))
            }
            CentralIntentError::Database(error) => {
                let message = error.to_string();
                if message.contains("UNIQUE constraint failed") {
                    Self::Conflict(message)
                } else {
                    Self::Database(message)
                }
            }
            CentralIntentError::InvalidStoredData(message) => Self::Database(message),
        }
    }
}

impl From<sea_orm::DbErr> for CentralNetworkServiceError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Database(error.to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkSettings {
    pub display_name: String,
    pub network_name: Option<String>,
    pub networking_method: String,
    pub public_server_url: Option<String>,
    #[serde(default)]
    pub peer_urls: Vec<String>,
    pub virtual_cidr: Option<String>,
    #[serde(default)]
    pub secure_mode: bool,
}

impl NetworkSettings {
    fn normalize_virtual_cidr(&mut self) {
        self.virtual_cidr = self.virtual_cidr.take().and_then(|value| {
            let value = value.trim();
            if value.is_empty() {
                None
            } else if value.contains('/') {
                Some(value.to_owned())
            } else {
                Some(format!("{value}/24"))
            }
        });
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateNetworkReq {
    pub settings: NetworkSettings,
    pub network_secret: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddMembersReq {
    pub device_ids: Vec<String>,
    #[serde(default)]
    pub temporary: bool,
    pub ttl_seconds: Option<u32>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UpdateMemberReq {
    pub hostname_override: Option<String>,
    pub virtual_ipv4: Option<String>,
    pub proxy_cidrs: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenerateCredentialReq {
    pub ttl_seconds: u32,
    pub credential_id: Option<String>,
    #[serde(default = "default_true")]
    pub reusable: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkSummary {
    pub network_id: String,
    pub display_name: String,
    pub network_name: String,
    pub networking_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_cidr: Option<String>,
    pub secure_mode: bool,
    pub member_count: usize,
    pub online_member_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceNetworkSummary {
    pub network_id: String,
    pub display_name: String,
    pub network_name: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkDetail {
    pub network_id: String,
    pub display_name: String,
    pub network_name: String,
    pub network_secret: String,
    pub networking_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_cidr: Option<String>,
    pub secure_mode: bool,
    pub public_server_url: Option<String>,
    pub peer_urls: Vec<String>,
    pub member_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberInfo {
    pub member_id: String,
    pub device_id: String,
    pub hostname: Option<String>,
    pub hostname_override: Option<String>,
    pub alias: Option<String>,
    pub virtual_ipv4: Option<String>,
    pub allocated_ipv4: Option<String>,
    pub online: bool,
    pub running: Option<bool>,
    pub runtime_virtual_ipv4: Option<String>,
    pub version: Option<String>,
    pub error_msg: Option<String>,
    pub has_override: bool,
    pub proxy_cidrs: Vec<String>,
    pub temporary: bool,
    pub credential_id: Option<String>,
    pub credential_expiry_unix: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MembersView {
    pub members: Vec<MemberInfo>,
    pub temporary_peers: Vec<TemporaryPeerInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkCredentialInfo {
    pub credential_id: String,
    pub credential_secret: String,
    pub expiry_unix: i64,
    pub reusable: bool,
    pub online_peers: Vec<TemporaryPeerInfo>,
}

#[derive(Clone)]
pub struct CentralNetworkService {
    pub(crate) db: Db,
    client_manager: Arc<ClientManager>,
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
    network_instances: Option<Arc<crate::central_network::gateway::NetworkInstanceManager>>,
    reconciler_started: Arc<AtomicBool>,
}

impl CentralNetworkService {
    pub fn new(db: Db, client_manager: Arc<ClientManager>) -> Self {
        Self::with_gateway(db, client_manager, None)
    }

    pub fn with_gateway(
        db: Db,
        client_manager: Arc<ClientManager>,
        network_instances: Option<Arc<crate::central_network::gateway::NetworkInstanceManager>>,
    ) -> Self {
        Self {
            db,
            client_manager,
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            network_instances,
            reconciler_started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) async fn lock_mutations(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.mutation_lock.lock().await
    }

    pub fn network_instances(
        &self,
    ) -> Option<&Arc<crate::central_network::gateway::NetworkInstanceManager>> {
        self.network_instances.as_ref()
    }

    /// Start only in central mode: Console supplies its own complete configs.
    pub fn start_reconciler(self: &Arc<Self>) {
        if self.reconciler_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let service = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(service) = service.upgrade() else {
                    return;
                };
                if let Err(error) = service.reconcile_all().await {
                    tracing::error!(%error, "failed to publish central network configs");
                }
                drop(service);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    async fn reconcile_all(&self) -> Result<(), CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let users = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT user_id FROM networks
            UNION SELECT user_id FROM devices
            UNION SELECT user_id FROM managed_config_revisions
                WHERE config_revision LIKE 'central:%'
            "#,
        )
        .fetch_all(&self.db.inner())
        .await
        .map_err(|error| CentralNetworkServiceError::Database(error.to_string()))?;
        let mut users = users.into_iter().collect::<BTreeSet<_>>();
        if let Some(instances) = &self.network_instances {
            // Include owners with no remaining intent or device rows so that
            // deleting their last network also retires its Gateway runtime.
            users.extend(
                instances
                    .network_ids()
                    .await
                    .into_iter()
                    .map(|(user_id, _)| user_id),
            );
        }
        for user_id in users {
            self.publish_user(user_id).await;
        }
        Ok(())
    }

    pub async fn list_networks(
        &self,
        user_id: UserIdInDb,
    ) -> Result<Vec<NetworkSummary>, CentralNetworkServiceError> {
        use crate::db::entity::{network_members, networks};
        let rows = networks::Entity::find()
            .filter(networks::Column::UserId.eq(user_id))
            .order_by_asc(networks::Column::CreateTime)
            .all(self.db.orm_db())
            .await?;
        let online: std::collections::HashSet<_> = self
            .client_manager
            .list_sessions_by_user_id(user_id)
            .await
            .into_iter()
            .map(|token| token.machine_id.to_string())
            .collect();
        let members = network_members::Entity::find()
            .filter(network_members::Column::UserId.eq(user_id))
            .all(self.db.orm_db())
            .await?;
        let mut counts = BTreeMap::new();
        for member in members {
            let (total, online_count) = counts.entry(member.network_id).or_insert((0, 0));
            *total += 1;
            *online_count += usize::from(online.contains(&member.device_id));
        }
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let (member_count, online_member_count) = counts.remove(&row.id).unwrap_or_default();
            result.push(NetworkSummary {
                network_id: row.id,
                display_name: row.display_name,
                network_name: row.network_name,
                networking_method: row.networking_method,
                virtual_cidr: row.virtual_cidr,
                secure_mode: row.secure_mode,
                member_count,
                online_member_count,
            });
        }
        Ok(result)
    }

    pub async fn list_device_networks(
        &self,
        user_id: UserIdInDb,
    ) -> Result<
        std::collections::HashMap<String, Vec<DeviceNetworkSummary>>,
        CentralNetworkServiceError,
    > {
        use crate::db::entity::{network_members, networks};

        let members = network_members::Entity::find()
            .filter(network_members::Column::UserId.eq(user_id))
            .all(self.db.orm_db())
            .await?;
        if members.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let mut device_ids_by_network = std::collections::HashMap::<String, Vec<String>>::new();
        for member in members {
            device_ids_by_network
                .entry(member.network_id)
                .or_default()
                .push(member.device_id);
        }

        let networks = networks::Entity::find()
            .filter(networks::Column::UserId.eq(user_id))
            .order_by_asc(networks::Column::CreateTime)
            .order_by_asc(networks::Column::Id)
            .all(self.db.orm_db())
            .await?;
        let mut result = std::collections::HashMap::<String, Vec<DeviceNetworkSummary>>::new();
        for network in networks {
            let Some(device_ids) = device_ids_by_network.remove(&network.id) else {
                continue;
            };
            let summary = DeviceNetworkSummary {
                network_id: network.id,
                display_name: network.display_name,
                network_name: network.network_name,
            };
            for device_id in device_ids {
                result.entry(device_id).or_default().push(summary.clone());
            }
        }
        Ok(result)
    }

    pub async fn create_network(
        &self,
        user_id: UserIdInDb,
        mut settings: NetworkSettings,
        network_secret: Option<String>,
    ) -> Result<NetworkDetail, CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        settings.normalize_virtual_cidr();
        let network_name = settings
            .network_name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| generated_network_name(&settings.display_name));
        let mode = mode_from_settings(&settings, self.gateway_config())?;
        let intent = CentralNetworkIntent {
            id: Uuid::new_v4(),
            user_id,
            display_name: settings.display_name,
            network_name,
            network_secret: network_secret.unwrap_or_else(random_secret),
            mode,
            virtual_cidr: settings.virtual_cidr,
            secure_mode: settings.secure_mode,
            members: Vec::new(),
            credentials: Vec::new(),
            acl_policy: None,
        };
        let network_id = intent.id;
        self.persist(intent).await?;
        self.get_network(user_id, network_id).await
    }

    pub async fn get_network(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
    ) -> Result<NetworkDetail, CentralNetworkServiceError> {
        let intent = self.load(user_id, network_id).await?;
        let (networking_method, public_server_url, peer_urls) = mode_view(&intent.mode);
        Ok(NetworkDetail {
            network_id: network_id.to_string(),
            display_name: intent.display_name,
            network_name: intent.network_name,
            network_secret: intent.network_secret,
            networking_method,
            virtual_cidr: intent.virtual_cidr,
            secure_mode: intent.secure_mode,
            public_server_url,
            peer_urls,
            member_count: intent.members.len(),
        })
    }

    pub async fn update_network(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        mut request: UpdateNetworkReq,
    ) -> Result<NetworkDetail, CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        request.settings.normalize_virtual_cidr();
        let mut intent = self.load(user_id, network_id).await?;
        let mode = mode_from_settings(&request.settings, self.gateway_config())?;
        intent.display_name = request.settings.display_name;
        if let Some(network_name) = request.settings.network_name {
            intent.network_name = network_name;
        }
        intent.mode = mode;
        if intent.virtual_cidr != request.settings.virtual_cidr {
            for member in &mut intent.members {
                member.allocated_ipv4 = None;
            }
        }
        intent.virtual_cidr = request.settings.virtual_cidr;
        intent.secure_mode = request.settings.secure_mode;
        if let Some(secret) = request.network_secret {
            intent.network_secret = secret;
        }
        self.persist(intent).await?;
        self.get_network(user_id, network_id).await
    }

    pub async fn delete_network(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
    ) -> Result<(), CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        self.load(user_id, network_id).await?;
        self.db
            .delete_central_network_intent(user_id, network_id)
            .await?;
        self.publish_user(user_id).await;
        Ok(())
    }

    pub async fn delete_device(
        &self,
        user_id: UserIdInDb,
        machine_id: Uuid,
        block: bool,
    ) -> Result<bool, CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        if let Some(session) = self
            .client_manager
            .get_session_by_machine_id(user_id, &machine_id)
        {
            let owned = self
                .db
                .central_owned_runtime_configs(user_id, machine_id)
                .await?;
            if !owned.is_empty() {
                let (revision, _) = self
                    .db
                    .publish_central_device_configs(user_id, machine_id, Vec::new())
                    .await?;
                self.client_manager
                    .invalidate_applied_config_revision(user_id, machine_id)
                    .await;
                let stopped = tokio::time::timeout(Duration::from_secs(30), async {
                    loop {
                        if !session.is_running()
                            || !self
                                .client_manager
                                .get_session_by_machine_id(user_id, &machine_id)
                                .is_some_and(|current| Arc::ptr_eq(&current, &session))
                        {
                            return Err(CentralNetworkServiceError::Conflict(
                                "device disconnected before its managed instances stopped".into(),
                            ));
                        }
                        if session.applied_config_revision().await.as_deref() == Some(&revision) {
                            let running = self.client_manager
                                .get_rpc_client((user_id, machine_id))
                                .ok_or_else(|| CentralNetworkServiceError::Conflict("device disconnected".into()))?
                                .list_network_instance(
                                    easytier::proto::rpc_types::controller::BaseController::default(),
                                    easytier::proto::api::manage::ListNetworkInstanceRequest::default(),
                                ).await
                                .map_err(|error| {
                                    CentralNetworkServiceError::Conflict(error.to_string())
                                })?;
                            if owned.iter().any(|config| {
                                running
                                    .inst_ids
                                    .contains(&config.instance_id.into())
                            }) {
                                return Err(CentralNetworkServiceError::Conflict(
                                    "device still has running managed instances".into(),
                                ));
                            }
                            return Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await
                .unwrap_or_else(|_| {
                    Err(CentralNetworkServiceError::Conflict(
                        "timed out waiting for managed instances to stop".into(),
                    ))
                });
                if let Err(error) = stopped {
                    self.publish_user(user_id).await;
                    return Err(error);
                }
            }
        }
        let deleted = match self
            .db
            .delete_device_with_optional_block((user_id, machine_id), block)
            .await
        {
            Ok(deleted) => deleted,
            Err(error) => {
                self.publish_user(user_id).await;
                return Err(error.into());
            }
        };
        if deleted {
            self.client_manager
                .disconnect_session_by_machine_id(user_id, &machine_id)
                .await;
            self.publish_user(user_id).await;
        }
        Ok(deleted)
    }

    pub async fn add_members(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        request: AddMembersReq,
    ) -> Result<(), CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let mut intent = self.load(user_id, network_id).await?;
        if request.device_ids.is_empty() {
            return Err(CentralNetworkServiceError::Invalid(
                "device_ids must not be empty".into(),
            ));
        }
        if request.temporary && !intent.secure_mode {
            return Err(CentralNetworkServiceError::Invalid(
                "temporary members require secure mode".into(),
            ));
        }
        let ttl = request
            .ttl_seconds
            .unwrap_or(TEMPORARY_MEMBER_DEFAULT_TTL_SECONDS);
        if request.temporary && !(1..=MAX_CREDENTIAL_TTL_SECONDS).contains(&ttl) {
            return Err(CentralNetworkServiceError::Invalid(
                "temporary member TTL must be between 1 second and 365 days".into(),
            ));
        }
        for raw_device_id in request.device_ids {
            let device_id = Uuid::parse_str(&raw_device_id).map_err(|_| {
                CentralNetworkServiceError::Invalid(format!("invalid device id: {raw_device_id}"))
            })?;
            if self.db.get_device((user_id, device_id)).await?.is_none() {
                return Err(CentralNetworkServiceError::NotFound(raw_device_id));
            }
            if intent
                .members
                .iter()
                .any(|member| member.device_id == device_id.to_string())
            {
                return Err(CentralNetworkServiceError::Conflict(format!(
                    "device already belongs to network: {device_id}"
                )));
            }
            let member_id = Uuid::new_v4();
            let credential_id = request.temporary.then(|| format!("member-{member_id}"));
            if let Some(credential_id) = credential_id.as_ref() {
                intent.credentials.push(NetworkCredentialIntent {
                    id: credential_id.clone(),
                    secret: random_secret(),
                    expiry_unix: chrono::Utc::now().timestamp() + i64::from(ttl),
                    grant: CredentialGrant {
                        acl_groups: vec![member_group_name(member_id)],
                        allow_relay: false,
                        allowed_proxy_cidrs: Vec::new(),
                        reusable: false,
                    },
                });
            }
            intent.members.push(NetworkMemberIntent {
                id: member_id,
                device_id: device_id.to_string(),
                hostname: None,
                virtual_ipv4: None,
                allocated_ipv4: None,
                config_override: None,
                credential_id,
                acl_group_secret: (!request.temporary && intent.acl_policy.is_some())
                    .then(random_secret),
            });
        }
        self.persist(intent).await?;
        Ok(())
    }

    pub async fn remove_member(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        device_id: Uuid,
    ) -> Result<(), CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let mut intent = self.load(user_id, network_id).await?;
        if !intent.remove_device(device_id) {
            return Err(CentralNetworkServiceError::NotFound(device_id.to_string()));
        }
        self.persist(intent).await?;
        Ok(())
    }

    pub async fn update_member(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        device_id: Uuid,
        request: UpdateMemberReq,
    ) -> Result<MemberInfo, CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let mut intent = self.load(user_id, network_id).await?;
        let position = member_position(&intent, device_id)?;
        let member = &mut intent.members[position];
        if let Some(hostname) = request.hostname_override {
            member.hostname = (!hostname.trim().is_empty()).then_some(hostname);
        }
        if let Some(virtual_ipv4) = request.virtual_ipv4 {
            member.virtual_ipv4 = (!virtual_ipv4.trim().is_empty()).then_some(virtual_ipv4);
        }
        if let Some(proxy_cidrs) = request.proxy_cidrs {
            let mut config = member.config_override.clone().unwrap_or_default();
            config.proxy_cidrs = proxy_cidrs;
            member.config_override = Some(config);
            sync_member_credential_proxy_cidrs(&mut intent, position)?;
        }
        self.persist(intent).await?;
        self.member_info(user_id, network_id, device_id).await
    }

    pub async fn get_member_config(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        device_id: Uuid,
    ) -> Result<NetworkConfig, CentralNetworkServiceError> {
        let intent = self.load(user_id, network_id).await?;
        let position = member_position(&intent, device_id)?;
        Ok(intent.members[position]
            .config_override
            .clone()
            .unwrap_or_default())
    }

    pub async fn set_member_config(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        device_id: Uuid,
        config: NetworkConfig,
    ) -> Result<MemberInfo, CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let mut intent = self.load(user_id, network_id).await?;
        let position = member_position(&intent, device_id)?;
        intent.members[position].config_override = Some(config);
        sync_member_credential_proxy_cidrs(&mut intent, position)?;
        self.persist(intent).await?;
        self.member_info(user_id, network_id, device_id).await
    }

    pub async fn clear_member_config(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        device_id: Uuid,
    ) -> Result<(), CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let mut intent = self.load(user_id, network_id).await?;
        let position = member_position(&intent, device_id)?;
        intent.members[position].config_override = None;
        sync_member_credential_proxy_cidrs(&mut intent, position)?;
        self.persist(intent).await?;
        Ok(())
    }

    pub async fn update_acl_policy(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        policy: AclPolicy,
    ) -> Result<AclPolicy, CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let mut intent = self.load(user_id, network_id).await?;
        for member in &mut intent.members {
            if member.credential_id.is_none() && member.acl_group_secret.is_none() {
                member.acl_group_secret = Some(random_secret());
            }
        }
        intent.acl_policy = Some(policy.clone());
        self.persist(intent).await?;
        Ok(policy)
    }

    pub async fn get_acl_policy(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
    ) -> Result<AclPolicy, CentralNetworkServiceError> {
        Ok(self
            .load(user_id, network_id)
            .await?
            .acl_policy
            .unwrap_or_default())
    }

    pub async fn generate_credential(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        request: GenerateCredentialReq,
    ) -> Result<NetworkCredentialInfo, CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let mut intent = self.load(user_id, network_id).await?;
        if !intent.secure_mode {
            return Err(CentralNetworkServiceError::Invalid(
                "credentials require secure mode".into(),
            ));
        }
        if !(1..=MAX_CREDENTIAL_TTL_SECONDS).contains(&request.ttl_seconds) {
            return Err(CentralNetworkServiceError::Invalid(
                "credential TTL must be between 1 second and 365 days".into(),
            ));
        }
        let credential_id = request
            .credential_id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| format!("credential-{}", Uuid::new_v4()));
        if intent
            .credentials
            .iter()
            .any(|credential| credential.id == credential_id)
        {
            return Err(CentralNetworkServiceError::Conflict(format!(
                "credential already exists: {credential_id}"
            )));
        }
        intent.credentials.push(NetworkCredentialIntent {
            id: credential_id.clone(),
            secret: random_secret(),
            expiry_unix: chrono::Utc::now().timestamp() + i64::from(request.ttl_seconds),
            grant: CredentialGrant {
                acl_groups: Vec::new(),
                allow_relay: false,
                allowed_proxy_cidrs: Vec::new(),
                reusable: request.reusable,
            },
        });
        self.persist(intent).await?;
        self.credential_info(user_id, network_id, &credential_id)
            .await
    }

    pub async fn revoke_credential(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        credential_id: &str,
    ) -> Result<(), CentralNetworkServiceError> {
        let _mutation = self.mutation_lock.lock().await;
        let mut intent = self.load(user_id, network_id).await?;
        if intent
            .members
            .iter()
            .any(|member| member.credential_id.as_deref() == Some(credential_id))
        {
            return Err(CentralNetworkServiceError::Conflict(format!(
                "credential is used by a network member: {credential_id}"
            )));
        }
        let before = intent.credentials.len();
        intent
            .credentials
            .retain(|credential| credential.id != credential_id);
        if intent.credentials.len() == before {
            return Err(CentralNetworkServiceError::NotFound(
                credential_id.to_owned(),
            ));
        }
        self.persist(intent).await?;
        Ok(())
    }

    pub async fn list_credentials(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
    ) -> Result<Vec<NetworkCredentialInfo>, CentralNetworkServiceError> {
        let intent = self.load(user_id, network_id).await?;
        let temporary_peers = super::temporary_peers::collect(
            self.client_manager.as_ref(),
            &intent,
            self.network_instances.as_deref(),
        )
        .await;
        let mut result = Vec::with_capacity(intent.credentials.len());
        for credential in &intent.credentials {
            let mut info = Self::credential_info_from_intent(credential);
            info.online_peers = credential_peers(&temporary_peers, &credential.id);
            result.push(info);
        }
        Ok(result)
    }

    pub async fn list_members(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
    ) -> Result<MembersView, CentralNetworkServiceError> {
        let intent = self.load(user_id, network_id).await?;
        let temporary_peers = super::temporary_peers::collect(
            self.client_manager.as_ref(),
            &intent,
            self.network_instances.as_deref(),
        )
        .await;
        let devices = self
            .db
            .list_devices(user_id)
            .await?
            .into_iter()
            .map(|device| (device.machine_id.clone(), device))
            .collect::<BTreeMap<_, _>>();
        let members = futures::stream::iter(
            intent
                .members
                .iter()
                .map(|member| {
                    self.member_info_with_device(&intent, member, devices.get(&member.device_id))
                })
                .collect::<Vec<_>>(),
        )
        .buffered(16)
        .try_collect()
        .await?;
        Ok(MembersView {
            members,
            temporary_peers,
        })
    }

    async fn member_info(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        device_id: Uuid,
    ) -> Result<MemberInfo, CentralNetworkServiceError> {
        let intent = self.load(user_id, network_id).await?;
        let position = member_position(&intent, device_id)?;
        self.member_info_from_intent(&intent, &intent.members[position])
            .await
    }

    async fn member_info_from_intent(
        &self,
        intent: &CentralNetworkIntent,
        member: &NetworkMemberIntent,
    ) -> Result<MemberInfo, CentralNetworkServiceError> {
        let device_id = Uuid::parse_str(&member.device_id)
            .map_err(|_| CentralNetworkServiceError::Database("invalid stored device id".into()))?;
        let device = self.db.get_device((intent.user_id, device_id)).await?;
        self.member_info_with_device(intent, member, device.as_ref())
            .await
    }

    async fn member_info_with_device(
        &self,
        intent: &CentralNetworkIntent,
        member: &NetworkMemberIntent,
        device: Option<&crate::db::entity::devices::Model>,
    ) -> Result<MemberInfo, CentralNetworkServiceError> {
        let user_id = intent.user_id;
        let network_id = intent.id;
        let device_id = Uuid::parse_str(&member.device_id)
            .map_err(|_| CentralNetworkServiceError::Database("invalid stored device id".into()))?;
        let online = self
            .client_manager
            .get_session_by_machine_id(user_id, &device_id)
            .is_some();
        let mut running = None;
        let mut runtime_virtual_ipv4 = None;
        let mut error_msg = None;
        if online {
            match self
                .client_manager
                .handle_collect_network_info((user_id, device_id), Some(vec![network_id]))
                .await
            {
                Ok(response) => {
                    if let Some((is_running, virtual_ipv4, runtime_error)) =
                        member_runtime_fields(&response, network_id)
                    {
                        running = Some(is_running);
                        runtime_virtual_ipv4 = virtual_ipv4;
                        error_msg = runtime_error;
                    }
                }
                Err(RemoteClientError::ClientNotFound) => {}
                Err(error) => error_msg = Some(error.to_string()),
            }
        }
        let credential_expiry_unix = member.credential_id.as_deref().and_then(|credential_id| {
            intent
                .credentials
                .iter()
                .find(|credential| credential.id == credential_id)
                .map(|credential| credential.expiry_unix)
        });
        Ok(MemberInfo {
            member_id: member.id.to_string(),
            device_id: member.device_id.clone(),
            hostname: member
                .hostname
                .clone()
                .or_else(|| device.as_ref().map(|device| device.hostname.clone())),
            hostname_override: member.hostname.clone(),
            alias: device
                .as_ref()
                .and_then(|device| (!device.alias.is_empty()).then(|| device.alias.clone())),
            virtual_ipv4: member.virtual_ipv4.clone(),
            allocated_ipv4: member.allocated_ipv4.clone(),
            online,
            running,
            runtime_virtual_ipv4,
            version: device.map(|device| device.easytier_version.clone()),
            error_msg,
            has_override: member.config_override.is_some(),
            proxy_cidrs: member
                .config_override
                .as_ref()
                .map(|config| config.proxy_cidrs.clone())
                .unwrap_or_default(),
            temporary: member.credential_id.is_some(),
            credential_id: member.credential_id.clone(),
            credential_expiry_unix,
        })
    }

    async fn credential_info(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
        credential_id: &str,
    ) -> Result<NetworkCredentialInfo, CentralNetworkServiceError> {
        let intent = self.load(user_id, network_id).await?;
        let credential = intent
            .credentials
            .iter()
            .find(|credential| credential.id == credential_id)
            .ok_or_else(|| CentralNetworkServiceError::NotFound(credential_id.to_owned()))?;
        Ok(Self::credential_info_from_intent(credential))
    }

    fn credential_info_from_intent(credential: &NetworkCredentialIntent) -> NetworkCredentialInfo {
        NetworkCredentialInfo {
            credential_id: credential.id.clone(),
            credential_secret: credential.secret.clone(),
            expiry_unix: credential.expiry_unix,
            reusable: credential.grant.reusable,
            online_peers: Vec::new(),
        }
    }

    async fn load(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
    ) -> Result<CentralNetworkIntent, CentralNetworkServiceError> {
        self.db
            .load_central_network_intent(user_id, network_id)
            .await?
            .ok_or_else(|| CentralNetworkServiceError::NotFound(network_id.to_string()))
    }

    async fn persist(
        &self,
        intent: CentralNetworkIntent,
    ) -> Result<(), CentralNetworkServiceError> {
        let user_id = intent.user_id;
        self.db.save_central_network_intent(intent).await?;
        self.publish_user(user_id).await;
        Ok(())
    }

    pub fn gateway_config(&self) -> Option<&crate::central_network::gateway::GatewayConfig> {
        self.network_instances
            .as_ref()
            .map(|instances| instances.config())
    }

    // The intent is already committed. Publishing is retryable and must not make
    // an accepted business mutation appear to have rolled back.
    async fn publish_user(&self, user_id: UserIdInDb) {
        if let Err(error) = self.publish_user_configs(user_id).await {
            tracing::error!(user_id, %error, "central configs will be retried");
        }
    }

    async fn publish_user_configs(
        &self,
        user_id: UserIdInDb,
    ) -> Result<(), CentralNetworkServiceError> {
        use crate::db::entity::networks;
        let networks = networks::Entity::find()
            .filter(networks::Column::UserId.eq(user_id))
            .order_by_asc(networks::Column::Id)
            .all(self.db.orm_db())
            .await?;
        let mut configs_by_device =
            BTreeMap::<Uuid, Vec<crate::webhook::ManagedNetworkConfig>>::new();
        let devices = sqlx::query_scalar::<_, String>(
            r#"
            SELECT machine_id FROM devices WHERE user_id = ?
            UNION SELECT device_id FROM network_members WHERE user_id = ?
            UNION SELECT device_id FROM managed_config_revisions
                WHERE user_id = ? AND config_revision LIKE 'central:%'
            "#,
        )
        .bind(user_id)
        .bind(user_id)
        .bind(user_id)
        .fetch_all(&self.db.inner())
        .await
        .map_err(|error| CentralNetworkServiceError::Database(error.to_string()))?;
        for device_id in devices {
            configs_by_device.insert(
                Uuid::parse_str(&device_id)
                    .map_err(|error| CentralNetworkServiceError::Database(error.to_string()))?,
                Vec::new(),
            );
        }
        // Build the entire snapshot before sending any Full. A failed load must
        // never look like a removed network and erase its last published config.
        let mut intents = Vec::with_capacity(networks.len());
        for network in networks {
            let network_id = Uuid::parse_str(&network.id)
                .map_err(|error| CentralNetworkServiceError::Database(error.to_string()))?;
            let intent = self.load(user_id, network_id).await?;
            let compiled = super::compiler::compile(&intent)
                .map_err(|error| CentralNetworkServiceError::Invalid(error.to_string()))?;
            for member in compiled.members {
                let device_id = Uuid::parse_str(&member.device_id)
                    .map_err(|error| CentralNetworkServiceError::Database(error.to_string()))?;
                configs_by_device.entry(device_id).or_default().push(
                    crate::webhook::ManagedNetworkConfig {
                        instance_id: network_id.to_string(),
                        network_config: serde_json::to_value(member.network_config).map_err(
                            |error| CentralNetworkServiceError::Database(error.to_string()),
                        )?,
                    },
                );
            }
            intents.push(intent);
        }
        if let Some(instances) = &self.network_instances {
            let gateway_ids = intents
                .iter()
                .filter(|intent| matches!(intent.mode, NetworkMode::Gateway { .. }))
                .map(|intent| intent.id)
                .collect::<BTreeSet<_>>();
            for (owner_id, network_id) in instances.network_ids().await {
                if owner_id == user_id && !gateway_ids.contains(&network_id) {
                    instances.remove(owner_id, network_id).await;
                }
            }
            for intent in &intents {
                if gateway_ids.contains(&intent.id) {
                    instances.reconcile(intent).await;
                }
            }
        }
        for (device_id, configs) in configs_by_device {
            match self
                .db
                .publish_central_device_configs(user_id, device_id, configs)
                .await
            {
                Ok((_, true)) => {
                    self.client_manager
                        .invalidate_applied_config_revision(user_id, device_id)
                        .await
                }
                Ok((_, false)) => {}
                Err(error) => {
                    tracing::error!(user_id, %device_id, %error, "central device config will be retried")
                }
            }
        }
        Ok(())
    }
}

fn member_position(
    intent: &CentralNetworkIntent,
    device_id: Uuid,
) -> Result<usize, CentralNetworkServiceError> {
    intent
        .members
        .iter()
        .position(|member| member.device_id == device_id.to_string())
        .ok_or_else(|| CentralNetworkServiceError::NotFound(device_id.to_string()))
}

fn credential_peers(
    temporary_peers: &[TemporaryPeerInfo],
    credential_id: &str,
) -> Vec<TemporaryPeerInfo> {
    temporary_peers
        .iter()
        .filter(|peer| peer.credential_id.as_deref() == Some(credential_id))
        .cloned()
        .collect()
}

fn sync_member_credential_proxy_cidrs(
    intent: &mut CentralNetworkIntent,
    member_position: usize,
) -> Result<(), CentralNetworkServiceError> {
    let member = &intent.members[member_position];
    let Some(credential_id) = member.credential_id.clone() else {
        return Ok(());
    };
    let proxy_cidrs = member
        .config_override
        .as_ref()
        .map(|config| config.proxy_cidrs.clone())
        .unwrap_or_default();
    let mut raw = easytier_core::config::InstanceConfigRaw::default();
    for cidr in &proxy_cidrs {
        easytier_core::config::api_input::add_proxy_network_to_raw(cidr, &mut raw)
            .map_err(|error| CentralNetworkServiceError::Invalid(error.to_string()))?;
    }
    let credential = intent
        .credentials
        .iter_mut()
        .find(|credential| credential.id == credential_id)
        .ok_or_else(|| {
            CentralNetworkServiceError::Database(format!(
                "member credential not found: {credential_id}"
            ))
        })?;
    credential.grant.allowed_proxy_cidrs = raw
        .proxy_network
        .unwrap_or_default()
        .into_iter()
        .map(|proxy| proxy.mapped_cidr.unwrap_or(proxy.cidr).to_string())
        .collect();
    Ok(())
}

fn mode_from_settings(
    settings: &NetworkSettings,
    gateway_config: Option<&crate::central_network::gateway::GatewayConfig>,
) -> Result<NetworkMode, CentralNetworkServiceError> {
    match settings.networking_method.as_str() {
        "PublicServer" | "public_server" => settings
            .public_server_url
            .clone()
            .map(|url| NetworkMode::PublicServer { url })
            .ok_or_else(|| CentralNetworkServiceError::Invalid("missing public server URL".into())),
        "Manual" | "manual" => Ok(NetworkMode::Manual {
            peer_urls: settings.peer_urls.clone(),
        }),
        "Standalone" | "standalone" => Ok(NetworkMode::Standalone),
        "Gateway" | "gateway" => gateway_config
            .map(|config| NetworkMode::Gateway {
                peer_url: config.peer_url.clone(),
            })
            .ok_or_else(|| {
                CentralNetworkServiceError::Invalid("Gateway runtime is disabled".into())
            }),
        value => Err(CentralNetworkServiceError::Invalid(format!(
            "unknown networking method: {value}"
        ))),
    }
}

fn mode_view(mode: &NetworkMode) -> (String, Option<String>, Vec<String>) {
    match mode {
        NetworkMode::PublicServer { url } => ("PublicServer".into(), Some(url.clone()), Vec::new()),
        NetworkMode::Manual { peer_urls } => ("Manual".into(), None, peer_urls.clone()),
        NetworkMode::Standalone => ("Standalone".into(), None, Vec::new()),
        NetworkMode::Gateway { peer_url } => ("Gateway".into(), None, vec![peer_url.clone()]),
    }
}

fn generated_network_name(display_name: &str) -> String {
    let mut slug = display_name
        .trim()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug = slug.trim_matches('-');
    let base = if slug.is_empty() { "net" } else { slug };
    let suffix = OsRng.next_u32();
    format!("{}-{suffix:08x}", base.chars().take(24).collect::<String>())
}

fn random_secret() -> String {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    base64::engine::general_purpose::STANDARD.encode(secret)
}

fn member_runtime_fields(
    response: &CollectNetworkInfoResponse,
    network_id: Uuid,
) -> Option<(bool, Option<String>, Option<String>)> {
    let info = response.info.as_ref()?.map.get(&network_id.to_string())?;
    let virtual_ipv4 = info
        .my_node_info
        .as_ref()
        .and_then(|node| node.virtual_ipv4.as_ref())
        .map(ToString::to_string);
    let error_msg = info.error_msg.clone().filter(|error| !error.is_empty());
    Some((info.running, virtual_ipv4, error_msg))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use easytier::proto::{
        api::manage::{MyNodeInfo, NetworkInstanceRunningInfo, NetworkInstanceRunningInfoMap},
        common::Ipv4Inet,
    };
    use uuid::Uuid;

    use super::*;
    use crate::{FeatureFlags, client_manager::HeartbeatPolicy, db::DeviceHeartbeatRecord};

    #[test]
    fn member_runtime_fields_use_exact_uuid_and_normalize_values() {
        let network_id = Uuid::new_v4();
        let other_network_id = Uuid::new_v4();
        let mut map = std::collections::BTreeMap::from([
            (
                other_network_id.to_string(),
                NetworkInstanceRunningInfo {
                    running: false,
                    error_msg: Some("other instance error".to_owned()),
                    ..Default::default()
                },
            ),
            (
                network_id.to_string(),
                NetworkInstanceRunningInfo {
                    my_node_info: Some(MyNodeInfo {
                        virtual_ipv4: Some(Ipv4Inet {
                            address: Some(std::net::Ipv4Addr::new(10, 88, 0, 9).into()),
                            network_length: 24,
                        }),
                        ..Default::default()
                    }),
                    running: true,
                    error_msg: Some(String::new()),
                    ..Default::default()
                },
            ),
        ]);
        let mut response = CollectNetworkInfoResponse {
            info: Some(NetworkInstanceRunningInfoMap { map: map.clone() }),
        };

        assert_eq!(
            member_runtime_fields(&response, network_id),
            Some((true, Some("10.88.0.9/24".to_owned()), None))
        );
        assert_eq!(member_runtime_fields(&response, Uuid::new_v4()), None);

        map.get_mut(&network_id.to_string()).unwrap().error_msg = Some("runtime failed".to_owned());
        response.info = Some(NetworkInstanceRunningInfoMap { map });
        assert_eq!(
            member_runtime_fields(&response, network_id),
            Some((
                true,
                Some("10.88.0.9/24".to_owned()),
                Some("runtime failed".to_owned())
            ))
        );
    }

    struct NoopGatewayRuntime;

    #[async_trait]
    impl crate::central_network::gateway::GatewayRuntime for NoopGatewayRuntime {
        async fn start(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn stop(&self) {}

        fn peer_manager(&self) -> Option<Arc<easytier_core::peers::peer_manager::PeerManagerCore>> {
            None
        }
    }

    struct NoopGatewayFactory;

    impl crate::central_network::gateway::GatewayRuntimeFactory for NoopGatewayFactory {
        fn build(
            &self,
            _spec: &crate::central_network::gateway::GatewayRuntimeSpec,
        ) -> anyhow::Result<Arc<dyn crate::central_network::gateway::GatewayRuntime>> {
            Ok(Arc::new(NoopGatewayRuntime))
        }
    }

    struct FailingGatewayFactory {
        fail_build: AtomicBool,
        fail_start: AtomicBool,
    }

    struct FailingGatewayRuntime {
        fail_start: bool,
    }

    #[async_trait]
    impl crate::central_network::gateway::GatewayRuntime for FailingGatewayRuntime {
        async fn start(&self) -> anyhow::Result<()> {
            anyhow::ensure!(!self.fail_start, "injected start failure");
            Ok(())
        }

        async fn stop(&self) {}

        fn peer_manager(&self) -> Option<Arc<easytier_core::peers::peer_manager::PeerManagerCore>> {
            None
        }
    }

    impl crate::central_network::gateway::GatewayRuntimeFactory for FailingGatewayFactory {
        fn build(
            &self,
            _spec: &crate::central_network::gateway::GatewayRuntimeSpec,
        ) -> anyhow::Result<Arc<dyn crate::central_network::gateway::GatewayRuntime>> {
            anyhow::ensure!(
                !self.fail_build.swap(false, Ordering::AcqRel),
                "injected build failure"
            );
            Ok(Arc::new(FailingGatewayRuntime {
                fail_start: self.fail_start.swap(false, Ordering::AcqRel),
            }))
        }
    }

    struct ObservingGatewayRuntime {
        observation:
            Arc<std::sync::Mutex<crate::central_network::gateway::GatewayNetworkObservation>>,
    }

    #[async_trait]
    impl crate::central_network::gateway::GatewayRuntime for ObservingGatewayRuntime {
        async fn start(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn stop(&self) {}

        fn peer_manager(&self) -> Option<Arc<easytier_core::peers::peer_manager::PeerManagerCore>> {
            None
        }

        async fn observe_network(
            &self,
        ) -> Option<crate::central_network::gateway::GatewayNetworkObservation> {
            Some(self.observation.lock().unwrap().clone())
        }
    }

    struct ObservingGatewayFactory {
        observation:
            Arc<std::sync::Mutex<crate::central_network::gateway::GatewayNetworkObservation>>,
    }

    impl crate::central_network::gateway::GatewayRuntimeFactory for ObservingGatewayFactory {
        fn build(
            &self,
            _spec: &crate::central_network::gateway::GatewayRuntimeSpec,
        ) -> anyhow::Result<Arc<dyn crate::central_network::gateway::GatewayRuntime>> {
            Ok(Arc::new(ObservingGatewayRuntime {
                observation: self.observation.clone(),
            }))
        }
    }

    async fn service() -> (CentralNetworkService, i32, i32) {
        let db = crate::db::Db::memory_db().await;
        let user_a = db.auto_create_user("tenant-a").await.unwrap().id;
        let user_b = db.auto_create_user("tenant-b").await.unwrap().id;
        let client_manager = std::sync::Arc::new(crate::client_manager::ClientManager::new(
            db.clone(),
            None,
            HeartbeatPolicy::default(),
            std::sync::Arc::new(FeatureFlags::default()),
            std::sync::Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        ));
        (
            CentralNetworkService::new(db, client_manager),
            user_a,
            user_b,
        )
    }

    async fn service_with_gateway() -> (CentralNetworkService, i32) {
        service_with_gateway_factory(Arc::new(NoopGatewayFactory)).await
    }

    async fn service_with_gateway_factory(
        factory: Arc<dyn crate::central_network::gateway::GatewayRuntimeFactory>,
    ) -> (CentralNetworkService, i32) {
        let db = crate::db::Db::memory_db().await;
        let user_id = db.auto_create_user("gateway-tenant").await.unwrap().id;
        let instances = Arc::new(
            crate::central_network::gateway::NetworkInstanceManager::with_factory(
                crate::central_network::gateway::GatewayConfig {
                    peer_url: "tcp://configured.example:22020".to_owned(),
                    relay_data: false,
                },
                factory,
            ),
        );
        let client_manager = Arc::new(crate::client_manager::ClientManager::new(
            db.clone(),
            None,
            HeartbeatPolicy::default(),
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        ));
        (
            CentralNetworkService::with_gateway(db, client_manager, Some(instances)),
            user_id,
        )
    }

    async fn service_with_gateway_observation() -> (
        CentralNetworkService,
        i32,
        Arc<std::sync::Mutex<crate::central_network::gateway::GatewayNetworkObservation>>,
    ) {
        let db = crate::db::Db::memory_db().await;
        let user_id = db
            .auto_create_user("observed-gateway-tenant")
            .await
            .unwrap()
            .id;
        let observation = Arc::new(std::sync::Mutex::new(
            crate::central_network::gateway::GatewayNetworkObservation::default(),
        ));
        let instances = Arc::new(
            crate::central_network::gateway::NetworkInstanceManager::with_factory(
                crate::central_network::gateway::GatewayConfig {
                    peer_url: "tcp://configured.example:22020".to_owned(),
                    relay_data: false,
                },
                Arc::new(ObservingGatewayFactory {
                    observation: observation.clone(),
                }),
            ),
        );
        let client_manager = Arc::new(crate::client_manager::ClientManager::new(
            db.clone(),
            None,
            HeartbeatPolicy::default(),
            Arc::new(FeatureFlags::default()),
            Arc::new(crate::webhook::WebhookConfig::new(
                None, None, None, None, None,
            )),
        ));
        (
            CentralNetworkService::with_gateway(db, client_manager, Some(instances)),
            user_id,
            observation,
        )
    }

    async fn register_device(service: &CentralNetworkService, user_id: i32, device_id: Uuid) {
        service
            .db
            .upsert_device_heartbeat(DeviceHeartbeatRecord {
                user_id,
                machine_id: device_id,
                hostname: format!("device-{device_id}"),
                easytier_version: "test".to_owned(),
                device_os: "{}".to_owned(),
                client_url: format!("tcp://{device_id}"),
            })
            .await
            .unwrap();
    }

    fn standalone_settings() -> NetworkSettings {
        NetworkSettings {
            display_name: "Engineering".to_owned(),
            network_name: Some("engineering".to_owned()),
            networking_method: "Standalone".to_owned(),
            public_server_url: None,
            peer_urls: Vec::new(),
            virtual_cidr: Some("10.88.0.0/24".to_owned()),
            secure_mode: true,
        }
    }

    fn gateway_settings(peer_urls: Vec<String>) -> NetworkSettings {
        NetworkSettings {
            networking_method: "Gateway".to_owned(),
            peer_urls,
            ..standalone_settings()
        }
    }

    #[tokio::test]
    async fn virtual_subnets_are_normalized_on_create_and_update() {
        let (service, user_id, _) = service().await;
        let existing = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let existing_id = Uuid::parse_str(&existing.network_id).unwrap();

        for (index, (input, expected)) in [
            (Some("10.88.0.0"), Some("10.88.0.0/24")),
            (Some(" \t10.88.0.0\n"), Some("10.88.0.0/24")),
            (Some(" 10.88.0.0/25 "), Some("10.88.0.0/25")),
            (Some("10.88.0.0/16"), Some("10.88.0.0/16")),
            (Some(""), None),
            (Some(" \t\n"), None),
            (None, None),
        ]
        .into_iter()
        .enumerate()
        {
            let mut settings = standalone_settings();
            settings.network_name = Some(format!("normalized-{index}"));
            settings.virtual_cidr = input.map(str::to_owned);
            let created = service
                .create_network(user_id, settings, None)
                .await
                .unwrap();
            assert_eq!(created.virtual_cidr.as_deref(), expected);
            let created_id = Uuid::parse_str(&created.network_id).unwrap();
            assert_eq!(
                service
                    .get_network(user_id, created_id)
                    .await
                    .unwrap()
                    .virtual_cidr
                    .as_deref(),
                expected
            );

            let mut settings = standalone_settings();
            settings.virtual_cidr = input.map(str::to_owned);
            let updated = service
                .update_network(
                    user_id,
                    existing_id,
                    UpdateNetworkReq {
                        settings,
                        network_secret: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(updated.virtual_cidr.as_deref(), expected);
            assert_eq!(
                service
                    .get_network(user_id, existing_id)
                    .await
                    .unwrap()
                    .virtual_cidr
                    .as_deref(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn virtual_subnets_still_reject_invalid_create_and_update_requests() {
        let (service, user_id, _) = service().await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let id = Uuid::parse_str(&network.network_id).unwrap();
        let before = service.load(user_id, id).await.unwrap();

        for input in [
            "not-an-ip",
            "10.88.0.256",
            "10.88.0.0/",
            "10.88.0.0/33",
            "10.88.0.0/invalid",
            "10.88.0.0/24/24",
            "fd00::",
        ] {
            let mut settings = standalone_settings();
            settings.network_name = Some("invalid-subnet".to_owned());
            settings.virtual_cidr = Some(input.to_owned());
            assert!(matches!(
                service
                    .create_network(user_id, settings.clone(), None)
                    .await,
                Err(CentralNetworkServiceError::Invalid(_))
            ));
            assert!(matches!(
                service
                    .update_network(
                        user_id,
                        id,
                        UpdateNetworkReq {
                            settings,
                            network_secret: None,
                        },
                    )
                    .await,
                Err(CentralNetworkServiceError::Invalid(_))
            ));
            assert_eq!(service.load(user_id, id).await.unwrap(), before);
        }
    }

    #[tokio::test]
    async fn equivalent_virtual_subnet_updates_preserve_automatic_allocations() {
        let (service, user_id, _) = service().await;
        let devices = [Uuid::new_v4(), Uuid::new_v4()];
        for device in devices {
            register_device(&service, user_id, device).await;
        }
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let id = Uuid::parse_str(&network.network_id).unwrap();
        service
            .add_members(
                user_id,
                id,
                AddMembersReq {
                    device_ids: devices.iter().map(ToString::to_string).collect(),
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();
        let initial = service.load(user_id, id).await.unwrap();
        let first = initial
            .members
            .iter()
            .find(|member| member.allocated_ipv4.as_deref() == Some("10.88.0.1"))
            .unwrap();
        service
            .remove_member(user_id, id, Uuid::parse_str(&first.device_id).unwrap())
            .await
            .unwrap();
        let before = service.load(user_id, id).await.unwrap();
        assert_eq!(before.members.len(), 1);
        assert_eq!(
            before.members[0].allocated_ipv4.as_deref(),
            Some("10.88.0.2")
        );

        // The free .1 address would replace .2 if an equivalent edit reset allocations.
        for input in ["10.88.0.0", " \t10.88.0.0\n", " 10.88.0.0/24 "] {
            let mut settings = standalone_settings();
            settings.virtual_cidr = Some(input.to_owned());
            service
                .update_network(
                    user_id,
                    id,
                    UpdateNetworkReq {
                        settings,
                        network_secret: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(service.load(user_id, id).await.unwrap(), before);
        }
    }

    #[tokio::test]
    async fn central_publication_preserves_direct_configs_and_removes_only_old_members() {
        use easytier::common::config::ConfigSource;
        use easytier_core::management::remote_client::Storage as _;
        let (service, user_id, _) = service().await;
        let device = Uuid::new_v4();
        register_device(&service, user_id, device).await;
        let enabled = Uuid::new_v4();
        let disabled = Uuid::new_v4();
        let local = Uuid::new_v4();
        for (id, source) in [
            (enabled, ConfigSource::Web),
            (disabled, ConfigSource::Web),
            (local, ConfigSource::User),
        ] {
            service
                .db
                .insert_or_update_user_network_config(
                    (user_id, device),
                    id,
                    NetworkConfig {
                        instance_id: Some(id.to_string()),
                        network_name: Some(id.to_string()),
                        ..Default::default()
                    },
                    source,
                )
                .await
                .unwrap();
        }
        service
            .db
            .update_network_config_state((user_id, device), disabled, true)
            .await
            .unwrap();
        let before = service
            .db
            .list_network_configs(
                (user_id, device),
                easytier_core::management::remote_client::ListNetworkProps::All,
            )
            .await
            .unwrap();
        service.reconcile_all().await.unwrap();
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        for delete_network in [false, true] {
            service
                .add_members(
                    user_id,
                    network_id,
                    AddMembersReq {
                        device_ids: vec![device.to_string()],
                        temporary: false,
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();
            assert!(
                service
                    .db
                    .get_network_config((user_id, device), &network.network_id)
                    .await
                    .unwrap()
                    .is_some()
            );
            if delete_network {
                service.delete_network(user_id, network_id).await.unwrap();
            } else {
                service
                    .remove_member(user_id, network_id, device)
                    .await
                    .unwrap();
            }
            let restarted =
                CentralNetworkService::new(service.db.clone(), service.client_manager.clone());
            restarted.reconcile_all().await.unwrap();
            assert!(
                service
                    .db
                    .get_network_config((user_id, device), &network.network_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            for expected in &before {
                assert_eq!(
                    service
                        .db
                        .get_network_config((user_id, device), &expected.network_instance_id)
                        .await
                        .unwrap()
                        .as_ref(),
                    Some(expected)
                );
            }
        }
    }

    #[tokio::test]
    async fn subnet_changes_reallocate_automatic_addresses_and_preserve_manual_intent() {
        let (service, user_id, _) = service().await;
        let devices = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        for device in devices {
            register_device(&service, user_id, device).await;
        }
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let id = Uuid::parse_str(&network.network_id).unwrap();
        service
            .add_members(
                user_id,
                id,
                AddMembersReq {
                    device_ids: devices.iter().map(ToString::to_string).collect(),
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();
        let initial = service.load(user_id, id).await.unwrap();
        let manual_ip = initial
            .members
            .iter()
            .find(|member| member.device_id == devices[1].to_string())
            .unwrap()
            .allocated_ipv4
            .clone()
            .unwrap();
        service
            .update_member(
                user_id,
                id,
                devices[0],
                UpdateMemberReq {
                    virtual_ipv4: Some(manual_ip.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut settings = standalone_settings();
        settings.virtual_cidr = Some("10.88.0.0/25".into());
        service
            .update_network(
                user_id,
                id,
                UpdateNetworkReq {
                    settings: settings.clone(),
                    network_secret: None,
                },
            )
            .await
            .unwrap();
        let mixed = service.load(user_id, id).await.unwrap();
        let manual = mixed
            .members
            .iter()
            .find(|member| member.device_id == devices[0].to_string())
            .unwrap();
        assert_eq!(manual.virtual_ipv4.as_deref(), Some(manual_ip.as_str()));
        assert!(manual.allocated_ipv4.is_none());
        let addresses: BTreeSet<_> = super::super::compiler::compile(&mixed)
            .unwrap()
            .members
            .into_iter()
            .map(|member| member.network_config.virtual_ipv4.unwrap())
            .collect();
        assert_eq!(addresses.len(), devices.len());
        settings.virtual_cidr = Some("192.168.5.0/24".into());
        assert!(
            service
                .update_network(
                    user_id,
                    id,
                    UpdateNetworkReq {
                        settings: settings.clone(),
                        network_secret: None
                    }
                )
                .await
                .is_err()
        );
        assert_eq!(service.load(user_id, id).await.unwrap(), mixed);
        service
            .update_member(
                user_id,
                id,
                devices[0],
                UpdateMemberReq {
                    virtual_ipv4: Some(String::new()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        service
            .update_network(
                user_id,
                id,
                UpdateNetworkReq {
                    settings: settings.clone(),
                    network_secret: None,
                },
            )
            .await
            .unwrap();
        let moved = service.load(user_id, id).await.unwrap();
        assert!(moved.members.iter().all(|member| {
            member.virtual_ipv4.is_none()
                && member
                    .allocated_ipv4
                    .as_deref()
                    .is_some_and(|ip| ip.starts_with("192.168.5."))
        }));
        settings.virtual_cidr = None;
        service
            .update_network(
                user_id,
                id,
                UpdateNetworkReq {
                    settings,
                    network_secret: None,
                },
            )
            .await
            .unwrap();
        let dhcp = service.load(user_id, id).await.unwrap();
        assert!(
            dhcp.members
                .iter()
                .all(|member| member.virtual_ipv4.is_none() && member.allocated_ipv4.is_none())
        );
        assert!(
            super::super::compiler::compile(&dhcp)
                .unwrap()
                .members
                .iter()
                .all(|member| member.network_config.dhcp == Some(true)
                    && member.network_config.virtual_ipv4.is_none())
        );
    }

    #[tokio::test]
    async fn device_delete_waits_for_core_shutdown_and_restores_intent_on_failure() {
        use easytier::{
            instance::factory::native_instance_manager,
            proto::rpc::standalone::{runtime_udp_tunnel_dialer, runtime_udp_tunnel_listener},
            web_client::WebClient,
        };
        async fn wait_for(mut condition: impl FnMut() -> bool) {
            tokio::time::timeout(Duration::from_secs(20), async {
                while !condition() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
        }
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("delete-owner").await.unwrap().id;
        let webhook = crate::webhook::WebhookConfig::new(None, None, None, None, None)
            .with_handler(Arc::new(
                crate::central_network::device_auth::DeviceAuth::new(db.clone(), false),
            ));
        let mut manager = ClientManager::new(
            db.clone(),
            None,
            HeartbeatPolicy::from_millis(1000, 10000).unwrap(),
            Arc::new(FeatureFlags::default()),
            Arc::new(webhook),
        );
        let url = manager
            .add_listener(runtime_udp_tunnel_listener(
                "udp://127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            ))
            .await
            .unwrap();
        let service = CentralNetworkService::new(db.clone(), Arc::new(manager));
        let device = Uuid::new_v4();
        register_device(&service, user_id, device).await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![device.to_string()],
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();
        service
            .set_member_config(
                user_id,
                network_id,
                device,
                NetworkConfig {
                    no_tun: Some(true),
                    disable_ipv6: Some(true),
                    multi_thread: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let before = service.load(user_id, network_id).await.unwrap();
        let core = Arc::new(native_instance_manager());
        let _client = WebClient::new(
            runtime_udp_tunnel_dialer(url),
            "delete-owner",
            device,
            "delete-test",
            false,
            core.clone(),
            None,
        );
        wait_for(|| core.config(network_id).is_some()).await;
        sqlx::query("CREATE TRIGGER fail_device_delete BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT, 'forced deletion failure'); END")
            .execute(&db.inner()).await.unwrap();
        assert!(service.delete_device(user_id, device, true).await.is_err());
        assert_eq!(service.load(user_id, network_id).await.unwrap(), before);
        assert!(db.list_blocked_devices(user_id).await.unwrap().is_empty());
        wait_for(|| core.config(network_id).is_some()).await;
        sqlx::query("DROP TRIGGER fail_device_delete")
            .execute(&db.inner())
            .await
            .unwrap();
        assert!(service.delete_device(user_id, device, true).await.unwrap());
        assert!(core.config(network_id).is_none());
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(core.config(network_id).is_none());
        assert_eq!(db.list_blocked_devices(user_id).await.unwrap().len(), 1);
        let replacement = Uuid::new_v4();
        register_device(&service, user_id, replacement).await;
        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![replacement.to_string()],
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            service.load(user_id, network_id).await.unwrap().members[0].allocated_ipv4,
            before.members[0].allocated_ipv4
        );
        assert!(core.config(network_id).is_none());
    }

    #[tokio::test]
    async fn device_network_summaries_are_tenant_scoped() {
        let (service, user_a, user_b) = service().await;
        let device_id = Uuid::new_v4();
        register_device(&service, user_a, device_id).await;
        register_device(&service, user_b, device_id).await;

        let mut alpha_settings = standalone_settings();
        alpha_settings.display_name = "Alpha".to_owned();
        alpha_settings.network_name = Some("alpha".to_owned());
        let alpha = service
            .create_network(user_a, alpha_settings, None)
            .await
            .unwrap();
        service
            .add_members(
                user_a,
                Uuid::parse_str(&alpha.network_id).unwrap(),
                AddMembersReq {
                    device_ids: vec![device_id.to_string()],
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        let mut beta_settings = standalone_settings();
        beta_settings.display_name = "Beta".to_owned();
        beta_settings.network_name = Some("beta".to_owned());
        let beta = service
            .create_network(user_a, beta_settings, None)
            .await
            .unwrap();
        service
            .add_members(
                user_a,
                Uuid::parse_str(&beta.network_id).unwrap(),
                AddMembersReq {
                    device_ids: vec![device_id.to_string()],
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        let mut other_settings = standalone_settings();
        other_settings.display_name = "Other tenant".to_owned();
        other_settings.network_name = Some("other-tenant".to_owned());
        let other = service
            .create_network(user_b, other_settings, None)
            .await
            .unwrap();
        service
            .add_members(
                user_b,
                Uuid::parse_str(&other.network_id).unwrap(),
                AddMembersReq {
                    device_ids: vec![device_id.to_string()],
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        let summaries = service.list_device_networks(user_a).await.unwrap();
        let device_summaries = summaries.get(&device_id.to_string()).unwrap();
        assert_eq!(device_summaries.len(), 2);
        assert!(
            device_summaries
                .iter()
                .any(|summary| summary.network_id == alpha.network_id)
        );
        assert!(
            device_summaries
                .iter()
                .any(|summary| summary.network_id == beta.network_id)
        );
        assert!(
            device_summaries
                .iter()
                .all(|summary| summary.network_id != other.network_id)
        );

        let empty = service
            .create_network(user_a, standalone_settings(), None)
            .await
            .unwrap();
        let networks = service.list_networks(user_a).await.unwrap();
        assert_eq!(networks.len(), 3);
        for network in networks {
            assert_ne!(network.network_id, other.network_id);
            assert_eq!(network.online_member_count, 0);
            assert_eq!(
                network.member_count,
                usize::from(network.network_id != empty.network_id)
            );
        }
        let other_networks = service.list_networks(user_b).await.unwrap();
        assert_eq!(other_networks.len(), 1);
        assert_eq!(other_networks[0].network_id, other.network_id);
        assert_eq!(other_networks[0].member_count, 1);
    }

    #[tokio::test]
    async fn gateway_mutations_retire_old_authorization_before_returning() {
        let (service, user_id) = service_with_gateway().await;
        let device_id = Uuid::new_v4();
        register_device(&service, user_id, device_id).await;
        let network = service
            .create_network(user_id, gateway_settings(Vec::new()), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        let instances = service.network_instances().unwrap();
        assert_eq!(
            instances
                .actual_mesh_name(user_id, network_id)
                .await
                .as_deref(),
            Some("engineering")
        );

        service
            .update_network(
                user_id,
                network_id,
                UpdateNetworkReq {
                    settings: gateway_settings(Vec::new()),
                    network_secret: Some("new-secret".to_owned()),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            instances
                .actual_mesh_name(user_id, network_id)
                .await
                .as_deref(),
            Some("engineering")
        );

        service.delete_network(user_id, network_id).await.unwrap();
        assert_eq!(instances.actual_mesh_name(user_id, network_id).await, None);

        let network = service
            .create_network(user_id, gateway_settings(Vec::new()), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();

        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![device_id.to_string()],
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();
        assert!(
            service
                .delete_device(user_id, device_id, false)
                .await
                .unwrap()
        );
        assert_eq!(
            instances
                .actual_mesh_name(user_id, network_id)
                .await
                .as_deref(),
            Some("engineering")
        );
        assert!(
            service
                .load(user_id, network_id)
                .await
                .unwrap()
                .members
                .is_empty()
        );
    }

    #[tokio::test]
    async fn gateway_update_ignores_client_peer_urls() {
        let (service, user_id) = service_with_gateway().await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();

        service
            .update_network(
                user_id,
                network_id,
                UpdateNetworkReq {
                    settings: gateway_settings(vec!["tcp://attacker.invalid:1".to_owned()]),
                    network_secret: None,
                },
            )
            .await
            .unwrap();
        let intent = service.load(user_id, network_id).await.unwrap();

        assert_eq!(
            intent.mode,
            NetworkMode::Gateway {
                peer_url: "tcp://configured.example:22020".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn gateway_mode_is_rejected_when_runtime_is_disabled() {
        let (service, user_id, _) = service().await;

        assert!(matches!(
            service
                .create_network(
                    user_id,
                    gateway_settings(vec!["tcp://client.example:22020".to_owned()]),
                    None,
                )
                .await,
            Err(CentralNetworkServiceError::Invalid(message))
                if message.contains("Gateway runtime is disabled")
        ));
    }

    #[tokio::test]
    async fn temporary_member_gets_exclusive_group_credential_without_acl_secret() {
        let (service, user_id, _) = service().await;
        let permanent_device = Uuid::new_v4();
        let temporary_device = Uuid::new_v4();
        register_device(&service, user_id, permanent_device).await;
        register_device(&service, user_id, temporary_device).await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();

        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![permanent_device.to_string()],
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();
        service
            .update_acl_policy(
                user_id,
                network_id,
                crate::central_network::model::AclPolicy::default(),
            )
            .await
            .unwrap();
        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![temporary_device.to_string()],
                    temporary: true,
                    ttl_seconds: Some(300),
                },
            )
            .await
            .unwrap();

        let intent = service
            .db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        let permanent = intent
            .members
            .iter()
            .find(|member| member.device_id == permanent_device.to_string())
            .unwrap();
        assert!(permanent.acl_group_secret.is_some());
        let temporary = intent
            .members
            .iter()
            .find(|member| member.device_id == temporary_device.to_string())
            .unwrap();
        assert!(temporary.acl_group_secret.is_none());
        let credential = intent
            .credentials
            .iter()
            .find(|credential| Some(&credential.id) == temporary.credential_id.as_ref())
            .unwrap();
        assert!(!credential.grant.reusable);
        assert_eq!(
            credential.grant.acl_groups,
            vec![crate::central_network::model::member_group_name(
                temporary.id
            )]
        );
    }

    #[tokio::test]
    async fn temporary_member_proxy_cidrs_follow_its_credential_grant() {
        let (service, user_id, _) = service().await;
        let device_id = Uuid::new_v4();
        register_device(&service, user_id, device_id).await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![device_id.to_string()],
                    temporary: true,
                    ttl_seconds: Some(300),
                },
            )
            .await
            .unwrap();

        service
            .update_member(
                user_id,
                network_id,
                device_id,
                UpdateMemberReq {
                    proxy_cidrs: Some(vec!["10.90.0.0/24->192.168.90.0/24".into()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let intent = service.load(user_id, network_id).await.unwrap();
        let credential_id = intent.members[0].credential_id.clone().unwrap();
        assert_eq!(
            intent
                .credentials
                .iter()
                .find(|credential| credential.id == credential_id)
                .unwrap()
                .grant
                .allowed_proxy_cidrs,
            vec!["192.168.90.0/24"]
        );

        service
            .set_member_config(
                user_id,
                network_id,
                device_id,
                NetworkConfig {
                    proxy_cidrs: vec![
                        "10.91.0.0/24->192.168.91.0/24".into(),
                        "10.92.0.0/24".into(),
                    ],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let intent = service.load(user_id, network_id).await.unwrap();
        assert_eq!(
            intent
                .credentials
                .iter()
                .find(|credential| credential.id == credential_id)
                .unwrap()
                .grant
                .allowed_proxy_cidrs,
            vec!["192.168.91.0/24", "10.92.0.0/24"]
        );

        service
            .clear_member_config(user_id, network_id, device_id)
            .await
            .unwrap();
        let intent = service.load(user_id, network_id).await.unwrap();
        assert!(
            intent
                .credentials
                .iter()
                .find(|credential| credential.id == credential_id)
                .unwrap()
                .grant
                .allowed_proxy_cidrs
                .is_empty()
        );
    }

    #[tokio::test]
    async fn central_persist_waits_for_the_service_mutation_boundary() {
        let (service, user_id, _) = service().await;
        let device_id = Uuid::new_v4();
        register_device(&service, user_id, device_id).await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![device_id.to_string()],
                    temporary: false,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();

        let guards = service.mutation_lock.lock().await;
        let waiting_service = service.clone();
        let update = tokio::spawn(async move {
            waiting_service
                .update_member(
                    user_id,
                    network_id,
                    device_id,
                    UpdateMemberReq {
                        hostname_override: Some("after-lock".into()),
                        ..Default::default()
                    },
                )
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!update.is_finished());
        drop(guards);
        tokio::time::timeout(std::time::Duration::from_secs(1), update)
            .await
            .expect("central mutation must resume after the device guard is released")
            .unwrap()
            .unwrap();
        assert_eq!(
            service.load(user_id, network_id).await.unwrap().members[0]
                .hostname
                .as_deref(),
            Some("after-lock")
        );
    }

    #[tokio::test]
    async fn tenant_cannot_load_or_mutate_another_tenants_network() {
        let (service, user_a, user_b) = service().await;
        let network = service
            .create_network(user_a, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();

        assert!(matches!(
            service.get_network(user_b, network_id).await,
            Err(CentralNetworkServiceError::NotFound(_))
        ));
        assert!(matches!(
            service
                .update_network(
                    user_b,
                    network_id,
                    UpdateNetworkReq {
                        settings: standalone_settings(),
                        network_secret: None,
                    },
                )
                .await,
            Err(CentralNetworkServiceError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn credential_in_use_by_member_cannot_be_revoked() {
        let (service, user_id, _) = service().await;
        let device_id = Uuid::new_v4();
        register_device(&service, user_id, device_id).await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![device_id.to_string()],
                    temporary: true,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();
        let credential_id = service
            .db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap()
            .members[0]
            .credential_id
            .clone()
            .unwrap();

        assert!(matches!(
            service
                .revoke_credential(user_id, network_id, &credential_id)
                .await,
            Err(CentralNetworkServiceError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn rejected_member_batch_does_not_persist_a_partial_candidate() {
        let (service, user_id, _) = service().await;
        let valid_device = Uuid::new_v4();
        register_device(&service, user_id, valid_device).await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();

        assert!(matches!(
            service
                .add_members(
                    user_id,
                    network_id,
                    AddMembersReq {
                        device_ids: vec![valid_device.to_string(), Uuid::new_v4().to_string()],
                        temporary: false,
                        ttl_seconds: None,
                    },
                )
                .await,
            Err(CentralNetworkServiceError::NotFound(_))
        ));
        let intent = service
            .db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        assert!(intent.members.is_empty());
        assert!(intent.credentials.is_empty());
    }

    #[tokio::test]
    async fn concurrent_mutations_do_not_overwrite_each_others_intent() {
        let (service, user_id, _) = service().await;
        let service = Arc::new(service);
        let first_device = Uuid::new_v4();
        let second_device = Uuid::new_v4();
        register_device(&service, user_id, first_device).await;
        register_device(&service, user_id, second_device).await;
        let network = service
            .create_network(user_id, standalone_settings(), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();

        let add_first = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .add_members(
                        user_id,
                        network_id,
                        AddMembersReq {
                            device_ids: vec![first_device.to_string()],
                            temporary: false,
                            ttl_seconds: None,
                        },
                    )
                    .await
            })
        };
        let add_second = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .add_members(
                        user_id,
                        network_id,
                        AddMembersReq {
                            device_ids: vec![second_device.to_string()],
                            temporary: false,
                            ttl_seconds: None,
                        },
                    )
                    .await
            })
        };
        add_first.await.unwrap().unwrap();
        add_second.await.unwrap().unwrap();

        let intent = service
            .db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(intent.members.len(), 2);
    }

    #[tokio::test]
    async fn credential_peer_remains_visible_in_member_and_credential_views() {
        let (service, user_id, observation) = service_with_gateway_observation().await;
        let device_id = Uuid::new_v4();
        register_device(&service, user_id, device_id).await;
        let network = service
            .create_network(user_id, gateway_settings(Vec::new()), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        service
            .add_members(
                user_id,
                network_id,
                AddMembersReq {
                    device_ids: vec![device_id.to_string()],
                    temporary: true,
                    ttl_seconds: None,
                },
            )
            .await
            .unwrap();
        let intent = service.load(user_id, network_id).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if service
                    .network_instances()
                    .unwrap()
                    .observe_network(user_id, network_id)
                    .await
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Gateway runtime did not converge");
        let credential = &intent.credentials[0];
        let private: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&credential.secret)
            .unwrap()
            .try_into()
            .unwrap();
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
        *observation.lock().unwrap() = crate::central_network::gateway::GatewayNetworkObservation {
            connections: vec![easytier_proto::core_peer::peer::PeerConnInfo {
                peer_id: 42,
                network_name: intent.network_name,
                peer_identity_type: easytier_proto::peer_rpc::PeerIdentityType::Credential as i32,
                noise_remote_static_pubkey: public.as_bytes().to_vec(),
                ..Default::default()
            }],
            routes: vec![easytier_proto::core_peer::peer::Route {
                peer_id: 42,
                hostname: "registered-temporary-device".to_owned(),
                version: "2.7.0".to_owned(),
                ..Default::default()
            }],
        };

        let credentials = service.list_credentials(user_id, network_id).await.unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].online_peers.len(), 1);
        assert_eq!(
            credentials[0].online_peers[0].hostname.as_deref(),
            Some("registered-temporary-device")
        );

        let members = service.list_members(user_id, network_id).await.unwrap();
        assert_eq!(members.members.len(), 1);
        assert_eq!(members.temporary_peers.len(), 1);
        assert_eq!(members.temporary_peers[0].peer_id, 42);
    }

    #[tokio::test]
    async fn service_reconciler_restores_tenants_and_retires_orphan_gateways() {
        let (service, user_id) = service_with_gateway().await;
        let second_user = service
            .db
            .auto_create_user("second-gateway-owner")
            .await
            .unwrap()
            .id;
        let network = service
            .create_network(user_id, gateway_settings(Vec::new()), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        let mut second = service.load(user_id, network_id).await.unwrap();
        second.user_id = second_user;
        second.network_name = "second-mesh".to_owned();
        service
            .db
            .save_central_network_intent(second)
            .await
            .unwrap();
        let instances = service.network_instances().unwrap().clone();
        instances.remove(user_id, network_id).await;
        assert!(instances.network_ids().await.is_empty());

        // Startup uses the same service worker as subsequent complete publishes.
        let service = Arc::new(service);
        service.start_reconciler();
        tokio::time::timeout(Duration::from_secs(2), async {
            while instances.network_ids().await.len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            instances.actual_mesh_name(user_id, network_id).await,
            Some(network.network_name)
        );
        assert_eq!(
            instances.actual_mesh_name(second_user, network_id).await,
            Some("second-mesh".to_owned())
        );

        // Simulate a committed deletion with no immediate publication. The
        // runtime owner is still visited even with no devices or intents left.
        service
            .db
            .delete_central_network_intent(user_id, network_id)
            .await
            .unwrap();
        service.reconcile_all().await.unwrap();
        assert_eq!(instances.actual_mesh_name(user_id, network_id).await, None);
        assert!(
            instances
                .actual_mesh_name(second_user, network_id)
                .await
                .is_some()
        );

        let mut second = service.load(second_user, network_id).await.unwrap();
        second.mode = NetworkMode::Standalone;
        service
            .db
            .save_central_network_intent(second)
            .await
            .unwrap();
        service.reconcile_all().await.unwrap();
        assert!(instances.network_ids().await.is_empty());
    }

    #[tokio::test]
    async fn service_reconcile_retries_gateway_build_and_start_failures() {
        let (service, user_id) = service_with_gateway_factory(Arc::new(FailingGatewayFactory {
            fail_build: AtomicBool::new(true),
            fail_start: AtomicBool::new(true),
        }))
        .await;
        let network = service
            .create_network(user_id, gateway_settings(Vec::new()), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        let instances = service.network_instances().unwrap();
        assert!(instances.network_ids().await.is_empty());
        assert!(service.load(user_id, network_id).await.is_ok());

        service.reconcile_all().await.unwrap();
        assert!(instances.network_ids().await.is_empty());
        service.reconcile_all().await.unwrap();
        assert_eq!(instances.network_ids().await, vec![(user_id, network_id)]);
        service.delete_network(user_id, network_id).await.unwrap();
        assert!(instances.network_ids().await.is_empty());
    }

    #[tokio::test]
    async fn invalid_full_snapshot_does_not_retire_a_published_gateway() {
        let (service, user_id) = service_with_gateway().await;
        let network = service
            .create_network(user_id, gateway_settings(Vec::new()), None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        // A committed but invalid full snapshot must not partially remove the
        // previous runtime before the whole tenant intent can be compiled.
        sqlx::query("UPDATE networks SET networking_method = 'Standalone', network_name = '' WHERE user_id = ? AND id = ?")
            .bind(user_id).bind(network_id.to_string())
            .execute(&service.db.inner()).await.unwrap();
        service.reconcile_all().await.unwrap();
        assert_eq!(
            service.network_instances().unwrap().network_ids().await,
            vec![(user_id, network_id)]
        );
        sqlx::query("UPDATE networks SET network_name = ? WHERE user_id = ? AND id = ?")
            .bind(network.network_name)
            .bind(user_id)
            .bind(network_id.to_string())
            .execute(&service.db.inner())
            .await
            .unwrap();
        service.reconcile_all().await.unwrap();
        assert!(
            service
                .network_instances()
                .unwrap()
                .network_ids()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn full_publish_aggregates_networks_and_retries_deletion_after_restart() {
        use easytier_core::management::remote_client::{ListNetworkProps, Storage as _};
        let (service, user_id, _) = service().await;
        let device_id = Uuid::new_v4();
        register_device(&service, user_id, device_id).await;
        let mut network_ids = Vec::new();
        for name in ["first", "second"] {
            let mut settings = standalone_settings();
            settings.network_name = Some(name.into());
            let network = service
                .create_network(user_id, settings, None)
                .await
                .unwrap();
            let network_id = Uuid::parse_str(&network.network_id).unwrap();
            network_ids.push(network_id);
            service
                .add_members(
                    user_id,
                    network_id,
                    AddMembersReq {
                        device_ids: vec![device_id.to_string()],
                        temporary: false,
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();
        }
        assert_eq!(
            service
                .db
                .list_network_configs((user_id, device_id), ListNetworkProps::All)
                .await
                .unwrap()
                .len(),
            2
        );
        let revision = service
            .db
            .get_managed_config_revision((user_id, device_id))
            .await
            .unwrap();
        service.reconcile_all().await.unwrap();
        assert_eq!(
            service
                .db
                .get_managed_config_revision((user_id, device_id))
                .await
                .unwrap(),
            revision
        );

        // Ownership and its generated rows must disappear atomically.
        sqlx::query("CREATE TRIGGER fail_config_delete BEFORE DELETE ON user_running_network_configs BEGIN SELECT RAISE(ABORT, 'forced publish failure'); END")
            .execute(&service.db.inner()).await.unwrap();
        assert!(
            service
                .delete_network(user_id, network_ids[0])
                .await
                .is_err()
        );
        assert!(
            service
                .db
                .load_central_network_intent(user_id, network_ids[0])
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            service
                .db
                .list_network_configs((user_id, device_id), ListNetworkProps::All)
                .await
                .unwrap()
                .len(),
            2
        );
        sqlx::query("DROP TRIGGER fail_config_delete")
            .execute(&service.db.inner())
            .await
            .unwrap();

        let restarted =
            CentralNetworkService::new(service.db.clone(), service.client_manager.clone());
        restarted
            .delete_network(user_id, network_ids[0])
            .await
            .unwrap();
        restarted.reconcile_all().await.unwrap();
        let configs = service
            .db
            .list_network_configs((user_id, device_id), ListNetworkProps::All)
            .await
            .unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].network_instance_id, network_ids[1].to_string());

        // Crash after the last intent disappears: generated rows are gone in
        // the same transaction, and the registered offline device is republished.
        service
            .db
            .delete_central_network_intent(user_id, network_ids[1])
            .await
            .unwrap();
        restarted.reconcile_all().await.unwrap();
        assert!(
            service
                .db
                .list_network_configs((user_id, device_id), ListNetworkProps::All)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            service
                .db
                .get_managed_config_revision((user_id, device_id))
                .await
                .unwrap()
                .unwrap()
                .starts_with("central:")
        );
    }

    #[tokio::test]
    async fn removing_member_revokes_published_credentials_and_clears_its_configs() {
        use easytier_core::management::remote_client::{
            ListNetworkProps, PersistentConfig as _, Storage as _,
        };
        let (service, user_id, _) = service().await;
        let permanent = Uuid::new_v4();
        let temporary = Uuid::new_v4();
        for device_id in [permanent, temporary] {
            register_device(&service, user_id, device_id).await;
        }
        let mut settings = standalone_settings();
        settings.secure_mode = true;
        let network = service
            .create_network(user_id, settings, None)
            .await
            .unwrap();
        let network_id = Uuid::parse_str(&network.network_id).unwrap();
        for (device_id, is_temporary) in [(permanent, false), (temporary, true)] {
            service
                .add_members(
                    user_id,
                    network_id,
                    AddMembersReq {
                        device_ids: vec![device_id.to_string()],
                        temporary: is_temporary,
                        ttl_seconds: None,
                    },
                )
                .await
                .unwrap();
        }
        let before = service
            .db
            .get_network_config((user_id, permanent), &network_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            before
                .get_network_config()
                .unwrap()
                .managed_credentials
                .len(),
            1
        );
        service
            .remove_member(user_id, network_id, temporary)
            .await
            .unwrap();
        let after = service
            .db
            .get_network_config((user_id, permanent), &network_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(
            after
                .get_network_config()
                .unwrap()
                .managed_credentials
                .is_empty()
        );
        assert!(
            service
                .db
                .list_network_configs((user_id, temporary), ListNetworkProps::All)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
