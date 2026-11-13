use std::collections::{BTreeMap, HashMap, HashSet};

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use sqlx::Sqlite;
use uuid::Uuid;

use crate::central_network::{
    compiler::{CompileError, compile},
    model::{
        CentralNetworkIntent, CredentialGrant, NetworkCredentialIntent, NetworkMemberIntent,
        NetworkMode,
    },
};

use super::{Db, UserIdInDb, sqlx_db_error};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CentralIntentError {
    #[error(transparent)]
    Compile(#[from] CompileError),
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
    #[error("invalid device id in central network intent: {0}")]
    InvalidDeviceId(String),
    #[error("invalid persisted central network intent: {0}")]
    InvalidStoredData(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CentralOwnedRuntimeConfig {
    pub instance_id: Uuid,
    pub network_name: String,
}

struct PreparedMember {
    id: String,
    device_id: Uuid,
    hostname: Option<String>,
    virtual_ipv4: Option<String>,
    allocated_ipv4: Option<String>,
    override_config: Option<String>,
    credential_id: Option<String>,
    acl_group_secret: Option<String>,
}

struct PreparedCredential {
    id: String,
    secret: String,
    expiry_unix: i64,
    acl_groups: String,
    allow_relay: bool,
    allowed_proxy_cidrs: String,
    reusable: bool,
}

struct PreparedIntent {
    intent: CentralNetworkIntent,
    networking_method: &'static str,
    public_server_url: Option<String>,
    peer_urls: String,
    acl_policy: Option<String>,
    members: Vec<PreparedMember>,
    credentials: Vec<PreparedCredential>,
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, CentralIntentError> {
    serde_json::to_string(value)
        .map_err(|error| CentralIntentError::Database(sea_orm::DbErr::Json(error.to_string())))
}

fn sqlx_context(context: &str, error: sqlx::Error) -> CentralIntentError {
    CentralIntentError::Database(sea_orm::DbErr::Custom(format!("{context}: {error}")))
}

fn prepare_intent(intent: CentralNetworkIntent) -> Result<PreparedIntent, CentralIntentError> {
    let compiled = compile(&intent)?;
    let (networking_method, public_server_url, raw_peer_urls) = match &intent.mode {
        NetworkMode::PublicServer { url } => ("PublicServer", Some(url.clone()), Vec::new()),
        NetworkMode::Manual { peer_urls } => ("Manual", None, peer_urls.clone()),
        NetworkMode::Standalone => ("Standalone", None, Vec::new()),
        NetworkMode::Gateway { peer_url } => ("Gateway", None, vec![peer_url.clone()]),
    };
    let compiled_by_member: HashMap<_, _> = compiled
        .members
        .iter()
        .map(|member| (member.member_id, member))
        .collect();
    let mut members = Vec::with_capacity(intent.members.len());
    for member in &intent.members {
        let device_id = Uuid::parse_str(&member.device_id)
            .map_err(|_| CentralIntentError::InvalidDeviceId(member.device_id.clone()))?;
        let compiled = compiled_by_member.get(&member.id).ok_or_else(|| {
            CentralIntentError::InvalidStoredData(format!("compiler omitted member {}", member.id))
        })?;
        members.push(PreparedMember {
            id: member.id.to_string(),
            device_id,
            hostname: member.hostname.clone(),
            virtual_ipv4: member.virtual_ipv4.clone(),
            allocated_ipv4: member
                .virtual_ipv4
                .is_none()
                .then(|| compiled.network_config.virtual_ipv4.clone())
                .flatten(),
            override_config: member.config_override.as_ref().map(json).transpose()?,
            credential_id: member.credential_id.clone(),
            acl_group_secret: member.acl_group_secret.clone(),
        });
    }
    members.sort_by_key(|member| member.device_id);

    let mut credentials = Vec::with_capacity(intent.credentials.len());
    for credential in &intent.credentials {
        credentials.push(PreparedCredential {
            id: credential.id.clone(),
            secret: credential.secret.clone(),
            expiry_unix: credential.expiry_unix,
            acl_groups: json(&credential.grant.acl_groups)?,
            allow_relay: credential.grant.allow_relay,
            allowed_proxy_cidrs: json(&credential.grant.allowed_proxy_cidrs)?,
            reusable: credential.grant.reusable,
        });
    }
    credentials.sort_by(|left, right| left.id.cmp(&right.id));

    Ok(PreparedIntent {
        peer_urls: json(&raw_peer_urls)?,
        acl_policy: intent.acl_policy.as_ref().map(json).transpose()?,
        intent,
        networking_method,
        public_server_url,
        members,
        credentials,
    })
}

pub(super) async fn remove_device_from_central_intents(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    device_id: Uuid,
) -> Result<(), CentralIntentError> {
    let network_ids = sqlx::query_scalar::<_, String>(
        r#"
        SELECT network_id
        FROM network_members
        WHERE user_id = ? AND device_id = ?
        ORDER BY network_id
        "#,
    )
    .bind(user_id)
    .bind(device_id.to_string())
    .fetch_all(&mut **transaction)
    .await
    .map_err(sqlx_db_error)?;
    for network_id in network_ids {
        let network_id = Uuid::parse_str(&network_id).map_err(|_| {
            CentralIntentError::InvalidStoredData(format!("invalid network id {network_id}"))
        })?;
        let mut intent = load_intent(transaction, user_id, network_id)
            .await?
            .ok_or_else(|| {
                CentralIntentError::InvalidStoredData(format!(
                    "network {network_id} disappeared while deleting device {device_id}"
                ))
            })?;
        if !intent.remove_device(device_id) {
            continue;
        }
        let prepared = prepare_intent(intent)?;
        persist_intent(transaction, &prepared).await?;
    }
    Ok(())
}

impl Db {
    pub(crate) async fn publish_central_device_configs(
        &self,
        user_id: UserIdInDb,
        device_id: Uuid,
        configs: Vec<crate::webhook::ManagedNetworkConfig>,
    ) -> Result<(String, bool), CentralIntentError> {
        let mut transaction = self
            .db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sqlx_db_error)?;
        let owned: HashSet<String> = sqlx::query_scalar(
            "SELECT network_id FROM network_members WHERE user_id = ? AND device_id = ?",
        )
        .bind(user_id)
        .bind(device_id.to_string())
        .fetch_all(&mut *transaction)
        .await
        .map_err(sqlx_db_error)?
        .into_iter()
        .collect();
        let stored: Vec<(String, String, bool)> = sqlx::query_as(
            "SELECT network_instance_id, network_config, disabled \
             FROM user_running_network_configs WHERE user_id = ? AND device_id = ? AND source = 'web'",
        )
        .bind(user_id).bind(device_id.to_string())
        .fetch_all(&mut *transaction).await.map_err(sqlx_db_error)?;
        let mut merged = BTreeMap::new();
        for (id, config, disabled) in stored {
            if !owned.contains(&id) {
                let config: serde_json::Value = serde_json::from_str(&config)
                    .map_err(|error| CentralIntentError::InvalidStoredData(error.to_string()))?;
                merged.insert(id, (config, disabled));
            }
        }
        for config in &configs {
            merged.insert(
                config.instance_id.clone(),
                (config.network_config.clone(), false),
            );
        }
        let revision = format!(
            "central:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(json(&merged)?.as_bytes()))
        );
        if super::read_managed_config_revision(&mut transaction, user_id, device_id)
            .await?
            .as_deref()
            == Some(&revision)
        {
            transaction.commit().await.map_err(sqlx_db_error)?;
            return Ok((revision, false));
        }
        // Keep direct rows, including their disabled state, unchanged. The
        // runtime Full reconcile reads the resulting combined Web snapshot.
        for instance_id in owned {
            if !merged.contains_key(&instance_id) {
                delete_member_config(
                    &mut transaction,
                    user_id,
                    &device_id.to_string(),
                    &instance_id,
                )
                .await?;
            }
        }
        for config in configs {
            let instance_id = Uuid::parse_str(&config.instance_id)
                .map_err(|error| CentralIntentError::InvalidStoredData(error.to_string()))?;
            if !super::upsert_network_config(
                &mut transaction,
                user_id,
                device_id,
                instance_id,
                &json(&config.network_config)?,
                easytier::common::config::ConfigSource::Web,
                true,
            )
            .await?
            {
                return Err(CentralIntentError::InvalidStoredData(format!(
                    "central instance {instance_id} conflicts with a user-owned configuration"
                )));
            }
        }
        super::write_managed_config_revision(&mut transaction, user_id, device_id, &revision)
            .await?;
        transaction.commit().await.map_err(sqlx_db_error)?;
        Ok((revision, true))
    }

    pub(crate) async fn central_owned_runtime_configs(
        &self,
        user_id: UserIdInDb,
        device_id: Uuid,
    ) -> Result<Vec<CentralOwnedRuntimeConfig>, sea_orm::DbErr> {
        let rows = sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT networks.id, networks.network_name
            FROM networks JOIN network_members
                ON networks.user_id = network_members.user_id
                AND networks.id = network_members.network_id
            WHERE network_members.user_id = ? AND network_members.device_id = ?
            ORDER BY networks.id
            "#,
        )
        .bind(user_id)
        .bind(device_id.to_string())
        .fetch_all(&self.db)
        .await
        .map_err(sqlx_db_error)?;
        rows.into_iter()
            .map(|(instance_id, network_name)| {
                Ok(CentralOwnedRuntimeConfig {
                    instance_id: Uuid::parse_str(&instance_id).map_err(|_| {
                        sea_orm::DbErr::Custom("invalid central instance id".into())
                    })?,
                    network_name,
                })
            })
            .collect()
    }

    pub(crate) async fn save_central_network_intent(
        &self,
        intent: CentralNetworkIntent,
    ) -> Result<(), CentralIntentError> {
        let prepared = prepare_intent(intent)?;
        let mut transaction = self
            .db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sqlx_db_error)?;
        let result = persist_intent(&mut transaction, &prepared).await;
        match result {
            Ok(result) => {
                transaction.commit().await.map_err(sqlx_db_error)?;
                Ok(result)
            }
            Err(error) => {
                transaction.rollback().await.map_err(sqlx_db_error)?;
                Err(error)
            }
        }
    }

    pub(crate) async fn load_central_network_intent(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
    ) -> Result<Option<CentralNetworkIntent>, CentralIntentError> {
        let mut transaction = self.db.begin().await.map_err(sqlx_db_error)?;
        let result = load_intent(&mut transaction, user_id, network_id).await;
        match result {
            Ok(intent) => {
                transaction.commit().await.map_err(sqlx_db_error)?;
                Ok(intent)
            }
            Err(error) => {
                transaction.rollback().await.map_err(sqlx_db_error)?;
                Err(error)
            }
        }
    }

    pub(crate) async fn delete_central_network_intent(
        &self,
        user_id: UserIdInDb,
        network_id: Uuid,
    ) -> Result<(), CentralIntentError> {
        let mut transaction = self
            .db
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sqlx_db_error)?;
        remove_obsolete_member_configs(&mut transaction, user_id, network_id, &[]).await?;
        sqlx::query("DELETE FROM networks WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(network_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_db_error)?;
        transaction.commit().await.map_err(sqlx_db_error)?;
        Ok(())
    }
}

async fn delete_member_config(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    device_id: &str,
    network_id: &str,
) -> Result<(), CentralIntentError> {
    sqlx::query("DELETE FROM user_running_network_configs WHERE user_id = ? AND device_id = ? AND network_instance_id = ? AND source = 'web'")
        .bind(user_id).bind(device_id).bind(network_id)
        .execute(&mut **transaction).await.map_err(sqlx_db_error)?;
    sqlx::query("DELETE FROM managed_config_revisions WHERE user_id = ? AND device_id = ?")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut **transaction)
        .await
        .map_err(sqlx_db_error)?;
    Ok(())
}

async fn remove_obsolete_member_configs(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    network_id: Uuid,
    members: &[PreparedMember],
) -> Result<(), CentralIntentError> {
    let retained: HashSet<_> = members
        .iter()
        .map(|member| member.device_id.to_string())
        .collect();
    let previous: Vec<String> = sqlx::query_scalar(
        "SELECT device_id FROM network_members WHERE user_id = ? AND network_id = ?",
    )
    .bind(user_id)
    .bind(network_id.to_string())
    .fetch_all(&mut **transaction)
    .await
    .map_err(sqlx_db_error)?;
    for device_id in previous {
        if !retained.contains(&device_id) {
            delete_member_config(transaction, user_id, &device_id, &network_id.to_string()).await?;
        }
    }
    Ok(())
}

async fn persist_intent(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    prepared: &PreparedIntent,
) -> Result<(), CentralIntentError> {
    let now = sqlx::types::chrono::Local::now().fixed_offset();
    sqlx::query(
        r#"
        INSERT INTO networks (
            user_id, id, display_name, network_name, network_secret,
            networking_method, public_server_url, peer_urls, virtual_cidr,
            secure_mode, acl_policy, create_time, update_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, id) DO UPDATE SET
            display_name = excluded.display_name,
            network_name = excluded.network_name,
            network_secret = excluded.network_secret,
            networking_method = excluded.networking_method,
            public_server_url = excluded.public_server_url,
            peer_urls = excluded.peer_urls,
            virtual_cidr = excluded.virtual_cidr,
            secure_mode = excluded.secure_mode,
            acl_policy = excluded.acl_policy,
            update_time = excluded.update_time
        "#,
    )
    .bind(prepared.intent.user_id)
    .bind(prepared.intent.id.to_string())
    .bind(&prepared.intent.display_name)
    .bind(&prepared.intent.network_name)
    .bind(&prepared.intent.network_secret)
    .bind(prepared.networking_method)
    .bind(&prepared.public_server_url)
    .bind(&prepared.peer_urls)
    .bind(&prepared.intent.virtual_cidr)
    .bind(prepared.intent.secure_mode)
    .bind(&prepared.acl_policy)
    .bind(now)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| sqlx_context("write central network", error))?;

    remove_obsolete_member_configs(
        transaction,
        prepared.intent.user_id,
        prepared.intent.id,
        &prepared.members,
    )
    .await?;
    sqlx::query("DELETE FROM network_members WHERE user_id = ? AND network_id = ?")
        .bind(prepared.intent.user_id)
        .bind(prepared.intent.id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(|error| sqlx_context("clear central network members", error))?;
    sqlx::query("DELETE FROM network_credentials WHERE user_id = ? AND network_id = ?")
        .bind(prepared.intent.user_id)
        .bind(prepared.intent.id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(|error| sqlx_context("clear central network credentials", error))?;

    for credential in &prepared.credentials {
        sqlx::query(
            r#"
            INSERT INTO network_credentials (
                user_id, network_id, credential_id, credential_secret,
                expiry_unix, acl_groups, allow_relay, allowed_proxy_cidrs,
                reusable, create_time, update_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(prepared.intent.user_id)
        .bind(prepared.intent.id.to_string())
        .bind(&credential.id)
        .bind(&credential.secret)
        .bind(credential.expiry_unix)
        .bind(&credential.acl_groups)
        .bind(credential.allow_relay)
        .bind(&credential.allowed_proxy_cidrs)
        .bind(credential.reusable)
        .bind(now)
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| sqlx_context("write central network credential", error))?;
    }
    for member in &prepared.members {
        sqlx::query(
            r#"
            INSERT INTO network_members (
                user_id, network_id, id, device_id, hostname_override,
                virtual_ipv4, allocated_ipv4, override_config, credential_id,
                acl_group_secret, create_time, update_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(prepared.intent.user_id)
        .bind(prepared.intent.id.to_string())
        .bind(&member.id)
        .bind(member.device_id.to_string())
        .bind(&member.hostname)
        .bind(&member.virtual_ipv4)
        .bind(&member.allocated_ipv4)
        .bind(&member.override_config)
        .bind(&member.credential_id)
        .bind(&member.acl_group_secret)
        .bind(now)
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| {
            sqlx_context(
                &format!(
                    "write central network member {} with credential {:?}",
                    member.id, member.credential_id
                ),
                error,
            )
        })?;
    }
    Ok(())
}

async fn load_intent(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    user_id: UserIdInDb,
    network_id: Uuid,
) -> Result<Option<CentralNetworkIntent>, CentralIntentError> {
    type NetworkRow = (
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        bool,
        Option<String>,
    );
    let row: Option<NetworkRow> = sqlx::query_as(
        r#"
        SELECT display_name, network_name, network_secret, networking_method,
            public_server_url, peer_urls, virtual_cidr, secure_mode, acl_policy
        FROM networks WHERE user_id = ? AND id = ?
        "#,
    )
    .bind(user_id)
    .bind(network_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(sqlx_db_error)?;
    let Some((
        display_name,
        network_name,
        network_secret,
        networking_method,
        public_server_url,
        peer_urls,
        virtual_cidr,
        secure_mode,
        acl_policy,
    )) = row
    else {
        return Ok(None);
    };
    let peer_urls: Vec<String> = serde_json::from_str(&peer_urls).map_err(|error| {
        CentralIntentError::InvalidStoredData(format!("invalid peer URLs: {error}"))
    })?;
    let mode = match networking_method.as_str() {
        "PublicServer" => NetworkMode::PublicServer {
            url: public_server_url.ok_or_else(|| {
                CentralIntentError::InvalidStoredData("missing public server URL".to_owned())
            })?,
        },
        "Manual" => NetworkMode::Manual { peer_urls },
        "Standalone" => NetworkMode::Standalone,
        "Gateway" => NetworkMode::Gateway {
            peer_url: peer_urls.into_iter().next().ok_or_else(|| {
                CentralIntentError::InvalidStoredData("missing Gateway peer URL".to_owned())
            })?,
        },
        other => {
            return Err(CentralIntentError::InvalidStoredData(format!(
                "unknown networking method {other}"
            )));
        }
    };
    let acl_policy = acl_policy
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| {
            CentralIntentError::InvalidStoredData(format!("invalid ACL policy: {error}"))
        })?;

    type CredentialRow = (String, String, i64, String, bool, String, bool);
    let credential_rows: Vec<CredentialRow> = sqlx::query_as(
        r#"
        SELECT credential_id, credential_secret, expiry_unix, acl_groups,
            allow_relay, allowed_proxy_cidrs, reusable
        FROM network_credentials
        WHERE user_id = ? AND network_id = ?
        ORDER BY credential_id
        "#,
    )
    .bind(user_id)
    .bind(network_id.to_string())
    .fetch_all(&mut **transaction)
    .await
    .map_err(sqlx_db_error)?;
    let credentials = credential_rows
        .into_iter()
        .map(
            |(id, secret, expiry_unix, acl_groups, allow_relay, allowed_proxy_cidrs, reusable)| {
                Ok(NetworkCredentialIntent {
                    id,
                    secret,
                    expiry_unix,
                    grant: CredentialGrant {
                        acl_groups: serde_json::from_str(&acl_groups).map_err(|error| {
                            CentralIntentError::InvalidStoredData(format!(
                                "invalid credential ACL groups: {error}"
                            ))
                        })?,
                        allow_relay,
                        allowed_proxy_cidrs: serde_json::from_str(&allowed_proxy_cidrs).map_err(
                            |error| {
                                CentralIntentError::InvalidStoredData(format!(
                                    "invalid credential proxy CIDRs: {error}"
                                ))
                            },
                        )?,
                        reusable,
                    },
                })
            },
        )
        .collect::<Result<Vec<_>, CentralIntentError>>()?;

    type MemberRow = (
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let member_rows: Vec<MemberRow> = sqlx::query_as(
        r#"
        SELECT allocated_ipv4, id, device_id, hostname_override, virtual_ipv4,
            override_config, credential_id, acl_group_secret
        FROM network_members
        WHERE user_id = ? AND network_id = ?
        ORDER BY id
        "#,
    )
    .bind(user_id)
    .bind(network_id.to_string())
    .fetch_all(&mut **transaction)
    .await
    .map_err(sqlx_db_error)?;
    let members = member_rows
        .into_iter()
        .map(
            |(
                allocated_ipv4,
                id,
                device_id,
                hostname,
                virtual_ipv4,
                override_config,
                credential_id,
                acl_group_secret,
            )| {
                Ok(NetworkMemberIntent {
                    id: Uuid::parse_str(&id).map_err(|_| {
                        CentralIntentError::InvalidStoredData(format!("invalid member id {id}"))
                    })?,
                    device_id,
                    hostname,
                    virtual_ipv4,
                    allocated_ipv4,
                    config_override: override_config
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()
                        .map_err(|error| {
                            CentralIntentError::InvalidStoredData(format!(
                                "invalid member override: {error}"
                            ))
                        })?,
                    credential_id,
                    acl_group_secret,
                })
            },
        )
        .collect::<Result<Vec<_>, CentralIntentError>>()?;

    Ok(Some(CentralNetworkIntent {
        id: network_id,
        user_id,
        display_name,
        network_name,
        network_secret,
        mode,
        virtual_cidr,
        secure_mode,
        members,
        credentials,
        acl_policy,
    }))
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use easytier_core::management::remote_client::{ListNetworkProps, Storage as _};
    use uuid::Uuid;

    use super::*;
    use crate::{
        central_network::model::{
            AclAction, AclDestination, AclPolicy, AclProtocol, AclProtocolTarget, AclRule,
            AclSource, CentralNetworkIntent, CredentialGrant, NetworkCredentialIntent,
            NetworkMemberIntent, NetworkMode,
        },
        db::{DeviceHeartbeatRecord, UserIdInDb},
    };

    fn member(id: u128, device_id: Uuid, credential_id: Option<&str>) -> NetworkMemberIntent {
        NetworkMemberIntent {
            id: Uuid::from_u128(id),
            device_id: device_id.to_string(),
            hostname: Some(format!("device-{id}")),
            virtual_ipv4: None,
            allocated_ipv4: None,
            config_override: None,
            credential_id: credential_id.map(str::to_owned),
            acl_group_secret: None,
        }
    }

    fn intent(user_id: UserIdInDb, network_id: Uuid, devices: [Uuid; 2]) -> CentralNetworkIntent {
        let temporary = member(2, devices[1], Some("temporary"));
        let mut permanent = member(1, devices[0], None);
        permanent.acl_group_secret = Some("permanent-group-secret".to_owned());
        CentralNetworkIntent {
            id: network_id,
            user_id,
            display_name: "Engineering".to_owned(),
            network_name: format!("engineering-{network_id}"),
            network_secret: "network-secret".to_owned(),
            mode: NetworkMode::Standalone,
            virtual_cidr: Some("10.42.0.0/29".to_owned()),
            secure_mode: true,
            members: vec![temporary.clone(), permanent],
            credentials: vec![NetworkCredentialIntent {
                id: "temporary".to_owned(),
                secret: BASE64_STANDARD.encode([1u8; 32]),
                expiry_unix: 2_000_000_000,
                grant: CredentialGrant {
                    acl_groups: vec![crate::central_network::model::member_group_name(
                        temporary.id,
                    )],
                    allow_relay: true,
                    allowed_proxy_cidrs: vec!["10.90.0.0/24".to_owned()],
                    reusable: false,
                },
            }],
            acl_policy: None,
        }
    }

    async fn register_devices(db: &Db, user_id: UserIdInDb, devices: &[Uuid]) {
        for (index, device_id) in devices.iter().enumerate() {
            db.upsert_device_heartbeat(DeviceHeartbeatRecord {
                user_id,
                machine_id: *device_id,
                hostname: format!("device-{index}"),
                easytier_version: "test".to_owned(),
                device_os: "{}".to_owned(),
                client_url: format!("tcp://127.0.0.1:{}", 11010 + index),
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn save_loads_business_intent_without_publishing_configs() {
        let db = Db::memory_db().await;
        let user_id = db
            .auto_create_user("central-intent-roundtrip")
            .await
            .unwrap()
            .id;
        let network_id = Uuid::new_v4();
        let devices = [Uuid::new_v4(), Uuid::new_v4()];
        register_devices(&db, user_id, &devices).await;

        db.save_central_network_intent(intent(user_id, network_id, devices))
            .await
            .unwrap();
        let loaded = db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.id, network_id);
        assert_eq!(loaded.user_id, user_id);
        assert_eq!(loaded.credentials.len(), 1);
        assert_eq!(loaded.credentials[0].grant.acl_groups.len(), 1);
        assert!(loaded.credentials[0].grant.allow_relay);
        assert_eq!(
            loaded.credentials[0].grant.allowed_proxy_cidrs,
            vec!["10.90.0.0/24"]
        );
        assert!(!loaded.credentials[0].grant.reusable);
        assert!(
            loaded
                .members
                .iter()
                .all(|member| member.virtual_ipv4.is_none() && member.allocated_ipv4.is_some())
        );

        for device_id in devices {
            assert!(
                db.list_network_configs((user_id, device_id), ListNetworkProps::All)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn load_intent_does_not_require_the_writer_lock() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("central-reader").await.unwrap().id;
        let network_id = Uuid::new_v4();
        let devices = [Uuid::new_v4(), Uuid::new_v4()];
        register_devices(&db, user_id, &devices).await;
        db.save_central_network_intent(intent(user_id, network_id, devices))
            .await
            .unwrap();

        let writer = db.db.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let loaded = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            db.load_central_network_intent(user_id, network_id),
        )
        .await
        .expect("reading intent should not wait for the writer")
        .unwrap()
        .unwrap();
        assert_eq!(loaded.id, network_id);
        assert_eq!(loaded.members.len(), 2);
        assert_eq!(loaded.credentials.len(), 1);
        writer.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn invalid_member_config_keeps_persisted_intent_unchanged() {
        let db = Db::memory_db().await;
        let user_id = db
            .auto_create_user("central-invalid-config")
            .await
            .unwrap()
            .id;
        let network_id = Uuid::new_v4();
        let devices = [Uuid::new_v4(), Uuid::new_v4()];
        register_devices(&db, user_id, &devices).await;
        db.save_central_network_intent(intent(user_id, network_id, devices))
            .await
            .unwrap();
        let original = db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        let mut candidate = original.clone();
        candidate.display_name = "must not be saved".to_owned();
        candidate.members[0].config_override = Some(easytier::common::config::NetworkConfig {
            proxy_cidrs: vec!["2001:db8:240::/64".to_owned()],
            ..Default::default()
        });
        assert!(matches!(
            db.save_central_network_intent(candidate).await,
            Err(CentralIntentError::Compile(
                CompileError::InvalidMemberConfig { .. }
            ))
        ));
        let after = db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after, original);
    }

    #[tokio::test]
    async fn persisted_effective_ips_do_not_shift_when_an_earlier_device_is_added() {
        let db = Db::memory_db().await;
        let user_id = db
            .auto_create_user("central-intent-stable-ip")
            .await
            .unwrap()
            .id;
        let network_id = Uuid::new_v4();
        let devices = [Uuid::from_u128(100), Uuid::from_u128(200)];
        register_devices(&db, user_id, &devices).await;
        db.save_central_network_intent(intent(user_id, network_id, devices))
            .await
            .unwrap();
        let mut replacement = db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        let previous_ips: HashMap<_, _> = replacement
            .members
            .iter()
            .map(|member| (member.device_id.clone(), member.allocated_ipv4.clone()))
            .collect();
        let earlier_device = Uuid::from_u128(1);
        register_devices(&db, user_id, &[earlier_device]).await;
        replacement.members.push(member(3, earlier_device, None));

        db.save_central_network_intent(replacement).await.unwrap();
        let loaded = db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        for member in loaded
            .members
            .iter()
            .filter(|member| member.device_id != earlier_device.to_string())
        {
            assert_eq!(member.allocated_ipv4, previous_ips[&member.device_id]);
        }
        assert_eq!(
            loaded
                .members
                .iter()
                .find(|member| member.device_id == earlier_device.to_string())
                .unwrap()
                .allocated_ipv4
                .as_deref(),
            Some("10.42.0.3")
        );
    }

    #[tokio::test]
    async fn deleting_registered_member_safely_shrinks_acl_selectors() {
        let db = Db::memory_db().await;
        let user_id = db
            .auto_create_user("central-device-delete-acl")
            .await
            .unwrap()
            .id;
        let network_id = Uuid::new_v4();
        let devices = [Uuid::new_v4(), Uuid::new_v4()];
        register_devices(&db, user_id, &devices).await;
        let mut candidate = intent(user_id, network_id, devices);
        let retained_member_id = candidate
            .members
            .iter()
            .find(|member| member.device_id == devices[0].to_string())
            .unwrap()
            .id;
        let deleted_member_id = candidate
            .members
            .iter()
            .find(|member| member.device_id == devices[1].to_string())
            .unwrap()
            .id;
        let protocols = vec![AclProtocolTarget {
            protocol: AclProtocol::Any,
            ports: Vec::new(),
            stateful: false,
        }];
        candidate.acl_policy = Some(AclPolicy {
            default_action: AclAction::Deny,
            rules: vec![
                AclRule {
                    id: "deleted-only".to_owned(),
                    name: "deleted only".to_owned(),
                    enabled: true,
                    action: AclAction::Allow,
                    sources: vec![AclSource::Member {
                        member_id: deleted_member_id,
                    }],
                    destinations: vec![AclDestination::Member {
                        member_id: retained_member_id,
                    }],
                    protocols: protocols.clone(),
                },
                AclRule {
                    id: "mixed".to_owned(),
                    name: "mixed selectors".to_owned(),
                    enabled: true,
                    action: AclAction::Deny,
                    sources: vec![
                        AclSource::Member {
                            member_id: retained_member_id,
                        },
                        AclSource::Member {
                            member_id: deleted_member_id,
                        },
                    ],
                    destinations: vec![
                        AclDestination::Member {
                            member_id: retained_member_id,
                        },
                        AclDestination::Subnet {
                            member_id: deleted_member_id,
                            cidrs: vec!["10.42.0.0/29".to_owned()],
                        },
                    ],
                    protocols,
                },
            ],
        });
        db.save_central_network_intent(candidate).await.unwrap();

        db.delete_device_with_optional_block((user_id, devices[1]), false)
            .await
            .unwrap();

        let loaded = db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        let rules = &loaded.acl_policy.unwrap().rules;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "mixed");
        assert_eq!(
            rules[0].sources,
            vec![AclSource::Member {
                member_id: retained_member_id,
            }]
        );
        assert_eq!(
            rules[0].destinations,
            vec![AclDestination::Member {
                member_id: retained_member_id,
            }]
        );
    }

    #[tokio::test]
    async fn failed_device_delete_rolls_back_members_credentials_and_block() {
        let db = Db::memory_db().await;
        let user_id = db.auto_create_user("delete-rollback").await.unwrap().id;
        let network_id = Uuid::new_v4();
        let devices = [Uuid::new_v4(), Uuid::new_v4()];
        register_devices(&db, user_id, &devices).await;
        db.save_central_network_intent(intent(user_id, network_id, devices))
            .await
            .unwrap();
        sqlx::query("CREATE TRIGGER fail_device_delete BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT, 'forced device deletion failure'); END")
            .execute(&db.inner()).await.unwrap();
        assert!(
            db.delete_device_with_optional_block((user_id, devices[1]), true)
                .await
                .is_err()
        );
        let retained = db
            .load_central_network_intent(user_id, network_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.members.len(), 2);
        assert_eq!(retained.credentials.len(), 1);
        let blocked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM blocked_devices WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(&db.inner())
                .await
                .unwrap();
        assert_eq!(blocked, 0);
    }

    #[tokio::test]
    async fn deleting_network_is_tenant_scoped_and_leaves_other_business_intent() {
        let db = Db::memory_db().await;
        let user_a = db.auto_create_user("delete-tenant-a").await.unwrap().id;
        let user_b = db.auto_create_user("delete-tenant-b").await.unwrap().id;
        let network_id = Uuid::new_v4();
        let devices = [Uuid::new_v4(), Uuid::new_v4()];
        for user_id in [user_a, user_b] {
            register_devices(&db, user_id, &devices).await;
            db.save_central_network_intent(intent(user_id, network_id, devices))
                .await
                .unwrap();
        }
        db.delete_central_network_intent(user_a, network_id)
            .await
            .unwrap();
        assert!(
            db.load_central_network_intent(user_a, network_id)
                .await
                .unwrap()
                .is_none()
        );
        let retained = db
            .load_central_network_intent(user_b, network_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.members.len(), 2);
        assert_eq!(retained.credentials.len(), 1);
        assert!(
            db.central_owned_runtime_configs(user_a, devices[0])
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.central_owned_runtime_configs(user_b, devices[0])
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
