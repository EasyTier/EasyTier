use async_trait::async_trait;
use uuid::Uuid;

use crate::proto::{api::manage::*, rpc_types::controller::BaseController};

#[async_trait]
pub trait RemoteClientManager<T, C, E>
where
    T: Clone + Send + 'static,
    C: PersistentConfig<E> + Send + 'static,
    E: Send + 'static,
{
    fn get_rpc_client(
        &self,
        identify: T,
    ) -> Option<Box<dyn WebClientService<Controller = BaseController> + Send>>;

    fn get_storage(&self) -> &impl Storage<T, C, E>;

    async fn handle_validate_config(
        &self,
        identify: T,
        config: NetworkConfig,
    ) -> Result<ValidateConfigResponse, RemoteClientError<E>> {
        let client = self
            .get_rpc_client(identify)
            .ok_or(RemoteClientError::ClientNotFound)?;
        client
            .validate_config(
                BaseController::default(),
                ValidateConfigRequest {
                    config: Some(config),
                },
            )
            .await
            .map_err(RemoteClientError::RpcError)
    }

    async fn handle_run_network_instance(
        &self,
        identify: T,
        config: NetworkConfig,
        save: bool,
    ) -> Result<(), RemoteClientError<E>> {
        let client = self
            .get_rpc_client(identify.clone())
            .ok_or(RemoteClientError::ClientNotFound)?;
        let resp = client
            .run_network_instance(
                BaseController::default(),
                RunNetworkInstanceRequest {
                    inst_id: None,
                    config: Some(config.clone()),
                    overwrite: true,
                },
            )
            .await?;

        if save {
            self.get_storage()
                .insert_or_update_user_network_config(
                    identify,
                    resp.inst_id.unwrap_or_default().into(),
                    config,
                )
                .await
                .map_err(RemoteClientError::PersistentError)?;
        }

        Ok(())
    }

    async fn handle_collect_network_info(
        &self,
        identify: T,
        inst_ids: Option<Vec<uuid::Uuid>>,
    ) -> Result<CollectNetworkInfoResponse, RemoteClientError<E>> {
        let client = self
            .get_rpc_client(identify)
            .ok_or(RemoteClientError::ClientNotFound)?;
        let resp = client
            .collect_network_info(
                BaseController::default(),
                CollectNetworkInfoRequest {
                    inst_ids: inst_ids
                        .unwrap_or_default()
                        .into_iter()
                        .map(|id| id.into())
                        .collect(),
                },
            )
            .await?;

        Ok(resp)
    }

    async fn handle_list_network_instance_ids(
        &self,
        identify: T,
    ) -> Result<ListNetworkInstanceIdsJsonResp, RemoteClientError<E>> {
        let client = self
            .get_rpc_client(identify.clone())
            .ok_or(RemoteClientError::ClientNotFound)?;
        let ret = client
            .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
            .await?;

        let running_inst_ids = ret.inst_ids.clone().into_iter().collect();

        // collect networks that are disabled
        let disabled_inst_ids = self
            .get_storage()
            .list_network_configs(identify, ListNetworkProps::All)
            .await
            .map_err(RemoteClientError::PersistentError)?
            .iter()
            .map(|x| Into::<crate::proto::common::Uuid>::into(x.get_network_inst_id().to_string()))
            .filter(|id| !ret.inst_ids.contains(id))
            .collect::<Vec<_>>();

        Ok(ListNetworkInstanceIdsJsonResp {
            running_inst_ids,
            disabled_inst_ids,
        })
    }

    async fn handle_remove_network_instances(
        &self,
        identify: T,
        inst_ids: Vec<uuid::Uuid>,
    ) -> Result<(), RemoteClientError<E>> {
        if inst_ids.is_empty() {
            return Ok(());
        }
        let client = self
            .get_rpc_client(identify.clone())
            .ok_or(RemoteClientError::ClientNotFound)?;
        self.get_storage()
            .delete_network_configs(identify, &inst_ids)
            .await
            .map_err(RemoteClientError::PersistentError)?;

        client
            .delete_network_instance(
                BaseController::default(),
                DeleteNetworkInstanceRequest {
                    inst_ids: inst_ids.into_iter().map(|id| id.into()).collect(),
                },
            )
            .await?;

        Ok(())
    }

    async fn handle_update_network_state(
        &self,
        identify: T,
        inst_id: uuid::Uuid,
        disabled: bool,
    ) -> Result<(), RemoteClientError<E>> {
        let client = self
            .get_rpc_client(identify.clone())
            .ok_or(RemoteClientError::ClientNotFound)?;

        let cfg = self
            .handle_get_network_config(identify.clone(), inst_id)
            .await?;

        if disabled {
            self.get_storage()
                .insert_or_update_user_network_config(identify.clone(), inst_id, cfg.clone())
                .await
                .map_err(RemoteClientError::PersistentError)?;

            client
                .delete_network_instance(
                    BaseController::default(),
                    DeleteNetworkInstanceRequest {
                        inst_ids: vec![inst_id.into()],
                    },
                )
                .await?;
        } else {
            client
                .run_network_instance(
                    BaseController::default(),
                    RunNetworkInstanceRequest {
                        inst_id: Some(inst_id.into()),
                        config: Some(cfg),
                        overwrite: true,
                    },
                )
                .await?;
        }

        self.get_storage()
            .update_network_config_state(identify, inst_id, disabled)
            .await
            .map_err(RemoteClientError::PersistentError)?;

        Ok(())
    }

    async fn handle_get_network_metas(
        &self,
        identify: T,
        inst_ids: Vec<uuid::Uuid>,
    ) -> Result<GetNetworkMetasResponse, RemoteClientError<E>> {
        let mut metas = std::collections::HashMap::new();

        if let Some(client) = self.get_rpc_client(identify.clone()) {
            if let Ok(resp) = client
                .list_network_instance_meta(
                    BaseController::default(),
                    ListNetworkInstanceMetaRequest {
                        inst_ids: inst_ids.iter().cloned().map(|id| id.into()).collect(),
                    },
                )
                .await
            {
                for meta in resp.metas {
                    if let Some(inst_id) = meta.inst_id.as_ref() {
                        let inst_id: uuid::Uuid = (*inst_id).into();
                        metas.insert(inst_id, meta);
                    }
                }
            }
        }

        for instance_id in inst_ids {
            if metas.contains_key(&instance_id) {
                continue;
            }
            let config = self
                .handle_get_network_config(identify.clone(), instance_id)
                .await?;
            metas.insert(
                instance_id,
                NetworkMeta {
                    inst_id: Some(instance_id.into()),
                    network_name: config.network_name.unwrap_or_default(),
                    config_permission: 0,
                },
            );
        }

        Ok(GetNetworkMetasResponse { metas })
    }

    async fn handle_save_network_config(
        &self,
        identify: T,
        inst_id: uuid::Uuid,
        config: NetworkConfig,
    ) -> Result<(), RemoteClientError<E>> {
        self.get_storage()
            .insert_or_update_user_network_config(identify.clone(), inst_id, config)
            .await
            .map_err(RemoteClientError::PersistentError)?;
        self.get_storage()
            .update_network_config_state(identify, inst_id, true)
            .await
            .map_err(RemoteClientError::PersistentError)?;
        Ok(())
    }

    async fn handle_get_network_config(
        &self,
        identify: T,
        inst_id: uuid::Uuid,
    ) -> Result<NetworkConfig, RemoteClientError<E>> {
        if let Some(client) = self.get_rpc_client(identify.clone()) {
            if let Ok(resp) = client
                .get_network_instance_config(
                    BaseController::default(),
                    GetNetworkInstanceConfigRequest {
                        inst_id: Some(inst_id.into()),
                    },
                )
                .await
            {
                if let Some(config) = resp.config {
                    return Ok(config);
                }
            }
        }

        let inst_id = inst_id.to_string();

        let db_row = self
            .get_storage()
            .get_network_config(identify, &inst_id)
            .await
            .map_err(RemoteClientError::PersistentError)?
            .ok_or(RemoteClientError::NotFound(format!(
                "No such network instance: {}",
                inst_id
            )))?;

        Ok(db_row
            .get_network_config()
            .map_err(RemoteClientError::PersistentError)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteClientError<E> {
    #[error("Client not found")]
    ClientNotFound,
    #[error("Not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    RpcError(#[from] crate::proto::rpc_types::error::Error),
    #[error(transparent)]
    PersistentError(E),
    #[error("Other error: {0}")]
    Other(String),
}

pub enum ListNetworkProps {
    All,
    EnabledOnly,
    DisabledOnly,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ListNetworkInstanceIdsJsonResp {
    running_inst_ids: Vec<crate::proto::common::Uuid>,
    disabled_inst_ids: Vec<crate::proto::common::Uuid>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct GetNetworkMetasResponse {
    metas: std::collections::HashMap<uuid::Uuid, NetworkMeta>,
}

pub trait PersistentConfig<E> {
    fn get_network_inst_id(&self) -> &str;
    fn get_network_config(&self) -> Result<NetworkConfig, E>;
}

#[async_trait]
pub trait Storage<T, C, E>: Send + Sync
where
    C: PersistentConfig<E>,
{
    async fn insert_or_update_user_network_config(
        &self,
        identify: T,
        network_inst_id: Uuid,
        network_config: NetworkConfig,
    ) -> Result<(), E>;

    async fn delete_network_configs(&self, identify: T, network_inst_ids: &[Uuid])
        -> Result<(), E>;

    async fn update_network_config_state(
        &self,
        identify: T,
        network_inst_id: Uuid,
        disabled: bool,
    ) -> Result<(), E>;

    async fn list_network_configs(&self, identify: T, props: ListNetworkProps)
        -> Result<Vec<C>, E>;

    async fn get_network_config(&self, identify: T, network_inst_id: &str) -> Result<Option<C>, E>;
}
