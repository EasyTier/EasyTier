use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{
            CredentialManageRpc, GenerateCredentialRequest, GenerateCredentialResponse,
            ListCredentialsRequest, ListCredentialsResponse, RevokeCredentialRequest,
            RevokeCredentialResponse,
        },
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct CredentialManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl CredentialManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl CredentialManageRpc for CredentialManageRpcService {
    type Controller = BaseController;

    async fn generate_credential(
        &self,
        ctrl: Self::Controller,
        req: GenerateCredentialRequest,
    ) -> crate::proto::rpc_types::error::Result<GenerateCredentialResponse> {
        super::get_instance_service(&self.instance_manager, &None)?
            .get_credential_manage_service()
            .generate_credential(ctrl, req)
            .await
    }

    async fn revoke_credential(
        &self,
        ctrl: Self::Controller,
        req: RevokeCredentialRequest,
    ) -> crate::proto::rpc_types::error::Result<RevokeCredentialResponse> {
        super::get_instance_service(&self.instance_manager, &None)?
            .get_credential_manage_service()
            .revoke_credential(ctrl, req)
            .await
    }

    async fn list_credentials(
        &self,
        ctrl: Self::Controller,
        req: ListCredentialsRequest,
    ) -> crate::proto::rpc_types::error::Result<ListCredentialsResponse> {
        super::get_instance_service(&self.instance_manager, &None)?
            .get_credential_manage_service()
            .list_credentials(ctrl, req)
            .await
    }
}
