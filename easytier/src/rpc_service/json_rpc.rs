use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::{
            config::ConfigRpc,
            instance::{
                AclManageRpc, ConnectorManageRpc, CredentialManageRpc, MappedListenerManageRpc,
                PeerManageRpc, PortForwardManageRpc, StatsRpc, TcpProxyRpc, VpnPortalRpc,
            },
            logger::LoggerRpc,
        },
        peer_rpc::PeerCenterRpc,
        rpc_types::{
            controller::BaseController,
            error::{Error, Result},
        },
    },
    rpc_service::{
        acl_manage::AclManageRpcService, config::ConfigRpcService,
        connector_manage::ConnectorManageRpcService, credential_manage::CredentialManageRpcService,
        logger::LoggerRpcService, mapped_listener_manage::MappedListenerManageRpcService,
        peer_center::PeerCenterManageRpcService, peer_manage::PeerManageRpcService,
        port_forward_manage::PortForwardManageRpcService, proxy::TcpProxyRpcService,
        stats::StatsRpcService, vpn_portal::VpnPortalRpcService,
    },
};

const INSTANCE_MANAGEMENT_SERVICE: &str = "api.manage.WebClientService";

fn service_not_exposed(service_name: &str) -> Error {
    anyhow::anyhow!(
        "service {} is not exposed through FFI/JNI generic RPC",
        service_name
    )
    .into()
}

fn tcp_proxy_domain(domain_name: Option<&str>) -> Result<&'static str> {
    match domain_name {
        None | Some("") => Ok("tcp"),
        Some("tcp") => Ok("tcp"),
        Some("kcp_src") => Ok("kcp_src"),
        Some("kcp_dst") => Ok("kcp_dst"),
        Some("quic_src") => Ok("quic_src"),
        Some("quic_dst") => Ok("quic_dst"),
        Some(domain) => {
            Err(anyhow::anyhow!("invalid TcpProxyRpcService domain_name: {}", domain).into())
        }
    }
}

pub async fn call_json_rpc(
    instance_manager: &Arc<NetworkInstanceManager>,
    service_name: &str,
    method_name: &str,
    domain_name: Option<&str>,
    payload: serde_json::Value,
) -> Result<serde_json::Value> {
    let ctrl = BaseController::default();

    match service_name {
        INSTANCE_MANAGEMENT_SERVICE => Err(service_not_exposed(service_name)),
        "api.instance.PeerManageRpcService" => {
            PeerManageRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.PeerCenterManageRpcService" => {
            PeerCenterManageRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.ConnectorManageRpcService" => {
            ConnectorManageRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.MappedListenerManageRpcService" => {
            MappedListenerManageRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.VpnPortalRpcService" => {
            VpnPortalRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.TcpProxyRpcService" => {
            TcpProxyRpcService::new(instance_manager.clone(), tcp_proxy_domain(domain_name)?)
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.AclManageRpcService" => {
            AclManageRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.PortForwardManageRpcService" => {
            PortForwardManageRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.StatsRpcService" => {
            StatsRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.instance.CredentialManageRpcService" => {
            CredentialManageRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.logger.LoggerRpcService" => {
            LoggerRpcService
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        "api.config.ConfigRpcService" => {
            ConfigRpcService::new(instance_manager.clone())
                .json_call_method(ctrl, method_name, payload)
                .await
        }
        _ => Err(Error::InvalidServiceKey(
            service_name.to_string(),
            service_name.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> Arc<NetworkInstanceManager> {
        Arc::new(NetworkInstanceManager::new())
    }

    #[tokio::test]
    async fn logger_json_rpc_succeeds() {
        let response = call_json_rpc(
            &manager(),
            "api.logger.LoggerRpcService",
            "get_logger_config",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();

        assert!(response.get("level").is_some());
    }

    #[tokio::test]
    async fn json_rpc_rejects_unknown_service() {
        let err = call_json_rpc(
            &manager(),
            "api.unknown.Service",
            "get_logger_config",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, Error::InvalidServiceKey(_, _)));
    }

    #[tokio::test]
    async fn json_rpc_rejects_instance_management_service() {
        let err = call_json_rpc(
            &manager(),
            INSTANCE_MANAGEMENT_SERVICE,
            "list_network_instance",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("not exposed"));
    }

    #[tokio::test]
    async fn json_rpc_rejects_unknown_method() {
        let err = call_json_rpc(
            &manager(),
            "api.logger.LoggerRpcService",
            "missing_method",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, Error::InvalidMethodIndex(0, _)));
    }

    #[tokio::test]
    async fn json_rpc_rejects_invalid_payload() {
        let err = call_json_rpc(
            &manager(),
            "api.logger.LoggerRpcService",
            "get_logger_config",
            None,
            serde_json::json!([]),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, Error::MalformatRpcPacket(_)));
    }

    #[tokio::test]
    async fn json_rpc_rejects_invalid_tcp_proxy_domain() {
        let err = call_json_rpc(
            &manager(),
            "api.instance.TcpProxyRpcService",
            "list_tcp_proxy_entry",
            Some("bad"),
            serde_json::json!({}),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid TcpProxyRpcService domain_name")
        );
    }
}
