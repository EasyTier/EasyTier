use std::sync::Arc;

use easytier_proto::{
    api::instance::{TcpProxyRpc, TcpProxyRpcServer},
    rpc_types::controller::BaseController,
};

use crate::{
    gateway::proxy::wrapped_transport::{WrappedTransportKind, WrappedTransportRole},
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    management::instance_rpc::packet_proxy::TcpProxyManagementRpc,
    rpc::service_registry::ServiceRegistry,
};

use super::JsonCall;

pub(in crate::management) fn register<F, H>(
    manager: Arc<InstanceManager<F>>,
    registry: &ServiceRegistry,
) where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    registry.register(
        TcpProxyRpcServer::new(TcpProxyManagementRpc::<F, H>::tcp(manager.clone())),
        "tcp",
    );
    for (domain, transport, role) in [
        (
            "kcp_src",
            WrappedTransportKind::Kcp,
            WrappedTransportRole::Source,
        ),
        (
            "kcp_dst",
            WrappedTransportKind::Kcp,
            WrappedTransportRole::Destination,
        ),
        (
            "quic_src",
            WrappedTransportKind::Quic,
            WrappedTransportRole::Source,
        ),
        (
            "quic_dst",
            WrappedTransportKind::Quic,
            WrappedTransportRole::Destination,
        ),
    ] {
        registry.register(
            TcpProxyRpcServer::new(TcpProxyManagementRpc::<F, H>::wrapped(
                manager.clone(),
                transport,
                role,
            )),
            domain,
        );
    }
}

pub(in crate::management) async fn call_json<F, H>(
    manager: &Arc<InstanceManager<F>>,
    service_name: &str,
    method_name: &str,
    domain_name: Option<&str>,
    payload: serde_json::Value,
) -> JsonCall
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    if service_name != "api.instance.TcpProxyRpcService" {
        return Err(payload);
    }

    let rpc = match tcp_proxy_json_service(manager.clone(), domain_name) {
        Ok(rpc) => rpc,
        Err(error) => return Ok(Err(error)),
    };
    Ok(rpc
        .json_call_method(BaseController::default(), method_name, payload)
        .await)
}

fn tcp_proxy_json_service<F, H>(
    manager: Arc<InstanceManager<F>>,
    domain_name: Option<&str>,
) -> crate::proto::rpc_types::error::Result<TcpProxyManagementRpc<F, H>>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    let rpc = match domain_name {
        None | Some("") | Some("tcp") => TcpProxyManagementRpc::tcp(manager),
        Some("kcp_src") => TcpProxyManagementRpc::wrapped(
            manager,
            WrappedTransportKind::Kcp,
            WrappedTransportRole::Source,
        ),
        Some("kcp_dst") => TcpProxyManagementRpc::wrapped(
            manager,
            WrappedTransportKind::Kcp,
            WrappedTransportRole::Destination,
        ),
        Some("quic_src") => TcpProxyManagementRpc::wrapped(
            manager,
            WrappedTransportKind::Quic,
            WrappedTransportRole::Source,
        ),
        Some("quic_dst") => TcpProxyManagementRpc::wrapped(
            manager,
            WrappedTransportKind::Quic,
            WrappedTransportRole::Destination,
        ),
        Some(domain) => {
            return Err(anyhow::anyhow!("invalid TcpProxyRpcService domain_name: {domain}").into());
        }
    };
    Ok(rpc)
}
