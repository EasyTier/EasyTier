//! Transport-neutral dispatch for one decoded RPC request.

use bytes::Bytes;
use std::time::Duration;

use crate::{
    foundation::time::timeout,
    proto::{
        common::{RpcDescriptor, RpcRequest, TunnelInfo},
        rpc_types::{
            controller::{BaseController, Controller as _},
            error::Result,
        },
    },
    rpc::service_registry::ServiceRegistry,
};

pub(crate) async fn dispatch_request(
    registry: &ServiceRegistry,
    descriptor: RpcDescriptor,
    request: RpcRequest,
    tunnel_info: Option<TunnelInfo>,
) -> Result<Bytes> {
    dispatch_payload(
        registry,
        descriptor,
        Bytes::from(request.request),
        Some(Duration::from_millis(request.timeout_ms as u64)),
        tunnel_info,
    )
    .await
}

pub(crate) async fn dispatch_payload(
    registry: &ServiceRegistry,
    descriptor: RpcDescriptor,
    raw_request: Bytes,
    timeout_duration: Option<Duration>,
    tunnel_info: Option<TunnelInfo>,
) -> Result<Bytes> {
    let mut controller = BaseController::default();
    controller.set_raw_input(raw_request.clone());
    controller.set_tunnel_info(tunnel_info);
    let call = registry.call_method(descriptor, controller.clone(), raw_request);
    let response = match timeout_duration {
        Some(duration) => timeout(duration, call).await??,
        None => call.await?,
    };
    Ok(controller.get_raw_output().unwrap_or(response))
}
