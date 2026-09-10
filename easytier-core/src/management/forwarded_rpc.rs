use std::marker::PhantomData;

use async_trait::async_trait;
use bytes::Bytes;

use crate::{
    proto::{
        api::{
            config::ConfigRpcDescriptor,
            instance::{ConnectorManageRpcDescriptor, PeerManageRpcDescriptor},
        },
        rpc_types::{
            controller::BaseController,
            descriptor::{MethodDescriptor, ServiceDescriptor},
            error,
            handler::Handler,
        },
    },
    rpc::service_registry::ServiceRegistry,
};

#[async_trait]
pub(crate) trait ManagementRpcForwarder: Clone + Send + Sync + 'static {
    async fn forward(&self, full_method_name: String, input: Bytes) -> error::Result<Bytes>;
}

struct ForwardedManagementHandler<F, D> {
    forwarder: F,
    _descriptor: PhantomData<fn() -> D>,
}

impl<F, D> ForwardedManagementHandler<F, D> {
    fn new(forwarder: F) -> Self {
        Self {
            forwarder,
            _descriptor: PhantomData,
        }
    }
}

impl<F, D> Clone for ForwardedManagementHandler<F, D>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self::new(self.forwarder.clone())
    }
}

#[async_trait]
impl<F, D> Handler for ForwardedManagementHandler<F, D>
where
    F: ManagementRpcForwarder,
    D: ServiceDescriptor + Default + 'static,
{
    type Descriptor = D;
    type Controller = BaseController;

    async fn call(
        &self,
        _: Self::Controller,
        method: D::Method,
        input: Bytes,
    ) -> error::Result<Bytes> {
        let descriptor = D::default();
        let full_method_name = if descriptor.package().is_empty() {
            format!("{}.{}", descriptor.proto_name(), method.proto_name())
        } else {
            format!(
                "{}.{}.{}",
                descriptor.package(),
                descriptor.proto_name(),
                method.proto_name()
            )
        };
        self.forwarder.forward(full_method_name, input).await
    }
}

/// Registers the instance-management services supported by the bound WASI RPC ABI.
pub(crate) fn register_forwarded_instance_management_rpc<F>(
    forwarder: F,
    registry: &ServiceRegistry,
) where
    F: ManagementRpcForwarder,
{
    registry.register(
        ForwardedManagementHandler::<F, PeerManageRpcDescriptor>::new(forwarder.clone()),
        "",
    );
    registry.register(
        ForwardedManagementHandler::<F, ConnectorManageRpcDescriptor>::new(forwarder.clone()),
        "",
    );
    registry.register(
        ForwardedManagementHandler::<F, ConfigRpcDescriptor>::new(forwarder),
        "",
    );
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct RecordingForwarder {
        calls: Arc<Mutex<Vec<(String, Bytes)>>>,
    }

    #[async_trait]
    impl ManagementRpcForwarder for RecordingForwarder {
        async fn forward(&self, full_method_name: String, input: Bytes) -> error::Result<Bytes> {
            self.calls
                .lock()
                .unwrap()
                .push((full_method_name, input.clone()));
            Ok(input)
        }
    }

    #[tokio::test]
    async fn registers_and_forwards_bound_instance_management_services() {
        let forwarder = RecordingForwarder::default();
        let registry = ServiceRegistry::new();
        register_forwarded_instance_management_rpc(forwarder.clone(), &registry);

        let methods = [
            "api.instance.PeerManageRpc.ListPeer",
            "api.instance.ConnectorManageRpc.ListConnector",
            "api.config.ConfigRpc.GetConfig",
        ];
        for (index, full_method_name) in methods.into_iter().enumerate() {
            let descriptor = registry
                .resolve_method("", full_method_name)
                .unwrap_or_else(|| panic!("missing forwarded method: {full_method_name}"));
            let request = Bytes::from(vec![index as u8]);
            let response = registry
                .call_method(descriptor, BaseController::default(), request.clone())
                .await
                .unwrap();
            assert_eq!(response, request);
        }

        let calls = forwarder.calls.lock().unwrap();
        assert_eq!(calls.len(), methods.len());
        for ((actual, _), expected) in calls.iter().zip(methods) {
            assert_eq!(actual, expected);
        }
    }
}
