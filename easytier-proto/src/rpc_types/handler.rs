//! Traits for defining generic RPC handlers.
use crate::proto::rpc_types::descriptor::MethodDescriptor;

use super::{
    controller::Controller,
    descriptor::{self, ServiceDescriptor},
};
use bytes;

/// An implementation of a specific RPC handler.
///
/// This can be an actual implementation of a service, or something that will send a request over
/// a network to fulfill a request.
#[async_trait::async_trait]
pub trait Handler: Clone + Send + Sync + 'static {
    /// The service descriptor for the service whose requests this handler can handle.
    type Descriptor: descriptor::ServiceDescriptor + Default;

    type Controller: super::controller::Controller;

    /// Perform a raw call to the specified service and method.
    async fn call(
        &self,
        ctrl: Self::Controller,
        method: <Self::Descriptor as descriptor::ServiceDescriptor>::Method,
        input: bytes::Bytes,
    ) -> super::error::Result<bytes::Bytes>;

    fn service_descriptor(&self) -> Self::Descriptor {
        Self::Descriptor::default()
    }

    fn get_method_from_index(
        &self,
        index: u8,
    ) -> super::error::Result<<Self::Descriptor as descriptor::ServiceDescriptor>::Method> {
        let desc = self.service_descriptor();
        <Self::Descriptor as descriptor::ServiceDescriptor>::Method::try_from(index)
            .map_err(|_| super::error::Error::InvalidMethodIndex(index, desc.name().to_string()))
    }
}

#[async_trait::async_trait]
pub trait HandlerExt: Send + Sync + 'static {
    type Controller;

    async fn call_method(
        &self,
        ctrl: Self::Controller,
        method_index: u8,
        input: bytes::Bytes,
    ) -> super::error::Result<bytes::Bytes>;

    fn get_method_name(&self, method_index: u8) -> super::error::Result<String>;
}

#[async_trait::async_trait]
impl<C: Controller, T: Handler<Controller = C>> HandlerExt for T {
    type Controller = C;

    async fn call_method(
        &self,
        ctrl: Self::Controller,
        method_index: u8,
        input: bytes::Bytes,
    ) -> super::error::Result<bytes::Bytes> {
        let method = self.get_method_from_index(method_index)?;
        self.call(ctrl, method, input).await
    }

    fn get_method_name(&self, method_index: u8) -> super::error::Result<String> {
        let method = self.get_method_from_index(method_index)?;
        let name = method.name().to_string();
        Ok(name)
    }
}
