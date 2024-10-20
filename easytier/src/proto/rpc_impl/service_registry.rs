use std::sync::Arc;

use dashmap::DashMap;

use crate::proto::common::RpcDescriptor;
use crate::proto::rpc_types;
use crate::proto::rpc_types::descriptor::ServiceDescriptor;
use crate::proto::rpc_types::handler::{Handler, HandlerExt};

use super::RpcController;

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct ServiceKey {
    pub domain_name: String,
    pub service_name: String,
    pub proto_name: String,
}

impl From<&RpcDescriptor> for ServiceKey {
    fn from(desc: &RpcDescriptor) -> Self {
        Self {
            domain_name: desc.domain_name.to_string(),
            service_name: desc.service_name.to_string(),
            proto_name: desc.proto_name.to_string(),
        }
    }
}

#[derive(Clone)]
struct ServiceEntry {
    service: Arc<Box<dyn HandlerExt<Controller = RpcController>>>,
}

impl ServiceEntry {
    fn new<H: Handler<Controller = RpcController>>(h: H) -> Self {
        Self {
            service: Arc::new(Box::new(h)),
        }
    }

    async fn call_method(
        &self,
        ctrl: RpcController,
        method_index: u8,
        input: bytes::Bytes,
    ) -> rpc_types::error::Result<bytes::Bytes> {
        self.service.call_method(ctrl, method_index, input).await
    }
}

pub struct ServiceRegistry {
    table: DashMap<ServiceKey, ServiceEntry>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    pub fn replace_registry(&self, registry: &ServiceRegistry) {
        self.table.clear();
        for item in registry.table.iter() {
            let (k, v) = item.pair();
            self.table.insert(k.clone(), v.clone());
        }
    }

    pub fn register<H: Handler<Controller = RpcController>>(&self, h: H, domain_name: &str) {
        let desc = h.service_descriptor();
        let key = ServiceKey {
            domain_name: domain_name.to_string(),
            service_name: desc.name().to_string(),
            proto_name: desc.proto_name().to_string(),
        };
        let entry = ServiceEntry::new(h);
        self.table.insert(key, entry);
    }

    pub fn unregister<H: Handler<Controller = RpcController>>(
        &self,
        h: H,
        domain_name: &str,
    ) -> Option<()> {
        let desc = h.service_descriptor();
        let key = ServiceKey {
            domain_name: domain_name.to_string(),
            service_name: desc.name().to_string(),
            proto_name: desc.proto_name().to_string(),
        };
        self.table.remove(&key).map(|_| ())
    }

    pub fn unregister_by_domain(&self, domain_name: &str) {
        self.table.retain(|k, _| k.domain_name != domain_name);
    }

    pub async fn call_method(
        &self,
        rpc_desc: RpcDescriptor,
        ctrl: RpcController,
        input: bytes::Bytes,
    ) -> rpc_types::error::Result<bytes::Bytes> {
        let service_key = ServiceKey::from(&rpc_desc);
        let method_index = rpc_desc.method_index as u8;
        let entry = self
            .table
            .get(&service_key)
            .ok_or(rpc_types::error::Error::InvalidServiceKey(
                service_key.service_name.clone(),
                service_key.proto_name.clone(),
            ))?
            .clone();
        entry.call_method(ctrl, method_index, input).await
    }
}
