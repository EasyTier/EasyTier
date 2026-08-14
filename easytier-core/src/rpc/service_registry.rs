use std::sync::Arc;

use dashmap::DashMap;

use crate::proto::common::RpcDescriptor;
use crate::proto::rpc_types;
#[cfg(all(feature = "management-rpc", any(test, target_os = "wasi")))]
use crate::proto::rpc_types::descriptor::MethodDescriptor;
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
    #[cfg(all(feature = "management-rpc", any(test, target_os = "wasi")))]
    methods: Arc<[(String, u8)]>,
}

impl ServiceEntry {
    fn new<H: Handler<Controller = RpcController>>(h: H) -> Self {
        #[cfg(all(feature = "management-rpc", any(test, target_os = "wasi")))]
        let descriptor = h.service_descriptor();
        #[cfg(all(feature = "management-rpc", any(test, target_os = "wasi")))]
        let service_name = match descriptor.package() {
            "" => descriptor.proto_name().to_owned(),
            package => format!("{package}.{}", descriptor.proto_name()),
        };
        #[cfg(all(feature = "management-rpc", any(test, target_os = "wasi")))]
        let methods = descriptor
            .methods()
            .iter()
            .map(|method| {
                (
                    format!("{service_name}.{}", method.proto_name()),
                    method.index(),
                )
            })
            .collect::<Vec<_>>()
            .into();
        Self {
            service: Arc::new(Box::new(h)),
            #[cfg(all(feature = "management-rpc", any(test, target_os = "wasi")))]
            methods,
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

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
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

    pub fn get_method_name(&self, rpc_desc: &RpcDescriptor) -> Option<String> {
        let service_key = ServiceKey::from(rpc_desc);
        let entry = self.table.get(&service_key)?;
        let method_index = rpc_desc.method_index as u8;
        let method_name = entry.service.get_method_name(method_index).ok()?;
        Some(method_name)
    }

    #[cfg(all(feature = "management-rpc", any(test, target_os = "wasi")))]
    pub(crate) fn resolve_method(
        &self,
        domain_name: &str,
        full_method_name: &str,
    ) -> Option<RpcDescriptor> {
        self.table.iter().find_map(|entry| {
            if entry.key().domain_name != domain_name {
                return None;
            }
            let method_index = entry
                .value()
                .methods
                .iter()
                .find_map(|(name, index)| (name == full_method_name).then_some(*index))?;
            Some(RpcDescriptor {
                domain_name: domain_name.to_owned(),
                proto_name: entry.key().proto_name.clone(),
                service_name: entry.key().service_name.clone(),
                method_index: method_index.into(),
            })
        })
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

    pub fn unregister_all(&self) {
        self.table.clear();
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
