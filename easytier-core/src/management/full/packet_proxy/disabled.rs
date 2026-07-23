use std::sync::Arc;

use crate::{
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    rpc::service_registry::ServiceRegistry,
};

use super::JsonCall;

pub(in crate::management) fn register<F, H>(
    _manager: Arc<InstanceManager<F>>,
    _registry: &ServiceRegistry,
) where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
}

pub(in crate::management) async fn call_json<F, H>(
    _manager: &Arc<InstanceManager<F>>,
    _service_name: &str,
    _method_name: &str,
    _domain_name: Option<&str>,
    payload: serde_json::Value,
) -> JsonCall
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    Err(payload)
}
