use std::sync::Arc;

use easytier_proto::api::instance::{InstanceIdentifier, instance_identifier::Selector};

use crate::instance::{
    CoreInstance, CoreInstanceHost,
    manager::{InstanceFactory, InstanceManager, ManagedInstance},
};

/// Transport-independent selector for one managed Instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementSelector {
    Id(uuid::Uuid),
    Name(String),
    UnambiguousDefault,
}

/// Instance metadata required by process-level management selection.
pub trait ManagementInstance: ManagedInstance {
    fn instance_name(&self) -> &str;
}

impl<H> ManagementInstance for CoreInstance<H>
where
    H: CoreInstanceHost,
{
    fn instance_name(&self) -> &str {
        self.instance_name()
    }
}

/// Resolves one stateless management selector through the canonical Manager.
pub fn resolve_instance<F>(
    manager: &InstanceManager<F>,
    identifier: Option<&InstanceIdentifier>,
) -> anyhow::Result<Arc<F::Instance>>
where
    F: InstanceFactory,
    F::Instance: ManagementInstance,
{
    let selector = match identifier.and_then(|identifier| identifier.selector.as_ref()) {
        Some(Selector::Id(instance_id)) => ManagementSelector::Id((*instance_id).into()),
        Some(Selector::InstanceSelector(selector)) => selector
            .name
            .clone()
            .map(ManagementSelector::Name)
            .unwrap_or(ManagementSelector::UnambiguousDefault),
        None => ManagementSelector::UnambiguousDefault,
    };
    resolve_management_instance(manager, &selector)
}

/// Resolves one Instance without coupling the caller to an RPC request type.
pub fn resolve_management_instance<F>(
    manager: &InstanceManager<F>,
    selector: &ManagementSelector,
) -> anyhow::Result<Arc<F::Instance>>
where
    F: InstanceFactory,
    F::Instance: ManagementInstance,
{
    if let ManagementSelector::Id(instance_id) = selector {
        return manager
            .get(*instance_id)
            .ok_or_else(|| anyhow::anyhow!("Instance not found"));
    }

    let matching = manager
        .list()
        .into_iter()
        .filter(|instance| match selector {
            ManagementSelector::Name(name) => instance.instance_name() == name,
            ManagementSelector::UnambiguousDefault => true,
            ManagementSelector::Id(_) => unreachable!(),
        })
        .collect::<Vec<_>>();

    match matching.as_slice() {
        [] => anyhow::bail!("No instance matches the selector"),
        [instance] => Ok(instance.clone()),
        _ => anyhow::bail!(
            "{} instances match the selector, please specify the instance ID",
            matching.len()
        ),
    }
}

/// Resolves a unique name, distinguishing a missing name from ambiguity.
pub fn resolve_optional_instance_by_name<F>(
    manager: &InstanceManager<F>,
    name: &str,
) -> anyhow::Result<Option<Arc<F::Instance>>>
where
    F: InstanceFactory,
    F::Instance: ManagementInstance,
{
    let matching = manager
        .list()
        .into_iter()
        .filter(|instance| instance.instance_name() == name)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [] => Ok(None),
        [instance] => Ok(Some(instance.clone())),
        _ => anyhow::bail!(
            "{} instances match the selector, please specify the instance ID",
            matching.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use easytier_proto::{
        api::instance::{
            InstanceIdentifier, instance_identifier::InstanceSelector,
            instance_identifier::Selector,
        },
        common::Uuid as UuidPb,
    };
    use uuid::Uuid;

    use super::*;
    use crate::{
        config::toml::{ConfigLoader as _, TomlConfig},
        instance::manager::InstanceCreateError,
    };

    #[derive(Debug)]
    struct TestInstance {
        id: Uuid,
        name: String,
    }

    impl ManagedInstance for TestInstance {
        fn instance_id(&self) -> Uuid {
            self.id
        }
    }

    impl ManagementInstance for TestInstance {
        fn instance_name(&self) -> &str {
            &self.name
        }
    }

    struct TestFactory;

    impl InstanceFactory for TestFactory {
        type Instance = TestInstance;
        type CreateContext = String;
        type Error = std::convert::Infallible;

        fn create(
            &self,
            config: TomlConfig,
            name: Self::CreateContext,
        ) -> Result<Arc<Self::Instance>, Self::Error> {
            Ok(Arc::new(TestInstance {
                id: config.get_id(),
                name,
            }))
        }
    }

    fn add(
        manager: &InstanceManager<TestFactory>,
        id: Uuid,
        name: &str,
    ) -> Result<(), InstanceCreateError<std::convert::Infallible>> {
        let config = TomlConfig::default();
        config.set_id(id);
        manager.create(config, name.to_owned()).map(|_| ())
    }

    fn by_id(id: Uuid) -> InstanceIdentifier {
        InstanceIdentifier {
            selector: Some(Selector::Id(UuidPb::from(id))),
        }
    }

    fn by_name(name: &str) -> InstanceIdentifier {
        InstanceIdentifier {
            selector: Some(Selector::InstanceSelector(InstanceSelector {
                name: Some(name.to_owned()),
            })),
        }
    }

    #[test]
    fn resolves_uuid_name_and_single_implicit_instance() {
        let manager = InstanceManager::new(TestFactory);
        let id = Uuid::new_v4();
        add(&manager, id, "alpha").unwrap();

        assert_eq!(resolve_instance(&manager, Some(&by_id(id))).unwrap().id, id);
        assert_eq!(
            resolve_instance(&manager, Some(&by_name("alpha")))
                .unwrap()
                .id,
            id
        );
        assert_eq!(resolve_instance(&manager, None).unwrap().id, id);
    }

    #[test]
    fn rejects_missing_and_ambiguous_selectors() {
        let manager = InstanceManager::new(TestFactory);
        assert_eq!(
            resolve_instance(&manager, None).unwrap_err().to_string(),
            "No instance matches the selector"
        );

        add(&manager, Uuid::new_v4(), "same").unwrap();
        add(&manager, Uuid::new_v4(), "same").unwrap();
        assert!(
            resolve_instance(&manager, None)
                .unwrap_err()
                .to_string()
                .contains("2 instances match")
        );
        assert!(
            resolve_instance(&manager, Some(&by_name("same")))
                .unwrap_err()
                .to_string()
                .contains("2 instances match")
        );
        assert_eq!(
            resolve_instance(&manager, Some(&by_name("missing")))
                .unwrap_err()
                .to_string(),
            "No instance matches the selector"
        );
    }
}
