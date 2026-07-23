//! Canonical collection for complete EasyTier instance records.

use std::{
    collections::{HashMap, hash_map::Entry},
    error::Error,
    fmt,
    sync::{Arc, Mutex},
};

use uuid::Uuid;

use crate::config::toml::TomlConfig;
use crate::instance::{CoreInstance, CoreInstanceHost};

/// Stable identity required by the instance collection.
pub trait ManagedInstance: Send + Sync + 'static {
    fn instance_id(&self) -> Uuid;
}

impl<H> ManagedInstance for CoreInstance<H>
where
    H: CoreInstanceHost,
{
    fn instance_id(&self) -> Uuid {
        self.instance_id()
    }
}

/// Host-specific construction seam for one complete instance record.
pub trait InstanceFactory: Send + Sync + 'static {
    type Instance: ManagedInstance;
    type CreateContext;
    type Error;

    fn create(
        &self,
        config: TomlConfig,
        context: Self::CreateContext,
    ) -> Result<Arc<Self::Instance>, Self::Error>;
}

/// Error returned while constructing or registering an instance.
#[derive(Debug)]
pub enum InstanceCreateError<E> {
    Factory(E),
    AlreadyExists { instance_id: Uuid },
}

impl<E> fmt::Display for InstanceCreateError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Factory(error) => write!(formatter, "failed to create instance: {error:#}"),
            Self::AlreadyExists { instance_id } => {
                write!(formatter, "instance {instance_id} already exists")
            }
        }
    }
}

impl<E> Error for InstanceCreateError<E> where E: fmt::Debug + fmt::Display {}

/// Owns the canonical UUID-to-instance collection for one Host composition.
pub struct InstanceManager<F>
where
    F: InstanceFactory,
{
    factory: F,
    instances: Mutex<HashMap<Uuid, Arc<F::Instance>>>,
}

impl<F> InstanceManager<F>
where
    F: InstanceFactory,
{
    pub fn new(factory: F) -> Self {
        Self {
            factory,
            instances: Mutex::new(HashMap::new()),
        }
    }

    pub fn create(
        &self,
        config: TomlConfig,
        context: F::CreateContext,
    ) -> Result<Arc<F::Instance>, InstanceCreateError<F::Error>> {
        let instance = self
            .factory
            .create(config, context)
            .map_err(InstanceCreateError::Factory)?;
        let instance_id = instance.instance_id();
        let mut instances = self.instances.lock().expect("instance map lock poisoned");

        match instances.entry(instance_id) {
            Entry::Vacant(entry) => {
                entry.insert(instance.clone());
                Ok(instance)
            }
            Entry::Occupied(_) => Err(InstanceCreateError::AlreadyExists { instance_id }),
        }
    }

    pub fn get(&self, instance_id: Uuid) -> Option<Arc<F::Instance>> {
        self.instances
            .lock()
            .expect("instance map lock poisoned")
            .get(&instance_id)
            .cloned()
    }

    pub fn list(&self) -> Vec<Arc<F::Instance>> {
        self.instances
            .lock()
            .expect("instance map lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub fn remove(&self, instance_id: Uuid) -> Option<Arc<F::Instance>> {
        self.instances
            .lock()
            .expect("instance map lock poisoned")
            .remove(&instance_id)
    }
}

impl<F> Default for InstanceManager<F>
where
    F: InstanceFactory + Default,
{
    fn default() -> Self {
        Self::new(F::default())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use super::*;
    use crate::config::toml::ConfigLoader as _;

    #[derive(Clone)]
    struct TestFactory {
        calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct TestInstance {
        id: Uuid,
        drops: Arc<AtomicUsize>,
    }

    impl ManagedInstance for TestInstance {
        fn instance_id(&self) -> Uuid {
            self.id
        }
    }

    impl Drop for TestInstance {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TestCreateContext {
        fail: bool,
        construction_barrier: Option<Arc<Barrier>>,
    }

    impl TestCreateContext {
        fn success() -> Self {
            Self {
                fail: false,
                construction_barrier: None,
            }
        }
    }

    impl InstanceFactory for TestFactory {
        type Instance = TestInstance;
        type CreateContext = TestCreateContext;
        type Error = anyhow::Error;

        fn create(
            &self,
            config: TomlConfig,
            context: Self::CreateContext,
        ) -> Result<Arc<Self::Instance>, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(barrier) = context.construction_barrier {
                barrier.wait();
            }
            if context.fail {
                return Err(
                    anyhow::anyhow!("factory root cause").context("requested factory failure")
                );
            }
            Ok(Arc::new(TestInstance {
                id: config.get_id(),
                drops: self.drops.clone(),
            }))
        }
    }

    fn manager() -> (
        Arc<InstanceManager<TestFactory>>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let manager = Arc::new(InstanceManager::new(TestFactory {
            calls: calls.clone(),
            drops: drops.clone(),
        }));
        (manager, calls, drops)
    }

    fn config(instance_id: Uuid) -> TomlConfig {
        let config = TomlConfig::default();
        config.set_id(instance_id);
        config
    }

    #[test]
    fn factory_failure_leaves_collection_unchanged() {
        let (manager, calls, drops) = manager();
        let error = manager
            .create(
                config(Uuid::new_v4()),
                TestCreateContext {
                    fail: true,
                    construction_barrier: None,
                },
            )
            .unwrap_err();

        assert!(matches!(error, InstanceCreateError::Factory(_)));
        assert!(manager.list().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn anyhow_factory_error_propagates_through_standard_question_mark() {
        fn create(manager: &InstanceManager<TestFactory>) -> anyhow::Result<()> {
            manager.create(
                config(Uuid::new_v4()),
                TestCreateContext {
                    fail: true,
                    construction_barrier: None,
                },
            )?;
            Ok(())
        }

        let (manager, _calls, _drops) = manager();
        let error = create(&manager).unwrap_err();

        let display = format!("{error:#}");
        assert!(display.contains("requested factory failure"));
        assert!(display.contains("factory root cause"));

        let typed = error
            .downcast_ref::<InstanceCreateError<anyhow::Error>>()
            .unwrap();
        let InstanceCreateError::Factory(factory_error) = typed else {
            panic!("expected factory error");
        };
        assert_eq!(factory_error.root_cause().to_string(), "factory root cause");
    }

    #[test]
    fn duplicate_creation_drops_losing_complete_record() {
        let (manager, calls, drops) = manager();
        let instance_id = Uuid::new_v4();
        let first = manager
            .create(config(instance_id), TestCreateContext::success())
            .unwrap();
        let error = manager
            .create(config(instance_id), TestCreateContext::success())
            .unwrap_err();

        assert!(matches!(
            error,
            InstanceCreateError::AlreadyExists { instance_id: duplicate } if duplicate == instance_id
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(Arc::ptr_eq(&first, &manager.get(instance_id).unwrap()));
    }

    #[test]
    fn concurrent_duplicate_construction_registers_exactly_one_instance() {
        let (manager, calls, drops) = manager();
        let instance_id = Uuid::new_v4();
        let barrier = Arc::new(Barrier::new(2));
        let workers = (0..2)
            .map(|_| {
                let manager = manager.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    manager.create(
                        config(instance_id),
                        TestCreateContext {
                            fail: false,
                            construction_barrier: Some(barrier),
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(InstanceCreateError::AlreadyExists { .. })))
                .count(),
            1
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(manager.list().len(), 1);
    }

    #[test]
    fn list_is_an_arc_snapshot_and_remove_returns_exact_stored_value() {
        let (manager, _calls, drops) = manager();
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let first = manager
            .create(config(first_id), TestCreateContext::success())
            .unwrap();
        let second = manager
            .create(config(second_id), TestCreateContext::success())
            .unwrap();

        let snapshot = manager.list();
        let removed = manager.remove(first_id).unwrap();

        assert!(Arc::ptr_eq(&first, &removed));
        assert!(snapshot.iter().any(|item| Arc::ptr_eq(item, &removed)));
        assert!(manager.get(first_id).is_none());
        assert!(Arc::ptr_eq(&second, &manager.get(second_id).unwrap()));
        drop(removed);
        drop(first);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(snapshot);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
