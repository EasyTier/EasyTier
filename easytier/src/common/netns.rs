//! Canonical native network domains and short synchronous OS scopes.

use std::{
    io,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use easytier_core::socket::{NetNamespace, SocketContext};

use crate::{common::dns::RuntimeDnsResolver, host_runtime::native_host_runtime};

mod platform;
pub(crate) use platform::{NetNsId, PlatformNamespace};

pub static ROOT_NETNS_NAME: &str = "_root_ns";

/// The unique service owner for one actual native network domain.
///
/// Obtain an Arc through current/open_existing; cloning an Arc shares authority.
pub struct NetNS {
    platform: PlatformNamespace,
    closing: AtomicBool,
    service_initialization: Mutex<()>,
    #[cfg(all(target_os = "linux", feature = "linux-netlink", feature = "tun"))]
    routes: OnceLock<Result<crate::instance::route::RouteController, Arc<str>>>,
    pub(crate) dns: RuntimeDnsResolver,
    #[cfg(feature = "tun")]
    pub(crate) nics: crate::instance::shared_virtual_nic::ArcSharedVirtualNicRegistry,
}

impl std::fmt::Debug for NetNS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetNS")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl From<Arc<NetNS>> for PlatformNamespace {
    fn from(namespace: Arc<NetNS>) -> Self {
        namespace.platform.clone()
    }
}

impl NetNS {
    pub fn current() -> io::Result<Arc<Self>> {
        native_host_runtime().intern_namespace(PlatformNamespace::current()?)
    }

    #[cfg(target_os = "linux")]
    pub fn open_existing(name: &str) -> io::Result<Arc<Self>> {
        native_host_runtime().intern_namespace(PlatformNamespace::open_existing(name)?)
    }

    pub(crate) fn resolve_config(name: Option<&str>) -> io::Result<Arc<Self>> {
        match name {
            None => Self::current(),
            #[cfg(target_os = "linux")]
            Some(name) => Self::open_existing(name),
            #[cfg(not(target_os = "linux"))]
            Some(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "named network namespaces are unsupported",
            )),
        }
    }

    pub(crate) fn from_platform(platform: PlatformNamespace) -> Self {
        Self {
            dns: RuntimeDnsResolver::in_namespace(platform.clone()),
            platform,
            closing: AtomicBool::new(false),
            service_initialization: Mutex::new(()),
            #[cfg(all(target_os = "linux", feature = "linux-netlink", feature = "tun"))]
            routes: OnceLock::new(),
            #[cfg(feature = "tun")]
            nics: Arc::new(tokio::sync::Mutex::new(
                crate::instance::shared_virtual_nic::SharedVirtualNicRegistry::new(),
            )),
        }
    }

    pub(crate) fn id(&self) -> NetNsId {
        self.platform.id()
    }

    pub(crate) fn platform(&self) -> &PlatformNamespace {
        &self.platform
    }

    pub(crate) fn token(&self) -> NetNamespace {
        NetNamespace::new(self.id().to_string())
    }

    pub(crate) fn validate_context(&self, context: &SocketContext) -> io::Result<()> {
        self.ensure_open()?;
        self.platform.validate_context(context)
    }

    pub(crate) fn ensure_open(&self) -> io::Result<()> {
        if self.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native network namespace is closing"));
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "linux-netlink", feature = "tun"))]
    pub(crate) fn route_controller(
        &self,
    ) -> anyhow::Result<&crate::instance::route::RouteController> {
        self.ensure_open()?;
        let result = if let Some(routes) = self.routes.get() {
            routes
        } else {
            // The gate spans OnceLock publication, not just its initializer.
            // Close cannot miss a newly published worker behind this gate.
            let _initialization = self.service_initialization.lock().unwrap();
            self.ensure_open()?;
            self.routes.get_or_init(|| {
                let shared = native_host_runtime()
                    .shared_executor()
                    .map_err(|error| Arc::<str>::from(error.to_string()))?;
                crate::instance::route::RouteController::new(self.platform.clone(), shared)
                    .map_err(|error| Arc::<str>::from(error.to_string()))
            })
        };
        result
            .as_ref()
            .map_err(|reason| anyhow::anyhow!("route controller initialization failed: {reason}"))
    }

    pub(crate) fn request_service_shutdown(&self) {
        self.closing.store(true, Ordering::Release);
        let _initialization = self.service_initialization.lock().unwrap();
        #[cfg(all(target_os = "linux", feature = "linux-netlink", feature = "tun"))]
        if let Some(Ok(routes)) = self.routes.get() {
            routes.request_shutdown();
        }
    }

    pub(crate) async fn wait_services_stopped(&self) -> anyhow::Result<()> {
        #[cfg(all(target_os = "linux", feature = "linux-netlink", feature = "tun"))]
        if let Some(routes) = self.routes.get() {
            match routes {
                Ok(routes) => routes.wait_stopped().await?,
                Err(reason) => anyhow::bail!("route controller initialization failed: {reason}"),
            }
        }
        Ok(())
    }

    pub(crate) fn run<R>(&self, operation: impl FnOnce() -> R) -> io::Result<R> {
        self.platform.run(operation)
    }

    #[cfg(test)]
    pub(crate) fn new(name: Option<String>) -> Arc<Self> {
        Self::resolve_config(name.as_deref()).expect("open test network namespace")
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn isolated_namespace_for_test() -> io::Result<Arc<NetNS>> {
    // Run the test process in `unshare --user --map-root-user --net` first, so
    // both the initial and additional domains belong to that user namespace.
    std::thread::Builder::new()
        .name("netns-test-fixture".to_owned())
        .spawn(|| {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
            let status = std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()?;
            if !status.success() {
                return Err(io::Error::other("failed to bring up isolated loopback"));
            }
            NetNS::current()
        })?
        .join()
        .map_err(|_| io::Error::other("namespace fixture thread panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run inside an isolated user+network namespace"]
    fn distinct_domains_restore_actual_thread_context_after_errors_and_unwind() {
        let original = NetNS::current().unwrap();
        let a = isolated_namespace_for_test().unwrap();
        let b = isolated_namespace_for_test().unwrap();
        assert_ne!(a.id(), b.id());
        a.run(|| {
            assert!(Arc::ptr_eq(&a, &NetNS::current().unwrap()));
            let result = b
                .run(|| {
                    assert!(Arc::ptr_eq(&b, &NetNS::current().unwrap()));
                    Err::<(), _>("operation failed")
                })
                .unwrap();
            assert!(result.is_err());
            assert!(Arc::ptr_eq(&a, &NetNS::current().unwrap()));
        })
        .unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            a.run(|| panic!("namespace operation panic")).unwrap();
        }));
        assert!(panic.is_err());
        assert!(Arc::ptr_eq(&original, &NetNS::current().unwrap()));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn asynchronous_io_keeps_its_bound_domain_on_default_runtime_threads() {
        use easytier_core::socket::udp::{
            UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory,
        };
        let original = NetNS::current().unwrap();
        let a = isolated_namespace_for_test().unwrap();
        let b = isolated_namespace_for_test().unwrap();
        let first = a
            .bind_udp(
                UdpBindOptions::direct_connect()
                    .with_local_addr(Some("127.0.0.1:0".parse().unwrap())),
            )
            .await
            .unwrap();
        let address = first.local_addr().unwrap();
        let second = b
            .bind_udp(UdpBindOptions::direct_connect().with_local_addr(Some(address)))
            .await
            .unwrap();
        assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
        assert!(
            a.bind_udp(UdpBindOptions::direct_connect().with_local_addr(Some(address)))
                .await
                .is_err()
        );
        let client = a.bind_udp(UdpBindOptions::direct_connect()).await.unwrap();
        client.send_to(b"bound-domain", address).await.unwrap();
        let mut buffer = [0; 32];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            first.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..length], b"bound-domain");
        assert!(Arc::ptr_eq(&original, &NetNS::current().unwrap()));
    }

    #[test]
    fn independent_instances_share_the_domain_but_not_their_run_identity() {
        use crate::common::{config::TomlConfig, global_ctx::GlobalCtx};
        let first = GlobalCtx::new(TomlConfig::default());
        let second = GlobalCtx::new(TomlConfig::default());
        assert!(Arc::ptr_eq(&first.net_ns, &second.net_ns));
        assert_ne!(first.run_key(), second.run_key());
        #[cfg(feature = "tun")]
        assert!(Arc::ptr_eq(&first.net_ns.nics, &second.net_ns.nics));
    }

    #[test]
    fn concurrent_current_calls_return_the_same_service_owner() {
        let expected = NetNS::current().unwrap();
        let threads = (0..8)
            .map(|_| std::thread::spawn(|| NetNS::current().unwrap()))
            .collect::<Vec<_>>();
        for thread in threads {
            assert!(Arc::ptr_eq(&expected, &thread.join().unwrap()));
        }
    }

    #[test]
    fn contexts_are_runtime_identities_and_none_uses_the_bound_domain() {
        let namespace = NetNS::current().unwrap();
        assert!(
            namespace
                .validate_context(&SocketContext::default())
                .is_ok()
        );
        assert!(
            namespace
                .validate_context(&SocketContext::default().with_netns(Some(namespace.token())))
                .is_ok()
        );
        assert!(
            namespace
                .validate_context(
                    &SocketContext::default()
                        .with_netns(Some(NetNamespace::new("configured-name")))
                )
                .is_err()
        );
    }
    #[cfg(all(target_os = "linux", feature = "linux-netlink", feature = "tun"))]
    #[tokio::test]
    async fn concurrent_route_service_initialization_has_one_owner_and_close_is_final() {
        // This fixture has no route demands and never mutates the host table.
        let namespace = Arc::new(NetNS::from_platform(PlatformNamespace::current().unwrap()));
        let callers = (0..16)
            .map(|_| {
                let namespace = namespace.clone();
                std::thread::spawn(move || {
                    namespace.route_controller().unwrap() as *const _ as usize
                })
            })
            .collect::<Vec<_>>();
        let addresses = callers
            .into_iter()
            .map(|caller| caller.join().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(addresses.len(), 1);
        let owner = namespace
            .route_controller()
            .unwrap()
            .open_instance(uuid::Uuid::new_v4(), String::new())
            .unwrap();
        owner
            .bind_config(easytier_core::config::runtime::CoreRuntimeConfigStore::new(
                easytier_core::config::runtime::CoreRuntimeConfig::default(),
                Arc::new(easytier_core::config::peers::PeerRuntimeSnapshot::default()),
            ))
            .unwrap();
        let claim = owner
            .handle()
            .publish(easytier_core::host::route::RouteDemand::Additional(
                Default::default(),
            ))
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), claim.wait_ready(None))
            .await
            .unwrap()
            .unwrap();
        namespace.request_service_shutdown();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            namespace.wait_services_stopped(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(namespace.route_controller().is_err());
        assert!(
            namespace
                .validate_context(&SocketContext::default())
                .is_err()
        );
    }

    #[cfg(all(target_os = "linux", feature = "linux-netlink", feature = "tun"))]
    #[tokio::test]
    async fn close_racing_first_initialization_cannot_publish_an_open_service() {
        let namespace = Arc::new(NetNS::from_platform(PlatformNamespace::current().unwrap()));
        let gate = Arc::new(std::sync::Barrier::new(9));
        let callers = (0..8)
            .map(|_| {
                let namespace = namespace.clone();
                let gate = gate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    let _ = namespace.route_controller();
                })
            })
            .collect::<Vec<_>>();
        gate.wait();
        namespace.request_service_shutdown();
        for caller in callers {
            caller.join().unwrap();
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            namespace.wait_services_stopped(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(namespace.route_controller().is_err());
        if let Some(Ok(controller)) = namespace.routes.get() {
            assert!(
                controller
                    .open_instance(uuid::Uuid::new_v4(), String::new())
                    .is_err()
            );
        }
    }
}
