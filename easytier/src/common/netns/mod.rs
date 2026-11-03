//! Plain OS network-namespace handle.

use std::{
    fmt,
    hash::{Hash, Hasher},
    io,
};

/// Operations every platform's `NetNS` must provide, so the platform
/// implementations cannot drift apart. Import it to call these methods.
pub(crate) trait NetNSImpl: Clone + Sized {
    /// Kernel namespace identity, independent of the name/path used to open it.
    fn id(&self) -> u128;
    /// The process's own namespace, regardless of the calling thread.
    fn process() -> io::Result<Self>;
    /// The calling thread's namespace.
    fn current() -> io::Result<Self>;
    /// Open a configured namespace by name; `None` selects the calling thread's.
    fn open(name: Option<&str>) -> io::Result<Self>;
    /// Run resource creation or a query inside this namespace, restoring the
    /// calling thread before returning.
    fn run<R>(&self, operation: impl FnOnce() -> R) -> io::Result<R>;
}

cfg_select! {
    target_os = "linux" => {
        mod linux;
        pub use linux::NetNS;
    },
    _ => {
        /// Platforms without network namespaces have exactly one.
        #[derive(Clone, Copy)]
        pub struct NetNS;

        impl NetNSImpl for NetNS {
            fn id(&self) -> u128 {
                0
            }

            fn process() -> io::Result<Self> {
                Ok(Self)
            }

            fn current() -> io::Result<Self> {
                Ok(Self)
            }

            fn open(name: Option<&str>) -> io::Result<Self> {
                if name.is_none() {
                    return Ok(Self);
                }
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "named network namespaces are unsupported",
                ))
            }

            fn run<R>(&self, operation: impl FnOnce() -> R) -> io::Result<R> {
                Ok(operation())
            }
        }
    },
}

impl fmt::Debug for NetNS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetNS").field("id", &self.id()).finish()
    }
}

impl PartialEq for NetNS {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for NetNS {}

impl PartialOrd for NetNS {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NetNS {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id().cmp(&other.id())
    }
}

impl Hash for NetNS {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

/// Legacy configuration label for PID 1's network namespace (/proc/1/ns/net).
/// This is distinct from the process default and may belong to a container.
pub const ROOT_NETNS_NAME: &str = "_root_ns";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use easytier_core::socket::BindConfig;
    use crate::host_runtime::NativeHostRuntime;

    #[cfg(target_os = "linux")]
    pub(crate) fn isolated_netns_for_test() -> io::Result<NetNS> {
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

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run inside an isolated user+network namespace"]
    fn distinct_domains_restore_actual_thread_context_after_errors_and_unwind() {
        let original = NetNS::current().unwrap();
        let a = isolated_netns_for_test().unwrap();
        let b = isolated_netns_for_test().unwrap();
        assert_ne!(a.id(), b.id());
        a.run(|| {
            assert!(a == NetNS::current().unwrap());
            let result = b
                .run(|| {
                    assert!(b == NetNS::current().unwrap());
                    Err::<(), _>("operation failed")
                })
                .unwrap();
            assert!(result.is_err());
            assert!(a == NetNS::current().unwrap());
        })
        .unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            a.run(|| panic!("namespace operation panic")).unwrap();
        }));
        assert!(panic.is_err());
        assert!(original == NetNS::current().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn asynchronous_io_keeps_its_bound_domain_on_default_runtime_threads() {
        use easytier_core::socket::udp::{VirtualUdpSocket, VirtualUdpSocketFactory};
        let original = NetNS::current().unwrap();
        let a = isolated_netns_for_test().unwrap();
        let b = isolated_netns_for_test().unwrap();
        let first = NativeHostRuntime::new(a.clone())
            .bind_udp(BindConfig {
                reuse_addr: Some(false),
                bind_device: Some(String::new()),
                local_addr: Some("127.0.0.1:0".parse().unwrap()),
                ..BindConfig::default()
            })
            .await
            .unwrap();
        let address = first.local_addr().unwrap();
        let second = NativeHostRuntime::new(b.clone())
            .bind_udp(BindConfig {
                reuse_addr: Some(false),
                bind_device: Some(String::new()),
                local_addr: Some(address),
                ..BindConfig::default()
            })
            .await
            .unwrap();
        assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
        assert!(
            NativeHostRuntime::new(a.clone())
                .bind_udp(BindConfig {
                    reuse_addr: Some(false),
                    bind_device: Some(String::new()),
                    local_addr: Some(address),
                    ..BindConfig::default()
                })
                .await
                .is_err()
        );
        let client = NativeHostRuntime::new(a.clone())
            .bind_udp(BindConfig {
                reuse_addr: Some(false),
                bind_device: Some(String::new()),
                ..BindConfig::default()
            })
            .await
            .unwrap();
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
        assert!(original == NetNS::current().unwrap());
    }

    #[test]
    fn current_identity_is_stable_and_clones_pin_the_same_domain() {
        let first = NetNS::current().unwrap();
        let second = NetNS::current().unwrap();
        assert_eq!(first.id(), second.id());
        assert_eq!(first.clone().id(), second.id());
        assert_eq!(first.run(|| 42).unwrap(), 42);
    }

    #[test]
    fn nested_current_domain_operations_restore_errors_and_unwind() {
        let net_ns = NetNS::current().unwrap();
        assert!(
            net_ns
                .run(|| net_ns.run(|| Err::<(), _>("operation")))
                .unwrap()
                .unwrap()
                .is_err()
        );
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            net_ns.run(|| panic!("operation panic")).unwrap();
        }));
        assert!(panic.is_err());
        assert_eq!(NetNS::current().unwrap().id(), net_ns.id());
    }
}
