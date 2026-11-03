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
