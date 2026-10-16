//! Pinned OS namespace resources. This module never owns native services.

use std::io;

#[cfg(target_os = "linux")]
use std::{
    fs::{File, Metadata},
    marker::PhantomData,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path},
    rc::Rc,
    sync::Arc,
};

/// Identity of an actual network domain, independent of its configured name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct NetNsId {
    #[cfg(target_os = "linux")]
    device: u64,
    #[cfg(target_os = "linux")]
    inode: u64,
}

#[cfg(target_os = "linux")]
impl NetNsId {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

impl std::fmt::Display for NetNsId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(target_os = "linux")]
        return write!(f, "native-netns:{}:{}", self.device, self.inode);

        #[cfg(not(target_os = "linux"))]
        f.write_str("native-netns:default")
    }
}

impl NetNsId {
    pub(crate) fn from_token(token: &str) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let parse = || {
                let (device, inode) = token.strip_prefix("native-netns:")?.split_once(':')?;
                Some(Self {
                    device: device.parse().ok()?,
                    inode: inode.parse().ok()?,
                })
            };
            parse().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid native namespace token",
                )
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            if token == "native-netns:default" {
                Ok(Self {})
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid native namespace token",
                ))
            }
        }
    }
}

/// Cloning pins the same kernel namespace, without retaining its service owner.
#[derive(Clone, Debug)]
pub(crate) struct PlatformNamespace {
    id: NetNsId,
    #[cfg(target_os = "linux")]
    file: Arc<File>,
}

impl PlatformNamespace {
    pub(crate) fn current() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        return Self::open_path(Path::new("/proc/thread-self/ns/net"));

        #[cfg(not(target_os = "linux"))]
        Ok(Self { id: NetNsId {} })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn open_existing(name: &str) -> io::Result<Self> {
        if name == super::ROOT_NETNS_NAME {
            return Self::open_path(Path::new("/proc/1/ns/net"));
        }
        // Names are labels under /var/run/netns, not arbitrary file paths.
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network namespace name must be one path component",
            ));
        }
        Self::open_path(&Path::new("/var/run/netns").join(name))
    }

    #[cfg(target_os = "linux")]
    fn open_path(path: &Path) -> io::Result<Self> {
        let file = Arc::new(File::open(path)?);
        let id = NetNsId::of(&file.metadata()?);
        // SAFETY: the ioctl takes no argument and only queries this open fd.
        let namespace_type =
            unsafe { nix::libc::ioctl(file.as_raw_fd(), nix::libc::NS_GET_NSTYPE) };
        if namespace_type < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(nix::libc::ENOTTY) {
                return Err(error);
            }
            // NS_GET_NSTYPE was added in Linux 4.11. The current network
            // namespace is already known without requiring CAP_SYS_ADMIN.
            if id != NetNsId::of(&std::fs::metadata("/proc/thread-self/ns/net")?) {
                // On older kernels setns validates the type. Use a disposable
                // thread so validation never changes the caller's namespace.
                let probe = file.clone();
                std::thread::Builder::new()
                    .name("easytier-netns-probe".to_owned())
                    .spawn(move || {
                        nix::sched::setns(probe.as_ref(), nix::sched::CloneFlags::CLONE_NEWNET)
                    })?
                    .join()
                    .map_err(|_| io::Error::other("namespace validation thread panicked"))??;
            }
        } else if namespace_type != nix::libc::CLONE_NEWNET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file is not a network namespace",
            ));
        }
        Ok(Self { id, file })
    }

    pub(crate) fn id(&self) -> NetNsId {
        self.id
    }

    pub(crate) fn validate_context(
        &self,
        context: &easytier_core::socket::SocketContext,
    ) -> io::Result<()> {
        if let Some(namespace) = &context.netns
            && NetNsId::from_token(namespace.token())? != self.id
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket context belongs to a different network namespace",
            ));
        }
        Ok(())
    }

    /// Run only the synchronous resource-creation/query portion of an operation.
    pub(crate) fn run<R>(&self, operation: impl FnOnce() -> R) -> io::Result<R> {
        #[cfg(target_os = "linux")]
        let _guard = self.enter()?;
        Ok(operation())
    }

    #[cfg(target_os = "linux")]
    fn enter(&self) -> io::Result<RestoreNamespace> {
        let current = NetNsId::of(&std::fs::metadata("/proc/thread-self/ns/net")?);
        let previous = if current == self.id {
            // Even setns to our own namespace requires privileges. Do not do it.
            None
        } else {
            let previous = File::open("/proc/thread-self/ns/net")?;
            nix::sched::setns(self.file.as_ref(), nix::sched::CloneFlags::CLONE_NEWNET)?;
            Some(previous)
        };
        Ok(RestoreNamespace {
            previous,
            _thread_bound: PhantomData,
        })
    }
}

/// Private and !Send / !Sync: namespace membership belongs to this OS thread.
#[cfg(target_os = "linux")]
struct RestoreNamespace {
    previous: Option<File>,
    _thread_bound: PhantomData<Rc<()>>,
}

#[cfg(target_os = "linux")]
impl Drop for RestoreNamespace {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous
            && let Err(error) = nix::sched::setns(previous, nix::sched::CloneFlags::CLONE_NEWNET)
        {
            // A contaminated runtime thread must never execute another task.
            tracing::error!(%error, "failed to restore network namespace; aborting");
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_identity_is_stable_and_clones_pin_the_same_domain() {
        let first = PlatformNamespace::current().unwrap();
        let second = PlatformNamespace::current().unwrap();
        assert_eq!(first.id(), second.id());
        assert_eq!(first.clone().id(), second.id());
        assert_eq!(first.run(|| 42).unwrap(), 42);
    }

    #[test]
    fn nested_current_domain_operations_restore_errors_and_unwind() {
        let namespace = PlatformNamespace::current().unwrap();
        assert!(
            namespace
                .run(|| namespace.run(|| Err::<(), _>("operation")))
                .unwrap()
                .unwrap()
                .is_err()
        );
        let panic = std::panic::catch_unwind(|| {
            namespace.run(|| panic!("operation panic")).unwrap();
        });
        assert!(panic.is_err());
        assert_eq!(PlatformNamespace::current().unwrap().id(), namespace.id());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_wrong_namespace_type_and_path_names() {
        let error =
            PlatformNamespace::open_path(Path::new("/proc/thread-self/ns/mnt")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        for name in ["", ".", "..", "/tmp/test", "a/b"] {
            assert_eq!(
                PlatformNamespace::open_existing(name).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
