//! Plain OS network-namespace handle. This module never owns native services.

use std::{
    fs::{self, File, Metadata},
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path},
    sync::Arc,
};

use guarden::guarded;

use super::NetNSImpl;

/// Cloning pins the same kernel namespace.
#[derive(Clone)]
pub struct NetNS {
    id: u128,
    file: Arc<File>,
}

impl NetNS {
    fn identity(metadata: &Metadata) -> u128 {
        (u128::from(metadata.dev()) << 64) | u128::from(metadata.ino())
    }

    fn at(path: &Path) -> io::Result<Self> {
        let file = Arc::new(File::open(path)?);
        let id = Self::identity(&file.metadata()?);
        // SAFETY: the ioctl takes no argument and only queries this open fd.
        let netns_type = unsafe { nix::libc::ioctl(file.as_raw_fd(), nix::libc::NS_GET_NSTYPE) };
        if netns_type < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(nix::libc::ENOTTY) {
                return Err(error);
            }
            // NS_GET_NSTYPE was added in Linux 4.11. The current network
            // namespace is already known without requiring CAP_SYS_ADMIN.
            if id != Self::identity(&fs::metadata("/proc/thread-self/ns/net")?) {
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
        } else if netns_type != nix::libc::CLONE_NEWNET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file is not a network namespace",
            ));
        }
        Ok(Self { id, file })
    }
}

impl NetNSImpl for NetNS {
    fn id(&self) -> u128 {
        self.id
    }

    fn process() -> io::Result<Self> {
        Self::at(Path::new("/proc/self/ns/net"))
    }

    fn current() -> io::Result<Self> {
        Self::at(Path::new("/proc/thread-self/ns/net"))
    }

    fn open(name: Option<&str>) -> io::Result<Self> {
        let Some(name) = name else {
            return Self::current();
        };
        if name == super::ROOT_NETNS_NAME {
            return Self::at(Path::new("/proc/1/ns/net"));
        }
        // Names are labels under /var/run/netns, not arbitrary file paths.
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "network namespace name must be one path component",
            ));
        }
        Self::at(&Path::new("/var/run/netns").join(name))
    }

    /// Run resource creation or a query inside this namespace, restoring the
    /// calling thread before returning.
    fn run<R>(&self, operation: impl FnOnce() -> R) -> io::Result<R> {
        let current = Self::identity(&fs::metadata("/proc/thread-self/ns/net")?);
        if current == self.id {
            // Even setns to our own namespace requires privileges. Do not do it.
            return Ok(operation());
        }
        let previous = File::open("/proc/thread-self/ns/net")?;
        nix::sched::setns(self.file.as_ref(), nix::sched::CloneFlags::CLONE_NEWNET)?;
        // Keep restoration in this synchronous scope so it cannot escape the thread.
        guarded!([previous] {
            if let Err(error) = nix::sched::setns(previous, nix::sched::CloneFlags::CLONE_NEWNET) {
                // A contaminated runtime thread must never execute another task.
                tracing::error!(%error, "failed to restore network namespace; aborting");
                std::process::abort();
            }
        });
        Ok(operation())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_netns_type_and_path_names() {
        let error = NetNS::at(Path::new("/proc/thread-self/ns/mnt")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        for name in ["", ".", "..", "/tmp/test", "a/b"] {
            assert_eq!(
                NetNS::open(Some(name)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
