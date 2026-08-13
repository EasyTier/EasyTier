use futures::Future;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use nix::sched::{CloneFlags, setns};
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;

pub struct NetNSGuard {
    #[cfg(target_os = "linux")]
    old_ns: Option<std::fs::File>,
}

pub static ROOT_NETNS_NAME: &str = "_root_ns";

#[cfg(target_os = "linux")]
impl NetNSGuard {
    pub fn new(ns: Option<String>) -> Box<Self> {
        Self::try_new(ns).expect("failed to switch network namespace")
    }

    pub fn try_new(ns: Option<String>) -> anyhow::Result<Box<Self>> {
        let old_ns = if ns.is_some() {
            let old_ns = Some(std::fs::File::open("/proc/self/ns/net")?);
            Self::switch_ns(ns)?;
            old_ns
        } else {
            None
        };
        Ok(Box::new(NetNSGuard { old_ns }))
    }

    fn switch_ns(name: Option<String>) -> anyhow::Result<()> {
        if name.is_none() {
            return Ok(());
        }

        let name = name.unwrap();
        let ns_path = resolve_netns_path(&name)?;

        let ns = std::fs::File::open(&ns_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to open network namespace {}: {error}",
                ns_path.display()
            )
        })?;
        tracing::info!(
            "[INIT NS] switching to new ns_name: {:?}, ns_file: {:?}",
            name,
            ns
        );

        setns(ns.as_fd(), CloneFlags::CLONE_NEWNET).map_err(|error| {
            anyhow::anyhow!(
                "failed to enter network namespace {}: {error}",
                ns_path.display()
            )
        })?;
        Ok(())
    }
}

pub fn resolve_netns_path(name: &str) -> anyhow::Result<PathBuf> {
    if name == ROOT_NETNS_NAME {
        return Ok(PathBuf::from("/proc/1/ns/net"));
    }

    let path = Path::new(name);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    if path.components().count() != 1 {
        anyhow::bail!("network namespace name must be a name or an absolute path: {name}");
    }

    Ok(Path::new("/var/run/netns").join(path))
}

#[cfg(target_os = "linux")]
impl Drop for NetNSGuard {
    fn drop(&mut self) {
        if self.old_ns.is_none() {
            return;
        }
        tracing::info!("[INIT NS] switching back to old ns, ns: {:?}", self.old_ns);
        if let Err(error) = setns(
            self.old_ns.as_ref().unwrap().as_fd(),
            CloneFlags::CLONE_NEWNET,
        ) {
            tracing::error!(?error, "failed to restore network namespace");
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl NetNSGuard {
    pub fn new(_ns: Option<String>) -> Box<Self> {
        Box::new(NetNSGuard {})
    }

    pub fn try_new(_ns: Option<String>) -> anyhow::Result<Box<Self>> {
        Ok(Box::new(NetNSGuard {}))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetNS {
    name: Option<String>,
}

impl NetNS {
    pub fn new(name: Option<String>) -> Self {
        NetNS { name }
    }

    pub async fn run_async<F, Fut, Ret>(&self, f: F) -> Ret
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Ret>,
    {
        // TODO: do we really need this lock
        // let _lock = LOCK.lock().await;
        let _guard = NetNSGuard::new(self.name.clone());
        f().await
    }

    pub fn run<F, Ret>(&self, f: F) -> Ret
    where
        F: FnOnce() -> Ret,
    {
        let _guard = NetNSGuard::new(self.name.clone());
        f()
    }

    pub fn guard(&self) -> Box<NetNSGuard> {
        NetNSGuard::new(self.name.clone())
    }

    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_network_namespace_paths() {
        assert_eq!(
            resolve_netns_path(ROOT_NETNS_NAME).unwrap(),
            PathBuf::from("/proc/1/ns/net")
        );
        assert_eq!(
            resolve_netns_path("pod-a").unwrap(),
            PathBuf::from("/var/run/netns/pod-a")
        );
        assert_eq!(
            resolve_netns_path("/proc/123/ns/net").unwrap(),
            PathBuf::from("/proc/123/ns/net")
        );
        assert!(resolve_netns_path("nested/pod-a").is_err());
    }
}
