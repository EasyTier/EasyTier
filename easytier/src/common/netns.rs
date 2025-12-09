use futures::Future;

#[cfg(target_os = "linux")]
use nix::sched::{setns, CloneFlags};
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
        let old_ns = if ns.is_some() {
            let old_ns = if cfg!(target_os = "linux") {
                Some(std::fs::File::open("/proc/self/ns/net").unwrap())
            } else {
                None
            };
            Self::switch_ns(ns);
            old_ns
        } else {
            None
        };
        Box::new(NetNSGuard { old_ns })
    }

    fn switch_ns(name: Option<String>) {
        if name.is_none() {
            return;
        }

        let name = name.unwrap();
        let ns_path: String = if name == ROOT_NETNS_NAME {
            "/proc/1/ns/net".to_string()
        } else {
            format!("/var/run/netns/{}", name)
        };

        let ns = std::fs::File::open(ns_path).unwrap();
        tracing::info!(
            "[INIT NS] switching to new ns_name: {:?}, ns_file: {:?}",
            name,
            ns
        );

        setns(ns.as_fd(), CloneFlags::CLONE_NEWNET).unwrap();
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetNSGuard {
    fn drop(&mut self) {
        if self.old_ns.is_none() {
            return;
        }
        tracing::info!("[INIT NS] switching back to old ns, ns: {:?}", self.old_ns);
        setns(
            self.old_ns.as_ref().unwrap().as_fd(),
            CloneFlags::CLONE_NEWNET,
        )
        .unwrap();
    }
}

#[cfg(not(target_os = "linux"))]
impl NetNSGuard {
    pub fn new(_ns: Option<String>) -> Box<Self> {
        Box::new(NetNSGuard {})
    }
}

#[derive(Clone, Debug)]
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
