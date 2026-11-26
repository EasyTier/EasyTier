use super::local_dns;
use super::state::clear_all_tun_attached;
#[cfg(not(target_env = "ohos"))]
use super::state::mark_tun_attached;
#[cfg(target_env = "ohos")]
use super::state::replace_tun_attached;
use super::{ASYNC_RUNTIME, INSTANCE_MANAGER};
#[cfg(not(target_env = "ohos"))]
use easytier::common::config::ConfigLoader;
use easytier::common::global_ctx::GlobalCtxEvent;
use easytier::instance::factory::subscribe_native_instance_event;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

static ACTIVE_VIRTUAL_TUN_FD: AtomicI32 = AtomicI32::new(-1);
static POLICY_REVISION: AtomicU64 = AtomicU64::new(1);
static TOPOLOGY_REVISION: AtomicU64 = AtomicU64::new(1);
static TUN_SYNC_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

pub fn set_virtual_tun_fd(fd: i32) {
    ACTIVE_VIRTUAL_TUN_FD.store(fd, Ordering::Release);
    sync_shared_tun_fd_sync();
    bump_policy_revision();
}

pub fn get_virtual_tun_fd() -> i32 {
    ACTIVE_VIRTUAL_TUN_FD.load(Ordering::Acquire)
}

pub fn clear_virtual_tun_fd() {
    ACTIVE_VIRTUAL_TUN_FD.store(-1, Ordering::Release);
    sync_shared_tun_fd_sync();
}

pub fn bump_policy_revision() {
    POLICY_REVISION.fetch_add(1, Ordering::AcqRel);
    TOPOLOGY_REVISION.fetch_add(1, Ordering::AcqRel);
}

pub fn bump_topology_revision() {
    TOPOLOGY_REVISION.fetch_add(1, Ordering::AcqRel);
}

pub fn policy_revision() -> i64 {
    POLICY_REVISION.load(Ordering::Acquire) as i64
}

pub fn topology_revision() -> i64 {
    TOPOLOGY_REVISION.load(Ordering::Acquire) as i64
}

/// Synchronizes all currently running TUN-enabled instances against the active
/// shared mobile TUN file descriptor using upstream `attach_mobile_tun_fd` on OHOS
/// (opening the shared fd once and multiplexing all disjoint instances cleanly).
pub async fn sync_shared_tun_fd_async() -> bool {
    let _guard = TUN_SYNC_LOCK.lock().await;
    let fd = get_virtual_tun_fd();
    let instance_ids = INSTANCE_MANAGER.instance_ids();
    if instance_ids.is_empty() {
        clear_all_tun_attached();
        return fd <= 0;
    }

    #[cfg(target_env = "ohos")]
    {
        match easytier::instance::factory::attach_mobile_tun_fd(
            INSTANCE_MANAGER.as_ref(),
            fd.max(0),
            None,
        )
        .await
        {
            Ok(config) => {
                if fd <= 0 {
                    clear_all_tun_attached();
                } else {
                    replace_tun_attached(config.instance_ids.iter().map(Uuid::to_string));
                }
                for rejected in &config.rejected {
                    ohrs_log_error!(
                        "[Rust] shared mobile TUN rejected instance={} err={}",
                        rejected.instance_id,
                        rejected.error
                    );
                }
                ohrs_log_info!(
                    "[Rust] shared mobile TUN synced fd={} attached={} rejected={}",
                    fd,
                    config.instance_ids.len(),
                    config.rejected.len()
                );
                true
            }
            Err(err) => {
                ohrs_log_error!("[Rust] shared mobile TUN sync failed fd={}: {:#}", fd, err);
                false
            }
        }
    }

    #[cfg(not(target_env = "ohos"))]
    {
        if fd <= 0 {
            clear_all_tun_attached();
            return true;
        }
        let mut ok = true;
        for id in instance_ids {
            let tun_enabled = INSTANCE_MANAGER
                .config(id)
                .map(|cfg| !cfg.get_flags().no_tun)
                .unwrap_or(false);
            if !tun_enabled {
                continue;
            }
            match INSTANCE_MANAGER.attach_tun_fd(id, fd) {
                Ok(_) => mark_tun_attached(&id.to_string()),
                Err(_) => ok = false,
            }
        }
        ok
    }
}

pub fn sync_shared_tun_fd_sync() -> bool {
    if tokio::runtime::Handle::try_current().is_ok() {
        ASYNC_RUNTIME.spawn(async {
            let _ = sync_shared_tun_fd_async().await;
        });
        return true;
    }
    ASYNC_RUNTIME.block_on(sync_shared_tun_fd_async())
}

/// Event-driven watcher that replaces the legacy 250ms Unix-socket polling thread.
/// Automatically attaches (and re-attaches after DHCP IP / route changes) all running
/// instances to the active shared TUN fd, refreshes the local authoritative
/// MagicDNS/custom-DNS catalog in-memory, and bumps atomic policy/topology revisions
/// only when real network events fire (0 background wakeups when idle).
pub fn spawn_instance_watcher(instance_id: Uuid, tun_enabled: bool) {
    let Some(instance) = INSTANCE_MANAGER.instance(instance_id) else {
        return;
    };
    let Some(mut receiver) = subscribe_native_instance_event(&instance) else {
        return;
    };
    bump_policy_revision();

    ASYNC_RUNTIME.spawn(async move {
        if !instance.is_ready() {
            for _ in 0..40 {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                if instance.is_ready() {
                    break;
                }
            }
        }
        if tun_enabled && get_virtual_tun_fd() > 0 {
            let _ = sync_shared_tun_fd_async().await;
        }
        let _ = local_dns::refresh_all_async().await;
        bump_policy_revision();
        loop {
            match receiver.recv().await {
                Ok(event) => match event {
                    GlobalCtxEvent::DhcpIpv4Changed(_, Some(_))
                    | GlobalCtxEvent::ProxyCidrsUpdated(_, _)
                    | GlobalCtxEvent::PublicIpv6RoutesUpdated(_, _)
                    | GlobalCtxEvent::ConfigPatched(_) => {
                        if tun_enabled && get_virtual_tun_fd() > 0 {
                            let _ = sync_shared_tun_fd_async().await;
                        }
                        let _ = local_dns::refresh_all_async().await;
                        bump_policy_revision();
                    }
                    GlobalCtxEvent::TunDeviceReady(_)
                    | GlobalCtxEvent::DhcpIpv4Changed(_, None)
                    | GlobalCtxEvent::DhcpIpv4Conflicted(_)
                    | GlobalCtxEvent::PeerAdded(_)
                    | GlobalCtxEvent::PeerRemoved(_) => {
                        let _ = local_dns::refresh_all_async().await;
                        bump_policy_revision();
                    }
                    GlobalCtxEvent::PeerConnAdded(_) | GlobalCtxEvent::PeerConnRemoved(_) => {
                        bump_topology_revision();
                    }
                    _ => {}
                },
                Err(RecvError::Lagged(_)) => {
                    if tun_enabled && get_virtual_tun_fd() > 0 {
                        let _ = sync_shared_tun_fd_async().await;
                    }
                    let _ = local_dns::refresh_all_async().await;
                    bump_policy_revision();
                }
                Err(RecvError::Closed) => {
                    if tun_enabled && get_virtual_tun_fd() > 0 {
                        let _ = sync_shared_tun_fd_async().await;
                    }
                    let _ = local_dns::refresh_all_async().await;
                    bump_policy_revision();
                    break;
                }
            }
        }
    });
}
