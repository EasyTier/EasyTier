use super::local_dns;
use super::state::mark_tun_attached;
use super::{ASYNC_RUNTIME, INSTANCE_MANAGER};
use easytier::common::global_ctx::GlobalCtxEvent;
use easytier::instance::factory::subscribe_native_instance_event;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

static ACTIVE_VIRTUAL_TUN_FD: AtomicI32 = AtomicI32::new(-1);
static POLICY_REVISION: AtomicU64 = AtomicU64::new(1);
static TOPOLOGY_REVISION: AtomicU64 = AtomicU64::new(1);

pub fn set_virtual_tun_fd(fd: i32) {
    ACTIVE_VIRTUAL_TUN_FD.store(fd, Ordering::Release);
    bump_policy_revision();
}

pub fn get_virtual_tun_fd() -> i32 {
    ACTIVE_VIRTUAL_TUN_FD.load(Ordering::Acquire)
}

pub fn clear_virtual_tun_fd() {
    ACTIVE_VIRTUAL_TUN_FD.store(-1, Ordering::Release);
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

fn attach_active_tun_fd(instance_id: Uuid) -> bool {
    let fd = get_virtual_tun_fd();
    if fd <= 0 {
        return false;
    }
    match INSTANCE_MANAGER.attach_tun_fd(instance_id, fd) {
        Ok(_) => {
            mark_tun_attached(&instance_id.to_string());
            true
        }
        Err(_) => false,
    }
}

/// Event-driven watcher that replaces the legacy 250ms Unix-socket polling thread.
/// Automatically attaches (and re-attaches after DHCP IP assignment) the active
/// ProxyHub virtual TUN fd, refreshes the local authoritative MagicDNS/custom-DNS
/// catalog in-memory, and bumps atomic policy/topology revisions only when real
/// network events fire (0 background wakeups when idle).
pub fn spawn_instance_watcher(instance_id: Uuid, tun_enabled: bool) {
    let Some(instance) = INSTANCE_MANAGER.instance(instance_id) else {
        return;
    };
    let Some(mut receiver) = subscribe_native_instance_event(&instance) else {
        return;
    };
    if tun_enabled {
        let _ = attach_active_tun_fd(instance_id);
    }
    bump_policy_revision();

    ASYNC_RUNTIME.spawn(async move {
        if local_dns::refresh_all_async().await {
            bump_policy_revision();
        }
        loop {
            match receiver.recv().await {
                Ok(event) => match event {
                    GlobalCtxEvent::DhcpIpv4Changed(_, Some(_)) => {
                        if tun_enabled {
                            let _ = attach_active_tun_fd(instance_id);
                        }
                        let _ = local_dns::refresh_all_async().await;
                        bump_policy_revision();
                    }
                    GlobalCtxEvent::DhcpIpv4Changed(_, None)
                    | GlobalCtxEvent::DhcpIpv4Conflicted(_)
                    | GlobalCtxEvent::ProxyCidrsUpdated(_, _)
                    | GlobalCtxEvent::PublicIpv6RoutesUpdated(_, _)
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
                    if tun_enabled {
                        let _ = attach_active_tun_fd(instance_id);
                    }
                    let _ = local_dns::refresh_all_async().await;
                    bump_policy_revision();
                }
                Err(RecvError::Closed) => {
                    let _ = local_dns::refresh_all_async().await;
                    bump_policy_revision();
                    break;
                }
            }
        }
    });
}
