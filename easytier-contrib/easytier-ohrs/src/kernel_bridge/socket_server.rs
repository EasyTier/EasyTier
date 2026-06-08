use super::protocol::{
    TunRequestPayload, broadcast_local_socket_json_payload_message, broadcast_local_socket_message,
};
use crate::INSTANCE_MANAGER;
use crate::config::repository::kernel_socket_path;
use crate::get_runtime_snapshot_inner;
use crate::kernel_bridge::routing::aggregate_tun_routes;
use easytier::common::global_ctx::{EventBusSubscriber, GlobalCtxEvent};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

struct LocalSocketState {
    stop_flag: std::sync::Arc<AtomicBool>,
    socket_path: PathBuf,
    worker: JoinHandle<()>,
}

static LOCAL_SOCKET_STATE: Lazy<Mutex<Option<LocalSocketState>>> = Lazy::new(|| Mutex::new(None));
static SNAPSHOT_BROADCAST_ENABLED: AtomicBool = AtomicBool::new(true);
const SOCKET_TICK_INTERVAL: Duration = Duration::from_millis(250);
const TUN_FAST_CHECK_WINDOW: Duration = Duration::from_secs(8);
const EVENT_RECEIVER_SYNC_INTERVAL: Duration = Duration::from_secs(1);

pub fn set_snapshot_broadcast_enabled(enabled: bool) {
    SNAPSHOT_BROADCAST_ENABLED.store(enabled, Ordering::Relaxed);
}

fn sync_tun_event_receivers(receivers: &mut HashMap<String, EventBusSubscriber>) {
    let mut active_instance_ids = HashSet::new();
    for instance in INSTANCE_MANAGER.iter() {
        let instance_id = instance.key().to_string();
        active_instance_ids.insert(instance_id.clone());
        if !receivers.contains_key(&instance_id)
            && let Some(receiver) = instance.value().subscribe_event()
        {
            receivers.insert(instance_id, receiver);
        }
    }
    receivers.retain(|instance_id, _| active_instance_ids.contains(instance_id));
}

fn event_needs_tun_refresh(event: &GlobalCtxEvent) -> bool {
    matches!(
        event,
        GlobalCtxEvent::DhcpIpv4Changed(_, _)
            | GlobalCtxEvent::DhcpIpv4Conflicted(_)
            | GlobalCtxEvent::PublicIpv6Changed(_, _)
            | GlobalCtxEvent::PublicIpv6RoutesUpdated(_, _)
            | GlobalCtxEvent::ProxyCidrsUpdated(_, _)
            | GlobalCtxEvent::ConfigPatched(_)
            | GlobalCtxEvent::PeerAdded(_)
            | GlobalCtxEvent::PeerRemoved(_)
            | GlobalCtxEvent::PeerConnAdded(_)
            | GlobalCtxEvent::PeerConnRemoved(_)
    )
}

fn drain_tun_refresh_events(receivers: &mut HashMap<String, EventBusSubscriber>) -> bool {
    let mut refresh_needed = false;
    let mut closed_receivers = Vec::new();
    for (instance_id, receiver) in receivers.iter_mut() {
        loop {
            match receiver.try_recv() {
                Ok(event) => {
                    refresh_needed = event_needs_tun_refresh(&event) || refresh_needed;
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                    refresh_needed = true;
                    continue;
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    closed_receivers.push(instance_id.clone());
                    break;
                }
            }
        }
    }
    for instance_id in closed_receivers {
        receivers.remove(&instance_id);
    }
    refresh_needed
}

pub fn start_local_socket_server() -> bool {
    let socket_path = match kernel_socket_path() {
        Some(path) => path,
        None => {
            ohrs_log_error!("[Rust] kernel socket path unavailable");
            return false;
        }
    };

    match LOCAL_SOCKET_STATE.lock() {
        Ok(guard) if guard.is_some() => return true,
        Ok(_) => {}
        Err(err) => {
            ohrs_log_error!("[Rust] lock localsocket state failed: {}", err);
            return false;
        }
    }

    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            ohrs_log_error!(
                "[Rust] bind localsocket failed {}: {}",
                socket_path.display(),
                err
            );
            return false;
        }
    };
    if let Err(err) = listener.set_nonblocking(true) {
        ohrs_log_error!("[Rust] set localsocket nonblocking failed: {}", err);
        let _ = std::fs::remove_file(&socket_path);
        return false;
    }

    let stop_flag = std::sync::Arc::new(AtomicBool::new(false));
    let worker_stop_flag = stop_flag.clone();
    let worker = thread::spawn(move || {
        let mut last_snapshot_json = String::new();
        let mut delivered_tun_requests = HashSet::new();
        let mut last_tun_route_signatures = HashMap::<String, String>::new();
        let mut tun_fast_until = Instant::now() + TUN_FAST_CHECK_WINDOW;
        let mut tun_bootstrap_done = false;
        let mut last_event_receiver_sync_at: Option<Instant> = None;
        let mut tun_event_receivers = HashMap::<String, EventBusSubscriber>::new();
        let mut clients = Vec::<UnixStream>::new();

        while !worker_stop_flag.load(Ordering::Relaxed) {
            let mut accepted_client = false;
            loop {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        accepted_client = true;
                        clients.push(stream);
                        tun_fast_until = Instant::now() + TUN_FAST_CHECK_WINDOW;
                        tun_bootstrap_done = false;
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                    Err(err) => {
                        ohrs_log_error!("[Rust] accept localsocket failed: {}", err);
                        break;
                    }
                }
            }

            let snapshot_enabled = SNAPSHOT_BROADCAST_ENABLED.load(Ordering::Relaxed);
            if clients.is_empty() {
                if !last_snapshot_json.is_empty() {
                    last_snapshot_json.clear();
                }
                delivered_tun_requests.clear();
                last_tun_route_signatures.clear();
                tun_event_receivers.clear();
                last_event_receiver_sync_at = None;
                tun_bootstrap_done = false;
                thread::sleep(SOCKET_TICK_INTERVAL);
                continue;
            }

            let now = Instant::now();
            let should_sync_event_receivers = accepted_client
                || last_event_receiver_sync_at
                    .map(|last| now.duration_since(last) >= EVENT_RECEIVER_SYNC_INTERVAL)
                    .unwrap_or(true);
            if should_sync_event_receivers {
                sync_tun_event_receivers(&mut tun_event_receivers);
                last_event_receiver_sync_at = Some(now);
            }
            if drain_tun_refresh_events(&mut tun_event_receivers) {
                tun_bootstrap_done = false;
                tun_fast_until = now + TUN_FAST_CHECK_WINDOW;
            }
            let should_collect_snapshot = snapshot_enabled
                || accepted_client
                || (!tun_bootstrap_done && now < tun_fast_until);
            if !should_collect_snapshot {
                if !last_snapshot_json.is_empty() {
                    last_snapshot_json.clear();
                }
                thread::sleep(SOCKET_TICK_INTERVAL);
                continue;
            }

            let snapshot = get_runtime_snapshot_inner();
            if snapshot_enabled {
                let snapshot_json = match serde_json::to_string(&snapshot) {
                    Ok(json) => json,
                    Err(err) => {
                        ohrs_log_error!("[Rust] serialize runtime snapshot failed: {}", err);
                        thread::sleep(SOCKET_TICK_INTERVAL);
                        continue;
                    }
                };

                if accepted_client || snapshot_json != last_snapshot_json {
                    let _ = broadcast_local_socket_json_payload_message(
                        &mut clients,
                        "runtime_snapshot",
                        &snapshot_json,
                    );
                    last_snapshot_json = snapshot_json;
                }
            } else if !last_snapshot_json.is_empty() {
                last_snapshot_json.clear();
            }

            let mut saw_running_instance = false;
            let mut saw_tun_candidate = false;
            for instance in snapshot.instances.iter() {
                if instance.running {
                    saw_running_instance = true;
                }
                if instance.running && instance.tun_required {
                    saw_tun_candidate = true;
                    let virtual_ipv4 = instance
                        .my_node_info
                        .as_ref()
                        .and_then(|info| info.virtual_ipv4.clone());
                    let virtual_ipv4_cidr = instance
                        .my_node_info
                        .as_ref()
                        .and_then(|info| info.virtual_ipv4_cidr.clone());
                    if clients.is_empty() {
                        continue;
                    }
                    if virtual_ipv4.is_none() || virtual_ipv4_cidr.is_none() {
                        continue;
                    }
                    let aggregated_routes = aggregate_tun_routes(instance);
                    let route_signature = serde_json::to_string(&(
                        &virtual_ipv4,
                        &virtual_ipv4_cidr,
                        &aggregated_routes,
                        instance.magic_dns_enabled,
                        instance.need_exit_node,
                    ))
                    .unwrap_or_else(|_| "[]".to_string());
                    let should_send = accepted_client
                        || !delivered_tun_requests.contains(&instance.instance_id)
                        || last_tun_route_signatures
                            .get(&instance.instance_id)
                            .map(|value| value != &route_signature)
                            .unwrap_or(true);
                    if !should_send {
                        continue;
                    }
                    let payload = TunRequestPayload {
                        config_id: instance.config_id.clone(),
                        instance_id: instance.instance_id.clone(),
                        display_name: instance.display_name.clone(),
                        virtual_ipv4,
                        virtual_ipv4_cidr,
                        aggregated_routes,
                        magic_dns_enabled: instance.magic_dns_enabled,
                        need_exit_node: instance.need_exit_node,
                    };
                    let payload_json = match serde_json::to_string(&payload) {
                        Ok(json) => json,
                        Err(err) => {
                            ohrs_log_error!("[Rust] serialize tun request failed: {}", err);
                            continue;
                        }
                    };
                    if broadcast_local_socket_message(&mut clients, "tun_request", &payload_json) {
                        delivered_tun_requests.insert(instance.instance_id.clone());
                        last_tun_route_signatures
                            .insert(instance.instance_id.clone(), route_signature);
                    }
                } else {
                    delivered_tun_requests.remove(&instance.instance_id);
                    last_tun_route_signatures.remove(&instance.instance_id);
                }
            }
            if !snapshot_enabled
                && (!delivered_tun_requests.is_empty()
                    || (saw_running_instance && !saw_tun_candidate)
                    || now >= tun_fast_until)
            {
                tun_bootstrap_done = true;
            }

            thread::sleep(SOCKET_TICK_INTERVAL);
        }
    });

    match LOCAL_SOCKET_STATE.lock() {
        Ok(mut guard) => {
            *guard = Some(LocalSocketState {
                stop_flag,
                socket_path,
                worker,
            });
            true
        }
        Err(err) => {
            ohrs_log_error!("[Rust] lock localsocket state failed: {}", err);
            false
        }
    }
}

pub fn stop_local_socket_server() -> bool {
    let state = match LOCAL_SOCKET_STATE.lock() {
        Ok(mut guard) => guard.take(),
        Err(err) => {
            ohrs_log_error!("[Rust] lock localsocket state failed: {}", err);
            return false;
        }
    };

    if let Some(state) = state {
        state.stop_flag.store(true, Ordering::Relaxed);
        let _ = state.worker.join();
        let _ = std::fs::remove_file(state.socket_path);
    }
    true
}
