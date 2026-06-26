use super::protocol::{
    TunRequestPayload, broadcast_local_socket_json_payload_message, broadcast_local_socket_message,
};
use crate::collect_runtime_state_inner;
use crate::config::repository::kernel_socket_path;
use crate::kernel_bridge::routing::aggregate_tun_routes;
use crate::runtime::state::runtime_state::{
    PeerConnInfo as RuntimePeerConnInfo, RuntimeAggregateState, peer_conn_to_view,
};
use crate::{ASYNC_RUNTIME, INSTANCE_MANAGER};
use easytier::common::global_ctx::{EventBusSubscriber, GlobalCtxEvent};
use easytier::proto::api::instance::ListPeerRequest;
use easytier::proto::rpc_types::controller::BaseController;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
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
const SOCKET_TICK_INTERVAL: Duration = Duration::from_millis(250);
const TRAFFIC_STATS_INTERVAL: Duration = Duration::from_secs(1);
const INSTANCE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const TUN_FAST_CHECK_WINDOW: Duration = Duration::from_secs(8);
const EVENT_RECEIVER_SYNC_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrafficStatsPayload {
    instances: Vec<InstanceTrafficStats>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstanceTrafficStats {
    config_id: String,
    instance_id: String,
    rx_bytes: i64,
    tx_bytes: i64,
    peers: Vec<PeerTrafficStats>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerTrafficStats {
    peer_id: i64,
    rx_bytes: i64,
    tx_bytes: i64,
    total_bytes: i64,
    latency_us: i64,
    loss_rate: f64,
}

struct PendingPeerEvent {
    event: &'static str,
    instance_id: String,
    peer_id: i64,
    conn: Option<RuntimePeerConnInfo>,
}

#[derive(Default)]
struct DrainedKernelEvents {
    tun_refresh: bool,
    topology_lost: bool,
    peer_events: Vec<PendingPeerEvent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimePeerEventPayload {
    event: &'static str,
    config_id: String,
    instance_id: String,
    peer_id: i64,
    conn: Option<RuntimePeerConnInfo>,
}

fn shrink_hash_map_if_sparse<K: Eq + Hash, V>(map: &mut HashMap<K, V>) {
    let sparse_limit = map.len().saturating_mul(2).max(8);
    if map.capacity() > sparse_limit {
        map.shrink_to_fit();
    }
}

fn shrink_hash_set_if_sparse<T: Eq + Hash>(set: &mut HashSet<T>) {
    let sparse_limit = set.len().saturating_mul(2).max(8);
    if set.capacity() > sparse_limit {
        set.shrink_to_fit();
    }
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
    shrink_hash_map_if_sparse(receivers);
}

fn event_needs_tun_refresh(event: &GlobalCtxEvent) -> bool {
    matches!(
        event,
        GlobalCtxEvent::DhcpIpv4Changed(_, _)
            | GlobalCtxEvent::ProxyCidrsUpdated(_, _)
            | GlobalCtxEvent::PublicIpv6RoutesUpdated(_, _)
    )
}

fn drain_kernel_events(receivers: &mut HashMap<String, EventBusSubscriber>) -> DrainedKernelEvents {
    let mut drained = DrainedKernelEvents::default();
    let mut closed_receivers = Vec::new();
    for (instance_id, receiver) in receivers.iter_mut() {
        loop {
            match receiver.try_recv() {
                Ok(event) => {
                    drained.tun_refresh = event_needs_tun_refresh(&event) || drained.tun_refresh;
                    match event {
                        GlobalCtxEvent::PeerAdded(peer_id) => {
                            drained.peer_events.push(PendingPeerEvent {
                                event: "peer_added",
                                instance_id: instance_id.clone(),
                                peer_id: peer_id as i64,
                                conn: None,
                            });
                        }
                        GlobalCtxEvent::PeerRemoved(peer_id) => {
                            drained.peer_events.push(PendingPeerEvent {
                                event: "peer_removed",
                                instance_id: instance_id.clone(),
                                peer_id: peer_id as i64,
                                conn: None,
                            });
                        }
                        GlobalCtxEvent::PeerConnAdded(conn_info) => {
                            let peer_id = conn_info.peer_id as i64;
                            drained.peer_events.push(PendingPeerEvent {
                                event: "peer_conn_added",
                                instance_id: instance_id.clone(),
                                peer_id,
                                conn: Some(peer_conn_to_view(conn_info)),
                            });
                        }
                        GlobalCtxEvent::PeerConnRemoved(conn_info) => {
                            let peer_id = conn_info.peer_id as i64;
                            drained.peer_events.push(PendingPeerEvent {
                                event: "peer_conn_removed",
                                instance_id: instance_id.clone(),
                                peer_id,
                                conn: Some(peer_conn_to_view(conn_info)),
                            });
                        }
                        _ => {}
                    }
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                    drained.topology_lost = true;
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
    drained
}

fn broadcast_runtime_peer_events(
    clients: &mut Vec<UnixStream>,
    peer_events: Vec<PendingPeerEvent>,
) {
    for event in peer_events {
        let payload = RuntimePeerEventPayload {
            event: event.event,
            config_id: event.instance_id.clone(),
            instance_id: event.instance_id,
            peer_id: event.peer_id,
            conn: event.conn,
        };
        match serde_json::to_string(&payload) {
            Ok(json) => {
                let _ = broadcast_local_socket_json_payload_message(
                    clients,
                    "runtime_peer_event",
                    &json,
                );
            }
            Err(err) => {
                ohrs_log_error!("[Rust] serialize runtime peer event failed: {}", err);
            }
        }
    }
}

fn tun_candidate_ids(snapshot: &RuntimeAggregateState) -> HashSet<String> {
    snapshot
        .instances
        .iter()
        .filter(|instance| instance.running && instance.tun_required)
        .map(|instance| instance.instance_id.clone())
        .collect()
}

fn collect_traffic_stats() -> TrafficStatsPayload {
    let services = INSTANCE_MANAGER
        .iter()
        .filter_map(|instance| {
            instance
                .value()
                .get_api_service()
                .map(|api_service| (instance.key().to_string(), api_service))
        })
        .collect::<Vec<_>>();

    let instances = ASYNC_RUNTIME.block_on(async {
        let mut instances = Vec::new();
        for (instance_id, api_service) in services {
            let peers = match api_service
                .get_peer_manage_service()
                .list_peer(BaseController::default(), ListPeerRequest::default())
                .await
            {
                Ok(response) => response.peer_infos,
                Err(err) => {
                    ohrs_log_debug!(
                        "[Rust] collect traffic stats list_peer failed instance={}: {}",
                        instance_id,
                        err
                    );
                    continue;
                }
            };

            let mut instance_rx_bytes = 0i64;
            let mut instance_tx_bytes = 0i64;
            let mut peer_stats = Vec::with_capacity(peers.len());

            for peer in peers {
                let mut peer_rx_bytes = 0i64;
                let mut peer_tx_bytes = 0i64;
                let mut latency_us = i64::MAX;
                let mut loss_rate = 0f64;

                for conn in peer.conns {
                    if let Some(stats) = conn.stats {
                        let rx_bytes = stats.rx_bytes as i64;
                        let tx_bytes = stats.tx_bytes as i64;
                        peer_rx_bytes += rx_bytes;
                        peer_tx_bytes += tx_bytes;
                        latency_us = latency_us.min(stats.latency_us as i64);
                    }
                    loss_rate = loss_rate.max(conn.loss_rate as f64);
                }

                instance_rx_bytes += peer_rx_bytes;
                instance_tx_bytes += peer_tx_bytes;
                peer_stats.push(PeerTrafficStats {
                    peer_id: peer.peer_id as i64,
                    rx_bytes: peer_rx_bytes,
                    tx_bytes: peer_tx_bytes,
                    total_bytes: peer_rx_bytes + peer_tx_bytes,
                    latency_us: if latency_us == i64::MAX {
                        -1
                    } else {
                        latency_us
                    },
                    loss_rate,
                });
            }

            instances.push(InstanceTrafficStats {
                config_id: instance_id.clone(),
                instance_id,
                rx_bytes: instance_rx_bytes,
                tx_bytes: instance_tx_bytes,
                peers: peer_stats,
            });
        }
        instances
    });

    TrafficStatsPayload { instances }
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
        let mut last_topology_json = String::new();
        let mut delivered_tun_requests = HashSet::new();
        let mut last_tun_route_signatures = HashMap::<String, String>::new();
        let mut tun_fast_until = Instant::now() + TUN_FAST_CHECK_WINDOW;
        let mut tun_bootstrap_done = false;
        let mut last_event_receiver_sync_at: Option<Instant> = None;
        let mut last_traffic_stats_at: Option<Instant> = None;
        let mut last_instance_poll_at: Option<Instant> = None;
        let mut tun_event_receivers = HashMap::<String, EventBusSubscriber>::new();
        let mut clients = Vec::<UnixStream>::new();

        while !worker_stop_flag.load(Ordering::Relaxed) {
            let mut full_topology_dirty = false;
            let mut accepted_client = false;
            loop {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        accepted_client = true;
                        full_topology_dirty = true;
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

            if clients.is_empty() {
                if !last_topology_json.is_empty() {
                    last_topology_json.clear();
                    last_topology_json.shrink_to_fit();
                }
                delivered_tun_requests.clear();
                shrink_hash_set_if_sparse(&mut delivered_tun_requests);
                last_tun_route_signatures.clear();
                shrink_hash_map_if_sparse(&mut last_tun_route_signatures);
                tun_event_receivers.clear();
                shrink_hash_map_if_sparse(&mut tun_event_receivers);
                clients.shrink_to_fit();
                last_event_receiver_sync_at = None;
                last_traffic_stats_at = None;
                last_instance_poll_at = None;
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
            let drained_events = drain_kernel_events(&mut tun_event_receivers);
            let tun_refresh = drained_events.tun_refresh;
            let topology_lost = drained_events.topology_lost;
            let peer_events = drained_events.peer_events;
            if topology_lost {
                full_topology_dirty = true;
            }
            if tun_refresh {
                tun_bootstrap_done = false;
                tun_fast_until = now + TUN_FAST_CHECK_WINDOW;
            }
            if !peer_events.is_empty() {
                broadcast_runtime_peer_events(&mut clients, peer_events);
            }
            let should_collect_traffic_stats = last_traffic_stats_at
                .map(|last| now.duration_since(last) >= TRAFFIC_STATS_INTERVAL)
                .unwrap_or(true);
            if should_collect_traffic_stats {
                last_traffic_stats_at = Some(now);
                match serde_json::to_string(&collect_traffic_stats()) {
                    Ok(json) => {
                        let _ = broadcast_local_socket_json_payload_message(
                            &mut clients,
                            "traffic_stats",
                            &json,
                        );
                    }
                    Err(err) => {
                        ohrs_log_error!("[Rust] serialize traffic stats failed: {}", err);
                    }
                }
            }
            let should_poll_instance = last_instance_poll_at
                .map(|last| now.duration_since(last) >= INSTANCE_POLL_INTERVAL)
                .unwrap_or(true);
            let should_collect_topology = accepted_client
                || full_topology_dirty
                || tun_refresh
                || should_poll_instance
                || (!tun_bootstrap_done && now < tun_fast_until);
            if !should_collect_topology {
                thread::sleep(SOCKET_TICK_INTERVAL);
                continue;
            }

            let snapshot = collect_runtime_state_inner();
            last_instance_poll_at = Some(now);
            match serde_json::to_string(&snapshot) {
                Ok(json) => {
                    if accepted_client || full_topology_dirty || json != last_topology_json {
                        let _ = broadcast_local_socket_json_payload_message(
                            &mut clients,
                            "runtime_topology",
                            &json,
                        );
                        last_topology_json = json;
                    }
                }
                Err(err) => {
                    ohrs_log_error!("[Rust] serialize runtime topology failed: {}", err);
                }
            }

            let active_tun_candidate_ids = tun_candidate_ids(&snapshot);
            delivered_tun_requests
                .retain(|instance_id| active_tun_candidate_ids.contains(instance_id));
            last_tun_route_signatures
                .retain(|instance_id, _| active_tun_candidate_ids.contains(instance_id));
            shrink_hash_set_if_sparse(&mut delivered_tun_requests);
            shrink_hash_map_if_sparse(&mut last_tun_route_signatures);
            let mut saw_running_instance = false;
            let mut saw_tun_candidate = false;
            for instance in snapshot.instances.iter() {
                if instance.running {
                    saw_running_instance = true;
                }
                if !(instance.running && instance.tun_required) {
                    continue;
                }

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
                let should_send = !delivered_tun_requests.contains(&instance.instance_id)
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
                    last_tun_route_signatures.insert(instance.instance_id.clone(), route_signature);
                }
            }
            if !delivered_tun_requests.is_empty()
                || (saw_running_instance && !saw_tun_candidate)
                || now >= tun_fast_until
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
