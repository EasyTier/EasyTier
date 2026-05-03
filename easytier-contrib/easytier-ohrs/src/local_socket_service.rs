use crate::config_repo::kernel_socket_path;
use crate::get_runtime_snapshot_inner;
use crate::stored_config::LocalSocketSyncMessage;
use ohos_hilog_binding::hilog_error;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{Error, ErrorKind, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TunRequestPayload {
    config_id: String,
    instance_id: String,
    display_name: String,
    virtual_ipv4: Option<String>,
    virtual_ipv4_cidr: Option<String>,
    aggregated_routes: Vec<String>,
    magic_dns_enabled: bool,
    need_exit_node: bool,
}

struct LocalSocketState {
    stop_flag: std::sync::Arc<AtomicBool>,
    socket_path: PathBuf,
    worker: JoinHandle<()>,
}

static LOCAL_SOCKET_STATE: Lazy<Mutex<Option<LocalSocketState>>> = Lazy::new(|| Mutex::new(None));

fn send_message(
    stream: &mut UnixStream,
    message_type: &str,
    payload_json: String,
) -> std::io::Result<()> {
    let message = LocalSocketSyncMessage {
        message_type: message_type.to_string(),
        payload_json,
    };
    let mut raw = serde_json::to_vec(&message)
        .map_err(|err| Error::new(ErrorKind::InvalidData, err.to_string()))?;
    raw.push(b'\n');
    stream.write_all(&raw)?;
    Ok(())
}

fn broadcast_message(
    clients: &mut Vec<UnixStream>,
    message_type: &str,
    payload_json: &str,
) -> bool {
    let mut active_clients = Vec::with_capacity(clients.len());
    let mut delivered = false;
    for mut client in clients.drain(..) {
        if send_message(&mut client, message_type, payload_json.to_string()).is_ok() {
            delivered = true;
            active_clients.push(client);
        }
    }
    *clients = active_clients;
    delivered
}

pub fn start_local_socket_server() -> bool {
    let socket_path = match kernel_socket_path() {
        Some(path) => path,
        None => {
            hilog_error!("[Rust] kernel socket path unavailable");
            return false;
        }
    };

    match LOCAL_SOCKET_STATE.lock() {
        Ok(guard) if guard.is_some() => return true,
        Ok(_) => {}
        Err(err) => {
            hilog_error!("[Rust] lock localsocket state failed: {}", err);
            return false;
        }
    }

    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            hilog_error!("[Rust] bind localsocket failed {}: {}", socket_path.display(), err);
            return false;
        }
    };
    if let Err(err) = listener.set_nonblocking(true) {
        hilog_error!("[Rust] set localsocket nonblocking failed: {}", err);
        let _ = std::fs::remove_file(&socket_path);
        return false;
    }

    let stop_flag = std::sync::Arc::new(AtomicBool::new(false));
    let worker_stop_flag = stop_flag.clone();
    let worker = thread::spawn(move || {
        let mut last_snapshot_json = String::new();
        let mut delivered_tun_requests = HashSet::new();
        let mut clients = Vec::<UnixStream>::new();

        while !worker_stop_flag.load(Ordering::Relaxed) {
            let mut accepted_client = false;
            loop {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        accepted_client = true;
                        clients.push(stream);
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                    Err(err) => {
                        hilog_error!("[Rust] accept localsocket failed: {}", err);
                        break;
                    }
                }
            }

            let snapshot = get_runtime_snapshot_inner();
            let snapshot_json = match serde_json::to_string(&snapshot) {
                Ok(json) => json,
                Err(err) => {
                    hilog_error!("[Rust] serialize runtime snapshot failed: {}", err);
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }
            };

            if accepted_client || snapshot_json != last_snapshot_json {
                let _ = broadcast_message(&mut clients, "runtime_snapshot", &snapshot_json);
                last_snapshot_json = snapshot_json;
            }

            for instance in snapshot.instances.iter() {
                if instance.running && instance.tun_required && !instance.tun_attached {
                    let virtual_ipv4 = instance
                        .my_node_info
                        .as_ref()
                        .and_then(|info| info.virtual_ipv4.clone());
                    let virtual_ipv4_cidr = instance
                        .my_node_info
                        .as_ref()
                        .and_then(|info| info.virtual_ipv4_cidr.clone());
                    if delivered_tun_requests.contains(&instance.instance_id) {
                        continue;
                    }
                    if clients.is_empty() {
                        continue;
                    }
                    if virtual_ipv4.is_none() || virtual_ipv4_cidr.is_none() {
                        continue;
                    }
                    let payload = TunRequestPayload {
                        config_id: instance.config_id.clone(),
                        instance_id: instance.instance_id.clone(),
                        display_name: instance.display_name.clone(),
                        virtual_ipv4,
                        virtual_ipv4_cidr,
                        aggregated_routes: snapshot.tun.aggregated_routes.clone(),
                        magic_dns_enabled: instance.magic_dns_enabled,
                        need_exit_node: instance.need_exit_node,
                    };
                    let payload_json = match serde_json::to_string(&payload) {
                        Ok(json) => json,
                        Err(err) => {
                            hilog_error!("[Rust] serialize tun request failed: {}", err);
                            continue;
                        }
                    };
                    if broadcast_message(&mut clients, "tun_request", &payload_json) {
                        delivered_tun_requests.insert(instance.instance_id.clone());
                    }
                } else {
                    delivered_tun_requests.remove(&instance.instance_id);
                }
            }

            thread::sleep(Duration::from_millis(250));
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
            hilog_error!("[Rust] lock localsocket state failed: {}", err);
            false
        }
    }
}

pub fn stop_local_socket_server() -> bool {
    let state = match LOCAL_SOCKET_STATE.lock() {
        Ok(mut guard) => guard.take(),
        Err(err) => {
            hilog_error!("[Rust] lock localsocket state failed: {}", err);
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
