use crate::config::repository::{clear_runtime_config_snapshot, get_runtime_config_snapshot};
use crate::config::types::stored_config::KeyValuePair;
use crate::kernel_bridge::{
    aggregate_requested_tun_routes, start_local_socket_server as start_local_socket_server_inner,
    stop_local_socket_server as stop_local_socket_server_inner,
};
use crate::runtime::state::runtime_state::{
    RuntimeAggregateState, RuntimeInstanceState, TunAggregateState, clear_tun_attached,
    is_tun_attached, mark_tun_attached, runtime_instance_from_config_snapshot,
    runtime_instance_from_running_info,
};
use crate::{ASYNC_RUNTIME, INSTANCE_MANAGER, WEB_CLIENTS};

pub(crate) fn start_kernel(
    config_id: String,
    start_kernel_with_config_id: impl Fn(&str) -> bool,
) -> bool {
    start_kernel_with_config_id(&config_id)
}

pub(crate) fn stop_kernel(
    config_id: String,
    stop_web_client: impl Fn(&str) -> bool,
    parse_instance_uuid: impl Fn(&str) -> Option<uuid::Uuid>,
    maybe_stop_local_socket_server: impl Fn(),
) -> bool {
    clear_tun_attached(&config_id);
    if stop_web_client(&config_id) {
        clear_runtime_config_snapshot(&config_id);
        return true;
    }

    let _ = stop_local_socket_server_inner();

    let Some(instance_id) = parse_instance_uuid(&config_id) else {
        return false;
    };

    let ret = INSTANCE_MANAGER
        .delete_network_instance(vec![instance_id])
        .map(|_| true)
        .unwrap_or_else(|err| {
            ohrs_log_error!("[Rust] stop_kernel failed {}: {}", config_id, err);
            false
        });
    if ret {
        clear_runtime_config_snapshot(&config_id);
    }
    let has_active_instances = !INSTANCE_MANAGER.list_network_instance_ids().is_empty();
    let has_web_clients = WEB_CLIENTS
        .lock()
        .map(|guard| !guard.is_empty())
        .unwrap_or(false);
    if has_active_instances || has_web_clients {
        let _ = start_local_socket_server_inner();
    }
    maybe_stop_local_socket_server();
    ret
}

pub(crate) fn stop_network_instance(
    config_ids: Vec<String>,
    stop_kernel: impl Fn(String) -> bool,
) -> bool {
    let mut ok = true;
    for config_id in config_ids {
        ok = stop_kernel(config_id) && ok;
    }
    ok
}

pub(crate) fn collect_network_infos() -> Vec<KeyValuePair> {
    let infos = match ASYNC_RUNTIME.block_on(INSTANCE_MANAGER.collect_network_infos()) {
        Ok(infos) => infos,
        Err(err) => {
            ohrs_log_error!("[Rust] collect network infos failed {}", err);
            return vec![];
        }
    };

    infos
        .into_iter()
        .filter_map(|(key, value)| {
            serde_json::to_string(&value)
                .ok()
                .map(|value_json| KeyValuePair {
                    key: key.to_string(),
                    value: value_json,
                })
        })
        .collect()
}

pub(crate) fn set_tun_fd(
    config_id: String,
    fd: i32,
    parse_instance_uuid: impl Fn(&str) -> Option<uuid::Uuid>,
) -> bool {
    let Some(instance_id) = parse_instance_uuid(&config_id) else {
        ohrs_log_error!("[Rust] set_tun_fd invalid instance id: {}", config_id);
        return false;
    };

    INSTANCE_MANAGER
        .set_tun_fd(&instance_id, fd)
        .map(|_| {
            mark_tun_attached(&config_id);
            ohrs_log_info!(
                "[Rust] set_tun_fd success instance={} fd={} marked_attached=true",
                config_id,
                fd
            );
            true
        })
        .unwrap_or_else(|err| {
            ohrs_log_error!("[Rust] set_tun_fd failed {}: {}", config_id, err);
            false
        })
}

pub(crate) fn collect_runtime_state() -> RuntimeAggregateState {
    let infos = match ASYNC_RUNTIME.block_on(INSTANCE_MANAGER.collect_network_infos()) {
        Ok(infos) => infos,
        Err(err) => {
            ohrs_log_error!("[Rust] collect network infos failed {}", err);
            return RuntimeAggregateState {
                instances: vec![],
                tun: TunAggregateState {
                    active: false,
                    attached_instance_ids: vec![],
                    aggregated_routes: vec![],
                    dns_servers: vec![],
                    need_rebuild: false,
                },
                running_instance_count: 0,
            };
        }
    };
    let mut live_infos = infos
        .into_iter()
        .map(|(instance_id, info)| (instance_id.to_string(), info))
        .collect::<std::collections::HashMap<_, _>>();
    let mut active_config_ids = live_infos.keys().cloned().collect::<Vec<_>>();
    if let Ok(guard) = WEB_CLIENTS.lock() {
        for config_id in guard.keys() {
            if !active_config_ids.iter().any(|value| value == config_id) {
                active_config_ids.push(config_id.clone());
            }
        }
    }

    let mut instances = Vec::with_capacity(active_config_ids.len());
    for config_id in active_config_ids {
        if let Some(info) = live_infos.remove(&config_id) {
            let snapshot = get_runtime_config_snapshot(&config_id);
            let display_name = snapshot
                .as_ref()
                .map(|snapshot| snapshot.display_name.clone())
                .unwrap_or_else(|| config_id.clone());
            let magic_dns_enabled = snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.config.enable_magic_dns)
                .unwrap_or(false);
            let need_exit_node = snapshot
                .as_ref()
                .map(|snapshot| !snapshot.config.exit_nodes.is_empty())
                .unwrap_or(false);
            instances.push(runtime_instance_from_running_info(
                config_id,
                display_name,
                magic_dns_enabled,
                need_exit_node,
                info,
            ));
        } else if let Some(snapshot) = get_runtime_config_snapshot(&config_id) {
            instances.push(runtime_instance_from_config_snapshot(
                config_id,
                snapshot.display_name,
                snapshot.config,
                true,
            ));
        } else {
            let tun_attached = is_tun_attached(&config_id);
            instances.push(RuntimeInstanceState {
                config_id: config_id.clone(),
                instance_id: config_id.clone(),
                display_name: config_id.clone(),
                running: true,
                tun_required: tun_attached,
                tun_attached,
                magic_dns_enabled: false,
                need_exit_node: false,
                error_message: None,
                my_node_info: None,
                events: Vec::new(),
                routes: Vec::new(),
                peers: Vec::new(),
            });
        }
    }

    instances.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.instance_id.cmp(&b.instance_id))
    });
    let attached_instance_ids = instances
        .iter()
        .filter(|instance| instance.tun_required)
        .map(|instance| instance.instance_id.clone())
        .collect::<Vec<_>>();
    let aggregated_routes = aggregate_requested_tun_routes(&instances);
    let running_instance_count =
        instances.iter().filter(|instance| instance.running).count() as i32;
    let tun_active = !attached_instance_ids.is_empty();

    RuntimeAggregateState {
        instances,
        tun: TunAggregateState {
            active: tun_active,
            attached_instance_ids,
            aggregated_routes,
            dns_servers: vec![],
            need_rebuild: false,
        },
        running_instance_count,
    }
}
