use crate::config::repository::load_config_json;
use crate::kernel_bridge::{aggregate_requested_tun_routes, start_local_socket_server as start_local_socket_server_inner, stop_local_socket_server as stop_local_socket_server_inner};
use crate::runtime::state::runtime_state::{RuntimeAggregateState, TunAggregateState, clear_tun_attached, mark_tun_attached, runtime_instance_from_running_info};
use crate::{ASYNC_RUNTIME, EASYTIER_VERSION, INSTANCE_MANAGER, WEB_CLIENTS};
use crate::config::storage::config_meta::get_config_display_name;
use crate::config::types::stored_config::KeyValuePair;
use easytier::proto::api::manage::NetworkConfig;
use ohos_hilog_binding::{hilog_error, hilog_info};
use std::sync::Arc;

pub(crate) fn start_kernel(config_id: String, start_kernel_with_config_id: impl Fn(&str) -> bool) -> bool {
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
        return true;
    }

    let Some(instance_id) = parse_instance_uuid(&config_id) else {
        return false;
    };

    let ret = INSTANCE_MANAGER
        .delete_network_instance(vec![instance_id])
        .map(|_| true)
        .unwrap_or_else(|err| {
            hilog_error!("[Rust] stop_kernel failed {}: {}", config_id, err);
            false
        });
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
    let infos = match INSTANCE_MANAGER.collect_network_infos_sync() {
        Ok(infos) => infos,
        Err(err) => {
            hilog_error!("[Rust] collect network infos failed {}", err);
            return vec![];
        }
    };

    infos.into_iter()
        .filter_map(|(key, value)| {
            serde_json::to_string(&value).ok().map(|value_json| KeyValuePair {
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
        hilog_error!("[Rust] set_tun_fd invalid instance id: {}", config_id);
        return false;
    };

    INSTANCE_MANAGER
        .set_tun_fd(&instance_id, fd)
        .map(|_| {
            mark_tun_attached(&config_id);
            hilog_info!("[Rust] set_tun_fd success instance={} fd={} marked_attached=true", config_id, fd);
            true
        })
        .unwrap_or_else(|err| {
            hilog_error!("[Rust] set_tun_fd failed {}: {}", config_id, err);
            false
        })
}

pub(crate) fn get_runtime_snapshot() -> RuntimeAggregateState {
    get_runtime_snapshot_inner()
}

pub(crate) fn get_runtime_snapshot_inner() -> RuntimeAggregateState {
    let infos = match INSTANCE_MANAGER.collect_network_infos_sync() {
        Ok(infos) => infos,
        Err(err) => {
            hilog_error!("[Rust] collect network infos failed {}", err);
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

    let mut instances = Vec::with_capacity(infos.len());
    for (instance_uuid, info) in infos {
        let config_id = instance_uuid.to_string();
        let display_name = get_config_display_name(&config_id).unwrap_or_else(|| config_id.clone());
        let config_json = load_config_json(&config_id);
        let stored_config = config_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<NetworkConfig>(raw).ok());
        let magic_dns_enabled = stored_config
            .as_ref()
            .and_then(|cfg| cfg.enable_magic_dns)
            .unwrap_or(false);
        let need_exit_node = stored_config
            .as_ref()
            .map(|cfg| !cfg.exit_nodes.is_empty())
            .unwrap_or(false);
        instances.push(runtime_instance_from_running_info(
            config_id,
            display_name,
            magic_dns_enabled,
            need_exit_node,
            info,
        ));
    }

    instances.sort_by(|a, b| a.display_name.cmp(&b.display_name).then_with(|| a.instance_id.cmp(&b.instance_id)));
    let attached_instance_ids = instances
        .iter()
        .filter(|instance| instance.tun_required)
        .map(|instance| instance.instance_id.clone())
        .collect::<Vec<_>>();
    let aggregated_routes = aggregate_requested_tun_routes(&instances);
    let running_instance_count = instances.iter().filter(|instance| instance.running).count() as i32;
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
