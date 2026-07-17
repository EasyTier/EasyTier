use std::ffi::{CString, c_char, c_int};

use easytier::common::config::{ConfigFileControl, ConfigLoader as _, TomlConfigLoader};

use crate::{
    config_server::{
        in_config_server_callback, remove_config_server_tracked_instance_ids,
        wait_for_config_server_delivery,
    },
    data_plane::remove_data_plane_handles_by_instance_ids,
    error::set_error_msg,
    state::{
        INSTANCE_MANAGER, INSTANCE_MUTATION_LOCK, INSTANCE_NAME_ID_MAP, instance_name_exists,
        lock_remote_instance_mutation,
    },
    types::KeyValuePair,
};

/// # Safety
/// Set the tun fd
pub(crate) unsafe fn set_tun_fd(inst_name: *const c_char, fd: c_int) -> c_int {
    let inst_name = unsafe {
        assert!(!inst_name.is_null());
        std::ffi::CStr::from_ptr(inst_name)
            .to_string_lossy()
            .into_owned()
    };
    if !INSTANCE_NAME_ID_MAP.contains_key(&inst_name) {
        return -1;
    }

    let inst_id = *INSTANCE_NAME_ID_MAP
        .get(&inst_name)
        .as_ref()
        .unwrap()
        .value();

    match INSTANCE_MANAGER.set_tun_fd(&inst_id, fd) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// # Safety
/// Parse the config
pub(crate) unsafe fn parse_config(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        std::ffi::CStr::from_ptr(cfg_str)
            .to_string_lossy()
            .into_owned()
    };

    if let Err(e) = TomlConfigLoader::new_from_str(&cfg_str) {
        set_error_msg(&format!("failed to parse config: {:?}", e));
        return -1;
    }

    0
}

/// # Safety
/// Run the network instance
pub(crate) unsafe fn run_network_instance(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot run network instance from config server callback");
        return -1;
    }

    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        std::ffi::CStr::from_ptr(cfg_str)
            .to_string_lossy()
            .into_owned()
    };
    let cfg = match TomlConfigLoader::new_from_str(&cfg_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            set_error_msg(&format!("failed to parse config: {}", e));
            return -1;
        }
    };

    let inst_name = cfg.get_inst_name();

    wait_for_config_server_delivery();
    let _remote_mutation_guard = lock_remote_instance_mutation();
    let _mutation_guard = match INSTANCE_MUTATION_LOCK.lock() {
        Ok(guard) => guard,
        Err(err) => {
            set_error_msg(&format!("failed to lock instance mutation: {}", err));
            return -1;
        }
    };

    if instance_name_exists(&inst_name) {
        set_error_msg("instance already exists");
        return -1;
    }

    let instance_id =
        match INSTANCE_MANAGER.run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG) {
            Ok(id) => id,
            Err(e) => {
                set_error_msg(&format!("failed to start instance: {}", e));
                return -1;
            }
        };

    INSTANCE_NAME_ID_MAP.insert(inst_name, instance_id);

    0
}

unsafe fn parse_instance_names(
    inst_names: *const *const c_char,
    length: usize,
) -> Option<Vec<String>> {
    if length == 0 {
        return Some(Vec::new());
    }
    if inst_names.is_null() {
        set_error_msg("inst_names is null");
        return None;
    }

    let names = unsafe { std::slice::from_raw_parts(inst_names, length) };
    let mut parsed = Vec::with_capacity(length);
    for (index, &name) in names.iter().enumerate() {
        if name.is_null() {
            set_error_msg(&format!("inst_names[{}] is null", index));
            return None;
        }
        parsed.push(
            unsafe { std::ffi::CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned(),
        );
    }
    Some(parsed)
}

/// # Safety
/// Retain the network instance
pub(crate) unsafe fn retain_network_instance(
    inst_names: *const *const std::ffi::c_char,
    length: usize,
) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot retain network instances from config server callback");
        return -1;
    }

    wait_for_config_server_delivery();
    let _remote_mutation_guard = lock_remote_instance_mutation();
    let _mutation_guard = match INSTANCE_MUTATION_LOCK.lock() {
        Ok(guard) => guard,
        Err(err) => {
            set_error_msg(&format!("failed to lock instance mutation: {}", err));
            return -1;
        }
    };

    if length == 0 {
        let removed_ids = INSTANCE_MANAGER.list_network_instance_ids();
        if let Err(e) = INSTANCE_MANAGER.delete_network_instance(removed_ids.clone()) {
            set_error_msg(&format!("failed to delete instances: {}", e));
            return -1;
        }
        remove_config_server_tracked_instance_ids(&removed_ids);
        remove_data_plane_handles_by_instance_ids(&removed_ids);
        INSTANCE_NAME_ID_MAP.clear();
        return 0;
    }

    let Some(inst_names) = (unsafe { parse_instance_names(inst_names, length) }) else {
        return -1;
    };

    let removed_ids = INSTANCE_MANAGER
        .list_network_instance_ids()
        .into_iter()
        .filter(|id| {
            INSTANCE_MANAGER
                .get_instance_name(id)
                .is_none_or(|name| !inst_names.contains(&name))
        })
        .collect::<Vec<_>>();

    if let Err(e) = INSTANCE_MANAGER.delete_network_instance(removed_ids.clone()) {
        set_error_msg(&format!("failed to delete instances: {}", e));
        return -1;
    }

    remove_config_server_tracked_instance_ids(&removed_ids);
    remove_data_plane_handles_by_instance_ids(&removed_ids);
    INSTANCE_NAME_ID_MAP.retain(|k, _| inst_names.contains(k));

    0
}

/// # Safety
/// Delete named network instances.
pub(crate) unsafe fn delete_network_instance(
    inst_names: *const *const std::ffi::c_char,
    length: usize,
) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot delete network instances from config server callback");
        return -1;
    }

    wait_for_config_server_delivery();
    let _remote_mutation_guard = lock_remote_instance_mutation();
    let _mutation_guard = match INSTANCE_MUTATION_LOCK.lock() {
        Ok(guard) => guard,
        Err(err) => {
            set_error_msg(&format!("failed to lock instance mutation: {}", err));
            return -1;
        }
    };

    if length == 0 {
        return 0;
    }

    let Some(inst_names) = (unsafe { parse_instance_names(inst_names, length) }) else {
        return -1;
    };

    let removed_ids = inst_names
        .iter()
        .filter_map(|name| INSTANCE_NAME_ID_MAP.get(name).map(|id| *id.value()))
        .collect::<Vec<_>>();

    if let Err(e) = INSTANCE_MANAGER.delete_network_instance(removed_ids.clone()) {
        set_error_msg(&format!("failed to delete instances: {}", e));
        return -1;
    }

    remove_config_server_tracked_instance_ids(&removed_ids);
    remove_data_plane_handles_by_instance_ids(&removed_ids);
    for name in inst_names {
        INSTANCE_NAME_ID_MAP.remove(&name);
    }

    0
}

/// # Safety
/// Collect the network infos
pub(crate) unsafe fn collect_network_infos(
    infos: *mut KeyValuePair,
    max_length: usize,
) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot collect network infos from config server callback");
        return -1;
    }

    if max_length == 0 {
        return 0;
    }

    let infos = unsafe {
        assert!(!infos.is_null());
        std::slice::from_raw_parts_mut(infos, max_length)
    };

    let collected_infos = match INSTANCE_MANAGER.collect_network_infos_sync() {
        Ok(infos) => infos,
        Err(e) => {
            set_error_msg(&format!("failed to collect network infos: {}", e));
            return -1;
        }
    };

    let mut index = 0;
    for (instance_id, value) in collected_infos.iter() {
        if index >= max_length {
            break;
        }
        let Some(key) = INSTANCE_MANAGER.get_instance_name(instance_id) else {
            continue;
        };
        // convert value to json string
        let value = match serde_json::to_string(&value) {
            Ok(value) => value,
            Err(e) => {
                set_error_msg(&format!("failed to serialize instance info: {}", e));
                return -1;
            }
        };

        infos[index] = KeyValuePair {
            key: std::ffi::CString::new(key).unwrap().into_raw(),
            value: std::ffi::CString::new(value).unwrap().into_raw(),
        };
        index += 1;
    }

    index as std::ffi::c_int
}

/// # Safety
/// List the instance names and IDs known by the FFI instance manager.
pub(crate) unsafe fn list_instance(infos: *mut KeyValuePair, max_length: usize) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot list instances from config server callback");
        return -1;
    }

    if max_length == 0 {
        return 0;
    }

    if infos.is_null() {
        set_error_msg("infos is null");
        return -1;
    }

    let infos = unsafe { std::slice::from_raw_parts_mut(infos, max_length) };
    let mut instances = INSTANCE_MANAGER
        .list_network_instance_ids()
        .into_iter()
        .filter_map(|id| {
            INSTANCE_MANAGER
                .get_instance_name(&id)
                .map(|name| (name, id))
        })
        .collect::<Vec<_>>();
    instances.sort_by(|(left_name, left_id), (right_name, right_id)| {
        left_name
            .cmp(right_name)
            .then_with(|| left_id.to_string().cmp(&right_id.to_string()))
    });

    let encoded_instances = match instances
        .into_iter()
        .take(max_length)
        .map(|(name, id)| {
            let key = CString::new(name)
                .map_err(|err| format!("failed to encode instance name: {}", err))?;
            let value = CString::new(id.to_string())
                .map_err(|err| format!("failed to encode instance id: {}", err))?;
            Ok((key, value))
        })
        .collect::<Result<Vec<_>, String>>()
    {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };

    let count = encoded_instances.len();
    for (index, (key, value)) in encoded_instances.into_iter().enumerate() {
        infos[index] = KeyValuePair {
            key: key.into_raw(),
            value: value.into_raw(),
        };
    }

    count as std::ffi::c_int
}
