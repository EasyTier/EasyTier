use crate::{
    config_server::{
        ConfigServerCallbackScope, ManagedConfigServerClientHooks, set_active_for_test,
    },
    state::{ffi_context, find_instance_id_by_name},
    *,
};
use easytier::{
    common::config::{ConfigFileControl, ConfigLoader as _, TomlConfigLoader},
    web_client::WebClientHooks,
};
use serde_json::Value;
use std::{
    collections::HashSet,
    ffi::{CStr, CString, c_char, c_void},
    sync::{Mutex, mpsc},
    time::Duration,
};
use uuid::Uuid;

#[test]
fn test_parse_config() {
    let cfg_str = r#"
            inst_name = "test"
            network = "test_network"
        "#;
    let cstr = std::ffi::CString::new(cfg_str).unwrap();
    unsafe {
        assert_eq!(parse_config(cstr.as_ptr()), 0);
    }
}

#[test]
fn test_run_network_instance() {
    let cfg_str = r#"
            inst_name = "test"
            network = "test_network"
        "#;
    let cstr = std::ffi::CString::new(cfg_str).unwrap();
    unsafe {
        assert_eq!(run_network_instance(cstr.as_ptr()), 0);
    }
}

#[test]
fn get_error_msg_returns_config_server_callback_error() {
    let hooks = ManagedConfigServerClientHooks::new(None, std::ptr::null_mut());
    let callback_error = format!("callback delivery failed {}", Uuid::new_v4());
    crate::config_server::clear_last_callback_error();
    hooks.note_callback_error(callback_error.clone());

    unsafe {
        let mut error_ptr: *const c_char = std::ptr::null();
        get_error_msg(&mut error_ptr);
        assert!(!error_ptr.is_null());
        let error_msg = CStr::from_ptr(error_ptr).to_string_lossy().into_owned();
        free_string(error_ptr);
        assert!(error_msg.contains(&callback_error));
    }

    crate::config_server::clear_last_callback_error();
}

unsafe extern "C" fn record_config_server_event(event_json: *const c_char, user_data: *mut c_void) {
    let events = unsafe { &*(user_data as *const Mutex<Vec<String>>) };
    events.lock().unwrap().push(
        unsafe { CStr::from_ptr(event_json) }
            .to_string_lossy()
            .into_owned(),
    );
}

fn take_last_error() -> Option<String> {
    unsafe {
        let mut error_ptr: *const c_char = std::ptr::null();
        get_error_msg(&mut error_ptr);
        if error_ptr.is_null() {
            None
        } else {
            let error = CStr::from_ptr(error_ptr).to_string_lossy().into_owned();
            free_string(error_ptr);
            Some(error)
        }
    }
}

fn free_key_value_pairs(infos: &[KeyValuePair]) {
    for info in infos {
        free_string(info.key);
        free_string(info.value);
    }
}

#[test]
fn list_instance_returns_instance_names_and_ids() {
    let instance_id = Uuid::new_v4();
    let instance_name = format!("list-instance-{}", instance_id);
    let cfg = TomlConfigLoader::default();
    cfg.set_id(instance_id);
    cfg.set_inst_name(instance_name.clone());
    ffi_context()
        .manager
        .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();

    let mut infos = vec![
        KeyValuePair {
            key: std::ptr::null(),
            value: std::ptr::null(),
        };
        16
    ];
    let count = unsafe { list_instance(infos.as_mut_ptr(), infos.len()) };
    assert!(count > 0);

    let mut found = false;
    for info in infos.iter().take(count as usize) {
        let key = unsafe { CStr::from_ptr(info.key) }.to_string_lossy();
        let value = unsafe { CStr::from_ptr(info.value) }.to_string_lossy();
        if key == instance_name {
            assert_eq!(value, instance_id.to_string());
            found = true;
        }
    }

    free_key_value_pairs(&infos[..count as usize]);
    ffi_context()
        .runtime
        .block_on(
            ffi_context()
                .manager
                .delete_network_instance(vec![instance_id]),
        )
        .unwrap();
    assert!(found);
}

#[test]
fn list_instance_allows_zero_length() {
    assert_eq!(unsafe { list_instance(std::ptr::null_mut(), 0) }, 0);
}

#[test]
fn list_instance_rejects_null_output_pointer() {
    assert_eq!(unsafe { list_instance(std::ptr::null_mut(), 1) }, -1);
    assert!(take_last_error().unwrap().contains("infos is null"));
}

#[test]
fn call_json_rpc_returns_logger_response() {
    let service = CString::new("api.logger.LoggerRpcService").unwrap();
    let method = CString::new("get_logger_config").unwrap();
    let payload = CString::new("{}").unwrap();
    let mut response_ptr: *const c_char = std::ptr::null();

    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                &mut response_ptr,
            )
        },
        0
    );
    assert!(!response_ptr.is_null());
    let response = unsafe { CStr::from_ptr(response_ptr) }
        .to_string_lossy()
        .into_owned();
    free_string(response_ptr);
    let response: Value = serde_json::from_str(&response).unwrap();
    assert!(response.get("level").is_some());
}

#[test]
fn call_json_rpc_rejects_instance_management_service() {
    let service = CString::new("api.manage.WebClientService").unwrap();
    let method = CString::new("list_network_instance").unwrap();
    let payload = CString::new("{}").unwrap();
    let mut response_ptr: *const c_char = std::ptr::null();

    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                &mut response_ptr,
            )
        },
        -1
    );
    assert!(response_ptr.is_null());
    assert!(take_last_error().unwrap().contains("not exposed"));
}

#[test]
fn call_json_rpc_rejects_malformed_payload_json() {
    let service = CString::new("api.logger.LoggerRpcService").unwrap();
    let method = CString::new("get_logger_config").unwrap();
    let payload = CString::new("{").unwrap();
    let mut response_ptr: *const c_char = std::ptr::null();

    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                &mut response_ptr,
            )
        },
        -1
    );
    assert!(response_ptr.is_null());
    assert!(
        take_last_error()
            .unwrap()
            .contains("failed to parse payload_json")
    );
}

#[test]
fn call_json_rpc_rejects_null_output_pointer() {
    let service = CString::new("api.logger.LoggerRpcService").unwrap();
    let method = CString::new("get_logger_config").unwrap();
    let payload = CString::new("{}").unwrap();

    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                std::ptr::null_mut(),
            )
        },
        -1
    );
    assert!(
        take_last_error()
            .unwrap()
            .contains("out_response_json is null")
    );
}

#[tokio::test]
async fn config_server_hooks_emit_run_event() {
    let events: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let hooks = ManagedConfigServerClientHooks::new(
        Some(record_config_server_event),
        &events as *const _ as *mut c_void,
    );
    let instance_id = Uuid::new_v4();
    let cfg = TomlConfigLoader::default();
    cfg.set_id(instance_id);
    let inst_name = format!("test-{}", instance_id);
    cfg.set_inst_name(inst_name.clone());
    hooks.pre_run_network_instance(&cfg).await.unwrap();
    ffi_context()
        .manager
        .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();

    hooks.post_run_network_instance(&instance_id).await.unwrap();

    let duplicate_cfg = TomlConfigLoader::default();
    duplicate_cfg.set_inst_name(inst_name);
    duplicate_cfg.set_id(Uuid::new_v4());
    assert!(
        hooks
            .pre_run_network_instance(&duplicate_cfg)
            .await
            .is_err()
    );

    assert_eq!(hooks.tracked_instance_ids(), vec![instance_id]);
    let events = events.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    let event: Value = serde_json::from_str(&events[0]).unwrap();
    assert_eq!(event["event"], "run_network_instance");
    assert_eq!(event["success"], true);
    assert_eq!(event["instance_id"], instance_id.to_string());
    assert!(event["error"].is_null());
    ffi_context()
        .manager
        .delete_network_instance(vec![instance_id])
        .await
        .unwrap();
}

#[tokio::test]
async fn config_server_hooks_emit_delete_events_for_tracked_instances() {
    let events: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let hooks = ManagedConfigServerClientHooks::new(
        Some(record_config_server_event),
        &events as *const _ as *mut c_void,
    );
    let instance_id_1 = Uuid::new_v4();
    let instance_id_2 = Uuid::new_v4();
    let unknown_instance_id = Uuid::new_v4();
    for id in [instance_id_1, instance_id_2] {
        let cfg = TomlConfigLoader::default();
        cfg.set_id(id);
        cfg.set_inst_name(format!("test-{}", id));
        hooks.pre_run_network_instance(&cfg).await.unwrap();
        ffi_context()
            .manager
            .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
    }

    hooks
        .post_run_network_instance(&instance_id_1)
        .await
        .unwrap();
    hooks
        .post_run_network_instance(&instance_id_2)
        .await
        .unwrap();
    events.lock().unwrap().clear();

    hooks
        .post_remove_network_instances(&[instance_id_1, unknown_instance_id, instance_id_2])
        .await
        .unwrap();

    assert!(hooks.tracked_instance_ids().is_empty());
    let events = events.lock().unwrap().clone();
    assert_eq!(events.len(), 2);
    let event_ids = events
        .iter()
        .map(|event| {
            let event: Value = serde_json::from_str(event).unwrap();
            assert_eq!(event["event"], "delete_network_instance");
            assert_eq!(event["success"], true);
            assert!(event["error"].is_null());
            event["instance_id"].as_str().unwrap().to_string()
        })
        .collect::<HashSet<_>>();
    assert_eq!(
        event_ids,
        HashSet::from([instance_id_1.to_string(), instance_id_2.to_string()])
    );
    ffi_context()
        .manager
        .delete_network_instance(vec![instance_id_1, instance_id_2])
        .await
        .unwrap();
}

#[tokio::test]
async fn config_server_hooks_ignore_untracked_instance_without_event() {
    let events: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let hooks = ManagedConfigServerClientHooks::new(
        Some(record_config_server_event),
        &events as *const _ as *mut c_void,
    );
    let local_id = Uuid::new_v4();

    hooks
        .post_remove_network_instances(&[local_id])
        .await
        .unwrap();

    assert!(events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn config_server_hooks_reject_duplicate_instance_name() {
    let hooks = ManagedConfigServerClientHooks::new(None, std::ptr::null_mut());
    let inst_name = format!("test-{}", Uuid::new_v4());
    let existing_id = Uuid::new_v4();
    let new_id = Uuid::new_v4();
    let existing_cfg = TomlConfigLoader::default();
    existing_cfg.set_inst_name(inst_name.clone());
    existing_cfg.set_id(existing_id);
    ffi_context()
        .manager
        .run_network_instance(existing_cfg, false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();

    let cfg = TomlConfigLoader::default();
    cfg.set_inst_name(inst_name.clone());
    cfg.set_id(new_id);

    assert!(hooks.pre_run_network_instance(&cfg).await.is_err());
    assert_eq!(find_instance_id_by_name(&inst_name), Some(existing_id));
    ffi_context()
        .manager
        .delete_network_instance(vec![existing_id])
        .await
        .unwrap();
}

#[tokio::test]
async fn config_server_hooks_remove_overwritten_id_before_duplicate_name_error() {
    let events: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let hooks = ManagedConfigServerClientHooks::new(
        Some(record_config_server_event),
        &events as *const _ as *mut c_void,
    );
    let old_name = format!("old-{}", Uuid::new_v4());
    let duplicate_name = format!("duplicate-{}", Uuid::new_v4());
    let overwritten_id = Uuid::new_v4();
    let duplicate_id = Uuid::new_v4();
    hooks.instance_ids.lock().unwrap().insert(overwritten_id);
    for (id, name) in [
        (overwritten_id, old_name.clone()),
        (duplicate_id, duplicate_name.clone()),
    ] {
        let cfg = TomlConfigLoader::default();
        cfg.set_id(id);
        cfg.set_inst_name(name);
        ffi_context()
            .manager
            .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
    }
    ffi_context()
        .manager
        .delete_network_instance(vec![overwritten_id])
        .await
        .unwrap();

    hooks
        .post_remove_network_instances(&[overwritten_id])
        .await
        .unwrap();

    let cfg = TomlConfigLoader::default();
    cfg.set_inst_name(duplicate_name.clone());
    cfg.set_id(overwritten_id);

    assert!(hooks.pre_run_network_instance(&cfg).await.is_err());
    assert!(hooks.tracked_instance_ids().is_empty());
    assert!(find_instance_id_by_name(&old_name).is_none());
    assert_eq!(
        find_instance_id_by_name(&duplicate_name),
        Some(duplicate_id)
    );
    assert_eq!(events.lock().unwrap().len(), 1);
    ffi_context()
        .manager
        .delete_network_instance(vec![duplicate_id])
        .await
        .unwrap();
}

#[tokio::test]
async fn config_server_hooks_remove_tracked_state_before_overwrite_retry() {
    let hooks = ManagedConfigServerClientHooks::new(None, std::ptr::null_mut());
    let inst_name = format!("test-{}", Uuid::new_v4());
    let instance_id = Uuid::new_v4();
    hooks.instance_ids.lock().unwrap().insert(instance_id);

    let cfg = TomlConfigLoader::default();
    cfg.set_inst_name(inst_name.clone());
    cfg.set_id(instance_id);
    ffi_context()
        .manager
        .run_network_instance(cfg.clone(), false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();
    ffi_context()
        .manager
        .delete_network_instance(vec![instance_id])
        .await
        .unwrap();

    hooks
        .post_remove_network_instances(&[instance_id])
        .await
        .unwrap();
    hooks.pre_run_network_instance(&cfg).await.unwrap();

    assert!(hooks.tracked_instance_ids().is_empty());
    assert!(find_instance_id_by_name(&inst_name).is_none());
}

#[tokio::test]
async fn config_server_hooks_reject_post_run_after_external_delete() {
    let hooks = ManagedConfigServerClientHooks::new(None, std::ptr::null_mut());
    let instance_id = Uuid::new_v4();
    let cfg = TomlConfigLoader::default();
    cfg.set_id(instance_id);
    cfg.set_inst_name(format!("test-{}", instance_id));
    hooks.pre_run_network_instance(&cfg).await.unwrap();
    ffi_context()
        .manager
        .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();
    ffi_context()
        .manager
        .delete_network_instance(vec![instance_id])
        .await
        .unwrap();

    assert!(hooks.post_run_network_instance(&instance_id).await.is_err());
}

#[test]
fn find_instance_id_by_name_resolves_uncommitted_manager_instance_name() {
    let instance_id = Uuid::new_v4();
    let inst_name = format!("test-{}", instance_id);
    let cfg = TomlConfigLoader::default();
    cfg.set_id(instance_id);
    cfg.set_inst_name(inst_name.clone());
    ffi_context()
        .manager
        .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
        .unwrap();

    assert_eq!(find_instance_id_by_name(&inst_name), Some(instance_id));
    ffi_context()
        .runtime
        .block_on(
            ffi_context()
                .manager
                .delete_network_instance(vec![instance_id]),
        )
        .unwrap();
}

#[test]
fn delete_network_instance_removes_only_named_instances() {
    let keep_id = Uuid::new_v4();
    let delete_id = Uuid::new_v4();
    let keep_name = format!("keep-{}", keep_id);
    let delete_name = format!("delete-{}", delete_id);

    for (id, name) in [
        (keep_id, keep_name.clone()),
        (delete_id, delete_name.clone()),
    ] {
        let cfg = TomlConfigLoader::default();
        cfg.set_id(id);
        cfg.set_inst_name(name.clone());
        ffi_context()
            .manager
            .run_network_instance(cfg, false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
    }

    let delete_name = CString::new(delete_name.clone()).unwrap();
    let inst_names = [delete_name.as_ptr()];
    assert_eq!(
        unsafe { delete_network_instance(inst_names.as_ptr(), inst_names.len()) },
        0
    );

    assert_eq!(find_instance_id_by_name(&keep_name), Some(keep_id));
    assert!(find_instance_id_by_name(delete_name.to_str().unwrap()).is_none());

    ffi_context()
        .runtime
        .block_on(ffi_context().manager.delete_network_instance(vec![keep_id]))
        .unwrap();
}

#[test]
fn retain_and_delete_network_instance_reject_invalid_name_pointers() {
    assert_eq!(unsafe { retain_network_instance(std::ptr::null(), 1) }, -1);
    assert_eq!(unsafe { delete_network_instance(std::ptr::null(), 1) }, -1);

    let inst_names = [std::ptr::null()];
    assert_eq!(
        unsafe { retain_network_instance(inst_names.as_ptr(), inst_names.len()) },
        -1
    );
    assert_eq!(
        unsafe { delete_network_instance(inst_names.as_ptr(), inst_names.len()) },
        -1
    );
}

#[test]
fn ffi_process_management_uses_manager_mutation_lock() {
    let manager_guard = ffi_context().manager.mutation_lock().blocking_lock_owned();
    let (done_tx, done_rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        ffi_context()
            .runtime
            .block_on(
                ffi_context()
                    .process_management
                    .delete_owned_network_instances(Vec::new()),
            )
            .unwrap();
        done_tx.send(()).unwrap();
    });

    assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
    drop(manager_guard);
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    waiter.join().unwrap();
}

#[tokio::test]
async fn config_server_hooks_reject_late_runs_for_core_rollback() {
    let events: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let hooks = ManagedConfigServerClientHooks::new(
        Some(record_config_server_event),
        &events as *const _ as *mut c_void,
    );
    hooks.start_stopping();

    assert!(
        hooks
            .post_run_network_instance(&Uuid::new_v4())
            .await
            .is_err()
    );

    assert!(hooks.tracked_instance_ids().is_empty());
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn delete_network_instance_rejects_an_ambiguous_name() {
    let duplicate_name = format!("duplicate-{}", Uuid::new_v4());
    let instance_ids = [Uuid::new_v4(), Uuid::new_v4()];
    for instance_id in instance_ids {
        let config = TomlConfigLoader::default();
        config.set_id(instance_id);
        config.set_inst_name(duplicate_name.clone());
        ffi_context()
            .manager
            .run_network_instance(config, false, ConfigFileControl::STATIC_CONFIG)
            .unwrap();
    }

    #[cfg(feature = "ffi-dataplane")]
    {
        assert!(crate::data_plane::get_instance_id(&duplicate_name).is_none());
        assert!(take_last_error().unwrap().contains("2 instances match"));
    }

    let duplicate_name = CString::new(duplicate_name).unwrap();
    let names = [duplicate_name.as_ptr()];
    assert_eq!(
        unsafe { delete_network_instance(names.as_ptr(), names.len()) },
        -1
    );
    assert!(take_last_error().unwrap().contains("2 instances match"));
    assert!(
        instance_ids
            .iter()
            .all(|id| ffi_context().manager.get_instance(id).is_some())
    );

    ffi_context()
        .runtime
        .block_on(
            ffi_context()
                .process_management
                .delete_owned_network_instances(instance_ids.to_vec()),
        )
        .unwrap();
}

#[test]
fn config_server_callback_context_rejects_nested_blocking_ffi_calls() {
    let _callback_scope = ConfigServerCallbackScope::enter();
    assert_eq!(is_config_server_client_connected(), 0);
    let service = CString::new("api.logger.LoggerRpcService").unwrap();
    let method = CString::new("get_logger_config").unwrap();
    let payload = CString::new("{}").unwrap();
    let mut response_ptr: *const c_char = std::ptr::null();
    assert_eq!(
        unsafe {
            call_json_rpc(
                service.as_ptr(),
                method.as_ptr(),
                std::ptr::null(),
                payload.as_ptr(),
                &mut response_ptr,
            )
        },
        -1
    );
    assert!(response_ptr.is_null());
    assert_eq!(
        unsafe { collect_network_infos(std::ptr::null_mut(), 0) },
        -1
    );
    assert_eq!(unsafe { list_instance(std::ptr::null_mut(), 0) }, -1);
    let cfg = CString::new("inst_name = \"callback-test\"\nlisteners = []").unwrap();
    assert_eq!(unsafe { run_network_instance(cfg.as_ptr()) }, -1);
    assert_eq!(unsafe { retain_network_instance(std::ptr::null(), 0) }, -1);
    assert_eq!(unsafe { delete_network_instance(std::ptr::null(), 0) }, -1);
    let url = CString::new("ring://test/token").unwrap();
    let machine_id = CString::new("test-machine").unwrap();
    assert_eq!(
        unsafe {
            start_config_server_client(
                url.as_ptr(),
                std::ptr::null(),
                machine_id.as_ptr(),
                false,
                None,
                std::ptr::null_mut(),
            )
        },
        -1
    );
    assert_eq!(stop_config_server_client(), -1);

    #[cfg(feature = "ffi-dataplane")]
    {
        assert_eq!(
            unsafe {
                data_plane_tcp_connect(
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                data_plane_tcp_bind(
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                data_plane_tcp_accept(
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(
            unsafe { data_plane_tcp_read(0, std::ptr::null_mut(), 0, 0) },
            -1
        );
        assert_eq!(
            unsafe { data_plane_tcp_write(0, std::ptr::null(), 0, 0) },
            -1
        );
        assert_eq!(data_plane_tcp_close(0), -1);
        assert_eq!(data_plane_tcp_listener_close(0), -1);
        assert_eq!(
            unsafe {
                data_plane_udp_bind(
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(
            unsafe { data_plane_udp_send_to(0, std::ptr::null(), 0, std::ptr::null(), 0, 0) },
            -1
        );
        assert_eq!(
            unsafe {
                data_plane_udp_recv_from(
                    0,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                )
            },
            -1
        );
        assert_eq!(data_plane_udp_close(0), -1);
        assert_eq!(data_plane_async_op_status(0), -2);
        assert_eq!(data_plane_async_op_wait(0, 0), -2);
        assert_eq!(data_plane_async_op_cancel(0), -2);
        assert_eq!(data_plane_async_op_free(0), -2);
        data_plane_free_bytes(std::ptr::null(), 0);
        assert_eq!(
            unsafe { data_plane_tcp_connect_start(std::ptr::null(), std::ptr::null(), 0, 0) },
            0
        );
        assert_eq!(
            unsafe { data_plane_tcp_bind_start(std::ptr::null(), 0, 0) },
            0
        );
        assert_eq!(unsafe { data_plane_tcp_accept_start(0, 0) }, 0);
        assert_eq!(unsafe { data_plane_tcp_read_start(0, 0, 0) }, 0);
        assert_eq!(
            unsafe { data_plane_tcp_write_start(0, std::ptr::null(), 0, 0) },
            0
        );
        assert_eq!(
            unsafe { data_plane_udp_bind_start(std::ptr::null(), 0, 0) },
            0
        );
        assert_eq!(
            unsafe { data_plane_udp_send_to_start(0, std::ptr::null(), 0, std::ptr::null(), 0, 0) },
            0
        );
        assert_eq!(unsafe { data_plane_udp_recv_from_start(0, 0, 0) }, 0);
    }
}

#[cfg(feature = "ffi-dataplane")]
#[test]
fn active_config_server_rejects_data_plane() {
    set_active_for_test(true);

    assert_eq!(
        unsafe {
            data_plane_tcp_connect(
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(
        unsafe { data_plane_tcp_read(0, std::ptr::null_mut(), 0, 0) },
        -1
    );
    assert_eq!(
        unsafe { data_plane_tcp_connect_start(std::ptr::null(), std::ptr::null(), 0, 0) },
        0
    );
    assert_eq!(unsafe { data_plane_tcp_read_start(0, 0, 0) }, 0);

    set_active_for_test(false);
}

#[cfg(feature = "ffi-dataplane")]
#[test]
fn async_op_invalid_handle_helpers_are_stable() {
    assert_eq!(data_plane_async_op_status(u64::MAX), -2);
    assert_eq!(data_plane_async_op_wait(u64::MAX, 1), -2);
    assert_eq!(data_plane_async_op_cancel(u64::MAX), -2);
    assert_eq!(data_plane_async_op_free(u64::MAX), -2);
    data_plane_free_bytes(std::ptr::null(), 0);
}
