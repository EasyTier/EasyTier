use std::{
    collections::BTreeSet,
    ptr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use easytier::{
    common::config::{ConfigFileControl, ConfigLoader, TomlConfigLoader},
    instance::factory::{NativeInstanceManager, native_instance_manager_with_runtime},
};
use jni::{
    JNIEnv,
    objects::{JClass, JString},
    sys::{jint, jstring},
};
use once_cell::sync::Lazy;
use serde::Serialize;
use uuid::Uuid;

static ANDROID_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("easytier-headless")
        .build()
        .expect("failed to create the Android EasyTier runtime")
});

static ANDROID_INSTANCE_MANAGER: Lazy<Arc<NativeInstanceManager>> = Lazy::new(|| {
    Arc::new(native_instance_manager_with_runtime(
        ANDROID_RUNTIME.handle().clone(),
    ))
});

static HEADLESS_OPERATION: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static HEADLESS_INSTANCE_ID: Lazy<RwLock<Option<Uuid>>> = Lazy::new(|| RwLock::new(None));

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    routes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u32>,
}

impl NativeResult {
    fn success() -> Self {
        Self {
            ok: true,
            error: None,
            instance_id: None,
            ipv4_addr: None,
            routes: None,
            dns: None,
            mtu: None,
        }
    }

    fn error(error: impl ToString) -> Self {
        Self {
            ok: false,
            error: Some(error.to_string()),
            ..Self::success()
        }
    }
}

pub(crate) fn instance_manager() -> Arc<NativeInstanceManager> {
    ANDROID_INSTANCE_MANAGER.clone()
}

fn stop_instance(instance_id: Uuid) -> anyhow::Result<()> {
    ANDROID_RUNTIME.block_on(ANDROID_INSTANCE_MANAGER.delete_network_instances([instance_id]))?;
    let mut headless_instance_id = HEADLESS_INSTANCE_ID.write().expect("headless id poisoned");
    if *headless_instance_id == Some(instance_id) {
        *headless_instance_id = None;
    }
    Ok(())
}

fn stop_previous_headless_instance() -> anyhow::Result<()> {
    let instance_id = *HEADLESS_INSTANCE_ID.read().expect("headless id poisoned");
    if let Some(instance_id) = instance_id {
        stop_instance(instance_id)?;
    }
    Ok(())
}

fn start(config_toml: &str) -> anyhow::Result<NativeResult> {
    let _operation = HEADLESS_OPERATION
        .lock()
        .expect("headless operation poisoned");
    stop_previous_headless_instance()?;

    let config = TomlConfigLoader::new_from_str(config_toml)?;
    let flags = config.get_flags();
    if flags.no_tun {
        anyhow::bail!("the saved network has no_tun enabled");
    }

    let configured_routes = config
        .get_routes()
        .unwrap_or_default()
        .into_iter()
        .map(|route| route.to_string())
        .collect::<BTreeSet<_>>();
    let enable_magic_dns = flags.accept_dns;
    let instance_id =
        ANDROID_INSTANCE_MANAGER.run_network_instance(config, ConfigFileControl::STATIC_CONFIG)?;
    *HEADLESS_INSTANCE_ID.write().expect("headless id poisoned") = Some(instance_id);

    let ready = ANDROID_RUNTIME.block_on(async {
        for _ in 0..60 {
            if let Some(info) = ANDROID_INSTANCE_MANAGER.network_info(instance_id).await {
                if let Some(error) = info.error_msg.filter(|error| !error.is_empty()) {
                    return Err(anyhow::anyhow!(error));
                }
                if let Some(ipv4) = info.my_node_info.and_then(|node| node.virtual_ipv4) {
                    let mut routes = configured_routes.clone();
                    for route in info.routes {
                        for mut cidr in route.proxy_cidrs {
                            if !cidr.contains('/') {
                                cidr.push_str("/32");
                            }
                            routes.insert(cidr);
                        }
                    }
                    if enable_magic_dns {
                        routes.insert("100.100.100.101/32".to_string());
                    }
                    return Ok(NativeResult {
                        ok: true,
                        error: None,
                        instance_id: Some(instance_id.to_string()),
                        ipv4_addr: Some(ipv4.to_string()),
                        routes: Some(routes.into_iter().collect()),
                        dns: enable_magic_dns.then(|| "100.100.100.101".to_string()),
                        mtu: Some(1300),
                    });
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(anyhow::anyhow!(
            "timed out waiting for the EasyTier virtual IPv4 address"
        ))
    });

    if ready.is_err() {
        let _ = stop_instance(instance_id);
    }
    ready
}

fn stop(instance_id: &str) -> anyhow::Result<NativeResult> {
    let _operation = HEADLESS_OPERATION
        .lock()
        .expect("headless operation poisoned");
    stop_instance(instance_id.parse()?)?;
    Ok(NativeResult::success())
}

fn attach_tun_fd(instance_id: &str, fd: i32) -> anyhow::Result<NativeResult> {
    let instance_id = instance_id.parse()?;
    ANDROID_INSTANCE_MANAGER.attach_tun_fd(instance_id, fd)?;
    Ok(NativeResult::success())
}

fn result_json(result: anyhow::Result<NativeResult>) -> String {
    let result = result.unwrap_or_else(NativeResult::error);
    serde_json::to_string(&result).unwrap_or_else(|error| {
        format!("{{\"ok\":false,\"error\":\"failed to serialize native result: {error}\"}}")
    })
}

fn java_string(env: JNIEnv, value: String) -> jstring {
    env.new_string(value)
        .map(|value| value.into_raw())
        .unwrap_or_else(|_| ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_plugin_vpnservice_HeadlessEasyTierBridge_start(
    mut env: JNIEnv,
    _class: JClass,
    config_toml: JString,
) -> jstring {
    let result = env
        .get_string(&config_toml)
        .map(|value| value.into())
        .map_err(anyhow::Error::new)
        .and_then(|config: String| start(&config));
    java_string(env, result_json(result))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_plugin_vpnservice_HeadlessEasyTierBridge_stop(
    mut env: JNIEnv,
    _class: JClass,
    instance_id: JString,
) -> jstring {
    let result = env
        .get_string(&instance_id)
        .map(|value| value.into())
        .map_err(anyhow::Error::new)
        .and_then(|instance_id: String| stop(&instance_id));
    java_string(env, result_json(result))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_plugin_vpnservice_HeadlessEasyTierBridge_attachTunFd(
    mut env: JNIEnv,
    _class: JClass,
    instance_id: JString,
    fd: jint,
) -> jstring {
    let result = env
        .get_string(&instance_id)
        .map(|value| value.into())
        .map_err(anyhow::Error::new)
        .and_then(|instance_id: String| attach_tun_fd(&instance_id, fd));
    java_string(env, result_json(result))
}
