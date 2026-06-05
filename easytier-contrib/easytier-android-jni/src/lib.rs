//! JNI facade for Android callers of EasyTier.
//!
//! This file intentionally lists every Java-visible native method exported by
//! `libeasytier_android_jni.so`. The implementation details live in sibling
//! modules so this facade stays readable as an API map.
//!
//! Network management APIs:
//! - `setTunFd(instanceName, fd)`: attach an Android TUN fd to an instance.
//! - `parseConfig(config)`: validate TOML config text.
//! - `runNetworkInstance(config)`: start a local network instance.
//! - `retainNetworkInstance(instanceNames)`: retain named instances and stop the rest.
//! - `collectNetworkInfos()`: return running instance info as a JSON string.
//!
//! Config server client APIs:
//! - `startConfigServerClient(url, hostname, machineId, secureMode, callback)`:
//!   start the managed remote config client.
//! - `stopConfigServerClient()`: stop the managed client and release its Java callback.
//! - `isConfigServerClientConnected()`: return whether the managed client is connected.
//!
//! Error API:
//! - `getLastError()`: return the latest FFI/JNI error string for the calling thread.

mod callback;
mod config_server_api;
mod error;
mod logger;
mod network_api;
mod strings;

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jint, jstring};

/// Attach a TUN file descriptor to an EasyTier network instance.
///
/// Java signature:
/// `EasyTierJNI.setTunFd(instanceName: String, fd: Int): Int`
///
/// `instanceName` must name an instance known to the shared FFI instance cache.
/// The `fd` must be a valid Android TUN file descriptor. On failure this
/// returns `-1` and throws `RuntimeException` with the FFI error message when
/// one is available.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_setTunFd(
    env: JNIEnv,
    class: JClass,
    inst_name: JString,
    fd: jint,
) -> jint {
    logger::init();
    network_api::set_tun_fd_jni(env, class, inst_name, fd)
}

/// Validate a TOML network config string.
///
/// Java signature:
/// `EasyTierJNI.parseConfig(config: String): Int`
///
/// This only validates the config text; it does not start or mutate any
/// instance. On failure this returns `-1` and throws `RuntimeException`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_parseConfig(
    env: JNIEnv,
    class: JClass,
    config: JString,
) -> jint {
    logger::init();
    network_api::parse_config_jni(env, class, config)
}

/// Start one local EasyTier network instance from TOML config text.
///
/// Java signature:
/// `EasyTierJNI.runNetworkInstance(config: String): Int`
///
/// The instance name in the config must be unique in the FFI instance cache.
/// On failure this returns `-1` and throws `RuntimeException`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_runNetworkInstance(
    env: JNIEnv,
    class: JClass,
    config: JString,
) -> jint {
    logger::init();
    network_api::run_network_instance_jni(env, class, config)
}

/// Retain the named network instances and stop all other instances.
///
/// Java signature:
/// `EasyTierJNI.retainNetworkInstance(instanceNames: Array<String>?): Int`
///
/// Passing `null` or an empty array stops all instances. Null elements inside a
/// non-empty array are skipped. On failure this returns `-1` and throws
/// `RuntimeException`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_retainNetworkInstance(
    env: JNIEnv,
    class: JClass,
    instance_names: JObjectArray,
) -> jint {
    logger::init();
    network_api::retain_network_instance_jni(env, class, instance_names)
}

/// Collect running network instance information.
///
/// Java signature:
/// `EasyTierJNI.collectNetworkInfos(maxLength: Int): String?`
///
/// Returns a JSON string containing `NetworkInstanceRunningInfoMap`, or null if
/// collection fails. `maxLength` limits how many FFI entries are collected. On
/// failure this throws `RuntimeException` when an error message is available.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_collectNetworkInfos(
    env: JNIEnv,
    class: JClass,
    max_length: jint,
) -> jstring {
    logger::init();
    network_api::collect_network_infos_jni(env, class, max_length)
}

/// Return the latest FFI/JNI error string for the calling thread.
///
/// Java signature:
/// `EasyTierJNI.getLastError(): String?`
///
/// This combines the FFI thread-local error with any pending config-server Java
/// callback error. It returns null when no error is available.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_getLastError(
    env: JNIEnv,
    class: JClass,
) -> jstring {
    error::get_last_error_jni(env, class)
}

/// Start the managed config-server client.
///
/// Java signature:
/// `EasyTierJNI.startConfigServerClient(url, hostname, machineId, secureMode, callback): Int`
///
/// JNI only converts Java values and keeps the Java callback alive. The FFI
/// layer owns singleton lifecycle, config-server/data-plane mutual exclusion,
/// remote instance tracking, and callback event timing. If `callback` is
/// non-null, each remote apply/delete event is delivered to
/// `ConfigServerEventCallback.onEvent(eventJson)`.
///
/// On failure this returns `-1` and throws `RuntimeException`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_startConfigServerClient(
    mut env: JNIEnv,
    _class: JClass,
    config_server_url: JString,
    hostname: JString,
    machine_id: JString,
    secure_mode: jboolean,
    callback: JObject,
) -> jint {
    logger::init();
    config_server_api::start_config_server_client_jni(
        &mut env,
        config_server_url,
        hostname,
        machine_id,
        secure_mode,
        callback,
    )
}

/// Stop the managed config-server client.
///
/// Java signature:
/// `EasyTierJNI.stopConfigServerClient(): Int`
///
/// The FFI layer performs the actual stop and managed instance cleanup. JNI
/// releases the Java callback reference after FFI stop succeeds. On failure
/// this returns `-1` and throws `RuntimeException`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_stopConfigServerClient(
    env: JNIEnv,
    class: JClass,
) -> jint {
    logger::init();
    config_server_api::stop_config_server_client_jni(env, class)
}

/// Report whether the managed config-server client is connected.
///
/// Java signature:
/// `EasyTierJNI.isConfigServerClientConnected(): Boolean`
///
/// Returns `JNI_TRUE` only when the FFI config-server client exists and reports
/// connected.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_isConfigServerClientConnected(
    env: JNIEnv,
    class: JClass,
) -> jboolean {
    logger::init();
    config_server_api::is_config_server_client_connected_jni(env, class)
}
