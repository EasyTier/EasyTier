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
//! - `listInstances()`: return running instance names and IDs as JSON.
//! - `collectNetworkInfos()`: return running instance info as a JSON string.
//! - `callJsonRpc(...)`: call an exposed EasyTier RPC service with JSON payload.
//!
//! Config server client APIs:
//! - `startConfigServerClient(url, hostname, machineId, secureMode, callback)`:
//!   start the managed remote config client.
//! - `stopConfigServerClient()`: stop the managed client and release its Java callback.
//! - `isConfigServerClientConnected()`: return whether the managed client is connected.
//!
//! Error API:
//! - `getLastError()`: return the latest FFI/JNI error string for the calling thread.
//!
//! Data-plane APIs:
//! - `EasyTierDataPlaneJNI.*`: low-level async op-handle data-plane JNI.
//! - `EasyTierJNI.dataPlane*`: compatibility exports for older callers.

mod callback;
mod config_server_api;
mod data_plane_api;
mod error;
mod json_rpc_api;
mod logger;
mod network_api;
mod strings;

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jint, jlong, jobject, jstring};

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
/// non-empty array are invalid. On failure this returns `-1` and throws
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

/// List running network instance names and IDs.
///
/// Java signature:
/// `EasyTierJNI.listInstances(maxLength: Int): String?`
///
/// Returns a JSON object whose keys are instance names and whose values are
/// instance ID strings. On failure this returns null and throws
/// `RuntimeException`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_listInstances(
    env: JNIEnv,
    class: JClass,
    max_length: jint,
) -> jstring {
    logger::init();
    network_api::list_instances_jni(env, class, max_length)
}

/// Call an exposed EasyTier RPC method using protobuf JSON.
///
/// Java signature:
/// `EasyTierJNI.callJsonRpc(serviceName, methodName, domainName, payloadJson): String?`
///
/// Instance lifecycle management RPCs are intentionally not exposed here. Use
/// the dedicated EasyTierJNI instance APIs for start/retain/delete/collect.
/// `payloadJson` must include any `instance` selector required by the target
/// RPC. On failure this returns null and throws `RuntimeException`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_callJsonRpc(
    env: JNIEnv,
    class: JClass,
    service_name: JString,
    method_name: JString,
    domain_name: JString,
    payload_json: JString,
) -> jstring {
    logger::init();
    json_rpc_api::call_json_rpc_jni(
        env,
        class,
        service_name,
        method_name,
        domain_name,
        payload_json,
    )
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

macro_rules! export_data_plane_jni {
    (
        $op_status:ident,
        $op_wait:ident,
        $op_cancel:ident,
        $op_free:ident,
        $tcp_connect_start:ident,
        $tcp_connect_finish:ident,
        $tcp_bind_start:ident,
        $tcp_bind_finish:ident,
        $tcp_accept_start:ident,
        $tcp_accept_finish:ident,
        $tcp_read_start:ident,
        $tcp_read_finish:ident,
        $tcp_write_start:ident,
        $tcp_write_finish:ident,
        $udp_bind_start:ident,
        $udp_bind_finish:ident,
        $udp_send_to_start:ident,
        $udp_send_to_finish:ident,
        $udp_recv_from_start:ident,
        $udp_recv_from_finish:ident,
        $tcp_close:ident,
        $tcp_listener_close:ident,
        $udp_close:ident
    ) => {
        #[unsafe(no_mangle)]
        pub extern "system" fn $op_status(env: JNIEnv, class: JClass, handle: jlong) -> jint {
            logger::init();
            data_plane_api::async_op_status_jni(env, class, handle)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $op_wait(
            env: JNIEnv,
            class: JClass,
            handle: jlong,
            timeout_ms: jlong,
        ) -> jint {
            logger::init();
            data_plane_api::async_op_wait_jni(env, class, handle, timeout_ms)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $op_cancel(env: JNIEnv, class: JClass, handle: jlong) -> jint {
            logger::init();
            data_plane_api::async_op_cancel_jni(env, class, handle)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $op_free(env: JNIEnv, class: JClass, handle: jlong) -> jint {
            logger::init();
            data_plane_api::async_op_free_jni(env, class, handle)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_connect_start(
            env: JNIEnv,
            class: JClass,
            inst_name: JString,
            dst_ip: JString,
            dst_port: jint,
            timeout_ms: jlong,
        ) -> jlong {
            logger::init();
            data_plane_api::tcp_connect_start_jni(
                env, class, inst_name, dst_ip, dst_port, timeout_ms,
            )
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_connect_finish(
            env: JNIEnv,
            class: JClass,
            op: jlong,
        ) -> jobject {
            logger::init();
            data_plane_api::tcp_connect_finish_jni(env, class, op)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_bind_start(
            env: JNIEnv,
            class: JClass,
            inst_name: JString,
            local_port: jint,
            timeout_ms: jlong,
        ) -> jlong {
            logger::init();
            data_plane_api::tcp_bind_start_jni(env, class, inst_name, local_port, timeout_ms)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_bind_finish(env: JNIEnv, class: JClass, op: jlong) -> jobject {
            logger::init();
            data_plane_api::tcp_bind_finish_jni(env, class, op)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_accept_start(
            env: JNIEnv,
            class: JClass,
            handle: jlong,
            timeout_ms: jlong,
        ) -> jlong {
            logger::init();
            data_plane_api::tcp_accept_start_jni(env, class, handle, timeout_ms)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_accept_finish(
            env: JNIEnv,
            class: JClass,
            op: jlong,
        ) -> jobject {
            logger::init();
            data_plane_api::tcp_accept_finish_jni(env, class, op)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_read_start(
            env: JNIEnv,
            class: JClass,
            handle: jlong,
            max_len: jint,
            timeout_ms: jlong,
        ) -> jlong {
            logger::init();
            data_plane_api::tcp_read_start_jni(env, class, handle, max_len, timeout_ms)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_read_finish(env: JNIEnv, class: JClass, op: jlong) -> jobject {
            logger::init();
            data_plane_api::tcp_read_finish_jni(env, class, op)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_write_start(
            env: JNIEnv,
            class: JClass,
            handle: jlong,
            data: JByteArray,
            timeout_ms: jlong,
        ) -> jlong {
            logger::init();
            data_plane_api::tcp_write_start_jni(env, class, handle, data, timeout_ms)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_write_finish(env: JNIEnv, class: JClass, op: jlong) -> jint {
            logger::init();
            data_plane_api::tcp_write_finish_jni(env, class, op)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $udp_bind_start(
            env: JNIEnv,
            class: JClass,
            inst_name: JString,
            local_port: jint,
            timeout_ms: jlong,
        ) -> jlong {
            logger::init();
            data_plane_api::udp_bind_start_jni(env, class, inst_name, local_port, timeout_ms)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $udp_bind_finish(env: JNIEnv, class: JClass, op: jlong) -> jobject {
            logger::init();
            data_plane_api::udp_bind_finish_jni(env, class, op)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $udp_send_to_start(
            env: JNIEnv,
            class: JClass,
            handle: jlong,
            dst_ip: JString,
            dst_port: jint,
            data: JByteArray,
            timeout_ms: jlong,
        ) -> jlong {
            logger::init();
            data_plane_api::udp_send_to_start_jni(
                env, class, handle, dst_ip, dst_port, data, timeout_ms,
            )
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $udp_send_to_finish(env: JNIEnv, class: JClass, op: jlong) -> jint {
            logger::init();
            data_plane_api::udp_send_to_finish_jni(env, class, op)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $udp_recv_from_start(
            env: JNIEnv,
            class: JClass,
            handle: jlong,
            max_len: jint,
            timeout_ms: jlong,
        ) -> jlong {
            logger::init();
            data_plane_api::udp_recv_from_start_jni(env, class, handle, max_len, timeout_ms)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $udp_recv_from_finish(
            env: JNIEnv,
            class: JClass,
            op: jlong,
        ) -> jobject {
            logger::init();
            data_plane_api::udp_recv_from_finish_jni(env, class, op)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_close(env: JNIEnv, class: JClass, handle: jlong) -> jint {
            logger::init();
            data_plane_api::tcp_close_jni(env, class, handle)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $tcp_listener_close(
            env: JNIEnv,
            class: JClass,
            handle: jlong,
        ) -> jint {
            logger::init();
            data_plane_api::tcp_listener_close_jni(env, class, handle)
        }

        #[unsafe(no_mangle)]
        pub extern "system" fn $udp_close(env: JNIEnv, class: JClass, handle: jlong) -> jint {
            logger::init();
            data_plane_api::udp_close_jni(env, class, handle)
        }
    };
}

export_data_plane_jni!(
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneAsyncOpStatus,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneAsyncOpWait,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneAsyncOpCancel,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneAsyncOpFree,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpConnectStart,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpConnectFinish,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpBindStart,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpBindFinish,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpAcceptStart,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpAcceptFinish,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpReadStart,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpReadFinish,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpWriteStart,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpWriteFinish,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneUdpBindStart,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneUdpBindFinish,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneUdpSendToStart,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneUdpSendToFinish,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneUdpRecvFromStart,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneUdpRecvFromFinish,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpClose,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneTcpListenerClose,
    Java_com_easytier_jni_EasyTierDataPlaneJNI_dataPlaneUdpClose
);

// Compatibility exports for older Kotlin/Java callers that used EasyTierJNI
// directly for data-plane operations.

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneAsyncOpStatus(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
) -> jint {
    logger::init();
    data_plane_api::async_op_status_jni(env, class, handle)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneAsyncOpWait(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
    timeout_ms: jlong,
) -> jint {
    logger::init();
    data_plane_api::async_op_wait_jni(env, class, handle, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneAsyncOpCancel(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
) -> jint {
    logger::init();
    data_plane_api::async_op_cancel_jni(env, class, handle)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneAsyncOpFree(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
) -> jint {
    logger::init();
    data_plane_api::async_op_free_jni(env, class, handle)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpConnectStart(
    env: JNIEnv,
    class: JClass,
    inst_name: JString,
    dst_ip: JString,
    dst_port: jint,
    timeout_ms: jlong,
) -> jlong {
    logger::init();
    data_plane_api::tcp_connect_start_jni(env, class, inst_name, dst_ip, dst_port, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpConnectFinish(
    env: JNIEnv,
    class: JClass,
    op: jlong,
) -> jobject {
    logger::init();
    data_plane_api::tcp_connect_finish_jni(env, class, op)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpBindStart(
    env: JNIEnv,
    class: JClass,
    inst_name: JString,
    local_port: jint,
    timeout_ms: jlong,
) -> jlong {
    logger::init();
    data_plane_api::tcp_bind_start_jni(env, class, inst_name, local_port, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpBindFinish(
    env: JNIEnv,
    class: JClass,
    op: jlong,
) -> jobject {
    logger::init();
    data_plane_api::tcp_bind_finish_jni(env, class, op)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpAcceptStart(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
    timeout_ms: jlong,
) -> jlong {
    logger::init();
    data_plane_api::tcp_accept_start_jni(env, class, handle, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpAcceptFinish(
    env: JNIEnv,
    class: JClass,
    op: jlong,
) -> jobject {
    logger::init();
    data_plane_api::tcp_accept_finish_jni(env, class, op)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpReadStart(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
    max_len: jint,
    timeout_ms: jlong,
) -> jlong {
    logger::init();
    data_plane_api::tcp_read_start_jni(env, class, handle, max_len, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpReadFinish(
    env: JNIEnv,
    class: JClass,
    op: jlong,
) -> jobject {
    logger::init();
    data_plane_api::tcp_read_finish_jni(env, class, op)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpWriteStart(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
    data: JByteArray,
    timeout_ms: jlong,
) -> jlong {
    logger::init();
    data_plane_api::tcp_write_start_jni(env, class, handle, data, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpWriteFinish(
    env: JNIEnv,
    class: JClass,
    op: jlong,
) -> jint {
    logger::init();
    data_plane_api::tcp_write_finish_jni(env, class, op)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneUdpBindStart(
    env: JNIEnv,
    class: JClass,
    inst_name: JString,
    local_port: jint,
    timeout_ms: jlong,
) -> jlong {
    logger::init();
    data_plane_api::udp_bind_start_jni(env, class, inst_name, local_port, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneUdpBindFinish(
    env: JNIEnv,
    class: JClass,
    op: jlong,
) -> jobject {
    logger::init();
    data_plane_api::udp_bind_finish_jni(env, class, op)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneUdpSendToStart(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
    dst_ip: JString,
    dst_port: jint,
    data: JByteArray,
    timeout_ms: jlong,
) -> jlong {
    logger::init();
    data_plane_api::udp_send_to_start_jni(env, class, handle, dst_ip, dst_port, data, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneUdpSendToFinish(
    env: JNIEnv,
    class: JClass,
    op: jlong,
) -> jint {
    logger::init();
    data_plane_api::udp_send_to_finish_jni(env, class, op)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneUdpRecvFromStart(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
    max_len: jint,
    timeout_ms: jlong,
) -> jlong {
    logger::init();
    data_plane_api::udp_recv_from_start_jni(env, class, handle, max_len, timeout_ms)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneUdpRecvFromFinish(
    env: JNIEnv,
    class: JClass,
    op: jlong,
) -> jobject {
    logger::init();
    data_plane_api::udp_recv_from_finish_jni(env, class, op)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpClose(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
) -> jint {
    logger::init();
    data_plane_api::tcp_close_jni(env, class, handle)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneTcpListenerClose(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
) -> jint {
    logger::init();
    data_plane_api::tcp_listener_close_jni(env, class, handle)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_dataPlaneUdpClose(
    env: JNIEnv,
    class: JClass,
    handle: jlong,
) -> jint {
    logger::init();
    data_plane_api::udp_close_jni(env, class, handle)
}
