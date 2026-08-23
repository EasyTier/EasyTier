//! JNI glue for the local TCP forwarder.
//!
//! Keeps a process-wide registry of running forwarders keyed by their bound
//! loopback port. Each forwarder owns the single native data-plane session of
//! its instance, so an instance can back at most one forwarder at a time; a
//! second `start` on the same instance fails with the FFI `ResourceLimit`
//! error message.

use std::{collections::HashMap, net::SocketAddrV4, sync::Mutex};

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jint;
use once_cell::sync::Lazy;

use crate::{error::throw_exception, forwarder::TcpForwarder, strings::jstring_to_cstring};

static FORWARDERS: Lazy<Mutex<HashMap<u16, TcpForwarder>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn registry() -> std::sync::MutexGuard<'static, HashMap<u16, TcpForwarder>> {
    FORWARDERS.lock().unwrap_or_else(|error| error.into_inner())
}

/// Java signature:
/// `EasyTierJNI.startTcpForwarder(instanceName, targetIp, targetPort, listenPort): int`
///
/// Returns the bound loopback port (`listenPort` when non-zero, otherwise the
/// system-assigned port). Returns -1 on failure and throws `RuntimeException`
/// with the error message when one is available.
pub(crate) fn start_tcp_forwarder_jni(
    mut env: JNIEnv,
    _class: JClass,
    instance_name: JString,
    target_ip: JString,
    target_port: jint,
    listen_port: jint,
) -> jint {
    let instance_name = match jstring_to_cstring(&mut env, &instance_name) {
        Ok(name) => name,
        Err(error) => {
            throw_exception(&mut env, &format!("Invalid instance name: {error}"));
            return -1;
        }
    };
    let instance_name = match instance_name.into_string() {
        Ok(name) => name,
        Err(_) => {
            throw_exception(&mut env, "Invalid instance name: not valid UTF-8");
            return -1;
        }
    };
    let target_ip = match jstring_to_cstring(&mut env, &target_ip) {
        Ok(ip) => ip,
        Err(error) => {
            throw_exception(&mut env, &format!("Invalid target IP: {error}"));
            return -1;
        }
    };
    let target_ip = match target_ip.to_str() {
        Ok(ip) => ip,
        Err(_) => {
            throw_exception(&mut env, "Invalid target IP: not valid UTF-8");
            return -1;
        }
    };
    let target_ip: std::net::Ipv4Addr = match target_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            throw_exception(&mut env, "Invalid target IP: expected an IPv4 address");
            return -1;
        }
    };
    if !(0..=u16::MAX as jint).contains(&target_port) {
        throw_exception(&mut env, "Invalid target port");
        return -1;
    }
    if !(0..=u16::MAX as jint).contains(&listen_port) {
        throw_exception(&mut env, "Invalid listen port");
        return -1;
    }
    let target = SocketAddrV4::new(target_ip, target_port as u16);

    let forwarder = match TcpForwarder::start(instance_name, target, listen_port as u16) {
        Ok(forwarder) => forwarder,
        Err(error) => {
            throw_exception(&mut env, &error.to_string());
            return -1;
        }
    };
    let local_port = forwarder.local_port;
    // A stale forwarder still owning this port (e.g. the OS reassigned it) is
    // stopped here, releasing the port for the new owner. Remove it before
    // inserting so its `stop` (which joins threads) runs outside the registry
    // lock and cannot block other JNI registry calls.
    let stale = registry().remove(&local_port);
    registry().insert(local_port, forwarder);
    drop(stale);
    local_port as jint
}

/// Java signature:
/// `EasyTierJNI.stopTcpForwarder(localPort): int`
///
/// Stops the forwarder bound to `localPort`. Returns 0 on success or when no
/// such forwarder exists, -1 on failure.
pub(crate) fn stop_tcp_forwarder_jni(mut env: JNIEnv, _class: JClass, local_port: jint) -> jint {
    if !(0..=u16::MAX as jint).contains(&local_port) {
        throw_exception(&mut env, "Invalid local port");
        return -1;
    }
    let forwarder = registry().remove(&(local_port as u16));
    let Some(forwarder) = forwarder else {
        return 0;
    };
    match forwarder.stop() {
        Ok(()) => 0,
        Err(error) => {
            throw_exception(&mut env, &format!("failed to stop tcp forwarder: {error}"));
            -1
        }
    }
}
