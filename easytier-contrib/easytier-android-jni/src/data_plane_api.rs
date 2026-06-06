use std::{
    ffi::{CStr, c_char},
    ptr,
};

use easytier_ffi::{
    data_plane_async_op_cancel, data_plane_async_op_free, data_plane_async_op_status,
    data_plane_async_op_wait, data_plane_free_bytes, data_plane_tcp_accept_finish,
    data_plane_tcp_accept_start, data_plane_tcp_bind_finish, data_plane_tcp_bind_start,
    data_plane_tcp_close, data_plane_tcp_connect_finish, data_plane_tcp_connect_start,
    data_plane_tcp_listener_close, data_plane_tcp_read_finish, data_plane_tcp_read_start,
    data_plane_tcp_write_finish, data_plane_tcp_write_start, data_plane_udp_bind_finish,
    data_plane_udp_bind_start, data_plane_udp_close, data_plane_udp_recv_from_finish,
    data_plane_udp_recv_from_start, data_plane_udp_send_to_finish, data_plane_udp_send_to_start,
    free_string,
};
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject, JString, JValue},
    sys::{jint, jlong, jobject},
};

use crate::{
    error::{get_last_error, throw_exception},
    strings::jstring_to_cstring,
};

const SOCKET_ADDR_CLASS: &str = "com/easytier/jni/DataPlaneSocketAddress";
const TCP_CONNECT_RESULT_CLASS: &str = "com/easytier/jni/DataPlaneTcpConnectResult";
const TCP_BIND_RESULT_CLASS: &str = "com/easytier/jni/DataPlaneTcpBindResult";
const TCP_ACCEPT_RESULT_CLASS: &str = "com/easytier/jni/DataPlaneTcpAcceptResult";
const TCP_READ_RESULT_CLASS: &str = "com/easytier/jni/DataPlaneTcpReadResult";
const UDP_BIND_RESULT_CLASS: &str = "com/easytier/jni/DataPlaneUdpBindResult";
const UDP_RECV_RESULT_CLASS: &str = "com/easytier/jni/DataPlaneUdpRecvResult";

fn timeout_from_jlong(timeout_ms: jlong) -> u64 {
    timeout_ms.max(0) as u64
}

fn port_from_jint(env: &mut JNIEnv, value: jint, name: &str) -> Option<u16> {
    match u16::try_from(value) {
        Ok(port) => Some(port),
        Err(_) => {
            throw_exception(env, &format!("Invalid {}: {}", name, value));
            None
        }
    }
}

fn len_from_jint(env: &mut JNIEnv, value: jint, name: &str) -> Option<u32> {
    match u32::try_from(value) {
        Ok(len) => Some(len),
        Err(_) => {
            throw_exception(env, &format!("Invalid {}: {}", name, value));
            None
        }
    }
}

fn throw_last(env: &mut JNIEnv) {
    let message = get_last_error().unwrap_or_else(|| "EasyTier data-plane call failed".to_string());
    throw_exception(env, &message);
}

unsafe fn take_ffi_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    free_string(ptr);
    value
}

fn new_socket_addr<'local>(
    env: &mut JNIEnv<'local>,
    ip: String,
    port: u16,
) -> Option<JObject<'local>> {
    let class = match env.find_class(SOCKET_ADDR_CLASS) {
        Ok(class) => class,
        Err(err) => {
            throw_exception(
                env,
                &format!("Failed to find socket address class: {:?}", err),
            );
            return None;
        }
    };
    let ip = match env.new_string(ip) {
        Ok(ip) => ip,
        Err(err) => {
            throw_exception(env, &format!("Failed to create IP string: {:?}", err));
            return None;
        }
    };
    match env.new_object(
        class,
        "(Ljava/lang/String;I)V",
        &[JValue::Object(&ip), JValue::Int(port as jint)],
    ) {
        Ok(addr) => Some(addr),
        Err(err) => {
            throw_exception(env, &format!("Failed to create socket address: {:?}", err));
            None
        }
    }
}

fn new_handle_addr_result(
    env: &mut JNIEnv,
    class_name: &str,
    handle: u64,
    ip: String,
    port: u16,
) -> jobject {
    let Some(addr) = new_socket_addr(env, ip, port) else {
        return ptr::null_mut();
    };
    let class = match env.find_class(class_name) {
        Ok(class) => class,
        Err(err) => {
            throw_exception(env, &format!("Failed to find result class: {:?}", err));
            return ptr::null_mut();
        }
    };
    let sig = format!("(JL{};)V", SOCKET_ADDR_CLASS);
    match env.new_object(
        class,
        sig.as_str(),
        &[JValue::Long(handle as jlong), JValue::Object(&addr)],
    ) {
        Ok(result) => result.into_raw(),
        Err(err) => {
            throw_exception(env, &format!("Failed to create result object: {:?}", err));
            ptr::null_mut()
        }
    }
}

fn close_tcp_stream_on_null(result: jobject, handle: u64) -> jobject {
    if result.is_null() {
        let _ = data_plane_tcp_close(handle);
    }
    result
}

fn close_tcp_listener_on_null(result: jobject, handle: u64) -> jobject {
    if result.is_null() {
        let _ = data_plane_tcp_listener_close(handle);
    }
    result
}

fn close_udp_socket_on_null(result: jobject, handle: u64) -> jobject {
    if result.is_null() {
        let _ = data_plane_udp_close(handle);
    }
    result
}

fn read_owned_bytes(ptr: *const u8, len: u32) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec();
    data_plane_free_bytes(ptr, len);
    bytes
}

pub(crate) fn async_op_status_jni(_env: JNIEnv, _class: JClass, handle: jlong) -> jint {
    data_plane_async_op_status(handle as u64)
}

pub(crate) fn async_op_wait_jni(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    timeout_ms: jlong,
) -> jint {
    data_plane_async_op_wait(handle as u64, timeout_ms.max(0) as u64)
}

pub(crate) fn async_op_cancel_jni(_env: JNIEnv, _class: JClass, handle: jlong) -> jint {
    data_plane_async_op_cancel(handle as u64)
}

pub(crate) fn async_op_free_jni(_env: JNIEnv, _class: JClass, handle: jlong) -> jint {
    data_plane_async_op_free(handle as u64)
}

pub(crate) fn tcp_connect_start_jni(
    mut env: JNIEnv,
    _class: JClass,
    inst_name: JString,
    dst_ip: JString,
    dst_port: jint,
    timeout_ms: jlong,
) -> jlong {
    let inst_name = match jstring_to_cstring(&mut env, &inst_name) {
        Ok(value) => value,
        Err(err) => {
            throw_exception(&mut env, &format!("Invalid instance name: {}", err));
            return 0;
        }
    };
    let dst_ip = match jstring_to_cstring(&mut env, &dst_ip) {
        Ok(value) => value,
        Err(err) => {
            throw_exception(&mut env, &format!("Invalid destination IP: {}", err));
            return 0;
        }
    };
    let Some(dst_port) = port_from_jint(&mut env, dst_port, "destination port") else {
        return 0;
    };
    let op = unsafe {
        data_plane_tcp_connect_start(
            inst_name.as_ptr(),
            dst_ip.as_ptr(),
            dst_port,
            timeout_ms.max(0) as u64,
        )
    };
    if op == 0 {
        throw_last(&mut env);
    }
    op as jlong
}

pub(crate) fn tcp_connect_finish_jni(mut env: JNIEnv, _class: JClass, op: jlong) -> jobject {
    let mut ip: *const c_char = ptr::null();
    let mut port = 0u16;
    let handle = unsafe { data_plane_tcp_connect_finish(op as u64, &mut ip, &mut port) };
    if handle == 0 {
        throw_last(&mut env);
        return ptr::null_mut();
    }
    close_tcp_stream_on_null(
        new_handle_addr_result(
            &mut env,
            TCP_CONNECT_RESULT_CLASS,
            handle,
            unsafe { take_ffi_string(ip) },
            port,
        ),
        handle,
    )
}

pub(crate) fn tcp_bind_start_jni(
    mut env: JNIEnv,
    _class: JClass,
    inst_name: JString,
    local_port: jint,
    timeout_ms: jlong,
) -> jlong {
    let inst_name = match jstring_to_cstring(&mut env, &inst_name) {
        Ok(value) => value,
        Err(err) => {
            throw_exception(&mut env, &format!("Invalid instance name: {}", err));
            return 0;
        }
    };
    let Some(local_port) = port_from_jint(&mut env, local_port, "local port") else {
        return 0;
    };
    let op = unsafe {
        data_plane_tcp_bind_start(
            inst_name.as_ptr(),
            local_port,
            timeout_from_jlong(timeout_ms),
        )
    };
    if op == 0 {
        throw_last(&mut env);
    }
    op as jlong
}

pub(crate) fn tcp_bind_finish_jni(mut env: JNIEnv, _class: JClass, op: jlong) -> jobject {
    let mut ip: *const c_char = ptr::null();
    let mut port = 0u16;
    let handle = unsafe { data_plane_tcp_bind_finish(op as u64, &mut ip, &mut port) };
    if handle == 0 {
        throw_last(&mut env);
        return ptr::null_mut();
    }
    close_tcp_listener_on_null(
        new_handle_addr_result(
            &mut env,
            TCP_BIND_RESULT_CLASS,
            handle,
            unsafe { take_ffi_string(ip) },
            port,
        ),
        handle,
    )
}

pub(crate) fn tcp_accept_start_jni(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    timeout_ms: jlong,
) -> jlong {
    let op = unsafe { data_plane_tcp_accept_start(handle as u64, timeout_from_jlong(timeout_ms)) };
    if op == 0 {
        throw_last(&mut env);
    }
    op as jlong
}

pub(crate) fn tcp_accept_finish_jni(mut env: JNIEnv, _class: JClass, op: jlong) -> jobject {
    let mut local_ip: *const c_char = ptr::null();
    let mut local_port = 0u16;
    let mut peer_ip: *const c_char = ptr::null();
    let mut peer_port = 0u16;
    let handle = unsafe {
        data_plane_tcp_accept_finish(
            op as u64,
            &mut local_ip,
            &mut local_port,
            &mut peer_ip,
            &mut peer_port,
        )
    };
    if handle == 0 {
        throw_last(&mut env);
        return ptr::null_mut();
    }
    let Some(local_addr) =
        new_socket_addr(&mut env, unsafe { take_ffi_string(local_ip) }, local_port)
    else {
        free_string(peer_ip);
        let _ = data_plane_tcp_close(handle);
        return ptr::null_mut();
    };
    let Some(peer_addr) = new_socket_addr(&mut env, unsafe { take_ffi_string(peer_ip) }, peer_port)
    else {
        let _ = data_plane_tcp_close(handle);
        return ptr::null_mut();
    };
    let class = match env.find_class(TCP_ACCEPT_RESULT_CLASS) {
        Ok(class) => class,
        Err(err) => {
            throw_exception(
                &mut env,
                &format!("Failed to find accept result class: {:?}", err),
            );
            let _ = data_plane_tcp_close(handle);
            return ptr::null_mut();
        }
    };
    let sig = format!("(JL{};L{};)V", SOCKET_ADDR_CLASS, SOCKET_ADDR_CLASS);
    let result = match env.new_object(
        class,
        sig.as_str(),
        &[
            JValue::Long(handle as jlong),
            JValue::Object(&local_addr),
            JValue::Object(&peer_addr),
        ],
    ) {
        Ok(result) => result.into_raw(),
        Err(err) => {
            throw_exception(
                &mut env,
                &format!("Failed to create accept result: {:?}", err),
            );
            ptr::null_mut()
        }
    };
    close_tcp_stream_on_null(result, handle)
}

pub(crate) fn tcp_read_start_jni(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    max_len: jint,
    timeout_ms: jlong,
) -> jlong {
    let Some(max_len) = len_from_jint(&mut env, max_len, "max length") else {
        return 0;
    };
    let op = unsafe {
        data_plane_tcp_read_start(handle as u64, max_len, timeout_from_jlong(timeout_ms))
    };
    if op == 0 {
        throw_last(&mut env);
    }
    op as jlong
}

pub(crate) fn tcp_read_finish_jni(mut env: JNIEnv, _class: JClass, op: jlong) -> jobject {
    let mut ptr: *const u8 = ptr::null();
    let mut len = 0u32;
    let ret = unsafe { data_plane_tcp_read_finish(op as u64, &mut ptr, &mut len) };
    if ret < 0 {
        throw_last(&mut env);
        return ptr::null_mut();
    }
    let bytes = read_owned_bytes(ptr, len);
    let array = match env.byte_array_from_slice(&bytes) {
        Ok(array) => array,
        Err(err) => {
            throw_exception(&mut env, &format!("Failed to create byte array: {:?}", err));
            return ptr::null_mut();
        }
    };
    let class = match env.find_class(TCP_READ_RESULT_CLASS) {
        Ok(class) => class,
        Err(err) => {
            throw_exception(
                &mut env,
                &format!("Failed to find read result class: {:?}", err),
            );
            return ptr::null_mut();
        }
    };
    match env.new_object(class, "([B)V", &[JValue::Object(&array)]) {
        Ok(result) => result.into_raw(),
        Err(err) => {
            throw_exception(
                &mut env,
                &format!("Failed to create read result: {:?}", err),
            );
            ptr::null_mut()
        }
    }
}

pub(crate) fn tcp_write_start_jni(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
    timeout_ms: jlong,
) -> jlong {
    let data = match env.convert_byte_array(&data) {
        Ok(data) => data,
        Err(err) => {
            throw_exception(&mut env, &format!("Invalid write buffer: {:?}", err));
            return 0;
        }
    };
    let ptr = if data.is_empty() {
        ptr::null()
    } else {
        data.as_ptr()
    };
    let op = unsafe {
        data_plane_tcp_write_start(
            handle as u64,
            ptr,
            data.len() as u32,
            timeout_from_jlong(timeout_ms),
        )
    };
    if op == 0 {
        throw_last(&mut env);
    }
    op as jlong
}

pub(crate) fn tcp_write_finish_jni(mut env: JNIEnv, _class: JClass, op: jlong) -> jint {
    let ret = data_plane_tcp_write_finish(op as u64);
    if ret < 0 {
        throw_last(&mut env);
    }
    ret
}

pub(crate) fn udp_bind_start_jni(
    mut env: JNIEnv,
    _class: JClass,
    inst_name: JString,
    local_port: jint,
    timeout_ms: jlong,
) -> jlong {
    let inst_name = match jstring_to_cstring(&mut env, &inst_name) {
        Ok(value) => value,
        Err(err) => {
            throw_exception(&mut env, &format!("Invalid instance name: {}", err));
            return 0;
        }
    };
    let Some(local_port) = port_from_jint(&mut env, local_port, "local port") else {
        return 0;
    };
    let op = unsafe {
        data_plane_udp_bind_start(
            inst_name.as_ptr(),
            local_port,
            timeout_from_jlong(timeout_ms),
        )
    };
    if op == 0 {
        throw_last(&mut env);
    }
    op as jlong
}

pub(crate) fn udp_bind_finish_jni(mut env: JNIEnv, _class: JClass, op: jlong) -> jobject {
    let mut ip: *const c_char = ptr::null();
    let mut port = 0u16;
    let handle = unsafe { data_plane_udp_bind_finish(op as u64, &mut ip, &mut port) };
    if handle == 0 {
        throw_last(&mut env);
        return ptr::null_mut();
    }
    close_udp_socket_on_null(
        new_handle_addr_result(
            &mut env,
            UDP_BIND_RESULT_CLASS,
            handle,
            unsafe { take_ffi_string(ip) },
            port,
        ),
        handle,
    )
}

pub(crate) fn udp_send_to_start_jni(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    dst_ip: JString,
    dst_port: jint,
    data: JByteArray,
    timeout_ms: jlong,
) -> jlong {
    let dst_ip = match jstring_to_cstring(&mut env, &dst_ip) {
        Ok(value) => value,
        Err(err) => {
            throw_exception(&mut env, &format!("Invalid destination IP: {}", err));
            return 0;
        }
    };
    let Some(dst_port) = port_from_jint(&mut env, dst_port, "destination port") else {
        return 0;
    };
    let data = match env.convert_byte_array(&data) {
        Ok(data) => data,
        Err(err) => {
            throw_exception(&mut env, &format!("Invalid UDP send buffer: {:?}", err));
            return 0;
        }
    };
    let ptr = if data.is_empty() {
        ptr::null()
    } else {
        data.as_ptr()
    };
    let op = unsafe {
        data_plane_udp_send_to_start(
            handle as u64,
            dst_ip.as_ptr(),
            dst_port,
            ptr,
            data.len() as u32,
            timeout_from_jlong(timeout_ms),
        )
    };
    if op == 0 {
        throw_last(&mut env);
    }
    op as jlong
}

pub(crate) fn udp_send_to_finish_jni(mut env: JNIEnv, _class: JClass, op: jlong) -> jint {
    let ret = data_plane_udp_send_to_finish(op as u64);
    if ret < 0 {
        throw_last(&mut env);
    }
    ret
}

pub(crate) fn udp_recv_from_start_jni(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    max_len: jint,
    timeout_ms: jlong,
) -> jlong {
    let Some(max_len) = len_from_jint(&mut env, max_len, "max length") else {
        return 0;
    };
    let op = unsafe {
        data_plane_udp_recv_from_start(handle as u64, max_len, timeout_from_jlong(timeout_ms))
    };
    if op == 0 {
        throw_last(&mut env);
    }
    op as jlong
}

pub(crate) fn udp_recv_from_finish_jni(mut env: JNIEnv, _class: JClass, op: jlong) -> jobject {
    let mut ptr: *const u8 = ptr::null();
    let mut len = 0u32;
    let mut ip: *const c_char = ptr::null();
    let mut port = 0u16;
    let ret = unsafe {
        data_plane_udp_recv_from_finish(op as u64, &mut ptr, &mut len, &mut ip, &mut port)
    };
    if ret < 0 {
        throw_last(&mut env);
        return ptr::null_mut();
    }
    let bytes = read_owned_bytes(ptr, len);
    let array = match env.byte_array_from_slice(&bytes) {
        Ok(array) => array,
        Err(err) => {
            free_string(ip);
            throw_exception(&mut env, &format!("Failed to create byte array: {:?}", err));
            return ptr::null_mut();
        }
    };
    let Some(peer_addr) = new_socket_addr(&mut env, unsafe { take_ffi_string(ip) }, port) else {
        return ptr::null_mut();
    };
    let class = match env.find_class(UDP_RECV_RESULT_CLASS) {
        Ok(class) => class,
        Err(err) => {
            throw_exception(
                &mut env,
                &format!("Failed to find UDP recv result class: {:?}", err),
            );
            return ptr::null_mut();
        }
    };
    let sig = format!("([BL{};)V", SOCKET_ADDR_CLASS);
    match env.new_object(
        class,
        sig.as_str(),
        &[JValue::Object(&array), JValue::Object(&peer_addr)],
    ) {
        Ok(result) => result.into_raw(),
        Err(err) => {
            throw_exception(
                &mut env,
                &format!("Failed to create UDP recv result: {:?}", err),
            );
            ptr::null_mut()
        }
    }
}

pub(crate) fn tcp_close_jni(mut env: JNIEnv, _class: JClass, handle: jlong) -> jint {
    let ret = data_plane_tcp_close(handle as u64);
    if ret != 0 {
        throw_last(&mut env);
    }
    ret
}

pub(crate) fn tcp_listener_close_jni(mut env: JNIEnv, _class: JClass, handle: jlong) -> jint {
    let ret = data_plane_tcp_listener_close(handle as u64);
    if ret != 0 {
        throw_last(&mut env);
    }
    ret
}

pub(crate) fn udp_close_jni(mut env: JNIEnv, _class: JClass, handle: jlong) -> jint {
    let ret = data_plane_udp_close(handle as u64);
    if ret != 0 {
        throw_last(&mut env);
    }
    ret
}
