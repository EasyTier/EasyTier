use std::sync::Mutex as StdMutex;

#[cfg(feature = "ffi-dataplane")]
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
#[cfg(feature = "ffi-dataplane")]
use easytier::launcher::{EasyTierTcpStream, EasyTierUdpSocket};
use easytier::{
    common::config::{ConfigFileControl, ConfigLoader as _, TomlConfigLoader},
    instance_manager::NetworkInstanceManager,
};
#[cfg(feature = "ffi-dataplane")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static INSTANCE_NAME_ID_MAP: once_cell::sync::Lazy<DashMap<String, uuid::Uuid>> =
    once_cell::sync::Lazy::new(DashMap::new);
static INSTANCE_MANAGER: once_cell::sync::Lazy<NetworkInstanceManager> =
    once_cell::sync::Lazy::new(NetworkInstanceManager::new);

static ERROR_MSG: once_cell::sync::Lazy<StdMutex<Vec<u8>>> =
    once_cell::sync::Lazy::new(|| StdMutex::new(Vec::new()));
#[cfg(feature = "ffi-dataplane")]
static FFI_RUNTIME: once_cell::sync::Lazy<tokio::runtime::Runtime> =
    once_cell::sync::Lazy::new(|| tokio::runtime::Runtime::new().unwrap());
#[cfg(feature = "ffi-dataplane")]
static NEXT_DATA_PLANE_HANDLE: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "ffi-dataplane")]
static DATA_PLANE_HANDLES: once_cell::sync::Lazy<DashMap<u64, DataPlaneHandle>> =
    once_cell::sync::Lazy::new(DashMap::new);

#[cfg(feature = "ffi-dataplane")]
#[derive(Clone)]
struct DataPlaneHandle {
    instance_id: uuid::Uuid,
    resource: DataPlaneResource,
}

#[cfg(feature = "ffi-dataplane")]
#[derive(Clone)]
enum DataPlaneResource {
    Tcp(Arc<tokio::sync::Mutex<EasyTierTcpStream>>),
    Udp(Arc<EasyTierUdpSocket>),
}

#[repr(C)]
pub struct KeyValuePair {
    pub key: *const std::ffi::c_char,
    pub value: *const std::ffi::c_char,
}

fn set_error_msg(msg: &str) {
    let bytes = msg.as_bytes();
    let mut msg_buf = ERROR_MSG.lock().unwrap();
    let len = bytes.len();
    msg_buf.resize(len, 0);
    msg_buf[..len].copy_from_slice(bytes);
}

// Several helper functions for FFI data plane operations to facilitate logic reuse.

#[cfg(feature = "ffi-dataplane")]
fn next_handle() -> u64 {
    NEXT_DATA_PLANE_HANDLE.fetch_add(1, Ordering::Relaxed)
}

#[cfg(feature = "ffi-dataplane")]
fn timeout_duration(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.max(1))
}

#[cfg(feature = "ffi-dataplane")]
fn timeout_secs(timeout_ms: u64) -> u64 {
    timeout_ms.div_ceil(1000).max(1)
}

#[cfg(feature = "ffi-dataplane")]
unsafe fn cstr_to_string(ptr: *const std::ffi::c_char, name: &str) -> Option<String> {
    if ptr.is_null() {
        set_error_msg(&format!("{} is null", name));
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(feature = "ffi-dataplane")]
fn get_instance_id(inst_name: &str) -> Option<uuid::Uuid> {
    INSTANCE_NAME_ID_MAP.get(inst_name).map(|id| *id.value())
}

#[cfg(feature = "ffi-dataplane")]
fn parse_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(e) => {
            set_error_msg(&format!("failed to parse ip address: {}", e));
            return None;
        }
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(feature = "ffi-dataplane")]
fn data_plane_resource(handle: u64, expected: &str) -> Option<DataPlaneResource> {
    let Some(handle) = DATA_PLANE_HANDLES.get(&handle) else {
        set_error_msg(&format!("{} handle not found", expected));
        return None;
    };
    Some(handle.resource.clone())
}

#[cfg(feature = "ffi-dataplane")]
fn get_tcp_stream(handle: u64) -> Option<Arc<tokio::sync::Mutex<EasyTierTcpStream>>> {
    match data_plane_resource(handle, "tcp stream") {
        Some(DataPlaneResource::Tcp(stream)) => Some(stream),
        Some(DataPlaneResource::Udp(_)) => {
            set_error_msg("handle is not a tcp stream");
            None
        }
        None => None,
    }
}

#[cfg(feature = "ffi-dataplane")]
fn get_udp_socket(handle: u64) -> Option<Arc<EasyTierUdpSocket>> {
    match data_plane_resource(handle, "udp socket") {
        Some(DataPlaneResource::Udp(socket)) => Some(socket),
        Some(DataPlaneResource::Tcp(_)) => {
            set_error_msg("handle is not a udp socket");
            None
        }
        None => None,
    }
}

#[cfg(feature = "ffi-dataplane")]
async fn data_plane_io<F>(timeout_ms: u64, error_prefix: &str, op: F) -> std::ffi::c_int
where
    F: Future<Output = Result<usize, std::io::Error>>,
{
    match tokio::time::timeout(timeout_duration(timeout_ms), op).await {
        Ok(Ok(n)) => n as std::ffi::c_int,
        Ok(Err(e)) => {
            set_error_msg(&format!("{}: {}", error_prefix, e));
            -1
        }
        Err(_) => {
            set_error_msg(&format!("{} timed out", error_prefix));
            -1
        }
    }
}

/// # Safety
/// Set the tun fd
#[unsafe(no_mangle)]
pub unsafe extern "C" fn set_tun_fd(
    inst_name: *const std::ffi::c_char,
    fd: std::ffi::c_int,
) -> std::ffi::c_int {
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
/// Get the last error message
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_error_msg(out: *mut *const std::ffi::c_char) {
    let msg_buf = ERROR_MSG.lock().unwrap();
    if msg_buf.is_empty() {
        unsafe {
            *out = std::ptr::null();
        }
        return;
    }
    let cstr = std::ffi::CString::new(&msg_buf[..]).unwrap();
    unsafe {
        *out = cstr.into_raw();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn free_string(s: *const std::ffi::c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = std::ffi::CString::from_raw(s as *mut std::ffi::c_char);
    }
}

/// # Safety
/// Parse the config
#[unsafe(no_mangle)]
pub unsafe extern "C" fn parse_config(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn run_network_instance(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
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

    if INSTANCE_NAME_ID_MAP.contains_key(&inst_name) {
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

/// # Safety
/// Retain the network instance
#[unsafe(no_mangle)]
pub unsafe extern "C" fn retain_network_instance(
    inst_names: *const *const std::ffi::c_char,
    length: usize,
) -> std::ffi::c_int {
    if length == 0 {
        if let Err(e) = INSTANCE_MANAGER.retain_network_instance(Vec::new()) {
            set_error_msg(&format!("failed to retain instances: {}", e));
            return -1;
        }
        INSTANCE_NAME_ID_MAP.clear();
        #[cfg(feature = "ffi-dataplane")]
        DATA_PLANE_HANDLES.clear();
        return 0;
    }

    let inst_names = unsafe {
        assert!(!inst_names.is_null());
        std::slice::from_raw_parts(inst_names, length)
            .iter()
            .map(|&name| {
                assert!(!name.is_null());
                std::ffi::CStr::from_ptr(name)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>()
    };

    let inst_ids: Vec<uuid::Uuid> = inst_names
        .iter()
        .filter_map(|name| INSTANCE_NAME_ID_MAP.get(name).map(|id| *id))
        .collect();

    if let Err(e) = INSTANCE_MANAGER.retain_network_instance(inst_ids.clone()) {
        set_error_msg(&format!("failed to retain instances: {}", e));
        return -1;
    }

    INSTANCE_NAME_ID_MAP.retain(|k, _| inst_names.contains(k));
    #[cfg(feature = "ffi-dataplane")]
    DATA_PLANE_HANDLES.retain(|_, handle| inst_ids.contains(&handle.instance_id));

    0
}

/// # Safety
/// Collect the network infos
#[unsafe(no_mangle)]
pub unsafe extern "C" fn collect_network_infos(
    infos: *mut KeyValuePair,
    max_length: usize,
) -> std::ffi::c_int {
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
/// Open a TCP stream through an EasyTier instance data plane. Returns 0 on failure.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_tcp_connect(
    inst_name: *const std::ffi::c_char,
    dst_ip: *const std::ffi::c_char,
    dst_port: std::ffi::c_ushort,
    timeout_ms: std::ffi::c_ulonglong,
) -> std::ffi::c_ulonglong {
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(dst_ip) = (unsafe { cstr_to_string(dst_ip, "dst_ip") }) else {
        return 0;
    };
    let Some(inst_id) = get_instance_id(&inst_name) else {
        set_error_msg("instance not found");
        return 0;
    };
    let Some(dst_addr) = parse_socket_addr(&dst_ip, dst_port as u16) else {
        return 0;
    };

    let timeout_s = timeout_secs(timeout_ms as u64);
    let stream = FFI_RUNTIME.block_on(async {
        INSTANCE_MANAGER
            .data_plane_tcp_connect(&inst_id, dst_addr, timeout_s)
            .await
    });
    match stream {
        Ok(stream) => {
            let handle = next_handle();
            DATA_PLANE_HANDLES.insert(
                handle,
                DataPlaneHandle {
                    instance_id: inst_id,
                    resource: DataPlaneResource::Tcp(Arc::new(tokio::sync::Mutex::new(stream))),
                },
            );
            handle as std::ffi::c_ulonglong
        }
        Err(e) => {
            set_error_msg(&format!("failed to connect tcp data plane: {}", e));
            0
        }
    }
}

/// # Safety
/// Read from a TCP data-plane stream.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_tcp_read(
    handle: std::ffi::c_ulonglong,
    buf: *mut std::ffi::c_uchar,
    len: std::ffi::c_ulong,
    timeout_ms: std::ffi::c_ulonglong,
) -> std::ffi::c_int {
    if buf.is_null() {
        set_error_msg("buf is null");
        return -1;
    }
    let Some(stream) = get_tcp_stream(handle as u64) else {
        return -1;
    };
    let buf = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    FFI_RUNTIME.block_on(async {
        let mut stream = stream.lock().await;
        data_plane_io(
            timeout_ms as u64,
            "failed to read tcp data plane",
            stream.read(buf),
        )
        .await
    })
}

/// # Safety
/// Write to a TCP data-plane stream.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_tcp_write(
    handle: std::ffi::c_ulonglong,
    buf: *const std::ffi::c_uchar,
    len: std::ffi::c_ulong,
    timeout_ms: std::ffi::c_ulonglong,
) -> std::ffi::c_int {
    if buf.is_null() {
        set_error_msg("buf is null");
        return -1;
    }
    let Some(stream) = get_tcp_stream(handle as u64) else {
        return -1;
    };
    let buf = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    FFI_RUNTIME.block_on(async {
        let mut stream = stream.lock().await;
        data_plane_io(
            timeout_ms as u64,
            "failed to write tcp data plane",
            stream.write(buf),
        )
        .await
    })
}

#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub extern "C" fn data_plane_tcp_close(handle: std::ffi::c_ulonglong) -> std::ffi::c_int {
    match data_plane_resource(handle as u64, "tcp stream") {
        Some(DataPlaneResource::Tcp(_)) => {
            DATA_PLANE_HANDLES.remove(&(handle as u64));
            0
        }
        Some(DataPlaneResource::Udp(_)) => {
            set_error_msg("handle is not a tcp stream");
            -1
        }
        None => -1,
    }
}

/// # Safety
/// Bind a UDP socket through an EasyTier instance data plane. Returns 0 on failure.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_udp_bind(
    inst_name: *const std::ffi::c_char,
    local_port: std::ffi::c_ushort,
    timeout_ms: std::ffi::c_ulonglong,
) -> std::ffi::c_ulonglong {
    let Some(inst_name) = (unsafe { cstr_to_string(inst_name, "inst_name") }) else {
        return 0;
    };
    let Some(inst_id) = get_instance_id(&inst_name) else {
        set_error_msg("instance not found");
        return 0;
    };

    let timeout_s = timeout_secs(timeout_ms as u64);
    let socket = FFI_RUNTIME.block_on(async {
        INSTANCE_MANAGER
            .data_plane_udp_bind(&inst_id, local_port as u16, timeout_s)
            .await
    });
    match socket {
        Ok(socket) => {
            let handle = next_handle();
            DATA_PLANE_HANDLES.insert(
                handle,
                DataPlaneHandle {
                    instance_id: inst_id,
                    resource: DataPlaneResource::Udp(Arc::new(socket)),
                },
            );
            handle as std::ffi::c_ulonglong
        }
        Err(e) => {
            set_error_msg(&format!("failed to bind udp data plane: {}", e));
            0
        }
    }
}

/// # Safety
/// Send a datagram through a UDP data-plane socket.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_udp_send_to(
    handle: std::ffi::c_ulonglong,
    dst_ip: *const std::ffi::c_char,
    dst_port: std::ffi::c_ushort,
    buf: *const std::ffi::c_uchar,
    len: std::ffi::c_ulong,
    timeout_ms: std::ffi::c_ulonglong,
) -> std::ffi::c_int {
    if buf.is_null() {
        set_error_msg("buf is null");
        return -1;
    }
    let Some(dst_ip) = (unsafe { cstr_to_string(dst_ip, "dst_ip") }) else {
        return -1;
    };
    let Some(dst_addr) = parse_socket_addr(&dst_ip, dst_port as u16) else {
        return -1;
    };
    let Some(socket) = get_udp_socket(handle as u64) else {
        return -1;
    };
    let buf = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    FFI_RUNTIME.block_on(data_plane_io(
        timeout_ms as u64,
        "failed to send udp data plane",
        socket.send_to(buf, dst_addr),
    ))
}

/// # Safety
/// Receive a datagram from a UDP data-plane socket.
#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn data_plane_udp_recv_from(
    handle: std::ffi::c_ulonglong,
    buf: *mut std::ffi::c_uchar,
    len: std::ffi::c_ulong,
    out_ip: *mut *const std::ffi::c_char,
    out_port: *mut std::ffi::c_ushort,
    timeout_ms: std::ffi::c_ulonglong,
) -> std::ffi::c_int {
    if buf.is_null() || out_ip.is_null() || out_port.is_null() {
        set_error_msg("output pointer is null");
        return -1;
    }
    let Some(socket) = get_udp_socket(handle as u64) else {
        return -1;
    };
    let buf = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    let ret = FFI_RUNTIME.block_on(async {
        tokio::time::timeout(timeout_duration(timeout_ms as u64), socket.recv_from(buf)).await
    });

    match ret {
        Ok(Ok((n, addr))) => {
            unsafe {
                *out_ip = std::ffi::CString::new(addr.ip().to_string())
                    .unwrap()
                    .into_raw();
                *out_port = addr.port() as std::ffi::c_ushort;
            }
            n as std::ffi::c_int
        }
        Ok(Err(e)) => {
            set_error_msg(&format!("failed to receive udp data plane: {}", e));
            -1
        }
        Err(_) => {
            set_error_msg("udp data plane receive timed out");
            -1
        }
    }
}

#[cfg(feature = "ffi-dataplane")]
#[unsafe(no_mangle)]
pub extern "C" fn data_plane_udp_close(handle: std::ffi::c_ulonglong) -> std::ffi::c_int {
    match data_plane_resource(handle as u64, "udp socket") {
        Some(DataPlaneResource::Udp(_)) => {
            DATA_PLANE_HANDLES.remove(&(handle as u64));
            0
        }
        Some(DataPlaneResource::Tcp(_)) => {
            set_error_msg("handle is not a udp socket");
            -1
        }
        None => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
