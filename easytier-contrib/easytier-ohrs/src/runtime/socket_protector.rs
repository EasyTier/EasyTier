use async_trait::async_trait;
use easytier::socket_protector::{NativeSocketProtector, set_native_socket_protector};
use once_cell::sync::Lazy;
use serde::Serialize;
use std::io;
#[cfg(target_env = "ohos")]
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SocketProtectState {
    pub enabled: bool,
    pub physical_net_id: i32,
    pub ok_count: u64,
    pub err_count: u64,
    pub last_error: String,
    pub physical_dns_servers: Vec<String>,
}

static PROTECT_ENABLED: AtomicBool = AtomicBool::new(false);
static CACHED_PHYSICAL_NET_ID: AtomicI32 = AtomicI32::new(0);
static PROTECT_OK_COUNT: AtomicU64 = AtomicU64::new(0);
static PROTECT_ERR_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_PROTECT_ERROR: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
static PHYSICAL_DNS_SERVERS: Lazy<RwLock<Vec<SocketAddr>>> = Lazy::new(|| RwLock::new(Vec::new()));

#[cfg(target_env = "ohos")]
fn set_last_error(msg: String) {
    if let Ok(mut guard) = LAST_PROTECT_ERROR.lock() {
        *guard = msg;
    }
}

fn clear_last_error() {
    if let Ok(mut guard) = LAST_PROTECT_ERROR.lock() {
        guard.clear();
    }
}

pub fn physical_dns_servers() -> Vec<SocketAddr> {
    if let Ok(guard) = PHYSICAL_DNS_SERVERS.read()
        && !guard.is_empty()
    {
        return guard.clone();
    }
    let _ = refresh_physical_network();
    PHYSICAL_DNS_SERVERS
        .read()
        .map(|g| g.clone())
        .unwrap_or_default()
}

pub fn socket_protect_state() -> SocketProtectState {
    let last_error = LAST_PROTECT_ERROR
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let dns = PHYSICAL_DNS_SERVERS
        .read()
        .map(|g| g.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    SocketProtectState {
        enabled: PROTECT_ENABLED.load(Ordering::Acquire),
        physical_net_id: CACHED_PHYSICAL_NET_ID.load(Ordering::Acquire),
        ok_count: PROTECT_OK_COUNT.load(Ordering::Acquire),
        err_count: PROTECT_ERR_COUNT.load(Ordering::Acquire),
        last_error,
        physical_dns_servers: dns,
    }
}

#[cfg(target_env = "ohos")]
mod ohos_netconn {
    use super::*;
    use std::ffi::CStr;
    use std::os::raw::c_char;

    const NETCONN_MAX_NET_SIZE: usize = 32;
    const NETCONN_MAX_BEARER_TYPE_SIZE: usize = 32;
    const NETCONN_MAX_CAP_SIZE: usize = 32;
    const NETCONN_MAX_ADDR_SIZE: usize = 32;
    const NETCONN_MAX_ROUTE_SIZE: usize = 64;
    const NETCONN_MAX_EXCLUSION_SIZE: usize = 256;
    const NETCONN_MAX_STR_LEN: usize = 256;

    const NETCONN_CAP_INTERNET: i32 = 12;
    const NETCONN_BEARER_VPN: i32 = 4;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct NetConnNetHandle {
        pub net_id: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NetConnNetCapabilities {
        link_up_bandwidth_kbps: u32,
        link_down_bandwidth_kbps: u32,
        net_caps: [i32; NETCONN_MAX_CAP_SIZE],
        net_caps_size: i32,
        bearer_types: [i32; NETCONN_MAX_BEARER_TYPE_SIZE],
        bearer_types_size: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NetConnNetAddr {
        family: u8,
        prefixlen: u8,
        port: u8,
        address: [c_char; NETCONN_MAX_STR_LEN],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NetConnRoute {
        iface: [c_char; NETCONN_MAX_STR_LEN],
        destination: NetConnNetAddr,
        gateway: NetConnNetAddr,
        has_gateway: i32,
        is_default_route: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NetConnHttpProxy {
        host: [c_char; NETCONN_MAX_STR_LEN],
        exclusion_list: [[c_char; NETCONN_MAX_STR_LEN]; NETCONN_MAX_EXCLUSION_SIZE],
        exclusion_list_size: i32,
        port: u16,
    }

    #[repr(C)]
    struct NetConnConnectionProperties {
        iface_name: [c_char; NETCONN_MAX_STR_LEN],
        domain: [c_char; NETCONN_MAX_STR_LEN],
        tcp_buffer_sizes: [c_char; NETCONN_MAX_STR_LEN],
        mtu: u16,
        net_addr_list: [NetConnNetAddr; NETCONN_MAX_ADDR_SIZE],
        net_addr_list_size: i32,
        dns_list: [NetConnNetAddr; NETCONN_MAX_ADDR_SIZE],
        dns_list_size: i32,
        route_list: [NetConnRoute; NETCONN_MAX_ROUTE_SIZE],
        route_list_size: i32,
        http_proxy: NetConnHttpProxy,
    }

    #[repr(C)]
    struct NetConnNetHandleList {
        net_handles: [NetConnNetHandle; NETCONN_MAX_NET_SIZE],
        net_handle_list_size: i32,
    }

    #[repr(C)]
    struct NetConnNetConnCallback {
        on_network_available: Option<unsafe extern "C" fn(*mut NetConnNetHandle)>,
        on_net_capabilities_change:
            Option<unsafe extern "C" fn(*mut NetConnNetHandle, *mut NetConnNetCapabilities)>,
        on_connetion_properties:
            Option<unsafe extern "C" fn(*mut NetConnNetHandle, *mut NetConnConnectionProperties)>,
        on_net_lost: Option<unsafe extern "C" fn(*mut NetConnNetHandle)>,
        on_net_unavailable: Option<unsafe extern "C" fn()>,
        on_net_block_status_change: Option<unsafe extern "C" fn(*mut NetConnNetHandle, bool)>,
    }

    #[link(name = "net_connection")]
    unsafe extern "C" {
        fn OH_NetConn_GetDefaultNet(net_handle: *mut NetConnNetHandle) -> i32;
        fn OH_NetConn_GetAllNets(net_handle_list: *mut NetConnNetHandleList) -> i32;
        fn OH_NetConn_GetNetCapabilities(
            net_handle: *mut NetConnNetHandle,
            net_capabilities: *mut NetConnNetCapabilities,
        ) -> i32;
        fn OH_NetConn_GetConnectionProperties(
            net_handle: *mut NetConnNetHandle,
            prop: *mut NetConnConnectionProperties,
        ) -> i32;
        fn OH_NetConn_BindSocket(socket_fd: i32, net_handle: *mut NetConnNetHandle) -> i32;
        fn OH_NetConn_RegisterDefaultNetConnCallback(
            callback: *mut NetConnNetConnCallback,
            callback_id: *mut u32,
        ) -> i32;
        fn OH_NetConn_UnregisterNetConnCallback(callback_id: u32) -> i32;
    }

    static CALLBACK_ID: Mutex<Option<u32>> = Mutex::new(None);

    fn is_non_vpn_physical(net_id: i32, require_internet: bool) -> bool {
        if net_id <= 0 {
            return false;
        }
        let mut handle = NetConnNetHandle { net_id };
        let mut caps: NetConnNetCapabilities = unsafe { std::mem::zeroed() };
        let rc = unsafe { OH_NetConn_GetNetCapabilities(&mut handle, &mut caps) };
        if rc != 0 {
            // If capability query fails transiently, trust OH_NetConn_GetDefaultNet's non-VPN contract.
            return !require_internet;
        }
        let bearer_len = (caps.bearer_types_size.max(0) as usize).min(NETCONN_MAX_BEARER_TYPE_SIZE);
        for &bearer in &caps.bearer_types[..bearer_len] {
            if bearer == NETCONN_BEARER_VPN {
                return false;
            }
        }
        if !require_internet {
            return true;
        }
        let cap_len = (caps.net_caps_size.max(0) as usize).min(NETCONN_MAX_CAP_SIZE);
        caps.net_caps[..cap_len].contains(&NETCONN_CAP_INTERNET)
    }

    fn update_dns_from_handle(net_id: i32) {
        if net_id <= 0 {
            if let Ok(mut guard) = PHYSICAL_DNS_SERVERS.write() {
                guard.clear();
            }
            return;
        }
        let mut handle = NetConnNetHandle { net_id };
        // Heap-allocate NetConnConnectionProperties (~80 KiB) to avoid touching the 512 KiB worker stack.
        let mut prop: Box<NetConnConnectionProperties> = unsafe { Box::new_zeroed().assume_init() };
        let rc = unsafe { OH_NetConn_GetConnectionProperties(&mut handle, prop.as_mut()) };
        if rc != 0 {
            return;
        }
        let count = (prop.dns_list_size.max(0) as usize).min(NETCONN_MAX_ADDR_SIZE);
        let mut servers = Vec::new();
        for addr in &prop.dns_list[..count] {
            let raw = unsafe { CStr::from_ptr(addr.address.as_ptr()) };
            if let Ok(s) = raw.to_str()
                && let Ok(ip) = s.trim().parse::<IpAddr>()
                && !ip.is_loopback()
                && !ip.is_unspecified()
            {
                let sa = SocketAddr::new(ip, 53);
                if !servers.contains(&sa) {
                    servers.push(sa);
                }
            }
        }
        if let Ok(mut guard) = PHYSICAL_DNS_SERVERS.write() {
            *guard = servers;
        }
    }

    pub fn query_physical_net_id() -> i32 {
        let mut handle = NetConnNetHandle { net_id: 0 };
        let rc = unsafe { OH_NetConn_GetDefaultNet(&mut handle) };
        if rc == 0 && handle.net_id > 0 && is_non_vpn_physical(handle.net_id, false) {
            CACHED_PHYSICAL_NET_ID.store(handle.net_id, Ordering::Release);
            update_dns_from_handle(handle.net_id);
            return handle.net_id;
        }

        // Fallback: scan all active nets for a non-VPN network with INTERNET capability.
        let mut list: NetConnNetHandleList = unsafe { std::mem::zeroed() };
        let rc_all = unsafe { OH_NetConn_GetAllNets(&mut list) };
        if rc_all == 0 {
            let count = (list.net_handle_list_size.max(0) as usize).min(NETCONN_MAX_NET_SIZE);
            for item in &list.net_handles[..count] {
                if is_non_vpn_physical(item.net_id, true) {
                    CACHED_PHYSICAL_NET_ID.store(item.net_id, Ordering::Release);
                    update_dns_from_handle(item.net_id);
                    return item.net_id;
                }
            }
        }

        CACHED_PHYSICAL_NET_ID.store(0, Ordering::Release);
        0
    }

    unsafe extern "C" fn on_network_available(net_handle: *mut NetConnNetHandle) {
        if net_handle.is_null() {
            return;
        }
        let net_id = unsafe { (*net_handle).net_id };
        if net_id > 0 && is_non_vpn_physical(net_id, false) {
            CACHED_PHYSICAL_NET_ID.store(net_id, Ordering::Release);
            update_dns_from_handle(net_id);
        }
    }

    unsafe extern "C" fn on_net_lost(net_handle: *mut NetConnNetHandle) {
        if net_handle.is_null() {
            return;
        }
        let lost_id = unsafe { (*net_handle).net_id };
        let _ = CACHED_PHYSICAL_NET_ID.compare_exchange(
            lost_id,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    unsafe extern "C" fn on_net_unavailable() {
        CACHED_PHYSICAL_NET_ID.store(0, Ordering::Release);
    }

    pub fn ensure_callback_registered() {
        let Ok(mut guard) = CALLBACK_ID.lock() else {
            return;
        };
        if guard.is_some() {
            return;
        }
        let mut cb = NetConnNetConnCallback {
            on_network_available: Some(on_network_available),
            on_net_capabilities_change: None,
            on_connetion_properties: None,
            on_net_lost: Some(on_net_lost),
            on_net_unavailable: Some(on_net_unavailable),
            on_net_block_status_change: None,
        };
        let mut id: u32 = 0;
        let rc = unsafe { OH_NetConn_RegisterDefaultNetConnCallback(&mut cb, &mut id) };
        if rc == 0 {
            *guard = Some(id);
        } else {
            set_last_error(format!("RegisterDefaultNetConnCallback failed rc={rc}"));
        }
    }

    pub fn unregister_callback() {
        let Ok(mut guard) = CALLBACK_ID.lock() else {
            return;
        };
        if let Some(id) = guard.take() {
            let _ = unsafe { OH_NetConn_UnregisterNetConnCallback(id) };
        }
    }

    pub fn bind_socket_to_physical(fd: i32) -> io::Result<()> {
        let mut net_id = CACHED_PHYSICAL_NET_ID.load(Ordering::Acquire);
        if net_id <= 0 {
            net_id = query_physical_net_id();
        }
        if net_id <= 0 {
            // Device currently has no active physical network; do not fail local socket creation.
            return Ok(());
        }
        let mut handle = NetConnNetHandle { net_id };
        let mut rc = unsafe { OH_NetConn_BindSocket(fd, &mut handle) };
        if rc != 0 {
            // Physical default net may have switched mid-flight; refresh once and retry.
            let refreshed = query_physical_net_id();
            if refreshed > 0 && refreshed != net_id {
                let mut retry_handle = NetConnNetHandle { net_id: refreshed };
                rc = unsafe { OH_NetConn_BindSocket(fd, &mut retry_handle) };
                net_id = refreshed;
            }
        }
        if rc == 0 {
            PROTECT_OK_COUNT.fetch_add(1, Ordering::Relaxed);
            clear_last_error();
            Ok(())
        } else {
            PROTECT_ERR_COUNT.fetch_add(1, Ordering::Relaxed);
            let msg = format!("OH_NetConn_BindSocket(fd={fd}, netId={net_id}) failed rc={rc}");
            set_last_error(msg.clone());
            Err(io::Error::other(msg))
        }
    }
}

#[cfg(not(target_env = "ohos"))]
mod ohos_netconn {
    use super::*;

    pub fn query_physical_net_id() -> i32 {
        CACHED_PHYSICAL_NET_ID.load(Ordering::Acquire)
    }

    pub fn ensure_callback_registered() {}

    pub fn unregister_callback() {}

    pub fn bind_socket_to_physical(_fd: i32) -> io::Result<()> {
        PROTECT_OK_COUNT.fetch_add(1, Ordering::Relaxed);
        clear_last_error();
        Ok(())
    }
}

struct OhosNetConnSocketProtector;

#[async_trait]
impl NativeSocketProtector for OhosNetConnSocketProtector {
    async fn protect(&self, socket_handle: u64) -> io::Result<()> {
        let fd = i32::try_from(socket_handle)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "negative socket fd",
            ));
        }
        ohos_netconn::bind_socket_to_physical(fd)
    }
}

pub fn refresh_physical_network() -> i32 {
    ohos_netconn::query_physical_net_id()
}

pub fn protect_raw_fd_if_enabled(fd: i32) -> io::Result<()> {
    if !PROTECT_ENABLED.load(Ordering::Acquire) {
        return Ok(());
    }
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "negative socket fd",
        ));
    }
    ohos_netconn::bind_socket_to_physical(fd)
}

pub fn set_socket_protect_enabled(enabled: bool) -> SocketProtectState {
    if enabled {
        PROTECT_ENABLED.store(true, Ordering::Release);
        ohos_netconn::ensure_callback_registered();
        let _ = ohos_netconn::query_physical_net_id();
        set_native_socket_protector(Some(Arc::new(OhosNetConnSocketProtector)));
    } else {
        PROTECT_ENABLED.store(false, Ordering::Release);
        set_native_socket_protector(None);
        ohos_netconn::unregister_callback();
    }
    socket_protect_state()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enable_and_disable_socket_protector_updates_state() {
        let enabled = set_socket_protect_enabled(true);
        assert!(enabled.enabled);
        let protector = OhosNetConnSocketProtector;
        protector
            .protect(3)
            .await
            .expect("host stub protect succeeds");
        let after = socket_protect_state();
        assert!(after.ok_count >= 1);
        assert_eq!(after.err_count, 0);

        let disabled = set_socket_protect_enabled(false);
        assert!(!disabled.enabled);
    }
}
