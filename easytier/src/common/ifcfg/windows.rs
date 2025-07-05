use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::null_mut,
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, NO_ERROR},
    NetworkManagement::{
        IpHelper::{
            AddIPAddress, CreateUnicastIpAddressEntry, DeleteIPAddress,
            DeleteUnicastIpAddressEntry, GetAdaptersAddresses, GetAdaptersInfo, GetIfEntry,
            GetIpInterfaceEntry, SetIfEntry, SetIpInterfaceEntry, GAA_FLAG_INCLUDE_PREFIX,
            IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_INFO, MIB_IFROW, MIB_IPINTERFACE_ROW,
            MIB_UNICASTIPADDRESS_ROW,
        },
        Ndis::NET_LUID_LH as NET_LUID,
    },
    Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN6, SOCKADDR_INET},
    System::Diagnostics::Debug::{
        FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    },
};
use winreg::{
    enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE},
    RegKey,
};
use winroute::{Route, RouteManager};

use super::{cidr_to_subnet_mask, Error, IfConfiguerTrait};

static ROUTE_MANAGER: Lazy<Mutex<Option<RouteManager>>> = Lazy::new(|| {
    let manager = RouteManager::new();
    if manager.is_err() {
        println!(
            "Failed to create route manager, cannot manage route table, error: {}",
            manager.as_ref().err().unwrap()
        );
    }
    Mutex::new(manager.ok())
});

pub struct WindowsIfConfiger {}

fn format_win_error(error: u32) -> String {
    // use FormatMessageW to get the error message
    let mut buffer = vec![0; 1024];
    let size = buffer.len() as u32;
    let flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

    unsafe {
        FormatMessageW(
            flags,
            null_mut(),
            error,
            0,
            buffer.as_mut_ptr() as *mut u16,
            size,
            null_mut(),
        );
    }
    let str_end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    format!(
        "{} (code: {})",
        String::from_utf16_lossy(&buffer[..str_end])
            .trim()
            .to_string(),
        error
    )
}

fn ipv4_to_u32(ip: &Ipv4Addr) -> u32 {
    let octets = ip.octets();
    u32::from_ne_bytes(octets)
}

impl WindowsIfConfiger {
    pub fn get_interface_index(name: &str) -> Option<u32> {
        crate::arch::windows::find_interface_index(name).ok()
    }

    #[tracing::instrument(err, ret)]
    async fn add_ip_address(name: &str, addr: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
        let if_index = Self::get_interface_index(name).ok_or(Error::NotFound)?;

        // 直接使用网络字节序（大端序）
        let ip_u32 = ipv4_to_u32(&addr);
        let mask_u32 = ipv4_to_u32(&cidr_to_subnet_mask(prefix_len));

        unsafe {
            let mut context = 0;
            let mut instance = 0;
            let result = AddIPAddress(ip_u32, mask_u32, if_index as _, &mut context, &mut instance);

            if result == NO_ERROR {
                tracing::info!(
                    "AddIPAddress success. Context: {}, Instance: {}",
                    context,
                    instance
                );
                return Ok(());
            } else {
                tracing::error!(
                    "AddIPAddress failed with error: {}",
                    format_win_error(result)
                );
                Err(Error::RouteError(Some(format!(
                    "AddIPAddress failed with error: {}",
                    format_win_error(result)
                ))))
            }
        }
    }

    #[tracing::instrument(err, ret)]
    async fn remove_ip_address(name: &str, addr: Option<Ipv4Addr>) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        unsafe {
            let mut size: u32 = 0;

            // First call to get required buffer size
            let status = GetAdaptersInfo(std::ptr::null_mut(), &mut size);
            if status != ERROR_BUFFER_OVERFLOW {
                return Err(anyhow::anyhow!(
                    "GetAdaptersInfo failed with error: {}",
                    format_win_error(status)
                )
                .into());
            }

            let mut buffer = vec![0u8; size as usize];
            let p_info = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

            let status = GetAdaptersInfo(p_info, &mut size);
            if status != ERROR_SUCCESS {
                return Err(anyhow::anyhow!(
                    "GetAdaptersInfo failed with error: {}",
                    format_win_error(status)
                )
                .into());
            }

            let mut adapter = p_info;
            let mut found = false;

            while !adapter.is_null() {
                if (*adapter).Index == if_index {
                    found = true;
                    let mut ip_entry = &(*adapter).IpAddressList;
                    loop {
                        let ip_str = std::ffi::CStr::from_ptr(
                            ip_entry.IpAddress.String.as_ptr() as *const i8
                        )
                        .to_string_lossy()
                        .into_owned();

                        let Ok(current_ip) = ip_str.parse::<Ipv4Addr>() else {
                            continue;
                        };

                        if (addr.is_none() || addr == Some(current_ip))
                            && !current_ip.is_unspecified()
                        {
                            let context = ip_entry.Context;
                            let result = DeleteIPAddress(context);
                            if result != 0 {
                                return Err(anyhow::anyhow!(
                                    "DeleteIPAddress failed with error: {}, ip: {}",
                                    format_win_error(result),
                                    current_ip
                                )
                                .into());
                            }
                            tracing::info!("DeleteIPAddress success. ip: {}", current_ip);
                        }

                        if ip_entry.Next.is_null() {
                            break;
                        }
                        ip_entry = &*ip_entry.Next;
                    }
                }

                if !found {
                    adapter = (*adapter).Next;
                } else {
                    break;
                }
            }

            if !found {
                return Err(Error::NotFound);
            }

            Ok(())
        }
    }

    #[tracing::instrument(err, ret)]
    async fn set_interface_status(name: &str, up: bool) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        unsafe {
            let mut if_row = MIB_IFROW {
                wszName: [0; 256],
                dwIndex: if_index,
                dwType: 0,
                dwMtu: 0,
                dwSpeed: 0,
                dwPhysAddrLen: 0,
                bPhysAddr: [0; 8],
                dwAdminStatus: if up { 1 } else { 2 }, // 1 = up, 2 = down
                dwOperStatus: 0,
                dwLastChange: 0,
                dwInOctets: 0,
                dwInUcastPkts: 0,
                dwInNUcastPkts: 0,
                dwInDiscards: 0,
                dwInErrors: 0,
                dwInUnknownProtos: 0,
                dwOutOctets: 0,
                dwOutUcastPkts: 0,
                dwOutNUcastPkts: 0,
                dwOutDiscards: 0,
                dwOutErrors: 0,
                dwOutQLen: 0,
                dwDescrLen: 0,
                bDescr: [0; 256],
            };

            if GetIfEntry(&mut if_row) == NO_ERROR {
                if SetIfEntry(&if_row) == NO_ERROR {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Failed to set interface status").into())
                }
            } else {
                Err(anyhow::anyhow!("Failed to get interface entry").into())
            }
        }
    }

    #[tracing::instrument(err, ret)]
    async fn set_interface_mtu(name: &str, mtu: u32) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        unsafe {
            unsafe fn set_ip_mtu(
                if_index: u32,
                mtu: u32,
                family: u16,
            ) -> windows_sys::Win32::Foundation::WIN32_ERROR {
                let mut row = MIB_IPINTERFACE_ROW {
                    Family: family,
                    InterfaceLuid: NET_LUID { Value: 0 },
                    InterfaceIndex: if_index,
                    ..std::mem::zeroed()
                };

                let result = GetIpInterfaceEntry(&mut row);
                if result == NO_ERROR {
                    println!(
                        "current mtu: {}, luid: {}, ifid: {}, family: {}, new_mtu: {}",
                        row.NlMtu, row.InterfaceLuid.Value, row.InterfaceIndex, row.Family, mtu
                    );
                    row.NlMtu = mtu;
                    // https://stackoverflow.com/questions/54857292/setipinterfaceentry-returns-error-invalid-parameter
                    row.SitePrefixLength = 0;
                    SetIpInterfaceEntry(&mut row)
                } else {
                    println!("GetIpInterfaceEntry failed: {}", format_win_error(result));
                    result
                }
            }

            // Set IPv4 MTU
            let ipv4_result = set_ip_mtu(if_index, mtu, AF_INET as u16);
            if ipv4_result == NO_ERROR {
                tracing::info!("Successfully set IPv4 interface MTU to {}", mtu);
            } else {
                tracing::warn!(
                    "Failed to set IPv4 interface MTU: {}",
                    format_win_error(ipv4_result)
                );
            }

            // Set IPv6 MTU
            let ipv6_result = set_ip_mtu(if_index, mtu, AF_INET6 as u16);
            if ipv6_result == NO_ERROR {
                tracing::info!("Successfully set IPv6 interface MTU to {}", mtu);
            } else {
                tracing::warn!(
                    "Failed to set IPv6 interface MTU: {}",
                    format_win_error(ipv6_result)
                );
            }

            // Return error only if both IPv4 and IPv6 failed
            if ipv4_result != NO_ERROR && ipv6_result != NO_ERROR {
                return Err(anyhow::anyhow!(
                    "Failed to set interface MTU. IPv4 error: {}, IPv6 error: {}",
                    format_win_error(ipv4_result),
                    format_win_error(ipv6_result)
                )
                .into());
            }

            Ok(())
        }
    }

    #[tracing::instrument(err, ret)]
    async fn add_ipv6_address(name: &str, addr: Ipv6Addr, prefix_len: u8) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        unsafe {
            let row = MIB_UNICASTIPADDRESS_ROW {
                InterfaceLuid: NET_LUID { Value: 0 },
                InterfaceIndex: if_index,
                PrefixOrigin: 1, // IpPrefixOriginManual
                SuffixOrigin: 1, // IpSuffixOriginManual
                ValidLifetime: u32::MAX,
                PreferredLifetime: u32::MAX,
                OnLinkPrefixLength: prefix_len,
                SkipAsSource: 0,
                DadState: 0, // IpDadStatePreferred
                ScopeId: std::mem::zeroed(),
                CreationTimeStamp: 0,
                Address: {
                    let mut addr_inet: SOCKADDR_INET = std::mem::zeroed();
                    addr_inet.Ipv6.sin6_family = AF_INET6 as u16;
                    addr_inet.Ipv6.sin6_addr.u.Byte = addr.octets();
                    addr_inet
                },
            };

            let result = CreateUnicastIpAddressEntry(&row);
            if result == NO_ERROR {
                Ok(())
            } else {
                Err(
                    anyhow::anyhow!("Failed to add IPv6 address: {}", format_win_error(result))
                        .into(),
                )
            }
        }
    }

    #[tracing::instrument(err, ret)]
    async fn remove_ipv6_address(name: &str, addr: Option<Ipv6Addr>) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        unsafe {
            let mut buffer_size = 0u32;
            GetAdaptersAddresses(
                AF_INET6 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                null_mut(),
                null_mut(),
                &mut buffer_size,
            );

            let mut buffer = vec![0u8; buffer_size as usize];
            let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

            if GetAdaptersAddresses(
                AF_INET6 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                null_mut(),
                adapter_addresses,
                &mut buffer_size,
            ) == NO_ERROR
            {
                let mut current = adapter_addresses;
                while !current.is_null() {
                    let adapter = &*current;
                    if adapter.Ipv6IfIndex == if_index {
                        let mut unicast = adapter.FirstUnicastAddress;
                        while !unicast.is_null() {
                            let addr_entry = &*unicast;
                            if let Some(target_addr) = addr {
                                let sockaddr = addr_entry.Address.lpSockaddr;
                                let sockaddr_in6 = &*(sockaddr as *const SOCKADDR_IN6);
                                let current_addr = Ipv6Addr::from(sockaddr_in6.sin6_addr.u.Byte);
                                if current_addr == target_addr {
                                    let row = MIB_UNICASTIPADDRESS_ROW {
                                        InterfaceLuid: NET_LUID { Value: 0 },
                                        InterfaceIndex: if_index,
                                        Address: {
                                            let mut addr_inet: SOCKADDR_INET = std::mem::zeroed();
                                            addr_inet.Ipv6 = *sockaddr_in6;
                                            addr_inet
                                        },
                                        PrefixOrigin: 0,
                                        SuffixOrigin: 0,
                                        ValidLifetime: 0,
                                        PreferredLifetime: 0,
                                        OnLinkPrefixLength: 0,
                                        SkipAsSource: 0,
                                        DadState: 0,
                                        ScopeId: std::mem::zeroed(),
                                        CreationTimeStamp: 0,
                                    };
                                    DeleteUnicastIpAddressEntry(&row);
                                }
                            } else {
                                let sockaddr = addr_entry.Address.lpSockaddr;
                                let sockaddr_in6 = &*(sockaddr as *const SOCKADDR_IN6);
                                let row = MIB_UNICASTIPADDRESS_ROW {
                                    InterfaceLuid: NET_LUID { Value: 0 },
                                    InterfaceIndex: if_index,
                                    Address: {
                                        let mut addr_inet: SOCKADDR_INET = std::mem::zeroed();
                                        addr_inet.Ipv6 = *sockaddr_in6;
                                        addr_inet
                                    },
                                    PrefixOrigin: 0,
                                    SuffixOrigin: 0,
                                    ValidLifetime: 0,
                                    PreferredLifetime: 0,
                                    OnLinkPrefixLength: 0,
                                    SkipAsSource: 0,
                                    DadState: 0,
                                    ScopeId: std::mem::zeroed(),
                                    CreationTimeStamp: 0,
                                };
                                DeleteUnicastIpAddressEntry(&row);
                            }
                            unicast = addr_entry.Next;
                        }
                        break;
                    }
                    current = adapter.Next;
                }
                Ok(())
            } else {
                Err(Error::RouteError(Some(
                    "Failed to get adapter addresses".into(),
                )))
            }
        }
    }
}

#[async_trait]
impl IfConfiguerTrait for WindowsIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        let route = Route::new(IpAddr::V4(address), cidr_prefix)
            .ifindex(if_index)
            .metric(cost.unwrap_or(9000) as u32);

        ROUTE_MANAGER
            .lock()
            .unwrap()
            .as_ref()
            .ok_or(anyhow::anyhow!("route manager not initialized"))?
            .add_route(&route)
            .map_err(|e| anyhow::anyhow!("Failed to add route: {}", e).into())
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        let route = Route::new(IpAddr::V4(address), cidr_prefix).ifindex(if_index);

        ROUTE_MANAGER
            .lock()
            .unwrap()
            .as_ref()
            .ok_or(anyhow::anyhow!("route manager not initialized"))?
            .delete_route(&route)
            .map_err(|e| anyhow::anyhow!("Failed to delete route: {}", e).into())
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        Self::add_ip_address(name, address, cidr_prefix).await
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        Self::set_interface_status(name, up).await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Addr>) -> Result<(), Error> {
        Self::remove_ip_address(name, ip).await
    }

    async fn wait_interface_show(&self, name: &str) -> Result<(), Error> {
        Ok(
            tokio::time::timeout(std::time::Duration::from_secs(10), async move {
                loop {
                    if let Some(idx) = Self::get_interface_index(name) {
                        tracing::info!(?name, ?idx, "Interface found");
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Ok::<(), Error>(())
            })
            .await??,
        )
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        println!("set_mtu: {} {}", name, mtu);
        Self::set_interface_mtu(name, mtu).await
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        Self::add_ipv6_address(name, address, cidr_prefix).await
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Addr>) -> Result<(), Error> {
        Self::remove_ipv6_address(name, ip).await
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        let route = Route::new(IpAddr::V6(address), cidr_prefix)
            .ifindex(if_index)
            .metric(cost.unwrap_or(9000) as u32);

        ROUTE_MANAGER
            .lock()
            .unwrap()
            .as_ref()
            .ok_or(anyhow::anyhow!("route manager not initialized"))?
            .add_route(&route)
            .map_err(|e| anyhow::anyhow!("Failed to add route: {}", e).into())
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        let route = Route::new(IpAddr::V6(address), cidr_prefix).ifindex(if_index);

        ROUTE_MANAGER
            .lock()
            .unwrap()
            .as_ref()
            .ok_or(anyhow::anyhow!("route manager not initialized"))?
            .delete_route(&route)
            .map_err(|e| anyhow::anyhow!("Failed to delete route: {}", e).into())
    }
}

pub struct RegistryManager;

impl RegistryManager {
    pub const IPV4_TCPIP_INTERFACE_PREFIX: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";
    pub const IPV6_TCPIP_INTERFACE_PREFIX: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\";
    pub const NETBT_INTERFACE_PREFIX: &str =
        r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_";

    pub fn reg_delete_obsoleted_items(dev_name: &str) -> io::Result<()> {
        use winreg::{enums::HKEY_LOCAL_MACHINE, enums::KEY_ALL_ACCESS, RegKey};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let profiles_key = hklm.open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
            KEY_ALL_ACCESS,
        )?;
        let unmanaged_key = hklm.open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
            KEY_ALL_ACCESS,
        )?;
        // collect subkeys to delete
        let mut keys_to_delete = Vec::new();
        let mut keys_to_delete_unmanaged = Vec::new();
        for subkey_name in profiles_key.enum_keys().filter_map(Result::ok) {
            let subkey = profiles_key.open_subkey(&subkey_name)?;
            // check if ProfileName contains "et"
            match subkey.get_value::<String, _>("ProfileName") {
                Ok(profile_name) => {
                    if profile_name.contains("et_")
                        || (!dev_name.is_empty() && dev_name == profile_name)
                    {
                        keys_to_delete.push(subkey_name);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to read ProfileName for subkey {}: {}",
                        subkey_name,
                        e
                    );
                }
            }
        }
        for subkey_name in unmanaged_key.enum_keys().filter_map(Result::ok) {
            let subkey = unmanaged_key.open_subkey(&subkey_name)?;
            // check if ProfileName contains "et"
            match subkey.get_value::<String, _>("Description") {
                Ok(profile_name) => {
                    if profile_name.contains("et_")
                        || (!dev_name.is_empty() && dev_name == profile_name)
                    {
                        keys_to_delete_unmanaged.push(subkey_name);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to read ProfileName for subkey {}: {}",
                        subkey_name,
                        e
                    );
                }
            }
        }
        // delete collected subkeys
        if !keys_to_delete.is_empty() {
            for subkey_name in keys_to_delete {
                match profiles_key.delete_subkey_all(&subkey_name) {
                    Ok(_) => tracing::trace!("Successfully deleted subkey: {}", subkey_name),
                    Err(e) => tracing::error!("Failed to delete subkey {}: {}", subkey_name, e),
                }
            }
        }
        if !keys_to_delete_unmanaged.is_empty() {
            for subkey_name in keys_to_delete_unmanaged {
                match unmanaged_key.delete_subkey_all(&subkey_name) {
                    Ok(_) => tracing::trace!("Successfully deleted subkey: {}", subkey_name),
                    Err(e) => tracing::error!("Failed to delete subkey {}: {}", subkey_name, e),
                }
            }
        }
        Ok(())
    }

    pub fn reg_change_catrgory_in_profile(dev_name: &str) -> io::Result<()> {
        use winreg::{enums::HKEY_LOCAL_MACHINE, enums::KEY_ALL_ACCESS, RegKey};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let profiles_key = hklm.open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
            KEY_ALL_ACCESS,
        )?;

        for subkey_name in profiles_key.enum_keys().filter_map(Result::ok) {
            let subkey = profiles_key.open_subkey_with_flags(&subkey_name, KEY_ALL_ACCESS)?;
            match subkey.get_value::<String, _>("ProfileName") {
                Ok(profile_name) => {
                    if !dev_name.is_empty() && dev_name == profile_name {
                        match subkey.set_value("Category", &1u32) {
                            Ok(_) => tracing::trace!("Successfully set Category in registry"),
                            Err(e) => tracing::error!("Failed to set Category in registry: {}", e),
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to read ProfileName for subkey {}: {}",
                        subkey_name,
                        e
                    );
                }
            }
        }
        Ok(())
    }

    // 根据接口名称查找 GUID
    pub fn find_interface_guid(interface_name: &str) -> io::Result<String> {
        // 注册表路径：所有网络接口的根目录
        let network_key_path =
            r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let network_key = hklm.open_subkey_with_flags(network_key_path, KEY_READ)?;

        // 遍历该路径下的所有 GUID 子键
        for guid in network_key.enum_keys().map_while(Result::ok) {
            if let Ok(guid_key) = network_key.open_subkey_with_flags(&guid, KEY_READ) {
                // 检查 Connection/Name 是否匹配目标接口名
                if let Ok(conn_key) = guid_key.open_subkey_with_flags("Connection", KEY_READ) {
                    if let Ok(name) = conn_key.get_value::<String, _>("Name") {
                        if name == interface_name {
                            return Ok(guid);
                        }
                    }
                }
            }
        }

        // 如果没有找到对应的接口
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Interface not found",
        ))
    }

    // 打开注册表键
    pub fn open_interface_key(interface_guid: &str, prefix: &str) -> io::Result<RegKey> {
        let path = format!(r"{}{}", prefix, interface_guid);
        let hkey_local_machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        hkey_local_machine.open_subkey_with_flags(&path, KEY_WRITE)
    }

    // 禁用动态 DNS 更新
    // disableDynamicUpdates sets the appropriate registry values to prevent the
    // Windows DHCP client from sending dynamic DNS updates for our interface to
    // AD domain controllers.
    pub fn disable_dynamic_updates(interface_guid: &str) -> io::Result<()> {
        let prefixes = [
            Self::IPV4_TCPIP_INTERFACE_PREFIX,
            Self::IPV6_TCPIP_INTERFACE_PREFIX,
        ];

        for prefix in &prefixes {
            let key = match Self::open_interface_key(interface_guid, prefix) {
                Ok(k) => k,
                Err(e) => {
                    // 模拟 mute-key-not-found-if-closing 行为
                    if matches!(e.kind(), io::ErrorKind::NotFound) {
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            };

            key.set_value("RegistrationEnabled", &0u32)?;
            key.set_value("DisableDynamicUpdate", &1u32)?;
            key.set_value("MaxNumberOfAddressesToRegister", &0u32)?;
        }

        Ok(())
    }

    // 设置单个 DWORD 值到指定的注册表路径下
    fn set_single_dword(
        interface_guid: &str,
        prefix: &str,
        value_name: &str,
        data: u32,
    ) -> io::Result<()> {
        let key = match Self::open_interface_key(interface_guid, prefix) {
            Ok(k) => k,
            Err(e) => {
                // 模拟 muteKeyNotFoundIfClosing 行为：忽略 Key Not Found 错误
                return if matches!(e.kind(), io::ErrorKind::NotFound) {
                    Ok(())
                } else {
                    Err(e)
                };
            }
        };

        key.set_value(value_name, &data)?;
        Ok(())
    }

    // 禁用 NetBIOS 名称解析请求
    pub fn disable_netbios(interface_guid: &str) -> io::Result<()> {
        Self::set_single_dword(
            interface_guid,
            Self::NETBT_INTERFACE_PREFIX,
            "NetbiosOptions",
            2,
        )
    }
}
