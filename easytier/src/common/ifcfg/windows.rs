use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::null_mut, sync::{Arc, Mutex, MutexGuard},
};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, NO_ERROR},
    NetworkManagement::{
        IpHelper::{
            AddIPAddress, CreateUnicastIpAddressEntry, DeleteIPAddress,
            DeleteUnicastIpAddressEntry, GetAdaptersAddresses, GetIfEntry, GetIpAddrTable,
            SetIfEntry, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH, MIB_IFROW,
            MIB_IPADDRTABLE, MIB_UNICASTIPADDRESS_ROW,
        },
        Ndis::NET_LUID_LH as NET_LUID,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, IN6_ADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
};
use winreg::{
    enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_WRITE},
    RegKey,
};
use winroute::{Route, RouteManager};

use super::{cidr_to_subnet_mask, run_shell_cmd, Error, IfConfiguerTrait};

static route_manager: Lazy<Mutex<Option<RouteManager>>> = Lazy::new(|| Mutex::new(RouteManager::new().ok()));

pub struct WindowsIfConfiger {

}

impl WindowsIfConfiger {
    pub fn get_interface_index(name: &str) -> Option<u32> {
        crate::arch::windows::find_interface_index(name).ok()
    }

    async fn add_ip_address(name: &str, addr: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        let addr_bytes = addr.octets();
        let mask = cidr_to_subnet_mask(prefix_len).octets();

        unsafe {
            let mut context = 0;
            let result = AddIPAddress(
                u32::from_be_bytes(addr_bytes) as _,
                u32::from_be_bytes(mask) as _,
                if_index as _,
                &mut context,
                std::ptr::null_mut(),
            );

            if result == NO_ERROR {
                Ok(())
            } else {
                Err(Error::RouteError(Some(format!(
                    "AddIPAddress failed with error: {}",
                    result
                ))))
            }
        }
    }

    async fn remove_ip_address(name: &str, addr: Option<Ipv4Addr>) -> Result<(), Error> {
        unsafe {
            let mut table_size = 0;
            GetIpAddrTable(std::ptr::null_mut(), &mut table_size, 0);

            let mut buffer = vec![0u8; table_size as usize];
            let table = buffer.as_mut_ptr() as *mut MIB_IPADDRTABLE;

            if GetIpAddrTable(table, &mut table_size, 0) == NO_ERROR {
                let table = &*table;
                for i in 0..table.dwNumEntries {
                    let entry = &table.table[i as usize];
                    if let Some(target_addr) = addr {
                        let entry_addr = Ipv4Addr::from(u32::from_be(entry.dwAddr as u32));
                        if entry_addr == target_addr {
                            DeleteIPAddress(entry.dwIndex);
                        }
                    } else {
                        DeleteIPAddress(entry.dwIndex);
                    }
                }
                Ok(())
            } else {
                Err(Error::RouteError(Some("Failed to get IP address table".into())))
            }
        }
    }

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
                    Err(Error::RouteError(Some("Failed to set interface status".into())))
                }
            } else {
                Err(Error::RouteError(Some("Failed to get interface entry".into())))
            }
        }
    }

    async fn set_interface_mtu(name: &str, mtu: u32) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        unsafe {
            let mut if_row = MIB_IFROW {
                wszName: [0; 256],
                dwIndex: if_index,
                dwType: 0,
                dwMtu: mtu,
                dwSpeed: 0,
                dwPhysAddrLen: 0,
                bPhysAddr: [0; 8],
                dwAdminStatus: 0,
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
                if_row.dwMtu = mtu;
                if SetIfEntry(&if_row) == NO_ERROR {
                    Ok(())
                } else {
                    Err(Error::RouteError(Some("Failed to set interface MTU".into())))
                }
            } else {
                Err(Error::RouteError(Some("Failed to get interface entry".into())))
            }
        }
    }

    async fn add_ipv6_address(name: &str, addr: Ipv6Addr, prefix_len: u8) -> Result<(), Error> {
        let Some(if_index) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };

        unsafe {
            let mut row = MIB_UNICASTIPADDRESS_ROW {
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
                Address: unsafe {
                    let mut addr_inet: SOCKADDR_INET = std::mem::zeroed();
                    addr_inet.Ipv6.sin6_family = AF_INET6 as u16;
                    addr_inet.Ipv6.sin6_addr.u.Byte = addr.octets();
                    addr_inet
                },
            };

            if CreateUnicastIpAddressEntry(&row) == NO_ERROR {
                Ok(())
            } else {
                Err(Error::RouteError(Some("Failed to add IPv6 address".into())))
            }
        }
    }

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
                                    let mut row = MIB_UNICASTIPADDRESS_ROW {
                                        InterfaceLuid: NET_LUID { Value: 0 },
                                        InterfaceIndex: if_index,
                                        Address: unsafe {
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
                                let mut row = MIB_UNICASTIPADDRESS_ROW {
                                    InterfaceLuid: NET_LUID { Value: 0 },
                                    InterfaceIndex: if_index,
                                    Address: unsafe {
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
                Err(Error::RouteError(Some("Failed to get adapter addresses".into())))
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

        let mut route = Route::new(IpAddr::V4(address), cidr_prefix);
        route.ifindex = Some(if_index);
        route.metric = Some(cost.unwrap_or(9000) as u32);

        route_manager.lock().unwrap().as_ref().ok_or(anyhow::anyhow!("route manager not initialized"))?
            .add_route(&route)
            .map_err(|e| Error::RouteError(Some(e.to_string())))
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

        let mut route = Route::new(IpAddr::V4(address), cidr_prefix).ifindex(if_index);

        route_manager.lock().unwrap().as_ref().ok_or(anyhow::anyhow!("route manager not initialized"))?
            .delete_route(&route)
            .map_err(|e| Error::RouteError(Some(e.to_string())))
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

        let mut route = Route::new(IpAddr::V6(address), cidr_prefix).ifindex(if_index).metric(9000);

        route_manager.lock().unwrap().as_ref().ok_or(anyhow::anyhow!("route manager not initialized"))?
            .add_route(&route)
            .map_err(|e| Error::RouteError(Some(e.to_string())))
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

        let mut route = Route::new(IpAddr::V6(address), cidr_prefix).ifindex(if_index);

        route_manager.lock().unwrap().as_ref().ok_or(anyhow::anyhow!("route manager not initialized"))?
            .delete_route(&route)
            .map_err(|e| Error::RouteError(Some(e.to_string())))
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
