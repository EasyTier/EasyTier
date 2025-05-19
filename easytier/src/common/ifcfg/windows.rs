use std::{io, net::Ipv4Addr};

use async_trait::async_trait;
use winreg::{
    enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE},
    RegKey,
};

use super::{cidr_to_subnet_mask, run_shell_cmd, Error, IfConfiguerTrait};

pub struct WindowsIfConfiger {}

impl WindowsIfConfiger {
    pub fn get_interface_index(name: &str) -> Option<u32> {
        crate::arch::windows::find_interface_index(name).ok()
    }

    async fn list_ipv4(name: &str) -> Result<Vec<Ipv4Addr>, Error> {
        use anyhow::Context;
        use network_interface::NetworkInterfaceConfig;
        use std::net::IpAddr;
        let ret = network_interface::NetworkInterface::show().with_context(|| "show interface")?;
        let addrs = ret
            .iter()
            .filter_map(|x| {
                if x.name != name {
                    return None;
                }
                Some(x.addr.clone())
            })
            .flat_map(|x| x)
            .map(|x| x.ip())
            .filter_map(|x| {
                if let IpAddr::V4(ipv4) = x {
                    Some(ipv4)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(addrs)
    }

    async fn remove_one_ipv4(name: &str, ip: Ipv4Addr) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "netsh interface ipv4 delete address {} address={}",
                name,
                ip.to_string()
            )
            .as_str(),
        )
        .await
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl IfConfiguerTrait for WindowsIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let Some(idx) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        run_shell_cmd(
            format!(
                "route ADD {} MASK {} 10.1.1.1 IF {} METRIC {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                idx,
                cost.unwrap_or(9000)
            )
            .as_str(),
        )
        .await
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let Some(idx) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        run_shell_cmd(
            format!(
                "route DELETE {} MASK {} IF {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                idx
            )
            .as_str(),
        )
        .await
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "netsh interface ipv4 add address {} address={} mask={}",
                name,
                address,
                cidr_to_subnet_mask(cidr_prefix)
            )
            .as_str(),
        )
        .await
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "netsh interface set interface {} {}",
                name,
                if up { "enable" } else { "disable" }
            )
            .as_str(),
        )
        .await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Addr>) -> Result<(), Error> {
        if ip.is_none() {
            for ip in Self::list_ipv4(name).await?.iter() {
                Self::remove_one_ipv4(name, *ip).await?;
            }
            Ok(())
        } else {
            Self::remove_one_ipv4(name, ip.unwrap()).await
        }
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
        let _ = run_shell_cmd(
            format!("netsh interface ipv6 set subinterface {} mtu={}", name, mtu).as_str(),
        )
        .await;
        run_shell_cmd(
            format!("netsh interface ipv4 set subinterface {} mtu={}", name, mtu).as_str(),
        )
        .await
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
