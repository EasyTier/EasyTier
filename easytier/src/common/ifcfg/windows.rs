use std::net::Ipv4Addr;

use async_trait::async_trait;

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
    ) -> Result<(), Error> {
        let Some(idx) = Self::get_interface_index(name) else {
            return Err(Error::NotFound);
        };
        run_shell_cmd(
            format!(
                "route ADD {} MASK {} 10.1.1.1 IF {} METRIC 9000",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                idx
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
