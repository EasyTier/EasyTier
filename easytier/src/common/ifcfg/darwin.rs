use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::Arc,
};

use super::{Error, IfConfiguerTrait, cidr_to_subnet_mask, run_shell_cmd};
use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};
use tokio::sync::Mutex;

#[derive(Default)]
pub struct MacIfConfiger {
    configured_ipv4: Arc<Mutex<BTreeMap<String, BTreeSet<Ipv4Inet>>>>,
}

impl MacIfConfiger {
    fn build_add_ipv4_cmd(name: &str, addr: Ipv4Inet, has_configured_ipv4: bool) -> String {
        let address = addr.address();
        if has_configured_ipv4 {
            format!(
                "ifconfig {} alias {:?} {:?} netmask {}",
                name,
                address,
                address,
                cidr_to_subnet_mask(addr.network_length())
            )
        } else {
            format!(
                "ifconfig {} {:?}/{:?} {:?} up",
                name,
                address,
                addr.network_length(),
                address,
            )
        }
    }
}

#[async_trait]
impl IfConfiguerTrait for MacIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n add {} -netmask {} -interface {} -hopcount {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                name,
                cost.unwrap_or(7)
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
        run_shell_cmd(
            format!(
                "route -n delete {} -netmask {} -interface {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                name
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
        let addr = Ipv4Inet::new(address, cidr_prefix).map_err(|err| {
            Error::RouteError(Some(format!(
                "invalid IPv4 address {address}/{cidr_prefix}: {err:?}"
            )))
        })?;
        let mut configured_ipv4 = self.configured_ipv4.lock().await;
        let has_configured_ipv4 = configured_ipv4
            .get(name)
            .is_some_and(|addresses| !addresses.is_empty());
        let cmd = Self::build_add_ipv4_cmd(name, addr, has_configured_ipv4);

        run_shell_cmd(cmd.as_str()).await?;
        configured_ipv4
            .entry(name.to_owned())
            .or_default()
            .insert(addr);
        Ok(())
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} {}", name, if up { "up" } else { "down" }).as_str())
            .await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        let mut configured_ipv4 = self.configured_ipv4.lock().await;
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet {} delete", name, ip.address()).as_str())
                .await?;
            if let Some(addresses) = configured_ipv4.get_mut(name) {
                addresses.remove(&ip);
                if addresses.is_empty() {
                    configured_ipv4.remove(name);
                }
            }
        } else {
            if let Some(addresses) = configured_ipv4.get(name).cloned() {
                for ip in addresses {
                    run_shell_cmd(
                        format!("ifconfig {} inet {} delete", name, ip.address()).as_str(),
                    )
                    .await?;
                    if let Some(addresses) = configured_ipv4.get_mut(name) {
                        addresses.remove(&ip);
                    }
                }
                configured_ipv4.remove(name);
            } else {
                run_shell_cmd(format!("ifconfig {} inet delete", name).as_str()).await?;
            }
        }
        Ok(())
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} mtu {}", name, mtu).as_str()).await
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} inet6 {}/{} add", name, address, cidr_prefix).as_str())
            .await
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            run_shell_cmd(format!("ifconfig {} inet6 {} delete", name, ip.address()).as_str()).await
        } else {
            // Remove all IPv6 addresses is more complex on macOS, just succeed
            Ok(())
        }
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let cmd = if let Some(cost) = cost {
            format!(
                "route -n add -inet6 {}/{} -interface {} -hopcount {}",
                address, cidr_prefix, name, cost
            )
        } else {
            format!(
                "route -n add -inet6 {}/{} -interface {}",
                address, cidr_prefix, name
            )
        };
        run_shell_cmd(cmd.as_str()).await
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n delete -inet6 {}/{} -interface {}",
                address, cidr_prefix, name
            )
            .as_str(),
        )
        .await
    }
}
