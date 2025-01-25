use std::net::Ipv4Addr;

use async_trait::async_trait;
use tokio::process::Command;

use super::error::Error;

#[async_trait]
pub trait IfConfiguerTrait: Send + Sync {
    async fn add_ipv4_route(
        &self,
        _name: &str,
        _address: Ipv4Addr,
        _cidr_prefix: u8,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn remove_ipv4_route(
        &self,
        _name: &str,
        _address: Ipv4Addr,
        _cidr_prefix: u8,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn add_ipv4_ip(
        &self,
        _name: &str,
        _address: Ipv4Addr,
        _cidr_prefix: u8,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn set_link_status(&self, _name: &str, _up: bool) -> Result<(), Error> {
        Ok(())
    }
    async fn remove_ip(&self, _name: &str, _ip: Option<Ipv4Addr>) -> Result<(), Error> {
        Ok(())
    }
    async fn wait_interface_show(&self, _name: &str) -> Result<(), Error> {
        return Ok(());
    }
    async fn set_mtu(&self, _name: &str, _mtu: u32) -> Result<(), Error> {
        Ok(())
    }
}

fn cidr_to_subnet_mask(prefix_length: u8) -> Ipv4Addr {
    if prefix_length > 32 {
        panic!("Invalid CIDR prefix length");
    }

    let subnet_mask: u32 = (!0u32)
        .checked_shl(32 - u32::from(prefix_length))
        .unwrap_or(0);
    Ipv4Addr::new(
        ((subnet_mask >> 24) & 0xFF) as u8,
        ((subnet_mask >> 16) & 0xFF) as u8,
        ((subnet_mask >> 8) & 0xFF) as u8,
        (subnet_mask & 0xFF) as u8,
    )
}

async fn run_shell_cmd(cmd: &str) -> Result<(), Error> {
    let cmd_out: std::process::Output;
    let stdout: String;
    let stderr: String;
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd_out = Command::new("cmd")
            .stdin(std::process::Stdio::null())
            .arg("/C")
            .arg(cmd)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .await?;
        stdout = crate::utils::utf8_or_gbk_to_string(cmd_out.stdout.as_slice());
        stderr = crate::utils::utf8_or_gbk_to_string(cmd_out.stderr.as_slice());
    };

    #[cfg(not(target_os = "windows"))]
    {
        cmd_out = Command::new("sh").arg("-c").arg(cmd).output().await?;
        stdout = String::from_utf8_lossy(cmd_out.stdout.as_slice()).to_string();
        stderr = String::from_utf8_lossy(cmd_out.stderr.as_slice()).to_string();
    };

    let ec = cmd_out.status.code();
    let succ = cmd_out.status.success();
    tracing::info!(?cmd, ?ec, ?succ, ?stdout, ?stderr, "run shell cmd");

    if !cmd_out.status.success() {
        return Err(Error::ShellCommandError(stdout + &stderr));
    }
    Ok(())
}

pub struct MacIfConfiger {}
#[async_trait]
impl IfConfiguerTrait for MacIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "route -n add {} -netmask {} -interface {} -hopcount 7",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                name
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
        run_shell_cmd(
            format!(
                "ifconfig {} {:?}/{:?} 10.8.8.8 up",
                name, address, cidr_prefix,
            )
            .as_str(),
        )
        .await
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} {}", name, if up { "up" } else { "down" }).as_str())
            .await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Addr>) -> Result<(), Error> {
        if ip.is_none() {
            run_shell_cmd(format!("ifconfig {} inet delete", name).as_str()).await
        } else {
            run_shell_cmd(
                format!("ifconfig {} inet {} delete", name, ip.unwrap().to_string()).as_str(),
            )
            .await
        }
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} mtu {}", name, mtu).as_str()).await
    }
}

pub struct LinuxIfConfiger {}
#[async_trait]
impl IfConfiguerTrait for LinuxIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(
            format!(
                "ip route add {}/{} dev {} metric 65535",
                address, cidr_prefix, name
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
        run_shell_cmd(format!("ip route del {}/{} dev {}", address, cidr_prefix, name).as_str())
            .await
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        run_shell_cmd(format!("ip addr add {:?}/{:?} dev {}", address, cidr_prefix, name).as_str())
            .await
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        run_shell_cmd(format!("ip link set {} {}", name, if up { "up" } else { "down" }).as_str())
            .await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Addr>) -> Result<(), Error> {
        if ip.is_none() {
            run_shell_cmd(format!("ip addr flush dev {}", name).as_str()).await
        } else {
            run_shell_cmd(
                format!("ip addr del {:?} dev {}", ip.unwrap().to_string(), name).as_str(),
            )
            .await
        }
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        run_shell_cmd(format!("ip link set dev {} mtu {}", name, mtu).as_str()).await
    }
}

#[cfg(target_os = "windows")]
pub struct WindowsIfConfiger {}

#[cfg(target_os = "windows")]
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

pub struct DummyIfConfiger {}
#[async_trait]
impl IfConfiguerTrait for DummyIfConfiger {}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub type IfConfiger = MacIfConfiger;

#[cfg(target_os = "linux")]
pub type IfConfiger = LinuxIfConfiger;

#[cfg(target_os = "windows")]
pub type IfConfiger = WindowsIfConfiger;

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "windows",
    target_os = "freebsd"
)))]
pub type IfConfiger = DummyIfConfiger;
