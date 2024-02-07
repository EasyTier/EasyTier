use std::net::Ipv4Addr;

use async_trait::async_trait;
use tokio::process::Command;

use super::error::Error;

#[async_trait]
pub trait IfConfiguerTrait {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error>;
    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error>;
    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error>;
    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error>;
    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Addr>) -> Result<(), Error>;
    async fn wait_interface_show(&self, _name: &str) -> Result<(), Error> {
        return Ok(());
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
    let cmd_out = if cfg!(target_os = "windows") {
        Command::new("cmd").arg("/C").arg(cmd).output().await?
    } else {
        Command::new("sh").arg("-c").arg(cmd).output().await?
    };
    let stdout = String::from_utf8_lossy(cmd_out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(cmd_out.stderr.as_slice());
    let ec = cmd_out.status.code();
    let succ = cmd_out.status.success();
    tracing::info!(?cmd, ?ec, ?succ, ?stdout, ?stderr, "run shell cmd");

    if !cmd_out.status.success() {
        return Err(Error::ShellCommandError(
            stdout.to_string() + &stderr.to_string(),
        ));
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
}

pub struct WindowsIfConfiger {}

#[async_trait]
impl IfConfiguerTrait for WindowsIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let idx = unsafe { libc::if_nametoindex(name.as_ptr() as *const i8) };
        run_shell_cmd(
            format!(
                "route ADD {} MASK {} 10.1.1.1 IF {} METRIC 255",
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
        let idx = unsafe { libc::if_nametoindex(name.as_ptr() as *const i8) };
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
            run_shell_cmd(format!("netsh interface ipv4 delete address {}", name).as_str()).await
        } else {
            run_shell_cmd(
                format!(
                    "netsh interface ipv4 delete address {} address={}",
                    name,
                    ip.unwrap().to_string()
                )
                .as_str(),
            )
            .await
        }
    }

    async fn wait_interface_show(&self, name: &str) -> Result<(), Error> {
        Ok(
            tokio::time::timeout(std::time::Duration::from_secs(10), async move {
                loop {
                    let Ok(_) = run_shell_cmd(
                        format!("netsh interface ipv4 show interfaces {}", name).as_str(),
                    )
                    .await
                    else {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    };
                    break;
                }
            })
            .await?,
        )
    }
}

#[cfg(target_os = "macos")]
pub type IfConfiger = MacIfConfiger;

#[cfg(target_os = "linux")]
pub type IfConfiger = LinuxIfConfiger;

#[cfg(target_os = "windows")]
pub type IfConfiger = WindowsIfConfiger;
