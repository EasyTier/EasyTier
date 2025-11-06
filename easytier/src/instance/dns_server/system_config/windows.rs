use std::net::IpAddr;
use std::process::Command;

use std::io;
use winreg::RegKey;

use crate::common::ifcfg::RegistryManager;

use super::{OSConfig, SystemConfig};

pub fn is_windows_10_or_better() -> io::Result<bool> {
    let hklm = winreg::enums::HKEY_LOCAL_MACHINE;
    let key_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    let key = winreg::RegKey::predef(hklm).open_subkey(key_path)?;

    // check CurrentMajorVersionNumber, which only exists on Windows 10 and later
    let value_name = "CurrentMajorVersionNumber";
    key.get_raw_value(value_name).map(|_| true)
}

// 假设 interface_guid 是你的网络接口 GUID
pub struct InterfaceControl {
    interface_guid: String,
}

impl InterfaceControl {
    // 构造函数
    pub fn new(interface_guid: &str) -> Self {
        InterfaceControl {
            interface_guid: interface_guid.to_string(),
        }
    }

    // 删除注册表值（模拟 delValue）
    fn delete_value(key: &RegKey, value_name: &str) -> io::Result<()> {
        match key.delete_value(value_name) {
            Ok(_) => Ok(()),
            Err(e) => {
                if matches!(e.kind(), io::ErrorKind::NotFound) {
                    Ok(()) // 忽略不存在的值
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn set_primary_dns(&self, resolvers: &[IpAddr], domains: &[String]) -> io::Result<()> {
        let (ipsv4, ipsv6): (Vec<String>, Vec<String>) = resolvers
            .iter()
            .map(|ip| ip.to_string())
            .partition(|ip| ip.contains('.'));

        let dom_strs: Vec<String> = domains
            .iter()
            .map(|d| d.trim_end_matches('.').to_string())
            .collect();

        // IPv4 处理
        if let Ok(key4) = RegistryManager::open_interface_key(
            &self.interface_guid,
            RegistryManager::IPV4_TCPIP_INTERFACE_PREFIX,
        ) {
            if ipsv4.is_empty() {
                Self::delete_value(&key4, "NameServer")?;
            } else {
                key4.set_value("NameServer", &ipsv4.join(","))?;
            }

            if dom_strs.is_empty() {
                Self::delete_value(&key4, "SearchList")?;
            } else {
                key4.set_value("SearchList", &dom_strs.join(","))?;
            }

            // 禁用 LLMNR（通过 DisableMulticast）
            key4.set_value("EnableMulticast", &0u32)?;
        }

        // IPv6 处理
        if let Ok(key6) = RegistryManager::open_interface_key(
            &self.interface_guid,
            RegistryManager::IPV6_TCPIP_INTERFACE_PREFIX,
        ) {
            if ipsv6.is_empty() {
                Self::delete_value(&key6, "NameServer")?;
            } else {
                key6.set_value("NameServer", &ipsv6.join(","))?;
            }

            if dom_strs.is_empty() {
                Self::delete_value(&key6, "SearchList")?;
            } else {
                key6.set_value("SearchList", &dom_strs.join(","))?;
            }
            key6.set_value("EnableMulticast", &0u32)?;
        }

        Ok(())
    }

    fn flush_dns(&self) -> io::Result<()> {
        // 刷新 DNS 缓存
        let output = Command::new("ipconfig")
            .arg("/flushdns")
            .output()
            .expect("failed to execute process");
        if !output.status.success() {
            return Err(io::Error::other("Failed to flush DNS cache"));
        }
        Ok(())
    }

    // re-register DNS
    pub fn re_register_dns(&self) -> io::Result<()> {
        // ipconfig /registerdns
        let output = Command::new("ipconfig")
            .arg("/registerdns")
            .output()
            .expect("failed to execute process");
        if !output.status.success() {
            return Err(io::Error::other("Failed to register DNS"));
        }
        Ok(())
    }
}

pub struct WindowsDNSManager {
    tun_dev_name: String,
    interface_control: InterfaceControl,
}

impl WindowsDNSManager {
    pub fn new(tun_dev_name: &str) -> io::Result<Self> {
        let interface_guid = RegistryManager::find_interface_guid(tun_dev_name)?;
        Ok(WindowsDNSManager {
            tun_dev_name: tun_dev_name.to_string(),
            interface_control: InterfaceControl::new(&interface_guid),
        })
    }

    pub fn set_primary_dns(&self, resolvers: &[IpAddr], domains: &[String]) -> io::Result<()> {
        self.interface_control.set_primary_dns(resolvers, domains)?;
        self.interface_control.flush_dns()?;
        Ok(())
    }
}

impl SystemConfig for WindowsDNSManager {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        self.set_primary_dns(
            &cfg.nameservers
                .iter()
                .map(|s| s.parse::<IpAddr>().unwrap())
                .collect::<Vec<_>>(),
            &cfg.match_domains,
        )?;
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cidr::Ipv4Inet;

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn test_windows_set_primary_server() {
        use std::{net::Ipv4Addr, str::FromStr as _, time::Duration};

        use tokio_util::sync::CancellationToken;

        use crate::instance::dns_server::{
            runner::DnsRunner,
            tests::{check_dns_record, prepare_env},
        };

        let tun_ip = Ipv4Inet::from_str("10.144.144.10/24").unwrap();
        let (peer_mgr, virtual_nic) = prepare_env("test1", tun_ip).await;
        let tun_name = virtual_nic.ifname().await.unwrap();

        println!("dev_name: {}", tun_name);
        let fake_ip = Ipv4Addr::from_str("100.100.100.101").unwrap();
        let mut dns_runner = DnsRunner::new(peer_mgr, Some(tun_name.clone()), tun_ip, fake_ip);

        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let t = tokio::spawn(async move {
            dns_runner.run(cancel_token_clone).await;
        });

        // windows is slow to add a ip address, wait for a longer time for dns server ready ,with ping
        let now = std::time::Instant::now();
        while now.elapsed() < Duration::from_secs(15) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Ok(o) = tokio::process::Command::new("ping")
                .arg("-n")
                .arg("1")
                .arg("-w")
                .arg("100")
                .arg(&fake_ip.to_string())
                .output()
                .await
            {
                if o.status.success() {
                    break;
                }
            }
        }

        check_dns_record(&fake_ip, "test1.et.net", "10.144.144.10").await;

        let dns_mgr = super::WindowsDNSManager::new(&tun_name).unwrap();
        println!("dev_name: {}", tun_name);
        println!("guid: {}", dns_mgr.interface_control.interface_guid);

        dns_mgr
            .interface_control
            .set_primary_dns(
                &["100.100.100.101".parse().unwrap()],
                &[".et.net.".to_string()],
            )
            .unwrap();
        dns_mgr.interface_control.flush_dns().unwrap();

        tracing::info!("check dns record with nslookup");

        // nslookup should return 10.144.144.10
        let ret = tokio::process::Command::new("nslookup")
            .arg("test1.et.net")
            .output()
            .await
            .expect("failed to execute process");
        assert!(ret.status.success());
        let output = String::from_utf8_lossy(&ret.stdout);
        println!("nslookup output: {}", output);
        assert!(output.contains("10.144.144.10"));

        cancel_token.cancel();
        let _ = t.await;
    }
}
