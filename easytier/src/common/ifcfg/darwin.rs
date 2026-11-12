use std::{collections::BTreeSet, net::Ipv4Addr};

use super::{
    Error, IfConfiguerTrait, cidr_to_subnet_mask, ignore_removed_shell_cmd_not_found,
    run_shell_cmd, run_shell_cmd_output,
};
use async_trait::async_trait;
use cidr::{Ipv4Inet, Ipv6Inet};
use tokio::sync::Mutex;

#[derive(Default)]
pub struct MacIfConfiger {
    configured_ipv4: Mutex<BTreeSet<Ipv4Inet>>,
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

async fn run_delete_shell_cmd(cmd: &str) -> Result<(), Error> {
    ignore_removed_shell_cmd_not_found(run_shell_cmd(cmd).await)
}

fn ipv4_route_matches(output: &str, name: &str, address: Ipv4Addr, prefix: u8) -> bool {
    let field = |key: &str| {
        output.lines().find_map(|line| {
            let (label, value) = line.trim().split_once(':')?;
            (label == key).then_some(value.trim())
        })
    };
    let destination = match field("destination") {
        Some("default") => Some(Ipv4Addr::UNSPECIFIED),
        Some(value) => value.parse().ok(),
        None => None,
    };
    let mask = match field("mask") {
        Some("default") => Some(Ipv4Addr::UNSPECIFIED),
        Some(value) => value.parse().ok(),
        None if field("destination") == Some("default") => Some(Ipv4Addr::UNSPECIFIED),
        None if field("flags")
            .is_some_and(|flags| flags.split([',', '<', '>']).any(|flag| flag == "HOST")) =>
        {
            Some(Ipv4Addr::BROADCAST)
        }
        None => None,
    };
    destination == Some(address)
        && mask == Some(cidr_to_subnet_mask(prefix))
        && field("interface") == Some(name)
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
        self.add_ipv4_route_with_source_hint(name, address, cidr_prefix, cost, None)
            .await
    }

    async fn add_ipv4_route_with_source_hint(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
        source_hint: Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        let source_hint = source_hint
            .map(|source| format!(" -ifa {}", source))
            .unwrap_or_default();
        run_shell_cmd(
            format!(
                "route -n add {} -netmask {} -interface {}{} -hopcount {}",
                address,
                cidr_to_subnet_mask(cidr_prefix),
                name,
                source_hint,
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
        // The -interface argument to route delete does not constrain route ownership.
        // A lookup can also return a covering route, so check the exact prefix.
        let output = match run_shell_cmd_output(&format!(
            "route -n get -net {} -netmask {}",
            address,
            cidr_to_subnet_mask(cidr_prefix),
        ))
        .await
        {
            Ok(output) => output,
            Err(err) => {
                ignore_removed_shell_cmd_not_found(Err(err))?;
                return Ok(());
            }
        };
        if !ipv4_route_matches(&output, name, address, cidr_prefix) {
            tracing::debug!(%name, %address, cidr_prefix, "skip deleting an IPv4 route owned elsewhere");
            return Ok(());
        }
        run_delete_shell_cmd(
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
            anyhow::anyhow!("invalid IPv4 address {address}/{cidr_prefix}: {err:?}")
        })?;
        let mut configured_ipv4 = self.configured_ipv4.lock().await;
        let cmd = Self::build_add_ipv4_cmd(name, addr, !configured_ipv4.is_empty());

        run_shell_cmd(cmd.as_str()).await?;
        configured_ipv4.insert(addr);
        Ok(())
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        run_shell_cmd(format!("ifconfig {} {}", name, if up { "up" } else { "down" }).as_str())
            .await
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        let mut configured_ipv4 = self.configured_ipv4.lock().await;
        if let Some(ip) = ip {
            run_delete_shell_cmd(
                format!("ifconfig {} inet {} delete", name, ip.address()).as_str(),
            )
            .await?;
            configured_ipv4.remove(&ip);
        } else {
            run_delete_shell_cmd(format!("ifconfig {} inet delete", name).as_str()).await?;
            configured_ipv4.clear();
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
            run_delete_shell_cmd(
                format!("ifconfig {} inet6 {} delete", name, ip.address()).as_str(),
            )
            .await
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
        run_delete_shell_cmd(
            format!(
                "route -n delete -inet6 {}/{} -interface {}",
                address, cidr_prefix, name
            )
            .as_str(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_route_cleanup_requires_the_exact_prefix_and_interface() {
        let subnet = "192.0.2.0".parse().unwrap();
        let own = "destination: 192.0.2.0\nmask: 255.255.255.0\ninterface: utun4\n";
        assert!(ipv4_route_matches(own, "utun4", subnet, 24));
        assert!(!ipv4_route_matches(own, "en0", subnet, 24));
        assert!(!ipv4_route_matches(own, "utun4", subnet, 25));
        assert!(!ipv4_route_matches(
            "destination: default\nmask: default\ninterface: utun4\n",
            "utun4",
            subnet,
            24,
        ));
        assert!(!ipv4_route_matches("", "utun4", subnet, 24));
    }

    #[test]
    fn ipv4_route_cleanup_handles_host_and_default_routes() {
        assert!(ipv4_route_matches(
            "destination: 192.0.2.1\ninterface: utun4\nflags: <UP,HOST,DONE,STATIC>\n",
            "utun4",
            "192.0.2.1".parse().unwrap(),
            32,
        ));
        assert!(ipv4_route_matches(
            "destination: default\ninterface: utun4\n",
            "utun4",
            Ipv4Addr::UNSPECIFIED,
            0,
        ));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires root; temporarily installs an unused documentation subnet on lo0"]
    async fn conflicting_ipv4_route_preserves_the_existing_interface() {
        let uid = std::process::Command::new("id").arg("-u").output().unwrap();
        assert_eq!(String::from_utf8_lossy(&uid.stdout).trim(), "0");
        let address: Ipv4Addr = "192.0.2.240".parse().unwrap();
        let prefix = 28;
        let query = "route -n get -net 192.0.2.240 -netmask 255.255.255.240";
        let before = run_shell_cmd_output(query).await.unwrap_or_default();
        assert!(
            !before
                .lines()
                .any(|line| line.trim() == "destination: 192.0.2.240"),
            "test destination is already in use"
        );

        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let output = std::process::Command::new("route")
                    .args([
                        "-n",
                        "get",
                        "-net",
                        "192.0.2.240",
                        "-netmask",
                        "255.255.255.240",
                    ])
                    .output()
                    .unwrap();
                if ipv4_route_matches(
                    &String::from_utf8_lossy(&output.stdout),
                    "lo0",
                    "192.0.2.240".parse().unwrap(),
                    28,
                ) {
                    let _ = std::process::Command::new("route")
                        .args([
                            "-n",
                            "delete",
                            "-net",
                            "192.0.2.240",
                            "-netmask",
                            "255.255.255.240",
                            "-interface",
                            "lo0",
                        ])
                        .output();
                }
            }
        }

        run_shell_cmd(
            "route -n add -net 192.0.2.240 -netmask 255.255.255.240 -interface 127.0.0.1",
        )
        .await
        .unwrap();
        let _cleanup = Cleanup;
        let configurer = MacIfConfiger::default();
        assert!(matches!(
            configurer
                .add_ipv4_route("en0", address, prefix, None)
                .await,
            Err(Error::ShellCommandError(_))
        ));
        configurer
            .remove_ipv4_route("en0", address, prefix)
            .await
            .unwrap();
        assert!(ipv4_route_matches(
            &run_shell_cmd_output(query).await.unwrap(),
            "lo0",
            address,
            prefix,
        ));

        configurer
            .remove_ipv4_route("lo0", address, prefix)
            .await
            .unwrap();
        configurer
            .add_ipv4_route("lo0", address, prefix, None)
            .await
            .unwrap();
        configurer
            .remove_ipv4_route("lo0", address, prefix)
            .await
            .unwrap();
        // Repeating cleanup must preserve the covering route returned by route get.
        configurer
            .remove_ipv4_route("lo0", address, prefix)
            .await
            .unwrap();
        assert!(!ipv4_route_matches(
            &run_shell_cmd_output(query).await.unwrap_or_default(),
            "lo0",
            address,
            prefix,
        ));
    }
}
