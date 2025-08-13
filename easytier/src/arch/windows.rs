use std::{io, net::SocketAddr, os::windows::io::AsRawSocket};

use anyhow::Context;
use network_interface::NetworkInterfaceConfig;
use windows::{
    core::BSTR,
    Win32::{
        Foundation::{BOOL, FALSE},
        NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, INetFwRule, NET_FW_ACTION_ALLOW, NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN,
            NET_FW_RULE_DIR_OUT,
        },
        Networking::WinSock::{
            htonl, setsockopt, WSAGetLastError, WSAIoctl, IPPROTO_IP, IPPROTO_IPV6,
            IPV6_UNICAST_IF, IP_UNICAST_IF, SIO_UDP_CONNRESET, SOCKET, SOCKET_ERROR,
        },
        System::Com::{
            CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED,
        },
    },
};

pub fn disable_connection_reset<S: AsRawSocket>(socket: &S) -> io::Result<()> {
    let handle = SOCKET(socket.as_raw_socket() as usize);

    unsafe {
        // Ignoring UdpSocket's WSAECONNRESET error
        // https://github.com/shadowsocks/shadowsocks-rust/issues/179
        // https://stackoverflow.com/questions/30749423/is-winsock-error-10054-wsaeconnreset-normal-with-udp-to-from-localhost
        //
        // This is because `UdpSocket::recv_from` may return WSAECONNRESET
        // if you called `UdpSocket::send_to` a destination that is not existed (may be closed).
        //
        // It is not an error. Could be ignored completely.
        // We have to ignore it here because it will crash the server.

        let mut bytes_returned: u32 = 0;
        let enable: BOOL = FALSE;

        let ret = WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            Some(&enable as *const _ as *const std::ffi::c_void),
            std::mem::size_of_val(&enable) as u32,
            None,
            0,
            &mut bytes_returned as *mut _,
            None,
            None,
        );

        if ret == SOCKET_ERROR {
            let err_code = WSAGetLastError();
            return Err(std::io::Error::from_raw_os_error(err_code.0));
        }
    }

    Ok(())
}

pub fn interface_count() -> io::Result<usize> {
    let ifaces = network_interface::NetworkInterface::show().map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to get interfaces. error: {}", e),
        )
    })?;
    Ok(ifaces.len())
}

pub fn find_interface_index(iface_name: &str) -> io::Result<u32> {
    let ifaces = network_interface::NetworkInterface::show().map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to get interfaces. {}, error: {}", iface_name, e),
        )
    })?;
    if let Some(iface) = ifaces.iter().find(|iface| iface.name == iface_name) {
        return Ok(iface.index);
    }
    tracing::error!("Failed to find interface index for {}", iface_name);
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        iface_name.to_string(),
    ))
}

pub fn set_ip_unicast_if<S: AsRawSocket>(
    socket: &S,
    addr: &SocketAddr,
    iface: &str,
) -> io::Result<()> {
    let handle = SOCKET(socket.as_raw_socket() as usize);

    let if_index = find_interface_index(iface)?;

    unsafe {
        // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        let ret = match addr {
            SocketAddr::V4(..) => {
                let if_index = htonl(if_index);
                let if_index_bytes = if_index.to_ne_bytes();
                setsockopt(handle, IPPROTO_IP.0, IP_UNICAST_IF, Some(&if_index_bytes))
            }
            SocketAddr::V6(..) => {
                let if_index_bytes = if_index.to_ne_bytes();
                setsockopt(
                    handle,
                    IPPROTO_IPV6.0,
                    IPV6_UNICAST_IF,
                    Some(&if_index_bytes),
                )
            }
        };

        if ret == SOCKET_ERROR {
            let err = std::io::Error::from_raw_os_error(WSAGetLastError().0);
            tracing::error!(
                "set IP_UNICAST_IF / IPV6_UNICAST_IF interface: {}, index: {}, error: {}",
                iface,
                if_index,
                err
            );
            return Err(err);
        }
    }

    Ok(())
}

pub fn setup_socket_for_win<S: AsRawSocket>(
    socket: &S,
    bind_addr: &SocketAddr,
    bind_dev: Option<String>,
    is_udp: bool,
) -> io::Result<()> {
    if is_udp {
        disable_connection_reset(socket)?;
    }

    if let Some(iface) = bind_dev {
        set_ip_unicast_if(socket, bind_addr, iface.as_str())?;
    }

    Ok(())
}

struct ComInitializer;

impl ComInitializer {
    fn new() -> windows::core::Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED)? };
        Ok(Self)
    }
}

impl Drop for ComInitializer {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

pub fn do_add_self_to_firewall_allowlist(inbound: bool) -> anyhow::Result<()> {
    let _com = ComInitializer::new()?;
    // Create firewall policy instance
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
            None,
            CLSCTX_ALL,
        )
    }?;

    // Create firewall rule instance
    let rule: INetFwRule = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwRule,
            None,
            CLSCTX_ALL,
        )
    }?;

    // Set rule properties
    let exe_path = std::env::current_exe()
        .with_context(|| "Failed to get current executable path when adding firewall rule")?
        .to_string_lossy()
        .replace(r"\\?\", "");

    let name = BSTR::from(format!(
        "EasyTier {} ({})",
        exe_path,
        if inbound { "Inbound" } else { "Outbound" }
    ));
    let desc = BSTR::from("Allow EasyTier to do subnet proxy and kcp proxy");
    let app_path = BSTR::from(&exe_path);

    unsafe {
        rule.SetName(&name)?;
        rule.SetDescription(&desc)?;
        rule.SetApplicationName(&app_path)?;
        rule.SetAction(NET_FW_ACTION_ALLOW)?;
        if inbound {
            rule.SetDirection(NET_FW_RULE_DIR_IN)?; // Allow inbound connections
        } else {
            rule.SetDirection(NET_FW_RULE_DIR_OUT)?; // Allow outbound connections
        }
        rule.SetEnabled(windows::Win32::Foundation::VARIANT_TRUE)?;
        rule.SetProfiles(
            NET_FW_PROFILE2_PRIVATE.0 | NET_FW_PROFILE2_PUBLIC.0 | NET_FW_PROFILE2_DOMAIN.0,
        )?;
        rule.SetGrouping(&BSTR::from("EasyTier"))?;

        // Get rule collection and add new rule
        let rules = policy.Rules()?;
        rules.Remove(&name)?; // Remove existing rule with same name first
        rules.Add(&rule)?;
    }

    Ok(())
}

pub fn add_self_to_firewall_allowlist() -> anyhow::Result<()> {
    do_add_self_to_firewall_allowlist(true)?;
    do_add_self_to_firewall_allowlist(false)?;
    Ok(())
}

/// Add firewall rules for specified network interface to allow all traffic
pub fn add_interface_to_firewall_allowlist(interface_name: &str) -> anyhow::Result<()> {
    let _com = ComInitializer::new()?;

    // Create firewall policy instance
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
            None,
            CLSCTX_ALL,
        )
    }?;

    tracing::info!(
        "Adding comprehensive firewall rules for interface: {}",
        interface_name
    );

    // Create rules for each protocol type
    add_protocol_firewall_rules(&policy, interface_name, "TCP", 6)?; // TCP protocol number 6
    tracing::debug!("Added TCP firewall rules for interface: {}", interface_name);

    add_protocol_firewall_rules(&policy, interface_name, "UDP", 17)?; // UDP protocol number 17
    tracing::debug!("Added UDP firewall rules for interface: {}", interface_name);

    add_protocol_firewall_rules(&policy, interface_name, "ICMP", 1)?; // ICMP protocol number 1
    tracing::debug!(
        "Added ICMP firewall rules for interface: {}",
        interface_name
    );

    // Add fallback rules for all protocols
    add_all_protocols_firewall_rules(&policy, interface_name)?;
    tracing::debug!(
        "Added fallback all-protocols rules for interface: {}",
        interface_name
    );

    tracing::info!(
        "Successfully created all firewall rules for interface: {}",
        interface_name
    );

    Ok(())
}

/// Add firewall rules for a specific protocol
fn add_protocol_firewall_rules(
    policy: &INetFwPolicy2,
    interface_name: &str,
    protocol_name: &str,
    protocol_number: i32,
) -> anyhow::Result<()> {
    // Create rules for both inbound and outbound traffic
    for (is_inbound, direction_name) in [(true, "Inbound"), (false, "Outbound")] {
        // Create firewall rule instance
        let rule: INetFwRule = unsafe {
            CoCreateInstance(
                &windows::Win32::NetworkManagement::WindowsFirewall::NetFwRule,
                None,
                CLSCTX_ALL,
            )
        }?;

        let rule_name = format!(
            "EasyTier {} - {} Protocol ({})",
            interface_name, protocol_name, direction_name
        );
        let description = format!(
            "Allow {} traffic on EasyTier interface {}",
            protocol_name, interface_name
        );

        let name_bstr = BSTR::from(&rule_name);
        let desc_bstr = BSTR::from(&description);

        unsafe {
            rule.SetName(&name_bstr)?;
            rule.SetDescription(&desc_bstr)?;
            rule.SetProtocol(protocol_number)?;
            rule.SetAction(NET_FW_ACTION_ALLOW)?;

            if is_inbound {
                rule.SetDirection(NET_FW_RULE_DIR_IN)?;
            } else {
                rule.SetDirection(NET_FW_RULE_DIR_OUT)?;
            }

            rule.SetEnabled(windows::Win32::Foundation::VARIANT_TRUE)?;
            rule.SetProfiles(
                NET_FW_PROFILE2_PRIVATE.0 | NET_FW_PROFILE2_PUBLIC.0 | NET_FW_PROFILE2_DOMAIN.0,
            )?;
            rule.SetGrouping(&BSTR::from("EasyTier"))?;

            // Get rule collection and add new rule
            let rules = policy.Rules()?;
            rules.Remove(&name_bstr)?; // Remove existing rule with same name first
            rules.Add(&rule)?;
        }
    }

    Ok(())
}

/// Add fallback rules for all protocols
fn add_all_protocols_firewall_rules(
    policy: &INetFwPolicy2,
    interface_name: &str,
) -> anyhow::Result<()> {
    // Create rules for both inbound and outbound traffic
    for (is_inbound, direction_name) in [(true, "Inbound"), (false, "Outbound")] {
        // Create firewall rule instance
        let rule: INetFwRule = unsafe {
            CoCreateInstance(
                &windows::Win32::NetworkManagement::WindowsFirewall::NetFwRule,
                None,
                CLSCTX_ALL,
            )
        }?;

        let rule_name = format!(
            "EasyTier {} - All Protocols ({})",
            interface_name, direction_name
        );
        let description = format!(
            "Allow all protocol traffic on EasyTier interface {}",
            interface_name
        );

        let name_bstr = BSTR::from(&rule_name);
        let desc_bstr = BSTR::from(&description);

        unsafe {
            rule.SetName(&name_bstr)?;
            rule.SetDescription(&desc_bstr)?;
            // Don't set protocol - allows all protocols by default
            rule.SetAction(NET_FW_ACTION_ALLOW)?;

            if is_inbound {
                rule.SetDirection(NET_FW_RULE_DIR_IN)?;
            } else {
                rule.SetDirection(NET_FW_RULE_DIR_OUT)?;
            }

            rule.SetEnabled(windows::Win32::Foundation::VARIANT_TRUE)?;
            rule.SetProfiles(
                NET_FW_PROFILE2_PRIVATE.0 | NET_FW_PROFILE2_PUBLIC.0 | NET_FW_PROFILE2_DOMAIN.0,
            )?;
            rule.SetGrouping(&BSTR::from("EasyTier"))?;

            // Get rule collection and add new rule
            let rules = policy.Rules()?;
            rules.Remove(&name_bstr)?; // Remove existing rule with same name first
            rules.Add(&rule)?;
        }
    }

    Ok(())
}

/// Remove firewall rules for specified interface
pub fn remove_interface_firewall_rules(interface_name: &str) -> anyhow::Result<()> {
    let _com = ComInitializer::new()?;

    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
            None,
            CLSCTX_ALL,
        )
    }?;

    let rules = unsafe { policy.Rules()? };

    // Remove protocol-specific rules
    for protocol_name in ["TCP", "UDP", "ICMP"] {
        for direction in ["Inbound", "Outbound"] {
            let rule_name = format!(
                "EasyTier {} - {} Protocol ({})",
                interface_name, protocol_name, direction
            );
            let name_bstr = BSTR::from(&rule_name);
            unsafe {
                let _ = rules.Remove(&name_bstr); // Ignore errors, rule might not exist
            }
        }
    }

    // Remove fallback protocol rules
    for direction in ["Inbound", "Outbound"] {
        let rule_name = format!(
            "EasyTier {} - All Protocols ({})",
            interface_name, direction
        );
        let name_bstr = BSTR::from(&rule_name);
        unsafe {
            let _ = rules.Remove(&name_bstr); // Ignore errors, rule might not exist
        }
    }

    Ok(())
}

/// List EasyTier firewall rules for specified interface (for debugging)
#[allow(dead_code)]
pub fn list_interface_firewall_rules(interface_name: &str) -> anyhow::Result<Vec<String>> {
    let _com = ComInitializer::new()?;

    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(
            &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
            None,
            CLSCTX_ALL,
        )
    }?;

    let rules = unsafe { policy.Rules()? };
    let mut found_rules = Vec::new();

    // Check protocol-specific rules
    for protocol_name in ["TCP", "UDP", "ICMP"] {
        for direction in ["Inbound", "Outbound"] {
            let rule_name = format!(
                "EasyTier {} - {} Protocol ({})",
                interface_name, protocol_name, direction
            );
            if check_rule_exists(&rules, &rule_name)? {
                found_rules.push(rule_name);
            }
        }
    }

    // Check fallback protocol rules
    for direction in ["Inbound", "Outbound"] {
        let rule_name = format!(
            "EasyTier {} - All Protocols ({})",
            interface_name, direction
        );
        if check_rule_exists(&rules, &rule_name)? {
            found_rules.push(rule_name);
        }
    }

    Ok(found_rules)
}

/// Check if a firewall rule with specified name exists
fn check_rule_exists(
    rules: &windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules,
    rule_name: &str,
) -> anyhow::Result<bool> {
    let name_bstr = BSTR::from(rule_name);
    unsafe {
        match rules.Item(&name_bstr) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_self_to_firewall_allowlist() {
        let res = add_self_to_firewall_allowlist();
        assert!(res.is_ok());
    }

    #[test]
    #[ignore] // Requires administrator privileges, ignored by default
    fn test_interface_firewall_rules() {
        let test_interface = "test_interface";

        // Add firewall rules
        let add_result = add_interface_to_firewall_allowlist(test_interface);
        assert!(
            add_result.is_ok(),
            "Failed to add interface firewall rules: {:?}",
            add_result
        );

        println!(
            "✓ Added comprehensive firewall rules for interface: {}",
            test_interface
        );

        // Verify rules were created
        let rules = list_interface_firewall_rules(test_interface).unwrap();
        println!("Created {} firewall rules:", rules.len());
        for rule in &rules {
            println!("  - {}", rule);
        }

        // Verify required protocol rules are all created
        let expected_protocols = ["TCP", "UDP", "ICMP"];
        let expected_directions = ["Inbound", "Outbound"];

        for protocol in &expected_protocols {
            for direction in &expected_directions {
                let rule_name = format!(
                    "EasyTier {} - {} Protocol ({})",
                    test_interface, protocol, direction
                );
                assert!(
                    rules.contains(&rule_name),
                    "Missing required rule: {}",
                    rule_name
                );
            }
        }

        println!("✓ All required protocol rules (TCP/UDP/ICMP) are present");

        // Remove firewall rules
        let remove_result = remove_interface_firewall_rules(test_interface);
        assert!(
            remove_result.is_ok(),
            "Failed to remove interface firewall rules: {:?}",
            remove_result
        );

        // Verify rules were removed
        let remaining_rules = list_interface_firewall_rules(test_interface).unwrap();
        assert!(
            remaining_rules.is_empty(),
            "Some rules were not removed: {:?}",
            remaining_rules
        );

        println!(
            "✓ Successfully removed all firewall rules for interface: {}",
            test_interface
        );
    }
}
