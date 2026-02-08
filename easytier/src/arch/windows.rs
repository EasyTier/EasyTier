use std::{
    io,
    mem::ManuallyDrop,
    net::{IpAddr, SocketAddr},
    os::windows::io::AsRawSocket,
};

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
        System::Ole::{SafeArrayCreateVector, SafeArrayPutElement},
        System::Variant::{VARENUM, VARIANT, VT_ARRAY, VT_BSTR, VT_VARIANT},
    },
};
use winreg::enums::*;
use winreg::RegKey;

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
    add_protocol_firewall_rules(&policy, interface_name, "TCP", Some(6))?; // TCP protocol number 6
    tracing::debug!("Added TCP firewall rules for interface: {}", interface_name);

    add_protocol_firewall_rules(&policy, interface_name, "UDP", Some(17))?; // UDP protocol number 17
    tracing::debug!("Added UDP firewall rules for interface: {}", interface_name);

    add_protocol_firewall_rules(&policy, interface_name, "ICMP", Some(1))?; // ICMP protocol number 1
    tracing::debug!(
        "Added ICMP firewall rules for interface: {}",
        interface_name
    );

    // Add fallback rules for all protocols
    add_protocol_firewall_rules(&policy, interface_name, "ALL", None)?;
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
    protocol_number: Option<i32>,
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
            if let Some(protocol_number) = protocol_number {
                rule.SetProtocol(protocol_number)?;
            }
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

            // Set the interface for this rule to apply to the specific network interface
            // According to Microsoft docs, interfaces should be represented by their friendly name
            // We need to create a SAFEARRAY of VARIANT strings containing the interface name
            let interface_bstr = BSTR::from(interface_name);

            // Create a SAFEARRAY containing one interface name
            let interface_array = SafeArrayCreateVector(VT_VARIANT, 0, 1);
            if interface_array.is_null() {
                return Err(anyhow::anyhow!("Failed to create SAFEARRAY"));
            }

            let index = 0i32;
            let mut variant_interface = VARIANT::default();
            (*variant_interface.Anonymous.Anonymous).vt = VT_BSTR;
            (*variant_interface.Anonymous.Anonymous).Anonymous.bstrVal =
                ManuallyDrop::new(interface_bstr);

            SafeArrayPutElement(
                interface_array,
                &index as *const _ as *const i32,
                &variant_interface as *const _ as *const std::ffi::c_void,
            )?;

            // Create the VARIANT that contains the SAFEARRAY
            let mut interface_variant = VARIANT::default();
            (*interface_variant.Anonymous.Anonymous).vt = VARENUM(VT_ARRAY.0 | VT_VARIANT.0);
            (*interface_variant.Anonymous.Anonymous).Anonymous.parray = interface_array;

            rule.SetInterfaces(interface_variant)?;

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

    for protocol_name in ["TCP", "UDP", "ICMP", "ALL"] {
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

// ============ Port Conflict Diagnostics ============

pub const GITHUB_ISSUE_URL: &str = "https://github.com/EasyTier/EasyTier/issues/1263";

// Registry path for TCP/IP parameters
const TCPIP_PARAMS_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

// Default dynamic port range for Windows Vista+ when not configured in registry
const DEFAULT_START_PORT: u16 = 49152;
const DEFAULT_NUM_PORTS: u16 = 16384; // 49152-65535

fn calc_dynamic_port_range_bounds(start_port: u32, num_ports: u32) -> (u16, u16) {
    let start_u32 = start_port.min(u16::MAX as u32);
    let end_u32 = start_u32
        .saturating_add(num_ports.saturating_sub(1))
        .min(u16::MAX as u32);
    (start_u32 as u16, end_u32 as u16)
}

/// Type of port conflict
#[derive(Debug, Clone, PartialEq)]
pub enum PortConflictType {
    /// Port is in Windows dynamic port range
    DynamicRange,
    /// Port is in Windows excluded port range (reserved by Hyper-V, etc.)
    ExcludedRange,
}

/// Result of port conflict diagnosis
#[derive(Debug, Clone)]
pub struct PortConflictInfo {
    pub port: u16,
    pub protocol: String,
    pub bind_host: String,
    pub netsh_ip_family: &'static str,
    pub conflict_type: PortConflictType,
    pub range_start: u16,
    pub range_end: u16,
    pub suggested_port: u16,
}

/// Get Windows dynamic port range from registry
/// Registry values (if configured):
///   HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
///     - DynamicPortRangeStartPort (DWORD)
///     - DynamicPortRangeNumberOfPorts (DWORD)
/// If not set, Windows uses default: 49152-65535
pub fn get_dynamic_port_range() -> io::Result<(u16, u16)> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    match hklm.open_subkey(TCPIP_PARAMS_KEY) {
        Ok(key) => {
            // Try to read configured values
            let start_port: u32 = key
                .get_value("DynamicPortRangeStartPort")
                .unwrap_or(u32::from(DEFAULT_START_PORT));
            let num_ports: u32 = key
                .get_value("DynamicPortRangeNumberOfPorts")
                .unwrap_or(u32::from(DEFAULT_NUM_PORTS));

            Ok(calc_dynamic_port_range_bounds(start_port, num_ports))
        }
        Err(_) => {
            // Use Windows default if registry key doesn't exist
            Ok(calc_dynamic_port_range_bounds(
                u32::from(DEFAULT_START_PORT),
                u32::from(DEFAULT_NUM_PORTS),
            ))
        }
    }
}

fn parse_dynamic_port_range_output(stdout: &str) -> Option<(u16, u16)> {
    let mut values = Vec::new();
    for line in stdout.lines() {
        let Some((_, value)) = line.split_once(':') else {
            continue;
        };
        if let Ok(v) = value.trim().parse::<u32>() {
            values.push(v);
        }
    }

    if values.len() < 2 {
        return None;
    }

    Some(calc_dynamic_port_range_bounds(values[0], values[1]))
}

/// Get Windows dynamic port range for specific IP family and protocol from netsh.
/// Falls back to registry/default range when command output cannot be parsed.
pub fn get_dynamic_port_range_for(protocol: &str, is_ipv6: bool) -> io::Result<(u16, u16)> {
    use std::process::Command;
    let ip_family = if is_ipv6 { "ipv6" } else { "ipv4" };

    let output = Command::new("netsh")
        .args(["int", ip_family, "show", "dynamicport", protocol])
        .output()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(range) = parse_dynamic_port_range_output(&stdout) {
            return Ok(range);
        }
    }

    get_dynamic_port_range()
}

/// Get Windows excluded port ranges from netsh command
/// Parses output of: netsh int ipv4 show excludedportrange tcp/udp
/// Returns a list of (start_port, end_port) tuples
fn parse_excluded_port_ranges_output(stdout: &str) -> Vec<(u16, u16)> {
    let mut ranges = Vec::new();

    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let Some(start) = parts.next().and_then(|v| v.parse::<u16>().ok()) else {
            continue;
        };
        let Some(end) = parts.next().and_then(|v| v.parse::<u16>().ok()) else {
            continue;
        };

        if start <= end {
            ranges.push((start, end));
        }
    }

    ranges
}

pub fn get_excluded_port_ranges(protocol: &str, is_ipv6: bool) -> io::Result<Vec<(u16, u16)>> {
    use std::process::Command;
    let ip_family = if is_ipv6 { "ipv6" } else { "ipv4" };

    let output = Command::new("netsh")
        .args(["int", ip_family, "show", "excludedportrange", protocol])
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_excluded_port_ranges_output(&stdout))
}

/// Check if port is in an excluded port range
pub fn check_port_in_excluded_ranges(
    port: u16,
    protocol: &str,
    is_ipv6: bool,
) -> Option<(u16, u16)> {
    let ranges = get_excluded_port_ranges(protocol, is_ipv6).ok()?;
    for (start, end) in ranges {
        if port >= start && port <= end {
            return Some((start, end));
        }
    }
    None
}

fn format_bind_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{}]", v6),
    }
}

/// Check if port is in dynamic range or excluded range and return conflict info
pub fn check_port_conflict(
    port: u16,
    transport_protocol: &str,
    is_ipv6: bool,
    listener_protocol: &str,
    bind_ip: IpAddr,
) -> Option<PortConflictInfo> {
    let netsh_ip_family = if is_ipv6 { "ipv6" } else { "ipv4" };
    let bind_host = format_bind_host(bind_ip);

    // First check excluded port ranges (more specific, Hyper-V reservations)
    if let Some((start, end)) = check_port_in_excluded_ranges(port, transport_protocol, is_ipv6) {
        let suggested = find_available_port(port, transport_protocol, is_ipv6);
        return Some(PortConflictInfo {
            port,
            protocol: listener_protocol.to_string(),
            bind_host: bind_host.clone(),
            netsh_ip_family,
            conflict_type: PortConflictType::ExcludedRange,
            range_start: start,
            range_end: end,
            suggested_port: suggested,
        });
    }

    // Then check dynamic port range
    let (dyn_start, dyn_end) = get_dynamic_port_range_for(transport_protocol, is_ipv6).ok()?;
    if port >= dyn_start && port <= dyn_end {
        return Some(PortConflictInfo {
            port,
            protocol: listener_protocol.to_string(),
            bind_host,
            netsh_ip_family,
            conflict_type: PortConflictType::DynamicRange,
            range_start: dyn_start,
            range_end: dyn_end,
            suggested_port: dyn_start.saturating_sub(1).max(1024),
        });
    }

    None
}

/// Find an available port that's not in any excluded range
fn find_available_port(original_port: u16, protocol: &str, is_ipv6: bool) -> u16 {
    let excluded_ranges = get_excluded_port_ranges(protocol, is_ipv6).unwrap_or_default();
    let (dyn_start, _) =
        get_dynamic_port_range_for(protocol, is_ipv6).unwrap_or((DEFAULT_START_PORT, 65535));

    // Try ports below dynamic range start, avoiding excluded ranges
    let mut candidate = original_port;
    if candidate >= dyn_start {
        candidate = dyn_start.saturating_sub(1);
    }

    // Search downward from candidate
    while candidate > 1024 {
        let in_excluded = excluded_ranges
            .iter()
            .any(|(start, end)| candidate >= *start && candidate <= *end);
        if !in_excluded {
            return candidate;
        }
        candidate = candidate.saturating_sub(1);
    }

    // Fallback: try common alternative ports
    for alt_port in [9999, 8080, 8443, 7070, 5000] {
        let in_excluded = excluded_ranges
            .iter()
            .any(|(start, end)| alt_port >= *start && alt_port <= *end);
        if !in_excluded && alt_port < dyn_start {
            return alt_port;
        }
    }

    // Last resort
    9999
}

/// Check if current process has administrator privileges
pub fn is_elevated() -> bool {
    use std::mem;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY};

    unsafe {
        let mut current_token_ptr: HANDLE = mem::zeroed();
        let mut token_elevation: TOKEN_ELEVATION = mem::zeroed();
        let token_elevation_type_ptr: *mut TOKEN_ELEVATION = &mut token_elevation;
        let mut size: DWORD = 0;

        let open_result =
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut current_token_ptr);

        if open_result != 0 {
            let query_result = GetTokenInformation(
                current_token_ptr,
                TokenElevation,
                token_elevation_type_ptr as *mut _,
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            let elevated = query_result != 0 && token_elevation.TokenIsElevated != 0;
            let _ = CloseHandle(current_token_ptr);
            return elevated;
        }
    }
    false
}

/// Attempt to automatically fix port range (requires admin)
/// Returns Ok(()) if successful, Err with message if failed
pub fn auto_fix_port_range(ip_family: &str, new_start: u16, num_ports: u16) -> io::Result<()> {
    use std::process::Command;

    if ip_family != "ipv4" && ip_family != "ipv6" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ip_family must be ipv4 or ipv6",
        ));
    }

    // Set TCP dynamic port range
    let tcp_result = Command::new("netsh")
        .args([
            "int",
            ip_family,
            "set",
            "dynamicport",
            "tcp",
            &format!("start={}", new_start),
            &format!("num={}", num_ports),
        ])
        .output()?;

    if !tcp_result.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Failed to set TCP dynamic port range",
        ));
    }

    // Set UDP dynamic port range
    let udp_result = Command::new("netsh")
        .args([
            "int",
            ip_family,
            "set",
            "dynamicport",
            "udp",
            &format!("start={}", new_start),
            &format!("num={}", num_ports),
        ])
        .output()?;

    if !udp_result.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Failed to set UDP dynamic port range",
        ));
    }

    // Restart WinNAT service to apply changes
    let _ = Command::new("net").args(["stop", "winnat"]).output();
    let _ = Command::new("net").args(["start", "winnat"]).output();

    Ok(())
}

/// Generate error message with solutions (English only)
pub fn format_port_conflict_message(
    info: &PortConflictInfo,
    auto_fix_attempted: bool,
    auto_resolve_enabled: bool,
) -> String {
    let conflict_desc = match info.conflict_type {
        PortConflictType::ExcludedRange => format!(
            "Port {} is in Windows excluded port range ({}-{}), likely reserved by Hyper-V.\n",
            info.port, info.range_start, info.range_end
        ),
        PortConflictType::DynamicRange => format!(
            "Port {} is in Windows dynamic port range ({}-{}).\n",
            info.port, info.range_start, info.range_end
        ),
    };

    let mut msg = conflict_desc;

    if auto_fix_attempted {
        msg.push_str("\nAutomatic fix failed (requires administrator privileges).\n");
    }

    msg.push_str(&format!(
        "\nSolutions:\n\
        1. Use a different port:\n\
           --listeners {}://{}:{}\n\n\
        2. Modify Windows dynamic port range (requires admin):\n\
           netsh int {} set dynamicport tcp start=40000 num=5000\n\
           netsh int {} set dynamicport udp start=40000 num=5000\n\
           net stop winnat && net start winnat\n",
        info.protocol,
        info.bind_host,
        info.suggested_port,
        info.netsh_ip_family,
        info.netsh_ip_family
    ));

    // Add diagnostic commands
    msg.push_str(&format!(
        "\nDiagnostic commands:\n\
           netsh int {} show excludedportrange tcp\n\
           netsh int {} show excludedportrange udp\n\
           netsh int {} show dynamicport tcp\n",
        info.netsh_ip_family, info.netsh_ip_family, info.netsh_ip_family
    ));

    // Suggest enabling auto_resolve if not already enabled
    if !auto_resolve_enabled {
        msg.push_str(
            "\n3. Enable automatic fix (run as admin):\n\
               Set 'auto_resolve_port_conflict = true' in config file,\n\
               then run EasyTier as administrator.\n",
        );
    }

    msg.push_str(&format!(
        "\nFor more information, see: {}",
        GITHUB_ISSUE_URL
    ));

    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_excluded_port_ranges_including_administered_rows() {
        let output = r"
Protocol tcp Port Exclusion Ranges

Start Port    End Port
----------    --------
     10000       10099
     50000       50059     *
          *
";

        let ranges = parse_excluded_port_ranges_output(output);
        assert_eq!(ranges, vec![(10000, 10099), (50000, 50059)]);
    }

    #[test]
    fn test_parse_dynamic_port_range_output() {
        let output = r"
Protocol tcp Dynamic Port Range
---------------------------------
Start Port      : 49152
Number of Ports : 16384
";

        let range = parse_dynamic_port_range_output(output);
        assert_eq!(range, Some((49152, 65535)));
    }

    #[test]
    fn test_format_port_conflict_message_uses_listener_protocol_and_host() {
        let info = PortConflictInfo {
            port: 10000,
            protocol: "quic".to_string(),
            bind_host: "[::]".to_string(),
            netsh_ip_family: "ipv6",
            conflict_type: PortConflictType::ExcludedRange,
            range_start: 10000,
            range_end: 10099,
            suggested_port: 9999,
        };
        let msg = format_port_conflict_message(&info, false, false);

        assert!(msg.contains("--listeners quic://[::]:9999"));
        assert!(msg.contains("netsh int ipv6 set dynamicport tcp start=40000 num=5000"));
        assert!(msg.contains("netsh int ipv6 show excludedportrange tcp"));
        assert!(msg.contains("netsh int ipv6 show dynamicport tcp"));
    }

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
