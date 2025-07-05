//
// Port supporting code for wireguard-nt from wireguard-windows v0.5.3 to Rust
// This file replicates the functionality of wireguard-windows/tunnel/winipcfg/netsh.go
//

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    process::{Command, Stdio},
};
use winapi::shared::ws2def::{ADDRESS_FAMILY, AF_INET, AF_INET6};

pub fn flush_dns(family: ADDRESS_FAMILY, if_index: u32) -> Result<(), String> {
    let proto_name = match family as i32 {
        AF_INET => "ipv4",
        AF_INET6 => "ipv6",
        _ => {
            return Err(String::from("Invalid address family"));
        }
    };

    //let netsh_params = format!("interface {proto} set dnsservers name={itf} source=static address=none validate=no register=both", proto=proto_name, itf=ip_itf.InterfaceIndex);
    let ret_netsh = Command::new("netsh.exe")
        .arg("interface")
        .arg(proto_name)
        .arg("set")
        .arg("dnsservers")
        .arg(format!("name={}", if_index))
        .arg("source=static")
        .arg("address=none")
        .arg("validate=no")
        .arg("register=both")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .output();
    match ret_netsh {
        Ok(output) => {
            // netsh.exe returns error messages only and is silent upon success. BUT then it will return \r\n, so we need to look at the lines.
            if let Ok(stdout_str) = String::from_utf8(output.stdout) {
                if stdout_str.is_empty() || stdout_str == "\r\n" {
                    Ok(())
                } else {
                    // TODO: ignore "There are no Domain Name Servers (DNS) configured on this computer."
                    // Is this string localized?
                    Err(stdout_str)
                }
            } else {
                Err(String::from("Could not parse netsh output"))
            }
        }
        Err(_) => Err(String::from("Failed to execute command")),
    }
}

// Please execute flush_dns() first, as written in the original source code.
fn add_dns(family: ADDRESS_FAMILY, if_index: u32, dnses: &[String]) -> Result<(), String> {
    let proto_name = match family as i32 {
        AF_INET => "ipv4",
        AF_INET6 => "ipv6",
        _ => {
            return Err(String::from("Invalid address family"));
        }
    };

    // "interface ipv4 add dnsservers name=%d address=%s validate=no"
    let ret_netsh = Command::new("netsh.exe")
        .arg("interface")
        .arg(proto_name)
        .arg("add")
        .arg("dnsservers")
        .arg(format!("name={}", if_index))
        .arg(format!(
            "address={}",
            dnses
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ))
        .arg("validate=no")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .output();
    match ret_netsh {
        Ok(output) => {
            // netsh.exe returns error messages only and is silent upon success. BUT then it will return \r\n, so we need to look at the lines.
            if let Ok(stdout_str) = String::from_utf8(output.stdout) {
                if stdout_str.is_empty() || stdout_str == "\r\n" {
                    Ok(())
                } else {
                    // TODO: ignore "There are no Domain Name Servers (DNS) configured on this computer."
                    // Is this string localized?
                    Err(stdout_str)
                }
            } else {
                Err(String::from("Could not parse netsh output"))
            }
        }
        Err(_) => Err(String::from("Failed to execute command")),
    }
}

pub fn add_dns_ipv4(if_index: u32, dnses: &[Ipv4Addr]) -> Result<(), String> {
    flush_dns(AF_INET as _, if_index)?;
    if dnses.is_empty() {
        return Ok(());
    }
    let dnses_str: Vec<String> = dnses.iter().map(|addr| addr.to_string()).collect();
    add_dns(AF_INET as _, if_index, &dnses_str)
}

pub fn add_dns_ipv6(if_index: u32, dnses: &[Ipv6Addr]) -> Result<(), String> {
    flush_dns(AF_INET6 as _, if_index)?;
    if dnses.is_empty() {
        return Ok(());
    }
    let dnses_str: Vec<String> = dnses.iter().map(|addr| addr.to_string()).collect();
    add_dns(AF_INET6 as _, if_index, &dnses_str)
}