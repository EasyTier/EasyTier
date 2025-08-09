// translated from tailscale #32ce1bdb48078ec4cedaeeb5b1b2ff9c0ef61a49

use crate::defer;
use anyhow::{Context, Result};
use dbus::blocking::stdintf::org_freedesktop_dbus::Properties as _;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use version_compare::Cmp;

// 声明依赖项（需要添加到Cargo.toml）
// use dbus::blocking::Connection;
// use nix::unistd::AccessFlags;
// use resolv_conf::Resolver;

// 常量定义
const RESOLV_CONF: &str = "/etc/resolv.conf";
const PING_TIMEOUT: Duration = Duration::from_secs(1);

// 错误类型定义
#[derive(Debug)]
struct DNSConfigError {
    message: String,
    source: Option<anyhow::Error>,
}

type DbusPingFn = dyn Fn(&str, &str) -> Result<()>;
type DbusReadStringFn = dyn Fn(&str, &str, &str, &str) -> Result<String>;
type NmIsUsingResolvedFn = dyn Fn() -> Result<()>;
type NmVersionBetweenFn = dyn Fn(&str, &str) -> Result<bool>;
type ResolvconfStyleFn = dyn Fn() -> String;

// 配置环境结构体
struct OSConfigEnv {
    fs: Box<dyn FileSystem>,
    dbus_ping: Box<DbusPingFn>,
    dbus_read_string: Box<DbusReadStringFn>,
    nm_is_using_resolved: Box<NmIsUsingResolvedFn>,
    nm_version_between: Box<NmVersionBetweenFn>,
    resolvconf_style: Box<dyn Fn() -> String>,
}

// DNS管理器trait
trait OSConfigurator: Send + Sync {
    // 实现相关方法
}

// 文件系统操作trait
trait FileSystem {
    fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    fn exists(&self, path: &str) -> bool;
}

// 直接文件系统实现
struct DirectFS;

impl FileSystem for DirectFS {
    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        fs::read(path).context("Failed to read file")
    }

    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
}

/// 检查 NetworkManager 是否使用 systemd-resolved 作为 DNS 管理器
pub fn nm_is_using_resolved() -> Result<()> {
    // 连接系统 D-Bus
    let conn = dbus::blocking::Connection::new_system().context("Failed to connect to D-Bus")?;

    // 创建 NetworkManager DnsManager 对象代理
    let proxy = conn.with_proxy(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager/DnsManager",
        std::time::Duration::from_secs(1),
    );

    // 获取 Mode 属性
    let (value,): (dbus::arg::Variant<Box<dyn dbus::arg::RefArg + 'static>>,) = proxy
        .method_call(
            "org.freedesktop.DBus.Properties",
            "Get",
            ("org.freedesktop.NetworkManager.DnsManager", "Mode"),
        )
        .context("Failed to get NM mode property")?;

    // 检查 Mode 是否为 "systemd-resolved"
    if value.0.as_str() != Some("systemd-resolved") {
        return Err(anyhow::anyhow!(
            "NetworkManager is not using systemd-resolved, found: {:?}",
            value
        ));
    }

    Ok(())
}

/// 返回系统中使用的 resolvconf 实现类型（"debian" 或 "openresolv"）
pub fn resolvconf_style() -> String {
    // 检查 resolvconf 命令是否存在
    if which::which("resolvconf").is_err() {
        return String::new();
    }

    // 执行 resolvconf --version 命令
    let output = match Command::new("resolvconf").arg("--version").output() {
        Ok(output) => output,
        Err(e) => {
            // 处理命令执行错误
            if let Some(code) = e.raw_os_error() {
                // Debian 版本的 resolvconf 不支持 --version，返回特定错误码 99
                if code == 99 {
                    return "debian".to_string();
                }
            }
            return String::new(); // 其他错误返回空字符串
        }
    };

    // 检查输出是否以 "Debian resolvconf" 开头
    if output.stdout.starts_with(b"Debian resolvconf") {
        return "debian".to_string();
    }

    // 默认视为 openresolv
    "openresolv".to_string()
}

// 构建配置环境
fn new_os_config_env() -> OSConfigEnv {
    OSConfigEnv {
        fs: Box::new(DirectFS),
        dbus_ping: Box::new(dbus_ping),
        dbus_read_string: Box::new(dbus_read_string),
        nm_is_using_resolved: Box::new(nm_is_using_resolved),
        nm_version_between: Box::new(nm_version_between),
        resolvconf_style: Box::new(resolvconf_style),
    }
}

// 创建DNS配置器
fn new_os_configurator(_interface_name: String) -> Result<()> {
    let env = new_os_config_env();

    let mode = dns_mode(&env).context("Failed to detect DNS mode")?;

    tracing::info!("dns: using {} mode", mode);

    // match mode.as_str() {
    //     "direct" => Ok(Box::new(DirectManager::new(env.fs)?)),
    //     // "systemd-resolved" => Ok(Box::new(ResolvedManager::new(
    //     //     &logf,
    //     //     health,
    //     //     interface_name,
    //     // )?)),
    //     // "network-manager" => Ok(Box::new(NMManager::new(interface_name)?)),
    //     // "debian-resolvconf" => Ok(Box::new(DebianResolvconfManager::new(&logf)?)),
    //     // "openresolv" => Ok(Box::new(OpenresolvManager::new(&logf)?)),
    //     _ => {
    //         tracing::warn!("Unexpected DNS mode {}, using direct manager", mode);
    //         Ok(Box::new(DirectManager::new(env.fs)?))
    //     }
    // }
    Ok(())
}

use std::io::{self, BufRead, Cursor};

/// 返回 `resolv.conf` 内容的拥有者（"systemd-resolved"、"NetworkManager"、"resolvconf" 或空字符串）
pub fn resolv_owner(bs: &[u8]) -> String {
    let mut likely = String::new();
    let cursor = Cursor::new(bs);
    let reader = io::BufReader::new(cursor);

    for line_result in reader.lines() {
        match line_result {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if !line.starts_with('#') {
                    // 第一个非注释且非空的行，直接返回当前结果
                    return likely;
                }

                // 检查注释行中的关键字
                if line.contains("systemd-resolved") {
                    likely = "systemd-resolved".to_string();
                } else if line.contains("NetworkManager") {
                    likely = "NetworkManager".to_string();
                } else if line.contains("resolvconf") {
                    likely = "resolvconf".to_string();
                }
            }
            Err(_) => {
                // 读取错误（如无效 UTF-8），直接返回当前结果
                return likely;
            }
        }
    }

    likely
}

// 检测DNS模式
fn dns_mode(env: &OSConfigEnv) -> Result<String> {
    let debug = std::cell::RefCell::new(Vec::new());
    let dbg = |k: &str, v: &str| debug.borrow_mut().push((k.to_string(), v.to_string()));

    // defer 日志记录
    defer! {
        if !debug.borrow().is_empty() {
            let log_entries: Vec<String> =
                debug.borrow().iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            tracing::info!("dns: [{}]", log_entries.join(" "));
        }
    };

    // 检查systemd-resolved状态
    let resolved_up =
        (env.dbus_ping)("org.freedesktop.resolve1", "/org/freedesktop/resolve1").is_ok();
    if resolved_up {
        dbg("resolved-ping", "yes");
    }

    // 读取resolv.conf
    let content = match env.fs.read_file(RESOLV_CONF) {
        Ok(content) => content,
        Err(e) if e.to_string().contains("NotFound") => {
            dbg("rc", "missing");
            return Ok("direct".to_string());
        }
        Err(e) => return Err(e).context("reading /etc/resolv.conf"),
    };

    // 检查resolv.conf所有者
    match resolv_owner(&content).as_str() {
        "systemd-resolved" => {
            dbg("rc", "resolved");
            // 检查是否实际使用resolved
            if let Err(e) = resolved_is_actually_resolver(env, &dbg, &content) {
                tracing::warn!("resolvedIsActuallyResolver error: {}", e);
                dbg("resolved", "not-in-use");
                return Ok("direct".to_string());
            }

            // NetworkManager检查逻辑...

            Ok("systemd-resolved".to_string())
        }
        "resolvconf" => {
            // resolvconf处理逻辑...
            Ok("debian-resolvconf".to_string())
        }
        "NetworkManager" => {
            // NetworkManager处理逻辑...
            Ok("systemd-resolved".to_string())
        }
        _ => Ok("direct".to_string()),
    }
}

// D-Bus ping实现
fn dbus_ping(name: &str, object_path: &str) -> Result<()> {
    let conn = dbus::blocking::Connection::new_system()?;
    let proxy = conn.with_proxy(name, object_path, PING_TIMEOUT);
    let _: () = proxy.method_call("org.freedesktop.DBus.Peer", "Ping", ())?;
    Ok(())
}

// D-Bus读取字符串实现
fn dbus_read_string(name: &str, object_path: &str, iface: &str, member: &str) -> Result<String> {
    let conn = dbus::blocking::Connection::new_system()?;
    let proxy = conn.with_proxy(name, object_path, PING_TIMEOUT);
    let (value,): (String,) =
        proxy.method_call("org.freedesktop.DBus.Properties", "Get", (iface, member))?;
    Ok(value)
}

// NetworkManager版本检查
fn nm_version_between(first: &str, last: &str) -> Result<bool> {
    let conn = dbus::blocking::Connection::new_system()?;
    let proxy = conn.with_proxy(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        PING_TIMEOUT,
    );

    let version: String = proxy.get("org.freedesktop.NetworkManager", "Version")?;
    let cmp_first = version_compare::compare(&version, first).unwrap_or(Cmp::Lt);
    let cmp_last = version_compare::compare(&version, last).unwrap_or(Cmp::Gt);
    Ok(cmp_first == Cmp::Ge && cmp_last == Cmp::Le)
}

// 检查是否实际使用systemd-resolved
fn resolved_is_actually_resolver(
    env: &OSConfigEnv,
    dbg: &dyn Fn(&str, &str),
    content: &[u8],
) -> Result<()> {
    if is_libnss_resolve_used(env).is_ok() {
        dbg("resolved", "nss");
        return Ok(());
    }

    // 解析resolv.conf内容
    let resolver = resolv_conf::Config::parse(content)?;

    // 检查nameserver配置
    if resolver.nameservers.is_empty() {
        return Err(anyhow::anyhow!("resolv.conf has no nameservers"));
    }

    for ns in resolver.nameservers {
        if ns != Ipv4Addr::new(127, 0, 0, 53).into() {
            return Err(anyhow::anyhow!(
                "resolv.conf doesn't point to systemd-resolved"
            ));
        }
    }

    dbg("resolved", "file");
    Ok(())
}

// 检查是否使用libnss_resolve
fn is_libnss_resolve_used(env: &OSConfigEnv) -> Result<()> {
    let content = env.fs.read_file("/etc/nsswitch.conf")?;

    for line in String::from_utf8_lossy(&content).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.first() == Some(&"hosts:") {
            for module in parts.iter().skip(1) {
                if *module == "dns" {
                    return Err(anyhow::anyhow!("dns module has higher priority"));
                }
                if *module == "resolve" {
                    return Ok(());
                }
            }
        }
    }

    Err(anyhow::anyhow!("libnss_resolve not used"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_mode_test() {
        let env = new_os_config_env();
        let mode = dns_mode(&env).unwrap();
        println!("Detected DNS mode: {}", mode);
    }
}
