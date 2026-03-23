use std::{collections::HashMap, fs, process::Command};

use crate::proto::web::DeviceOsInfo;

pub fn collect_device_os_info() -> DeviceOsInfo {
    let os_type = normalize_os_type(std::env::consts::OS);
    let (version, distribution) = detect_os_version_and_distribution(&os_type);

    DeviceOsInfo {
        os_type,
        version,
        distribution,
    }
}

fn normalize_os_type(raw: &str) -> String {
    match raw {
        "macos" => "macos".to_string(),
        "windows" => "windows".to_string(),
        "linux" => "linux".to_string(),
        "android" => "android".to_string(),
        "ios" => "ios".to_string(),
        "freebsd" => "freebsd".to_string(),
        other => other.to_string(),
    }
}

fn detect_os_version_and_distribution(os_type: &str) -> (String, String) {
    match os_type {
        "linux" | "android" => linux_version_and_distribution(os_type),
        "macos" => (
            first_non_empty([
                command_output("sw_vers", &["-productVersion"]),
                unix_kernel_release(),
            ]),
            "macOS".to_string(),
        ),
        "windows" => (
            first_non_empty([windows_version(), None]),
            "Windows".to_string(),
        ),
        "freebsd" => (
            first_non_empty([
                command_output("freebsd-version", &[]),
                unix_kernel_release(),
            ]),
            "FreeBSD".to_string(),
        ),
        other => (
            unix_kernel_release().unwrap_or_else(|| "unknown".to_string()),
            other.to_string(),
        ),
    }
}

fn linux_version_and_distribution(os_type: &str) -> (String, String) {
    let os_release = parse_os_release().unwrap_or_default();
    let version = first_non_empty([
        os_release.get("VERSION_ID").cloned(),
        os_release.get("VERSION").cloned(),
        unix_kernel_release(),
    ]);
    let distribution = first_non_empty([
        os_release.get("NAME").cloned(),
        os_release.get("ID").cloned().map(title_case),
        Some(if os_type == "android" {
            "Android".to_string()
        } else {
            "Linux".to_string()
        }),
    ]);
    (version, distribution)
}

fn parse_os_release() -> Option<HashMap<String, String>> {
    ["/etc/os-release", "/usr/lib/os-release"]
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|content| {
            content
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        return None;
                    }
                    let (key, value) = line.split_once('=')?;
                    Some((key.to_string(), trim_os_release_value(value)))
                })
                .collect()
        })
}

fn trim_os_release_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn unix_kernel_release() -> Option<String> {
    command_output("uname", &["-r"])
}

fn windows_version() -> Option<String> {
    let output = command_output("cmd", &["/C", "ver"])?;
    output
        .split("Version")
        .nth(1)
        .map(str::trim)
        .map(|part| part.trim_matches(&['[', ']'][..]).to_string())
        .filter(|value| !value.is_empty())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn first_non_empty<const N: usize>(values: [Option<String>; N]) -> String {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn title_case(value: String) -> String {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return value;
    };
    first.to_uppercase().collect::<String>() + chars.as_str()
}
