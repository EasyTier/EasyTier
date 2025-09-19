use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsInfo {
    pub os_type: String,
    pub os_version: String,
    pub arch: String,
}

impl OsInfo {
    pub fn collect() -> Self {
        Self {
            os_type: get_os_type(),
            os_version: get_os_version(),
            arch: get_arch(),
        }
    }

    pub fn to_string(&self) -> String {
        format!("{} {} ({})", self.os_type, self.os_version, self.arch)
    }
}

impl Default for OsInfo {
    fn default() -> Self {
        Self {
            os_type: "Unknown".to_string(),
            os_version: "Unknown".to_string(),
            arch: "Unknown".to_string(),
        }
    }
}

fn get_os_type() -> String {
    std::env::consts::OS.to_string()
}

fn get_arch() -> String {
    std::env::consts::ARCH.to_string()
}

#[cfg(target_os = "linux")]
fn get_os_version() -> String {
    // Try to read distribution information from common files
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        if let Some(pretty_name) = extract_value_from_os_release(&content, "PRETTY_NAME") {
            return pretty_name;
        }
        if let Some(name) = extract_value_from_os_release(&content, "NAME") {
            let version = extract_value_from_os_release(&content, "VERSION").unwrap_or_default();
            return if version.is_empty() {
                name
            } else {
                format!("{} {}", name, version)
            };
        }
    }

    // Fallback to /etc/lsb-release
    if let Ok(content) = fs::read_to_string("/etc/lsb-release") {
        if let Some(description) = extract_value_from_lsb_release(&content, "DISTRIB_DESCRIPTION") {
            return description;
        }
    }

    // Fallback to kernel version
    if let Ok(content) = fs::read_to_string("/proc/version") {
        if let Some(first_line) = content.lines().next() {
            return first_line.to_string();
        }
    }

    "Linux".to_string()
}

#[cfg(target_os = "windows")]
fn get_os_version() -> String {
    // On Windows, try to get version from registry or use a simple approach
    // For now, use a simple fallback
    "Windows".to_string()
}

#[cfg(target_os = "macos")]
fn get_os_version() -> String {
    // Try to get macOS version using system_profiler or sw_vers
    if let Ok(output) = std::process::Command::new("sw_vers")
        .arg("-productName")
        .output()
    {
        if output.status.success() {
            let product_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            
            if let Ok(version_output) = std::process::Command::new("sw_vers")
                .arg("-productVersion")
                .output()
            {
                if version_output.status.success() {
                    let version = String::from_utf8_lossy(&version_output.stdout).trim().to_string();
                    return format!("{} {}", product_name, version);
                }
            }
            return product_name;
        }
    }
    
    "macOS".to_string()
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn get_os_version() -> String {
    std::env::consts::OS.to_string()
}

#[cfg(target_os = "linux")]
fn extract_value_from_os_release(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(pos) = line.find('=') {
            let (line_key, value) = line.split_at(pos);
            if line_key == key {
                let value = &value[1..]; // Skip the '='
                // Remove quotes if present
                let value = value.trim_matches('"').trim_matches('\'');
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn extract_value_from_lsb_release(content: &str, key: &str) -> Option<String> {
    extract_value_from_os_release(content, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_info_collection() {
        let os_info = OsInfo::collect();
        
        // Basic checks that we get some meaningful information
        assert!(!os_info.os_type.is_empty());
        assert!(!os_info.arch.is_empty());
        assert!(!os_info.os_version.is_empty());
        
        println!("OS Info: {}", os_info.to_string());
    }

    #[test]
    fn test_os_info_default() {
        let default_info = OsInfo::default();
        assert_eq!(default_info.os_type, "Unknown");
        assert_eq!(default_info.os_version, "Unknown");
        assert_eq!(default_info.arch, "Unknown");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_extract_value_from_os_release() {
        let content = r#"NAME="Ubuntu"
VERSION="20.04.3 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.3 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal"#;

        assert_eq!(extract_value_from_os_release(content, "NAME"), Some("Ubuntu".to_string()));
        assert_eq!(extract_value_from_os_release(content, "PRETTY_NAME"), Some("Ubuntu 20.04.3 LTS".to_string()));
        assert_eq!(extract_value_from_os_release(content, "VERSION_ID"), Some("20.04".to_string()));
        assert_eq!(extract_value_from_os_release(content, "NONEXISTENT"), None);
    }

    #[test]
    fn test_os_info_integration_with_route_peer_info() {
        use crate::proto::peer_rpc::RoutePeerInfo;
        use std::time::SystemTime;
        
        // Test that RoutePeerInfo can hold OS information
        let os_info = OsInfo::collect();
        let mut peer_info = RoutePeerInfo::new();
        peer_info.os_info = Some(os_info.to_string());
        peer_info.hostname = Some("test-node".to_string());
        peer_info.peer_id = 12345;
        peer_info.last_update = Some(SystemTime::now().into());
        
        // Verify the OS info is stored correctly
        assert!(peer_info.os_info.is_some());
        assert!(peer_info.os_info.as_ref().unwrap().contains(&os_info.os_type));
        assert!(peer_info.os_info.as_ref().unwrap().contains(&os_info.arch));
        
        // Test conversion to CLI Route
        let cli_route: crate::proto::cli::Route = peer_info.into();
        assert!(cli_route.os_info.is_some());
        assert!(cli_route.os_info.as_ref().unwrap().contains(&os_info.os_type));
        
        println!("OS Info in Route: {:?}", cli_route.os_info);
    }
}