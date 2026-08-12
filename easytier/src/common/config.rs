//! Native Adapters around the core-owned TOML configuration model.

use std::path::PathBuf;

use anyhow::Context as _;
use strum::VariantArray as _;
#[cfg(feature = "management")]
use tokio::io::AsyncReadExt as _;

use easytier_core::config::MappedListenerPolicy;
#[cfg(feature = "management")]
pub use easytier_core::config::api_input::{
    NetworkConfig, NetworkConfigExt, NetworkingMethod, add_proxy_network_to_config,
};
pub use easytier_core::config::toml::*;

#[cfg(feature = "management")]
use crate::common::env_parser;
use crate::tunnel::IpScheme;

#[cfg(feature = "management")]
pub use easytier_core::management::{config_source_from_rpc, config_source_to_rpc};

pub fn parse_mapped_listener_urls(
    mapped_listeners: &[String],
) -> Result<Vec<url::Url>, anyhow::Error> {
    MappedListenerPolicy::new(IpScheme::VARIANTS.iter().map(ToString::to_string))
        .parse_urls(mapped_listeners)
}

pub fn parse_encryption_algorithm(value: &str) -> Result<EncryptionAlgorithm, String> {
    value
        .parse()
        .map_err(|_| format!("'{value}' is not a valid encryption algorithm"))
}

pub fn load_toml_config_from_path(path: &PathBuf) -> Result<TomlConfigLoader, anyhow::Error> {
    let config = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    TomlConfigLoader::new_from_str_with_source(&path.display().to_string(), &config)
}

#[cfg(feature = "management-rpc")]
pub use easytier_core::management::{ConfigFileControl, ConfigFilePermission};

#[cfg(feature = "management")]
pub async fn config_file_control_from_path(path: PathBuf) -> ConfigFileControl {
    let read_only = tokio::fs::metadata(&path)
        .await
        .map(|metadata| metadata.permissions().readonly())
        .unwrap_or(true);
    ConfigFileControl::new(
        Some(path),
        if read_only {
            ConfigFilePermission::from(ConfigFilePermission::READ_ONLY)
        } else {
            ConfigFilePermission::default()
        },
    )
}

#[cfg(feature = "management")]
pub async fn load_config_from_file(
    config_file: &PathBuf,
    config_dir: Option<&PathBuf>,
    disable_env_parsing: bool,
) -> Result<(TomlConfigLoader, ConfigFileControl), anyhow::Error> {
    if config_file.as_os_str() == "-" {
        let mut stdin = String::new();
        tokio::io::stdin()
            .read_to_string(&mut stdin)
            .await
            .context("failed to read config from stdin")?;
        let config = TomlConfigLoader::new_from_str_with_source("stdin", &stdin)?;
        return Ok((config, ConfigFileControl::STATIC_CONFIG));
    }

    let config_str = tokio::fs::read_to_string(config_file)
        .await
        .with_context(|| format!("failed to read config file: {}", config_file.display()))?;
    let (expanded_config_str, uses_env_vars) = if disable_env_parsing {
        (config_str, false)
    } else {
        env_parser::expand_env_vars(&config_str)
    };

    if disable_env_parsing {
        tracing::info!(?config_file, "environment variable parsing is disabled");
    } else if uses_env_vars {
        tracing::info!(?config_file, "environment variables detected and expanded");
    }

    let source_name = config_file.display().to_string();
    let config = TomlConfigLoader::new_from_str_with_source(&source_name, &expanded_config_str)?;
    let mut control = config_file_control_from_path(config_file.clone()).await;

    if uses_env_vars {
        control.set_read_only(true);
        control.set_no_delete(true);
    } else if control.is_read_only() {
        control.set_no_delete(true);
    } else if let Some(config_dir) = config_dir {
        let is_managed_file = config_file.parent() == Some(config_dir.as_path())
            && config_file.file_stem() == Some(config.get_id().to_string().as_ref())
            && config_file.extension() == Some(std::ffi::OsStr::new("toml"));
        control.set_no_delete(!is_managed_file);
    } else {
        control.set_no_delete(true);
    }

    Ok((config, control))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn path_adapter_preserves_file_name_in_parse_error() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "dhcp = \"yes\"").unwrap();

        let error = load_toml_config_from_path(&file.path().to_path_buf())
            .unwrap_err()
            .to_string();

        assert!(error.contains(file.path().to_string_lossy().as_ref()));
        assert!(error.contains("dhcp = \"yes\""));
    }

    #[tokio::test]
    async fn file_adapter_keeps_os_metadata_outside_core_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "instance_name = \"from-file\"").unwrap();

        let (config, control) = load_config_from_file(&file.path().to_path_buf(), None, true)
            .await
            .unwrap();

        assert_eq!(config.get_inst_name(), "from-file");
        assert_eq!(control.path.as_deref(), Some(file.path()));
    }
}

#[cfg(test)]
mod compatibility_tests {
    use std::{io::Write as _, path::PathBuf};

    use tempfile::NamedTempFile;

    use super::*;
    use crate::tests::{remove_env_var, set_env_var};
    /// 配置文件环境变量解析功能的集成测试
    ///
    /// 测试范围：
    /// 1. 配置加载功能测试（环境变量替换、权限标记）
    /// 2. RPC API 安全测试（只读配置保护）
    /// 3. CLI 参数测试（--disable-env-parsing 开关）
    /// 4. 多实例隔离测试
    /// 5. 实际配置字段测试（network_secret、peer.uri 等）
    /// 配置加载功能测试（环境变量替换、权限标记）
    ///
    /// 验证：
    /// - 环境变量能正确替换到配置中
    /// - 包含环境变量的配置文件自动标记为只读和禁止删除
    #[tokio::test]
    async fn test_env_var_expansion_and_readonly_flag() {
        // 设置测试环境变量
        set_env_var("TEST_SECRET", "my-test-secret-123");
        set_env_var("TEST_NETWORK", "test-network");

        // 创建临时配置文件，包含环境变量占位符
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "test-instance"

[network_identity]
network_name = "${TEST_NETWORK}"
network_secret = "${TEST_SECRET}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 加载配置（启用环境变量解析）
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证环境变量已被替换
        let network_identity = config.get_network_identity();
        assert_eq!(network_identity.network_name, "test-network");
        assert_eq!(
            network_identity.network_secret.as_ref().unwrap(),
            "my-test-secret-123"
        );

        // 验证权限标记：包含环境变量的配置应被标记为只读和禁止删除
        assert!(
            control.is_read_only(),
            "Config with env vars should be marked as READ_ONLY"
        );
        assert!(
            control.is_no_delete(),
            "Config with env vars should be marked as NO_DELETE"
        );

        // 清理环境变量
        remove_env_var("TEST_SECRET");
        remove_env_var("TEST_NETWORK");
    }

    /// RPC API 安全测试（只读配置保护）
    ///
    /// 验证：
    /// - 只读配置不会通过 RPC API 暴露给远程调用
    /// - 这需要测试 get_network_instance_config 拒绝返回只读配置
    ///
    /// 注：这个测试验证权限标记的正确设置，实际的 RPC API 保护已在
    /// `easytier/src/rpc_service/instance_manage.rs` 中实现
    #[tokio::test]
    async fn test_readonly_config_api_protection() {
        set_env_var("API_TEST_SECRET", "secret-value");

        // 创建包含环境变量的配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "api-test"

[network_identity]
network_name = "api-network"
network_secret = "${API_TEST_SECRET}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 加载配置
        let (_config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证只读标记已设置（这是 RPC API 保护的前提）
        assert!(
            control.is_read_only(),
            "Config should be marked as READ_ONLY for RPC protection"
        );
        assert!(
            control.permission.has_flag(ConfigFilePermission::READ_ONLY),
            "Permission flag should be set correctly"
        );

        remove_env_var("API_TEST_SECRET");
    }

    /// CLI 参数测试（--disable-env-parsing 开关）
    ///
    /// 验证：
    /// - disable_env_parsing = true 时，环境变量不会被替换
    /// - 配置不会被标记为只读
    #[tokio::test]
    async fn test_disable_env_parsing_flag() {
        set_env_var("DISABLED_TEST_VAR", "should-not-expand");

        // 创建包含环境变量占位符的配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "disable-test"

[network_identity]
network_name = "test"
network_secret = "${DISABLED_TEST_VAR}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        // 以 disable_env_parsing = true 加载配置
        let (config, control) = load_config_from_file(&config_path, None, true)
            .await
            .unwrap();

        // 验证环境变量未被替换（保持原样）
        let network_identity = config.get_network_identity();
        assert_eq!(
            network_identity.network_secret.as_ref().unwrap(),
            "${DISABLED_TEST_VAR}",
            "Env var should not be expanded when parsing is disabled"
        );

        assert!(!control.is_read_only());
        assert!(
            control.is_no_delete(),
            "Config should be NO_DELETE due to no config_dir, not env vars"
        );

        remove_env_var("DISABLED_TEST_VAR");
    }

    /// 多实例隔离测试
    ///
    /// 验证：
    /// - 不同实例可以使用不同的环境变量值
    /// - 环境变量在运行时被解析，支持动态切换
    #[tokio::test]
    async fn test_multiple_instances_with_different_env_vars() {
        // 实例1：使用第一组环境变量
        set_env_var("INSTANCE_SECRET", "instance1-secret");
        set_env_var("INSTANCE_NAME", "instance-one");

        let mut temp_file1 = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "${INSTANCE_NAME}"

[network_identity]
network_name = "multi-test"
network_secret = "${INSTANCE_SECRET}"
"#;
        temp_file1.write_all(config_content.as_bytes()).unwrap();
        temp_file1.flush().unwrap();

        let config_path1 = PathBuf::from(temp_file1.path());
        let (config1, _) = load_config_from_file(&config_path1, None, false)
            .await
            .unwrap();

        // 验证实例1的配置
        assert_eq!(config1.get_inst_name(), "instance-one");
        assert_eq!(
            config1
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "instance1-secret"
        );

        // 实例2：修改环境变量后加载同一模板
        set_env_var("INSTANCE_SECRET", "instance2-secret");
        set_env_var("INSTANCE_NAME", "instance-two");

        let mut temp_file2 = NamedTempFile::new().unwrap();
        temp_file2.write_all(config_content.as_bytes()).unwrap();
        temp_file2.flush().unwrap();

        let config_path2 = PathBuf::from(temp_file2.path());
        let (config2, _) = load_config_from_file(&config_path2, None, false)
            .await
            .unwrap();

        // 验证实例2使用了不同的环境变量值
        assert_eq!(config2.get_inst_name(), "instance-two");
        assert_eq!(
            config2
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "instance2-secret"
        );

        // 验证两个实例的配置确实不同
        assert_ne!(config1.get_inst_name(), config2.get_inst_name());
        assert_ne!(
            config1.get_network_identity().network_secret,
            config2.get_network_identity().network_secret
        );

        // 清理
        remove_env_var("INSTANCE_SECRET");
        remove_env_var("INSTANCE_NAME");
    }

    /// 实际配置字段测试（network_secret、peer.uri 等）
    ///
    /// 验证：
    /// - network_secret 字段支持环境变量
    /// - peer.uri 字段支持环境变量
    /// - listeners 字段支持环境变量
    /// - 其他实际使用的配置字段
    #[tokio::test]
    async fn test_real_config_fields_expansion() {
        // 设置各种实际场景的环境变量
        set_env_var("CONFIG_REAL_SECRET", "production-secret-key");
        set_env_var("PEER_HOST", "peer.example.com");
        set_env_var("PEER_PORT", "11011");
        set_env_var("LISTEN_PORT", "11010");
        set_env_var("NETWORK_NAME", "prod-network");

        // 创建包含多个实际字段的完整配置
        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "production"
ipv4 = "10.144.144.1"
listeners = ["tcp://0.0.0.0:${LISTEN_PORT}"]

[network_identity]
network_name = "${NETWORK_NAME}"
network_secret = "${CONFIG_REAL_SECRET}"

[[peer]]
uri = "tcp://${PEER_HOST}:${PEER_PORT}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证 network_identity 字段
        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "prod-network");
        assert_eq!(
            identity.network_secret.as_ref().unwrap(),
            "production-secret-key"
        );

        // 验证 listeners 字段
        let listeners = config.get_listener_uris();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].to_string(), "tcp://0.0.0.0:11010");

        // 验证 peer 字段
        let peers = config.get_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].uri.to_string(), "tcp://peer.example.com:11011");

        // 验证配置被正确标记
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理环境变量
        remove_env_var("CONFIG_REAL_SECRET");
        remove_env_var("PEER_HOST");
        remove_env_var("PEER_PORT");
        remove_env_var("LISTEN_PORT");
        remove_env_var("NETWORK_NAME");
    }

    /// 带默认值的环境变量
    ///
    /// 验证：
    /// - ${VAR:-default} 语法在变量未定义时使用默认值
    #[tokio::test]
    async fn test_env_var_with_default_value() {
        // 确保变量未定义
        remove_env_var("UNDEFINED_PORT");
        remove_env_var("UNDEFINED_SECRET");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "default-test"
listeners = ["tcp://0.0.0.0:${UNDEFINED_PORT:-11010}"]

[network_identity]
network_name = "test"
network_secret = "${UNDEFINED_SECRET:-default-secret}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());

        let (config, _) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证使用了默认值
        assert_eq!(
            config
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "default-secret"
        );
        assert_eq!(
            config.get_listener_uris()[0].to_string(),
            "tcp://0.0.0.0:11010"
        );
    }

    /// 环境变量未定义且无默认值的情况
    ///
    /// 验证：
    /// - 未定义的环境变量保持原样（shellexpand 的默认行为）
    #[tokio::test]
    async fn test_undefined_env_var_without_default() {
        remove_env_var("COMPLETELY_UNDEFINED");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "undefined-test"

[network_identity]
network_name = "test"
network_secret = "${COMPLETELY_UNDEFINED}"
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证变量保持原样
        assert_eq!(
            config
                .get_network_identity()
                .network_secret
                .as_ref()
                .unwrap(),
            "${COMPLETELY_UNDEFINED}"
        );

        assert!(!control.is_read_only());
        assert!(control.is_no_delete());
    }

    /// 布尔类型环境变量
    ///
    /// 验证：
    /// - 布尔类型的环境变量能正确解析和反序列化
    /// - TOML 解析器能将字符串 "true"/"false" 转换为布尔值
    #[tokio::test]
    async fn test_boolean_type_env_vars() {
        // 设置布尔类型的环境变量
        set_env_var("ENABLE_DHCP", "true");
        set_env_var("ENABLE_ENCRYPTION", "false");
        set_env_var("ENABLE_IPV6", "true");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "bool-test"
dhcp = ${ENABLE_DHCP}

[network_identity]
network_name = "test"
network_secret = "secret"

[flags]
enable_encryption = ${ENABLE_ENCRYPTION}
enable_ipv6 = ${ENABLE_IPV6}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证布尔值被正确解析
        assert!(config.get_dhcp(), "dhcp should be true");

        let flags = config.get_flags();
        assert!(
            !flags.enable_encryption,
            "enable_encryption should be false"
        );
        assert!(flags.enable_ipv6, "enable_ipv6 should be true");

        // 验证使用环境变量的配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        remove_env_var("ENABLE_DHCP");
        remove_env_var("ENABLE_ENCRYPTION");
        remove_env_var("ENABLE_IPV6");
    }

    /// 数字类型环境变量
    ///
    /// 验证：
    /// - 数字类型（整数、端口号）的环境变量能正确解析和反序列化
    /// - TOML 解析器能将字符串 "1380" 转换为整数
    #[tokio::test]
    async fn test_numeric_type_env_vars() {
        // 设置数字类型的环境变量
        set_env_var("MTU_VALUE", "1400");
        set_env_var("THREAD_COUNT", "4");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "numeric-test"

[network_identity]
network_name = "test"
network_secret = "secret"

[flags]
mtu = ${MTU_VALUE}
multi_thread_count = ${THREAD_COUNT}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证数字值被正确解析
        let flags = config.get_flags();
        assert_eq!(flags.mtu, 1400, "mtu should be 1400");
        assert_eq!(
            flags.multi_thread_count, 4,
            "multi_thread_count should be 4"
        );

        // 验证使用环境变量的配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        remove_env_var("MTU_VALUE");
        remove_env_var("THREAD_COUNT");
    }

    /// 混合类型环境变量
    ///
    /// 验证：
    /// - 字符串、布尔、数字类型的环境变量可以同时使用
    /// - 所有类型都能正确解析和反序列化
    /// - 模拟真实的复杂配置场景
    #[tokio::test]
    async fn test_mixed_type_env_vars() {
        // 设置不同类型的环境变量
        set_env_var("MIXED_SECRET", "mixed-secret-key");
        set_env_var("MIXED_NETWORK", "production");
        set_env_var("MIXED_DHCP", "true");
        set_env_var("MIXED_MTU", "1500");
        set_env_var("MIXED_ENCRYPTION", "false");
        set_env_var("MIXED_LISTEN_PORT", "12345");

        let mut temp_file = NamedTempFile::new().unwrap();
        let config_content = r#"
instance_name = "mixed-test"
ipv4 = "10.0.0.1"
dhcp = ${MIXED_DHCP}
listeners = ["tcp://0.0.0.0:${MIXED_LISTEN_PORT}"]

[network_identity]
network_name = "${MIXED_NETWORK}"
network_secret = "${MIXED_SECRET}"

[flags]
mtu = ${MIXED_MTU}
enable_encryption = ${MIXED_ENCRYPTION}
"#;
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config_path = PathBuf::from(temp_file.path());
        let (config, control) = load_config_from_file(&config_path, None, false)
            .await
            .unwrap();

        // 验证字符串类型
        let identity = config.get_network_identity();
        assert_eq!(identity.network_name, "production");
        assert_eq!(
            identity.network_secret.as_ref().unwrap(),
            "mixed-secret-key"
        );

        // 验证布尔类型
        assert!(config.get_dhcp());

        let flags = config.get_flags();
        assert!(!flags.enable_encryption);

        // 验证数字类型
        assert_eq!(flags.mtu, 1500);

        // 验证 URL 中的端口号（数字）
        let listeners = config.get_listener_uris();
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].to_string(), "tcp://0.0.0.0:12345");

        // 验证配置被标记为只读
        assert!(control.is_read_only());
        assert!(control.is_no_delete());

        // 清理
        remove_env_var("MIXED_SECRET");
        remove_env_var("MIXED_NETWORK");
        remove_env_var("MIXED_DHCP");
        remove_env_var("MIXED_MTU");
        remove_env_var("MIXED_ENCRYPTION");
        remove_env_var("MIXED_LISTEN_PORT");
    }
}
