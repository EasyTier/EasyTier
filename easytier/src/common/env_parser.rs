//! 环境变量解析模块
//!
//! 提供配置文件中环境变量占位符的解析功能
//! 支持 Shell 风格的语法：${VAR}、$VAR、${VAR:-default} 等

use std::borrow::Cow;

/// 解析字符串中的环境变量占位符
///
/// 支持的语法：
/// - `${VAR_NAME}`          - 标准格式（推荐）
/// - `$VAR_NAME`            - 简写格式
/// - `${VAR_NAME:-default}` - 带默认值（bash 标准语法）
///
/// # 参数
/// - `text`: 待解析的字符串
///
/// # 返回值
/// - `String`: 替换后的字符串
/// - `bool`: 是否检测到并替换了环境变量
pub fn expand_env_vars(text: &str) -> (String, bool) {
    // 使用 shellexpand::env() 解析环境变量
    // 该函数仅处理环境变量，不处理 tilde (~) 扩展，适合配置文件场景
    match shellexpand::env(text) {
        Ok(expanded) => {
            // 通过比较原始字符串和扩展后的字符串判断是否发生了替换
            let changed = match &expanded {
                Cow::Borrowed(_) => false, // 未发生变化，仍是借用
                Cow::Owned(_) => true,     // 发生了变化，产生了新字符串
            };

            (expanded.into_owned(), changed)
        }
        Err(e) => {
            // 如果解析失败（例如变量引用语法错误），记录警告并返回原字符串
            tracing::warn!("Failed to expand environment variables in config: {}", e);
            (text.to_string(), false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_standard_syntax() {
        std::env::set_var("TEST_VAR_STANDARD", "test_value");
        let (result, changed) = expand_env_vars("secret=${TEST_VAR_STANDARD}");
        assert_eq!(result, "secret=test_value");
        assert!(changed);
    }

    #[test]
    fn test_expand_short_syntax() {
        std::env::set_var("TEST_VAR_SHORT", "short_value");
        let (result, changed) = expand_env_vars("key=$TEST_VAR_SHORT");
        assert_eq!(result, "key=short_value");
        assert!(changed);
    }

    #[test]
    fn test_expand_with_default() {
        // 确保变量未定义
        std::env::remove_var("UNDEFINED_VAR_WITH_DEFAULT");
        let (result, changed) = expand_env_vars("port=${UNDEFINED_VAR_WITH_DEFAULT:-8080}");
        assert_eq!(result, "port=8080");
        assert!(changed);
    }

    #[test]
    fn test_no_env_vars() {
        let (result, changed) = expand_env_vars("plain text without variables");
        assert_eq!(result, "plain text without variables");
        assert!(!changed);
    }

    #[test]
    fn test_empty_string() {
        let (result, changed) = expand_env_vars("");
        assert_eq!(result, "");
        assert!(!changed);
    }

    #[test]
    fn test_multiple_vars() {
        std::env::set_var("VAR1", "value1");
        std::env::set_var("VAR2", "value2");
        let (result, changed) = expand_env_vars("${VAR1} and ${VAR2}");
        assert_eq!(result, "value1 and value2");
        assert!(changed);
    }

    #[test]
    fn test_undefined_var_without_default() {
        // 确保变量未定义
        std::env::remove_var("COMPLETELY_UNDEFINED_VAR");
        let (result, changed) = expand_env_vars("value=${COMPLETELY_UNDEFINED_VAR}");
        // shellexpand::env 对未定义的变量会保持原样
        assert_eq!(result, "value=${COMPLETELY_UNDEFINED_VAR}");
        assert!(!changed);
    }

    #[test]
    fn test_complex_toml_config() {
        std::env::set_var("ET_SECRET", "my-secret-key");
        std::env::set_var("ET_PORT", "11010");

        let config = r#"
[network_identity]
network_name = "test-network"
network_secret = "${ET_SECRET}"

[[peer]]
uri = "tcp://127.0.0.1:${ET_PORT}"
"#;

        let (result, changed) = expand_env_vars(config);
        assert!(changed);
        assert!(result.contains(r#"network_secret = "my-secret-key""#));
        assert!(result.contains(r#"uri = "tcp://127.0.0.1:11010""#));
    }

    #[test]
    fn test_escape_syntax_double_dollar() {
        std::env::set_var("ESCAPED_VAR", "should_not_expand");
        // shellexpand 使用 $$ 作为转义序列，表示字面量的单个 $
        // $$ 会被转义为单个 $，不会触发变量扩展
        let (result, changed) = expand_env_vars("value=$${ESCAPED_VAR}");
        assert_eq!(result, "value=${ESCAPED_VAR}");
        assert!(changed); // $$ -> $ 被视为一次变换
    }

    #[test]
    fn test_escape_syntax_backslash() {
        std::env::set_var("ESCAPED_VAR", "should_not_expand");
        // shellexpand 中反斜杠转义的行为：\$ 会展开为 \<变量值>
        // 这不是推荐的转义方式，此测试仅为记录实际行为
        let (result, changed) = expand_env_vars(r"value=\${ESCAPED_VAR}");
        assert_eq!(result, r"value=\should_not_expand");
        assert!(changed);
    }

    #[test]
    fn test_multiple_dollar_signs() {
        std::env::set_var("TEST_VAR", "value");
        // 测试多个连续的 $ 符号
        let (result1, changed1) = expand_env_vars("$$");
        assert_eq!(result1, "$");
        assert!(changed1);

        let (result2, changed2) = expand_env_vars("$$$$");
        assert_eq!(result2, "$$");
        assert!(changed2);

        // $$ 后跟变量扩展
        let (result3, changed3) = expand_env_vars("$$$TEST_VAR");
        assert_eq!(result3, "$value");
        assert!(changed3);
    }

    #[test]
    fn test_empty_var_value() {
        std::env::set_var("EMPTY_VAR", "");
        let (result, changed) = expand_env_vars("value=${EMPTY_VAR}");
        // 变量存在但值为空
        assert_eq!(result, "value=");
        assert!(changed);
    }

    #[test]
    fn test_default_with_special_chars() {
        std::env::remove_var("UNDEFINED_SPECIAL");
        // 测试默认值包含冒号、等号、空格等特殊字符
        let (result, changed) = expand_env_vars("url=${UNDEFINED_SPECIAL:-http://localhost:8080}");
        assert_eq!(result, "url=http://localhost:8080");
        assert!(changed);

        let (result2, changed2) = expand_env_vars("key=${UNDEFINED_SPECIAL:-name=value}");
        assert_eq!(result2, "key=name=value");
        assert!(changed2);

        let (result3, changed3) = expand_env_vars("msg=${UNDEFINED_SPECIAL:-hello world}");
        assert_eq!(result3, "msg=hello world");
        assert!(changed3);
    }

    #[test]
    fn test_var_name_with_numbers_underscores() {
        std::env::set_var("VAR_123", "num_value");
        std::env::set_var("_VAR", "underscore_prefix");
        std::env::set_var("VAR_", "underscore_suffix");

        let (result1, changed1) = expand_env_vars("${VAR_123}");
        assert_eq!(result1, "num_value");
        assert!(changed1);

        let (result2, changed2) = expand_env_vars("${_VAR}");
        assert_eq!(result2, "underscore_prefix");
        assert!(changed2);

        let (result3, changed3) = expand_env_vars("${VAR_}");
        assert_eq!(result3, "underscore_suffix");
        assert!(changed3);
    }

    #[test]
    fn test_invalid_syntax() {
        // 测试无效语法的处理
        let (result1, changed1) = expand_env_vars("${}");
        // shellexpand 会保留无效语法原样
        assert_eq!(result1, "${}");
        assert!(!changed1);

        // 注意：未闭合的 ${VAR 实际上 shellexpand 会当作普通文本处理
        // 它会尝试查找名为 "VAR" 的环境变量（到字符串末尾）
        std::env::remove_var("VAR");
        let (result2, _changed2) = expand_env_vars("incomplete ${VAR");
        // 如果 VAR 未定义，shellexpand 会返回错误或保持原样
        assert_eq!(result2, "incomplete ${VAR");
        // 注意：changed2 的值取决于 shellexpand 是否认为这是有效语法
        // 因此不对 changed2 做断言
    }

    #[test]
    fn test_mixed_defined_undefined_vars() {
        std::env::set_var("DEFINED_VAR", "defined");
        std::env::remove_var("UNDEFINED_VAR");

        // 混合已定义和未定义的变量
        // shellexpand::env 在遇到未定义变量时会返回错误（默认行为）
        // 因此整个字符串会保持不变
        let (result, changed) = expand_env_vars("${DEFINED_VAR} and ${UNDEFINED_VAR}");
        assert_eq!(result, "${DEFINED_VAR} and ${UNDEFINED_VAR}");
        assert!(!changed);
    }

    #[test]
    fn test_nested_braces() {
        std::env::set_var("OUTER", "outer_value");
        // 嵌套的大括号是无效语法，shellexpand::env 会返回错误
        let (result, changed) = expand_env_vars("${OUTER} and ${{INNER}}");
        // 由于语法错误，整个字符串保持不变
        assert_eq!(result, "${OUTER} and ${{INNER}}");
        assert!(!changed);
    }
}
