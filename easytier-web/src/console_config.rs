use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsoleConfig {
    console_enroll_command: Option<String>,
}

/// Load the console settings, with CLI/environment values taking precedence.
/// Preserve command text verbatim; the frontend expands its placeholders.
pub fn load(path: Option<&Path>, command_override: Option<String>) -> Result<Option<String>> {
    let config = if let Some(path) = path {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read console config file '{}'", path.display()))?;
        toml::from_str::<ConsoleConfig>(&content)
            .with_context(|| format!("Failed to parse console config file '{}'", path.display()))?
    } else {
        ConsoleConfig::default()
    };

    let command = command_override.or(config.console_enroll_command);
    if command
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("console_enroll_command must not be empty or whitespace-only");
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_toml(content: &str, command_override: Option<&str>) -> Result<Option<String>> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.toml");
        std::fs::write(&path, content).unwrap();
        load(Some(&path), command_override.map(str::to_owned))
    }

    #[test]
    fn absent_configuration_preserves_default_command() {
        assert_eq!(load(None, None).unwrap(), None);
        assert_eq!(load_toml("", None).unwrap(), None);
    }

    #[test]
    fn reads_command_template_from_toml() {
        let command = "easytier-core -w {protocol}://{host}:{port}/{username}";
        let config = format!("console_enroll_command = '{command}'");
        assert_eq!(load_toml(&config, None).unwrap().as_deref(), Some(command));
    }

    #[test]
    fn preserves_multiline_command_and_whitespace() {
        let config = "console_enroll_command = '''\n  first {username}\nsecond {host}  \n'''";
        assert_eq!(
            load_toml(config, None).unwrap().as_deref(),
            Some("  first {username}\nsecond {host}  \n")
        );
    }

    #[test]
    fn cli_or_environment_value_takes_precedence_over_file() {
        assert_eq!(
            load_toml("console_enroll_command = 'from-file'", Some("  override  "))
                .unwrap()
                .as_deref(),
            Some("  override  ")
        );
        assert_eq!(
            load(None, Some("override".to_owned())).unwrap().as_deref(),
            Some("override")
        );
    }

    #[test]
    fn validates_only_the_effective_command() {
        assert_eq!(
            load_toml("console_enroll_command = ''", Some("override"))
                .unwrap()
                .as_deref(),
            Some("override")
        );
        for value in ["", " \t\n "] {
            let error = load_toml("console_enroll_command = 'from-file'", Some(value)).unwrap_err();
            assert!(error.to_string().contains("must not be empty"));
        }
        for config in [
            "console_enroll_command = ''",
            "console_enroll_command = '   '",
        ] {
            assert!(
                load_toml(config, None)
                    .unwrap_err()
                    .to_string()
                    .contains("must not be empty")
            );
        }
    }

    #[test]
    fn rejects_invalid_toml_and_wrong_value_type_even_with_override() {
        for content in ["console_enroll_command = [", "console_enroll_command = 12"] {
            let error = load_toml(content, Some("override")).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Failed to parse console config file")
            );
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = load_toml("console_enrollment_command = 'typo'", None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("unknown field"));
        assert!(message.contains("console_enrollment_command"));
    }

    #[test]
    fn reports_file_read_failure_even_with_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-console.toml");
        let error = load(Some(&path), Some("override".to_owned())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Failed to read console config file")
        );
        assert!(error.to_string().contains("missing-console.toml"));
    }
}
