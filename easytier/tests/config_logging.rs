#![cfg(feature = "management")]

use std::{
    io::Write as _,
    process::{Command, Output, Stdio},
};

use tempfile::NamedTempFile;

fn check_config_command() -> Command {
    // Nextest remaps this path when running tests from an extracted archive.
    let binary = std::env::var_os("NEXTEST_BIN_EXE_easytier_core")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_easytier-core").into());
    let mut command = Command::new(binary);
    command
        .env_clear()
        .arg("--check-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn stderr_on_success(output: Output) -> String {
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}");
    stderr
}

#[test]
fn check_config_warns_for_each_file_with_ignored_logging() {
    let mut console_config = NamedTempFile::new().unwrap();
    writeln!(console_config, "[console_logger]\nlevel = 'off'").unwrap();
    let mut file_config = NamedTempFile::new().unwrap();
    writeln!(file_config, "[file_logger]\nlevel = 'info'").unwrap();

    let output = check_config_command()
        .arg("--config-file")
        .arg(console_config.path())
        .arg(file_config.path())
        .output()
        .unwrap();
    let stderr = stderr_on_success(output);

    assert_eq!(
        stderr
            .matches("Logging configuration in TOML is ignored")
            .count(),
        2
    );
    for file in [&console_config, &file_config] {
        assert!(stderr.contains(&format!("{:?}", file.path().display().to_string())));
    }
    assert!(stderr.contains("console_logger"));
    assert!(stderr.contains("file_logger"));
    assert!(stderr.contains("process-wide"));
    assert!(stderr.contains("--console-log-level"));
    assert!(stderr.contains("--file-log-level"));
    assert!(stderr.contains("ET_*"));
}

#[test]
fn check_config_warns_for_stdin_without_validating_ignored_values() {
    let mut child = check_config_command()
        .args(["--config-file", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"file_logger = 'ignored'\n[console_logger]\nlevel = 123\n")
        .unwrap();
    let stderr = stderr_on_success(child.wait_with_output().unwrap());

    assert_eq!(
        stderr
            .matches("Logging configuration in TOML is ignored")
            .count(),
        1
    );
    assert!(stderr.contains("stdin"));
    assert!(stderr.contains("file_logger"));
    assert!(stderr.contains("console_logger"));
}

#[test]
fn check_config_does_not_warn_for_comments_strings_or_nested_sections() {
    let mut config = NamedTempFile::new().unwrap();
    writeln!(
        config,
        "# [file_logger]\ninstance_name = '[console_logger]'\n[unknown.file_logger]\nlevel = 'info'"
    )
    .unwrap();

    let output = check_config_command()
        .arg("--config-file")
        .arg(config.path())
        .output()
        .unwrap();
    let stderr = stderr_on_success(output);

    assert!(!stderr.contains("Logging configuration in TOML is ignored"));
}
