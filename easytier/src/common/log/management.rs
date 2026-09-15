use anyhow::Context as _;

use crate::common::config::LoggingConfigLoader;

use super::{FileSink, Logger, TargetFilter, install, parse_level};

pub fn init(config: impl LoggingConfigLoader, reload: bool) -> anyhow::Result<()> {
    init_with_default_console_targets(config, reload, &[super::LOG_TARGET])
}

pub fn init_with_default_console_targets(
    config: impl LoggingConfigLoader,
    reload: bool,
    default_targets: &[&str],
) -> anyhow::Result<()> {
    let console_config = config.get_console_logger_config();
    let console_level = console_config
        .level
        .as_deref()
        .map(parse_level)
        .transpose()
        .context("invalid console log level")?;
    let console = TargetFilter::console_with_default_targets(console_level, default_targets)?;
    let file = FileSink::from_config(config.get_file_logger_config(), reload)?;

    install(Logger::new(console, file))
}
