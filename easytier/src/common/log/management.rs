use anyhow::Context as _;

use crate::common::config::LoggingConfigLoader;

use super::{FileSink, Logger, TargetFilter, install, parse_level};

pub fn init(config: impl LoggingConfigLoader, reload: bool) -> anyhow::Result<()> {
    let console_config = config.get_console_logger_config();
    let console_level = console_config
        .level
        .as_deref()
        .map(parse_level)
        .transpose()
        .context("invalid console log level")?;
    let console = TargetFilter::console(console_level)?;
    let file = FileSink::from_config(config.get_file_logger_config(), reload)?;

    install(Logger::new(console, file))
}
